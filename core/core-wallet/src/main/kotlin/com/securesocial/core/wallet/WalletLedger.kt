package com.securesocial.core.wallet

import com.securesocial.core.crypto.EcdsaOperations
import java.security.PublicKey
import java.util.Base64

/**
 * ═══════════════════════════════════════════════════════════════════
 *  SPARK 签名账本 (内存链 + 全链校验 + 双账户余额推导)
 *  v3.37: 签名账本基础 · v3.38: 双账户 + 足额规则 + 交接终结
 * ═══════════════════════════════════════════════════════════════════
 *
 *  职责 (纯 Kotlin, 无存储无 Android —— 持久化由宿主包装):
 *  · [verify] 全链校验: 每笔签名 + 链接 (prevTxHash) + 序号递增 +
 *    总额足额 (total 运行余额恒 ≥ 0);
 *  · [balances] 余额 = Σ effects —— 推导值, 从不存储;
 *  · [nextSeq] / [nextPrevHash] 新交易的链接材料;
 *  · [appendTx] 追加已签名交易 (追加前零信任校验);
 *  · [canSpend] 出账足额预检 (Vault 签名前调用, v3.39 起按 total)。
 *
 *  校验规则 (violation 即 TAMPERED, 账本冻结支出):
 *  1. 首笔: seq ≥ 1 且 prevTxHash == "" (未迁移的钱包直接从 GRANT 起链);
 *  2. 后续: seq > 前笔 seq (严格递增; **间隙允许** —— 见下);
 *  3. 后续: prevTxHash == 前笔 txHash (断链 = 篡改/删除痕迹);
 *  4. 每笔: signature 对 [TxCanonical.bytes] 用钱包公钥验签通过;
 *  5. 每笔: amount > 0, GRANT 的 counterparty 为空
 *     (GENESIS 例外: 交接承接时 counterparty = 旧公钥 hex);
 *  6. GENESIS 只允许出现在首笔 (迁移语义唯一);
 *  7. v3.38 双账户足额 → **v3.39 合并为总额足额**: 任一时点
 *     custody + margin ≥ 0 —— 权威记账方 (Vault) 从不签出超支交易,
 *     链上出现负总额运行余额 = 密钥在记账方之外被使用过 (妥协信号)
 *     → TAMPERED。(旧链双账户分量各自非负 → total 必然非负, 兼容);
 *  8. v3.38 交接终结 → **v3.39 全额移交 total**: HANDOVER 必须是最后一笔
 *     (其后任何交易违规), 且 amount == 交接时点的 total 余额
 *     (custody + margin; 全额移交, 残留即死账)。兼容旧链: amount ==
 *     交接口 custody (v3.38 语义, margin 不迁移) 亦接受 —— 两种历史
 *     在 total 规则下均自洽。
 *
 *  序号间隙的合法性 (v3.37 定稿, 与初版 "严格 +1" 的差异):
 *  · Vault 高水位 (HWM) 在签名即推进, 镜像侧只在回调送达后追加 ——
 *    签名已生成但回调丢失 (进程被杀/超时) 时, 该序号在 Vault 侧
 *    已烧毁, 镜像侧交易未入账。重试同序号必被 HWM 拒绝 (TX_SEQ_REJECTED),
 *    唯一出路是跳号续链。
 *  · 若账本强制 "严格 +1", 一次回调丢失即永久 TAMPERED —— 可用性不可接受;
 *  · 间隙不削弱防篡改: prevTxHash 链仍保证顺序与完整性 (链是主见证,
 *    序号是辅助回滚见证); 序号回退 (seq ≤ 前笔) 依然违规。
 *  · 间隙语义 = "该序号的交易被签名后丢失" —— 与回滚攻击 (恢复旧账本)
 *    的区别在于: 回滚恢复的旧账本尾 seq 必然 ≤ Vault HWM, 由签名侧
 *    拒绝, 与账本侧规则无关。
 */
class WalletLedger(private val walletPublicKey: PublicKey) {

    private val ecdsa = EcdsaOperations()

    private val _txs = mutableListOf<WalletTx>()
    val txs: List<WalletTx> get() = _txs.toList()

    /** 当前账本健康状态 */
    var status: Status = Status.CLEAN
        private set

    enum class Status {
        /** 全链校验通过 */
        CLEAN,

        /** 校验失败 —— 账本只读, 拒绝追加与支出 (UI 呈警示) */
        TAMPERED,
    }

    /** 校验失败原因 (日志/UI 用; 不含敏感材料) */
    var tamperReason: String? = null
        private set

    sealed class ChainCheck {
        /** 校验通过 */
        data class Ok(val txCount: Int, val balances: WalletBalances) : ChainCheck()

        /** 校验失败: [reason] 定位坏点 */
        data class Bad(val reason: String) : ChainCheck()
    }

    // ---- 装载与校验 ----

    /**
     * 装载持久化账本 (宿主在启动时调用): 逐条校验后装载。
     * 任何一条违规 → TAMPERED (已通过的前缀保留为只读证据)。
     */
    fun load(existing: List<WalletTx>): ChainCheck {
        val check = verify(existing)
        _txs.clear()
        _txs.addAll(existing)
        status = if (check is ChainCheck.Ok) Status.CLEAN else Status.TAMPERED
        tamperReason = if (check is ChainCheck.Bad) check.reason else null
        return check
    }

    /**
     * 全链独立校验 (不改变账本状态) —— 拿公钥的任何人可复算。
     */
    fun verify(chain: List<WalletTx>): ChainCheck {
        if (chain.isEmpty()) return ChainCheck.Ok(0, WalletBalances(0, 0))

        var prev: WalletTx? = null
        var custody = 0L
        var margin = 0L
        for ((index, tx) in chain.withIndex()) {
            val at = "tx[$index seq=${tx.seq}]"

            if (tx.amount <= 0) return ChainCheck.Bad("$at amount<=0")

            if (prev == null) {
                if (tx.seq < 1L) return ChainCheck.Bad("$at first tx seq<1")
                if (tx.prevTxHash.isNotEmpty()) return ChainCheck.Bad("$at first tx prevTxHash!=''")
                if (tx.type == TxType.HANDOVER)
                    return ChainCheck.Bad("$at HANDOVER cannot be first (no custody to hand over)")
            } else {
                if (tx.seq <= prev.seq)
                    return ChainCheck.Bad("$at seq regression (expect >${prev.seq})")
                if (tx.prevTxHash != prev.txHash)
                    return ChainCheck.Bad("$at prevTxHash link broken")
                if (prev.type == TxType.GENESIS && tx.type == TxType.GENESIS)
                    return ChainCheck.Bad("$at duplicate GENESIS")
                if (prev.type == TxType.HANDOVER)
                    return ChainCheck.Bad("$at tx after terminal HANDOVER")
            }

            when (tx.type) {
                TxType.GRANT ->
                    if (!tx.counterparty.isNullOrEmpty())
                        return ChainCheck.Bad("$at GRANT must have no counterparty")
                else -> Unit
            }
            if (tx.type == TxType.GENESIS && index != 0)
                return ChainCheck.Bad("$at GENESIS not first")

            // 签名校验 (规范化字节, 域分离)
            val sig = runCatching { Base64.getDecoder().decode(tx.signature) }
                .getOrElse { return ChainCheck.Bad("$at signature not base64") }
            if (!ecdsa.verify(walletPublicKey, TxCanonical.bytes(tx), sig))
                return ChainCheck.Bad("$at signature invalid")

            // 交接语义: 全额移交 (残留即死账 —— 其后不可再有任何交易)
            if (tx.type == TxType.HANDOVER) {
                if (tx.counterparty.isNullOrBlank())
                    return ChainCheck.Bad("$at HANDOVER must name new pubkey (counterparty)")
                val totalAtPoint = custody + margin
                // v3.39: 全额移交 total; 兼容旧链 amount == custody (margin 不迁移)
                if (tx.amount != totalAtPoint && tx.amount != custody)
                    return ChainCheck.Bad(
                        "$at HANDOVER amount ${tx.amount} != total $totalAtPoint (must drain fully)",
                    )
            }

            val eff = tx.effects()
            custody += eff.custody
            margin += eff.margin

            // v3.39 足额规则: 总额运行余额恒非负
            // (v3.38 旧链两分量各自非负 → total 必然非负, 升级兼容)
            val totalNow = custody + margin
            if (totalNow < 0L) return ChainCheck.Bad("$at total overdrawn ($totalNow)")

            prev = tx
        }
        return ChainCheck.Ok(chain.size, WalletBalances(custody, margin))
    }

    // ---- 余额与链接材料 ----

    /** 双账户余额 = Σ effects (推导值; TAMPERED 状态下仍可查看但不许支出) */
    fun balances(): WalletBalances =
        _txs.fold(WalletBalances(0, 0)) { acc, tx -> acc + tx.effects() }

    /** 可用余额 (v3.39 合并语义) = custody + margin */
    fun balance(): Long = balances().total

    fun nextSeq(): Long = (_txs.lastOrNull()?.seq ?: 0L) + 1L

    fun nextPrevHash(): String = _txs.lastOrNull()?.txHash ?: ""

    fun isEmpty(): Boolean = _txs.isEmpty()

    /** 链是否已终结 (最后一笔为 HANDOVER —— 不可再追加任何交易) */
    fun isTerminal(): Boolean = _txs.lastOrNull()?.type == TxType.HANDOVER

    // ---- 足额预检 (权威记账方签名前调用) ----

    /** SPEND 足额 (v3.39): total (custody + margin) ≥ amount */
    fun canSpend(amount: Long): Boolean =
        amount > 0L && balances().total >= amount

    // ---- 追加 ----

    /**
     * 追加一笔已签名交易: 追加前以全链视角校验 (前缀 + 新交易),
     * 保证账本内永远只有可验证历史。TAMPERED 状态拒绝追加。
     */
    fun appendTx(tx: WalletTx): ChainCheck {
        if (status == Status.TAMPERED)
            return ChainCheck.Bad("ledger tampered: append rejected")
        if (isTerminal())
            return ChainCheck.Bad("ledger terminal (HANDOVER): append rejected")

        val extended = _txs + tx
        val check = verify(extended)
        if (check is ChainCheck.Bad) return check

        _txs.add(tx)
        return ChainCheck.Ok(_txs.size, balances())
    }
}
