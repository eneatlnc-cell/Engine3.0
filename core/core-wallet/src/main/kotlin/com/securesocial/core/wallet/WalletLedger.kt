package com.securesocial.core.wallet

import com.securesocial.core.crypto.EcdsaOperations
import java.security.PublicKey
import java.util.Base64

/**
 * ═══════════════════════════════════════════════════════════════════
 *  v3.37 · SPARK 签名账本 (内存链 + 全链校验 + 余额推导)
 * ═══════════════════════════════════════════════════════════════════
 *
 *  职责 (纯 Kotlin, 无存储无 Android —— 持久化由宿主包装):
 *  · [verify] 全链校验: 每笔签名 + 链接 (prevTxHash) + 序号连续性;
 *  · [balance] 余额 = Σ signedAmount —— 推导值, 从不存储;
 *  · [nextSeq] / [nextPrevHash] 新交易的链接材料;
 *  · [appendTx] 追加已签名交易 (追加前零信任校验)。
 *
 *  校验规则 (violation 即 TAMPERED, 账本冻结支出):
 *  1. 首笔: seq ≥ 1 且 prevTxHash == "" (未迁移的钱包直接从 GRANT 起链);
 *  2. 后续: seq > 前笔 seq (严格递增; **间隙允许** —— 见下);
 *  3. 后续: prevTxHash == 前笔 txHash (断链 = 篡改/删除痕迹);
 *  4. 每笔: signature 对 [TxCanonical.bytes] 用钱包公钥验签通过;
 *  5. 每笔: amount > 0, GENESIS/GRANT 的 counterparty 为空;
 *  6. GENESIS 只允许出现在首笔 (迁移语义唯一)。
 *
 *  序号间隙的合法性 (v3.37 定稿, 与初版 "严格 +1" 的差异):
 *  · Vault 高水位 (HWM) 在签名即推进, Engine 账本只在回调送达后追加 ——
 *    签名已生成但回调丢失 (Engine 进程被杀/超时) 时, 该序号在 Vault 侧
 *    已烧毁, Engine 侧交易未入账。重试同序号必被 HWM 拒绝 (TX_SEQ_REJECTED),
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
        data class Ok(val txCount: Int, val balance: Long) : ChainCheck()

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
        if (chain.isEmpty()) return ChainCheck.Ok(0, 0L)

        var prev: WalletTx? = null
        var balance = 0L
        for ((index, tx) in chain.withIndex()) {
            val at = "tx[$index seq=${tx.seq}]"

            if (tx.amount <= 0) return ChainCheck.Bad("$at amount<=0")

            if (prev == null) {
                if (tx.seq < 1L) return ChainCheck.Bad("$at first tx seq<1")
                if (tx.prevTxHash.isNotEmpty()) return ChainCheck.Bad("$at first tx prevTxHash!=''")
            } else {
                if (tx.seq <= prev.seq)
                    return ChainCheck.Bad("$at seq regression (expect >${prev.seq})")
                if (tx.prevTxHash != prev.txHash)
                    return ChainCheck.Bad("$at prevTxHash link broken")
                if (prev.type == TxType.GENESIS && tx.type == TxType.GENESIS)
                    return ChainCheck.Bad("$at duplicate GENESIS")
            }

            when (tx.type) {
                TxType.GENESIS, TxType.GRANT ->
                    if (!tx.counterparty.isNullOrEmpty())
                        return ChainCheck.Bad("$at ${tx.type} must have no counterparty")
                else -> Unit
            }
            if (tx.type == TxType.GENESIS && index != 0)
                return ChainCheck.Bad("$at GENESIS not first")

            // 签名校验 (规范化字节, 域分离)
            val sig = runCatching { Base64.getDecoder().decode(tx.signature) }
                .getOrElse { return ChainCheck.Bad("$at signature not base64") }
            if (!ecdsa.verify(walletPublicKey, TxCanonical.bytes(tx), sig))
                return ChainCheck.Bad("$at signature invalid")

            balance += tx.signedAmount
            prev = tx
        }
        return ChainCheck.Ok(chain.size, balance)
    }

    // ---- 余额与链接材料 ----

    /** 余额 = Σ signedAmount (推导值; TAMPERED 状态下仍可查看但不许支出) */
    fun balance(): Long = _txs.sumOf { it.signedAmount }

    fun nextSeq(): Long = (_txs.lastOrNull()?.seq ?: 0L) + 1L

    fun nextPrevHash(): String = _txs.lastOrNull()?.txHash ?: ""

    fun isEmpty(): Boolean = _txs.isEmpty()

    // ---- 追加 ----

    /**
     * 追加一笔已签名交易: 追加前以全链视角校验 (前缀 + 新交易),
     * 保证账本内永远只有可验证历史。TAMPERED 状态拒绝追加。
     */
    fun appendTx(tx: WalletTx): ChainCheck {
        if (status == Status.TAMPERED)
            return ChainCheck.Bad("ledger tampered: append rejected")

        val extended = _txs + tx
        val check = verify(extended)
        if (check is ChainCheck.Bad) return check

        _txs.add(tx)
        return ChainCheck.Ok(_txs.size, balance())
    }
}
