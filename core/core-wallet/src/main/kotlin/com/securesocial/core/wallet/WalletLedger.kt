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
    val txs: List<WalletTx> get() = synchronized(lock) { _txs.toList() }

    // ── v3.59 增量校验状态 (修复: 同步延迟随链长恶化, 逐笔追赶 O(n²)) ──
    //
    // 背景: 旧实现对账时每轮做整链重验 —— Vault 权威侧 walletState 每轮
    // 全链 verify, Engine 镜像每 appendTx 一次又对完整前缀链全量重验
    // (appendTx 内部 verify(extended))。链一笔笔增长后, 逐笔追赶 N 笔退化为
    // 近似 O(n·N), 即 "同步钱包延迟 / 杀几次进程才对齐" 的区块侧根因。
    //
    // 本字段维护"已验证前缀"的游标与累计余额: appendTx / balances 只做
    // 增量 (验新一笔), 不再从第 0 笔重跑。链语义逐字节不变 (签名域、
    // prevTxHash 链接、HANDOVER/GENESIS 规则原样保留), 不引入任何 checkpoint
    // 信任折损 —— 前缀在进程内仅由本对象 append 演进, 无可被外部篡改的面;
    // 初次装载 / full 全链重建仍走全量 verify (见 [verify] / [load])。
    private var verifiedCount = 0
    private var runningBalance = WalletBalances(0, 0)

    /**
     * 内部互斥锁 (修复 B-1): 使 "校验 → 追加 → 游标 → 余额" 的写路径
     * 与 `balances/nextSeq/isTerminal` 等读路径原子化, 杜绝并发 append
     * 导致的断链/游标与 _txs 不同步。JVM 内建锁重入, append/balances
     * 嵌套调用安全。
     */
    private val lock = Any()

    /** 当前账本健康状态 */
    var status: Status = Status.CLEAN
        get() = synchronized(lock) { field }
        private set

    enum class Status {
        /** 全链校验通过 */
        CLEAN,

        /** 校验失败 —— 账本只读, 拒绝追加与支出 (UI 呈警示) */
        TAMPERED,
    }

    /** 校验失败原因 (日志/UI 用; 不含敏感材料) */
    var tamperReason: String? = null
        get() = synchronized(lock) { field }
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
    fun load(existing: List<WalletTx>): ChainCheck = synchronized(lock) {
        val check = verify(existing)
        _txs.clear()
        _txs.addAll(existing)
        status = if (check is ChainCheck.Ok) Status.CLEAN else Status.TAMPERED
        tamperReason = if (check is ChainCheck.Bad) check.reason else null
        // 增量游标同步: Ok → 整链已验, 后续 append 只增量验新一笔;
        // Bad → 保守置 0 (balances() 回退全量 fold, appendTx 因 TAMPERED 拒绝,
        // 只读证据语义不变)。
        if (check is ChainCheck.Ok) {
            verifiedCount = existing.size
            runningBalance = check.balances
        } else {
            verifiedCount = 0
            runningBalance = WalletBalances(0, 0)
        }
        check
    }

    /**
     * 全链独立校验 (不改变账本状态) —— 拿公钥的任何人可复算。
     */
    fun verify(chain: List<WalletTx>): ChainCheck {
        if (chain.isEmpty()) return ChainCheck.Ok(0, WalletBalances(0, 0))

        var prev: WalletTx? = null
        var running = WalletBalances(0, 0)
        for ((index, tx) in chain.withIndex()) {
            val at = "tx[$index seq=${tx.seq}]"
            when (val one = validateOne(tx, prev, running, isFirst = index == 0)) {
                is OneCheck.Bad -> return ChainCheck.Bad("$at ${one.reason}")
                is OneCheck.Ok -> running = one.balances
            }
            prev = tx
        }
        return ChainCheck.Ok(chain.size, running)
    }

    /** 单笔校验结果 (增量 append 与全量 [verify] 共用, 规则单点不漂移) */
    private sealed class OneCheck {
        data class Ok(val balances: WalletBalances) : OneCheck()
        data class Bad(val reason: String) : OneCheck()
    }

    /**
     * 校验单笔交易相对其前一笔 ([prev]) 的合法性, 返回累计余额。
     *
     * [startBalances] 为 [prev] 之后 (已验证前缀) 的累计效果。校验规则
     * 与历史 [verify] 逐笔分支完全一致 —— 增量 append (见 [appendTx])
     * 借此只验新一笔、避免整链重验, 而规则保持单一来源。
     */
    private fun validateOne(
        tx: WalletTx,
        prev: WalletTx?,
        startBalances: WalletBalances,
        isFirst: Boolean,
    ): OneCheck {
        if (tx.amount <= 0) return OneCheck.Bad("amount<=0")

        if (prev == null) {
            if (tx.seq < 1L) return OneCheck.Bad("first tx seq<1")
            if (tx.prevTxHash.isNotEmpty()) return OneCheck.Bad("first tx prevTxHash!=''")
            if (tx.type == TxType.HANDOVER)
                return OneCheck.Bad("HANDOVER cannot be first (no custody to hand over)")
        } else {
            if (tx.seq <= prev.seq)
                return OneCheck.Bad("seq regression (expect >${prev.seq})")
            if (tx.prevTxHash != prev.txHash)
                return OneCheck.Bad("prevTxHash link broken")
            if (prev.type == TxType.GENESIS && tx.type == TxType.GENESIS)
                return OneCheck.Bad("duplicate GENESIS")
            if (prev.type == TxType.HANDOVER)
                return OneCheck.Bad("tx after terminal HANDOVER")
        }

        when (tx.type) {
            TxType.GRANT ->
                if (!tx.counterparty.isNullOrEmpty())
                    return OneCheck.Bad("GRANT must have no counterparty")
            else -> Unit
        }
        if (tx.type == TxType.GENESIS && !isFirst)
            return OneCheck.Bad("GENESIS not first")

        // 签名校验 (规范化字节, 域分离)
        val sig = runCatching { Base64.getDecoder().decode(tx.signature) }
            .getOrElse { return OneCheck.Bad("signature not base64") }
        if (!ecdsa.verify(walletPublicKey, TxCanonical.bytes(tx), sig))
            return OneCheck.Bad("signature invalid")

        var custody = startBalances.custody
        var margin = startBalances.margin

        // 交接语义: 全额移交 (残留即死账 —— 其后不可再有任何交易)
        if (tx.type == TxType.HANDOVER) {
            if (tx.counterparty.isNullOrBlank())
                return OneCheck.Bad("HANDOVER must name new pubkey (counterparty)")
            val totalAtPoint = custody + margin
            // v3.39: 全额移交 total; 兼容旧链 amount == custody (margin 不迁移)
            if (tx.amount != totalAtPoint && tx.amount != custody)
                return OneCheck.Bad(
                    "HANDOVER amount ${tx.amount} != total $totalAtPoint (must drain fully)",
                )
        }

        val eff = tx.effects()
        custody += eff.custody
        margin += eff.margin

        // v3.39 足额规则: 总额运行余额恒非负
        // (v3.38 旧链两分量各自非负 → total 必然非负, 升级兼容)
        val totalNow = custody + margin
        if (totalNow < 0L) return OneCheck.Bad("total overdrawn ($totalNow)")

        return OneCheck.Ok(WalletBalances(custody, margin))
    }

    // ---- 余额与链接材料 ----

    /** 双账户余额 = Σ effects (推导值; TAMPERED 状态下仍可查看但不许支出) */
    fun balances(): WalletBalances = synchronized(lock) {
        if (verifiedCount == _txs.size) runningBalance
        else _txs.fold(WalletBalances(0, 0)) { acc, tx -> acc + tx.effects() }
    }

    /** 可用余额 (v3.39 合并语义) = custody + margin */
    fun balance(): Long = balances().total

    fun nextSeq(): Long = synchronized(lock) { (_txs.lastOrNull()?.seq ?: 0L) + 1L }

    fun nextPrevHash(): String = synchronized(lock) { _txs.lastOrNull()?.txHash ?: "" }

    fun isEmpty(): Boolean = synchronized(lock) { _txs.isEmpty() }

    /** 链是否已终结 (最后一笔为 HANDOVER —— 不可再追加任何交易) */
    fun isTerminal(): Boolean = synchronized(lock) { _txs.lastOrNull()?.type == TxType.HANDOVER }

    // ---- 足额预检 (权威记账方签名前调用) ----

    /** SPEND 足额 (v3.39): total (custody + margin) ≥ amount */
    fun canSpend(amount: Long): Boolean =
        amount > 0L && balances().total >= amount

    // ---- 追加 ----

    /**
     * 追加一笔已签名交易: 追加前以全链视角校验 (前缀 + 新交易),
     * 保证账本内永远只有可验证历史。TAMPERED 状态拒绝追加。
     */
    fun appendTx(tx: WalletTx): ChainCheck = synchronized(lock) {
        if (status == Status.TAMPERED)
            return@synchronized ChainCheck.Bad("ledger tampered: append rejected")
        if (isTerminal())
            return@synchronized ChainCheck.Bad("ledger terminal (HANDOVER): append rejected")
        // 前缀必须已全量验证 (load 或前次 append 之后), 增量校验才成立;
        // 否则回退整链重验 (理论仅 TAMPERED 前的异常态可达)。
        if (verifiedCount != _txs.size) {
            val extended = _txs + tx
            val check = verify(extended)
            if (check is ChainCheck.Bad) return@synchronized check
            val ok = check as ChainCheck.Ok
            _txs.add(tx)
            verifiedCount = _txs.size
            runningBalance = ok.balances
            return@synchronized ChainCheck.Ok(_txs.size, runningBalance)
        }

        // v3.59 增量路径: 只验新一笔 (规则与 [verify] 单一来源)
        when (val one = validateOne(tx, _txs.lastOrNull(), runningBalance, isFirst = _txs.isEmpty())) {
            is OneCheck.Bad -> return@synchronized ChainCheck.Bad(one.reason)
            is OneCheck.Ok -> {
                _txs.add(tx)
                verifiedCount++
                runningBalance = one.balances
                return@synchronized ChainCheck.Ok(_txs.size, runningBalance)
            }
        }
    }
}
