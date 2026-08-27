package com.securesocial.core.wallet

import com.securesocial.core.crypto.EcdsaOperations
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * v3.37 · SPARK 钱包账本单测
 *
 * 覆盖: 规范化字节确定性 / 编解码往返 / 全链校验 / 余额推导 /
 * 篡改-删除-回滚-重放四类攻击检出 / 域分离。
 */
class WalletLedgerTest {

    /** JUnit4 无 assertIs: 类型断言辅助 */
    private inline fun <reified T : WalletLedger.ChainCheck> expect(x: WalletLedger.ChainCheck): T {
        assertTrue("expected ${T::class.simpleName} but was: $x", x is T)
        return x as T
    }

    private fun ok(x: WalletLedger.ChainCheck): WalletLedger.ChainCheck.Ok =
        expect<WalletLedger.ChainCheck.Ok>(x)

    private fun bad(x: WalletLedger.ChainCheck): WalletLedger.ChainCheck.Bad =
        expect<WalletLedger.ChainCheck.Bad>(x)

    private val ecdsa = EcdsaOperations()
    private val kp = ecdsa.generateKeyPair()
    private val pub = kp.public
    private val priv = kp.private

    /** 构造并签名一笔交易 */
    private fun signedTx(
        seq: Long,
        type: TxType,
        amount: Long,
        counterparty: String? = null,
        memo: String? = null,
        ts: Long = 1_700_000_000_000L + seq,
        prevHash: String = "",
    ): WalletTx {
        val unsigned = WalletTx(
            seq = seq, type = type, amount = amount,
            counterparty = counterparty, memo = memo,
            timestamp = ts, prevTxHash = prevHash,
        )
        val sig = ecdsa.sign(priv, TxCanonical.bytes(unsigned))
        return unsigned.copy(signature = Base64.getEncoder().encodeToString(sig))
    }

    /** 标准链: 迁移 4500 → 赠金 1000 → 消息计费 30 → 收到打赏 10 */
    private fun standardChain(): List<WalletTx> {
        val g = signedTx(1, TxType.GENESIS, 4500)
        val grant = signedTx(2, TxType.GRANT, 1000, memo = "daily-grant:2026-08-27", prevHash = g.txHash)
        val spend = signedTx(3, TxType.SPEND, 30, memo = "msg×3", prevHash = grant.txHash)
        val tip = signedTx(4, TxType.RECEIVE, 10, counterparty = "feed", memo = "tip", prevHash = spend.txHash)
        return listOf(g, grant, spend, tip)
    }

    // ---- 规范化序列化 ----

    @Test
    fun `canonical bytes are deterministic and domain separated`() {
        val tx = signedTx(1, TxType.GENESIS, 100)
        val again = tx.copy() // 同字段重建
        assertTrue(TxCanonical.bytes(tx).contentEquals(TxCanonical.bytes(again)))
        // 域前缀
        assertTrue(TxCanonical.bytes(tx).take(18)
            .toByteArray().decodeToString() == TxCanonical.DOMAIN)
        // 任一字段变化 → 字节变化
        val changed = tx.copy(amount = 101)
        assertNotEquals(TxCanonical.bytes(tx), TxCanonical.bytes(changed))
    }

    @Test
    fun `canonical bytes immune to JSON serialization drift`() {
        // JSON 字段顺序/空白与签名无关: 编码→解码→重签 对象与原交易等价
        val tx = signedTx(3, TxType.SPEND, 30, counterparty = "ab", prevHash = "cd")
        val decoded = TxJsonCodec.decode(TxJsonCodec.encode(tx))!!
        assertEquals(tx, decoded)
        assertTrue(TxCanonical.bytes(tx).contentEquals(TxCanonical.bytes(decoded)))
    }

    @Test
    fun `codec tolerates unknown fields`() {
        val tx = signedTx(2, TxType.GRANT, 1000)
        val json = TxJsonCodec.encode(tx).replaceFirst("{", """{"futureField":42,""")
        assertEquals(tx, TxJsonCodec.decode(json))
    }

    // ---- 链校验与余额 ----

    @Test
    fun `standard chain verifies and derives balance`() {
        val ledger = WalletLedger(pub)
        val check = ledger.load(standardChain())
        val ok = ok(check)
        assertEquals(4, ok.txCount)
        // 4500 + 1000 - 30 + 10
        assertEquals(5480L, ok.balance)
        assertEquals(5480L, ledger.balance())
        assertEquals(5L, ledger.nextSeq())
    }

    @Test
    fun `empty ledger is clean with zero balance`() {
        val ledger = WalletLedger(pub)
        val ok = ok(ledger.load(emptyList()))
        assertEquals(0, ok.txCount)
        assertEquals(0L, ledger.balance())
        assertEquals(1L, ledger.nextSeq())
        assertEquals("", ledger.nextPrevHash())
    }

    // ---- 攻击面: 篡改 ----

    @Test
    fun `tampered amount breaks signature`() {
        val chain = standardChain()
        val tampered = chain[2].copy(amount = 3) // 30 → 3, 签名不重算
        val modified = chain.toMutableList().also { it[2] = tampered }
        val check = WalletLedger(pub).verify(modified)
        bad(check)
    }

    @Test
    fun `signature swapped between txs is rejected`() {
        val chain = standardChain()
        // 把第 3 笔的签名挪到第 4 笔 (合法签名, 错误交易)
        val swapped = chain[3].copy(signature = chain[2].signature)
        val check = WalletLedger(pub).verify(chain.take(3) + swapped)
        bad(check)
    }

    // ---- 攻击面: 删除 (日志中段抽笔) ----

    @Test
    fun `deleted middle tx detected by broken prevHash link`() {
        // v3.37 序号间隙合法化后, 抽掉中段交易的检出依据是 prevHash 链断裂
        // (被删交易的后继 prevTxHash 指向已不存在的交易哈希), 不再是序号缺口。
        val chain = standardChain()
        val check = WalletLedger(pub).verify(chain.filterIndexed { i, _ -> i != 1 })
        bad(check)
    }

    // ---- 序号间隙 (v3.37 合法: 回调丢失烧号后续链) ----

    @Test
    fun `seq gap is legal - burned seq after lost callback`() {
        // 场景: seq 3 的交易已获 Vault 签名但回调丢失 (HWM=3 烧毁),
        // Engine 跳号续链: seq 4 直接接在 seq 2 之后, prevHash 正确链接。
        // 严格 +1 规则会把这种可用性恢复判为 TAMPERED —— 定稿为间隙合法。
        val g = signedTx(1, TxType.GENESIS, 4500)
        val grant = signedTx(2, TxType.GRANT, 1000, prevHash = g.txHash)
        val afterBurn = signedTx(4, TxType.SPEND, 30, memo = "burned-3-recovered", prevHash = grant.txHash)
        val ledger = WalletLedger(pub)
        val ok = ok(ledger.load(listOf(g, grant, afterBurn)))
        assertEquals(5470L, ok.balance)
        assertEquals(5L, ledger.nextSeq())
    }

    @Test
    fun `seq regression still rejected`() {
        // 间隙合法 ≠ 序号可回退: 回退意味着旧交易重排/替换 (回滚攻击形态)
        val g = signedTx(1, TxType.GENESIS, 4500)
        val grant = signedTx(2, TxType.GRANT, 1000, prevHash = g.txHash)
        val regressed = signedTx(2, TxType.SPEND, 30, prevHash = grant.txHash)
        bad(WalletLedger(pub).verify(listOf(g, grant, regressed)))
    }

    // ---- 攻击面: 回滚 (截断尾部) ----

    @Test
    fun `truncated tail still verifies - why vault high-water exists`() {
        // 诚实边界: 截断后的"合法前缀"本身自洽 —— 支出被裁掉,
        // 余额变大。这正是 Vault 侧高水位序号见证存在的原因
        // (旧 seq 的重签请求会被 Vault 拒绝), 本地校验单独无法检出。
        val chain = standardChain()
        val truncated = chain.take(2) // 裁掉 spend, 余额 5500 > 真实 5480
        val ok = ok(WalletLedger(pub).verify(truncated))
        assertEquals(5500L, ok.balance)
    }

    // ---- 攻击面: 重放 ----

    @Test
    fun `duplicate seq append rejected`() {
        val ledger = WalletLedger(pub)
        ledger.load(standardChain())
        val dup = signedTx(4, TxType.RECEIVE, 10, counterparty = "feed", prevHash = ledger.nextPrevHash())
        // seq 4 已存在 → append 全链校验失败
        bad(ledger.appendTx(dup))
        assertEquals(4, ledger.txs.size)
    }

    @Test
    fun `appended tx extends chain and updates balance`() {
        val ledger = WalletLedger(pub)
        ledger.load(standardChain())
        val next = signedTx(5, TxType.SPEND, 8, memo = "msg", prevHash = ledger.nextPrevHash())
        val ok = ok(ledger.appendTx(next))
        assertEquals(5472L, ok.balance)
        assertEquals(5, ledger.txs.size)
    }

    // ---- 结构规则 ----

    @Test
    fun `genesis not first is rejected`() {
        val chain = standardChain()
        val extra = signedTx(5, TxType.GENESIS, 999, prevHash = ledgerHash(chain))
        bad(WalletLedger(pub).verify(chain + extra))
    }

    @Test
    fun `genesis with counterparty rejected`() {
        val g = signedTx(1, TxType.GENESIS, 100, counterparty = "peer")
        bad(WalletLedger(pub).verify(listOf(g)))
    }

    @Test
    fun `tampered ledger freezes appends`() {
        val ledger = WalletLedger(pub)
        ledger.load(standardChain())
        // 人为注入坏账本 (篡改 amount 不重签)
        val bad = ledger.txs.toMutableList().also { it[0] = it[0].copy(amount = 999999) }
        ledger.load(bad)
        assertEquals(WalletLedger.Status.TAMPERED, ledger.status)
        val next = signedTx(9, TxType.SPEND, 1, prevHash = ledger.nextPrevHash())
        bad(ledger.appendTx(next))
    }

    private fun ledgerHash(chain: List<WalletTx>): String = chain.last().txHash
}
