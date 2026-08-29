package com.securesocial.core.wallet

import com.securesocial.core.crypto.EcdsaOperations
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * SPARK 钱包账本单测
 * v3.37: 规范化字节 / 编解码往返 / 全链校验 / 余额推导 /
 *        篡改-删除-回滚-重放四类攻击检出 / 域分离
 * v3.38: 双账户 (custody/margin) / DEPOSIT-WITHDRAW / 足额规则 /
 *        HANDOVER 终结语义 / 交接证书验证 / v3.37 链兼容
 * v3.39: 单账户合并 —— balance/canSpend 一律取 total, 足额改总额,
 *        HANDOVER 全额移交 total (旧链 custody 语义兼容)
 */
class WalletLedgerTest {

    /** JUnit4 无 assertIs: 类型断言辅助 */
    private inline fun <reified T> expectAny(x: Any): T {
        assertTrue("expected ${T::class.simpleName} but was: $x", x is T)
        return x as T
    }

    private inline fun <reified T : WalletLedger.ChainCheck> expect(x: WalletLedger.ChainCheck): T =
        expectAny<T>(x)

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

    @Test
    fun `tx list codec roundtrip for walletstate payload`() {
        val chain = standardChain()
        val decoded = TxJsonCodec.decodeList(TxJsonCodec.encodeList(chain))!!
        assertEquals(chain, decoded)
        assertNull(TxJsonCodec.decodeList("not-json"))
    }

    // ---- 链校验与余额 ----

    @Test
    fun `standard chain verifies and derives balance`() {
        val ledger = WalletLedger(pub)
        val check = ledger.load(standardChain())
        val ok = ok(check)
        assertEquals(4, ok.txCount)
        // margin: 4500 + 1000 - 30 + 10; custody: 0 (v3.37 链无托管流水)
        assertEquals(5480L, ok.balances.margin)
        assertEquals(0L, ok.balances.custody)
        // v3.39: 可用余额 = total (custody + margin)
        assertEquals(5480L, ok.balances.total)
        assertEquals(5480L, ledger.balance())
        assertEquals(WalletBalances(custody = 0, margin = 5480), ledger.balances())
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

    // ---- v3.38 划转交易 (v3.39: 仅旧链推导, total 效果恒为 0) ----

    @Test
    fun `transfer txs keep total invariant and spend checks total`() {
        // 提回 1000 (margin→custody) → 充值 400 (custody→margin) → 打赏 50
        val ledger = WalletLedger(pub)
        val g = signedTx(1, TxType.GENESIS, 4500)
        val wd = signedTx(2, TxType.WITHDRAW, 1000, memo = "to-custody", prevHash = g.txHash)
        val dep = signedTx(3, TxType.DEPOSIT, 400, memo = "recharge", prevHash = wd.txHash)
        val tip = signedTx(4, TxType.SPEND, 50, counterparty = "feed", memo = "tip", prevHash = dep.txHash)
        val ok = ok(ledger.load(listOf(g, wd, dep, tip)))
        // custody: 1000 - 400 = 600; margin: 4500 - 1000 + 400 - 50 = 3850
        assertEquals(WalletBalances(custody = 600, margin = 3850), ok.balances)
        // v3.39: 划转不改 total (4500-50=4450), 足额一律按 total
        assertEquals(4450L, ok.balances.total)
        assertTrue(ledger.canSpend(4450))
        assertTrue(!ledger.canSpend(4451))
    }

    @Test
    fun `overspend rejected by running-balance rule`() {
        // 权威记账方从不签超支交易: 链上出现负 total = 妥协信号 → TAMPERED
        val g = signedTx(1, TxType.GENESIS, 100)
        val overspend = signedTx(2, TxType.SPEND, 200, prevHash = g.txHash)
        val check = WalletLedger(pub).verify(listOf(g, overspend))
        bad(check)
    }

    @Test
    fun `spend may draw on custody after merge - single balance semantics`() {
        // v3.39 核心: custody 200 + margin 300, SPEND 400 —— 旧双账户
        // 规则 (margin < 400) 与新总额规则 (total 500 ≥ 400) 判定相反,
        // 合并语义下这笔交易合法 —— 托管与可用本就是同一个余额。
        val g = signedTx(1, TxType.GENESIS, 500)
        val wd = signedTx(2, TxType.WITHDRAW, 200, prevHash = g.txHash) // custody 200, margin 300
        val spend = signedTx(3, TxType.SPEND, 400, prevHash = wd.txHash) // total 100 ≥ 0
        val ok = ok(WalletLedger(pub).verify(listOf(g, wd, spend)))
        assertEquals(100L, ok.balances.total)
    }

    // ---- v3.38/v3.39 HANDOVER 终结语义 ----

    private fun handoverChain(newPubHex: String): List<WalletTx> {
        val g = signedTx(1, TxType.GENESIS, 4500)
        val wd = signedTx(2, TxType.WITHDRAW, 2000, memo = "to-custody", prevHash = g.txHash)
        val ho = signedTx(3, TxType.HANDOVER, 2000, counterparty = newPubHex, memo = "handover:2000", prevHash = wd.txHash)
        return listOf(g, wd, ho)
    }

    @Test
    fun `legacy handover draining only custody still verifies`() {
        // v3.38 旧链兼容: amount == custody (margin 不迁移) 依然合法
        val newKp = ecdsa.generateKeyPair()
        val newPubHex = HandoverCertificate.pubKeyHex(ecdsa.encodePublicKey(newKp.public))
        val ledger = WalletLedger(pub)
        val ok = ok(ledger.load(handoverChain(newPubHex)))
        // custody 全额移交 → 0; margin 2500 残留 (旧语义可弃) → total 2500
        assertEquals(WalletBalances(custody = 0, margin = 2500), ok.balances)
        assertEquals(2500L, ok.balances.total)
        assertTrue(ledger.isTerminal())
        // 终结链不可再追加
        val extra = signedTx(4, TxType.GRANT, 100, prevHash = ledger.nextPrevHash())
        bad(ledger.appendTx(extra))
    }

    @Test
    fun `v3_39 handover drains total balance`() {
        // v3.39: amount == total (custody 2000 + margin 2500 = 4500) 全额移交;
        // effects 后 custody = -2500 (分量透支) 但 total = 0 —— 总额规则下合法
        val newKp = ecdsa.generateKeyPair()
        val newPubHex = HandoverCertificate.pubKeyHex(ecdsa.encodePublicKey(newKp.public))
        val g = signedTx(1, TxType.GENESIS, 4500)
        val wd = signedTx(2, TxType.WITHDRAW, 2000, prevHash = g.txHash)
        val ho = signedTx(3, TxType.HANDOVER, 4500, counterparty = newPubHex, memo = "handover:4500", prevHash = wd.txHash)
        val ledger = WalletLedger(pub)
        val ok = ok(ledger.load(listOf(g, wd, ho)))
        assertEquals(0L, ok.balances.total)
        assertTrue(ledger.isTerminal())
    }

    @Test
    fun `tx after handover rejected by verify`() {
        val newKp = ecdsa.generateKeyPair()
        val newPubHex = HandoverCertificate.pubKeyHex(ecdsa.encodePublicKey(newKp.public))
        val chain = handoverChain(newPubHex)
        val after = signedTx(4, TxType.GRANT, 100, prevHash = chain.last().txHash)
        bad(WalletLedger(pub).verify(chain + after))
    }

    @Test
    fun `handover must drain balance fully`() {
        val newKp = ecdsa.generateKeyPair()
        val newPubHex = HandoverCertificate.pubKeyHex(ecdsa.encodePublicKey(newKp.public))
        val g = signedTx(1, TxType.GENESIS, 4500)
        val wd = signedTx(2, TxType.WITHDRAW, 2000, prevHash = g.txHash)
        // custody=2000, margin=2500, total=4500; 只交 1500 → 残留死账 → 违规
        val partial = signedTx(3, TxType.HANDOVER, 1500, counterparty = newPubHex, prevHash = wd.txHash)
        bad(WalletLedger(pub).verify(listOf(g, wd, partial)))
    }

    @Test
    fun `handover cannot be first tx`() {
        val newKp = ecdsa.generateKeyPair()
        val newPubHex = HandoverCertificate.pubKeyHex(ecdsa.encodePublicKey(newKp.public))
        val ho = signedTx(1, TxType.HANDOVER, 100, counterparty = newPubHex)
        bad(WalletLedger(pub).verify(listOf(ho)))
    }

    // ---- v3.38 交接证书 ----

    private fun buildCertificate(): Pair<HandoverCertificate, ByteArray> {
        val newKp = ecdsa.generateKeyPair()
        val newPubX509 = ecdsa.encodePublicKey(newKp.public)
        val newPubHex = HandoverCertificate.pubKeyHex(newPubX509)
        val oldPubX509 = ecdsa.encodePublicKey(pub)
        // 旧链: total 2000 (v3.39 全额移交语义)
        val g = signedTx(1, TxType.GENESIS, 2000)
        val unsignedHo = HandoverCertificate.buildHandoverTx(
            balanceSnapshot = 2000,
            newPubKeyHex = newPubHex,
            seq = 2,
            prevHash = g.txHash,
        )
        val sig = ecdsa.sign(priv, TxCanonical.bytes(unsignedHo))
        val hoTx = unsignedHo.copy(signature = Base64.getEncoder().encodeToString(sig))
        val cert = HandoverCertificate(
            oldPubKeyB64 = Base64.getEncoder().encodeToString(oldPubX509),
            newPubKeyB64 = Base64.getEncoder().encodeToString(newPubX509),
            handoverTx = hoTx,
        )
        return cert to newPubX509
    }

    @Test
    fun `certificate verifies and yields genesis for new chain`() {
        val (cert, newPubX509) = buildCertificate()
        val result = cert.verify(newPubX509)
        val ok = expectAny<HandoverCertificate.VerifyResult.Ok>(result)
        assertEquals(2000L, ok.balanceCarried)

        // 新链 GENESIS 承接 (新密钥签名 — 由新机 WalletKeyManager 完成, 此处验证结构)
        val genesis = HandoverCertificate.buildGenesisTx(
            balanceCarried = ok.balanceCarried,
            oldPubKeyHex = cert.oldPubKeyHex()!!,
            handoverTxHash = ok.handoverTxHash,
        )
        assertEquals(TxType.GENESIS, genesis.type)
        assertEquals(2000L, genesis.amount)
        assertEquals(1L, genesis.seq)
        assertTrue(genesis.memo!!.contains(ok.handoverTxHash.take(16)))

        // v2 规则: 交接承接 GENESIS 允许携带 counterparty (旧公钥 hex)
        val newKp2 = ecdsa.generateKeyPair()
        val sig2 = ecdsa.sign(newKp2.private, TxCanonical.bytes(genesis))
        val signed = genesis.copy(signature = Base64.getEncoder().encodeToString(sig2))
        val newLedger = WalletLedger(newKp2.public)
        val newCheck = ok(newLedger.load(listOf(signed)))
        // v3.39 合并语义: 承接余额直达可用 (total), 无需充值环节
        assertEquals(WalletBalances(custody = 2000, margin = 0), newCheck.balances)
        assertEquals(2000L, newLedger.balance())
        assertTrue(newLedger.canSpend(2000))
        assertTrue(!newLedger.canSpend(2001))
    }

    @Test
    fun `certificate encode-decode roundtrip`() {
        val (cert, _) = buildCertificate()
        val decoded = HandoverCertificate.decode(HandoverCertificate.encode(cert))
        assertNotNull(decoded)
        assertEquals(cert, decoded)
        assertNull(HandoverCertificate.decode("garbage"))
    }

    @Test
    fun `certificate bound to different device rejected`() {
        // 证书被拍照转发到另一台设备: 该设备的新公钥 ≠ 证书 counterparty → 拒绝
        val (cert, _) = buildCertificate()
        val otherKp = ecdsa.generateKeyPair()
        val otherPub = ecdsa.encodePublicKey(otherKp.public)
        val result = cert.verify(otherPub)
        expectAny<HandoverCertificate.VerifyResult.Bad>(result)
    }

    @Test
    fun `tampered certificate signature rejected`() {
        val (cert, newPubX509) = buildCertificate()
        val tamperedTx = cert.handoverTx.copy(amount = 999999) // 改金额不重签
        val tampered = cert.copy(handoverTx = tamperedTx)
        expectAny<HandoverCertificate.VerifyResult.Bad>(tampered.verify(newPubX509))
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
        // 序号间隙合法化后, 抽掉中段交易的检出依据是 prevHash 链断裂
        // (被删交易的后继 prevTxHash 指向已不存在的交易哈希), 不再是序号缺口。
        val chain = standardChain()
        val check = WalletLedger(pub).verify(chain.filterIndexed { i, _ -> i != 1 })
        bad(check)
    }

    // ---- 序号间隙 (v3.37 合法: 回调丢失烧号后续链) ----

    @Test
    fun `seq gap is legal - burned seq after lost callback`() {
        // 场景: seq 3 的交易已获 Vault 签名但回调丢失 (HWM=3 烧毁),
        // 镜像侧跳号续链: seq 4 直接接在 seq 2 之后, prevHash 正确链接。
        // 严格 +1 规则会把这种可用性恢复判为 TAMPERED —— 定稿为间隙合法。
        val g = signedTx(1, TxType.GENESIS, 4500)
        val grant = signedTx(2, TxType.GRANT, 1000, prevHash = g.txHash)
        val afterBurn = signedTx(4, TxType.SPEND, 30, memo = "burned-3-recovered", prevHash = grant.txHash)
        val ledger = WalletLedger(pub)
        val ok = ok(ledger.load(listOf(g, grant, afterBurn)))
        assertEquals(5470L, ok.balances.margin)
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
        assertEquals(5500L, ok.balances.margin)
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
        assertEquals(5472L, ok.balances.margin)
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
    fun `grant with counterparty rejected`() {
        // GRANT (系统赠金) 无对手方; GENESIS 例外 — 交接承接携带旧公钥 hex
        val g = signedTx(1, TxType.GRANT, 100, counterparty = "peer")
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

    // ---- v3.37 链兼容 (升级零重签) ----

    @Test
    fun `v3_37 chain verifies under v3_38 rules unchanged`() {
        // v3.37 生产链 = GENESIS/GRANT/RECEIVE/SPEND 的任意组合。
        // v3.38 新增规则 (足额/终结) 对其零影响: 足额规则下 v3.37 链
        // 的运行 margin 恒 ≥ 0 (Engine 门禁保证), custody 恒为 0。
        val ledger = WalletLedger(pub)
        val ok = ok(ledger.load(standardChain()))
        assertEquals(5480L, ok.balances.margin)
        assertEquals(0L, ok.balances.custody)
        assertTrue(!ledger.isTerminal())
    }

    // ---- v3.45: 赠金跨端契约冻结 ----

    @Test
    fun `wallet grant constants stay consistent`() {
        // 签名端金额白名单与 memo 前缀是跨端契约, 冻结防漂移:
        // MEMO_PREFIX / DAILY_GRANT_AMOUNT 与 Engine 侧 SparkEconomy 同值,
        // Vault 签名前强制 GRANT 金额 == DAILY_GRANT_AMOUNT (见 WalletGrant 头注)
        assertEquals("daily-grant:", WalletGrant.MEMO_PREFIX)
        assertEquals(1000L, WalletGrant.DAILY_GRANT_AMOUNT)
        assertTrue(WalletGrant.memoForDate(0L).startsWith("daily-grant:"))
        // 标准链中的赠金 memo 即按此契约构造
        assertEquals(
            "daily-grant:2026-08-27",
            WalletGrant.memoForDate(java.text.SimpleDateFormat(
                "yyyy-MM-dd", java.util.Locale.US
            ).parse("2026-08-27").time)
        )
    }

    private fun ledgerHash(chain: List<WalletTx>): String = chain.last().txHash
}
