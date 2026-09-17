package com.securesocial.core.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

/**
 * DupProbe 单元测试 (v3.74 · P2-a)
 *
 * 覆盖: 确定性 / 输出格式 / 输入敏感性 (钱包 · 序号) / **不可链接性**
 * (相邻序号探针的比特分布) / 序号进度不可见 / 域分离 / 边界序号 /
 * 格式工具 (isWellFormed · normalize)。
 */
class DupProbeTest {

    private val ecdsa = EcdsaOperations()

    /** 两个不同钱包 (双花防护的"钱包"维度) */
    private val walletA = ecdsa.generateKeyPair()
    private val walletB = ecdsa.generateKeyPair()
    private val pubA: ByteArray = ecdsa.encodePublicKey(walletA.public)
    private val pubB: ByteArray = ecdsa.encodePublicKey(walletB.public)

    // ── 确定性与格式 ────────────────────────────────────────────────

    @Test
    fun `same input yields identical probe - receiver can recompute`() {
        val first = DupProbe.of(pubA, 7L)
        val second = DupProbe.of(pubA, 7L)
        assertEquals(first, second)
    }

    @Test
    fun `output is 64 lowercase hex chars`() {
        val probe = DupProbe.of(pubA, 1L)
        assertEquals(64, probe.length)
        assertTrue(probe.all { it in '0'..'9' || it in 'a'..'f' })
        assertTrue(probe.none { it.isUpperCase() })
    }

    @Test
    fun `PublicKey overload equals encoded-bytes overload`() {
        assertEquals(
            DupProbe.of(pubA, 42L),
            DupProbe.of(walletA.public, 42L)
        )
    }

    // ── 输入敏感性 ──────────────────────────────────────────────────

    @Test
    fun `different wallets produce different probes at same seq`() {
        assertNotEquals(DupProbe.of(pubA, 5L), DupProbe.of(pubB, 5L))
    }

    @Test
    fun `same wallet different seq produces different probes`() {
        assertNotEquals(DupProbe.of(pubA, 5L), DupProbe.of(pubA, 6L))
    }

    @Test
    fun `single bit flip in public key changes probe entirely`() {
        val tampered = pubA.copyOf()
        tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 0x01).toByte()
        val a = DupProbe.of(pubA, 3L)
        val b = DupProbe.of(tampered, 3L)
        assertNotEquals(a, b)
        // 雪崩: 探针为 32 字节 = 256 比特, 期望约半数 (128) 翻转
        val dist = hamming(hexToBytes(a), hexToBytes(b))
        assertTrue("雪崩距离应接近 128 (实测 $dist)", dist in 90..166)
    }

    // ── 不可链接性 (隐私核心) ───────────────────────────────────────

    @Test
    fun `consecutive seq probes are unlinkable - average hamming distance near 128 of 256 bits`() {
        val n = 512
        var total = 0
        for (i in 0 until n) {
            val a = hexToBytes(DupProbe.of(pubA, i.toLong()))
            val b = hexToBytes(DupProbe.of(pubA, (i + 1).toLong()))
            total += hamming(a, b)
        }
        val avg = total.toDouble() / n
        // 独立随机串: 期望 128, 标准差 8, 512 样本均值标准误 ≈ 0.36
        assertTrue("相邻序号探针平均汉明距离应接近 128 (实测 $avg)", avg > 115.0 && avg < 141.0)
    }

    @Test
    fun `seq progress is invisible - probe prefix spreads over many distinct values`() {
        val leadingChars = (0 until 512).map { DupProbe.of(pubA, it.toLong())[0] }.toSet()
        assertTrue(
            "连续 512 个序号的探针首字符应分散 (实测 ${leadingChars.size} 种)",
            leadingChars.size >= 10
        )
    }

    // ── 域分离 ──────────────────────────────────────────────────────

    @Test
    fun `domain separation - differs from bare hash and foreign domains`() {
        val md = MessageDigest.getInstance("SHA-256")
        val walletId = md.digest(pubA)

        // 无域前缀
        md.reset()
        md.update(walletId)
        md.update(byteArrayOf(0, 0, 0, 0, 0, 0, 0, 9))
        val bare = md.digest().toHexString()

        // 借用其它协议域
        val foreign = sha256(
            "SPARK-ID-ROTATION-V1".toByteArray(Charsets.UTF_8) + walletId +
                byteArrayOf(0, 0, 0, 0, 0, 0, 0, 9)
        ).toHexString()

        val probe = DupProbe.of(pubA, 9L)
        assertNotEquals(bare, probe)
        assertNotEquals(foreign, probe)
    }

    @Test
    fun `domain constant is distinct from sibling protocols`() {
        val siblings = setOf(
            "SPARK-WALLET-TX-V1",
            "SPARK-ID-ROTATION-V1",
            "RELAY-AUTH-V1",
            "SIGNAL-V1"
        )
        assertTrue(DupProbe.DOMAIN !in siblings)
        assertEquals("SPARK-TX-DUP-PROBE-V1", DupProbe.DOMAIN)
    }

    // ── 序号边界 ────────────────────────────────────────────────────

    @Test
    fun `boundary seq values are handled deterministically`() {
        val cases = longArrayOf(0L, 1L, 255L, 256L, 65_536L, Long.MAX_VALUE, -1L)
        val seen = HashSet<String>()
        cases.forEach { seq ->
            val p = DupProbe.of(pubA, seq)
            assertEquals(64, p.length)
            assertTrue(seen.add(p))      // 互不碰撞
        }
        // 大端编码: seq=256 与 seq=1 不得因截断而同值
        assertNotEquals(DupProbe.of(pubA, 256L), DupProbe.of(pubA, 1L))
    }

    // ── 格式工具 ────────────────────────────────────────────────────

    @Test
    fun `isWellFormed accepts canonical probes only`() {
        assertTrue(DupProbe.isWellFormed(DupProbe.of(pubA, 1L)))
        assertFalse(DupProbe.isWellFormed(""))                        // 空
        assertFalse(DupProbe.isWellFormed("a".repeat(63)))            // 短一位
        assertFalse(DupProbe.isWellFormed("a".repeat(65)))            // 长一位
        assertFalse(DupProbe.isWellFormed("z".repeat(64)))            // 非 hex
        assertFalse(DupProbe.isWellFormed("a".repeat(63) + " "))      // 尾随空白
    }

    @Test
    fun `normalize lowercases and rejects malformed`() {
        val probe = DupProbe.of(pubA, 11L)
        assertEquals(probe, DupProbe.normalize(probe.uppercase()))
        assertEquals(probe, DupProbe.normalize(probe))
        assertNull(DupProbe.normalize("nope"))
        assertNull(DupProbe.normalize(""))
        // 大小写必须收敛为同一键, 否则同一 (钱包, seq) 可被认领两次
        assertEquals(
            DupProbe.normalize(DupProbe.of(pubA, 3L).uppercase()),
            DupProbe.normalize(DupProbe.of(pubA, 3L))
        )
    }

    // ── 辅助 ────────────────────────────────────────────────────────

    private fun hamming(a: ByteArray, b: ByteArray): Int {
        var d = 0
        for (i in a.indices) {
            var x = (a[i].toInt() xor b[i].toInt()) and 0xFF
            while (x != 0) {
                d += x and 1
                x = x shr 1
            }
        }
        return d
    }

    private fun hexToBytes(s: String): ByteArray {
        val out = ByteArray(s.length / 2)
        for (i in out.indices) {
            out[i] = s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        return out
    }

    private fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    private fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }
}
