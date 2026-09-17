package com.securesocial.core.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * IdentityRotationStatement 单元测试 (v3.73 · P1-b 预埋)
 *
 * 覆盖: 签发→验签往返 / JSON 往返 / 规范化确定性 / 篡改拦截
 * (newPub / ts / oldFp / 版本) / 时钟窗口 / 恶意输入容错。
 */
class IdentityRotationStatementTest {

    private val ecdsa = EcdsaOperations()

    private val nowMs = 1_728_000_000_000L

    /** 旧身份 (轮换主体) 与新身份 (接替者) 密钥对 */
    private val oldPair = ecdsa.generateKeyPair()
    private val newPair = ecdsa.generateKeyPair()

    private val oldFp = KeyFingerprint.compute(oldPair.public)
    private val newPubBytes = ecdsa.encodePublicKey(newPair.public)
    private val newPubB64 = Base64.getEncoder().encodeToString(newPubBytes)
    private val newFp = KeyFingerprint.compute(newPair.public)

    private fun signedStatement(): IdentityRotationStatement =
        IdentityRotationStatement.draft(oldFp, newPubBytes, nowMs).sign(oldPair.private)

    // ── 签发 → 验签往返 ─────────────────────────────────────────────

    @Test
    fun `sign then verify roundtrip succeeds`() {
        val stmt = signedStatement()
        assertNotNull(stmt.signatureB64)
        assertTrue(stmt.verify(oldPubBytes = ecdsa.encodePublicKey(oldPair.public), nowMs = nowMs))
    }

    @Test
    fun `draft derives newFp from newPub`() {
        val stmt = IdentityRotationStatement.draft(oldFp, newPubBytes, nowMs)
        assertEquals(newFp, stmt.newFp)
        assertEquals(oldFp, stmt.oldFp)
        assertNull(stmt.signatureB64)
    }

    @Test
    fun `unsigned statement fails verification`() {
        val stmt = IdentityRotationStatement.draft(oldFp, newPubBytes, nowMs)
        assertFalse(stmt.verify(oldPubBytes = ecdsa.encodePublicKey(oldPair.public), nowMs = nowMs))
    }

    // ── 规范化字节 ──────────────────────────────────────────────────

    @Test
    fun `canonical bytes are deterministic`() {
        val a = IdentityRotationStatement.draft(oldFp, newPubBytes, nowMs).canonicalBytes()
        val b = IdentityRotationStatement.draft(oldFp, newPubBytes, nowMs).canonicalBytes()
        assertArrayEquals(a, b)
    }

    @Test
    fun `canonical bytes start with domain separator`() {
        val bytes = signedStatement().canonicalBytes()
        val domain = IdentityRotationStatement.DOMAIN.toByteArray(Charsets.UTF_8)
        assertTrue(bytes.size > domain.size)
        for (i in domain.indices) {
            assertEquals(domain[i], bytes[i])
        }
    }

    @Test
    fun `canonical bytes differ across timestamp`() {
        val a = IdentityRotationStatement.draft(oldFp, newPubBytes, nowMs).canonicalBytes()
        val b = IdentityRotationStatement.draft(oldFp, newPubBytes, nowMs + 1).canonicalBytes()
        assertFalse(a.contentEquals(b))
    }

    // ── 篡改拦截 ────────────────────────────────────────────────────

    @Test
    fun `tampered newPub fails verification`() {
        val stmt = signedStatement()
        val otherPub = ecdsa.encodePublicKey(ecdsa.generateKeyPair().public)
        val tampered = stmt.copy(newPubB64 = Base64.getEncoder().encodeToString(otherPub))
        // newFp 与 newPub 不再自洽 → 拦截 (签名本身也无法通过)
        assertFalse(tampered.verify(oldPubBytes = ecdsa.encodePublicKey(oldPair.public), nowMs = nowMs))
    }

    @Test
    fun `tampered timestamp fails verification`() {
        val stmt = signedStatement()
        val tampered = stmt.copy(timestamp = nowMs + 1)
        assertFalse(tampered.verify(oldPubBytes = ecdsa.encodePublicKey(oldPair.public), nowMs = nowMs))
    }

    @Test
    fun `tampered oldFp fails verification`() {
        val stmt = signedStatement()
        val stranger = ecdsa.generateKeyPair()
        val tampered = stmt.copy(oldFp = KeyFingerprint.compute(stranger.public))
        assertFalse(tampered.verify(oldPubBytes = ecdsa.encodePublicKey(oldPair.public), nowMs = nowMs))
    }

    @Test
    fun `wrong old public key fails verification`() {
        val stmt = signedStatement()
        val stranger = ecdsa.generateKeyPair()
        assertFalse(stmt.verify(oldPubBytes = ecdsa.encodePublicKey(stranger.public), nowMs = nowMs))
    }

    @Test
    fun `signature by new key instead of old key fails verification`() {
        // 声明必须由旧私钥签署 —— 新私钥自签不构成合法轮换授权
        val stmt = IdentityRotationStatement.draft(oldFp, newPubBytes, nowMs).sign(newPair.private)
        assertFalse(stmt.verify(oldPubBytes = ecdsa.encodePublicKey(oldPair.public), nowMs = nowMs))
    }

    @Test
    fun `wrong protocol version fails verification`() {
        val stmt = signedStatement()
        val tampered = stmt.copy(version = IdentityRotationStatement.VERSION + 1)
        assertFalse(tampered.verify(oldPubBytes = ecdsa.encodePublicKey(oldPair.public), nowMs = nowMs))
    }

    // ── 时钟窗口 ────────────────────────────────────────────────────

    @Test
    fun `timestamp beyond future skew window fails`() {
        val stmt = signedStatement()
        val farFuture = nowMs + IdentityRotationStatement.MAX_CLOCK_SKEW_MS + 1
        assertFalse(stmt.verify(oldPubBytes = ecdsa.encodePublicKey(oldPair.public), nowMs = farFuture))
    }

    @Test
    fun `stale statement beyond past skew window fails`() {
        val stmt = signedStatement()
        val farPast = nowMs - IdentityRotationStatement.MAX_CLOCK_SKEW_MS - 1
        assertFalse(stmt.verify(oldPubBytes = ecdsa.encodePublicKey(oldPair.public), nowMs = farPast))
    }

    @Test
    fun `clock check can be disabled for offline batch verification`() {
        val stmt = signedStatement()
        val farPast = nowMs - IdentityRotationStatement.MAX_CLOCK_SKEW_MS - 1
        assertTrue(
            stmt.verify(
                oldPubBytes = ecdsa.encodePublicKey(oldPair.public),
                nowMs = farPast,
                checkClock = false
            )
        )
    }

    // ── JSON 运输形态 ───────────────────────────────────────────────

    @Test
    fun `serialize then deserialize roundtrip preserves statement`() {
        val stmt = signedStatement()
        val raw = IdentityRotationStatement.serialize(stmt)
        val parsed = IdentityRotationStatement.deserialize(raw)
        assertNotNull(parsed)
        assertEquals(stmt.version, parsed!!.version)
        assertEquals(stmt.oldFp, parsed.oldFp)
        assertEquals(stmt.newFp, parsed.newFp)
        assertEquals(stmt.newPubB64, parsed.newPubB64)
        assertEquals(stmt.timestamp, parsed.timestamp)
        assertEquals(stmt.signatureB64, parsed.signatureB64)
        assertTrue(parsed.verify(oldPubBytes = ecdsa.encodePublicKey(oldPair.public), nowMs = nowMs))
    }

    @Test
    fun `deserialize rejects malformed input`() {
        assertNull(IdentityRotationStatement.deserialize("not json at all"))
        assertNull(IdentityRotationStatement.deserialize("{\"version\":1}|sig:AAA"))
        // 缺签名尾段
        assertNull(
            IdentityRotationStatement.deserialize(
                "{\"version\":1,\"oldFp\":\"a\",\"newFp\":\"b\",\"newPub\":\"c\",\"ts\":1}"
            )
        )
    }

    @Test
    fun `deserialize tolerates unknown json fields`() {
        val stmt = signedStatement()
        val raw = IdentityRotationStatement.serialize(stmt)
        val injected = raw.replace(
            "{\"version\"",
            "{\"evil\":\"x\",\"version\""
        )
        val parsed = IdentityRotationStatement.deserialize(injected)
        assertNotNull(parsed)
    }
}
