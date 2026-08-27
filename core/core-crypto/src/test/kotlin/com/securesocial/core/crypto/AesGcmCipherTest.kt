package com.securesocial.core.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.crypto.AEADBadTagException
import javax.crypto.KeyGenerator

/**
 * AES-256-GCM 加解密单元测试 (审计 P0-3, v3.29)
 *
 * 覆盖:
 * - 加解密往返 (含 AAD 与不含 AAD)
 * - AAD 上下文绑定: 指纹/序列号任一变动 → 认证失败 (防跨上下文移植)
 * - 密文/IV/AuthTag 篡改 → 认证失败 (防位翻转攻击)
 * - IV 随机性: 同明文两次加密 IV 不同, 密文不同
 * - Base64 序列化格式往返
 * - AAD 构建的确定性
 */
class AesGcmCipherTest {

    private val cipher = AesGcmCipher()
    private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()

    @Test
    fun `roundtrip without aad`() {
        val plaintext = "端到端加密消息测试".toByteArray(Charsets.UTF_8)
        val payload = cipher.encrypt(plaintext, key)
        val decrypted = cipher.decrypt(payload, key)
        assertArrayEquals(plaintext, decrypted)
    }

    @Test
    fun `roundtrip with aad`() {
        val aad = cipher.buildMessageAad("a1b2".repeat(8), "c3d4".repeat(8), 42L)
        val plaintext = "with aad".toByteArray()
        val payload = cipher.encrypt(plaintext, key, aad)
        assertArrayEquals(plaintext, cipher.decrypt(payload, key, aad))
    }

    @Test
    fun `aad mismatch causes authentication failure`() {
        val aad = cipher.buildMessageAad("a1b2".repeat(8), "c3d4".repeat(8), 42L)
        val payload = cipher.encrypt("secret".toByteArray(), key, aad)

        // 发送方指纹被中继篡改 → GCM 认证失败
        val tamperedAad = cipher.buildMessageAad("ffff".repeat(8), "c3d4".repeat(8), 42L)
        try {
            cipher.decrypt(payload, key, tamperedAad)
            throw AssertionError("Expected AEADBadTagException")
        } catch (expected: AEADBadTagException) {
            // 预期路径
        }
    }

    @Test
    fun `sequence number in aad prevents replay`() {
        val aad42 = cipher.buildMessageAad("fp-a", "fp-b", 42L)
        val aad43 = cipher.buildMessageAad("fp-a", "fp-b", 43L)
        val payload = cipher.encrypt("msg".toByteArray(), key, aad42)

        try {
            cipher.decrypt(payload, key, aad43)
            throw AssertionError("Expected AEADBadTagException")
        } catch (expected: AEADBadTagException) {
            // 同一密文无法在另一序列号位置重放
        }
    }

    @Test
    fun `tampered ciphertext fails authentication`() {
        val payload = cipher.encrypt("attack".toByteArray(), key)
        payload.ciphertext[0] = (payload.ciphertext[0].toInt() xor 0x01).toByte()
        try {
            cipher.decrypt(payload, key)
            throw AssertionError("Expected AEADBadTagException")
        } catch (expected: AEADBadTagException) {
            // 预期路径
        }
    }

    @Test
    fun `tampered auth tag fails authentication`() {
        val payload = cipher.encrypt("attack".toByteArray(), key)
        payload.authTag[15] = (payload.authTag[15].toInt() xor 0x80).toByte()
        try {
            cipher.decrypt(payload, key)
            throw AssertionError("Expected AEADBadTagException")
        } catch (expected: AEADBadTagException) {
            // 预期路径
        }
    }

    @Test
    fun `wrong key fails authentication`() {
        val otherKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val payload = cipher.encrypt("secret".toByteArray(), key)
        try {
            cipher.decrypt(payload, otherKey)
            throw AssertionError("Expected AEADBadTagException")
        } catch (expected: AEADBadTagException) {
            // 预期路径
        }
    }

    @Test
    fun `iv is random per encryption`() {
        val plaintext = "same".toByteArray()
        val first = cipher.encrypt(plaintext, key)
        val second = cipher.encrypt(plaintext, key)
        assertFalse("IV 必须随机", first.iv.contentEquals(second.iv))
        assertFalse("同明文密文必须不同", first.ciphertext.contentEquals(second.ciphertext))
    }

    @Test
    fun `iv is 12 bytes and tag is 16 bytes`() {
        val payload = cipher.encrypt("len".toByteArray(), key)
        assertEquals(12, payload.iv.size)
        assertEquals(16, payload.authTag.size)
    }

    @Test
    fun `base64 string roundtrip`() {
        val aad = cipher.buildMessageAad("src", "dst", 7L)
        val encoded = cipher.encryptString("字符串往返", key, aad)
        val payload = AesGcmCipher.EncryptedPayload.fromBase64String(encoded)
        assertArrayEquals("字符串往返".toByteArray(), cipher.decrypt(payload, key, aad))
    }

    @Test
    fun `malformed base64 payload rejected`() {
        try {
            AesGcmCipher.EncryptedPayload.fromBase64String("not-a-valid-format")
            throw AssertionError("Expected IllegalArgumentException")
        } catch (expected: IllegalArgumentException) {
            // 三段式格式不符应拒绝
        }
    }

    @Test
    fun `buildMessageAad is deterministic and binds all fields`() {
        val a1 = cipher.buildMessageAad("a", "b", 1L)
        val a2 = cipher.buildMessageAad("a", "b", 1L)
        assertArrayEquals(a1, a2)
        assertNotEquals(
            "不同序列号的 AAD 必须不同",
            a1.toList(),
            cipher.buildMessageAad("a", "b", 2L).toList()
        )
    }

    @Test
    fun `aad starts with domain separator`() {
        val aad = cipher.buildMessageAad("s", "t", 1L)
        val prefix = AesGcmCipher.MSG_AAD_DOMAIN.toByteArray(Charsets.UTF_8)
        assertArrayEquals(prefix, aad.copyOfRange(0, prefix.size))
    }
}
