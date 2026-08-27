package com.securesocial.core.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ECDSA P-256 签名验签单元测试 (审计 P0-3, v3.29)
 *
 * 覆盖:
 * - 签名/验签往返
 * - 篡改数据 / 篡改签名 / 错误公钥 → 验签失败
 * - 公钥私钥编解码往返 (X.509 / PKCS#8)
 * - 签名随机化: 同数据两次签名不同 (ECDSA k 随机), 但均可验过
 * - 指纹与公钥绑定校验
 */
class EcdsaOperationsTest {

    private val ecdsa = EcdsaOperations()

    @Test
    fun `sign and verify roundtrip`() {
        val keyPair = ecdsa.generateKeyPair()
        val data = "RELAY-AUTH-V1|a1b2c3|nonce-bytes".toByteArray()
        val sig = ecdsa.sign(keyPair.private, data)
        assertTrue(ecdsa.verify(keyPair.public, data, sig))
    }

    @Test
    fun `tampered data fails verification`() {
        val keyPair = ecdsa.generateKeyPair()
        val data = "original".toByteArray()
        val sig = ecdsa.sign(keyPair.private, data)
        val tampered = "originalX".toByteArray()
        assertFalse(ecdsa.verify(keyPair.public, tampered, sig))
    }

    @Test
    fun `tampered signature fails verification`() {
        val keyPair = ecdsa.generateKeyPair()
        val data = "payload".toByteArray()
        val sig = ecdsa.sign(keyPair.private, data)
        sig[sig.size / 2] = (sig[sig.size / 2].toInt() xor 0x01).toByte()
        assertFalse(ecdsa.verify(keyPair.public, data, sig))
    }

    @Test
    fun `signature from another key fails verification`() {
        val signer = ecdsa.generateKeyPair()
        val attacker = ecdsa.generateKeyPair()
        val data = "payload".toByteArray()
        val forgedSig = ecdsa.sign(attacker.private, data)
        assertFalse("他人私钥签名不可冒充", ecdsa.verify(signer.public, data, forgedSig))
    }

    @Test
    fun `public key encoding roundtrip`() {
        val keyPair = ecdsa.generateKeyPair()
        val encoded = ecdsa.encodePublicKey(keyPair.public)
        val restored = ecdsa.decodePublicKey(encoded)
        assertArrayEquals(encoded, restored.encoded)

        // 还原的公钥仍可验签
        val data = "roundtrip".toByteArray()
        val sig = ecdsa.sign(keyPair.private, data)
        assertTrue(ecdsa.verify(restored, data, sig))
    }

    @Test
    fun `private key encoding roundtrip`() {
        val keyPair = ecdsa.generateKeyPair()
        val encoded = ecdsa.encodePrivateKey(keyPair.private)
        val restored = ecdsa.decodePrivateKey(encoded)

        // 还原的私钥可签名且原公钥可验
        val data = "prv-roundtrip".toByteArray()
        val sig = ecdsa.sign(restored, data)
        assertTrue(ecdsa.verify(keyPair.public, data, sig))
    }

    @Test
    fun `ecdsa signatures are randomized per call`() {
        val keyPair = ecdsa.generateKeyPair()
        val data = "same-data".toByteArray()
        val sig1 = ecdsa.sign(keyPair.private, data)
        val sig2 = ecdsa.sign(keyPair.private, data)
        assertNotEquals("ECDSA 每次签名应使用随机 k", sig1.toList(), sig2.toList())
        // 但两者均验签通过
        assertTrue(ecdsa.verify(keyPair.public, data, sig1))
        assertTrue(ecdsa.verify(keyPair.public, data, sig2))
    }

    @Test
    fun `garbage signature returns false instead of throwing`() {
        val keyPair = ecdsa.generateKeyPair()
        assertFalse(ecdsa.verify(keyPair.public, "data".toByteArray(), byteArrayOf(1, 2, 3)))
    }

    @Test
    fun `generated fingerprints bind to public keys`() {
        val keyPair = ecdsa.generateKeyPair()
        val fp = KeyFingerprint.compute(ecdsa.encodePublicKey(keyPair.public))
        assertTrue(KeyFingerprint.matches(keyPair.public, fp))
        assertTrue("指纹匹配应大小写不敏感", KeyFingerprint.matches(keyPair.public, fp.uppercase()))
        assertFalse(KeyFingerprint.matches(keyPair.public, "0".repeat(32)))
        assertNotEquals(fp, "0".repeat(32))
    }
}
