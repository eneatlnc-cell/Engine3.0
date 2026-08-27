package com.securesocial.core.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ECDH P-256 密钥协商单元测试 (审计 P0-3, v3.29)
 *
 * 覆盖:
 * - 双方各自 ECDH + 相同 info 派生出相同会话密钥
 * - 交换方向无关: A(privA, pubB) == B(privB, pubA)
 * - sessionKeyInfo 双指纹字典序规范化: 参数顺序无关
 * - 不同 info 派生不同密钥 (域分隔有效性)
 * - 不同密钥对派生不同会话密钥
 */
class EcdhKeyAgreementTest {

    private val ecdh = EcdhKeyAgreement()

    @Test
    fun `both parties derive the same session key`() {
        val alice = ecdh.generateKeyPair()
        val bob = ecdh.generateKeyPair()

        val aliceKey = ecdh.agreeAndDerive(alice.private, bob.public, "ENGINE-SESSION-V1|a|b")
        val bobKey = ecdh.agreeAndDerive(bob.private, alice.public, "ENGINE-SESSION-V1|a|b")

        assertArrayEquals(aliceKey.encoded, bobKey.encoded)
        assertEquals("AES", aliceKey.algorithm)
        assertEquals(32, aliceKey.encoded.size) // AES-256
    }

    @Test
    fun `raw agree is symmetric`() {
        val alice = ecdh.generateKeyPair()
        val bob = ecdh.generateKeyPair()

        val s1 = ecdh.agree(alice.private, bob.public)
        val s2 = ecdh.agree(bob.private, alice.public)

        assertArrayEquals(s1, s2)
    }

    @Test
    fun `sessionKeyInfo is order independent`() {
        val infoAB = EcdhKeyAgreement.sessionKeyInfo("aaaa", "zzzz")
        val infoBA = EcdhKeyAgreement.sessionKeyInfo("zzzz", "aaaa")
        assertEquals("双指纹须按字典序规范化, 与参数顺序无关", infoAB, infoBA)
        assertTrue(infoAB.startsWith(EcdhKeyAgreement.SESSION_KEY_DOMAIN))
    }

    @Test
    fun `different info derives different keys`() {
        val alice = ecdh.generateKeyPair()
        val bob = ecdh.generateKeyPair()
        val secret = ecdh.agree(alice.private, bob.public)

        val k1 = ecdh.deriveSessionKey(secret, "ENGINE-SESSION-V1|a|b")
        val k2 = ecdh.deriveSessionKey(secret, "ENGINE-SESSION-V1|other-context")

        assertNotEquals("HKDF info 域分隔必须产生不同密钥", k1.encoded.toList(), k2.encoded.toList())
    }

    @Test
    fun `different key pairs derive different session keys`() {
        val alice = ecdh.generateKeyPair()
        val bob = ecdh.generateKeyPair()
        val eve = ecdh.generateKeyPair()

        val legit = ecdh.agreeAndDerive(alice.private, bob.public, "same-info")
        val mitm = ecdh.agreeAndDerive(alice.private, eve.public, "same-info")

        assertNotEquals(legit.encoded.toList(), mitm.encoded.toList())
    }

    @Test
    fun `derived session key actually works with AES-GCM`() {
        val alice = ecdh.generateKeyPair()
        val bob = ecdh.generateKeyPair()
        val info = EcdhKeyAgreement.sessionKeyInfo("fpA", "fpB")

        val aliceKey = ecdh.agreeAndDerive(alice.private, bob.public, info)
        val bobKey = ecdh.agreeAndDerive(bob.private, alice.public, info)

        val cipher = AesGcmCipher()
        val payload = cipher.encrypt("会话密钥可用性".toByteArray(), aliceKey)
        assertArrayEquals("会话密钥可用于对称加解密", "会话密钥可用性".toByteArray(), cipher.decrypt(payload, bobKey))
    }
}
