package com.securesocial.core.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * KeyFingerprint / KeyPayloadSerializer / SignalAuth 单元测试 (审计 P0-3, v3.29)
 */
class KeyFingerprintSerializerSignalTest {

    private val ecdsa = EcdsaOperations()

    // ── KeyFingerprint ──────────────────────────────────────────────

    @Test
    fun `fingerprint is 32 lowercase hex chars`() {
        val keyPair = ecdsa.generateKeyPair()
        val fp = KeyFingerprint.compute(keyPair.public)
        assertEquals(32, fp.length)
        assertTrue(fp.matches(Regex("[0-9a-f]{32}")))
    }

    @Test
    fun `fingerprint is deterministic and key-bound`() {
        val keyPair = ecdsa.generateKeyPair()
        val other = ecdsa.generateKeyPair()
        assertEquals(KeyFingerprint.compute(keyPair.public), KeyFingerprint.compute(keyPair.public))
        assertNotEquals("不同公钥指纹必须不同", KeyFingerprint.compute(keyPair.public), KeyFingerprint.compute(other.public))
    }

    @Test
    fun `fingerprint from encoded bytes equals fingerprint from key object`() {
        val keyPair = ecdsa.generateKeyPair()
        assertEquals(
            KeyFingerprint.compute(keyPair.public),
            KeyFingerprint.compute(ecdsa.encodePublicKey(keyPair.public))
        )
    }

    // ── KeyPayloadSerializer ────────────────────────────────────────

    @Test
    fun `key payload json roundtrip`() {
        val keyPair = ecdsa.generateKeyPair()
        val pub = ecdsa.encodePublicKey(keyPair.public)
        val prv = ecdsa.encodePrivateKey(keyPair.private)

        val json = KeyPayloadSerializer.serialize(pub, prv)
        val restored = KeyPayloadSerializer.deserialize(json)

        assertTrue(restored != null)
        assertArrayEquals(pub, restored!!.publicKey)
        assertArrayEquals(prv, restored.privateKey)
        assertEquals("P-256", restored.curve)
    }

    @Test
    fun `payload json contains no plaintext private key marker`() {
        // 私钥在 JSON 中必须 Base64 编码, 不允许 PKCS#8 明文 (PEM 头) 出现
        val keyPair = ecdsa.generateKeyPair()
        val json = KeyPayloadSerializer.serialize(
            ecdsa.encodePublicKey(keyPair.public),
            ecdsa.encodePrivateKey(keyPair.private)
        )
        assertFalse(json.contains("PRIVATE KEY"))
        assertFalse(json.contains("-----"))
    }

    @Test
    fun `unsupported curve rejected`() {
        val keyPair = ecdsa.generateKeyPair()
        val json = KeyPayloadSerializer.serialize(
            ecdsa.encodePublicKey(keyPair.public),
            ecdsa.encodePrivateKey(keyPair.private)
        ).replace("P-256", "P-384")
        assertNull("非 P-256 曲线必须拒绝", KeyPayloadSerializer.deserialize(json))
    }

    @Test
    fun `garbage json returns null`() {
        assertNull(KeyPayloadSerializer.deserialize("not json at all"))
        assertNull(KeyPayloadSerializer.deserialize("{\"pub\":\"!!\",\"prv\":\"!!\",\"curve\":\"P-256\"}"))
    }

    @Test
    fun `validate accepts a genuine pair and rejects a mismatched pair`() {
        val genuine = ecdsa.generateKeyPair()
        val other = ecdsa.generateKeyPair()

        val ok = KeyPayloadSerializer.deserialize(
            KeyPayloadSerializer.serialize(
                ecdsa.encodePublicKey(genuine.public),
                ecdsa.encodePrivateKey(genuine.private)
            )
        )
        assertTrue(KeyPayloadSerializer.validate(ok!!))

        // 公钥换成他人的 → 私钥签名公钥验不过
        val mismatched = KeyPayloadSerializer.deserialize(
            KeyPayloadSerializer.serialize(
                ecdsa.encodePublicKey(other.public),
                ecdsa.encodePrivateKey(genuine.private)
            )
        )
        assertTrue(mismatched != null)
        assertFalse("公私钥不匹配必须拒绝", KeyPayloadSerializer.validate(mismatched!!))
    }

    // ── SignalAuth (v3.29 文档修订后的实际运行格式) ─────────────────

    @Test
    fun `signal auth content format is domain then fingerprints then pubkey`() {
        val pub = byteArrayOf(1, 2, 3, 4)
        val content = SignalAuth.signingContent(pub, "AAAA", "BBBB")
        val expected = ("SIGNAL-V1" + "AAAA" + "BBBB").toByteArray(Charsets.UTF_8) + pub
        assertArrayEquals(expected, content)
    }

    @Test
    fun `signal auth content is receiver-bound`() {
        val pub = byteArrayOf(9, 9, 9)
        val forBob = SignalAuth.signingContent(pub, "alice", "bob")
        val forEve = SignalAuth.signingContent(pub, "alice", "eve")
        assertNotEquals("定向信令: 换接收方指纹必须改变签名内容", forBob.toList(), forEve.toList())
    }

    @Test
    fun `signal auth content is pubkey-bound`() {
        val content1 = SignalAuth.signingContent(byteArrayOf(1), "a", "b")
        val content2 = SignalAuth.signingContent(byteArrayOf(2), "a", "b")
        assertNotEquals("ECDH 公钥替换必须改变签名内容 (防 MITM 替换公钥)", content1.toList(), content2.toList())
    }

    @Test
    fun `signal auth verify flow end to end`() {
        // 模拟: Alice 经 Vault 用身份私钥对 ECDH 信令签名, Bob 验签
        val aliceId = ecdsa.generateKeyPair()
        val aliceEcdh = EcdhKeyAgreement().generateKeyPair()
        val aliceFp = KeyFingerprint.compute(aliceId.public)
        val bobFp = "b".repeat(32)
        val ecdhPubBytes = aliceEcdh.public.encoded

        val content = SignalAuth.signingContent(ecdhPubBytes, aliceFp, bobFp)
        val sig = ecdsa.sign(aliceId.private, content)

        // 验签侧以相同算法重建内容
        val rebuilt = SignalAuth.signingContent(ecdhPubBytes, aliceFp, bobFp)
        assertTrue(ecdsa.verify(aliceId.public, rebuilt, sig))
        assertTrue(KeyFingerprint.matches(aliceId.public, aliceFp))
    }
}
