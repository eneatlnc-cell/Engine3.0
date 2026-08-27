package com.securesocial.core.protocol

import kotlinx.serialization.json.Json
import kotlinx.serialization.encodeToString
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 协议消息封皮单元测试 (审计 P0-3, v3.29)
 *
 * 覆盖:
 * - MessageEnvelope JSON 序列化/反序列化往返 (中继路由字段)
 * - RelayAuth 挑战应答签名内容格式 (域分隔 ‖ 指纹 ‖ nonce)
 * - SignalPayload 载荷结构与验签链 (与 crypto.SignalAuth 实际格式一致)
 * - InviteCode 生成/校验/防枚举约束
 * - 协议常量边界
 */
class MessageEnvelopeTest {

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    // ── MessageEnvelope ─────────────────────────────────────────────

    @Test
    fun `envelope json roundtrip preserves routing fields`() {
        val envelope = MessageEnvelope(
            type = MessageType.MSG,
            source = "a".repeat(32),
            target = "b".repeat(32),
            payload = "base64ciphertext",
            seq = 42L,
            ts = 1723737600000L
        )
        val decoded = json.decodeFromString(MessageEnvelope.serializer(), json.encodeToString(envelope))
        assertEquals(envelope, decoded)
    }

    @Test
    fun `envelope type field survives json relay`() {
        // 中继只解析 type/source/target; 类型名必须与枚举严格对齐
        val raw = """{"type":"CHALLENGE","source":null,"target":"x","payload":null}"""
        val decoded = json.decodeFromString(MessageEnvelope.serializer(), raw)
        assertEquals(MessageType.CHALLENGE, decoded.type)
    }

    @Test
    fun `every message type roundtrips through json`() {
        for (type in MessageType.entries) {
            val envelope = MessageEnvelope(type = type)
            val decoded = json.decodeFromString(
                MessageEnvelope.serializer(), json.encodeToString(envelope)
            )
            assertEquals("类型 $type 必须可无损往返", type, decoded.type)
        }
    }

    @Test
    fun `unknown enum value is rejected`() {
        // 协议前向兼容: 未知类型必须拒绝而非静默吞掉 (中继仅路由已定义类型)
        val raw = """{"type":"TOTALLY_NEW_FRAME"}"""
        try {
            json.decodeFromString(MessageEnvelope.serializer(), raw)
            throw AssertionError("Expected SerializationException")
        } catch (expected: Exception) {
            assertTrue(expected is kotlinx.serialization.SerializationException)
        }
    }

    // ── RelayAuth (注册挑战应答) ─────────────────────────────────────

    @Test
    fun `relay auth content is domain separator plus fingerprint plus nonce`() {
        val nonce = ByteArray(32) { it.toByte() }
        val content = RelayAuth.signingContent("a1b2".repeat(8), nonce)
        assertArrayEquals(
            ("RELAY-AUTH-V1" + "a1b2".repeat(8)).toByteArray(Charsets.UTF_8) + nonce,
            content
        )
    }

    @Test
    fun `relay auth content is nonce-bound`() {
        val n1 = ByteArray(32) { 1 }
        val n2 = ByteArray(32) { 2 }
        val c1 = RelayAuth.signingContent("fp", n1)
        val c2 = RelayAuth.signingContent("fp", n2)
        assertNotEquals(c1.toList(), c2.toList())
    }

    // ── SignalPayload 契约 ──────────────────────────────────────────

    @Test
    fun `signal payload roundtrip`() {
        val payload = SignalPayload(ecdh = "ecdhB64", idpub = "pubB64", sig = "sigB64")
        val decoded = json.decodeFromString(SignalPayload.serializer(), json.encodeToString(payload))
        assertEquals(payload, decoded)
    }

    @Test
    fun `signal verification chain uses crypto SignalAuth format`() {
        // v3.29 回归: 验签链 = crypto.SignalAuth 内容 + 指纹匹配 (文档修订锚点)
        val ecdsa = com.securesocial.core.crypto.EcdsaOperations()
        val identity = ecdsa.generateKeyPair()
        val ecdhPub = ByteArray(91) { it.toByte() } // P-256 X.509 编码长度
        val senderFp = com.securesocial.core.crypto.KeyFingerprint.compute(identity.public)
        val receiverFp = "c".repeat(32)

        val content = com.securesocial.core.crypto.SignalAuth.signingContent(ecdhPub, senderFp, receiverFp)
        val sig = ecdsa.sign(identity.private, content)

        // 验证条件 1: idpub 指纹 == 信封 source
        assertTrue(com.securesocial.core.crypto.KeyFingerprint.matches(identity.public, senderFp))
        // 验证条件 2: 签名验证
        assertTrue(ecdsa.verify(identity.public, content, sig))
        // 篡改 ecdh 公钥 → 验签失败
        val tampered = ecdhPub.copyOf().also { it[0] = (it[0] + 1).toByte() }
        assertFalse(ecdsa.verify(identity.public, com.securesocial.core.crypto.SignalAuth.signingContent(tampered, senderFp, receiverFp), sig))
    }

    // ── InviteCode ──────────────────────────────────────────────────

    @Test
    fun `invite code generation is valid and unambiguous`() {
        repeat(50) {
            val code = InviteCode.generate()
            assertTrue("生成的邀请码必须合法: $code", InviteCode.isValid(code))
        }
    }

    @Test
    fun `invite code alphabet excludes confusable characters`() {
        // 字母表剔除 I O 0 1 (口播/截图友好)
        for (ch in InviteCode.ALPHABET) {
            assertFalse(ch in "IO01")
        }
    }

    @Test
    fun `invite code validation rejects bad input`() {
        assertFalse(InviteCode.isValid("SHORT"))
        assertFalse(InviteCode.isValid("TOOLONGCODE123"))
        assertFalse(InviteCode.isValid("ABCDEFGI")) // 含 I
        assertFalse(InviteCode.isValid("ABCDEFG0")) // 含 0
        assertFalse(InviteCode.isValid("abcdefgh")) // 小写
        assertTrue(InviteCode.isValid("ABCDEFGH"))
    }

    // ── 协议常量 ────────────────────────────────────────────────────

    @Test
    fun `protocol constants stay within documented budgets`() {
        // v3.17.1 消息预算: 40KB 文本/48KB 媒体 → 加密+Base64 后 < 128KB
        assertTrue(ProtocolConstants.MAX_PAYLOAD_SIZE == 128 * 1024)
        // 群成员上限与限流护栏存在且为正
        assertTrue(GroupLimits.MAX_MEMBERS == 200)
        assertTrue(ProtocolConstants.GROUP_FANOUT_MSG_PER_SECOND > 0)
        assertTrue(ProtocolConstants.GLOBAL_FANOUT_BYTES_PER_SECOND > 0)
        assertTrue(
            "群级突发必须不大于全局突发",
            ProtocolConstants.GROUP_FANOUT_BYTES_BURST <= ProtocolConstants.GLOBAL_FANOUT_BYTES_BURST
        )
    }
}
