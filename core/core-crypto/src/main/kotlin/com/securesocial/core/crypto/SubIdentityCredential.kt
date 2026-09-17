package com.securesocial.core.crypto

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.security.PrivateKey
import java.security.PublicKey
import java.util.Base64

/**
 * 子身份凭证 (v3.76.0 · P1 DID 派生)
 *
 * 语义: **主 DID 授权派生子身份** —— Vault 的主 DID (全局钱包) 私钥
 * 对子身份公钥签名, 证明"此子身份由本 Vault 主 DID 授权派生"。
 *
 * 与 [IdentityRotationStatement] 的区别:
 * - IdentityRotationStatement: 旧子身份私钥 → 新子身份公钥 ("我授权接班人")
 * - SubIdentityCredential:       主 DID 私钥 → 子身份公钥 ("我派生这个子身份")
 *
 * 验证者 (联系人) 可凭主 DID 公钥验签, 确认子身份的派生归属。
 * 主 DID 公钥可经 E2E 通道或中继 HELLO 声明获取 (非秘密材料)。
 *
 * 规范化字节布局 (域分离, 防跨协议重放):
 * `DOMAIN || frame(mainDidFp) || frame(subFp) || frame(subPub)`
 */
@Serializable
data class SubIdentityCredentialPayload(
    val version: Int,        // 协议版本 (当前 = 1)
    val mainDidFp: String,   // 主 DID 指纹 (全局钱包公钥指纹)
    val subFp: String,       // 子身份指纹
    val subPub: String,      // 子身份公钥 (X.509 Base64)
    val ts: Long             // 签发时间戳 (ms)
)

data class SubIdentityCredential(
    val payload: SubIdentityCredentialPayload,
    val signatureB64: String?   // 主 DID 私钥对 canonicalBytes 的签名 (DER, Base64)
) {
    /** 无签名规范化字节 (签名对象) */
    fun canonicalBytes(): ByteArray = canonicalBytes(
        payload.version, payload.mainDidFp, payload.subFp, payload.subPub, payload.ts
    )

    /**
     * 用主 DID (钱包) 私钥签署, 返回带签副本。
     *
     * 签发方: Vault 内 `PrivateKeyManager`, 使用 `KeystoreManager.getOrCreateWalletSigningKeyPair()`
     * 的 TEE 硬件私钥 (与钱包交易签名同密钥)。
     */
    fun sign(mainDidPrivateKey: PrivateKey): SubIdentityCredential {
        val ecdsa = EcdsaOperations()
        val sig = ecdsa.sign(mainDidPrivateKey, canonicalBytes())
        return copy(signatureB64 = Base64.getEncoder().encodeToString(sig))
    }

    /**
     * 验证子身份凭证 (验证者视角)。
     *
     * 四重校验:
     * 1. 协议版本匹配;
     * 2. 声明内部自洽: subFp == compute(subPub);
     * 3. 主体匹配: mainDidFp == compute(验证者持有的主 DID 公钥);
     * 4. 签名可被**主 DID 公钥**验证 (主 DID 私钥持有证明)。
     *
     * @param mainDidPubBytes 主 DID (钱包) 公钥 (X.509 编码字节)
     * @return true = 凭证有效, 子身份确由该主 DID 派生
     */
    fun verify(mainDidPubBytes: ByteArray): Boolean {
        if (payload.version != VERSION) return false
        if (signatureB64.isNullOrEmpty()) return false
        return try {
            val ecdsa = EcdsaOperations()
            val subPubBytes = Base64.getDecoder().decode(payload.subPub)
            // ② 子身份内部自洽
            if (payload.subFp != KeyFingerprint.compute(ecdsa.decodePublicKey(subPubBytes))) return false
            // ③ 主 DID 主体匹配
            if (payload.mainDidFp != KeyFingerprint.compute(ecdsa.decodePublicKey(mainDidPubBytes))) return false
            // ④ 主 DID 私钥持有证明
            val sig = Base64.getDecoder().decode(signatureB64)
            ecdsa.verify(ecdsa.decodePublicKey(mainDidPubBytes), canonicalBytes(), sig)
        } catch (e: Exception) {
            false
        }
    }

    companion object {
        /** 签名域 (域分离: 与 RELAY-AUTH-V1 / SIGNAL-V1 / SPARK-ID-ROTATION-V1 互斥) */
        const val DOMAIN = "SPARK-SUBID-CRED-V1"

        /** 当前协议版本 */
        const val VERSION = 1

        private val domainBytes = DOMAIN.toByteArray(Charsets.UTF_8)

        private val json = Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
        }

        /**
         * 构造一个未签名的子身份凭证。
         *
         * @param mainDidFp 主 DID 指纹 (全局钱包公钥指纹)
         * @param subPubBytes 子身份公钥 (X.509 编码字节)
         * @param nowMs 签发时间戳
         */
        fun draft(
            mainDidFp: String,
            subPubBytes: ByteArray,
            nowMs: Long = System.currentTimeMillis()
        ): SubIdentityCredential {
            val ecdsa = EcdsaOperations()
            val subFp = KeyFingerprint.compute(ecdsa.decodePublicKey(subPubBytes))
            val payload = SubIdentityCredentialPayload(
                version = VERSION,
                mainDidFp = mainDidFp,
                subFp = subFp,
                subPub = Base64.getEncoder().encodeToString(subPubBytes),
                ts = nowMs
            )
            return SubIdentityCredential(payload, null)
        }

        /** 无签名规范化字节 (静态入口) */
        fun canonicalBytes(
            version: Int,
            mainDidFp: String,
            subFp: String,
            subPubB64: String,
            ts: Long
        ): ByteArray {
            val out = ArrayList<ByteArray>()
            out.add(domainBytes)
            out.add(u32(version))
            out.add(frame(mainDidFp.toByteArray(Charsets.UTF_8)))
            out.add(frame(subFp.toByteArray(Charsets.UTF_8)))
            out.add(frame(subPubB64.toByteArray(Charsets.UTF_8)))
            out.add(u64(ts))

            var size = 0
            out.forEach { size += it.size }
            val buf = ByteArray(size)
            var off = 0
            out.forEach { chunk ->
                System.arraycopy(chunk, 0, buf, off, chunk.size)
                off += chunk.size
            }
            return buf
        }

        // ---- JSON 运输形态 ----

        fun serialize(cred: SubIdentityCredential): String {
            val payloadJson = json.encodeToString(cred.payload)
            val sig = cred.signatureB64 ?: ""
            return payloadJson + "|sig:" + sig
        }

        fun deserialize(raw: String): SubIdentityCredential? {
            return try {
                val sigIdx = raw.lastIndexOf("|sig:")
                if (sigIdx < 0) return null
                val payloadPart = raw.substring(0, sigIdx)
                val sigB64 = raw.substring(sigIdx + "|sig:".length)
                val payload = json.decodeFromString(SubIdentityCredentialPayload.serializer(), payloadPart)
                SubIdentityCredential(payload, sigB64.ifBlank { null })
            } catch (e: Exception) {
                null
            }
        }

        private fun u64(v: Long): ByteArray = byteArrayOf(
            (v ushr 56).toByte(), (v ushr 48).toByte(), (v ushr 40).toByte(), (v ushr 32).toByte(),
            (v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte()
        )

        private fun u32(v: Int): ByteArray = byteArrayOf(
            (v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte()
        )

        private fun frame(payload: ByteArray): ByteArray {
            val len = u32(payload.size)
            return len + payload
        }
    }
}
