package com.securesocial.core.crypto

import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import java.util.Base64

/**
 * AES-256-GCM 加解密
 *
 * 用于消息体的端到端加密:
 * - 加密: 明文 + AES-256 密钥 → 密文 + IV + AuthTag
 * - 解密: 密文 + IV + AuthTag + AES-256 密钥 → 明文
 *
 * v2 安全增强 (防重放/防跨上下文移植):
 * - 加解密支持 AAD (Additional Authenticated Data):
 *   将 "协议域分隔符 ‖ 发送方指纹 ‖ 接收方指纹 ‖ 序列号" 作为 AAD 绑定进 AuthTag,
 *   密文被移动到其他会话/其他位置/其他序列号时 GCM 认证失败,
 *   消除 "完整性 ≠ 新鲜性/上下文正确性" 的缝隙。
 *
 * 设计决策: encrypt/decrypt 方法接受 SecretKey 参数,
 * 该密钥可以是软件生成的密钥 (App A 使用),
 * 也可以是 Keystore 支持的硬件密钥 (App B 使用)。
 * 这实现了密码学原语与密钥来源的解耦。
 */
class AesGcmCipher {

    companion object {
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_LENGTH_BITS = 128  // 16 bytes
        private const val IV_LENGTH_BYTES = 12       // GCM 标准 IV 长度

        /** 消息加密 AAD 的域分隔符: 防止不同用途的 GCM 输出被交叉使用 */
        const val MSG_AAD_DOMAIN = "ENGINE-MSG-V1"
    }

    /**
     * 加密结果
     *
     * @param ciphertext 密文 (不含 IV 和 AuthTag)
     * @param iv 初始化向量 (12 bytes)
     * @param authTag 认证标签 (16 bytes)
     */
    data class EncryptedPayload(
        val ciphertext: ByteArray,
        val iv: ByteArray,
        val authTag: ByteArray
    ) {
        /**
         * 序列化为 Base64 字符串格式: iv.ciphertext.authTag
         */
        fun toBase64String(): String {
            val ivB64 = Base64.getEncoder().encodeToString(iv)
            val ctB64 = Base64.getEncoder().encodeToString(ciphertext)
            val tagB64 = Base64.getEncoder().encodeToString(authTag)
            return "$ivB64.$ctB64.$tagB64"
        }

        companion object {
            /**
             * 从 Base64 字符串反序列化: iv.ciphertext.authTag
             */
            fun fromBase64String(encoded: String): EncryptedPayload {
                val parts = encoded.split(".")
                require(parts.size == 3) { "Invalid encrypted payload format" }
                val decoder = Base64.getDecoder()
                return EncryptedPayload(
                    ciphertext = decoder.decode(parts[1]),
                    iv = decoder.decode(parts[0]),
                    authTag = decoder.decode(parts[2])
                )
            }
        }
    }

    /**
     * 构建消息 AAD: 域分隔符 ‖ source ‖ target ‖ seq (UTF-8 顺序拼接)
     *
     * 发送方与接收方必须以完全一致的内容计算, 任何字段被中继篡改都会导致解密认证失败。
     */
    fun buildMessageAad(source: String, target: String, seq: Long): ByteArray {
        return (MSG_AAD_DOMAIN + source + target + seq.toString()).toByteArray(Charsets.UTF_8)
    }

    /**
     * 加密明文
     *
     * @param plaintext 明文字节
     * @param key AES-256 密钥 (软件或硬件来源均可)
     * @param aad 附加认证数据 (v2): 绑定消息上下文, 可为 null (不推荐, 仅为兼容保留)
     * @return EncryptedPayload 包含密文 + IV + AuthTag
     */
    fun encrypt(plaintext: ByteArray, key: SecretKey, aad: ByteArray? = null): EncryptedPayload {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val iv = ByteArray(IV_LENGTH_BYTES).also {
            java.security.SecureRandom().nextBytes(it)
        }
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
        if (aad != null) cipher.updateAAD(aad)
        // GCM 模式下, doFinal 返回密文 + AuthTag 的拼接
        val cipherOutput = cipher.doFinal(plaintext)
        val ciphertext = cipherOutput.copyOf(cipherOutput.size - GCM_TAG_LENGTH_BITS / 8)
        val authTag = cipherOutput.copyOfRange(cipherOutput.size - GCM_TAG_LENGTH_BITS / 8, cipherOutput.size)
        return EncryptedPayload(ciphertext, iv, authTag)
    }

    /**
     * 解密密文
     *
     * @param payload EncryptedPayload 包含密文 + IV + AuthTag
     * @param key AES-256 密钥
     * @param aad 附加认证数据 (v2): 必须与加密时完全一致, 否则抛出 AEADBadTagException
     * @return 明文字节
     */
    fun decrypt(payload: EncryptedPayload, key: SecretKey, aad: ByteArray? = null): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH_BITS, payload.iv))
        if (aad != null) cipher.updateAAD(aad)
        // GCM 解密需要密文 + AuthTag 拼接
        val combined = payload.ciphertext + payload.authTag
        return cipher.doFinal(combined)
    }

    /**
     * 便捷方法: 加密字符串并返回 Base64 编码
     */
    fun encryptString(plaintext: String, key: SecretKey, aad: ByteArray? = null): String {
        return encrypt(plaintext.toByteArray(Charsets.UTF_8), key, aad).toBase64String()
    }

    /**
     * 便捷方法: 从 Base64 编码解密字符串
     */
    fun decryptString(encoded: String, key: SecretKey, aad: ByteArray? = null): String {
        return String(decrypt(EncryptedPayload.fromBase64String(encoded), key, aad), Charsets.UTF_8)
    }
}
