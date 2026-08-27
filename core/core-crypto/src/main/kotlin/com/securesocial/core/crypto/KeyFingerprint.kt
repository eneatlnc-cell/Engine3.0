package com.securesocial.core.crypto

import java.security.MessageDigest
import java.security.PublicKey
import java.util.Base64

/**
 * 公钥指纹计算
 *
 * 使用 SHA-256 对公钥编码进行哈希, 截取前 16 字节并编码为十六进制字符串,
 * 作为全局唯一节点 ID。
 *
 * 格式: 32 个十六进制字符 (如 "a1b2c3d4e5f6...")
 */
object KeyFingerprint {

    private const val FINGERPRINT_BYTES = 16  // 截取前 16 字节

    /**
     * 计算公钥指纹
     *
     * @param publicKey 公钥对象
     * @return 32 字符的十六进制指纹
     */
    fun compute(publicKey: PublicKey): String {
        return compute(publicKey.encoded)
    }

    /**
     * 从公钥编码字节计算指纹
     *
     * @param encodedKey X.509 编码的公钥字节
     * @return 32 字符的十六进制指纹
     */
    fun compute(encodedKey: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(encodedKey)
        val truncated = hash.copyOf(FINGERPRINT_BYTES)
        return truncated.toHex()
    }

    /**
     * 验证指纹与公钥是否匹配
     */
    fun matches(publicKey: PublicKey, fingerprint: String): Boolean {
        return compute(publicKey).equals(fingerprint, ignoreCase = true)
    }

    private fun ByteArray.toHex(): String {
        return joinToString("") { "%02x".format(it) }
    }
}
