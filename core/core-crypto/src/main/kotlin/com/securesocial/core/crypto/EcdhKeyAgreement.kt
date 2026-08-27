package com.securesocial.core.crypto

import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec
import java.security.MessageDigest

/**
 * ECDH P-256 密钥协商
 *
 * 用于 App A 双方协商共享会话密钥:
 * 1. 双方各自生成临时 ECDH 密钥对
 * 2. 交换公钥
 * 3. 使用己方私钥 + 对方公钥协商共享密钥
 * 4. HKDF 派生 AES-256 会话密钥
 */
class EcdhKeyAgreement {

    companion object {
        private const val CURVE = "secp256r1"
        private const val KEY_ALGORITHM = "EC"
        private const val KEY_AGREEMENT_ALGORITHM = "ECDH"
        private const val HASH_ALGORITHM = "SHA-256"
        private const val AES_KEY_SIZE = 256 // bits

        /** 会话密钥派生的域分隔符 (v2) */
        const val SESSION_KEY_DOMAIN = "ENGINE-SESSION-V1"

        /**
         * 构建会话密钥 HKDF info (v2 安全增强):
         * "ENGINE-SESSION-V1" ‖ min(fpA,fpB) ‖ "|" ‖ max(fpA,fpB)
         *
         * - 绑定双方身份指纹 → 消除 unknown key-share: 本会话密钥只属于这一对身份
         * - 两个指纹按字典序规范化排序 → 双方以相同顺序计算, 派生出相同密钥
         * - 全局唯一 info → 防止与其他协议/用途的 HKDF 输出交叉复用
         */
        fun sessionKeyInfo(myFingerprint: String, peerFingerprint: String): String {
            val (lo, hi) = if (myFingerprint <= peerFingerprint)
                myFingerprint to peerFingerprint
            else
                peerFingerprint to myFingerprint
            return "$SESSION_KEY_DOMAIN|$lo|$hi"
        }
    }

    /**
     * 生成临时 ECDH 密钥对 (软件实现, 仅存内存)
     */
    fun generateKeyPair(): KeyPair {
        val generator = KeyPairGenerator.getInstance(KEY_ALGORITHM)
        generator.initialize(ECGenParameterSpec(CURVE))
        return generator.generateKeyPair()
    }

    /**
     * ECDH 协商共享密钥
     *
     * @param privateKey 己方 ECDH 私钥
     * @param publicKey 对方 ECDH 公钥
     * @return 共享密钥原始字节 (32 bytes for P-256)
     */
    fun agree(privateKey: PrivateKey, publicKey: PublicKey): ByteArray {
        val keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM)
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(publicKey, true)
        return keyAgreement.generateSecret()
    }

    /**
     * 使用 HKDF-SHA256 从共享密钥派生 AES-256 会话密钥
     *
     * 简化 HKDF 实现: HMAC-SHA256(extract) + HMAC-SHA256(expand)
     *
     * @param sharedSecret ECDH 协商出的共享密钥
     * @param info 上下文信息字符串 (如 "session-key")
     * @return AES-256 SecretKey
     */
    fun deriveSessionKey(sharedSecret: ByteArray, info: String): SecretKey {
        // Extract: PRK = HMAC-SHA256(salt="", IKM=sharedSecret)
        val prk = hmacSha256(ByteArray(32), sharedSecret)

        // Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
        val infoBytes = info.toByteArray(Charsets.UTF_8)
        val expandInput = infoBytes + byteArrayOf(0x01)
        val okm = hmacSha256(prk, expandInput)

        // 取前 32 字节作为 AES-256 密钥
        val keyBytes = okm.copyOf(AES_KEY_SIZE / 8)
        return SecretKeySpec(keyBytes, "AES")
    }

    /**
     * 一步到位: ECDH 协商 + HKDF 派生
     */
    fun agreeAndDerive(
        privateKey: PrivateKey,
        publicKey: PublicKey,
        info: String
    ): SecretKey {
        val sharedSecret = agree(privateKey, publicKey)
        return deriveSessionKey(sharedSecret, info)
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }
}
