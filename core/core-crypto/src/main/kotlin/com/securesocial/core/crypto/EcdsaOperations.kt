package com.securesocial.core.crypto

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * ECDSA P-256 签名/验签操作
 *
 * 用于:
 * - App A: 生成临时身份密钥对 (内存中)
 * - App B: 使用 Keystore 保护的私钥进行签名
 * - 双方: 验证对方签名以互验身份
 */
class EcdsaOperations {

    companion object {
        private const val CURVE = "secp256r1"
        private const val KEY_ALGORITHM = "EC"
        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
    }

    /**
     * 生成 ECDSA P-256 密钥对 (软件实现, 仅存内存)
     */
    fun generateKeyPair(): KeyPair {
        val generator = KeyPairGenerator.getInstance(KEY_ALGORITHM)
        generator.initialize(ECGenParameterSpec(CURVE))
        return generator.generateKeyPair()
    }

    /**
     * 使用私钥对数据进行签名
     */
    fun sign(privateKey: PrivateKey, data: ByteArray): ByteArray {
        val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
        signature.initSign(privateKey)
        signature.update(data)
        return signature.sign()
    }

    /**
     * 使用公钥验证签名
     */
    fun verify(publicKey: PublicKey, data: ByteArray, signatureBytes: ByteArray): Boolean {
        return try {
            val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
            signature.initVerify(publicKey)
            signature.update(data)
            signature.verify(signatureBytes)
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 将公钥编码为 X.509 字节数组
     */
    fun encodePublicKey(key: PublicKey): ByteArray {
        return key.encoded
    }

    /**
     * 从 X.509 字节数组解码公钥
     */
    fun decodePublicKey(bytes: ByteArray): PublicKey {
        val keySpec = X509EncodedKeySpec(bytes)
        return KeyFactory.getInstance(KEY_ALGORITHM).generatePublic(keySpec)
    }

    /**
     * 将私钥编码为 PKCS#8 字节数组
     */
    fun encodePrivateKey(key: PrivateKey): ByteArray {
        return key.encoded
    }

    /**
     * 从 PKCS#8 字节数组解码私钥
     */
    fun decodePrivateKey(bytes: ByteArray): PrivateKey {
        val keySpec = PKCS8EncodedKeySpec(bytes)
        return KeyFactory.getInstance(KEY_ALGORITHM).generatePrivate(keySpec)
    }
}
