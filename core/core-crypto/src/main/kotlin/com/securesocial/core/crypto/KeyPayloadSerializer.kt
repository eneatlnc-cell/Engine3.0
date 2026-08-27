package com.securesocial.core.crypto

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.encodeToString
import java.util.Base64

/**
 * 二维码密钥载荷序列化/反序列化
 *
 * 用于 App A 与 App B 之间的私钥光学通道传递:
 * - App A: 生成密钥对 → 序列化为 JSON → ZXing 渲染为二维码
 * - App B: ML Kit 扫码 → 解析 JSON → 校验曲线参数 → 加密存储
 *
 * JSON 载荷结构:
 * {"pub":"<Base64>","prv":"<Base64>","curve":"P-256"}
 *
 * 安全约束:
 * - URI Scheme 中绝对禁止携带私钥明文
 * - 私钥仅通过此二维码光学通道传递
 */
object KeyPayloadSerializer {

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    private const val SUPPORTED_CURVE = "P-256"

    @Serializable
    data class KeyPayload(
        val pub: String,    // X.509 Base64 编码的公钥
        val prv: String,    // PKCS#8 Base64 编码的私钥
        val curve: String   // 椭圆曲线名称
    )

    /**
     * 解析后的密钥数据
     */
    data class KeyPairData(
        val publicKey: ByteArray,   // X.509 编码
        val privateKey: ByteArray,   // PKCS#8 编码
        val curve: String
    )

    /**
     * 序列化密钥对为 JSON 字符串 (用于生成二维码)
     *
     * @param publicKey X.509 编码的公钥字节
     * @param privateKey PKCS#8 编码的私钥字节
     * @return JSON 字符串
     */
    fun serialize(publicKey: ByteArray, privateKey: ByteArray): String {
        val payload = KeyPayload(
            pub = Base64.getEncoder().encodeToString(publicKey),
            prv = Base64.getEncoder().encodeToString(privateKey),
            curve = SUPPORTED_CURVE
        )
        return json.encodeToString(payload)
    }

    /**
     * 反序列化 JSON 字符串为密钥数据 (用于扫码解析)
     *
     * @param raw JSON 字符串
     * @return 解析后的 KeyPairData, 校验失败返回 null
     */
    fun deserialize(raw: String): KeyPairData? {
        return try {
            val payload = json.decodeFromString(KeyPayload.serializer(), raw)

            // 校验椭圆曲线参数合法性
            if (payload.curve != SUPPORTED_CURVE) {
                return null
            }

            val decoder = Base64.getDecoder()
            KeyPairData(
                publicKey = decoder.decode(payload.pub),
                privateKey = decoder.decode(payload.prv),
                curve = payload.curve
            )
        } catch (e: Exception) {
            null
        }
    }

    /**
     * 校验密钥对的合法性 (公钥指纹匹配 + 签名验证)
     *
     * @param keyData 密钥数据
     * @return true 如果密钥对合法
     */
    fun validate(keyData: KeyPairData): Boolean {
        return try {
            val ecdsa = EcdsaOperations()
            val publicKey = ecdsa.decodePublicKey(keyData.publicKey)
            val privateKey = ecdsa.decodePrivateKey(keyData.privateKey)

            // 验证密钥对匹配: 用私钥签名随机数据, 再用公钥验签
            val testData = "validation-${System.currentTimeMillis()}".toByteArray()
            val signature = ecdsa.sign(privateKey, testData)
            ecdsa.verify(publicKey, testData, signature)
        } catch (e: Exception) {
            false
        }
    }
}
