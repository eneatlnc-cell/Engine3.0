package com.securesocial.core.crypto

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.security.PrivateKey
import java.util.Base64

/**
 * 身份轮换载荷 (JSON 运输形态, v3.73 · P1-b)
 *
 * 字段与 [IdentityRotationStatement] 一一对应; 签名始终针对
 * [IdentityRotationStatement.canonicalBytes] 规范化字节, JSON 字段顺序
 * / 空白 / 未知字段均不影响签名有效性 (同 [com.securesocial.core.wallet.TxJsonCodec] 哲学)。
 */
@Serializable
data class IdentityRotationPayload(
    val version: Int,     // 协议版本 (当前 = 1)
    val oldFp: String,    // 旧身份公钥指纹 (轮换主体)
    val newFp: String,    // 新身份公钥指纹 (接替者)
    val newPub: String,   // 新身份公钥 (X.509 Base64)
    val ts: Long          // 签发时间戳 (ms, 重放窗口判据)
)

/**
 * 身份轮换声明 (v3.73 · P1-b 预埋)。
 *
 * 语义: **旧身份私钥授权新公钥接替** —— "旧私钥对新公钥指纹签名"。
 * 验证者 (联系人 / 中继) 用自己记录的旧身份公钥验签通过后, 即可将
 * 联系人指向的公钥更新为新公钥, 会话加密关系随之迁移, 旧身份退役。
 * 这是 "身份密钥永远无法离开 Vault (TEE)" 之后唯一合法的身份更替
 * 通道: 不存在私钥导出, 轮换 = 旧钥授权新钥。
 *
 * P1 范围边界 (诚实入档): 本文件只交付**协议格式 + 规范化序列化 +
 * 签发/验签工具** —— 广播传播依赖中继端点 (rotation 公告类型的定义
 * 与中继广播协议), 归 P2 双花根除批次实现。签发侧可立即复用现有
 * Vault sign 通道 (对 canonicalBytes 走一次签名挑战), 零 Vault 改动。
 *
 * 规范化字节布局 (同 TxCanonical 帧风格, 域分离防跨协议重放):
 * `DOMAIN || u32(version) || frame(oldFp) || frame(newFp) || frame(newPub) || u64(ts)`
 */
data class IdentityRotationStatement(
    val version: Int,
    val oldFp: String,
    val newFp: String,
    val newPubB64: String,
    val timestamp: Long,
    val signatureB64: String?
) {

    /** 无签名规范化字节 (签名对象) */
    fun canonicalBytes(): ByteArray =
        canonicalBytes(version, oldFp, newFp, newPubB64, timestamp)

    /**
     * 用旧身份私钥签署, 返回带签副本。
     *
     * P1 签发路径: oldPrivateKey 可为软件密钥 (测试) 或 Vault TEE 硬件
     * 身份密钥句柄 ([PrivateKeyManager.signChallenge] 通道产出的 DER
     * 签名亦可直接填入 [signatureB64]) —— SHA256withECDSA 语义一致。
     */
    fun sign(oldPrivateKey: PrivateKey): IdentityRotationStatement {
        val ecdsa = EcdsaOperations()
        val sig = ecdsa.sign(oldPrivateKey, canonicalBytes())
        return copy(
            signatureB64 = Base64.getEncoder().encodeToString(sig)
        )
    }

    /**
     * 验证声明 (验证者视角)。
     *
     * 五重校验:
     * 1. 协议版本匹配;
     * 2. 时间戳落在重放窗口内 ([MAX_CLOCK_SKEW_MS], checkClock = true 时);
     * 3. 声明内部自洽: newFp == compute(newPub);
     * 4. 声明主体匹配: oldFp == compute(验证者提供的旧公钥) —— 防止把
     *    针对他人身份的轮换声明套用到自己认识的联系人上;
     * 5. 签名可被**旧身份公钥**验证 (旧私钥持有证明)。
     *
     * @param oldPubBytes 旧身份公钥 (X.509 编码字节; 验证者从自己
     *        记录的联系人关系取得, 不信任声明内字段)
     * @param nowMs 当前时间 (默认真实时钟; 测试可注入)
     * @param checkClock 是否校验时间戳窗口 (离线批量回放场景可关)
     * @return true = 声明有效, 可将联系人公钥更新为 newPub
     */
    fun verify(
        oldPubBytes: ByteArray,
        nowMs: Long = System.currentTimeMillis(),
        checkClock: Boolean = true
    ): Boolean {
        if (version != VERSION) return false
        if (signatureB64.isNullOrEmpty()) return false
        if (checkClock &&
            (timestamp > nowMs + MAX_CLOCK_SKEW_MS || timestamp < nowMs - MAX_CLOCK_SKEW_MS)
        ) {
            return false
        }
        return try {
            val ecdsa = EcdsaOperations()
            val newPubBytes = Base64.getDecoder().decode(newPubB64)
            // ③ 声明内部自洽
            if (newFp != KeyFingerprint.compute(ecdsa.decodePublicKey(newPubBytes))) return false
            // ④ 声明主体匹配验证者持有的旧身份
            if (oldFp != KeyFingerprint.compute(ecdsa.decodePublicKey(oldPubBytes))) return false
            // ⑤ 旧私钥持有证明
            val sig = Base64.getDecoder().decode(signatureB64)
            ecdsa.verify(ecdsa.decodePublicKey(oldPubBytes), canonicalBytes(), sig)
        } catch (e: Exception) {
            false
        }
    }

    companion object {
        /** 签名域 (域分离: 与 RELAY-AUTH-V1 / SIGNAL-V1 / SPARK-WALLET-TX-V1 互斥) */
        const val DOMAIN = "SPARK-ID-ROTATION-V1"

        /** 当前协议版本 */
        const val VERSION = 1

        /**
         * 重放窗口: 声明时间戳与验证时刻的最大偏差。
         * DR7 定稿值 7d (v3.76.0) —— E2E 传播场景下, 轮换声明可能因对方
         * 离线而延迟数天才送达; 7 天窗口覆盖"周末+假期"离线场景, 同时
         * 仍有效限制重放窗口 (远短于密钥生命周期)。相比 P1 预埋的 24h,
         * 7d 更匹配真实 E2E 投递延迟分布。
         */
        const val MAX_CLOCK_SKEW_MS = 7L * 24 * 60 * 60 * 1000

        private val domainBytes = DOMAIN.toByteArray(Charsets.UTF_8)

        /**
         * 构造一个未签名的轮换声明 (newFp 由 newPubBytes 派生, 不可外部指定)。
         */
        fun draft(
            oldFp: String,
            newPubBytes: ByteArray,
            nowMs: Long = System.currentTimeMillis()
        ): IdentityRotationStatement {
            val ecdsa = EcdsaOperations()
            val newFp = KeyFingerprint.compute(ecdsa.decodePublicKey(newPubBytes))
            return IdentityRotationStatement(
                version = VERSION,
                oldFp = oldFp,
                newFp = newFp,
                newPubB64 = Base64.getEncoder().encodeToString(newPubBytes),
                timestamp = nowMs,
                signatureB64 = null
            )
        }

        /** 无签名规范化字节 (静态入口, 供 Vault sign 通道等外部签名方复用) */
        fun canonicalBytes(
            version: Int,
            oldFp: String,
            newFp: String,
            newPubB64: String,
            timestamp: Long
        ): ByteArray {
            val out = ArrayList<ByteArray>()
            out.add(domainBytes)
            out.add(u32(version))
            out.add(frame(oldFp.toByteArray(Charsets.UTF_8)))
            out.add(frame(newFp.toByteArray(Charsets.UTF_8)))
            out.add(frame(newPubB64.toByteArray(Charsets.UTF_8)))
            out.add(u64(timestamp))

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

        // ---- JSON 运输形态 (P2 广播传播使用; P1 仅交付编解码) ----

        private val json = Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
        }

        fun serialize(statement: IdentityRotationStatement): String {
            return json.encodeToString(
                IdentityRotationPayload(
                    version = statement.version,
                    oldFp = statement.oldFp,
                    newFp = statement.newFp,
                    newPub = statement.newPubB64,
                    ts = statement.timestamp
                )
            ) + "|sig:" + (statement.signatureB64 ?: "")
        }

        /**
         * 解析轮换声明 (JSON + "|sig:<Base64>" 尾段)。
         * 解析失败 / 字段缺失返回 null; **不做任何密码学校验** ——
         * 调用方必须随后调用 [verify]。
         */
        fun deserialize(raw: String): IdentityRotationStatement? {
            return try {
                val sigIdx = raw.lastIndexOf("|sig:")
                if (sigIdx < 0) return null
                val payloadPart = raw.substring(0, sigIdx)
                val sigB64 = raw.substring(sigIdx + "|sig:".length)
                val payload = json.decodeFromString(IdentityRotationPayload.serializer(), payloadPart)
                IdentityRotationStatement(
                    version = payload.version,
                    oldFp = payload.oldFp,
                    newFp = payload.newFp,
                    newPubB64 = payload.newPub,
                    timestamp = payload.ts,
                    signatureB64 = sigB64.ifBlank { null }
                )
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
