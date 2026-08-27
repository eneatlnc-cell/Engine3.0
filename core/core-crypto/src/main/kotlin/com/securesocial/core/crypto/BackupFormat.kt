package com.securesocial.core.crypto

import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * ═══════════════════════════════════════════════════════════════════
 *  v3.35 · 本地备份文件格式 (BackupCrypto + 容器)
 * ═══════════════════════════════════════════════════════════════════
 *
 *  背景 (2026-08 数据丢失事故复盘): 联系人 / 标记物 / SPARK 余额 /
 *  密封注册表均为**仅本地**数据 (Vault 只保管密钥, 中继零状态,
 *  Android 系统级备份被 data_extraction_rules 全域排除 —— E2EE
 *  应用的正确决策), 签名证书变更导致的卸载重装会整体抹掉它们。
 *  本格式提供"用户自持的加密备份文件"作为找回通道。
 *
 *  为什么是口令派生密钥而不是身份密钥加密:
 *  · 绑定完成后 Engine 仅持有**公钥** (私钥零出 Vault, 审计确认的
 *    设计红线), Engine 侧无法构造"仅本身份可解"的非对称加密;
 *  · 给 Vault 增加密钥协商 IPC 可实现, 但突破 Vault 极简职责;
 *  · 故采用 Signal 同款成熟模型: PBKDF2-HMAC-SHA256 口令派生 +
 *    AES-256-GCM, 文件头明文绑定身份指纹 (导入时先验归属再问口令)。
 *
 *  二进制布局 (v1, 全部大端):
 *  ┌────────┬──────┬────────────┬────────┬────────┬─────────┬──────┬────────────┐
 *  │ "EGBK" │ ver=1│ iterations │ salt16 │ fp 32B │ createdAt│ iv12 │ AES-GCM 密文│
 *  │ 0..3   │  4   │   5..8     │ 9..24  │ 25..56 │ 57..64  │65..76│  77..      │
 *  └────────┴──────┴────────────┴────────┴────────┴─────────┴──────┴────────────┘
 *  · 明文头 (0..64) 纳入 GCM AAD —— 头部字段不可篡改、不可嫁接;
 *  · 密文 = payload JSON (含联系人/标记物明文快照/密封密钥等敏感
 *    数据), 仅在口令正确时可解;
 *  · 指纹 32 字符小写 hex (SHA-256 前 16 字节), 固定长度无歧义。
 *
 *  口令处理遵循项目「敏感数据内存处理规范」: 口令一律 CharArray
 *  承载, KDF 消费完立即零覆写, 不产生 String 中间形态。
 */
object BackupFormat {

    const val MAGIC = "EGBK"
    const val VERSION = 1

    /** PBKDF2-HMAC-SHA256 迭代次数 (OWASP 2023 基线之上, 中端机约 0.3~0.8s) */
    const val DEFAULT_ITERATIONS = 350_000

    private const val OFF_VERSION = 4
    private const val OFF_ITER = 5
    private const val OFF_SALT = 9
    private const val OFF_FP = 25
    private const val OFF_CREATED = 57
    private const val OFF_IV = 65
    private const val OFF_CIPHER = 77

    const val SALT_LEN = 16
    const val IV_LEN = 12
    const val FP_LEN = 32
    const val KEY_BITS = 256
    private const val GCM_TAG_BITS = 128

    /** 备份文件解析失败原因 (调用方据此给用户定向提示) */
    enum class Error { NOT_BACKUP, BAD_FORMAT, WRONG_PASSPHRASE, CORRUPTED }

    /** 明文头 (解密前可见 —— 归属校验与预览的时间戳来源) */
    data class Header(
        val fingerprint: String,
        val createdAtMs: Long,
        val iterations: Int,
        val salt: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean =
            other is Header &&
                other.fingerprint == fingerprint &&
                other.createdAtMs == createdAtMs &&
                other.iterations == iterations &&
                other.salt.contentEquals(salt)

        override fun hashCode(): Int =
            fingerprint.hashCode() * 31 + createdAtMs.hashCode() * 7 + iterations
    }

    /** 解密成功产物 (payloadJson 由调用方反序列化) */
    data class Opened(val header: Header, val payloadJson: String)

    // ── 封装 ────────────────────────────────────────────────

    /**
     * 生成加密备份文件字节。
     *
     * @param passphrase 口令 (CharArray; 本方法返回后调用方自行清零;
     *        内部 PBEKeySpec 消费完即 clear)
     * @param fingerprint 绑定身份指纹 (32 字符小写 hex, 入明文头)
     * @param createdAtMs 创建时间戳
     * @param payloadJson 已序列化的 [BackupPayloadV1] JSON
     */
    fun seal(
        passphrase: CharArray,
        fingerprint: String,
        createdAtMs: Long,
        payloadJson: String,
        iterations: Int = DEFAULT_ITERATIONS,
    ): ByteArray {
        require(fingerprint.length == FP_LEN) {
            "fingerprint must be $FP_LEN lowercase hex chars"
        }
        val salt = ByteArray(SALT_LEN).also { SecureRandom().nextBytes(it) }
        val iv = ByteArray(IV_LEN).also { SecureRandom().nextBytes(it) }

        val header = ByteBuffer.allocate(OFF_IV)
            .put(MAGIC.toByteArray(Charsets.US_ASCII))   // 0..3
            .put(VERSION.toByte())                       // 4
            .putInt(iterations)                          // 5..8
            .put(salt)                                   // 9..24
            .put(fingerprint.toByteArray(Charsets.US_ASCII)) // 25..56
            .putLong(createdAtMs)                        // 57..64
            .array()

        val keyBytes = deriveKey(passphrase, salt, iterations)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyBytes, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
            cipher.updateAAD(header)
            val ct = cipher.doFinal(payloadJson.toByteArray(Charsets.UTF_8))
            return header + iv + ct
        } finally {
            Arrays.fill(keyBytes, 0)   // 密钥用完即清 (内存卫生规范)
        }
    }

    // ── 解析 ────────────────────────────────────────────────

    /** 仅读明文头 (不解密; 长度/魔数/版本不符返回 null) */
    fun peek(blob: ByteArray): Header? {
        if (blob.size < OFF_CIPHER) return null
        if (String(blob, 0, 4, Charsets.US_ASCII) != MAGIC) return null
        if (blob[OFF_VERSION].toInt() != VERSION) return null
        val iter = ByteBuffer.wrap(blob, OFF_ITER, 4).int
        if (iter < 1 || iter > 10_000_000) return null
        val salt = blob.copyOfRange(OFF_SALT, OFF_SALT + SALT_LEN)
        val fp = String(blob, OFF_FP, FP_LEN, Charsets.US_ASCII)
        if (!fp.all { it in '0'..'9' || it in 'a'..'f' }) return null
        val created = ByteBuffer.wrap(blob, OFF_CREATED, 8).long
        return Header(fp, created, iter, salt)
    }

    /**
     * 解密并校验。
     * @return [Opened]; 失败抛 [BackupFormatException] (reason 见 [Error])
     */
    fun open(passphrase: CharArray, blob: ByteArray): Opened {
        val header = peek(blob) ?: throw BackupFormatException(Error.BAD_FORMAT)
        val iv = blob.copyOfRange(OFF_IV, OFF_IV + IV_LEN)
        val ct = blob.copyOfRange(OFF_CIPHER, blob.size)
        val aad = blob.copyOfRange(0, OFF_IV)
        val keyBytes = deriveKey(passphrase, header.salt, header.iterations)
        val plain = try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(keyBytes, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
            cipher.updateAAD(aad)
            cipher.doFinal(ct)
        } catch (e: java.security.GeneralSecurityException) {
            // GCM tag 校验失败 = 口令错误或密文被篡改;
            // 口令错误占绝对多数, 归入 WRONG_PASSPHRASE 语义
            throw BackupFormatException(Error.WRONG_PASSPHRASE, e)
        } finally {
            Arrays.fill(keyBytes, 0)
        }
        return try {
            Opened(header, String(plain, Charsets.UTF_8))
        } catch (e: Exception) {
            Arrays.fill(plain, 0)
            throw BackupFormatException(Error.CORRUPTED, e)
        }
    }

    // ── KDF ────────────────────────────────────────────────

    /** PBKDF2-HMAC-SHA256 → 256-bit 原始密钥字节; PBEKeySpec 口令副本用完即清 (内存卫生规范) */
    private fun deriveKey(passphrase: CharArray, salt: ByteArray, iterations: Int): ByteArray {
        val spec = PBEKeySpec(passphrase, salt, iterations, KEY_BITS)
        return try {
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            factory.generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }
}

/** 备份文件解析异常 (reason 驱动 UI 定向提示) */
class BackupFormatException(
    val reason: BackupFormat.Error,
    cause: Throwable? = null,
) : Exception("backup ${reason.name.lowercase()}", cause)
