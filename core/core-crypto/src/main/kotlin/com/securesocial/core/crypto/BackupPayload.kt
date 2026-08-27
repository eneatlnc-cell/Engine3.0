package com.securesocial.core.crypto

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * ═══════════════════════════════════════════════════════════════════
 *  v3.35 · 备份载荷 (v1 schema)
 * ═══════════════════════════════════════════════════════════════════
 *
 *  备份边界 (与"仅本地数据"精确对齐):
 *  · 包含: 联系人 / 标记物(明文快照) / SPARK 余额 / 赠金领取日 /
 *    密封注册表(含一次性密钥) / 档案(昵称+头像) / 贴纸·表情最近使用
 *  · 不含: 聊天消息 (零落盘红线, 不因备份破例) · 群组 (纯内存,
 *    主权接力设计) · 身份私钥 (Vault 职责, 经 Vault→Vault 迁移码
 *    单独流转) · pending_restore 会话 (TTL 10 分钟的瞬态)
 *
 *  密封一次性密钥入备份的安全性: 本地 spark_seals.xml 中该密钥是
 *  明文 (审计 F1 已接受), 备份文件内它处于口令派生 AES-GCM 密文
 *  之中 —— 保护强度严格高于现状。丢失该表则发送方无法应答迟到
 *   支付的放钥请求, 故纳入。
 *
 *  前向兼容: 全字段默认值 + ignoreUnknownKeys, 旧备份在新版本
 *  可无损读取; 新增字段一律 Optional/默认值。
 */
object BackupPayloadCodec {
    val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = false
    }

    fun encode(p: BackupPayloadV1): String = json.encodeToString(BackupPayloadV1.serializer(), p)

    fun decode(s: String): BackupPayloadV1 = json.decodeFromString(BackupPayloadV1.serializer(), s)
}

@Serializable
data class BackupPayloadV1(
    val v: Int = 1,
    val createdAt: Long = 0L,
    val fingerprint: String = "",
    val profile: ProfileBackup = ProfileBackup(),
    val contacts: List<ContactBackup> = emptyList(),
    val markers: List<MarkerBackup> = emptyList(),
    val wallet: WalletBackup = WalletBackup(),
    val seals: SealsBackup = SealsBackup(),
    val recent: RecentBackup = RecentBackup(),
)

@Serializable
data class ProfileBackup(
    val nickname: String = "",
    /** 512px JPEG Base64; null = 未设置头像 */
    val avatarJpegB64: String? = null,
)

@Serializable
data class ContactBackup(
    val fp: String,
    val nickname: String,
)

@Serializable
data class MarkerBackup(
    val messageId: String,
    val peerFingerprint: String,
    val peerName: String,
    val text: String,
    val isMine: Boolean,
    val messageTimestamp: Long,
    val markedAt: Long,
    val stickerId: String? = null,
)

@Serializable
data class WalletBackup(
    val balance: Long = 0L,
    /** yyyy-MM-dd 本地时区; "" = 从未领取 */
    val lastGrantDay: String = "",
)

@Serializable
data class SealsBackup(
    /** 己方密封注册表 (发送方视角, 含一次性密钥) */
    val own: List<OwnSealBackup> = emptyList(),
    /** 我已支付过的 sealId 集 (防重放二次付费) */
    val paidByMe: List<String> = emptyList(),
)

@Serializable
data class OwnSealBackup(
    val id: String,
    val keyB64: String,
    val price: Long,
    val paidBy: List<String> = emptyList(),
)

@Serializable
data class RecentBackup(
    val stickers: List<String> = emptyList(),
    val emoji: List<String> = emptyList(),
)
