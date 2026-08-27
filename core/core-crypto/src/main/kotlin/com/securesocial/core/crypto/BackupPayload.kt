package com.securesocial.core.crypto

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * ═══════════════════════════════════════════════════════════════════
 *  v3.36 · 备份载荷 (schema 收窄: 联系人 + 标记物)
 * ═══════════════════════════════════════════════════════════════════
 *
 *  v3.35 落盘六类 (联系人/标记物/余额/密封/档案/偏好), v3.36 收窄为
 *  两类。收窄依据 (产品决策 2026-08):
 *
 *  · SPARK 余额 —— 金额是**未来可交易资产**, 绝不可进入"口令恢复"
 *    通道: 恢复语义 max(本机,备份) 在可交易后等价于余额重放印钞机
 *    (备份→花光→恢复→再卖)。余额安全由专用本地钱包承担 (密钥
 *    同身份密钥进 Vault, 余额由签名交易历史推导, 见 TODO v3.37)。
 *    旧备份中的 wallet 字段在新版本被静默忽略 (ignoreUnknownKeys)。
 *  · 密封一次性密钥 —— 私钥材料不该有第二条落盘路径, 迟到放钥
 *    场景的丢失代价已被接受为钱包化设计的边界条件。
 *  · 档案/表情偏好 —— 低价值高频变动数据, 备份它们只会让用户
 *    在"过时快照 vs 现状"间困惑。
 *  · 联系人/标记物 —— 用户长期积累、无法再生的高价值社交数据,
 *    且与身份解耦 (按对端指纹合并, 跨身份导入亦安全), 保留。
 *
 *  前向兼容: 全字段默认值 + ignoreUnknownKeys。旧备份 (含六类
 *  字段) 在新版本无损读取其中联系人/标记物; 新备份在 v3.35 旧
 *  版本中读取时其余字段取默认值 (余额 0, 不动本地账)。
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
    val contacts: List<ContactBackup> = emptyList(),
    val markers: List<MarkerBackup> = emptyList(),
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
