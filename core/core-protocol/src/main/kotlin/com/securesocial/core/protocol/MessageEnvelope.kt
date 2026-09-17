package com.securesocial.core.protocol

import kotlinx.serialization.Serializable

/**
 * 消息类型枚举 - 中继服务器仅解析此字段做路由与认证状态机
 *
 * v2 新增:
 * - CHALLENGE: 服务器 → 客户端的注册挑战 (随机 nonce)
 * - HELLO_AUTH: 客户端 → 服务器的挑战应答 (身份私钥对 nonce 的 ECDSA 签名)
 */
@Serializable
enum class MessageType {
    HELLO,        // 节点注册声明 (携带身份公钥)
    CHALLENGE,    // 服务器注册挑战 (v2: 32 字节随机 nonce)
    HELLO_AUTH,   // 挑战应答 (v2: 身份私钥对 nonce 的 ECDSA 签名)
    SIGNAL,       // ECDH 密钥交换信令 (v2: 携带身份公钥 + 签名)
    MSG,          // 加密消息透传
    PING,         // 心跳保活
    PONG,         // 心跳响应
    ERROR,        // 错误反馈
    ROOM_REGISTER, // v3.14: 群主向中继登记邀请码 → 群主指纹映射
    ROOM_LOOKUP,   // v3.14: 凭邀请码查询群主指纹 (中继目录服务)
    ROOM_INFO,     // v3.14: 中继对 ROOM_* 的统一应答
    GROUP_MSG,     // v3.14: 群聊消息 (群密钥加密); v3.18: target=null 时走中继扇出路径
    GROUP_CTRL,    // v3.14: 群控制信令 (成对加密: 密钥分发/花名册/入群/退群/解散)
    GROUP_SUBSCRIBE, // v3.18: 客户端 → 中继: 订阅群扇出 (groupId 即鉴权, 中继零验证)
    GROUP_FANOUT,   // v3.18: 群密钥控制帧扇出 (PRESENCE 等, 中继向订阅集投递, 同 GROUP_MSG 密文透传)
    GRANT_CHECK,    // v3.45: 领金日去重 (客户端 → 中继: 设备哈希+当日, 中继当日集合幂等)
    GRANT_ACK,      // v3.45: 中继对 GRANT_CHECK 的应答 (allowed=false = 当日已领)
    MSG_ACK,        // v3.53: 中继 → 发送方的投递回执 (queued=已入离线队列 / delivered=已送达)
    QUEUE_FULL,     // v3.53: 中继 → 发送方: 目标离线队列已满, 本条消息被拒绝
    GRAFFITI_POST,      // v3.56: 涂鸦留言卡发布 (客户端 → 中继, 明文公开内容)
    GRAFFITI_SUBSCRIBE, // v3.56: 订阅涂鸦墙 (客户端 → 中继: 入实时广播集 + 领取 24h 快照)
    GRAFFITI_CARD,      // v3.56: 涂鸦卡片帧 (中继 → 客户端: 实时广播 / 订阅快照 / 作者回显)
    GRAFFITI_COMMENT,   // v3.81: 卡片留言 (客户端 → 中继; 同卡同指纹限 1 条, 10 SPARK 回显扣费)
    GRAFFITI_VIEW,      // v3.81: 浏览上报 (客户端 → 中继: 打开卡片详情; 按指纹去重计数)
    GRAFFITI_MORE,      // v3.81: 快照翻页 (客户端 → 中继: 自 offset 续领 GRAFFITI_PAGE_SIZE 张)
    GRAFFITI_PAGE_END,  // v3.81: 页末标记 (中继 → 客户端: 本页张数 / 是否还有 / 墙总量)
    DUP_CLAIM,          // v3.74: 双花探针认领 (客户端 → 中继: 盲化序号探针, 原子查并占)
    DUP_CLAIM_RESULT    // v3.74: 中继对 DUP_CLAIM 的应答 (granted=false = 该探针已被认领过)
}

/**
 * WebSocket 信令协议消息封皮
 *
 * 中继服务器仅解析 type/source/target 字段做路由,
 * payload 字段永不解析, 始终以 Base64/JSON 字符串透传。
 *
 * JSON 结构示例:
 * {"type":"MSG","source":"a1b2...","target":"d4e5...","payload":"base64...","seq":42,"ts":1723737600000}
 */
@Serializable
data class MessageEnvelope(
    val type: MessageType,
    val source: String? = null,        // 发送方公钥指纹
    val target: String? = null,        // 接收方公钥指纹
    val payload: String? = null,       // 加密密文/信令载荷, 中继永不解析
    val seq: Long = 0,                 // 序列号
    val ts: Long = System.currentTimeMillis(),  // 时间戳
    val groupId: String? = null,       // v3.14: 群消息路由用 (中继不解析, 仅透传)
    // v3.80: 发送者道环等级搭车同步 (0 = 未激活, 1..5 = RING 等级)。
    // 信封头明文字段, 与 source/seq/groupId 同性质 —— 中继只透传不解析,
    // 旧版本双端 ignoreUnknownKeys 自动忽略, 向后兼容。接收方据此登记
    // 发送者环级 (RingStore.registerMember), 气泡环徽跟人不跟机:
    // 未激活对端不再被本机环态「借光」, 己方环徽也能在对端正确显示。
    // 展示性自报字段, 伪造仅影响对方看到的徽记颜色, 不参与任何鉴权/计费。
    val ring: Int = 0
)

/**
 * HELLO 消息载荷 - 节点注册声明 (v2)
 *
 * v2 安全增强: 必须携带身份公钥 (X.509 Base64)。
 * 服务器校验 fingerprint(pub) == source 后才下发挑战,
 * 注册从 "自报 ID" 升级为 "公钥持有证明"。
 */
@Serializable
data class HelloPayload(
    val fingerprint: String,   // 公钥指纹, 作为全局唯一节点 ID
    val pubkey: String = ""    // 身份公钥 X.509 编码 (Base64), v2 必填
)

/**
 * CHALLENGE 消息载荷 - 服务器注册挑战 (v2)
 *
 * 服务器生成 32 字节 SecureRandom nonce, 客户端须在超时前
 * 用身份私钥对 "RELAY-AUTH-V1|fingerprint|nonce" 完成 ECDSA 签名
 * 并以 HELLO_AUTH 回送。
 */
@Serializable
data class ChallengePayload(
    val fingerprint: String,   // 被挑战的节点指纹
    val nonce: String          // 挑战随机数 (32 字节, Base64)
)

/**
 * HELLO_AUTH 消息载荷 - 挑战应答 (v2)
 *
 * signature = Sign_identityPrivateKey("RELAY-AUTH-V1" ‖ fingerprint ‖ nonce_bytes)
 * 服务器用 HELLO 中声明的公钥验签, 通过后才允许注册与收发消息。
 */
@Serializable
data class HelloAuthPayload(
    val fingerprint: String,   // 应答方指纹
    val signature: String      // ECDSA 签名 (DER, Base64)
)

/**
 * SIGNAL 消息载荷 - ECDH 密钥交换信令 (v2)
 *
 * v2 安全增强: ECDH 公钥必须由发送方的身份私钥签名,
 * 接收方验证签名且指纹匹配后才采纳, 消除中间人替换公钥的攻击面。
 *
 * 签名内容由 com.securesocial.core.crypto.SignalAuth 构建 (v3.29 修订文档
 * 使其与实际实现一致; 本文件曾存在一个从未被引用的 ENGINE-SIGNAL-V1
 * 变体对象, 已作为死代码删除):
 *   "SIGNAL-V1" ‖ sender_fp(utf8) ‖ receiver_fp(utf8) ‖ ecdh_pub_bytes
 * 验证条件: ECDSA.verify(idpub, sig, content) && fingerprint(idpub) == envelope.source
 */
@Serializable
data class SignalPayload(
    val ecdh: String,          // 发送方 ECDH 公钥 (X.509, Base64)
    val idpub: String,         // 发送方身份公钥 (X.509, Base64)
    val sig: String            // 身份私钥对绑定内容的 ECDSA 签名 (DER, Base64)
)

/**
 * 挑战应答签名内容的域分隔符
 */
object RelayAuth {
    const val DOMAIN = "RELAY-AUTH-V1"

    /** 构建中继注册挑战的签名内容: "RELAY-AUTH-V1" ‖ fingerprint ‖ nonce */
    fun signingContent(fingerprint: String, nonce: ByteArray): ByteArray {
        return (DOMAIN + fingerprint).toByteArray(Charsets.UTF_8) + nonce
    }
}

/**
 * ERROR 消息 - 错误反馈
 */
@Serializable
data class ErrorPayload(
    val code: String,
    val message: String,
    val target: String? = null  // 导致错误的目标节点指纹
)

/**
 * 错误码常量
 */
object ErrorCodes {
    const val TARGET_OFFLINE = "TARGET_OFFLINE"
    const val INVALID_FORMAT = "INVALID_FORMAT"
    const val UNAUTHORIZED = "UNAUTHORIZED"
    const val PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    const val AUTH_FAILED = "AUTH_FAILED"          // v2: 挑战应答失败/超时/签名不合法
    const val FINGERPRINT_MISMATCH = "FINGERPRINT_MISMATCH"  // v2: 声称指纹与公钥不匹配
    const val SOURCE_MISMATCH = "SOURCE_MISMATCH"  // v2: envelope.source 与注册身份不符

    // v3.53: 离线队列容量已满 (消息被拒, 未入队未投递)
    // 注意: QUEUE_FULL 同时有独立信封类型 (MessageType.QUEUE_FULL),
    // ErrorCodes 中的常量供 ERROR 信封错误码字段复用。
    const val QUEUE_FULL = "QUEUE_FULL"

    // v3.18: 群扇出 (错误信封 target 字段携带 groupId)
    const val GROUP_NO_SUBSCRIBERS = "GROUP_NO_SUBSCRIBERS"  // 扇出消息无订阅者 (全员离线)
    const val GROUP_RATE_LIMITED = "GROUP_RATE_LIMITED"      // 群级令牌桶拒绝 (持续速率超限)
    const val GROUP_SUBSCRIBE_LIMIT = "GROUP_SUBSCRIBE_LIMIT" // 单连接订阅群数超上限

    // v3.56: 涂鸦墙 (客户端据此区分拒收原因; 未收到回显即不计费)
    const val GRAFFITI_MALFORMED = "GRAFFITI_MALFORMED"      // 载荷畸形 / author ≠ 认证身份
    const val GRAFFITI_TOO_LONG = "GRAFFITI_TOO_LONG"        // 正文超 300 词元
    const val GRAFFITI_COOLDOWN = "GRAFFITI_COOLDOWN"        // 单指纹发卡冷却中
    const val GRAFFITI_IMAGE_TOO_LARGE = "GRAFFITI_IMAGE_TOO_LARGE" // v3.63: 配图超 90KB base64

    // v3.81: 涂鸦墙留言/翻页 (客户端据此区分拒收原因; 留言未回显即不计费)
    const val GRAFFITI_WALL_FULL = "GRAFFITI_WALL_FULL"            // 墙满 (9192 张) 拒收新卡, 客户端弹温馨等候卡片
    const val GRAFFITI_CARD_NOT_FOUND = "GRAFFITI_CARD_NOT_FOUND"  // 留言/浏览目标卡已出墙 (过期或淘汰)
    const val GRAFFITI_COMMENT_EXISTS = "GRAFFITI_COMMENT_EXISTS"  // 同卡同指纹限 1 条, 已留过
    const val GRAFFITI_COMMENT_TOO_LONG = "GRAFFITI_COMMENT_TOO_LONG" // 留言超 100 词元
}

/**
 * ROOM_REGISTER 载荷 (v3.14) - 群主登记邀请码
 *
 * 中继仅维护 邀请码 → 群主指纹 的内存映射 (TTL 过期),
 * 不保存任何群成员/群密钥信息 —— 无状态红线不破。
 */
@Serializable
data class RoomRegisterPayload(
    val code: String,          // 邀请码 (8 位大写字母+数字)
    val fingerprint: String    // 群主指纹
)

/**
 * ROOM_LOOKUP 载荷 (v3.14) - 凭邀请码找群主
 */
@Serializable
data class RoomLookupPayload(
    val code: String
)

/**
 * ROOM_INFO 载荷 (v3.14) - 中继对 ROOM_REGISTER / ROOM_LOOKUP 的统一应答
 *
 * ok=true: 登记/查询成功; ownerFingerprint 非空 (LOOKUP)
 * ok=false: error 携带 GroupErrorCodes
 */
@Serializable
data class RoomInfoPayload(
    val ok: Boolean,
    val code: String = "",
    val ownerFingerprint: String? = null,
    val error: String? = null
)

/**
 * 群组规模常量 (v3.17.1 · v3.55 调档)
 *
 * MAX_MEMBERS = 50 (v3.55 用户定案: 200 → 50, 先收敛扇出压力
 * 保单中继余量, 后期按实际负载再迭代扩容):
 * - 群消息经中继向 N-1 在线成员扇出, 单条最坏 egress = (N-1) × 帧体。
 *   N=50: 48KB 媒体附件 (帧 ≈117KB) → ~5.7MB ≈ 0.46s 满管 (100Mbps),
 *   并发多群也留有充足管道余量;
 * - v3.17.1 曾按 100Mbps ÷ 200 人 = 人均 ~62KB/s 扇出预算定档 200,
 *   实际部署为单中继低配机, 落到 50 人把人均预算放宽 4 倍,
 *   秒杀 P99 尾延迟;
 * - 兼容性: 上限仅由群主侧 (建群截断 / 入群批准) 强制执行, 中继
 *   零群组状态 —— 存量 >50 人群不受影响 (仅无法再增员), 新建群
 *   即刻收敛到 50。
 *
 * 花名册经 KEY_DIST/ROSTER 分发至全体成员客户端 (中继零群组状态),
 * 上限由群主侧在建群/入群批准两处强制执行。
 */
object GroupLimits {
    /** 单群成员上限 (含群主) */
    const val MAX_MEMBERS = 50
}

/**
 * 群组操作错误码 (v3.14)
 */
object GroupErrorCodes {
    const val INVALID_CODE = "INVALID_CODE"       // 邀请码格式不合法
    const val CODE_TAKEN = "CODE_TAKEN"           // 邀请码已被占用
    const val NOT_FOUND = "NOT_FOUND"            // 邀请码不存在/已过期
    const val RATE_LIMITED = "RATE_LIMITED"       // 查询限流 (防枚举)
    const val UNAUTHORIZED = "UNAUTHORIZED"       // 非群主操作他人映射
    const val GROUP_FULL = "GROUP_FULL"           // v3.17.1: 群成员已达上限 (v3.55 起为 50)
    const val JOIN_REJECTED = "JOIN_REJECTED"     // v3.19: 群主审批拒绝 (门禁模式)
}

/**
 * 邀请码 (v3.14)
 *
 * - 8 位大写字母 + 数字, 剔除易混淆字符 (I O 0 1) —— 口播/截图友好
 * - 熵: log2(32^8) ≈ 40 bit; 配合中继查询限流 (10 次/分钟/指纹),
 *   枚举命中期望 > 10^10 年
 */
object InviteCode {
    const val LENGTH = 8
    const val ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

    /** 生成随机邀请码 */
    fun generate(): String {
        val random = java.security.SecureRandom()
        return buildString {
            repeat(LENGTH) {
                append(ALPHABET[random.nextInt(ALPHABET.length)])
            }
        }
    }

    /** 格式校验: 8 位且全部在字母表内 */
    fun isValid(code: String): Boolean =
        code.length == LENGTH && code.all { it in ALPHABET }
}

// ==================== v3.14: 群组控制协议 ====================

/**
 * 群成员条目 (随花名册分发)
 */
@Serializable
data class GroupMemberData(
    val fp: String,                    // 成员身份指纹
    val nickname: String = "",         // 群内显示名
    val role: String = "MEMBER"        // GroupRoles: OWNER / ADMIN / MEMBER
)

/**
 * 群组三级角色
 *
 * - OWNER: 建群者; 唯一有权 分发/轮换群密钥、审批入群、解散
 * - ADMIN: 预留 (v3.14 未启用; 未来承担邀请/移人)
 * - MEMBER: 发言 / 退群
 */
object GroupRoles {
    const val OWNER = "OWNER"
    const val ADMIN = "ADMIN"
    const val MEMBER = "MEMBER"
}

/**
 * GROUP_CTRL 控制动作常量
 */
object GroupCtrlActions {
    /** 群主 → 成员: 群密钥 + 花名册 (入群批准 / 密钥轮换 / 离线补发) */
    const val KEY = "KEY"

    /** 群主 → 成员: 仅花名册更新 (无密钥变化) */
    const val ROSTER = "ROSTER"

    /** 申请者 → 群主: 凭邀请码申请入群 (groupId 为空, 群主按 code 匹配) */
    const val JOIN_REQ = "JOIN_REQ"

    /** 群主 → 申请者: 拒绝入群 (approved=false + reason; 通过以 KEY 落地) */
    const val JOIN_RESP = "JOIN_RESP"

    /** 成员 → 群主: 主动退群 (群主随之轮换密钥) */
    const val LEAVE = "LEAVE"

    /** 群主 → 被移除者 (预留, v3.14 未启用) */
    const val KICK = "KICK"

    /** 成员 → 群主: 群密钥过期/解密失败, 请求补发 */
    const val KEY_REQ = "KEY_REQ"

    /** 群主 → 全员: 解散群组 */
    const val DISSOLVE = "DISSOLVE"

    /**
     * 成员 → 成员: 在线心跳 (v3.14.1 主权顺移)
     *
     * 每 30s 一跳, 接收方据此维护 (groupId → 成员 → lastSeen) 在场表;
     * 群主失联超 90s 时由顺位首位在线成员接管群主权。
     */
    const val PRESENCE = "PRESENCE"
}

/**
 * GROUP_CTRL 载荷 (v3.14)
 *
 * 传输时整体经 1:1 ECDH 会话密钥加密 (与 MSG 同路径),
 * 中继全程只见密文 —— 群成员表/群密钥对中继零暴露。
 *
 * action=KEY 时 keyB64 携带 AES-256 群密钥原始字节 (Base64);
 * 群密钥每次成员减少时由群主轮换 (keyVersion 递增)。
 */
@Serializable
data class GroupCtrlPayload(
    val action: String,                        // GroupCtrlActions.*
    val groupId: String? = null,               // JOIN_REQ 为空 (凭 code 定位群)
    val groupName: String? = null,
    val ownerFp: String? = null,
    val code: String? = null,                  // 邀请码 (JOIN_REQ 携带)
    val requesterFp: String? = null,           // 申请人指纹 (JOIN_REQ)
    val approved: Boolean = true,              // JOIN_RESP: false = 拒绝
    val members: List<GroupMemberData> = emptyList(),  // 花名册 (KEY/ROSTER)
    val keyB64: String? = null,                // KEY: AES-256 群密钥 (Base64)
    val keyVersion: Int = 0,
    val reason: String? = null                 // 拒绝/解散原因
)

/**
 * 协议常量
 */
object ProtocolConstants {
    const val HEARTBEAT_INTERVAL_MS = 30_000L
    const val HEARTBEAT_TIMEOUT_MS = 60_000L
    /**
     * WebSocket 单帧 (JSON 信封全文) 字节数上限 (v2 服务端强制执行)。
     *
     * v3.17: 64KB → 128KB。v3.17.1 消息预算定稿 (文本 40KB / 媒体 48KB) 后核算:
     * - 40KB 文本 → 加密+Base64 后信封 ≈54KB
     * - 48KB 媒体文件 → Base64 文本 ~64KB → 加密+Base64 后信封 ≈86KB
     * 128KB 对最坏情况 (媒体) 仍有 ~33% 余量, 维持不变。
     */
    const val MAX_PAYLOAD_SIZE = 128 * 1024
    const val WEBSOCKET_PATH = "/relay"

    // ==================== v3.74: 双花探针认领 (DUP_CLAIM) ====================

    /**
     * 双花探针认领端点 (v3.74 · 决策 D-2): **独立、不认证**。
     *
     * 与 `WEBSOCKET_PATH` 分离的理由是隐私而非工程整洁 —— 认领帧若
     * 走认证通道, 中继就能把每个 probe 绑定到节点指纹, 盲化带来的
     * "不可链接" 收益会被认证头抵消。独立端点只接受 DUP_CLAIM 一种
     * 帧型, 不做 HELLO/CHALLENGE 握手, 连接即可用, 仅按 IP 限速。
     */
    const val DUPPROBE_PATH = "/dupprobe"

    /**
     * 单 IP 认领速率上限 (条/秒, 令牌桶容量 = 速率)。
     *
     * 依据: 正版客户端只在**交易锚定成功后**认领一次 (每笔交易恰好
     * 一帧), 重度用户峰值 ≪ 5/s。20/s 与业务消息同账, 对正常支付
     * 无任何可感影响; 超限时**丢弃帧不回包** (客户端按超时处理 →
     * 宽松降级标记 PENDING_DUP_CHECK, 不阻塞支付 —— 见 D-1)。
     */
    const val DUP_CLAIM_PER_IP_PER_SECOND = 20

    /**
     * 认领集合**告警阈值** (条) —— v3.74.1 起只是监控水位, 不是放行开关。
     *
     * v3.74.0 曾定义"超限即 granted=true (fail-open)", 已废除: 那等于给
     * 反滥用防线自带一个"放弃防护开关"。SQLite 后端单文件可承载亿级行
     * (每行 ~80B, 亿行 ≈ 8GB), 该阈值的意义仅是提醒运维"该做分片拆库
     * 或归档评审了"。触达时中继照常精确判定, 同时输出告警日志。
     */
    const val DUP_WARN_ENTRIES = 2_000_000

    /**
     * 磁盘可用空间告警线 (字节): 认领库所在分区低于此值时中继周期输出
     * 告警。存储故障时中继**拒绝认领** (granted=null, 三态见
     * [DupClaimResultPayload]), 绝不放行也绝不谎报双花 —— 磁盘水位
     * 监控就是为了让这个拒绝路径永远不被触发。
     */
    const val DUP_DISK_MIN_FREE_BYTES = 1L * 1024 * 1024 * 1024   // 1 GiB

    /** 单条探针十六进制长度 (32 字节) */
    const val DUP_PROBE_HEX_LENGTH = 64

    /**
     * 客户端认领超时 (ms): 超时视为"结果未知" (宽松降级, 不阻塞支付)。
     */
    const val DUP_CLAIM_TIMEOUT_MS = 3_000L

    /**
     * 中继认领库磁盘水位自检周期 (ms)。
     */
    const val DUP_DISK_CHECK_INTERVAL_MS = 5L * 60 * 1000

    /**
     * v2: 注册挑战应答超时 (未完成认证的连接将被断开)
     *
     * v3.67.1 (30s → 90s, 后台认证死循环根治): 客户端 AUTH_REQUIRED
     * (Vault Keystore 认证窗口关闭, 用户不在场) 的后台驻留重试节律为
     * 90s (SIGN_AUTO_RETRY_BACKGROUND_MS), 而本超时 30s —— 重试永远
     * 落在已被踢的死连接之后, 形成「30s 被踢 → 1s 重连 → 90s 排程 →
     * 再被踢」风暴 (生产日志 19:20-19:22 每 30~32s 一条 1008, 8h 内
     * 认证成功仅 6 次, 两端在线率趋零, 消息全堆离线队列 = 用户感知
     * 「消息无法到达」)。90s 让后台重试落在活连接内; 前台「升级用户
     * 级签名」的指纹框交互 (掏机+解锁+按压) 也常超 30s, 同被覆盖。
     * DoS 面由 MAX_CONNECTIONS_PER_IP 与认证期帧预算双重兜底, 不放宽。
     */
    const val AUTH_TIMEOUT_MS = 90_000L

    /** v2: 单 IP 最大并发连接数 */
    const val MAX_CONNECTIONS_PER_IP = 20

    /** v2: 单连接消息速率 (条/秒, 超限断开) */
    const val MAX_MSG_PER_SECOND = 20

    // ==================== v3.18: 群扇出 ====================

    /** 单连接可订阅群数上限 (防订阅表膨胀: 64 群 × 每群 200 人 已是重度用户) */
    const val MAX_GROUP_SUBSCRIPTIONS_PER_CONNECTION = 64

    /**
     * v3.18.1: 单连接控制帧速率 (条/秒, 超限断开)。
     *
     * 适用帧型: GROUP_SUBSCRIBE / GROUP_FANOUT (与业务消息 20 msg/s 分账)。
     *
     * 审计 R2: 这两类帧按群计帧 —— 重连重订阅对每群一帧 GROUP_SUBSCRIBE,
     * 在场心跳每拍对每群一帧 GROUP_FANOUT。若与 MSG 同账 20 msg/s,
     * 21+ 群用户重连即被断连 (重订阅风暴 → 断连 → 重连死循环),
     * 且每 30s 心跳拍整拍被杀 —— v3.18 根治的 "限流误杀" 在多群维度回归。
     *
     * 预算 128 = 64 群重订阅 + 64 群同拍心跳的峰值; 有界性:
     * GROUP_SUBSCRIBE 受 64 群订阅上限硬约束 (幂等重复无副作用),
     * GROUP_FANOUT 受群级 10 msg/s 令牌桶约束 (超限仅丢帧不投递)。
     */
    const val MAX_CONTROL_FRAMES_PER_SECOND = 128

    /**
     * 群级扇出令牌桶: 消息速率上限 (条/秒, 桶容量 = 速率, 即允许 1s 突发)。
     *
     * 200 人群聊天典型峰值 ~7 msg/s (人均 1 条/30s), 10 msg/s 覆盖活跃
     * 时段并抑制刷屏/风暴; 超限消息被丢弃 (回 GROUP_RATE_LIMITED, 不断连)。
     */
    const val GROUP_FANOUT_MSG_PER_SECOND = 10

    /**
     * 群级扇出字节预算: 持续速率 (bytes/s) 与突发容量 (bytes)。
     *
     * 突发容量 16MB > 200 人单条贴纸扇出 egress ≈15.6MB (≈79KB 帧 × 199),
     * 即单条满额贴纸可整帧放行 (瞬时 ~1.25s 满管), 随后以 2MB/s 补充 ——
     * "吸收突发 + 限持续速率"; 连续大贴纸会被迫降速而非丢弃首条。
     */
    const val GROUP_FANOUT_BYTES_PER_SECOND = 2L * 1024 * 1024
    const val GROUP_FANOUT_BYTES_BURST = 16L * 1024 * 1024

    /**
     * 全局扇出 egress 护栏 (令牌桶): 持续 8MB/s / 突发 32MB。
     *
     * 100Mbps ≈ 12.5MB/s: 全局扇出持续吃 8MB/s, 为 1:1 消息/信令留 ~4.5MB/s;
     * 突发容量 32MB 允许两个大群贴纸同时放行 (2 × 15.6MB), 第三个起排队。
     */
    const val GLOBAL_FANOUT_BYTES_PER_SECOND = 8L * 1024 * 1024
    const val GLOBAL_FANOUT_BYTES_BURST = 32L * 1024 * 1024

    // ==================== v3.53: 离线投递队列 ====================

    /**
     * 单节点离线队列深度上限 (条)。
     *
     * 中继对目标离线者缓存消息, 上线即按序冲刷; 超过此深度
     * 拒收新消息 (回 QUEUE_FULL), 防恶意/失控客户端将中继内存
     * 当免费存储池。512 条 ≈ 单聊一周重度使用量级, 正常用户
     * 远触不到顶。
     */
    const val OFFLINE_QUEUE_MAX_DEPTH = 512

    /**
     * 单条离线消息在队列中的最大滞留时长 (24 小时)。
     *
     * 超期即被丢弃 —— 中继不做持久化承诺, 只解决「对方暂时
     * 不在线」的投递窗口; 24h 覆盖一日活跃周期, 对齐涂鸦卡片
     * /群消息的统一托管语义, 又限制最坏内存占用时长 (512 条
     * × 128KB ≈ 64MB/节点为理论上限, 实际文本消息帧体 ≈4KB,
     * 512 条 ≈ 2MB)。
     */
    const val OFFLINE_QUEUE_TTL_MS = 24L * 60 * 60 * 1000

    /**
     * 节点上线后离线队列的冲刷限速 (条/秒)。
     *
     * 防止大队列上线瞬间灌满接收方连接与客户端解码;
     * 256 条/s 下 512 条满队列 ≈2s 冲刷完毕, 用户无感。
     */
    const val OFFLINE_QUEUE_FLUSH_PER_SECOND = 256

    // ==================== v3.56: 群消息离线托管 (backlog) ====================

    /**
     * 单群 backlog 深度上限 (条)。
     *
     * 群消息 24h 托管窗口的载体: 中继为「订阅时不在场」的成员
     * 保留近窗口消息, 订阅 (含重连重订阅) 时快照冲刷。超深度
     * 丢最旧 (ring 语义) —— backlog 是尽力补投, 不做完整性承诺。
     * 512 条 ≈ 活跃群 24h 消息量级。
     */
    const val GROUP_BACKLOG_MAX_DEPTH = 512

    /**
     * 中继跟踪的群 backlog 总数上限 (个)。
     *
     * backlog 按 groupId 键控 —— 中继仍不持有群成员表 (零群组
     * 状态红线), 只见「有扇出流量的群」。超限时不再为新群建
     * backlog (既有群不受影响), 防恶意指纹农场以随机 groupId
     * 撑爆内存。
     */
    const val GROUP_BACKLOG_MAX_GROUPS = 4096

    // ==================== v3.56: 涂鸦墙 ====================

    /**
     * 涂鸦留言卡正文的词元上限 (300 词元)。
     *
     * 词元口径 (GraffitiTokenCounter): CJK 表意文字逐字计 1,
     * 拉丁字母/数字连续串计 1 (按词), 其余符号/空格/emoji 计 1。
     * 客户端发帖框实时计数拦截, 中继同口径二次校验 (公开广播
     * 面必须服务端把关, 与私聊「零解析」红线不同 —— 涂鸦内容
     * 本就是主动公开的推广留言)。
     */
    const val GRAFFITI_MAX_TEXT_TOKENS = 300

    /**
     * 涂鸦卡片配图体积上限 (v3.63): base64 字节 ≤ 90KB。
     *
     * 图片在客户端选图后压缩至该上限 (≤90KB), 以 base64 内联于
     * 卡片 JSON 随 GRAFFITI_POST/CARD 传播。客户端走「压缩至达标」:
     * 反复降采样直到 base64 长度不超限; 中继侧对超限卡拒收 (回
     * GRAFFITI_IMAGE_TOO_LARGE), 双侧同口径。
     */
    const val GRAFFITI_MAX_IMAGE_B64_BYTES = 90 * 1024

    /**
     * 涂鸦墙全局卡片数上限 (张)。
     *
     * v3.81 (用户拍板): 1024 → 9192, 定位类论坛翻阅。语义从 ring
     * 改为**满员拒收** —— 墙满时 GRAFFITI_POST 回 GRAFFITI_WALL_FULL,
     * 客户端弹温馨等候卡片, 不再静默丢最旧。内存: 9192 × ~1KB 文本
     * ≈ 9MB; 图片卡最坏 90KB/张由全局字节护栏兜底 (超限淘汰最旧,
     * 安全阀语义, 正常不触发)。
     */
    const val GRAFFITI_WALL_MAX_CARDS = 9192

    /**
     * v3.81: 快照分页页大小 (张)。
     *
     * SUBSCRIBE 首刷只发最新 300 张 + GRAFFITI_PAGE_END; 客户端
     * 瀑布流触底发 GRAFFITI_MORE(offset) 续领。不加搜索 (用户拍板:
     * 翻阅才有意思), 分页仅为移动端流量/内存可控。
     */
    const val GRAFFITI_PAGE_SIZE = 300

    /** v3.81: 卡片留言词元上限 (口径同 GraffitiTokenCounter) */
    const val GRAFFITI_COMMENT_MAX_TOKENS = 100

    /** v3.81: 留言全局冷却 (同指纹两条留言最小间隔, 防跨卡灌水) */
    const val GRAFFITI_COMMENT_COOLDOWN_MS = 10_000L

    /** v3.81: 每卡留言保留上限 (超出丢最旧; 同卡同指纹限 1 条) */
    const val GRAFFITI_COMMENTS_MAX_PER_CARD = 200

    /**
     * 涂鸦卡片展示时长 = 托管 TTL (24 小时)。
     *
     * 中继侧超期出墙 (快照/广播不再含); 客户端侧按卡片 ts
     * 本地过期清理 (时钟独立判活, 双侧一致收敛)。
     */
    const val GRAFFITI_TTL_MS = 24L * 60 * 60 * 1000

    /**
     * 单指纹发涂鸦卡的最小间隔 (30 秒)。
     *
     * 100000 SPARK/张 是客户端钱包侧的经济学约束 (与消息计费
     * 同为客户端执行、服务端不做账本核验); 中继侧对公开广播
     * 面叠加轻量节奏护栏 —— 30s 足以封死脚本刷墙, 正常用户
     * 无感 (写卡 + 看墙的往返远超 30s)。
     */
    const val GRAFFITI_POST_COOLDOWN_MS = 30_000L

    /**
     * 涂鸦墙订阅快照的冲刷限速 (条/秒)。
     *
     * 与离线队列冲刷同级: 满墙 1024 张 ≈4s 冲完, 不瞬时灌满
     * 客户端解码与 UI 重组。
     */
    const val GRAFFITI_FLUSH_PER_SECOND = 256
}

/**
 * GRANT_CHECK 载荷 (v3.45) - 领金日去重
 *
 * h 为设备哈希: SHA-256("spark-grant-dedupe/1" ‖ day ‖ deviceSeed) 前 16 hex。
 * deviceSeed 客户端本地派生 (TEE/DRM 种子优先, 跨卸载稳定) —— 中继只见
 * 不可链接哈希, 不同日互不可关联, 中继无法跨日追踪同一设备。
 * day 由客户端本地日历产生; 时钟偏移攻击由 Vault 签名侧
 * "memo 必须 == Vault 本地今日" 门槛封死, 中继不做时钟裁决。
 */
@Serializable
data class GrantCheckPayload(
    val h: String,     // 设备日哈希 (16 hex)
    val day: String    // 客户端本地领金日 (yyyy-MM-dd)
)

/**
 * ═══════════════════════════════════════════════════════════════════
 *  v3.74 · 双花探针认领 (DUP_CLAIM / DUP_CLAIM_RESULT)
 * ═══════════════════════════════════════════════════════════════════
 *
 * 语义: **(钱包, 递增序号) 全局唯一认领** —— 同一 probe 首次出现即占
 * 位并返回 granted=true; 再次出现返回 granted=false, 表示该序号已被
 * 花过 (双花)。
 *
 * ```
 * probe = SHA256("SPARK-TX-DUP-PROBE-V1" ‖ SHA256(钱包公钥X.509) ‖ u64be(seq))
 * ```
 *
 * 隐私契约 (红线):
 * · probe 是**盲化**的 —— 中继拿它推不出钱包公钥, 也推不出序号;
 * · 同一钱包的不同序号产生**互不关联**的伪随机串, 中继看不出它们
 *   同源, 更看不出消费进度;
 * · 因此本帧走**独立不认证端点** `ProtocolConstants.DUPPROBE_PATH`
 *   (见 D-2): 不携带任何身份指纹, 中继只做 IP 维度限速。若走认证通道,
 *   中继就能把 probe 关联到节点指纹, 多次认领可按指纹聚合成序列 ——
 *   盲化带来的隐私收益会被认证头一笔勾销。
 */

/**
 * DUP_CLAIM 载荷 (v3.74) - 客户端 → 中继
 *
 * @param probe 64 hex 盲化探针 (算法见 [DupProbe], core-crypto)
 * @param id 请求 id (客户端自增, 用于并发请求与回包配对; 中继原样回显, 不解析语义)
 */
@Serializable
data class DupClaimPayload(
    val probe: String,
    val id: String
)

/**
 * DUP_CLAIM_RESULT 载荷 (v3.74.1 起为**三态**) - 中继 → 客户端
 *
 * @param granted 三态:
 *   - `true`  = 首次认领成功 (probe 已持久化入集合);
 *   - `false` = 已被认领过 (疑似双花);
 *   - `null`  = **服务暂不可用** (存储故障) —— v3.74.1 修正: 中继在存储
 *     故障时**绝不放行** (授予是安全决策, 故障时没有资格做), 也不谎报
 *     "双花" (不冤枉用户), 而是明确说"我不知道"。客户端按宽松降级
 *     (D-1) 处理: 不阻塞支付, 记待核验, 联网后补认领。
 *     历史包袱说明: v3.74.0 曾在集合容量超限时返回 granted=true
 *     (fail-open), 那是反滥用防线自带的"放弃防护开关", 已废除 ——
 *     容量是运维问题 (监控告警/扩容分片), 不是放行的理由。
 * @param id 回显请求 id (与 DUP_CLAIM 同值, 供客户端配对)
 */
@Serializable
data class DupClaimResultPayload(
    val probe: String,
    val granted: Boolean? = null,
    val id: String
)

/**
 * GRANT_ACK 载荷 (v3.45) - 中继应答
 *
 * allowed=false = 该 (day, h) 已被领取过 (当日重复/重装重领)。
 */
@Serializable
data class GrantAckPayload(
    val allowed: Boolean,
    val day: String
)

/**
 * MSG_ACK 载荷 (v3.53) - 中继对 MSG/GROUP_MSG 发送方的投递回执
 *
 * status 三态:
 * - "queued":    目标离线, 消息已入中继离线队列, 待目标上线冲刷
 * - "delivered": 目标在线且帧已写入其连接 (1:1) / 已扇出至订阅集 (群)
 * - "rejected": 消息被拒 (队列满等, 仅当作为通用失败态时出现;
 *                队列满的规范路径是独立的 QUEUE_FULL 信封)
 *
 * seq 为被回执消息的原始 seq (发送方据此匹配本地待确认表)。
 * 计费契约: 客户端仅在收到 delivered 后才视为「发送成功」
 * 而落账扣费; queued 状态语义为「中继已代管, 但未送达」——
 * 对端上线冲刷成功前不扣费, 冲刷后按离线送达结算。
 */
@Serializable
data class MsgAckPayload(
    val status: String,     // MsgAckStatus.QUEUED / DELIVERED / REJECTED
    val seq: Long,          // 被回执消息的原始 seq (发送方匹配用)
    val target: String,     // 被回执消息的目标 (单聊指纹 / 群 groupId)
    val ts: Long = 0        // 回执产生时间 (epoch ms, 中继时钟)
)

/**
 * MSG_ACK status 常量 (v3.53)
 */
object MsgAckStatus {
    const val QUEUED = "queued"
    const val DELIVERED = "delivered"
    const val REJECTED = "rejected"
}

/**
 * GRAFFITI_CARD 载荷 (v3.56) - 涂鸦留言卡
 *
 * 涂鸦墙是**主动公开**的推广留言面: 内容为明文 JSON (不加密),
 * 作者指纹即回传通道 —— 读者点卡片可复制指纹加联系人。
 * 与私聊信封的「零解析」红线不同, 中继对公开广播面做内容
 * 约束校验 (词元上限 / author 一致性), 防滥用广播信道。
 *
 * · id:     发帖方生成的 UUID —— 接收端幂等去重键;
 * · author: 发帖人指纹 (中继校验 == 信封 source);
 * · text:   留言内容 (≤300 词元);
 * · effect: 卡片特效编号 (0..5, 发帖端随机挑选, 接收端据此
 *           渲染渐变/光晕等视觉 —— 纯表现层, 协议不解释);
 * · imageB64: 可选配图 (base64, ≤90KB; v3.63 新增, 旧端缺省
 *           空串仍可解析 —— 向后兼容);
 * · ts:     发帖时间 (发帖端时钟, 接收端按 ts + TTL 判过期)。
 */
@Serializable
data class GraffitiCardPayload(
    val id: String,        // 卡片唯一 ID (UUID, 接收端去重键)
    val author: String,    // 发帖人指纹
    val text: String,      // 留言内容 (≤300 词元)
    val effect: Int = 0,   // 卡片特效编号 (表现层)
    val imageB64: String? = null, // v3.63: 可选配图 (≤90KB base64)
    val ts: Long,          // 发帖时间戳 (epoch ms)
    // v3.81: 浏览数 (按指纹去重) + 留言列表 (自包含, 方案 A)。
    // 旧版客户端 ignoreUnknownKeys 忽略两字段, 向后兼容。
    val views: Int = 0,
    val comments: List<GraffitiCommentPayload> = emptyList()
)

/**
 * 涂鸦卡片留言 (v3.81)
 *
 * 公开明文, 与卡片同生命周期 (卡出墙留言随之消失)。产品语义:
 * 互动 + 群众曝光骗局 (不做中心化制裁); 10 SPARK/条 + 同卡同指纹
 * 限 1 条, 双约束防灌水 (用户拍板)。
 */
@Serializable
data class GraffitiCommentPayload(
    val id: String,        // 留言 UUID (去重键)
    val cardId: String,    // 所属卡片 ID
    val author: String,    // 留言人指纹 (== 认证身份, 中继校验)
    val text: String,      // 留言内容 (≤100 词元)
    val ts: Long           // 留言时间戳 (epoch ms)
)

/** GRAFFITI_COMMENT 请求载荷 (v3.81, 客户端 → 中继) */
@Serializable
data class GraffitiCommentReqPayload(
    val cardId: String,
    val text: String
)

/** GRAFFITI_VIEW 请求载荷 (v3.81, 客户端 → 中继) */
@Serializable
data class GraffitiViewReqPayload(
    val cardId: String
)

/** GRAFFITI_MORE 请求载荷 (v3.81, 客户端 → 中继: 自 offset 续领一页) */
@Serializable
data class GraffitiMorePayload(
    val offset: Int
)

/**
 * GRAFFITI_PAGE_END 载荷 (v3.81, 中继 → 客户端)
 *
 * 一页 GRAFFITI_CARD 冲刷完毕的收尾标记:
 * · offset    本页起点 (订阅首刷 = 0)
 * · delivered 本页实际送达张数 (可能 < PAGE_SIZE: 墙尾/过期截断)
 * · hasMore   墙里还有没有更旧的卡
 * · wallTotal 当前在墙总张数 (UI「墙已满 x/9192」等候提示用)
 */
@Serializable
data class GraffitiPageEndPayload(
    val offset: Int,
    val delivered: Int,
    val hasMore: Boolean,
    val wallTotal: Int
)

/**
 * 涂鸦词元计数器 (v3.56)
 *
 * 「字数≤300词元」的统一口径 —— 客户端发帖框与中继校验共用,
 * 双侧必须逐字一致 (改口径 = 协议变更):
 * · CJK 表意文字 (含扩展A/兼容表意): 逐字计 1;
 * · 拉丁字母/数字连续串: 计 1 (按词);
 * · 其余字符 (标点/空格/emoji/其他文字): 逐字计 1。
 *
 * 与 Unicode code point 对齐 (emoji 按码点拆分, 不按 char 拆 ——
 * surrogate pair 计 1 而非 2), 避免同一文本两端计数漂移。
 */
object GraffitiTokenCounter {

    /** 文本词元数 (发帖框实时计数 / 中继入墙校验共用) */
    fun count(text: String): Int {
        var tokens = 0
        var inLatinRun = false
        var index = 0
        while (index < text.length) {
            val cp = text.codePointAt(index)
            if (isCjk(cp)) {
                tokens++
                inLatinRun = false
            } else if (Character.isLetterOrDigit(cp) && !isCjk(cp)) {
                // 拉丁/数字连续串合一词元; 其他文字体系 (西里尔/
                // 希腊/假名等) 走逐字口径
                if (!inLatinRun) {
                    tokens++
                    inLatinRun = true
                }
            } else {
                tokens++
                inLatinRun = false
            }
            index += Character.charCount(cp)
        }
        return tokens
    }

    /** CJK 表意文字判定 (统一表意 + 扩展A + 兼容表意) */
    private fun isCjk(cp: Int): Boolean = when (cp) {
        in 0x4E00..0x9FFF -> true   // CJK 统一表意
        in 0x3400..0x4DBF -> true   // 扩展 A
        in 0xF900..0xFAFF -> true   // 兼容表意
        in 0x3040..0x30FF -> true   // 假名 (逐字口径)
        else -> false
    }
}
