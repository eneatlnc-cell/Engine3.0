package com.securesocial.core.protocol

import kotlinx.serialization.Serializable
import java.security.MessageDigest

/**
 * Spark 账本协议定义 (v3.15)
 *
 * 架构定位:
 * - Spark 是产品方发行的计费货币; 账本为**独立有状态服务** (spark-ledger,
 *   部署于 VPS), 与无状态中继并行 —— 中继零状态红线不破
 * - 账户 = 身份指纹 (与中继/E2EE 同一套 ECDSA P-256 身份体系)
 * - 所有写操作经身份私钥签名 (客户端经 Vault IPC 完成签名,
 *   服务端用开户时登记的公钥验签)
 *
 * 计费模型 (本地预扣 + 批量结算 + 服务端权威):
 * - 按 KB 计费: 1KB = 10 Spark (v3.27 由 1 上调至 10) —— 消息按 UTF-8
 *   字节数向上取整计费, 单条最低 10 Spark (17 字节贴纸引用与 1KB 文本
 *   同为 10 Spark, 40KB 满额文本 400 Spark; 预算上限不变)
 * - 赠金模型 (v3.34): 设备终生一次激活赠金退役 —— 内测期改为
 *   每日登录赠送: 每自然日 (本地时区) 首次进入首页弹框确认后
 *   发放 1,000 SPARK, 当日幂等; 服务端 spark-ledger 接入后按
 *   服务器日历裁决 (防改本地时间刷领)
 * - 客户端本地预扣余额视图 (零额外延迟), 每累计 N 条 / 定时批量上报
 *   totalSpent (累计消耗 Spark 数, 单调递增), 服务端按差值扣减并回传
 *   权威余额, 客户端校正本地视图
 * - 防作弊边界: 客户端篡改少报 → 服务端余额与上报值同步锁定,
 *   透支上限 = 一次结算周期的消耗量; 正式版可升级为逐条签名结算
 */
object SparkAuth {

    /** 签名域分隔符 */
    const val DOMAIN = "SPARK-V1"

    // HTTP 签名头
    const val HEADER_FP = "X-Spark-FP"
    const val HEADER_TS = "X-Spark-TS"
    const val HEADER_NONCE = "X-Spark-Nonce"
    const val HEADER_SIG = "X-Spark-Sig"
    const val HEADER_ADMIN = "X-Spark-Admin"

    /** 时间戳容忍窗口 (±5 分钟, 防重放窗口与 nonce 缓存 TTL 一致) */
    const val TIMESTAMP_TOLERANCE_MS = 5 * 60 * 1000L

    /**
     * 构建签名内容: "SPARK-V1" ‖ fp ‖ ts ‖ nonce ‖ SHA-256(body)
     *
     * 签名 = ECDSA(SHA256withECDSA, DER) 由身份私钥完成。
     * ts/nonce 以十进制/原文 UTF-8 拼接, 与 body 哈希一并绑定,
     * 请求体不可篡改、不可重放。
     */
    fun signingContent(fp: String, ts: Long, nonce: String, body: ByteArray): ByteArray {
        val bodyHash = MessageDigest.getInstance("SHA-256").digest(body)
        return (DOMAIN + fp + ts + nonce).toByteArray(Charsets.UTF_8) + bodyHash
    }
}

/**
 * Spark 计费经济常量 (客户端拦截 / 服务端结算共用)
 */
object SparkEconomy {

    /** 计费单价: 每 1024 字节 (UTF-8) 计 10 Spark (v3.27 由 1 上调) */
    const val SPARK_PER_KB = 10L

    /** 单条消息最低消耗 (防 0 成本垃圾消息 —— 与 SPARK_PER_KB 对齐, 不足 1KB 按 1KB 计) */
    const val MIN_COST_PER_MESSAGE = 10L

    /**
     * 计费函数: 按消息 UTF-8 字节数计费, 1KB = 10 Spark, 向上取整,
     * 单条最低 [MIN_COST_PER_MESSAGE]。
     *
     * - 17 字节贴纸引用 → 10 Spark; 40KB 满额文本 → 400 Spark
     * - 群消息按发送方单条计费 (扇出是传输行为, 不是计费事件)
     */
    fun costFor(bytes: Long): Long {
        require(bytes >= 0) { "bytes must be >= 0" }
        if (bytes == 0L) return MIN_COST_PER_MESSAGE
        return maxOf(MIN_COST_PER_MESSAGE, (bytes + 1023) / 1024 * SPARK_PER_KB)
    }

    /**
     * 每日登录赠金 (v3.34): 每自然日 (本地时区) 一次 —— 首页弹框
     * 确认后入账钱包 (不自动入账)。
     * v3.27 设备终生一次激活赠金模型退役; 内测期 SPARK 不可转移
     * 与兑换, 纯燃料计费闭环。
     */
    const val DAILY_LOGIN_GRANT = 1000L

    /**
     * 单条文本消息字节上限 (UTF-8): 40KB。
     *
     * v3.17 由 1KB 上调至 60KB 支持媒体内联; v3.17.1 下调至 40KB 定稿:
     * 文本场景 40KB (≈2 万汉字) 已远超聊天所需, 收紧上限可同时压低
     * 中继最坏帧体与群组扇出流量 (200 人群 × 54KB 帧 ≈ 10.6MB/条,
     * 100Mbps VPS 上 ≈0.85s 满管)。
     */
    const val MAX_MESSAGE_BYTES = 40 * 1024

    /**
     * 单条媒体消息 (贴纸/表情) 解码后字节上限: 48KB。
     *
     * 媒体以 Base64 文本装载 (膨胀 4/3): 48KB 文件 → ~64KB 文本,
     * 超出 40KB 文本上限, 故媒体消息不走 [MAX_MESSAGE_BYTES] 文本校验,
     * 而是按解码后原始字节对照本预算 (Spark 表情包全量 ≤44KB 落于预算内,
     * 余 4KB 供后续表情包变体)。
     *
     * 编码链路核算: 48KB → Base64 ~64KB → AES-GCM ~64KB → 信封 Base64
     * ~86KB < 128KB 帧上限, 链路自洽。
     */
    const val MAX_MEDIA_BYTES = 48 * 1024

    /** 批量结算阈值: 未上报条数达到此值立即结算 */
    const val SETTLE_BATCH = 10

    /** 批量结算定时 (兜底) */
    const val SETTLE_INTERVAL_MS = 30_000L

    /** 交易明细保留条数 (每账户, 服务端) */
    const val TX_KEEP_PER_ACCOUNT = 100

    /** 交易明细返回条数 (单次查询) */
    const val TX_QUERY_LIMIT = 50
}

/**
 * Spark 错误码
 */
object SparkErrorCodes {
    const val BAD_REQUEST = "BAD_REQUEST"           // 参数不合法
    const val NO_ACCOUNT = "NO_ACCOUNT"             // 账户不存在 (未开户)
    const val ALREADY_OPEN = "ALREADY_OPEN"         // 重复开户 (幂等成功)
    const val ALREADY_CLAIMED = "ALREADY_CLAIMED"   // 每日赠金今日已领 (幂等成功, v3.34 每日一次)
    const val BAD_SIGNATURE = "BAD_SIGNATURE"       // 签名缺失/伪造/不可解码
    const val REPLAY = "REPLAYED_NONCE"             // nonce 重放
    const val EXPIRED_TS = "EXPIRED_TS"             // 时间戳超出容忍窗口
    const val INSUFFICIENT = "INSUFFICIENT"         // 余额不足
    const val SETTLE_REGRESSION = "SETTLE_REGRESSION" // totalSpent 回退
    const val RATE_LIMITED = "RATE_LIMITED"         // 请求过频
    const val FORBIDDEN = "FORBIDDEN"               // 管理接口令牌错误
}

// ==================== API 模型 ====================

/** 开户: 登记身份公钥 */
@Serializable
data class SparkOpenRequest(
    val fingerprint: String,
    val pubkey: String            // X.509 Base64 (验签用)
)

/** 每日登录赠金领取 (幂等; v3.34: 每自然日一次, 服务端日历权威裁决) */
@Serializable
data class SparkClaimRequest(
    val date: String = ""         // 客户端本地日期 (仅参考, 服务端按自身日历裁决)
)

/** 批量结算: 上报累计消耗 Spark 数 (单调递增; 按 KB 计费后口径从条数改为消耗量) */
@Serializable
data class SparkSettleRequest(
    val totalSpent: Long
)

/** 转账 */
@Serializable
data class SparkTransferRequest(
    val to: String,               // 对方指纹
    val amount: Long,             // > 0
    val memo: String = ""
)

/** 运营充值 (admin·mint) */
@Serializable
data class SparkMintRequest(
    val to: String,
    val amount: Long,
    val memo: String = "充值"
)

/** 空请求体 (balance / history) */
@Serializable
data class SparkEmptyRequest(
    val nonce: String = ""
)

/** 统一应答: 成功携带业务字段, 失败携带 error */
@Serializable
data class SparkBalanceResponse(
    val ok: Boolean = false,
    val balance: Long = 0,
    val error: String? = null,
    val message: String? = null
)

@Serializable
data class SparkClaimResponse(
    val ok: Boolean = false,
    val claimed: Boolean = false,   // false = 今日已领 (幂等)
    val amount: Long = 0,
    val balance: Long = 0,
    val date: String = "",
    val error: String? = null,
    val message: String? = null
)

@Serializable
data class SparkSettleResponse(
    val ok: Boolean = false,
    val spent: Long = 0,            // 本次结算扣减量
    val balance: Long = 0,
    val error: String? = null,
    val message: String? = null
)

@Serializable
data class SparkTransferResponse(
    val ok: Boolean = false,
    val balance: Long = 0,
    val error: String? = null,
    val message: String? = null
)

/** 交易明细条目 */
@Serializable
data class SparkTxEntry(
    val type: String,          // OPEN/CLAIM/SPEND/TRANSFER_IN/TRANSFER_OUT/MINT
    val amount: Long,          // 有符号
    val balanceAfter: Long,
    val note: String,
    val ts: Long
)

@Serializable
data class SparkHistoryResponse(
    val ok: Boolean = false,
    val transactions: List<SparkTxEntry> = emptyList(),
    val error: String? = null,
    val message: String? = null
)
