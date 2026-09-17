package com.securesocial.core.wallet

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.security.MessageDigest
import java.util.Base64

/**
 * ═══════════════════════════════════════════════════════════════════
 *  SPARK 本地钱包 — 交易模型与规范化序列化 (纯 Kotlin)
 *  v3.37: 签名账本基础 · v3.38: 双账户模型 + 交接协议
 * ═══════════════════════════════════════════════════════════════════
 *
 *  设计核心: **余额不是存储值, 是签名历史的推导值** (比特币钱包模型):
 *  · 账本 = append-only 交易日志, 每笔交易由 Vault 内的钱包私钥签名;
 *  · 余额 = Σ(日志) —— 篡改任何一笔交易, 其签名校验立即失败;
 *  · 删除/回滚任意中段交易, prevTxHash 链与序号连续性双双断裂;
 *  · 任何人持有钱包公钥即可独立验证整条链 (无需信任设备本地存储)。
 *
 *  v3.39 单账户合并 (用户定稿): SPARK 后期可交易可兑换, 托管/可用
 *  双账户区分不再有意义 —— **余额 = custody + margin (total)**, 统一
 *  呈现为 "可用余额"。
 *  · 兼容性: effects() 的双账户向量保留 (旧链交易的验签与推导依赖
 *    既有字节语义, 不可变更); 新交易照常记账, 只是展示与足额判断
 *    一律取 [WalletBalances.total];
 *  · DEPOSIT/WITHDRAW (账户内划转) 的 total 效果为 0 —— 合并后不再
 *    产生新划转交易, 旧链上的划转对 total 无影响, 天然兼容;
 *  · 足额与校验规则同步改为 "total 运行余额恒 ≥ 0" (旧链的双账户
 *    分量均非负 → total 必然非负, 升级不破坏任何已签链)。
 *
 *  v3.38 双账户 (交易所式, 历史语义, 仅旧链推导使用):
 *  · custody (托管) — 钱包主账本余额, 由 Vault 权威记账; 外部获得的
 *    SPARK 与未来购买通道入账于此; 换机时随交接证书迁移;
 *  · margin (保证金) — Engine 侧可用余额 (消息计费/打赏/密封支付),
 *    收入直达 (B 方案, 零摩擦), 经 DEPOSIT 从 custody 充值获得;
 *    换机不迁移 (可弃设计, 丢了就再充)。
 *
 *  GENESIS 的双语义 (v3.38 定稿, 按 counterparty 判别):
 *  · counterparty == null — 旧明文余额迁移 / 钱包重置承接:
 *    金额直达 margin (历史余额本就是可用形态, 保持 v3.37 行为);
 *  · counterparty != null — 换机交接承接 (counterparty = 旧公钥 hex):
 *    金额入 **custody** —— 旧机的托管储蓄迁移后仍是托管储蓄,
 *    不会静默变成可热支付的 margin (托管 = 绝对安全层的定位)。
 *
 *  与消息计费 (SparkEconomy) 的关系: 本模块只管"账", 不管"价" ——
 *  定价规则仍在 core-protocol; 钱包层接收任意 amount 并记账。
 *
 *  诚实边界 (v3.38, spark-ledger 上线前):
 *  · RECEIVE/GRANT 为自记账 (自签 = 防篡改, 不证明对手方确实付款);
 *  · 双花 (隐藏另一条日志) 本地无法根除 —— 对手方验证通道未接入;
 *  · Vault 侧权威账本 + 高水位序号挡"恢复旧备份重放余额",
 *    但 root 级攻击者仍可同时清写两侧存储 (TEE 保密钥, 不保存储);
 *  · 交接 (HANDOVER) 为单方终结语义: 新链不回指旧链的历史, 旧链
 *    在交接后不可再续签 (Vault 清除密钥), 双活窗口见 HandoverCertificate。
 */

/** 交易类型 */
enum class TxType {
    /** 一次性迁移: 旧明文余额 → 签名账本 (必须是链上第一笔); v3.38 交接承接亦用此类型 */
    GENESIS,

    /** 每日登录赠金入账 (自记账, 直达 margin) */
    GRANT,

    /** 支出: 消息计费 / 打赏 / 密封支付 (扣 margin) */
    SPEND,

    /** 收入: 被打赏 / 收到礼物 / 密封支付入账 (自记账, 直达 margin) */
    RECEIVE,

    /** 充值: custody → margin (v3.38 划转; v3.39 起不再产生新交易, 仅旧链推导) */
    DEPOSIT,

    /** 提回: margin → custody (v3.38 预留; v3.39 起同 DEPOSIT, 仅旧链推导) */
    WITHDRAW,

    /**
     * 钱包交接: 旧密钥签署的终结交易, 把全部余额 (v3.39: total) 移交新公钥。
     * 必须是链上最后一笔 (其后不可再有任何交易); amount 必须 == 交接
     * 时点的 total 余额 (全额移交); counterparty = 新公钥 hex。
     */
    HANDOVER,
}

/**
 * 双账户余额快照 (推导值)。
 *
 * v3.39: 对外余额语义统一为 [total] (custody + margin) —— 单一可用余额;
 * custody/margin 分量仅为旧链 (v3.38 划转交易) 推导保留, 新代码不消费。
 */
data class WalletBalances(
    /** 托管余额 (v3.38 历史语义; 旧链推导保留) */
    val custody: Long,
    /** 保证金余额 (v3.38 历史语义; 旧链推导保留) */
    val margin: Long,
) {
    /** 可用余额 (v3.39 合并语义): 托管 + 可用的总和 */
    val total: Long get() = custody + margin

    operator fun plus(other: WalletBalances): WalletBalances =
        WalletBalances(custody + other.custody, margin + other.margin)
}

/**
 * 每日登录赠金约定 (v3.39 提升为两 App 共用契约):
 * · Engine (SparkWalletManager) 生成 GRANT 交易时 memo = "daily-grant:<yyyy-MM-dd>";
 * · Vault (WalletKeyManager) 以同一约定扫描权威账本做**每日幂等**判定
 *   (卸载重装 Engine 不再重复领取 —— 账本为准, 不依赖 Engine 本地标记)。
 * · 两侧同设备同时区, 日期口径天然一致。
 */
object WalletGrant {
    /** 每日赠金 memo 前缀; 完整格式 "daily-grant:<yyyy-MM-dd>" */
    const val MEMO_PREFIX = "daily-grant:"

    /**
     * 每日赠金标准额度 (v3.43: Vault 签名侧金额白名单判据)。
     *
     * 与 Engine 侧 SparkEconomy.DAILY_LOGIN_GRANT 同值 —— GRANT 交易
     * 金额由 Engine 填写, 签名前 Vault 强制等于本值: 被篡改/伪造的
     * Engine (或未来回归) 无法以任意金额铸造赠金。
     */
    const val DAILY_GRANT_AMOUNT = 1000L

    /** 生成指定时刻所在日的赠金 memo (yyyy-MM-dd, 设备本地时区) */
    fun memoForDate(epochMillis: Long = System.currentTimeMillis()): String {
        val fmt = java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US)
        fmt.timeZone = java.util.TimeZone.getDefault()
        return MEMO_PREFIX + fmt.format(java.util.Date(epochMillis))
    }

    /** memo 是否为指定时刻所在日的赠金 (幂等判定) */
    fun isGrantMemoForDate(memo: String?, epochMillis: Long = System.currentTimeMillis()): Boolean =
        memo != null && memo == memoForDate(epochMillis)
}

/**
 * 交易来源归属保留字 (v3.49)。
 *
 * source 字段取值为发起应用包名 (com.engine 及未来同证书应用) 或本
 * 保留字 —— [VAULT] 表示操作由 Vault 自身发起 (交接出账 / 承接 GENESIS),
 * 不归属任何应用。
 */
object TxSource {
    /** Vault 内部操作 (非应用发起) */
    const val VAULT = "vault"
}

/**
 * 一笔签名交易。JSON 形态用于落盘与 IPC 载荷; 签名对象是
 * [TxCanonical.bytes] 的规范化字节 (字段定序 + 长度前缀,
 * 与 JSON 序列化的字段顺序/空白完全无关 —— 签名永不因
 * 序列化抖动而失效)。
 *
 * @param seq          链内序号, 严格递增, 首笔 ≥ 1 (缺口 = 烧号痕迹, 见 WalletLedger)
 * @param amount       金额, 恒正 (方向与账户由 [type] 决定, 见 [effects])
 * @param counterparty 对手方指纹 (hex); HANDOVER 时为新公钥 hex; GENESIS(交接承接)时为旧公钥 hex
 * @param memo         业务线索 ("daily-grant:2026-08-27" / "msg×5" / "tip:a1b2c3d4" / "handover:1:<hash>")
 * @param prevTxHash   前一笔交易的 [WalletTx.txHash]; 首笔为 ""
 * @param signature    Base64(DER ECDSA-P256) 对 [TxCanonical.bytes] 的签名
 * @param source       v3.49 来源归属: 发起应用包名 / [TxSource.VAULT] / null(旧链)。
 *                     **未签名元数据列** —— 不进 [TxCanonical] 签名域, 由
 *                     Vault 在签名时注入 (调用方自报无效, 见 WalletKeyManager):
 *                     一钱包一总账模型下, 记录 "这笔 SPARK 变动由哪个应用
 *                     发起"。旧链交易解码为 null, 展示为 "未知 (升级前)"。
 */
@Serializable
data class WalletTx(
    val seq: Long,
    val type: TxType,
    val amount: Long,
    val counterparty: String? = null,
    val memo: String? = null,
    val timestamp: Long,
    val prevTxHash: String = "",
    val signature: String = "",
    val source: String? = null,
) {
    /** 本交易的哈希: SHA-256(规范化字节 ‖ 签名字节) 的 hex —— 链式链接材料 */
    val txHash: String
        get() = TxCanonical.txHash(this)

    /**
     * 双账户效果 (v3.38):
     *
     * | type          | custody | margin |
     * |---------------|---------|--------|
     * | GENESIS(迁移) | 0       | +a     |  counterparty == null
     * | GENESIS(承接) | +a      | 0      |  counterparty != null (换机交接)
     * | GRANT         | 0       | +a     |
     * | RECEIVE       | 0       | +a     |
     * | SPEND         | 0       | −a     |
     * | DEPOSIT       | −a      | +a     |
     * | WITHDRAW      | +a      | −a     |
     * | HANDOVER      | −a      | 0      |
     * |
     * |---------------|---------|--------|
     * ⚠ 边界 (v3.39 total 语义, 修复 B-5): HANDOVER 全额移交 **total** 时,
     * effects() 的 custody 分量为 −a; 在 running 推导上下文中, 单分量可按
     * "custody += eff.custody" 被算成负值 (例: custody 2000 → handover 4500
     * ⇒ custody = −2500)。这仅是**推导中间值, 不用于任何余额消费** —— 支出/
     * 足额/展示一律取 [WalletBalances.total] (恒 ≥ 0)。若未来任何调用方直接
     * 消费 custody/margin 单分量, 必须先对分量做 **max(0) 钳制**, 否则会读到
     * 负余额语义; 现有 total 校验保持不变。
     */
    fun effects(): WalletBalances = WalletBalances(
        custody = when (type) {
            TxType.DEPOSIT, TxType.HANDOVER -> -amount
            TxType.WITHDRAW -> amount
            // 交接承接 GENESIS: 旧机 custody 迁移落地仍是 custody
            TxType.GENESIS -> if (counterparty != null) amount else 0L
            else -> 0L
        },
        margin = when (type) {
            TxType.GRANT, TxType.RECEIVE -> amount
            TxType.SPEND, TxType.WITHDRAW -> -amount
            TxType.DEPOSIT -> amount
            TxType.HANDOVER -> 0L
            // 迁移 GENESIS (无 counterparty): 旧明文余额直达可用
            TxType.GENESIS -> if (counterparty == null) amount else 0L
        },
    )

    /** total 侧是否为入账 (v3.39; 确认页方向图标用) */
    val isIncoming: Boolean
        get() = effects().total > 0L
}

/**
 * 规范化序列化 (签名域)。
 *
 * 帧格式 (大端, 定长头 + 长度前缀字段, 逐字段无歧义):
 * ```
 * "SPARK-WALLET-TX-V1"          域分离前缀 (≠ 消息/中继签名域)
 * u32be len("GENESIS"…)         类型名 (字符串, 枚举演进不破坏字节布局)
 * u64be seq
 * u64be amount
 * u32be len ‖ bytes             counterparty (可空 → 长度 0)
 * u32be len ‖ bytes             memo (可空 → 长度 0)
 * u64be timestamp
 * u32be len ‖ bytes             prevTxHash (hex 字符串)
 * ```
 * 签名域前缀与既有 "SIGNAL-V1" / "RELAY-AUTH-V1" 互斥 ——
 * 身份域签名绝不可能被重放为钱包交易签名 (跨协议重放防护)。
 *
 * v3.49 source 列排除声明: [WalletTx.source] (来源归属) **不进本
 * 签名域** —— 余额/序号/链接等安全核心仍由签名覆盖, source 是
 * Vault 侧注入的审计展示列。代价与边界 (如实): root 级篡改账本
 * JSON 的 source 值不触发验签失败 —— 但能写 Vault 私有目录的攻击
 * 者本可重写整本账本, source 并未降低既有安全水位; 收益: 签名域
 * 字节布局对 v3.37~v3.44 全部已签链逐字节稳定, 新旧版本任意混布
 * (旧端验签/新端验签/镜像校验互认), 链式 txHash 亦不受 source
 * 影响 —— prevTxHash 链接跨版本成立。
 *
 * v3.38 兼容性: 帧格式**未变** —— 新交易类型只是新的类型名字符串
 * (长度前缀设计), v3.37 已签交易的规范化字节与其签名保持逐字节
 * 稳定, 升级不触发任何重签。
 */
object TxCanonical {

    const val DOMAIN = "SPARK-WALLET-TX-V1"

    private val domainBytes = DOMAIN.toByteArray(Charsets.UTF_8)

    /** 无签名规范化字节 (签名对象) */
    fun bytes(tx: WalletTx): ByteArray {
        val out = ArrayList<ByteArray>()
        out.add(domainBytes)
        out.add(frame(tx.type.name.toByteArray(Charsets.UTF_8)))
        out.add(u64(tx.seq))
        out.add(u64(tx.amount))
        out.add(frame((tx.counterparty ?: "").toByteArray(Charsets.UTF_8)))
        out.add(frame((tx.memo ?: "").toByteArray(Charsets.UTF_8)))
        out.add(u64(tx.timestamp))
        out.add(frame(tx.prevTxHash.toByteArray(Charsets.UTF_8)))

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

    /** 交易哈希: 规范化字节 ‖ 原始签名字节 → SHA-256 hex */
    fun txHash(tx: WalletTx): String {
        val sig = runCatching { Base64.getDecoder().decode(tx.signature) }
            .getOrElse { ByteArray(0) }
        val canonical = bytes(tx)
        val buf = ByteArray(canonical.size + sig.size)
        System.arraycopy(canonical, 0, buf, 0, canonical.size)
        System.arraycopy(sig, 0, buf, canonical.size, sig.size)
        val digest = MessageDigest.getInstance("SHA-256").digest(buf)
        return digest.joinToString("") { "%02x".format(it) }
    }

    // ---- 帧原语 ----

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

/**
 * 交易 JSON 编解码 (落盘 JSONL / IPC 载荷)。
 *
 * JSON 仅是**运输形态** —— 签名始终针对 [TxCanonical.bytes],
 * 字段顺序 / 空白 / 未知字段均不影响签名有效性。
 */
object TxJsonCodec {
    val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    fun encode(tx: WalletTx): String = json.encodeToString(WalletTx.serializer(), tx)

    fun decode(s: String): WalletTx? = runCatching {
        json.decodeFromString(WalletTx.serializer(), s)
    }.getOrNull()

    /** 交易列表 (JSONL 落盘 / walletstate 回调载荷) */
    fun encodeList(txs: List<WalletTx>): String =
        json.encodeToString(kotlinx.serialization.builtins.ListSerializer(WalletTx.serializer()), txs)

    fun decodeList(s: String): List<WalletTx>? = runCatching {
        json.decodeFromString(kotlinx.serialization.builtins.ListSerializer(WalletTx.serializer()), s)
    }.getOrNull()
}
