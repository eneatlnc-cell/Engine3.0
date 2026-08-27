package com.securesocial.core.wallet

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.security.MessageDigest
import java.util.Base64

/**
 * ═══════════════════════════════════════════════════════════════════
 *  v3.37 · SPARK 本地钱包 — 交易模型与规范化序列化 (纯 Kotlin)
 * ═══════════════════════════════════════════════════════════════════
 *
 *  设计核心: **余额不是存储值, 是签名历史的推导值** (比特币钱包模型):
 *  · 账本 = append-only 交易日志, 每笔交易由 Vault 内的钱包私钥签名;
 *  · 余额 = Σ(日志) —— 篡改任何一笔交易, 其签名校验立即失败;
 *  · 删除/回滚任意中段交易, prevTxHash 链与序号连续性双双断裂;
 *  · 任何人持有钱包公钥即可独立验证整条链 (无需信任设备本地存储)。
 *
 *  与消息计费 (SparkEconomy) 的关系: 本模块只管"账", 不管"价" ——
 *  定价规则仍在 core-protocol; 钱包层接收任意 amount 并记账。
 *
 *  v3.37 边界 (诚实声明, v3.38+ 由 spark-ledger 解决):
 *  · RECEIVE/GRANT 为自记账 (自签 = 防篡改, 不证明对手方确实付款);
 *  · 双花 (隐藏另一条日志) 本地无法根除 —— 对手方验证通道未接入;
 *  · Vault 侧高水位序号 (core-ipc signtx) 挡"恢复旧备份重放余额",
 *    但 root 级攻击者仍可同时清写两侧存储 (TEE 保密钥, 不保存储)。
 */

/** 交易类型 */
enum class TxType {
    /** 一次性迁移: 旧明文余额 → 签名账本 (必须是链上第一笔) */
    GENESIS,

    /** 每日登录赠金入账 (自记账) */
    GRANT,

    /** 支出: 消息计费 / 打赏 / 密封支付 / 未来转账出账 */
    SPEND,

    /** 收入: 被打赏 / 收到礼物 / 密封支付入账 (自记账) */
    RECEIVE,
}

/**
 * 一笔签名交易。JSON 形态用于落盘与 IPC 载荷; 签名对象是
 * [TxCanonical.bytes] 的规范化字节 (字段定序 + 长度前缀,
 * 与 JSON 序列化的字段顺序/空白完全无关 —— 签名永不因
 * 序列化抖动而失效)。
 *
 * @param seq          链内序号, 严格 +1 递增, 首笔为 1 (缺口 = 删除痕迹)
 * @param amount       金额, 恒正 (方向由 [type] 决定)
 * @param counterparty 对手方指纹 (hex); 计费类支出与赠金为 null
 * @param memo         业务线索 ("daily-grant:2026-08-27" / "msg×5" / "tip:a1b2c3d4")
 * @param prevTxHash   前一笔交易的 [WalletTx.txHash]; 首笔为 ""
 * @param signature    Base64(DER ECDSA-P256) 对 [TxCanonical.bytes] 的签名
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
) {
    /** 本交易的哈希: SHA-256(规范化字节 ‖ 签名字节) 的 hex —— 链式链接材料 */
    val txHash: String
        get() = TxCanonical.txHash(this)

    /** 交易对余额的方向贡献 */
    val signedAmount: Long
        get() = when (type) {
            TxType.GENESIS, TxType.GRANT, TxType.RECEIVE -> amount
            TxType.SPEND -> -amount
        }
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
}
