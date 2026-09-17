package com.securesocial.core.crypto

import java.security.MessageDigest
import java.security.PublicKey

/**
 * 双花探针 (v3.74 · P2-a)
 *
 * 语义: **把"某个钱包的第 N 笔序号"压缩成一个不可逆、不可链接的盲化指纹**,
 * 供中继做全局唯一性认领 (CHECK-and-SET), 从而在入账路径上根除双花。
 *
 * ```
 * probe = SHA256( DOMAIN ‖ SHA256(钱包公钥 X.509) ‖ u64be(seq) )   → 64 hex 小写
 * ```
 *
 * ## 为什么这样构造
 *
 * | 性质 | 依据 | 意义 |
 * |---|---|---|
 * | **不可逆** | 两层 SHA-256 | 中继拿 probe 推不出钱包公钥, 也推不出序号 |
 * | **不可链接** | seq 进入哈希 | 同一钱包的 seq=7 与 seq=8 是两个互不相关的伪随机串, 中继**看不出它们属于同一钱包**, 更看不出消费进度 |
 * | **可复算** | 输入全取自交易自带字段 | 收款方用"验签公钥 + tx.seq"即可自算, 零额外依赖, 无需发起方透露任何隐私 |
 * | **域分离** | DOMAIN 常量 | 与 SPARK-WALLET-TX-V1 / SPARK-ID-ROTATION-V1 / RELAY-AUTH-V1 / SIGNAL-V1 互斥, 防跨协议重放 |
 *
 * ## 隐私边界 (诚实入档)
 *
 * probe **不是交易 ID**, 与金额 / 收款方 / 时间 / 备注一律无关 —— 中继只见
 * "某个我不认识的主体认领了一个我无法归类的随机数"。它知道的全部信息是:
 * 全网共发生了多少次序号认领, 以及每次认领来自哪个 IP (见 D-2: 独立不认证
 * 端点, 仅 IP 关联, 无身份)。序号本身仍只有 Vault 权威账本掌握。
 *
 * ## 拼接为何不用帧 (frame)
 *
 * 三段皆为**定长**: DOMAIN 明文定长 + 32B 钱包哈希 + 8B 大端序号。
 * 定长拼接不存在解析歧义, 故不套 `IdentityRotationStatement` 的
 * `frame(len‖payload)` 风格 —— 少一层长度前缀, 中继端复算实现更薄。
 *
 * ## 输入契约
 *
 * - `walletPublicKeyX509`: 钱包公钥的 **X.509 DER 编码** (即 `PublicKey.encoded`)。
 *   调用方必须传入**验证该笔交易签名的那个公钥**, 否则探针与账本不同源, 认领失去意义。
 * - `seq`: 钱包单调递增序号 (与 `WalletTx.seq` 同源)。单调递增是双花判定的
 *   语义基础 —— 同一 (钱包, seq) 只允许被认领一次。
 *
 * P2 范围边界: 本文件只交付 **探针算法 + 格式工具**; 认领协议
 * (`DUP_CLAIM` / `DUP_CLAIM_RESULT`) 归 P2-c 中继端, 入账核验归 P2-b。
 */
object DupProbe {

    /** 探针域 (域分离: 与 SPARK-WALLET-TX-V1 / SPARK-ID-ROTATION-V1 / RELAY-AUTH-V1 / SIGNAL-V1 互斥) */
    const val DOMAIN = "SPARK-TX-DUP-PROBE-V1"

    /** 探针输出长度 (32 字节 → 64 个 hex 字符) */
    const val HEX_LENGTH = 64

    private val DOMAIN_BYTES = DOMAIN.toByteArray(Charsets.UTF_8)

    private val HEX64: Regex = Regex("[0-9a-fA-F]{64}")

    /**
     * 计算探针。
     *
     * 纯函数: 相同输入恒定输出, 无状态, 线程安全。
     *
     * @param walletPublicKeyX509 钱包公钥 X.509 DER 编码 (验证该笔交易的公钥)
     * @param seq 钱包递增序号
     * @return 64 字符小写十六进制探针
     */
    fun of(walletPublicKeyX509: ByteArray, seq: Long): String {
        val md = MessageDigest.getInstance("SHA-256")

        // ① 钱包标识: 公钥哈希 (定长 32B, 抹掉公钥本身的形状信息)
        val walletId = md.digest(walletPublicKeyX509)

        // ② 探针: DOMAIN ‖ walletId ‖ u64be(seq)
        md.reset()
        md.update(DOMAIN_BYTES)
        md.update(walletId)
        md.update(u64(seq))
        return md.digest().toHex()
    }

    /**
     * 计算探针 (公钥对象重载)。
     *
     * 等价于 `of(publicKey.encoded, seq)` —— `PublicKey.encoded` 即 X.509 DER。
     */
    fun of(walletPublicKey: PublicKey, seq: Long): String =
        of(walletPublicKey.encoded, seq)

    /**
     * 格式校验: 是否为 64 位十六进制串。
     *
     * 供中继在写入集合前做**白名单消毒** (防畸形/超长键污染存储),
     * 以及客户端对网络回包做防御性校验。大小写皆可, 但语义上
     * 本库产出的规范形态恒为**小写** —— 存储键请走 [normalize]。
     */
    fun isWellFormed(probe: String): Boolean =
        probe.length == HEX_LENGTH && HEX64.matchEntire(probe) != null

    /**
     * 归一化为小写规范形式; 非法输入返回 null。
     *
     * 中继端应以此作为集合键: 同一探针的大写/小写写法必须收敛到同一个键,
     * 否则同一 (钱包, seq) 会被认领两次, 双花防护被大小写绕过。
     */
    fun normalize(probe: String): String? =
        if (isWellFormed(probe)) probe.lowercase() else null

    /** 大端 u64 (与 TxCanonical / IdentityRotationStatement 同款字节序) */
    private fun u64(v: Long): ByteArray = byteArrayOf(
        (v ushr 56).toByte(), (v ushr 48).toByte(), (v ushr 40).toByte(), (v ushr 32).toByte(),
        (v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte()
    )

    private fun ByteArray.toHex(): String {
        val out = CharArray(size * 2)
        val digits = "0123456789abcdef"
        for (i in indices) {
            val v = this[i].toInt() and 0xFF
            out[i * 2] = digits[v ushr 4]
            out[i * 2 + 1] = digits[v and 0x0F]
        }
        return out.concatToString()
    }
}
