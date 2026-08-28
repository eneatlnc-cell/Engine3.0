package com.securesocial.core.wallet

import com.securesocial.core.crypto.EcdsaOperations
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * ═══════════════════════════════════════════════════════════════════
 *  v3.38 · SPARK 钱包交接证书 (双 QR 光学通道)
 * ═══════════════════════════════════════════════════════════════════
 *
 *  换机迁移协议 (私钥零拷贝 —— 与身份密钥迁移的本质差异):
 *
 *  ```
 *  新手机                     旧手机
 *  ──────                     ──────
 *  ① TEE 生成全新钱包密钥对
 *     展示 QR: 新公钥  ────────→  ② 扫码 + 指纹验证持有旧密钥
 *                                  ③ 旧密钥签署交接交易 (HANDOVER):
 *                                    custody 快照 + 新公钥 + 终结声明
 *     ④ 扫码验签           ←──────── 展示 QR: 交接证书
 *  ⑤ 新链 GENESIS 承接 custody
 *     (counterparty = 旧公钥, memo = 交接交易哈希)
 *                                  ⑥ 旧密钥/账本/高水位本地销毁
 *  ```
 *
 *  证书内容 (全部为**公钥材料与签名** —— 二维码被拍照/截屏
 *  不泄露任何私钥):
 *  · 旧公钥 — 新机据此独立验签交接交易;
 *  · 新公钥 — 与交易 counterparty 比对, 防中间人调包;
 *  · 交接交易 — 旧密钥对规范化字节的签名 (域分离)。
 *
 *  新链承接语义: 新链 GENESIS 的 amount = 交接交易的余额快照
 *  (v3.39: total 全额移交; v3.38 旧证书为 custody 快照, 结构不变,
 *  新机按 amount 原样承接, 天然兼容)。
 *
 *  诚实边界 (自托管无救济, 产品层必须明示):
 *  · 交接为**单方终结**: 旧链在交接后不可续签 (Vault 清除密钥),
 *    旧机在 ⑥ 之前仍持有签名能力 (分钟级窗口, 由 ③ 的指纹门看护);
 *  · 新机在交接完成后损坏 = custody 资产全失 —— 无链外备份可回退,
 *    这是自托管的本质代价;
 *  · 证书重放: 同一证书可在多台新设备重复使用 (旧链无全局共识),
 *    但每次承接都要求新设备 TEE 内的**新密钥**匹配证书 counterparty,
 *    且旧机密钥销毁后窗口即闭合。
 */
@Serializable
data class HandoverCertificate(
    /** 载荷版本 (前向兼容) */
    val v: Int = 1,
    /** 判别串 (与身份迁移二维码载荷区分) */
    val kind: String = KIND,
    /** 旧钱包公钥 (X.509 编码, Base64) — 验签锚点 */
    val oldPubKeyB64: String,
    /** 新钱包公钥 (X.509 编码, Base64) — 必须与交易 counterparty 一致 */
    val newPubKeyB64: String,
    /** 旧密钥签署的终结交易 (HANDOVER, 已签名) */
    val handoverTx: WalletTx,
) {
    companion object {
        const val KIND = "spark-handover"

        private val json = Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
        }

        fun encode(cert: HandoverCertificate): String =
            json.encodeToString(HandoverCertificate.serializer(), cert)

        fun decode(s: String): HandoverCertificate? = runCatching {
            json.decodeFromString(HandoverCertificate.serializer(), s)
        }.getOrNull()

        /** X.509 字节 → hex (交易 counterparty 的编码形态) */
        fun pubKeyHex(x509: ByteArray): String =
            x509.joinToString("") { "%02x".format(it) }

        /**
         * 构造未签名交接交易 (旧机, 指纹验证通过后调用)。
         *
         * @param balanceSnapshot 交接时点余额 (v3.39: total 全额移交)
         * @param newPubKeyHex    新公钥 hex (= counterparty)
         * @param seq             旧链下一序号
         * @param prevHash        旧链当前尾哈希
         */
        fun buildHandoverTx(
            balanceSnapshot: Long,
            newPubKeyHex: String,
            seq: Long,
            prevHash: String,
        ): WalletTx = WalletTx(
            seq = seq,
            type = TxType.HANDOVER,
            amount = balanceSnapshot,
            counterparty = newPubKeyHex,
            memo = "handover:$balanceSnapshot",
            timestamp = System.currentTimeMillis(),
            prevTxHash = prevHash,
            signature = "",
        )

        /**
         * 构造新链承接创世交易 (新机, 证书验签通过后调用)。
         *
         * counterparty = 旧公钥 hex (来源线索), memo 携带交接交易哈希
         * (审计回溯锚点: 任何人可用旧公钥复验该哈希对应的签名)。
         */
        fun buildGenesisTx(
            balanceCarried: Long,
            oldPubKeyHex: String,
            handoverTxHash: String,
        ): WalletTx = WalletTx(
            seq = 1L,
            type = TxType.GENESIS,
            amount = balanceCarried,
            counterparty = oldPubKeyHex,
            memo = "handover-genesis:$handoverTxHash",
            timestamp = System.currentTimeMillis(),
            prevTxHash = "",
            signature = "",
        )
    }

    /** 验证结果 */
    sealed class VerifyResult {
        /** 验证通过: [balanceCarried] = 可承接的余额快照 (v3.39: total) */
        data class Ok(val balanceCarried: Long, val handoverTxHash: String) : VerifyResult()

        /** 验证失败: [reason] 面向用户 (不含敏感材料) */
        data class Bad(val reason: String) : VerifyResult()
    }

    /**
     * 新机侧验证 (零信任 — 只信密码学, 不信扫码通道):
     * 1. 载荷结构: kind/version/公钥可解码/交易类型与金额;
     * 2. 交易 counterparty == 本机新公钥 hex (防调包);
     * 3. 旧公钥对交接交易规范化字节的签名 (域分离验签)。
     */
    fun verify(localNewPubKeyX509: ByteArray): VerifyResult {
        if (kind != KIND || v != 1)
            return VerifyResult.Bad("交接证书版本不识别")
        if (handoverTx.type != TxType.HANDOVER)
            return VerifyResult.Bad("证书交易类型非法")
        if (handoverTx.amount <= 0L)
            return VerifyResult.Bad("交接金额非法")
        if (handoverTx.signature.isEmpty())
            return VerifyResult.Bad("交接交易未签名")

        // 防调包: 证书指名的新公钥必须是本机刚生成的那对
        val localHex = pubKeyHex(localNewPubKeyX509)
        if (pubKeyHex(decodeB64(newPubKeyB64) ?: return VerifyResult.Bad("新公钥编码非法")) != localHex)
            return VerifyResult.Bad("证书不是签给本机的 (新公钥不匹配)")

        val oldPubBytes = decodeB64(oldPubKeyB64)
            ?: return VerifyResult.Bad("旧公钥编码非法")
        val oldPubKey = try {
            java.security.KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(oldPubBytes))
        } catch (e: Exception) {
            return VerifyResult.Bad("旧公钥无法解析")
        }

        // 旧公钥 hex (新链 GENESIS 的 counterparty 线索)
        val oldHex = pubKeyHex(oldPubBytes)
        if (handoverTx.counterparty != localHex)
            return VerifyResult.Bad("交接交易对手方与本机公钥不符")

        val sig = try {
            Base64.getDecoder().decode(handoverTx.signature)
        } catch (e: IllegalArgumentException) {
            return VerifyResult.Bad("交接签名编码非法")
        }
        val ecdsa = EcdsaOperations()
        if (!ecdsa.verify(oldPubKey, TxCanonical.bytes(handoverTx), sig))
            return VerifyResult.Bad("旧密钥签名验证失败 (证书被篡改?)")

        if (oldHex.isEmpty()) return VerifyResult.Bad("旧公钥为空")
        return VerifyResult.Ok(
            balanceCarried = handoverTx.amount,
            handoverTxHash = handoverTx.txHash,
        )
    }

    /** 旧公钥 hex (承接 GENESIS 的 counterparty; verify 通过后才有意义) */
    fun oldPubKeyHex(): String? =
        decodeB64(oldPubKeyB64)?.let { pubKeyHex(it) }

    private fun decodeB64(s: String): ByteArray? = try {
        Base64.getDecoder().decode(s)
    } catch (e: IllegalArgumentException) {
        null
    }
}
