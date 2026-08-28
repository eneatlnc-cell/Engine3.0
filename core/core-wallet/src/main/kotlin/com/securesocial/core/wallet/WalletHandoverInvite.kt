package com.securesocial.core.wallet

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * ═══════════════════════════════════════════════════════════════════
 *  v3.38 · 钱包交接公钥邀请 (双 QR 通道 · QR #1)
 * ═══════════════════════════════════════════════════════════════════
 *
 *  双 QR 交接协议中的第一张码 (新机 → 旧机):
 *  ```
 *  新手机                     旧手机
 *  ──────                     ──────
 *  ① walletinit 生成新密钥对
 *     展示 QR #1 (本载荷) ─────→  ② Vault 扫码取新公钥
 *                                  ③ 指纹门 + signHandover
 *     ④ Engine 扫码验签    ←──────── 展示 QR #2 (交接证书)
 *  ⑤ walletadopt 承接 custody
 *  ```
 *
 *  载荷全部为**公钥材料** (无任何秘密):
 *  · 被拍照/截屏/转发不泄露私钥;
 *  · 中间人替换公钥 → 交接证书 verify 的 "防调包" 检查
 *    (证书新公钥必须 == 本机公钥) 在新机侧立即戳穿;
 *  · [pubKeyHex] 与 HANDOVER 交易的 counterparty 编码形态
 *    完全一致 (X.509 → hex), 旧机扫码即签, 无二次转换歧义。
 *
 *  [appPackage] 标识钱包归属应用 (多应用绑定架构, v3): 旧机 Vault
 *  据此路由到对应应用的钱包槽位; 与 [com.securesocial.core.ipc.IpcContract]
 *  的 app 参数同一取值域。
 *
 *  载荷量级: ~250 字符 (hex 公钥 182 + 包名 + 域标识), 单 QR 富余。
 */
@Serializable
data class WalletHandoverInvite(
    /** 载荷版本 (前向兼容) */
    val v: Int = 1,
    /** 判别串 (与身份迁移二维码 / 交接证书载荷区分) */
    val kind: String = KIND,
    /** 钱包归属应用包名 (旧机据此路由钱包槽位) */
    val appPackage: String,
    /** 新钱包公钥 (X.509 编码 → hex; = HANDOVER counterparty 形态) */
    val pubKeyHex: String,
) {
    init {
        require(kind == KIND) { "handover invite kind mismatch" }
        require(pubKeyHex.isNotEmpty()) { "handover invite pubkey empty" }
    }

    /** 公钥指纹 (确认页展示: 供用户与旧机扫码结果肉眼比对) */
    val pubKeyFingerprint: String
        get() = if (pubKeyHex.length >= 16) {
            pubKeyHex.take(8) + "…" + pubKeyHex.takeLast(8)
        } else {
            pubKeyHex
        }

    companion object {
        const val KIND = "spark-handover-invite"

        private val json = Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
        }

        fun encode(invite: WalletHandoverInvite): String =
            json.encodeToString(WalletHandoverInvite.serializer(), invite)

        /**
         * 解析公钥邀请 (结构校验): kind/version/包名/公钥 hex 合法性。
         * 返回 null = 不是有效的交接邀请载荷 (扫码通道噪声)。
         */
        fun decode(s: String): WalletHandoverInvite? = runCatching {
            val invite = json.decodeFromString(WalletHandoverInvite.serializer(), s)
            if (invite.v != 1) return null
            if (invite.kind != KIND) return null
            if (invite.appPackage.isBlank()) return null
            if (invite.pubKeyHex.length < 64) return null          // P-256 公钥下界
            if (!invite.pubKeyHex.all { it.isDigit() || it in 'a'..'f' }) return null
            invite
        }.getOrNull()
    }
}
