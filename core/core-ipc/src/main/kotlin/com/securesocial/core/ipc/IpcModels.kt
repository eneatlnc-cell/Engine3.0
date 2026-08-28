package com.securesocial.core.ipc

import android.content.Intent
import android.net.Uri

/**
 * IPC 错误码枚举
 */
enum class IpcErrorCode(val code: String, val description: String) {
    FORMAT_ERROR("FORMAT_ERROR", "二维码格式错误或曲线参数不合法"),
    USER_CANCELLED("USER_CANCELLED", "用户取消了导入操作"),
    KEYSTORE_ERROR("KEYSTORE_ERROR", "Keystore 加密或存储异常"),
    BIOMETRIC_UNAVAILABLE("BIOMETRIC_UNAVAILABLE", "设备未录入指纹, 请先在系统设置中录入"),
    BIOMETRIC_FAILED("BIOMETRIC_FAILED", "指纹验证未通过"),
    NO_KEY_BOUND("NO_KEY_BOUND", "Vault 中没有已绑定的私钥, 无法签名"),
    NO_BINDING("NO_BINDING", "Vault 中没有该应用的可恢复身份, 请直接生成新密钥对"),
    SIGN_FAILED("SIGN_FAILED", "签名失败 (载荷格式错误或密码学异常)"),
    SIGN_TIMEOUT("SIGN_TIMEOUT", "签名请求超时 (Vault 未响应)"),
    NO_WALLET_KEY("NO_WALLET_KEY", "Vault 中没有该应用的钱包密钥, 请先初始化钱包"),
    TX_FORMAT_ERROR("TX_FORMAT_ERROR", "交易载荷格式错误, 无法解析"),
    TX_SEQ_REJECTED("TX_SEQ_REJECTED", "交易序号未超过高水位 (检测到账本回滚), 拒绝签名"),
    // ---- v3.39: 赠金幂等 + 单账户合并 ----
    /** GRANT 每日幂等: 权威账本当日已有 GRANT (memo: daily-grant:<date>), 拒绝再签 */
    GRANT_ALREADY_CLAIMED("GRANT_ALREADY_CLAIMED", "今日赠金已领取 (以 Vault 账本为准)"),
    /** SPEND 总额足额失败 (v3.39: custody+margin < amount) */
    INSUFFICIENT_TOTAL("INSUFFICIENT_TOTAL", "可用余额不足"),
    // ---- v3.38: 双账户足额 + 交接终结错误码 ----
    /** SPEND/WITHDRAW 足额失败: 权威账本 margin < amount (可用余额不足, 引导充值) */
    INSUFFICIENT_MARGIN("INSUFFICIENT_MARGIN", "可用余额不足, 请先从托管余额充值"),
    /** DEPOSIT/HANDOVER 足额失败: 权威账本 custody 不足 (充值超额 / 交接非全额) */
    INSUFFICIENT_CUSTODY("INSUFFICIENT_CUSTODY", "托管余额不足, 无法完成该笔操作"),
    /** 链已终结 (最后一笔为 HANDOVER): 旧机钱包已迁出, 不可再签任何交易 */
    WALLET_TERMINAL("WALLET_TERMINAL", "此设备钱包已交接迁出, 无法继续使用"),
    /** 承接时本机已有非空权威账本: 换机方向反了 (应先在本机出账/交接) */
    WALLET_ALREADY_INITIALIZED("WALLET_ALREADY_INITIALIZED", "本机已有钱包账本, 不能承接 (请先交接现有钱包)"),
    /** 交接证书验证失败: 非签给本机 / 签名不符 / 结构非法 */
    HANDOVER_CERT_INVALID("HANDOVER_CERT_INVALID", "交接证书验证失败 (被篡改或不是签给本机的)"),
    UNKNOWN_ERROR("UNKNOWN_ERROR", "未知错误");

    companion object {
        fun fromCode(code: String?): IpcErrorCode? {
            return entries.find { it.code == code }
        }
    }
}

/**
 * IPC 回调数据 (v2)
 *
 * 从 myvault://callback Intent 解析而来 (v3.17: sig/result 优先读 Intent Extra,
 * 回退读 URI 查询参数以兼容旧版 Vault)。
 * - sessionId 必须原样回传, 发起方据此将回调路由给正确的等待者
 * - ts + sig: Vault 的 ECDSA 签名覆盖 (sessionId ‖ status ‖ ts),
 *   发起方 (Engine) 必须用绑定身份公钥验签并校验时间戳窗口后才可信任本回调
 * - result: 业务结果 (签名请求返回的 Base64 签名字节)
 *
 * 未验签的回调不可作为任何安全判定的依据 (修复: 登录回调伪造)。
 */
data class IpcCallback(
    val sessionId: String?,
    val isSuccess: Boolean,
    val errorCode: IpcErrorCode? = null,
    val timestamp: Long = 0L,
    val signature: String? = null,
    val result: String? = null
) {
    /**
     * 本回调是否携带有效签名材料 (发起方仍需用绑定公钥完成验签)
     */
    val hasSignatureMaterial: Boolean
        get() = sessionId != null && signature != null && timestamp > 0L

    companion object {
        /**
         * 从 Intent 解析回调 (v3.17 推荐入口)
         *
         * 路由字段 (session/status/code/ts) 读 URI; 敏感字段 (sig/result)
         * 优先读 Intent Extra —— 新版 Vault 经 Extra 投递, Extra 缺失时
         * 回退 URI 查询参数 (兼容升级窗口期的旧版 Vault)。
         */
        fun fromIntent(intent: Intent): IpcCallback? {
            val uri = intent.data ?: return null
            if (!IpcContract.isCallbackUri(uri)) return null

            val sigExtra = intent.getStringExtra(IpcContract.EXTRA_SIG)
            val resultExtra = intent.getStringExtra(IpcContract.EXTRA_RESULT)

            val callback = fromUri(uri) ?: return null
            return callback.copy(
                signature = sigExtra ?: callback.signature,
                result = resultExtra ?: callback.result
            )
        }

        /**
         * 从 URI 解析回调 (v3.17: sig/result 仅作旧版兼容回退)
         */
        fun fromUri(uri: Uri): IpcCallback? {
            if (!IpcContract.isCallbackUri(uri)) return null

            val sessionId = uri.getQueryParameter(IpcContract.PARAM_SESSION)
            val status = uri.getQueryParameter(IpcContract.PARAM_STATUS)
            val ts = uri.getQueryParameter(IpcContract.PARAM_TS)?.toLongOrNull() ?: 0L
            val sig = uri.getQueryParameter(IpcContract.PARAM_SIG)
            val result = uri.getQueryParameter(IpcContract.PARAM_RESULT)
            return when (status) {
                IpcContract.STATUS_SUCCESS -> IpcCallback(
                    sessionId, isSuccess = true,
                    timestamp = ts, signature = sig, result = result
                )
                IpcContract.STATUS_FAIL -> {
                    val code = uri.getQueryParameter(IpcContract.PARAM_CODE)
                    IpcCallback(
                        sessionId, isSuccess = false,
                        errorCode = IpcErrorCode.fromCode(code),
                        timestamp = ts, signature = sig
                    )
                }
                else -> null
            }
        }
    }
}

/**
 * IPC 导入请求数据
 *
 * 从 myvault://import URI + Intent Extra 解析而来。
 *
 * @param sessionId 会话标识
 * @param payload  密钥二维码载荷 (JSON 字符串); 非空表示 Engine 直接传递, Vault 无需开摄像头
 */
data class IpcImportRequest(
    val sessionId: String,
    val payload: String? = null
) {
    companion object {
        /**
         * 从 Intent 解析导入请求 (URI + Extra)
         */
        fun fromIntent(intent: Intent): IpcImportRequest? {
            val uri = intent.data ?: return null
            if (!IpcContract.isImportUri(uri)) return null

            val sessionId = uri.getQueryParameter(IpcContract.PARAM_SESSION)
            return if (sessionId != null) {
                val payload = intent.getStringExtra(IpcContract.EXTRA_PAYLOAD)
                IpcImportRequest(sessionId, payload)
            } else {
                null
            }
        }

        /**
         * 从 URI 解析导入请求 (仅 sessionId, 无 payload)
         */
        fun fromUri(uri: Uri): IpcImportRequest? {
            if (!IpcContract.isImportUri(uri)) return null

            val sessionId = uri.getQueryParameter(IpcContract.PARAM_SESSION)
            return if (sessionId != null) {
                IpcImportRequest(sessionId)
            } else {
                null
            }
        }
    }
}

/**
 * IPC 签名请求数据 (v2 新增)
 *
 * 从 myvault://sign Intent 解析而来 (v3.17: payload 优先读 Intent Extra,
 * 回退读 URI 查询参数以兼容旧版 Engine)。
 * Engine 请求 Vault 用绑定的身份私钥对 payload 做 ECDSA 签名。
 *
 * @param sessionId 会话标识
 * @param payloadBase64 待签字节 (Base64)
 */
data class IpcSignRequest(
    val sessionId: String,
    val payloadBase64: String
) {
    /** 解码后的待签字节; 载荷非法时为 null */
    val payloadBytes: ByteArray?
        get() = runCatching {
            java.util.Base64.getDecoder().decode(payloadBase64)
        }.getOrNull()

    companion object {
        /**
         * 从 Intent 解析签名请求 (v3.17 推荐入口)
         *
         * sessionId 读 URI; payload 优先读 Intent Extra (EXTRA_PAYLOAD),
         * Extra 缺失时回退 URI 查询参数 (兼容旧版 Engine)。
         */
        fun fromIntent(intent: Intent): IpcSignRequest? {
            val uri = intent.data ?: return null
            if (!IpcContract.isSignUri(uri)) return null

            val payloadExtra = intent.getStringExtra(IpcContract.EXTRA_PAYLOAD)
            val fromExtra = payloadExtra?.let { fromParts(uri, it) }
            if (fromExtra != null) return fromExtra
            return fromUri(uri)
        }

        /**
         * 从 URI 解析签名请求 (v3.17: payload 仅作旧版兼容回退)
         */
        fun fromUri(uri: Uri): IpcSignRequest? {
            if (!IpcContract.isSignUri(uri)) return null
            val payload = uri.getQueryParameter(IpcContract.PARAM_PAYLOAD) ?: return null
            return fromParts(uri, payload)
        }

        private fun fromParts(uri: Uri, payload: String): IpcSignRequest? {
            val sessionId = uri.getQueryParameter(IpcContract.PARAM_SESSION) ?: return null
            // Base64 载荷必须可解码, 拒绝畸形请求
            if (runCatching { java.util.Base64.getDecoder().decode(payload) }.isFailure) return null
            return IpcSignRequest(sessionId, payload)
        }
    }
}

/**
 * v3.37 · SPARK 钱包初始化请求
 *
 * 从 myvault://walletinit URI 解析而来。Vault 在指纹门后为该应用生成
 * 钱包专属密钥对 (与身份密钥独立的第二个密钥槽), 公钥经回调 result
 * 返回; 幂等: 已有钱包密钥时直接返回既有公钥。
 *
 * 仅含路由字段 (sessionId), 无载荷 Extra —— 钱包密钥对在 Vault 进程内
 * 生成, Engine 侧不提供任何种子材料 (杜绝弱熵注入)。
 */
data class IpcWalletInitRequest(
    val sessionId: String
) {
    companion object {
        /** 从 Intent 解析钱包初始化请求 */
        fun fromIntent(intent: Intent): IpcWalletInitRequest? {
            val uri = intent.data ?: return null
            return fromUri(uri)
        }

        /** 从 URI 解析钱包初始化请求 */
        fun fromUri(uri: Uri): IpcWalletInitRequest? {
            if (!IpcContract.isWalletInitUri(uri)) return null
            val sessionId = uri.getQueryParameter(IpcContract.PARAM_SESSION) ?: return null
            return IpcWalletInitRequest(sessionId)
        }
    }
}

/**
 * v3.37 · SPARK 钱包交易签名请求
 *
 * 从 myvault://signtx URI + Intent Extra 解析而来:
 * - Engine 构造未签名交易 ([com.securesocial.core.wallet.WalletTx],
 *   signature = "") 的 JSON, 经 EXTRA_PAYLOAD 投递 (防系统日志泄露,
 *   与 sign 请求同一策略);
 * - Vault 在自己进程渲染确认页 (金额/类型/对手方/序号), 生物识别通过后:
 *   1. 校验 tx.seq > 本地高水位序号 (账本回滚见证, 旧序号一律拒绝);
 *   2. 用钱包私钥对 TxCanonical 规范化字节签名 (域分离 SPARK-WALLET-TX-V1);
 *   3. 更新高水位为 tx.seq;
 *   4. Base64(DER) 签名经回调 result 返回。
 *
 * 解析侧强校验 (畸形载荷在入口即拒, 不进签名流程):
 * - JSON 必须可解码为 WalletTx;
 * - signature 必须为空串 (已签名交易不接受重签);
 * - seq/amount 必须 > 0;
 * - type 必须为已知枚举。
 *
 * @param sessionId   会话标识
 * @param txJson      未签名交易 JSON (EXTRA_PAYLOAD)
 * @param tx          解析后的未签名交易; 校验失败时为 null
 */
data class IpcSignTxRequest(
    val sessionId: String,
    val txJson: String,
    val tx: com.securesocial.core.wallet.WalletTx?
) {
    companion object {
        /**
         * 从 Intent 解析交易签名请求 (推荐入口)。
         *
         * sessionId 读 URI; 交易 JSON 读 EXTRA_PAYLOAD (必填 ——
         * 钱包签名是 v3.37 新通道, 无旧版 URI 回退路径)。
         */
        fun fromIntent(intent: Intent): IpcSignTxRequest? {
            val uri = intent.data ?: return null
            if (!IpcContract.isSignTxUri(uri)) return null

            val sessionId = uri.getQueryParameter(IpcContract.PARAM_SESSION) ?: return null
            val txJson = intent.getStringExtra(IpcContract.EXTRA_PAYLOAD) ?: return null
            return IpcSignTxRequest(sessionId, txJson, parseTx(txJson))
        }

        /** 从 URI 解析 (仅 sessionId; 交易 JSON 必须经 Intent Extra, URI 无此参数) */
        fun fromUri(uri: Uri): IpcSignTxRequest? {
            if (!IpcContract.isSignTxUri(uri)) return null
            val sessionId = uri.getQueryParameter(IpcContract.PARAM_SESSION) ?: return null
            return IpcSignTxRequest(sessionId, "", null)
        }

        /**
         * 畸形交易校验: 返回 null 表示载荷不可接受。
         * 注意: seq 高水位比较在 Vault 的 WalletKeyManager 内完成
         * (需要读取持久化状态, 非 pure 函数)。
         */
        private fun parseTx(txJson: String): com.securesocial.core.wallet.WalletTx? {
            val tx = com.securesocial.core.wallet.TxJsonCodec.decode(txJson) ?: return null
            if (tx.signature.isNotEmpty()) return null          // 已签名交易不接受重签
            if (tx.seq <= 0L) return null                        // 序号非法
            if (tx.amount <= 0L) return null                     // 金额必须恒正
            if (tx.prevTxHash.isEmpty() && tx.seq != 1L) return null // 非首笔必须有前向哈希
            return tx
        }
    }
}

/**
 * v3.38 · 权威账本状态查询请求
 *
 * 从 myvault://walletstate URI 解析而来 (纯路由, 无载荷 Extra)。
 * Vault 免指纹应答 —— 摘要非秘密材料, 入口受 signature 权限保护。
 *
 * v3.39: [full] = true (URI full=1) 时应答携带完整已签名链 (chainJson)
 * 与 grantClaimedToday —— Engine 重装/分叉场景一次拉全量重建镜像。
 */
data class IpcWalletStateRequest(
    val sessionId: String,
    /** v3.39: 请求全链拉取 (URI 参数 full=1) */
    val full: Boolean = false,
) {
    companion object {
        /** 从 Intent 解析状态查询请求 */
        fun fromIntent(intent: Intent): IpcWalletStateRequest? {
            val uri = intent.data ?: return null
            return fromUri(uri)
        }

        /** 从 URI 解析状态查询请求 */
        fun fromUri(uri: Uri): IpcWalletStateRequest? {
            if (!IpcContract.isWalletStateUri(uri)) return null
            return fromParams(
                uri.getQueryParameter(IpcContract.PARAM_SESSION),
                uri.getQueryParameter(IpcContract.PARAM_FULL),
            )
        }

        /**
         * 从查询参数表解析 (纯 Kotlin, 本地单测锚点):
         * full 语义 = 参数值恰为 "1" —— 其余值 (缺省/0/true/任意串)
         * 一律视为非全量请求。
         */
        fun fromParams(sessionId: String?, full: String?): IpcWalletStateRequest? {
            if (sessionId == null) return null
            return IpcWalletStateRequest(sessionId, full == "1")
        }
    }
}

/**
 * v3.38 · 权威账本状态摘要 (walletstate 回调 result 载荷)
 *
 * Vault 权威账本的推导快照, Engine 据此与本地镜像对账。全部字段为
 * 非秘密材料 (余额/序号/哈希指纹) —— 回调泄露不影响资产安全, 但
 * result 纳入回调签名范围 (v3.29), 镜像对账有密码学锚点。
 *
 * 对账语义 (Engine 侧执行):
 * - balances 与本地镜像不一致 → 以 Vault 为准重建镜像;
 * - highWaterSeq > 本地镜像尾序号 → 镜像丢账, 拉全量重建;
 * - highWaterSeq < 本地镜像尾序号 → 账本回滚 (严重异常, 锁定钱包);
 * - terminal → 锁定钱包 UI, 引导 "已迁出" 文案。
 *
 * v3.39 字段演进:
 * - [total] 可用余额 (custody + margin 合并语义, Engine 展示/足额一律
 *   以此为准); custody/margin 分量保留仅为诊断旧链划转流水;
 * - [grantClaimedToday] 权威账本当日是否已有 GRANT (每日赠金幂等标记,
 *   Vault 按自身账本扫描 daily-grant:<date> 判定 —— 卸载重装 Engine
 *   不再重复赠送);
 * - [chainJson] full=1 请求时携带完整已签名链 (List<WalletTx> JSON),
 *   Engine 空镜像/分叉时全量重建, 追加前仍走全链校验。
 */
@kotlinx.serialization.Serializable
data class IpcWalletState(
    /** 钱包密钥是否已初始化 (false 时其余字段无意义) */
    val initialized: Boolean,
    /** 可用余额 (v3.39 合并语义 = custody + margin; Engine 唯一展示口径) */
    val total: Long = 0L,
    /** 权威托管余额 (v3.38 历史分量, 诊断用) */
    val custody: Long = 0L,
    /** 权威可用余额分量 (v3.38 历史分量, 诊断用) */
    val margin: Long = 0L,
    /** 已签名交易的最高序号 (高水位) */
    val highWaterSeq: Long = 0L,
    /** 权威账本尾交易哈希 (hex; 空账本为 "") */
    val tipHash: String = "",
    /** 链是否已交接终结 (最后一笔为 HANDOVER) */
    val terminal: Boolean = false,
    /** 交易总数 (含 GENESIS; Engine 侧全量重建的行数校验; -1 = 权威账本 TAMPERED) */
    val txCount: Long = 0L,
    /** 每日赠金幂等标记: 权威账本当日已有 GRANT (Vault 账本为准) */
    val grantClaimedToday: Boolean = false,
    /**
     * 权威账本尾交易 JSON (WalletTx 编码; 空账本为 null)。
     *
     * 镜像追赶通道 (v3.38): Vault 签名即落权威账本, Engine 回调丢失
     * (进程被杀/超时) 时镜像落后一笔 —— prevHash 链式链接决定了不能
     * 跳号续链, Engine 必须拿到那笔**已签名交易本体**才能续链。
     * 每次对账携带尾交易 (~300B), Engine 追加前仍走全链校验
     * (appendTx), 双重防线: 回调签名 (v3.29) + 链上签名验证。
     */
    val tipTxJson: String? = null,
    /**
     * 完整已签名链 JSON (List<WalletTx> 编码; 仅 full=1 请求携带)。
     *
     * 全量重建通道 (v3.39): Engine 重装/清数据后镜像为空, 或镜像与
     * 权威链分叉 (tipHash 不一致) 时, 一次对账拉全链重建镜像 ——
     * 从根上终结 "seq 拒绝 → 重试 → Vault 弹框" 的死循环。重建
     * 前仍走 WalletLedger.verify 全链校验 (签名/链接/足额), 链不可
     * 验证则拒绝落库并提示。
     */
    val chainJson: String? = null,
) {
    companion object {
        private val json = kotlinx.serialization.json.Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
        }

        fun encode(state: IpcWalletState): String =
            json.encodeToString(serializer(), state)

        fun decode(s: String): IpcWalletState? = runCatching {
            json.decodeFromString(serializer(), s)
        }.getOrNull()
    }
}

/**
 * v3.38 · 充值签名请求 (custody → margin)
 *
 * 从 myvault://deposit URI + Intent Extra 解析而来。载荷与
 * [IpcSignTxRequest] 同构 (未签名交易 JSON via EXTRA_PAYLOAD),
 * 但入口强校验:
 * - type 必须 == DEPOSIT (防确认页语义混淆: 用充值文案诱导签 SPEND);
 * - 其余结构与 signtx 一致 (未签名 / seq > 0 / amount > 0 / 链式哈希)。
 *
 * Vault 侧 (DepositActivity): custody 足额校验 → 指纹门 → 签名 →
 * 权威账本落库 → Base64 签名经回调 result 返回。
 */
data class IpcDepositRequest(
    val sessionId: String,
    val txJson: String,
    val tx: com.securesocial.core.wallet.WalletTx?,
) {
    companion object {
        /**
         * 从 Intent 解析充值请求。sessionId 读 URI; 交易 JSON 读
         * EXTRA_PAYLOAD (必填, v3.38 新通道无 URI 回退路径)。
         */
        fun fromIntent(intent: Intent): IpcDepositRequest? {
            val uri = intent.data ?: return null
            if (!IpcContract.isDepositUri(uri)) return null

            val sessionId = uri.getQueryParameter(IpcContract.PARAM_SESSION) ?: return null
            val txJson = intent.getStringExtra(IpcContract.EXTRA_PAYLOAD) ?: return null
            return IpcDepositRequest(sessionId, txJson, parseDepositTx(txJson))
        }

        /** 从 URI 解析 (仅 sessionId; 交易 JSON 必须经 Intent Extra) */
        fun fromUri(uri: Uri): IpcDepositRequest? {
            if (!IpcContract.isDepositUri(uri)) return null
            val sessionId = uri.getQueryParameter(IpcContract.PARAM_SESSION) ?: return null
            return IpcDepositRequest(sessionId, "", null)
        }

        /**
         * 畸形充值交易校验: 非 DEPOSIT 类型一律拒绝 (语义混淆防护)。
         * internal: 单测锁定类型门禁 (v3.38 语义混淆攻击面)。
         */
        internal fun parseDepositTx(txJson: String): com.securesocial.core.wallet.WalletTx? {
            val tx = com.securesocial.core.wallet.TxJsonCodec.decode(txJson) ?: return null
            if (tx.type != com.securesocial.core.wallet.TxType.DEPOSIT) return null // 仅充值
            if (tx.signature.isNotEmpty()) return null
            if (tx.seq <= 0L) return null
            if (tx.amount <= 0L) return null
            if (tx.prevTxHash.isEmpty() && tx.seq != 1L) return null
            return tx
        }
    }
}

/**
 * v3.38 · 钱包交接承接请求 (新机)
 *
 * 从 myvault://walletadopt URI + Intent Extra 解析而来:
 * - Engine 扫旧机交接二维码获得证书 JSON, 经 EXTRA_PAYLOAD 投递;
 * - Vault 侧解析为 [com.securesocial.core.wallet.HandoverCertificate],
 *   结构校验通过后才进入确认页 (不可解码 → HANDOVER_CERT_INVALID);
 * - 密码学验证 (防调包 + 旧密钥验签) 在指纹门通过后由 Vault 的
 *   WalletKeyManager 执行 (需要本机钱包公钥, 非 pure 函数)。
 *
 * @param sessionId 会话标识
 * @param certJson  交接证书 JSON (EXTRA_PAYLOAD)
 * @param cert      解析后的证书; 结构校验失败时为 null
 */
data class IpcWalletAdoptRequest(
    val sessionId: String,
    val certJson: String,
    val cert: com.securesocial.core.wallet.HandoverCertificate?,
) {
    companion object {
        /**
         * 从 Intent 解析承接请求。sessionId 读 URI; 证书 JSON 读
         * EXTRA_PAYLOAD (必填, v3.38 新通道无 URI 回退路径)。
         */
        fun fromIntent(intent: Intent): IpcWalletAdoptRequest? {
            val uri = intent.data ?: return null
            if (!IpcContract.isWalletAdoptUri(uri)) return null

            val sessionId = uri.getQueryParameter(IpcContract.PARAM_SESSION) ?: return null
            val certJson = intent.getStringExtra(IpcContract.EXTRA_PAYLOAD) ?: return null
            return IpcWalletAdoptRequest(sessionId, certJson, parseCert(certJson))
        }

        /** 从 URI 解析 (仅 sessionId; 证书 JSON 必须经 Intent Extra) */
        fun fromUri(uri: Uri): IpcWalletAdoptRequest? {
            if (!IpcContract.isWalletAdoptUri(uri)) return null
            val sessionId = uri.getQueryParameter(IpcContract.PARAM_SESSION) ?: return null
            return IpcWalletAdoptRequest(sessionId, "", null)
        }

        /**
         * 证书结构校验 (纯解析层): JSON 可解码 + 域类型正确 +
         * 交接交易已签名。完整密码学验证 (本机公钥匹配 + 旧密钥
         * 验签) 在 Vault 指纹门后执行。
         * internal: 单测锁定结构门禁。
         */
        internal fun parseCert(certJson: String): com.securesocial.core.wallet.HandoverCertificate? {
            val cert = com.securesocial.core.wallet.HandoverCertificate.decode(certJson) ?: return null
            if (cert.handoverTx.type != com.securesocial.core.wallet.TxType.HANDOVER) return null
            if (cert.handoverTx.signature.isEmpty()) return null
            return cert
        }
    }
}

/**
 * v3.38 · 权威账本播种请求 (v3.37→v3.38 升级路径)
 *
 * 从 myvault://walletsync URI + Intent Extra 解析而来:
 * - Engine 提交完整已签名链 (List<WalletTx> JSON via EXTRA_PAYLOAD);
 * - Vault 全链验签 (签名/链接/序号/双账户足额, 用钱包公钥) +
 *   链尾 seq ≤ HWM 校验后落库为权威账本;
 * - 免指纹: 纯公开材料验证, 无任何密钥操作。
 *
 * 解析侧强校验 (畸形载荷入口即拒):
 * - JSON 必须可解码为非空交易列表;
 * - 每笔交易已签名 (signature 非空) 且 seq > 0。
 * 完整链校验 (验签/链接/足额/尾序号) 在 Vault 的 WalletKeyManager
 * 内完成 (需要钱包公钥与 HWM, 非 pure 函数)。
 */
data class IpcWalletSyncRequest(
    val sessionId: String,
    val chainJson: String,
    val chain: List<com.securesocial.core.wallet.WalletTx>?,
) {
    companion object {
        /**
         * 从 Intent 解析播种请求。sessionId 读 URI; 链 JSON 读
         * EXTRA_PAYLOAD (必填, v3.38 新通道无 URI 回退路径)。
         */
        fun fromIntent(intent: Intent): IpcWalletSyncRequest? {
            val uri = intent.data ?: return null
            if (!IpcContract.isWalletSyncUri(uri)) return null

            val sessionId = uri.getQueryParameter(IpcContract.PARAM_SESSION) ?: return null
            val chainJson = intent.getStringExtra(IpcContract.EXTRA_PAYLOAD) ?: return null
            return IpcWalletSyncRequest(sessionId, chainJson, parseChain(chainJson))
        }

        /** 从 URI 解析 (仅 sessionId; 链 JSON 必须经 Intent Extra) */
        fun fromUri(uri: Uri): IpcWalletSyncRequest? {
            if (!IpcContract.isWalletSyncUri(uri)) return null
            val sessionId = uri.getQueryParameter(IpcContract.PARAM_SESSION) ?: return null
            return IpcWalletSyncRequest(sessionId, "", null)
        }

        /**
         * 播种链结构校验 (纯解析层): 列表非空 + 每笔已签名 + 序号合法。
         * internal: 单测锁定结构门禁。
         */
        internal fun parseChain(chainJson: String): List<com.securesocial.core.wallet.WalletTx>? {
            val chain = com.securesocial.core.wallet.TxJsonCodec.decodeList(chainJson)
                ?: return null
            if (chain.isEmpty()) return null
            for (tx in chain) {
                if (tx.signature.isEmpty()) return null   // 播种链必须全签名
                if (tx.seq <= 0L) return null
                if (tx.amount <= 0L) return null
            }
            return chain
        }
    }
}
