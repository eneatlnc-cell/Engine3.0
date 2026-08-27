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
