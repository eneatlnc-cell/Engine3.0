package com.securesocial.core.ipc

import android.net.Uri

/**
 * IPC URI Scheme 契约 (Engine ↔ Vault)
 *
 * 安全模型 (v2, 修复隐式 Intent 广播式投递与回调伪造):
 * - 所有跨 App 唤起必须使用显式包名投递 (Intent.setPackage), 消除 chooser 误选与恶意 App 抢答
 * - 组件受 signature 级自定义权限保护, 只有与 Vault 同证书签名的应用才能唤起
 * - 移除 BROWSABLE 类别, 浏览器/任意网页无法唤起 IPC 入口
 * - 所有回调必须携带 ECDSA 签名 (sig = Sign_vault(sessionId ‖ status ‖ ts [‖ result]),
 *   v3.29: 成功回调的业务结果一并纳入签名), Engine 用绑定公钥验签 + 时间戳窗口校验,
 *   防止回调伪造与重放; 成功回调无签名时一律拒绝 (失败回调按契约可免签)
 * - 私钥仍仅经二维码光学通道或受保护的 Intent Extra (import) 传递
 *
 * v3.17 载荷去 URI 化 (修复: 敏感材料进系统日志):
 * - 系统在启动 Activity 时会把 Intent URI 完整写入 logcat
 *   (ActivityTaskManager 的 "START u0" 行), bug 报告/流氓 App 均可读取。
 * - 原 sign 请求的 payload (中继挑战 nonce / ECDH 公钥) 与 callback 的
 *   sig / result (ECDSA 签名材料) 全部挂在 URI 查询串里 —— 敏感材料
 *   系统级泄露面。v3.17 起 URI 仅承载路由字段 (session/status/code/ts/app),
 *   一切载荷经 Intent Extra 传递 (Extra 不进 ActivityTaskManager 日志)。
 * - 解析端保留 URI 参数回退路径, 兼容新旧版本混布 (升级窗口期)。
 *
 * URI 格式 (v3.17: 载荷已移出 URI):
 * - 唤起导入:  myvault://import?session=<sessionId>&app=<callingPackage>
 * - 唤起验证:  myvault://verify?session=<sessionId>&app=<callingPackage>
 * - 签名请求:  myvault://sign?session=<sessionId>&app=<callingPackage>   (payload → EXTRA_PAYLOAD)
 * - 成功回调:  myvault://callback?session=<id>&status=success&ts=<millis> (sig/result → EXTRA_SIG/EXTRA_RESULT)
 * - 失败回调:  myvault://callback?session=<id>&status=fail&code=<err>&ts=<millis> (sig → EXTRA_SIG)
 *
 * 多应用绑定 (v3): app 参数标识发起方包名, Vault 据此路由 "该应用专属的活动密钥",
 * 并在状态页展示来源应用名称。包名可信: IPC 入口受 signature 权限保护,
 * 只有同证书应用能进入; Vault 侧再用 PackageManager 校验该包真实存在。
 */
object IpcContract {
    const val SCHEME = "myvault"
    const val HOST_IMPORT = "import"
    const val HOST_CALLBACK = "callback"
    const val HOST_VERIFY = "verify"
    const val HOST_SIGN = "sign"
    const val HOST_RESTORE = "restore"

    // ---- v3.37: SPARK 钱包 IPC 入口 ----
    /** 钱包密钥初始化: Vault 内生成钱包密钥对, 公钥经回调返回 (私钥永不离开 Vault) */
    const val HOST_WALLET_INIT = "walletinit"

    /** 钱包交易签名: Engine 提交未签名交易 JSON, Vault 确认页渲染后用钱包私钥签名 */
    const val HOST_SIGN_TX = "signtx"

    const val PARAM_SESSION = "session"
    const val PARAM_STATUS = "status"
    const val PARAM_CODE = "code"
    const val PARAM_PAYLOAD = "payload"
    const val PARAM_RESULT = "result"
    const val PARAM_TS = "ts"
    const val PARAM_SIG = "sig"
    const val PARAM_APP = "app"

    const val STATUS_SUCCESS = "success"
    const val STATUS_FAIL = "fail"

    // ---- 显式投递目标与权限 (v2) --------------------------------------------

    /** Vault 应用包名: Engine 发起的全部 IPC Intent 必须锁定此包名 */
    const val VAULT_PACKAGE = "com.vault"

    /** Engine 应用包名: Vault 发起的回调 Intent 必须锁定此包名 */
    const val ENGINE_PACKAGE = "com.engine"

    /**
     * Vault 侧 signature 级自定义权限。
     * 保护 Vault 的 import/verify/sign 入口组件: 仅与 Vault 同一证书签名的应用
     * (即 Engine, 开发期共用 debug keystore / 发布期需统一 release 签名) 可唤起。
     */
    const val VAULT_IPC_PERMISSION = "com.vault.permission.VAULT_IPC"

    /**
     * Engine 侧 signature 级自定义权限。
     * 保护 Engine 的 callback 入口组件: 仅持有该权限者 (即 Vault) 可投递登录/签名回调。
     */
    const val ENGINE_CALLBACK_PERMISSION = "com.engine.permission.ENGINE_CALLBACK"

    /** 回调签名验证的时间戳容忍窗口 (毫秒): ±120 秒 */
    const val CALLBACK_TS_TOLERANCE_MS = 120_000L

    /**
     * Intent Extra 键: 用于直接传递密钥二维码载荷 (JSON 字符串)。
     *
     * 当 Engine 通过 "一键唤起" 调起 Vault 时, 将 QR payload 作为 Intent Extra 传递,
     * Vault 可直接解析而无需开启摄像头扫描。
     * 安全约束 (v2): 该通道仅在 signature 权限 + 显式包名投递保护下使用,
     * 恶意 App 既无法收到此 Intent, 也无法伪造回调。
     *
     * v3.17: 同键复用于签名请求的待签字节 (Base64) —— URI 不再携带 payload
     * (防系统日志泄露, 详见契约头注释)。
     */
    const val EXTRA_PAYLOAD = "extra_payload"

    /**
     * Intent Extra 键: 回调 ECDSA 签名 (Base64)。
     *
     * v3.17 新增: 原挂在回调 URI 的 sig 参数上, 会随 ActivityTaskManager 的
     * "START u0" 日志行整体进 logcat。迁移至 Extra 后系统日志中仅剩
     * session/status/code/ts 路由字段。
     */
    const val EXTRA_SIG = "extra_sig"

    /**
     * Intent Extra 键: 回调业务结果 (Base64, 如签名字节 / 恢复公钥)。
     *
     * v3.17 新增: 与 EXTRA_SIG 同因从 URI 查询串迁移而来。
     */
    const val EXTRA_RESULT = "extra_result"

    /**
     * 构建回调签名内容: sessionId ‖ status ‖ ts ‖ result (均 UTF-8 字节顺序拼接)
     *
     * Vault 对该内容做 ECDSA P-256 签名后经 Intent Extra 附在回调中,
     * Engine 用绑定身份公钥验签 —— 回调从 "状态字符串" 升级为 "私钥持有证明"。
     *
     * v3.29 审计修复 #7: 成功回调的 result (签名字节 / 恢复公钥) 纳入签名范围。
     * 旧签名仅覆盖 sessionId‖status‖ts —— 验签通过不能证明 result 未被替换,
     * 被拦截的回调可在保留合法签名的同时调包业务结果。result 为 null 时
     * (导入/登录流程的成功回调、全部失败回调) 签名内容与 v2 完全一致。
     *
     * ⚠ 兼容性: 本变更要求 Engine 与 Vault 成对升级 (v3.29+); 混布时
     * 旧版 Vault 发出的 sign/restore 成功回调会被新版 Engine 验签拒绝
     * (导入/登录流程不受影响 —— 其 result 本就为 null)。
     */
    fun callbackSigningContent(
        sessionId: String,
        status: String,
        ts: String,
        result: String? = null
    ): ByteArray {
        val base = sessionId + status + ts
        return if (result != null) {
            (base + result).toByteArray(Charsets.UTF_8)
        } else {
            base.toByteArray(Charsets.UTF_8)
        }
    }

    /**
     * 构建唤起 App B 导入的 URI
     *
     * @param appPackage 发起方包名 (v3: Vault 据此绑定 "该应用专属的活动密钥")
     */
    fun buildImportUri(sessionId: String, appPackage: String = ENGINE_PACKAGE): String {
        return Uri.Builder()
            .scheme(SCHEME)
            .authority(HOST_IMPORT)
            .appendQueryParameter(PARAM_SESSION, sessionId)
            .appendQueryParameter(PARAM_APP, appPackage)
            .build()
            .toString()
    }

    /**
     * 构建成功回调 URI (v3.17: 仅路由字段)
     *
     * URI 只携带 session/status/ts; ECDSA 签名与业务结果由调用方经
     * Intent Extra (EXTRA_SIG / EXTRA_RESULT) 投递 —— Extra 不进
     * ActivityTaskManager 日志, 签名材料不再随系统日志泄露。
     */
    fun buildSuccessCallbackUri(sessionId: String, ts: Long): String {
        return Uri.Builder()
            .scheme(SCHEME)
            .authority(HOST_CALLBACK)
            .appendQueryParameter(PARAM_SESSION, sessionId)
            .appendQueryParameter(PARAM_STATUS, STATUS_SUCCESS)
            .appendQueryParameter(PARAM_TS, ts.toString())
            .build()
            .toString()
    }

    /**
     * 构建失败回调 URI (v3.17: 仅路由字段, 签名经 EXTRA_SIG 投递)
     */
    fun buildFailCallbackUri(errorCode: IpcErrorCode, sessionId: String, ts: Long): String {
        return Uri.Builder()
            .scheme(SCHEME)
            .authority(HOST_CALLBACK)
            .appendQueryParameter(PARAM_SESSION, sessionId)
            .appendQueryParameter(PARAM_STATUS, STATUS_FAIL)
            .appendQueryParameter(PARAM_CODE, errorCode.code)
            .appendQueryParameter(PARAM_TS, ts.toString())
            .build()
            .toString()
    }

    /**
     * 构建唤起指纹验证的 URI
     */
    fun buildVerifyUri(sessionId: String, appPackage: String = ENGINE_PACKAGE): String {
        return Uri.Builder()
            .scheme(SCHEME)
            .authority(HOST_VERIFY)
            .appendQueryParameter(PARAM_SESSION, sessionId)
            .appendQueryParameter(PARAM_APP, appPackage)
            .build()
            .toString()
    }

    /**
     * 构建签名请求 URI (v3.17: 仅路由字段)。
     *
     * 待签字节 (Base64) 由调用方经 Intent Extra (EXTRA_PAYLOAD) 投递,
     * 不再挂 URI 查询串 —— 中继挑战 nonce / ECDH 公钥等材料
     * 不随 ActivityTaskManager 系统日志泄露。
     *
     * Engine 将待签字节 (Base64) 发给 Vault, Vault 验证生物识别后用
     * 该应用绑定的身份私钥做 ECDSA 签名, 签名结果经 callback 的 result 返回。
     * 典型用途: 中继注册挑战应答、ECDH 信号公钥签名。
     */
    fun buildSignUri(
        sessionId: String,
        appPackage: String = ENGINE_PACKAGE
    ): String {
        return Uri.Builder()
            .scheme(SCHEME)
            .authority(HOST_SIGN)
            .appendQueryParameter(PARAM_SESSION, sessionId)
            .appendQueryParameter(PARAM_APP, appPackage)
            .build()
            .toString()
    }

    /** 检查 URI 是否为 IPC 唤起请求 */
    fun isImportUri(uri: Uri): Boolean =
        uri.scheme == SCHEME && uri.host == HOST_IMPORT

    /** 检查 URI 是否为 IPC 回调 */
    fun isCallbackUri(uri: Uri): Boolean =
        uri.scheme == SCHEME && uri.host == HOST_CALLBACK

    /** 检查 URI 是否为指纹验证请求 */
    fun isVerifyUri(uri: Uri): Boolean =
        uri.scheme == SCHEME && uri.host == HOST_VERIFY

    /** 检查 URI 是否为签名请求 */
    fun isSignUri(uri: Uri): Boolean =
        uri.scheme == SCHEME && uri.host == HOST_SIGN

    /**
     * v3.6 构建 "身份恢复" 唤起 URI。
     *
     * 场景: Engine 清除数据 / 换机重装后本地绑定身份丢失, 但 Vault 仍持有
     * 该应用专属的绑定私钥。Engine 发起 restore 请求, Vault 在指纹门后
     * 将 "该绑定的公钥 (X.509 Base64)" 经回调 result 参数送回 ——
     * Engine 恢复同一 DID 身份, 私钥全程不出 Vault。
     *
     * 安全模型:
     * - 回调通道受 ENGINE_CALLBACK signature 权限保护 (仅 Vault 可投递)
     * - 回调 sig 用 "被恢复的那把绑定私钥" 签名, Engine 用返回的公钥验签
     *   —— 构成私钥持有证明 + 公私钥自洽证明
     * - 公钥与指纹均非秘密材料, 回调泄露不影响私钥安全
     */
    fun buildRestoreUri(sessionId: String, appPackage: String = ENGINE_PACKAGE): String {
        return Uri.Builder()
            .scheme(SCHEME)
            .authority(HOST_RESTORE)
            .appendQueryParameter(PARAM_SESSION, sessionId)
            .appendQueryParameter(PARAM_APP, appPackage)
            .build()
            .toString()
    }

    /** 检查 URI 是否为身份恢复请求 */
    fun isRestoreUri(uri: Uri): Boolean =
        uri.scheme == SCHEME && uri.host == HOST_RESTORE

    // ---- v3.37: SPARK 钱包 IPC ----

    /**
     * v3.37 构建 "钱包密钥初始化" 唤起 URI。
     *
     * 场景: Engine 首次使用 SPARK 钱包时调用。Vault 在指纹门后为该应用
     * 生成**钱包专属密钥对** (与身份密钥完全独立的第二个密钥槽):
     * - 私钥仅以 Keystore 加密形态存于 Vault, 永不离开 (比身份密钥的
     *   二维码导入路径更严 —— 钱包密钥连光学通道都不经过);
     * - 公钥 (X.509 Base64) 经回调 result 送回 Engine, Engine 保存并
     *   用于此后全部交易签名的验签;
     * - 幂等: 已有钱包密钥时直接返回既有公钥, 不重新生成。
     *
     * 安全模型与 restore 一致: 回调受 ENGINE_CALLBACK signature 权限
     * 保护 + 身份绑定私钥对 (sessionId ‖ status ‖ ts ‖ result) 签名。
     */
    fun buildWalletInitUri(sessionId: String, appPackage: String = ENGINE_PACKAGE): String {
        return Uri.Builder()
            .scheme(SCHEME)
            .authority(HOST_WALLET_INIT)
            .appendQueryParameter(PARAM_SESSION, sessionId)
            .appendQueryParameter(PARAM_APP, appPackage)
            .build()
            .toString()
    }

    /** 检查 URI 是否为钱包初始化请求 */
    fun isWalletInitUri(uri: Uri): Boolean =
        uri.scheme == SCHEME && uri.host == HOST_WALLET_INIT

    /**
     * v3.37 构建 "钱包交易签名" 唤起 URI (仅路由字段)。
     *
     * 待签交易 (未签名 [com.securesocial.core.wallet.WalletTx] 的 JSON)
     * 经 Intent Extra (EXTRA_PAYLOAD) 投递 —— 与既有 sign 请求同一
     * 防日志泄露策略。Vault 解析后在**自己进程渲染的确认页**上展示
     * 金额/类型/对手方/序号 (Ledger 模式: 主机被攻破也无法骗签),
     * 生物识别通过后:
     * 1. 校验 tx.seq > 本地高水位序号 (回滚见证, 旧序号一律拒绝);
     * 2. 用该应用的钱包私钥对 [com.securesocial.core.wallet.TxCanonical]
     *    规范化字节签名 (域分离: SPARK-WALLET-TX-V1);
     * 3. 更新高水位为 tx.seq;
     * 4. Base64 签名经回调 result 返回。
     */
    fun buildSignTxUri(sessionId: String, appPackage: String = ENGINE_PACKAGE): String {
        return Uri.Builder()
            .scheme(SCHEME)
            .authority(HOST_SIGN_TX)
            .appendQueryParameter(PARAM_SESSION, sessionId)
            .appendQueryParameter(PARAM_APP, appPackage)
            .build()
            .toString()
    }

    /** 检查 URI 是否为钱包交易签名请求 */
    fun isSignTxUri(uri: Uri): Boolean =
        uri.scheme == SCHEME && uri.host == HOST_SIGN_TX
}
