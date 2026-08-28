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
 * URI 格式 (v3.17: 载荷已移出 URI; v3.38: 新增钱包双账户/交接入口):
 * - 唤起导入:  myvault://import?session=<sessionId>&app=<callingPackage>
 * - 唤起验证:  myvault://verify?session=<sessionId>&app=<callingPackage>
 * - 签名请求:  myvault://sign?session=<sessionId>&app=<callingPackage>   (payload → EXTRA_PAYLOAD)
 * - 钱包初始化: myvault://walletinit?session=<id>&app=<pkg>              (v3.37)
 * - 钱包签名:  myvault://signtx?session=<id>&app=<pkg>                   (v3.37, tx JSON → EXTRA_PAYLOAD)
 * - 账本对账:  myvault://walletstate?session=<id>&app=<pkg>              (v3.38, 免指纹摘要查询)
 * - 充值签名:  myvault://deposit?session=<id>&app=<pkg>                  (v3.38, DEPOSIT tx → EXTRA_PAYLOAD)
 * - 交接承接:  myvault://walletadopt?session=<id>&app=<pkg>              (v3.38, 证书 JSON → EXTRA_PAYLOAD)
 * - 账本播种:  myvault://walletsync?session=<id>&app=<pkg>               (v3.38, 链 JSON → EXTRA_PAYLOAD)
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

    // ---- v3.38: SPARK 钱包双账户 + 交接 IPC 入口 ----

    /**
     * 权威账本状态查询: Engine 定期对账用。Vault 免指纹返回双余额摘要
     * (custody/margin/高水位/尾哈希/终结态) —— 摘要非秘密材料, 且入口
     * 受 signature 权限保护 (仅同证书应用可发起); 回调经身份绑定私钥
     * 签名 (result 纳入签名范围, v3.29), 镜像对账有密码学锚点。
     */
    const val HOST_WALLET_STATE = "walletstate"

    /**
     * 充值签名 (custody → margin): DEPOSIT 交易的专用入口。与 signtx
     * 载荷同构 (未签名交易 JSON via EXTRA_PAYLOAD), 但入口强校验
     * type == DEPOSIT, Vault 侧路由到充值确认页 (DepositActivity)。
     * 签名前 Vault 用**权威账本**做 custody 足额校验 (关盲签缺口)。
     */
    const val HOST_DEPOSIT = "deposit"

    /**
     * 钱包交接承接 (新机): Engine 提交旧机交接证书 (HandoverCertificate
     * JSON via EXTRA_PAYLOAD)。Vault 验证证书 (防调包 + 旧密钥验签) +
     * 指纹门后, 用本机钱包私钥签署承接 GENESIS 交易并落库为权威账本,
     * 签名后的 GENESIS 经回调 result 返回 Engine 落镜像。
     */
    const val HOST_WALLET_ADOPT = "walletadopt"

    /**
     * 权威账本播种 (v3.37→v3.38 升级路径): Engine 提交完整已签名链
     * (JSON via EXTRA_PAYLOAD), Vault 全链验签后落库为权威账本。
     *
     * 背景: v3.37 只在 Vault 侧记高水位 (HWM), 交易链仅存 Engine 镜像;
     * v3.38 Vault 需要权威账本做签名前足额校验 (关盲签缺口)。老设备
     * 升级后 Engine 检测到 walletstate 返回 txCount=0 且 highWaterSeq>0,
     * 即触发一次性播种。
     *
     * 验签规则 (Vault 侧, 零信任 Engine):
     * - 全链签名/链接/序号/足额校验 (WalletLedger.verify, 用钱包公钥);
     * - 链尾 seq ≤ HWM (链尾必须不超过已签名高水位 —— 伪造未来交易直接拒);
     * - Vault 权威账本已非空时拒绝 (AlreadySeeded, 不可覆盖)。
     *
     * 残余面 (诚实边界): 播种链若为真实链的前缀 (隐藏尾部支出), 权威
     * 余额将被高估 —— 这是被攻破 Engine 的一次性窗口, 与 v3.37 声明的
     * root/Engine 妥协残余面同级; 播种后每笔交易由 Vault 独立记账,
     * 窗口即闭合。
     */
    const val HOST_WALLET_SYNC = "walletsync"

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

    // ---- v3.38: SPARK 钱包双账户 + 交接 IPC ----

    /**
     * v3.38 构建 "权威账本状态查询" 唤起 URI。
     *
     * 场景: Engine 启动/前台时向 Vault 拉取权威账本摘要, 与本地镜像
     * 账本对账:
     * - custody/margin 余额不一致 → 镜像被篡改/丢失, 以 Vault 为准重建;
     * - highWaterSeq 不一致 → 账本回滚/烧号, 拒绝后续交易提交;
     * - tipHash 不一致 → 逐笔核对定位分叉点;
     * - terminal == true → 本地钱包已交接终结, Engine 锁定钱包 UI
     *   并引导 "此设备钱包已迁出" 文案。
     *
     * 无载荷 Extra (纯查询); Vault 免指纹直接应答 (摘要非秘密材料,
     * 入口受 signature 权限保护)。钱包未初始化时回调
     * NO_WALLET_KEY 失败码 (Engine 据此引导初始化)。
     */
    fun buildWalletStateUri(sessionId: String, appPackage: String = ENGINE_PACKAGE): String {
        return Uri.Builder()
            .scheme(SCHEME)
            .authority(HOST_WALLET_STATE)
            .appendQueryParameter(PARAM_SESSION, sessionId)
            .appendQueryParameter(PARAM_APP, appPackage)
            .build()
            .toString()
    }

    /** 检查 URI 是否为权威账本状态查询 */
    fun isWalletStateUri(uri: Uri): Boolean =
        uri.scheme == SCHEME && uri.host == HOST_WALLET_STATE

    /**
     * v3.38 构建 "充值签名" 唤起 URI (仅路由字段)。
     *
     * 载荷与 signtx 同构: 未签名 DEPOSIT 交易 JSON 经 EXTRA_PAYLOAD
     * 投递。独立入口的价值:
     * - Vault 侧路由到充值确认页 (展示 custody → margin 双账户效果,
     *   而非通用 "支出" 确认页文案);
     * - 入口即强校验 type == DEPOSIT (非 DEPOSIT 交易走此入口直接
     *   TX_FORMAT_ERROR, 防止确认页语义混淆攻击 —— 用充值页文案
     *   诱导用户签署 SPEND);
     * - Vault 签名前用权威账本做 custody 足额校验, 不足即
     *   INSUFFICIENT_CUSTODY (与 signtx 的 INSUFFICIENT_MARGIN
     *   错误语义分离, Engine 据此分流引导)。
     */
    fun buildDepositUri(sessionId: String, appPackage: String = ENGINE_PACKAGE): String {
        return Uri.Builder()
            .scheme(SCHEME)
            .authority(HOST_DEPOSIT)
            .appendQueryParameter(PARAM_SESSION, sessionId)
            .appendQueryParameter(PARAM_APP, appPackage)
            .build()
            .toString()
    }

    /** 检查 URI 是否为充值签名请求 */
    fun isDepositUri(uri: Uri): Boolean =
        uri.scheme == SCHEME && uri.host == HOST_DEPOSIT

    /**
     * v3.38 构建 "钱包交接承接" 唤起 URI (仅路由字段)。
     *
     * 场景 (新机侧): Engine 扫旧机交接二维码获得 [HandoverCertificate],
     * 经此入口提交给 Vault (证书 JSON via EXTRA_PAYLOAD)。Vault:
     * 1. 结构校验 (可解码 / type == HANDOVER / 金额恒正);
     * 2. 确认页展示承接金额 + 旧公钥指纹, 生物识别门;
     * 3. 证书验证 (HandoverCertificate.verify): 证书必须签给**本机**
     *    钱包公钥 (防调包) + 旧密钥签名验证 (防篡改);
     * 4. 本机权威账本必须为空 (已有账本的设备不能承接 —— 换机方向
     *    反了; 先在新机 Vault 内出账/交接旧钱包);
     * 5. 构造承接 GENESIS (amount = 证书 custody 快照, counterparty =
     *    旧公钥 hex, memo = 交接交易哈希), 用本机钱包私钥签名;
     * 6. 落库为权威账本 (高水位重置为 1);
     * 7. 签名后的 GENESIS 交易 JSON 经回调 result 返回, Engine 落镜像。
     *
     * 失败码: HANDOVER_CERT_INVALID (证书验证失败) /
     * WALLET_ALREADY_INITIALIZED (本机已有账本) / NO_WALLET_KEY
     * (本机钱包密钥未初始化 —— 先 walletinit 生成新密钥对再发起承接)。
     */
    fun buildWalletAdoptUri(sessionId: String, appPackage: String = ENGINE_PACKAGE): String {
        return Uri.Builder()
            .scheme(SCHEME)
            .authority(HOST_WALLET_ADOPT)
            .appendQueryParameter(PARAM_SESSION, sessionId)
            .appendQueryParameter(PARAM_APP, appPackage)
            .build()
            .toString()
    }

    /** 检查 URI 是否为钱包交接承接请求 */
    fun isWalletAdoptUri(uri: Uri): Boolean =
        uri.scheme == SCHEME && uri.host == HOST_WALLET_ADOPT

    /**
     * v3.38 构建 "权威账本播种" 唤起 URI (仅路由字段)。
     *
     * 载荷: 完整已签名链 JSON (List<WalletTx> via EXTRA_PAYLOAD)。
     * Vault 全链验签 (签名/链接/序号/足额) + 链尾 seq ≤ HWM 校验后
     * 落库; 免指纹 (纯公开材料验证, 无密钥操作 —— 但要求钱包密钥
     * 已初始化)。失败码: TX_FORMAT_ERROR (链不可验证) /
     * WALLET_ALREADY_INITIALIZED (权威账本已非空) / NO_WALLET_KEY。
     */
    fun buildWalletSyncUri(sessionId: String, appPackage: String = ENGINE_PACKAGE): String {
        return Uri.Builder()
            .scheme(SCHEME)
            .authority(HOST_WALLET_SYNC)
            .appendQueryParameter(PARAM_SESSION, sessionId)
            .appendQueryParameter(PARAM_APP, appPackage)
            .build()
            .toString()
    }

    /** 检查 URI 是否为权威账本播种请求 */
    fun isWalletSyncUri(uri: Uri): Boolean =
        uri.scheme == SCHEME && uri.host == HOST_WALLET_SYNC
}
