package com.securesocial.core.ipc

import android.os.Binder
import android.os.IBinder
import android.os.IInterface
import android.os.Parcel

/**
 * v3.40 Binder IPC 通道 —— 根治「"Engine" 想要打开 "Vault"」系统级
 * 跳转确认弹窗 (真机回归确认的循环弹窗问题)。
 *
 * ── 问题根源 ──────────────────────────────────────────────
 * 旧通道的每一跳都是跨应用 `startActivity(ACTION_VIEW myvault://…)`:
 *   Engine → Vault 入口一跳, Vault → Engine 回调再一跳。
 * 部分 ROM (MIUI/HyperOS/ColorOS 等) 对跨应用跳转一律弹
 * 「"A" 想要打开 "B"」确认框 —— 每次签名/验证/对账要弹 2 次,
 * 拒绝后 Engine 重试又弹, 即用户报告的「循环弹出」。
 * 静默对账 (walletstate) 轮询时尤甚: 用户每分钟被打断数次。
 *
 * ── 解法 ──────────────────────────────────────────────────
 * Engine `bindService` 到 Vault 的 [com.vault.ipc.VaultIpcService]
 * (显式 Intent + signature 权限保护, 绑定行为不触发任何用户确认),
 * 之后:
 *   · 请求: Engine 经 [IVaultIpcService.request] 投递 URI + 载荷,
 *     Vault 在自己进程内路由 (静默入口直跑 / UI 入口启动应用内
 *     Activity —— 应用内跳转永不触发跨应用确认框);
 *   · 回调: Vault 经 [IEngineIpcCallback.onCallback] 把签名回调
 *     URI + 敏感 Extra 直送 Engine 进程, 不再 startActivity。
 * 双向跨应用跳转全部消失。
 *
 * Android 10+ 后台 Activity 启动限制的豁免依据: 被前台可见应用
 * 绑定的服务允许启动 Activity (官方 Background activity starts
 * exemptions 条款)。Engine 前台发起请求时绑定关系成立, 满足豁免。
 *
 * ── 安全模型 (不弱于旧通道) ────────────────────────────────
 *   1. Service 由 signature 级权限 com.vault.permission.VAULT_IPC
 *      保护 —— 只有同签名证书的 Engine 能绑定 (manifest 声明);
 *   2. Vault 侧 request() 复核 Binder.getCallingUid 归属包名;
 *   3. 回调仍是签名回调 (ECDSA 覆盖 sessionId‖status‖ts‖result,
 *      v3.29 契约), Engine 侧 verifyCallbackSignature 验签逻辑
 *      原样复用 —— Binder 通道只换「投递方式」, 不动密码学。
 *
 * ── 兼容性 ────────────────────────────────────────────────
 * Engine 端 bind 失败 / Vault 版本过旧无 Service 时自动回退
 * 旧 Activity 跳转通道 (渐进部署窗口期双端可独立升级)。
 *
 * 本文件在 Engine 与 Vault 两工程 core-ipc 模块内镜像维护,
 * 描述符与 transaction code 必须逐字节一致。
 */
object VaultIpcBinderContract {

    /** 服务接口描述符 (两工程必须一致) */
    const val DESCRIPTOR_SERVICE = "com.securesocial.core.ipc.binder.VaultIpcService"

    /** 回调接口描述符 (两工程必须一致) */
    const val DESCRIPTOR_CALLBACK = "com.securesocial.core.ipc.binder.EngineIpcCallback"

    /** IVaultIpcService.request 事务码 */
    const val TRANSACTION_REQUEST = Binder.FIRST_CALL_TRANSACTION + 0

    /** IVaultIpcService.ping 事务码 (通道握手/版本探测) */
    const val TRANSACTION_PING = Binder.FIRST_CALL_TRANSACTION + 1

    /** IEngineIpcCallback.onCallback 事务码 */
    const val TRANSACTION_ON_CALLBACK = Binder.FIRST_CALL_TRANSACTION + 0

    /** Binder 通道协议版本 (ping 返回值; 不匹配时 Engine 回退旧通道) */
    const val PROTOCOL_VERSION = 1

    /** request() 结果: 已受理 (结果经 onCallback 异步送达) */
    const val RESULT_ACCEPTED = 0

    /** request() 结果: 拒绝 (调用方校验失败 / 参数非法 / host 未知) */
    const val RESULT_REJECTED = 1

    /** request() 结果: 受理失败 (内部异常, 可回退旧通道重试) */
    const val RESULT_INTERNAL = 2
}

/**
 * Vault IPC 服务接口 (Engine 持代理, Vault 实现 Stub)。
 *
 * [request] 与旧通道的 myvault:// 跳转语义一一对应:
 *   @param uriString    完整 myvault:// 请求 URI (含 session/app 参数)
 *   @param payloadBase64 EXTRA_PAYLOAD (签名载荷/交易 JSON 等), 可空
 *   @param callback     Engine 侧回调 Binder (结果经 onCallback 送达)
 *   @return RESULT_* 结果码
 */
interface IVaultIpcService : IInterface {

    fun request(uriString: String, payloadBase64: String?, callback: IEngineIpcCallback): Int

    fun ping(): Int

    abstract class Stub : Binder(), IVaultIpcService {

        init {
            attachInterface(this, VaultIpcBinderContract.DESCRIPTOR_SERVICE)
        }

        override fun asBinder(): IBinder = this

        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            when (code) {
                VaultIpcBinderContract.TRANSACTION_REQUEST -> {
                    data.enforceInterface(VaultIpcBinderContract.DESCRIPTOR_SERVICE)
                    val uriString = data.readString()
                    val payloadBase64 = data.readString()
                    val callbackBinder = data.readStrongBinder()
                    val callback =
                        if (callbackBinder != null) IEngineIpcCallback.Stub.asInterface(callbackBinder) else null
                    val result = if (uriString == null || callback == null) {
                        VaultIpcBinderContract.RESULT_REJECTED
                    } else {
                        try {
                            request(uriString, payloadBase64, callback)
                        } catch (e: Exception) {
                            VaultIpcBinderContract.RESULT_INTERNAL
                        }
                    }
                    reply?.writeNoException()
                    reply?.writeInt(result)
                    return true
                }

                VaultIpcBinderContract.TRANSACTION_PING -> {
                    data.enforceInterface(VaultIpcBinderContract.DESCRIPTOR_SERVICE)
                    val result = ping()
                    reply?.writeNoException()
                    reply?.writeInt(result)
                    return true
                }
            }
            return super.onTransact(code, data, reply, flags)
        }

        companion object {
            fun asInterface(binder: IBinder?): IVaultIpcService? {
                if (binder == null) return null
                val local = binder.queryLocalInterface(VaultIpcBinderContract.DESCRIPTOR_SERVICE)
                if (local is IVaultIpcService) return local
                return Proxy(binder)
            }
        }

        private class Proxy(private val remote: IBinder) : IVaultIpcService {

            override fun asBinder(): IBinder = remote

            override fun request(
                uriString: String,
                payloadBase64: String?,
                callback: IEngineIpcCallback
            ): Int {
                val data = Parcel.obtain()
                val reply = Parcel.obtain()
                return try {
                    data.writeInterfaceToken(VaultIpcBinderContract.DESCRIPTOR_SERVICE)
                    data.writeString(uriString)
                    data.writeString(payloadBase64)
                    data.writeStrongBinder(callback.asBinder())
                    remote.transact(VaultIpcBinderContract.TRANSACTION_REQUEST, data, reply, 0)
                    reply.readException()
                    reply.readInt()
                } finally {
                    reply.recycle()
                    data.recycle()
                }
            }

            override fun ping(): Int {
                val data = Parcel.obtain()
                val reply = Parcel.obtain()
                return try {
                    data.writeInterfaceToken(VaultIpcBinderContract.DESCRIPTOR_SERVICE)
                    remote.transact(VaultIpcBinderContract.TRANSACTION_PING, data, reply, 0)
                    reply.readException()
                    reply.readInt()
                } finally {
                    reply.recycle()
                    data.recycle()
                }
            }
        }
    }
}

/**
 * Engine 回调接口 (Engine 实现 Stub, Vault 持代理)。
 *
 * [onCallback] 与旧通道 Vault→Engine 的 myvault://callback 跳转
 * 语义一一对应 —— 载荷即 IpcReceiver 构造的签名回调:
 *   @param uriString  签名回调 URI (session/status/code/ts 查询参数)
 *   @param sigB64     ECDSA 签名 Base64 (EXTRA_SIG 等价物)
 *   @param resultB64  业务结果 Base64 (EXTRA_RESULT 等价物)
 *
 * Engine 实现侧收到后构造虚拟 Intent 喂给 IpcCallback.fromIntent(),
 * 与旧 CallbackActivity 的解析路径完全合流。
 */
interface IEngineIpcCallback : IInterface {

    fun onCallback(uriString: String, sigB64: String?, resultB64: String?)

    abstract class Stub : Binder(), IEngineIpcCallback {

        init {
            attachInterface(this, VaultIpcBinderContract.DESCRIPTOR_CALLBACK)
        }

        override fun asBinder(): IBinder = this

        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            when (code) {
                VaultIpcBinderContract.TRANSACTION_ON_CALLBACK -> {
                    data.enforceInterface(VaultIpcBinderContract.DESCRIPTOR_CALLBACK)
                    val uriString = data.readString()
                    val sigB64 = data.readString()
                    val resultB64 = data.readString()
                    if (uriString != null) {
                        try {
                            onCallback(uriString, sigB64, resultB64)
                        } catch (e: Exception) {
                            // Engine 实现异常不影响 Vault 侧投递流程
                        }
                    }
                    reply?.writeNoException()
                    return true
                }
            }
            return super.onTransact(code, data, reply, flags)
        }

        companion object {
            fun asInterface(binder: IBinder?): IEngineIpcCallback? {
                if (binder == null) return null
                val local = binder.queryLocalInterface(VaultIpcBinderContract.DESCRIPTOR_CALLBACK)
                if (local is IEngineIpcCallback) return local
                return Proxy(binder)
            }
        }

        private class Proxy(private val remote: IBinder) : IEngineIpcCallback {

            override fun asBinder(): IBinder = remote

            override fun onCallback(uriString: String, sigB64: String?, resultB64: String?) {
                val data = Parcel.obtain()
                val reply = Parcel.obtain()
                try {
                    data.writeInterfaceToken(VaultIpcBinderContract.DESCRIPTOR_CALLBACK)
                    data.writeString(uriString)
                    data.writeString(sigB64)
                    data.writeString(resultB64)
                    remote.transact(VaultIpcBinderContract.TRANSACTION_ON_CALLBACK, data, reply, 0)
                    reply.readException()
                } finally {
                    reply.recycle()
                    data.recycle()
                }
            }
        }
    }
}
