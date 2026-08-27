package com.securesocial.core.ipc

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * IPC 回调签名契约单元测试 (审计 P0-3, v3.29)
 *
 * 回调签名是 Engine↔Vault 信任传递的核心: 签名内容格式的任何
 * 不一致都会导致验签失败 (协议断裂) 或保护范围缺口 (安全回退)。
 * 本测试锁定 v3.29 修复 #7 的契约语义:
 * - result 为 null 时与 v2 三参数格式逐字节一致 (混布兼容边界)
 * - 成功回调 result 纳入签名 (防调包业务结果)
 * - 任何字段变动改变签名内容
 *
 * 注: URI 构建依赖 android.net.Uri, 属 Android 集成测试范畴;
 * 本地单测聚焦纯 Kotlin 的签名内容契约。
 */
class IpcContractTest {

    @Test
    fun `v2 compat - null result equals legacy three-field content`() {
        val legacy = IpcContract.callbackSigningContent("session-1", "success", "1700000000000")
        val modern = IpcContract.callbackSigningContent("session-1", "success", "1700000000000", null)
        assertArrayEquals(
            "result=null 必须与 v2 三参数版本逐字节一致 (导入/登录回调兼容)",
            legacy,
            modern
        )
    }

    @Test
    fun `content is strict utf8 concatenation`() {
        val content = IpcContract.callbackSigningContent("s", "fail", "123")
        assertArrayEquals("sfail123".toByteArray(Charsets.UTF_8), content)
    }

    @Test
    fun `result is appended to signing content`() {
        val without = IpcContract.callbackSigningContent("s", "success", "123")
        val withResult = IpcContract.callbackSigningContent("s", "success", "123", "SIGNATURE_BYTES")
        assertEquals(
            "result 必须拼接在三元组之后",
            "ssuccess123SIGNATURE_BYTES",
            String(withResult, Charsets.UTF_8)
        )
        assertNotEquals(without.toList(), withResult.toList())
    }

    @Test
    fun `tampering any covered field changes content`() {
        val base = IpcContract.callbackSigningContent("sess", "success", "1000", "result")
        val tamperedSession = IpcContract.callbackSigningContent("sessX", "success", "1000", "result")
        val tamperedStatus = IpcContract.callbackSigningContent("sess", "failure", "1000", "result")
        val tamperedTs = IpcContract.callbackSigningContent("sess", "success", "2000", "result")
        val tamperedResult = IpcContract.callbackSigningContent("sess", "success", "1000", "resultX")

        for (t in listOf(tamperedSession, tamperedStatus, tamperedTs, tamperedResult)) {
            assertNotEquals("被覆盖字段篡改必须改变签名内容", base.toList(), t.toList())
        }
    }

    @Test
    fun `sign and verify flow with real ecdsa key`() {
        // 端到端: Vault 签 (sessionId‖status‖ts‖result) → Engine 验
        val ecdsa = com.securesocial.core.crypto.EcdsaOperations()
        val keyPair = ecdsa.generateKeyPair()

        val sessionId = "restore-42"
        val ts = System.currentTimeMillis().toString()
        val result = "restored-pubkey-base64"

        val content = IpcContract.callbackSigningContent(sessionId, "success", ts, result)
        val sig = ecdsa.sign(keyPair.private, content)

        // Engine 侧以同参数重建并验签
        val rebuilt = IpcContract.callbackSigningContent(sessionId, "success", ts, result)
        assertTrue(ecdsa.verify(keyPair.public, rebuilt, sig))

        // 攻击者替换 result (保留合法三元组签名) → 验签失败
        val swapped = IpcContract.callbackSigningContent(sessionId, "success", ts, "EVIL_RESULT")
        assertFalse("result 调包必须被签名覆盖拒绝", ecdsa.verify(keyPair.public, swapped, sig))
    }

    @Test
    fun `contract constants are stable`() {
        // 契约常量变更即协议破坏, 锁定值防意外漂移
        assertEquals("myvault", IpcContract.SCHEME)
        assertEquals("com.vault", IpcContract.VAULT_PACKAGE)
        assertEquals("com.engine", IpcContract.ENGINE_PACKAGE)
        assertEquals("com.vault.permission.VAULT_IPC", IpcContract.VAULT_IPC_PERMISSION)
        assertEquals("com.engine.permission.ENGINE_CALLBACK", IpcContract.ENGINE_CALLBACK_PERMISSION)
        assertEquals("success", IpcContract.STATUS_SUCCESS)
        assertEquals("fail", IpcContract.STATUS_FAIL)
        assertEquals(120_000L, IpcContract.CALLBACK_TS_TOLERANCE_MS)
    }
}
