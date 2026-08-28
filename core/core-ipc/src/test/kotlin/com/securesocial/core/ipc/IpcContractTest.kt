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

    // ---- v3.38: 钱包双账户 + 交接契约 ----

    @Test
    fun `v338 wallet hosts are stable`() {
        assertEquals("walletinit", IpcContract.HOST_WALLET_INIT)
        assertEquals("signtx", IpcContract.HOST_SIGN_TX)
        assertEquals("walletstate", IpcContract.HOST_WALLET_STATE)
        assertEquals("deposit", IpcContract.HOST_DEPOSIT)
        assertEquals("walletadopt", IpcContract.HOST_WALLET_ADOPT)
        assertEquals("walletsync", IpcContract.HOST_WALLET_SYNC)
    }

    @Test
    fun `v338 error codes round-trip`() {
        // 新错误码: 值稳定 + fromCode 反查闭环 (Engine 侧错误分流依赖)
        val pairs = listOf(
            IpcErrorCode.INSUFFICIENT_MARGIN to "INSUFFICIENT_MARGIN",
            IpcErrorCode.INSUFFICIENT_CUSTODY to "INSUFFICIENT_CUSTODY",
            IpcErrorCode.WALLET_TERMINAL to "WALLET_TERMINAL",
            IpcErrorCode.WALLET_ALREADY_INITIALIZED to "WALLET_ALREADY_INITIALIZED",
            IpcErrorCode.HANDOVER_CERT_INVALID to "HANDOVER_CERT_INVALID",
        )
        for ((code, raw) in pairs) {
            assertEquals(raw, code.code)
            assertEquals("fromCode($raw) 必须闭环", code, IpcErrorCode.fromCode(raw))
            assertTrue("错误描述必须面向用户", code.description.isNotEmpty())
        }
    }

    @Test
    fun `walletstate payload round-trips`() {
        // 对账摘要编解码闭环: 余额/高水位/尾哈希/终结态不丢字段
        val state = IpcWalletState(
            initialized = true,
            custody = 600L,
            margin = 3850L,
            highWaterSeq = 4L,
            tipHash = "a1b2c3d4e5f6",
            terminal = false,
            txCount = 4L,
        )
        val decoded = IpcWalletState.decode(IpcWalletState.encode(state))
        assertEquals(state, decoded)

        // v3.38 镜像追赶: 尾交易 JSON 一并往返 (Engine 丢回调后拉取续链)
        val tip = com.securesocial.core.wallet.WalletTx(
            seq = 4L, type = com.securesocial.core.wallet.TxType.SPEND, amount = 30L,
            counterparty = null, memo = "msg×3", timestamp = 1L,
            prevTxHash = "h3", signature = "sig",
        )
        val withTip = state.copy(
            tipTxJson = com.securesocial.core.wallet.TxJsonCodec.encode(tip),
        )
        val decodedTip = IpcWalletState.decode(IpcWalletState.encode(withTip))!!
        assertEquals(withTip, decodedTip)
        assertEquals(tip, com.securesocial.core.wallet.TxJsonCodec.decode(decodedTip.tipTxJson!!))
    }

    @Test
    fun `walletstate defaults for uninitialized wallet`() {
        // 未初始化: 其余字段全默认 (Engine 据此引导 walletinit)
        val decoded = IpcWalletState.decode(IpcWalletState.encode(IpcWalletState(initialized = false)))!!
        assertEquals(false, decoded.initialized)
        assertEquals(0L, decoded.custody)
        assertEquals(0L, decoded.margin)
        assertEquals(0L, decoded.highWaterSeq)
        assertEquals("", decoded.tipHash)
        assertEquals(false, decoded.terminal)
    }

    @Test
    fun `walletstate rejects malformed payload`() {
        assertEquals(null, IpcWalletState.decode("not-json"))
        assertEquals(null, IpcWalletState.decode("{}")) // initialized 必填
    }

    @Test
    fun `deposit gate accepts only deposit tx`() {
        // 语义混淆防护: 充值入口仅接受 DEPOSIT, 其余类型 (含 SPEND) 一律拒
        val deposit = com.securesocial.core.wallet.WalletTx(
            seq = 3L, type = com.securesocial.core.wallet.TxType.DEPOSIT, amount = 400L,
            counterparty = null, memo = "recharge", timestamp = 1L, prevTxHash = "h2", signature = "",
        )
        val parsed = IpcDepositRequest.parseDepositTx(
            com.securesocial.core.wallet.TxJsonCodec.encode(deposit)
        )
        assertEquals(com.securesocial.core.wallet.TxType.DEPOSIT, parsed?.type)

        // 用充值入口提交 SPEND (语义混淆攻击) → 拒
        val spend = deposit.copy(type = com.securesocial.core.wallet.TxType.SPEND)
        assertEquals(
            "非 DEPOSIT 交易走 deposit 入口必须被拒",
            null,
            IpcDepositRequest.parseDepositTx(com.securesocial.core.wallet.TxJsonCodec.encode(spend)),
        )
    }

    @Test
    fun `deposit gate rejects signed and malformed tx`() {
        val signed = com.securesocial.core.wallet.WalletTx(
            seq = 3L, type = com.securesocial.core.wallet.TxType.DEPOSIT, amount = 400L,
            counterparty = null, memo = null, timestamp = 1L, prevTxHash = "h2",
            signature = "already-signed",
        )
        assertEquals(null, IpcDepositRequest.parseDepositTx(com.securesocial.core.wallet.TxJsonCodec.encode(signed)))
        assertEquals(null, IpcDepositRequest.parseDepositTx("garbage"))
        // 非首笔缺前向哈希 → 拒
        val noPrev = com.securesocial.core.wallet.WalletTx(
            seq = 5L, type = com.securesocial.core.wallet.TxType.DEPOSIT, amount = 10L,
            counterparty = null, memo = null, timestamp = 1L, prevTxHash = "", signature = "",
        )
        assertEquals(null, IpcDepositRequest.parseDepositTx(com.securesocial.core.wallet.TxJsonCodec.encode(noPrev)))
    }

    @Test
    fun `adopt gate accepts only signed handover cert`() {
        // 合法结构: HANDOVER 交易 + 已签名
        val handoverTx = com.securesocial.core.wallet.WalletTx(
            seq = 3L, type = com.securesocial.core.wallet.TxType.HANDOVER, amount = 2000L,
            counterparty = "aabb", memo = "handover:2000", timestamp = 1L, prevTxHash = "h2",
            signature = "sig-bytes",
        )
        val cert = com.securesocial.core.wallet.HandoverCertificate(
            oldPubKeyB64 = "b2xk", newPubKeyB64 = "bmV3", handoverTx = handoverTx,
        )
        val parsed = IpcWalletAdoptRequest.parseCert(
            com.securesocial.core.wallet.HandoverCertificate.encode(cert)
        )
        assertEquals(com.securesocial.core.wallet.TxType.HANDOVER, parsed?.handoverTx?.type)

        // 未签名交接交易 → 拒 (结构门禁在确认页之前)
        val unsigned = cert.copy(
            handoverTx = handoverTx.copy(signature = ""),
        )
        assertEquals(null, IpcWalletAdoptRequest.parseCert(com.securesocial.core.wallet.HandoverCertificate.encode(unsigned)))

        // 非 HANDOVER 类型 → 拒
        val wrongType = cert.copy(
            handoverTx = handoverTx.copy(type = com.securesocial.core.wallet.TxType.SPEND),
        )
        assertEquals(null, IpcWalletAdoptRequest.parseCert(com.securesocial.core.wallet.HandoverCertificate.encode(wrongType)))

        assertEquals(null, IpcWalletAdoptRequest.parseCert("garbage"))
    }

    @Test
    fun `sync gate accepts only fully signed chain`() {
        fun signedTx(seq: Long) = com.securesocial.core.wallet.WalletTx(
            seq = seq, type = com.securesocial.core.wallet.TxType.GRANT, amount = 100L,
            counterparty = null, memo = "g$seq", timestamp = seq, prevTxHash = "h${seq - 1}",
            signature = "sig-$seq",
        )

        // 合法播种链: 非空 + 全签名
        val chain = listOf(signedTx(1), signedTx(2), signedTx(3))
        val parsed = IpcWalletSyncRequest.parseChain(
            com.securesocial.core.wallet.TxJsonCodec.encodeList(chain)
        )
        assertEquals(3, parsed?.size)

        // 空链 → 拒 (无播种意义)
        assertEquals(
            null,
            IpcWalletSyncRequest.parseChain(
                com.securesocial.core.wallet.TxJsonCodec.encodeList(emptyList())
            ),
        )
        // 含未签名交易 → 拒 (播种链必须全签名)
        val withUnsigned = listOf(signedTx(1), signedTx(2).copy(signature = ""))
        assertEquals(
            null,
            IpcWalletSyncRequest.parseChain(
                com.securesocial.core.wallet.TxJsonCodec.encodeList(withUnsigned)
            ),
        )
        // 畸形 JSON → 拒
        assertEquals(null, IpcWalletSyncRequest.parseChain("garbage"))
    }
}
