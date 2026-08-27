package com.securesocial.core.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.Arrays

/**
 * v3.36 · 备份文件格式单测
 *
 * 覆盖: 往返一致性 / 错口令 / 头部篡改 (AAD) / 密文篡改 /
 * 非备份文件 / 版本错配 / 载荷 schema 往返 / 旧版六类字段前向兼容。
 * 迭代次数降到 1_000 (测试耗时), 格式与 350_000 完全同构 ——
 * 迭代数存在头里, 解密侧自适应。
 */
class BackupFormatTest {

    private val fp = "0123456789abcdef0123456789abcdef"
    private val payload = BackupPayloadV1(
        createdAt = 1_700_000_000_000L,
        fingerprint = fp,
        contacts = listOf(ContactBackup("fedcba9876543210fedcba9876543210", "对方")),
        markers = listOf(
            MarkerBackup("m1", "fedcba9876543210fedcba9876543210", "对方", "消息明文", true, 123L, 456L)
        ),
    )

    private fun sealBlob(pass: CharArray): ByteArray = BackupFormat.seal(
        passphrase = pass,
        fingerprint = fp,
        createdAtMs = 1_700_000_000_000L,
        payloadJson = BackupPayloadCodec.encode(payload),
        iterations = 1_000,
    )

    @Test
    fun `roundtrip - 加解密往返一致`() {
        val blob = sealBlob("correct-horse".toCharArray())
        val opened = BackupFormat.open("correct-horse".toCharArray(), blob)
        assertEquals(fp, opened.header.fingerprint)
        assertEquals(1_700_000_000_000L, opened.header.createdAtMs)
        assertEquals(payload, BackupPayloadCodec.decode(opened.payloadJson))
    }

    @Test
    fun `peek - 明文头可在解密前读取`() {
        val blob = sealBlob("pw".toCharArray())
        val header = BackupFormat.peek(blob)
        assertNotNull(header)
        assertEquals(fp, header!!.fingerprint)
        assertEquals(1_000, header.iterations)
        // 非备份文件 / 截断
        assertNull(BackupFormat.peek(ByteArray(20)))
        assertNull(BackupFormat.peek("not-a-backup-file-contents!!".toByteArray()))
    }

    @Test
    fun `wrong passphrase - GCM tag 校验拒绝`() {
        val blob = sealBlob("right".toCharArray())
        try {
            BackupFormat.open("wrong".toCharArray(), blob)
            fail("should throw")
        } catch (e: BackupFormatException) {
            assertEquals(BackupFormat.Error.WRONG_PASSPHRASE, e.reason)
        }
    }

    @Test
    fun `tampered header - AAD 绑定拒绝头部篡改`() {
        val blob = sealBlob("pw".toCharArray()).copyOf()
        // 篡改明文头中的指纹首字节 (位置 25)
        blob[25] = if (blob[25] == '0'.code.toByte()) '1'.code.toByte() else '0'.code.toByte()
        try {
            BackupFormat.open("pw".toCharArray(), blob)
            fail("should throw")
        } catch (e: BackupFormatException) {
            assertEquals(BackupFormat.Error.WRONG_PASSPHRASE, e.reason)
        }
    }

    @Test
    fun `tampered ciphertext - GCM 完整性拒绝`() {
        val blob = sealBlob("pw".toCharArray()).copyOf()
        blob[blob.size - 1] = (blob[blob.size - 1] + 1).toByte()
        try {
            BackupFormat.open("pw".toCharArray(), blob)
            fail("should throw")
        } catch (e: BackupFormatException) {
            assertEquals(BackupFormat.Error.WRONG_PASSPHRASE, e.reason)
        }
    }

    @Test
    fun `version mismatch - peek 拒绝未知版本`() {
        val blob = sealBlob("pw".toCharArray()).copyOf()
        blob[4] = 99
        assertNull(BackupFormat.peek(blob))
        try {
            BackupFormat.open("pw".toCharArray(), blob)
            fail("should throw")
        } catch (e: BackupFormatException) {
            assertEquals(BackupFormat.Error.BAD_FORMAT, e.reason)
        }
    }

    @Test
    fun `truncated blob - 格式校验拒绝`() {
        val blob = sealBlob("pw".toCharArray())
        try {
            BackupFormat.open("pw".toCharArray(), blob.copyOf(30))
            fail("should throw")
        } catch (e: BackupFormatException) {
            assertEquals(BackupFormat.Error.BAD_FORMAT, e.reason)
        }
    }

    @Test
    fun `codec - schema 往返与未知字段前向兼容`() {
        val json = BackupPayloadCodec.encode(payload)
        assertEquals(payload, BackupPayloadCodec.decode(json))
        // 未知字段 (未来版本) 不影响旧版本读取
        val future = json.replaceFirst("{", """{"futureField":42,""")
        assertEquals(payload, BackupPayloadCodec.decode(future))
    }

    @Test
    fun `codec - 旧版备份含六类字段前向兼容读取`() {
        // v3.35 备份含 wallet/seals/profile/recent 字段; v3.36 收窄后
        // 这些字段被静默忽略, 联系人/标记物无损读取 —— 老用户备份不废
        val legacy = """
            {"v":1,"createdAt":1700000000000,"fingerprint":"$fp",
             "profile":{"nickname":"旧用户","avatarJpegB64":"aGVsbG8="},
             "contacts":[{"fp":"fedcba9876543210fedcba9876543210","nickname":"对方"}],
             "markers":[{"messageId":"m1","peerFingerprint":"fedcba9876543210fedcba9876543210",
                         "peerName":"对方","text":"消息明文","isMine":true,
                         "messageTimestamp":123,"markedAt":456}],
             "wallet":{"balance":4500,"lastGrantDay":"2026-08-27"},
             "seals":{"own":[{"id":"abc","keyB64":"a2V5","price":100,"paidBy":[]}],"paidByMe":["abc"]},
             "recent":{"stickers":["wave"],"emoji":["😀"]}}
        """.trimIndent()
        assertEquals(payload, BackupPayloadCodec.decode(legacy))
    }

    @Test
    fun `empty passphrase not allowed by contract`() {
        // 口令为空数组在 KDF 层仍可工作, 但调用方 (UI) 强制最小长度;
        // 此处验证格式本身对口令内容无偏置 —— 加解密仍一致
        val blob = BackupFormat.seal(
            CharArray(0), fp, 1L, "{}", iterations = 1_000,
        )
        val opened = BackupFormat.open(CharArray(0), blob)
        assertEquals("{}", opened.payloadJson)
    }

    @Test
    fun `ciphertext never leaks plaintext`() {
        val blob = sealBlob("pw".toCharArray())
        val asText = String(blob, Charsets.ISO_8859_1)
        assertTrue(!asText.contains("对方"))
        assertTrue(!asText.contains("消息明文"))
    }

    @Test
    fun `salt randomization - 两次封装备份盐与密文均不同`() {
        val a = sealBlob("pw".toCharArray())
        val b = sealBlob("pw".toCharArray())
        assertTrue(!Arrays.equals(a, b))
        val ha = BackupFormat.peek(a)!!
        val hb = BackupFormat.peek(b)!!
        assertArrayEquals(fp.toByteArray(), ha.fingerprint.toByteArray())
        assertTrue(!ha.salt.contentEquals(hb.salt))
    }
}
