package com.securesocial.core.crypto

/**
 * SIGNAL 信令签名规范 (v2)
 *
 * ECDH 公钥交换信令必须携带身份私钥签名, 接收端验签后才采纳 ——
 * 这是 v2 防 MITM 的核心: 攻击者无法冒充他人身份发送伪造 ECDH 公钥。
 *
 * 签名内容 (域分隔 ‖ 发送方指纹 ‖ 接收方指纹 ‖ ECDH 公钥):
 *   "SIGNAL-V1" ‖ senderFp ‖ receiverFp ‖ ecdhPub
 *
 * 绑定接收方指纹: 防止截获信令后向第三方重放 (定向信令)。
 */
object SignalAuth {

    /** 签名域分隔符 */
    const val DOMAIN = "SIGNAL-V1"

    /**
     * 构建签名内容
     *
     * @param ecdhPub  本方 ECDH 公钥 (X.509 编码字节)
     * @param senderFp   发送方身份指纹 (签名者)
     * @param receiverFp 接收方身份指纹 (信令目标)
     */
    fun signingContent(ecdhPub: ByteArray, senderFp: String, receiverFp: String): ByteArray {
        return (DOMAIN + senderFp + receiverFp).toByteArray(Charsets.UTF_8) + ecdhPub
    }
}
