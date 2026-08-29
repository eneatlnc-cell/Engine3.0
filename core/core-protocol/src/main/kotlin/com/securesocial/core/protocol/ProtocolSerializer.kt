package com.securesocial.core.protocol

import kotlinx.serialization.json.Json
import kotlinx.serialization.encodeToString

/**
 * 协议消息序列化工具
 *
 * 提供消息封皮与 JSON 字符串之间的双向转换。
 * 使用宽松的 JSON 解析配置以兼容不同客户端实现。
 */
object ProtocolSerializer {

    val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = false
        explicitNulls = false
    }

    fun encode(envelope: MessageEnvelope): String {
        return json.encodeToString(envelope)
    }

    fun decode(raw: String): MessageEnvelope? {
        return try {
            json.decodeFromString(MessageEnvelope.serializer(), raw)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * HELLO 注册声明 (v2: 必须携带身份公钥)
     */
    fun encodeHello(fingerprint: String, pubkeyBase64: String): String {
        val envelope = MessageEnvelope(
            type = MessageType.HELLO,
            source = fingerprint,
            payload = json.encodeToString(HelloPayload(fingerprint, pubkeyBase64))
        )
        return encode(envelope)
    }

    /**
     * CHALLENGE 注册挑战 (服务器 → 客户端, v2)
     */
    fun encodeChallenge(fingerprint: String, nonceBase64: String): String {
        val envelope = MessageEnvelope(
            type = MessageType.CHALLENGE,
            target = fingerprint,
            payload = json.encodeToString(ChallengePayload(fingerprint, nonceBase64))
        )
        return encode(envelope)
    }

    /**
     * HELLO_AUTH 挑战应答 (客户端 → 服务器, v2)
     */
    fun encodeHelloAuth(fingerprint: String, signatureBase64: String): String {
        val envelope = MessageEnvelope(
            type = MessageType.HELLO_AUTH,
            source = fingerprint,
            payload = json.encodeToString(HelloAuthPayload(fingerprint, signatureBase64))
        )
        return encode(envelope)
    }

    fun encodeMsg(source: String, target: String, payload: String, seq: Long): String {
        return encode(MessageEnvelope(
            type = MessageType.MSG,
            source = source,
            target = target,
            payload = payload,
            seq = seq
        ))
    }

    /**
     * SIGNAL 密钥交换信令 (v2: 携带 ECDH 公钥 + 身份公钥 + 签名)
     */
    fun encodeSignal(source: String, target: String, signal: SignalPayload): String {
        return encode(MessageEnvelope(
            type = MessageType.SIGNAL,
            source = source,
            target = target,
            payload = json.encodeToString(signal)
        ))
    }

    /**
     * 解析 SIGNAL 载荷 (v2)
     */
    fun decodeSignalPayload(payload: String): SignalPayload? {
        return try {
            json.decodeFromString(SignalPayload.serializer(), payload)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * 解析 HELLO 载荷 (v2)
     */
    fun decodeHelloPayload(payload: String): HelloPayload? {
        return try {
            json.decodeFromString(HelloPayload.serializer(), payload)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * 解析 CHALLENGE 载荷 (v2)
     */
    fun decodeChallengePayload(payload: String): ChallengePayload? {
        return try {
            json.decodeFromString(ChallengePayload.serializer(), payload)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * 解析 HELLO_AUTH 载荷 (v2)
     */
    fun decodeHelloAuthPayload(payload: String): HelloAuthPayload? {
        return try {
            json.decodeFromString(HelloAuthPayload.serializer(), payload)
        } catch (e: Exception) {
            null
        }
    }

    fun encodePing(seq: Long): String {
        return encode(MessageEnvelope(
            type = MessageType.PING,
            seq = seq
        ))
    }

    fun encodePong(seq: Long): String {
        return encode(MessageEnvelope(
            type = MessageType.PONG,
            seq = seq
        ))
    }

    fun encodeError(code: String, message: String, target: String? = null): String {
        val envelope = MessageEnvelope(
            type = MessageType.ERROR,
            payload = json.encodeToString(ErrorPayload(code, message, target))
        )
        return encode(envelope)
    }

    // ==================== v3.14: 群组目录服务 ====================

    /**
     * ROOM_REGISTER - 群主登记邀请码 (客户端 → 中继)
     */
    fun encodeRoomRegister(fingerprint: String, code: String): String {
        return encode(MessageEnvelope(
            type = MessageType.ROOM_REGISTER,
            source = fingerprint,
            payload = json.encodeToString(RoomRegisterPayload(code, fingerprint))
        ))
    }

    /**
     * ROOM_LOOKUP - 凭邀请码查询群主指纹 (客户端 → 中继)
     */
    fun encodeRoomLookup(fingerprint: String, code: String): String {
        return encode(MessageEnvelope(
            type = MessageType.ROOM_LOOKUP,
            source = fingerprint,
            payload = json.encodeToString(RoomLookupPayload(code))
        ))
    }

    /**
     * ROOM_INFO - 中继统一应答 (中继 → 客户端)
     */
    fun encodeRoomInfo(target: String, info: RoomInfoPayload): String {
        return encode(MessageEnvelope(
            type = MessageType.ROOM_INFO,
            target = target,
            payload = json.encodeToString(info)
        ))
    }

    fun decodeRoomRegisterPayload(payload: String): RoomRegisterPayload? = try {
        json.decodeFromString(RoomRegisterPayload.serializer(), payload)
    } catch (e: Exception) { null }

    fun decodeRoomLookupPayload(payload: String): RoomLookupPayload? = try {
        json.decodeFromString(RoomLookupPayload.serializer(), payload)
    } catch (e: Exception) { null }

    fun decodeRoomInfoPayload(payload: String): RoomInfoPayload? = try {
        json.decodeFromString(RoomInfoPayload.serializer(), payload)
    } catch (e: Exception) { null }

    // ==================== v3.45: 领金日去重 ====================

    /**
     * GRANT_CHECK - 领金前置核验 (客户端 → 中继)
     *
     * h = SHA-256("spark-grant-dedupe/1" ‖ day ‖ deviceSeed) 前 16 hex。
     * deviceSeed 为设备本地派生 (TEE/DRM 种子, 跨卸载稳定) —— 中继只见
     * 不可链接哈希: 不同日的 h 互不可关联, 中继无法跨日追踪同一设备。
     */
    fun encodeGrantCheck(fingerprint: String, h: String, day: String, seq: Long): String {
        return encode(MessageEnvelope(
            type = MessageType.GRANT_CHECK,
            source = fingerprint,
            payload = json.encodeToString(GrantCheckPayload(h, day)),
            seq = seq
        ))
    }

    /** GRANT_ACK - 中继应答 (allowed=false = 该 (day,h) 当日已领取) */
    fun encodeGrantAck(target: String, allowed: Boolean, day: String): String {
        return encode(MessageEnvelope(
            type = MessageType.GRANT_ACK,
            target = target,
            payload = json.encodeToString(GrantAckPayload(allowed, day))
        ))
    }

    fun decodeGrantCheckPayload(payload: String): GrantCheckPayload? = try {
        json.decodeFromString(GrantCheckPayload.serializer(), payload)
    } catch (e: Exception) { null }

    fun decodeGrantAckPayload(payload: String): GrantAckPayload? = try {
        json.decodeFromString(GrantAckPayload.serializer(), payload)
    } catch (e: Exception) { null }

    // ==================== v3.14: 群组消息与控制 ====================

    /**
     * GROUP_MSG - 群聊消息 (发送方 → 每位成员各一封, 群密钥密文)
     *
     * payload 为同一份群密钥密文 (AAD 绑定 gid+发送者+seq, 与接收者无关),
     * 因此扇出 N 人只需加密一次。
     */
    fun encodeGroupMsg(
        source: String,
        target: String,
        groupId: String,
        payload: String,
        seq: Long
    ): String {
        return encode(MessageEnvelope(
            type = MessageType.GROUP_MSG,
            source = source,
            target = target,
            payload = payload,
            seq = seq,
            groupId = groupId
        ))
    }

    /**
     * GROUP_CTRL - 群控制信令 (1:1 会话密钥密文, 中继同 MSG 透传)
     */
    fun encodeGroupCtrl(
        source: String,
        target: String,
        groupId: String?,
        payload: String,
        seq: Long
    ): String {
        return encode(MessageEnvelope(
            type = MessageType.GROUP_CTRL,
            source = source,
            target = target,
            payload = payload,
            seq = seq,
            groupId = groupId
        ))
    }

    /**
     * GROUP_MSG 扇出变体 (v3.18): 单帧上行, 无 target。
     *
     * 中继收到 target=null 的 GROUP_MSG → 向该 groupId 的订阅集扇出
     * (订阅集为空回 GROUP_NO_SUBSCRIBERS); 旧版中继 (不识别) 会静默丢弃,
     * 部署顺序须先升中继再发客户端。
     */
    fun encodeGroupMsgFanout(
        source: String,
        groupId: String,
        payload: String,
        seq: Long
    ): String {
        return encode(MessageEnvelope(
            type = MessageType.GROUP_MSG,
            source = source,
            payload = payload,
            seq = seq,
            groupId = groupId
        ))
    }

    /**
     * GROUP_SUBSCRIBE - 订阅群扇出 (v3.18, 客户端 → 中继)
     *
     * groupId 为不可猜测 UUID, 仅经 E2E 密钥分发通道扩散:
     * 能订阅即持有群秘密, 订阅本身即鉴权 (中继不验证成员身份,
     * 非成员订阅者拿到的只是无法解密的密文)。幂等, 重连后重发。
     */
    fun encodeGroupSubscribe(source: String, groupId: String): String {
        return encode(MessageEnvelope(
            type = MessageType.GROUP_SUBSCRIBE,
            source = source,
            groupId = groupId
        ))
    }

    /**
     * GROUP_FANOUT - 群密钥控制帧扇出 (v3.18)
     *
     * payload 为 GroupCtrlPayload JSON 的群密钥密文 (AAD 绑定 gid+source+seq),
     * 当前承载 PRESENCE 心跳; 中继同 GROUP_MSG 透传给订阅集 (排除发送者)。
     */
    fun encodeGroupFanout(
        source: String,
        groupId: String,
        payload: String,
        seq: Long
    ): String {
        return encode(MessageEnvelope(
            type = MessageType.GROUP_FANOUT,
            source = source,
            payload = payload,
            seq = seq,
            groupId = groupId
        ))
    }

    /**
     * 解析 GROUP_CTRL 明文 (解密后调用)
     */
    fun decodeGroupCtrlPayload(payload: String): GroupCtrlPayload? = try {
        json.decodeFromString(GroupCtrlPayload.serializer(), payload)
    } catch (e: Exception) { null }

    /**
     * GROUP_CTRL 明文序列化 (加密前调用)
     */
    fun encodeGroupCtrlJson(ctrl: GroupCtrlPayload): String =
        json.encodeToString(GroupCtrlPayload.serializer(), ctrl)
}
