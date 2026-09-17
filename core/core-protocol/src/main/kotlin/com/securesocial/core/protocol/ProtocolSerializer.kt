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

    fun encodeMsg(source: String, target: String, payload: String, seq: Long, ring: Int = 0): String {
        return encode(MessageEnvelope(
            type = MessageType.MSG,
            source = source,
            target = target,
            payload = payload,
            seq = seq,
            ring = ring
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

    // ==================== v3.74: 双花探针认领 (DUP_CLAIM) ====================

    /**
     * DUP_CLAIM - 序号认领 (客户端 → 中继, 独立不认证端点)。
     *
     * **不携带 source 指纹** —— 见 [DupClaimPayload] 头注的隐私契约:
     * 认证头会让中继把 probe 绑定到身份, 盲化收益归零。
     */
    fun encodeDupClaim(probe: String, id: String, seq: Long = 0L): String {
        return encode(MessageEnvelope(
            type = MessageType.DUP_CLAIM,
            payload = json.encodeToString(DupClaimPayload(probe, id)),
            seq = seq
        ))
    }

    /**
     * DUP_CLAIM_RESULT - 中继应答 (三态, v3.74.1):
     * granted=true 首次认领 / false 已被认领 (疑似双花) / null 服务暂不可用
     * (存储故障; 客户端按"结果未知"宽松降级 —— 中继故障时绝不放行也绝不谎报)。
     * granted=null 时该字段不上线 (explicitNulls=false), 线格式为字段缺省。
     */
    fun encodeDupClaimResult(probe: String, granted: Boolean?, id: String): String {
        return encode(MessageEnvelope(
            type = MessageType.DUP_CLAIM_RESULT,
            payload = json.encodeToString(DupClaimResultPayload(probe, granted, id))
        ))
    }

    fun decodeDupClaimPayload(payload: String): DupClaimPayload? = try {
        json.decodeFromString(DupClaimPayload.serializer(), payload)
    } catch (e: Exception) { null }

    fun decodeDupClaimResultPayload(payload: String): DupClaimResultPayload? = try {
        json.decodeFromString(DupClaimResultPayload.serializer(), payload)
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
        seq: Long,
        ring: Int = 0
    ): String {
        return encode(MessageEnvelope(
            type = MessageType.GROUP_MSG,
            source = source,
            target = target,
            payload = payload,
            seq = seq,
            groupId = groupId,
            ring = ring
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

    // ==================== v3.53: 离线投递回执 ====================

    /**
     * MSG_ACK - 中继对 MSG/GROUP_MSG 发送方的投递回执 (中继 → 发送方)
     *
     * status: MsgAckStatus.QUEUED (目标离线已入队) /
     *         MsgAckStatus.DELIVERED (已投递) /
     *         MsgAckStatus.REJECTED (被拒)
     */
    fun encodeMsgAck(target: String, ack: MsgAckPayload): String {
        return encode(MessageEnvelope(
            type = MessageType.MSG_ACK,
            target = target,
            payload = json.encodeToString(ack)
        ))
    }

    /**
     * MSG_ACK (端到端回执, v3.66) - 接收方 B → 中继 → 原发送方 A
     *
     * 与 [encodeMsgAck] (中继合成, 无 source) 的区别: 本信封由**接收方客户端**
     * 发出 —— envelope.source = B (中继据此校验身份), envelope.target = A
     * (原发送方, 中继据此路由), payload.seq = 被确认消息的原始 seq,
     * payload.target = B (被回执消息的目标, A 端 removeDesyncSend 匹配键)。
     *
     * 语义: 「该帧已真实到达 B 的进程」—— 关闭中继侧「写入 socket 缓冲 =
     * 已送达」的黑洞窗口 (移动网络僵尸连接下, 缓冲写成功 ≠ 对端收到)。
     * 中继收到后: ① 按指纹+seq 冲账冲刷未确认登记; ② 转发给 A, A 离线则
     * 入 A 的离线队列待其上线冲刷 (与中继自产的 DELIVERED 回执同收敛点,
     * A 端 handleMsgAck 幂等)。
     *
     * 仅 status=DELIVERED 一种取值 (客户端只确认收妥, 不产生其他语义)。
     */
    fun encodeE2eMsgAck(source: String, target: String, seq: Long, ackTarget: String): String {
        return encode(MessageEnvelope(
            type = MessageType.MSG_ACK,
            source = source,
            target = target,
            payload = json.encodeToString(
                MsgAckPayload(
                    status = MsgAckStatus.DELIVERED,
                    seq = seq,
                    target = ackTarget,
                    ts = System.currentTimeMillis()
                )
            )
        ))
    }

    /**
     * QUEUE_FULL - 目标离线队列已满, 消息被拒 (中继 → 发送方)
     *
     * 独立信封而非 MSG_ACK(rejected): 客户端可区分「投递失败可重试」
     * 与「中继代管已达上限, 继续发送无意义」, 前者 UI 提示重试,
     * 后者提示等待对端上线清空队列。
     */
    fun encodeQueueFull(target: String, seq: Long, queueTarget: String): String {
        return encode(MessageEnvelope(
            type = MessageType.QUEUE_FULL,
            target = target,
            seq = seq,
            payload = json.encodeToString(
                MsgAckPayload(
                    status = MsgAckStatus.REJECTED,
                    seq = seq,
                    target = queueTarget,
                    ts = System.currentTimeMillis()
                )
            )
        ))
    }

    fun decodeMsgAckPayload(payload: String): MsgAckPayload? = try {
        json.decodeFromString(MsgAckPayload.serializer(), payload)
    } catch (e: Exception) { null }

    // ==================== v3.56: 涂鸦墙 ====================

    /**
     * GRAFFITI_POST - 发布涂鸦留言卡 (客户端 → 中继)
     *
     * payload 为 GraffitiCardPayload 明文 JSON (公开内容不加密);
     * 中继校验 author == source、词元 ≤ 300、节奏护栏后入墙,
     * 并向订阅集广播 GRAFFITI_CARD (含作者本人 —— 回显即受理回执,
     * 客户端「确认后扣费」的锚点, 与 MSG_ACK 计费契约同构)。
     */
    fun encodeGraffitiPost(card: GraffitiCardPayload): String {
        return encode(MessageEnvelope(
            type = MessageType.GRAFFITI_POST,
            source = card.author,
            payload = json.encodeToString(card)
        ))
    }

    /**
     * GRAFFITI_SUBSCRIBE - 订阅涂鸦墙 (客户端 → 中继)
     *
     * 幂等: 打开涂鸦页/重连后各发一次即可。订阅语义:
     * · 入实时广播集 (会话态, 断开即除名);
     * · 领取当前墙快照 (≤24h 存活卡片, 限速冲刷)。
     */
    fun encodeGraffitiSubscribe(source: String): String {
        return encode(MessageEnvelope(
            type = MessageType.GRAFFITI_SUBSCRIBE,
            source = source
        ))
    }

    /**
     * GRAFFITI_CARD - 涂鸦卡片帧 (中继 → 客户端)
     *
     * 实时广播 / 订阅快照 / 作者回显共用本帧型; 接收端按
     * card.id 幂等去重, 按 card.ts + GRAFFITI_TTL_MS 判过期。
     */
    fun encodeGraffitiCard(card: GraffitiCardPayload): String {
        return encode(MessageEnvelope(
            type = MessageType.GRAFFITI_CARD,
            source = card.author,
            payload = json.encodeToString(card)
        ))
    }

    fun decodeGraffitiCardPayload(payload: String): GraffitiCardPayload? = try {
        json.decodeFromString(GraffitiCardPayload.serializer(), payload)
    } catch (e: Exception) { null }

    // ==================== v3.81: 涂鸦墙留言 / 浏览 / 分页 ====================

    /**
     * GRAFFITI_COMMENT - 卡片留言 (客户端 → 中继)
     *
     * 中继校验链: 卡在墙未过期 → 同卡同指纹限 1 条 → 词元 ≤100 →
     * 全局冷却 10s → author == 认证身份。受理后追加留言并向全部
     * 订阅者广播**更新后的整卡** (含给留言者的回显 —— 客户端
     * 「确认后扣费」10 SPARK 的锚点, 与发帖 100k 同构)。
     */
    fun encodeGraffitiComment(source: String, cardId: String, text: String): String {
        return encode(MessageEnvelope(
            type = MessageType.GRAFFITI_COMMENT,
            source = source,
            payload = json.encodeToString(GraffitiCommentReqPayload(cardId, text))
        ))
    }

    /**
     * GRAFFITI_VIEW - 浏览上报 (客户端 → 中继)
     *
     * 打开卡片详情时发送; 中继按 (卡, 指纹) 去重计数, 更新卡
     * 仅定向回给请求会话 (不广播 —— 浏览数非实时协作语义,
     * 其他人下次打开详情/翻页时自然拿到新值)。
     */
    fun encodeGraffitiView(source: String, cardId: String): String {
        return encode(MessageEnvelope(
            type = MessageType.GRAFFITI_VIEW,
            source = source,
            payload = json.encodeToString(GraffitiViewReqPayload(cardId))
        ))
    }

    /** GRAFFITI_MORE - 快照翻页 (客户端 → 中继: 自 offset 续领一页) */
    fun encodeGraffitiMore(source: String, offset: Int): String {
        return encode(MessageEnvelope(
            type = MessageType.GRAFFITI_MORE,
            source = source,
            payload = json.encodeToString(GraffitiMorePayload(offset))
        ))
    }

    /** GRAFFITI_PAGE_END - 页末标记 (中继 → 客户端, 见载荷头注) */
    fun encodeGraffitiPageEnd(page: GraffitiPageEndPayload): String {
        return encode(MessageEnvelope(
            type = MessageType.GRAFFITI_PAGE_END,
            payload = json.encodeToString(page)
        ))
    }

    fun decodeGraffitiCommentReq(payload: String): GraffitiCommentReqPayload? = try {
        json.decodeFromString(GraffitiCommentReqPayload.serializer(), payload)
    } catch (e: Exception) { null }

    fun decodeGraffitiViewReq(payload: String): GraffitiViewReqPayload? = try {
        json.decodeFromString(GraffitiViewReqPayload.serializer(), payload)
    } catch (e: Exception) { null }

    fun decodeGraffitiMore(payload: String): GraffitiMorePayload? = try {
        json.decodeFromString(GraffitiMorePayload.serializer(), payload)
    } catch (e: Exception) { null }

    fun decodeGraffitiPageEnd(payload: String): GraffitiPageEndPayload? = try {
        json.decodeFromString(GraffitiPageEndPayload.serializer(), payload)
    } catch (e: Exception) { null }
}
