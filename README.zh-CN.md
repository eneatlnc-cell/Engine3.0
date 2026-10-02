# Engine 3.0 — E2EE 协议栈（公开审计版）

> Engine E2EE 通信产品的**协议栈公开审计版**。产品客户端与基础设施
> 闭源，端到端加密层在此开源，接受社区审计——加密闭源没有意义，
> **可验证性才是安全的来源**（Signal 模式）。

**License: AGPL-3.0** · 快照版本: **v3.82.0-audit** · [English version](README.md)

**「公开审计版」的含义**：本仓库面向开放的社区评审而发布。它**尚未**
经过正式的第三方审计——补上这个缺口正是本仓库存在的目的。

**快照策略**：本仓库跟踪产品所用协议栈，可能落后于产品版本（当前同步至 Engine v3.82）。

## 本仓库包含什么

| 模块 | 内容 | 测试 |
| --- | --- | --- |
| `core/core-crypto` | AES-256-GCM 封装（IV 纳入 AAD 三方绑定）、P-256 ECDSA 签名/验签、ECDH 密钥协商、SHA-256 密钥指纹、中继挑战-应答（SignalAuth）、身份密钥零出口（v3.72+：identityinit/identityrotate，TEE 内生成/轮换且不可导出，Engine 只见公钥；`KeyPayloadSerializer` 仅对旧版迁移码保留导入兼容）、本地备份容器格式（PBKDF2 + AES-GCM）、双花探针（v3.74 `DupProbe`，不可逆不可链接盲化指纹）、身份轮换声明（v3.73）、子身份凭证（v3.76 主 DID 派生） | 7 套 |
| `core/core-protocol` | 消息信封线协议（AAD 绑定双方指纹+序列号防重放）、协议序列化、Spark 账本协议（SPARK-V1 HTTP 签名内容、计量常量、错误码与请求模型）、领金日去重帧（v3.45：`GRANT_CHECK`/`GRANT_ACK`，不可链接设备日哈希）、离线投递队列（v3.53 `MSG_ACK`/`QUEUE_FULL`）、群消息离线托管 backlog（v3.56）、涂鸦墙（v3.56~v3.81：卡片/留言/浏览量/分页翻阅）、双花认领（v3.74 `DUP_CLAIM`/`DUP_CLAIM_RESULT` 三态） | 1 套 |
| `core/core-ipc` | Engine↔Vault 签名回调契约（回调签名规则、错误码、防篡改；钱包密钥初始化/交易签名/总额足额校验/账本对账摘要/全链拉取（full=1）/每日赠金幂等标记/交接承接请求契约）、v3.40 Binder 直连通道契约（事务描述符逐字节一致、signature 权限保护绑定、回调注册表、旧 Activity 跳转通道回退）、v3.51 静默签名入口、v3.72 权威账本恢复（walletrestore）、v3.76 身份密钥初始化与轮换（identityinit/identityrotate） | 1 套 |
| `core/core-wallet` | 本地签名账本：交易模型与规范化序列化、域分离签名（SPARK-WALLET-TX-V1）、append-only 哈希链、单一可用余额推导（total，v3.39 合并双账户；旧链 custody/margin 分量仍可推导）、全链验签（重放/回退/断链检出）、钱包交接协议（HANDOVER 终结交易 + 交接证书 + 承接 GENESIS）、增量校验（v3.59，消除整链重验 O(n²)）、并发原子化（B-1 互斥锁）、来源归属（v3.49 `source` 审计展示列） | 1 套 |

构建要求：**JDK 17**；`core-ipc` 是 Android 契约模块（基于 `Intent`/`Uri`），
需 **Android SDK (platform 34)**，其余模块纯 JVM：

    ./gradlew test         # 运行全部 10 套测试 / 147 个用例，预期全绿

纯 JVM 模块（crypto / protocol / wallet）在仅安装 OpenJDK 17、无任何
Android 工具链的环境下同样可构建并通过测试。

## 不包含什么（以及为什么）

| 排除项 | 理由 |
| --- | --- |
| Android 客户端 / 密钥库 App | 产品实现，闭源 |
| 中继服务 relay-server | 商业私有化交付物；且中继**不落任何用户数据**（只转发密文），其安全性不依赖源码保密；残余的进程内存态与部署约束已在 [ARCHITECTURE.md](ARCHITECTURE.md) 中如实说明 |
| 服务端账本设计 | 未部署的商业设计 |
| 部署手册 / 运维文档 | 内部资产 |

## 安全模型速览

- **零知识服务端**：中继只见密文与指纹前缀，换掉/攻破中继得不到任何明文
- **私钥不出设备**：身份私钥由独立的硬件密钥库（Android Keystore/TEE）
  保管，签名在密钥库内完成，本协议栈中的所有操作只接触公钥
- **每会话前向保密**：ECDH 临时密钥协商，公钥交换带身份签名防中间人
- **消息零落盘**：客户端不持久化聊天消息（E2EE 之上再加一层数据最小化）
- **本地备份**：口令派生密钥（PBKDF2-HMAC-SHA256, 350k 迭代）+
  AES-256-GCM，文件头纳入 AAD 防篡改
- **本地钱包**：余额不是存储的数字，而是 append-only 签名交易历史的
  推导值——每笔交易由密钥库内的钱包密钥做域分离签名，篡改/删除/
  重排任何历史记录都会破坏哈希链而被全链验签检出；钱包余额既不
  上服务端，也不进备份文件
- **诚实的边界**：「无消息状态」不等于「无状态」——中继进程内存持有
  三张表（连接注册表、群扇出订阅、领金日去重）。领金去重的防滥用
  效果以**单实例部署**为前提，多实例扩容前必须先实施分片，详见
  [ARCHITECTURE.md](ARCHITECTURE.md)

架构与信任域划分详见 [ARCHITECTURE.md](ARCHITECTURE.md)；按关注点的
审计入口见 [SECURITY.md](SECURITY.md)。

## 漏洞报告

**请勿通过公开 issue 报告安全漏洞。** 请走私密通道，流程与赏金
分级见 [SECURITY.md](SECURITY.md)。E2EE 密码学层破坏（T1）享有
最高等级。

## 免责声明

本仓库按「现状」提供，不构成生产就绪承诺，不含任何担保。
