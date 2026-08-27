# 安全政策 / Security Policy

## 报告漏洞

**请勿通过公开 issue 报告安全漏洞。**

- GitHub 私密安全通告：仓库 Security 标签页 → Report a vulnerability
- 或联系：eneatlnc@gmail.com

请包含：影响模块（E2EE 层 / 协议层 / 边界）、复现步骤或 PoC、
威胁模型假设（攻击者位置：网络 / 本机 / 中继运营方 / 恶意对端）。

响应时效目标：确认 ≤ 72 小时，初步评估 ≤ 7 天。

## 赏金分级

| 等级 | 范围 | 例 |
|---|---|---|
| **T1** | E2EE 密码学层破坏 | 不知晓会话密钥解密消息；GCM AAD 绕过；备份格式口令离线暴力加速 |
| **T2** | 协议层攻击 | ECDH 信令中间人；线协议重放跨身份生效；序列号绕过 |
| **T3** | 边界/实现缺陷 | IPC 回调伪造；签名验签绕过；ECDSA 实现缺陷（如 nonce 复用） |
| 不在范围 | 需物理接触且设备已解锁的攻击；服务端可用性；社会工程；仅影响闭源部分且不涉及本仓库代码的问题 | — |

## 审计导航

| 关注点 | 起点 |
|---|---|
| AES-GCM 封装与 AAD 绑定 | `core/core-crypto/src/main/kotlin/com/securesocial/core/crypto/AesGcmCipher.kt` |
| ECDSA 签名 / 验签 | `EcdsaOperations.kt` |
| ECDH 会话密钥协商 | `EcdhKeyAgreement.kt` |
| 中继挑战-应答 | `SignalAuth.kt` |
| 消息信封与防重放 | `core/core-protocol/.../MessageEnvelope.kt` |
| 回调签名契约 | `core/core-ipc/.../IpcContract.kt` |
| 备份容器格式 | `BackupFormat.kt` |

每个模块附测试（`src/test/`），`./gradlew test` 可本地复现。

## Safe Harbor

出于善意、遵循本政策的研究行为，不被视为未授权访问。
