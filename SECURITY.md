# Security Policy · [中文版](SECURITY.zh-CN.md)

## Reporting a vulnerability

**Do not report security vulnerabilities via public issues.**

- GitHub private security advisory: repo *Security* tab → *Report a vulnerability*
- Or contact: eneatlnc@gmail.com

Please include: the affected module (E2EE layer / protocol layer / boundary),
reproduction steps or a PoC, and your threat-model assumptions (attacker
position: network / same device / relay operator / malicious peer).

Response-time targets: acknowledgment ≤ 72 h, initial assessment ≤ 7 days.

## Bounty tiers

| Tier | Scope | Examples |
| --- | --- | --- |
| **T1** | Break of the E2EE crypto layer | Decrypting messages without the session key; GCM AAD bypass; offline password-guessing speedup against the backup format |
| **T2** | Protocol-layer attacks | MITM on ECDH signaling; wire-protocol replay taking effect across identities; sequence-number bypass |
| **T3** | Boundary / implementation flaws | Forged IPC callbacks; signature-verification bypass; ECDSA implementation flaws (e.g. nonce reuse) |
| Out of scope | Attacks requiring physical access to an unlocked device; server availability; social engineering; issues affecting only closed-source parts with no involvement of code in this repository | — |

## Audit navigation

| Concern | Start here |
| --- | --- |
| AES-GCM envelope & AAD binding | `core/core-crypto/src/main/kotlin/com/securesocial/core/crypto/AesGcmCipher.kt` |
| ECDSA sign / verify | `EcdsaOperations.kt` |
| ECDH session key agreement | `EcdhKeyAgreement.kt` |
| Relay challenge–response | `SignalAuth.kt` |
| Message envelope & replay defense | `core/core-protocol/.../MessageEnvelope.kt` |
| Callback signature contract | `core/core-ipc/.../IpcContract.kt` |
| Backup container format | `BackupFormat.kt` |

Every module ships with tests (`src/test/`); `./gradlew test` reproduces
them locally (10 suites / 147 test cases).

## Safe Harbor

Good-faith research that follows this policy is not considered unauthorized
access.
