# Engine 3.0 — E2EE Protocol Stack (Public Audit Edition)

> The open protocol & cryptography layer of the Engine E2EE messaging products.
> Product clients and infrastructure are closed-source; the end-to-end encryption
> layer is published here for public audit — closed-source cryptography is
> meaningless, **verifiability is where security comes from** (the Signal model).

**License: AGPL-3.0** · Snapshot: **v3.82.0-audit** · [中文文档](README.zh-CN.md)

**What "public audit edition" means:** this repository is published for open,
community-driven review. It has **not** undergone a formal third-party audit —
closing that gap is exactly what this repo is for.

**Snapshot policy:** this repo tracks the protocol layer of the shipping
products and may lag the product version (currently synced to Engine v3.82).

## What's in this repository

| Module | Contents | Tests |
| --- | --- | --- |
| `core/core-crypto` | AES-256-GCM envelope (IV bound into AAD, three-way binding), P-256 ECDSA sign/verify, ECDH key agreement, SHA-256 key fingerprints, relay challenge–response (SignalAuth), zero-export identity keys (v3.72+: `identityinit`/`identityrotate` — generated and rotated inside the TEE, not exportable; Engine only ever sees public keys; `KeyPayloadSerializer` retains import-compatibility only for legacy migration codes), local backup container format (PBKDF2 + AES-GCM), double-spend probe (v3.74 `DupProbe`, irreversible & unlinkable blinded fingerprint), identity-rotation statements (v3.73), sub-identity credentials (v3.76, derived from a master DID) | 7 suites |
| `core/core-protocol` | Message-envelope wire protocol (AAD binds both fingerprints + sequence number, preventing cross-session / cross-identity replay), protocol serialization, SPARK billing protocol (SPARK-V1 HTTP-signed content, metering constants, error codes, request models), daily-grant dedup frames (v3.45: `GRANT_CHECK`/`GRANT_ACK`, unlinkable per-day device hashes), offline delivery queue (v3.53 `MSG_ACK`/`QUEUE_FULL`), group-message backlog custody (v3.56), graffiti wall (v3.56–v3.81: cards / messages / view counts / paging), double-spend claims (v3.74 `DUP_CLAIM`/`DUP_CLAIM_RESULT`, three-state) | 1 suite |
| `core/core-ipc` | Engine↔Vault signing-callback contract (callback signature rules, error codes, tamper-proofing; wallet key init / transaction signing / sufficiency checks / ledger reconciliation digest / full-chain pull (`full=1`) / daily-grant idempotence marker / handover acceptance contract), v3.40 Binder direct-channel contract (byte-exact transaction descriptors, signature-permission-protected binding, callback registry, legacy Activity-channel fallback), v3.51 silent-signing entry, v3.72 authoritative ledger restore (`walletrestore`), v3.76 identity key init & rotation | 1 suite |
| `core/core-wallet` | Local signed ledger: transaction model & canonical serialization, domain-separated signatures (`SPARK-WALLET-TX-V1`), append-only hash chain, single available-balance derivation (v3.39 merged the dual custody/margin accounts into `total`), full-chain verification (replay / rollback / chain-break detection), wallet handover protocol (HANDOVER terminal tx + handover certificate + GENESIS acceptance), incremental verification (v3.59, removes O(n²) full-chain re-verification), concurrency atomization (B-1 mutex), source attribution (v3.49) | 1 suite |

## Build & verify

Requirements: **JDK 17**. `core-ipc` is an Android contract module
(Intent/Uri-based) and additionally needs the **Android SDK (platform 34)**;
the other three modules are pure JVM:

```bash
./gradlew test    # 10 suites / 147 test cases — expected: all green
```

The pure-JVM modules (crypto / protocol / wallet) also build and test green
on a stock OpenJDK 17 without any Android tooling.

## What is NOT here (and why)

| Excluded | Reason |
| --- | --- |
| Android clients / key-vault app | Product implementations, closed-source |
| Relay server (`relay-server`) | Commercial private-deployment deliverable; the relay keeps **no user data at rest** (it forwards ciphertext only), so its security does not depend on source secrecy. Residual in-memory state and its deployment constraints are documented honestly in [ARCHITECTURE.md](ARCHITECTURE.md) |
| Server-side ledger design | Undeployed commercial design |
| Deployment / ops documentation | Internal assets |

## Security model at a glance

- **Zero-knowledge server**: the relay sees only ciphertext and fingerprint
  prefixes; replacing or compromising it yields no plaintext
- **Private keys never leave the device**: identity keys are held by a
  dedicated hardware key vault (Android Keystore/TEE); signing happens inside
  the vault, and every operation in this stack touches public keys only
- **Per-session forward secrecy**: ECDH ephemeral key agreement; the public-key
  exchange is identity-signed against MITM
- **Zero message persistence**: clients never write chat messages to disk
  (data minimization on top of E2EE)
- **Local backups**: password-derived keys (PBKDF2-HMAC-SHA256, 350k
  iterations) + AES-256-GCM, cleartext header bound into AAD against tampering
- **Local wallet**: balances are not stored numbers but derivations over an
  append-only signed transaction history — every transaction is signed inside
  the key vault with domain separation; tampering, deletion or reordering
  breaks the hash chain and is caught by full-chain verification. Balances
  never go to the server and never enter backup files
- **Honest limits**: "no message state" is not "no state" — the relay process
  holds three in-memory tables (connection registry, group fan-out
  subscriptions, daily-grant dedupe). The dedupe table's anti-abuse guarantee
  assumes **single-instance deployment**; see
  [ARCHITECTURE.md](ARCHITECTURE.md) for the sharding design that must be
  implemented before any multi-instance scale-out

Full trust-domain partitioning: [ARCHITECTURE.md](ARCHITECTURE.md).
Audit starting points per concern: [SECURITY.md](SECURITY.md).

## Reporting vulnerabilities

**Do not report security vulnerabilities via public issues.** Use the private
channel described in [SECURITY.md](SECURITY.md). Breaks of the E2EE crypto
layer (T1) carry the highest bounty tier.

## Disclaimer

This repository is provided as-is. It is not a production-readiness
commitment and carries no warranty.
