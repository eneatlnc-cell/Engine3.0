# Engine 3.0 — E2EE Protocol Stack (Public Audit Edition)

[中文](./README.zh-CN.md)

> The end-to-end encryption protocol stack of the Engine messaging product, published for public audit. The product clients and infrastructure remain closed-source; the crypto layer is open, because **closed-source cryptography is meaningless — verifiability is where security comes from** (the Signal model).

| | |
|---|---|
| License | **AGPL-3.0** |
| Snapshot | **v3.82.0-audit** |
| Language | Kotlin (pure JVM) + one Android contract module |
| Build | JDK 17; Android SDK (platform 34) required for `core-ipc` only |
| Tests | `./gradlew test` → **10 suites / 164 assertions, all green** |

## What's in this repo

| Module | Contents | Tests |
|---|---|---|
| `core/core-crypto` | AES-256-GCM envelopes (IV bound into AAD, three-way binding) · P-256 ECDSA sign/verify · ECDH key agreement · SHA-256 key fingerprints · relay challenge–response (SignalAuth) · **zero-export identity keys** (v3.72+: `identityinit`/`identityrotate` — generated and rotated inside the TEE, never exportable; the client only ever sees public keys; `KeyPayloadSerializer` retains import compatibility for legacy migration code only) · local backup container format (PBKDF2 + AES-GCM) · double-spend probe (v3.74 `DupProbe` — irreversible, unlinkable blinded fingerprints) · identity-rotation statements (v3.73) · sub-identity credentials (v3.76, derived from the main DID) | 7 suites |
| `core/core-protocol` | message-envelope wire protocol (AAD binds both fingerprints + sequence number → anti-replay) · protocol serialization · SPARK ledger protocol (SPARK-V1 signed HTTP content, metering constants, error codes and request models) · daily fuel-subsidy dedupe frames (v3.45: `GRANT_CHECK`/`GRANT_ACK` — unlinkable per-day device hashes) · offline delivery queue (v3.53 `MSG_ACK`/`QUEUE_FULL`) · group-message offline backlog (v3.56) · message wall (v3.56–v3.81: cards/messages/view counts/pagination) · double-spend claims (v3.74 `DUP_CLAIM`/`DUP_CLAIM_RESULT`, three-state) | 1 suite |
| `core/core-ipc` | Engine↔Vault signed-callback contract (callback signature rules, error codes, anti-tampering; wallet key init / transaction signing / total-amount sufficiency checks / ledger reconciliation summary / full-chain pull (`full=1`) / daily fuel idempotence marker / handover-acceptance request contract) · v3.40 Binder direct channel (byte-identical transaction descriptors, signature-permission-protected binding, callback registry, automatic fallback to the legacy activity-hop channel) · v3.51 silent signing entry · v3.72 authoritative ledger restore (`walletrestore`) · v3.76 identity key init and rotation (`identityinit`/`identityrotate`) | 1 suite |
| `core/core-wallet` | local signed ledger: transaction model and canonical serialization · domain-separated signing (SPARK-WALLET-TX-V1) · append-only hash chain · single spendable-balance derivation (total; v3.39 merged the dual accounts — legacy chains still derive custody/margin components) · full-chain verification (detects replay, rollback, broken chains) · wallet handover protocol (HANDOVER terminal transaction + handover certificate + GENESIS acceptance on the new device) · incremental verification (v3.59 — eliminates O(n²) full-chain re-verification) · concurrency atomicity (B-1 mutex) · source attribution (v3.49 `source` audit column) | 1 suite |

## Build and test

```bash
./gradlew test
```

`core-ipc` is the only Android-dependent module (it is a contract module built on `Intent`/`Uri`); everything else is pure JVM.

## Security model at a glance

- **Zero-knowledge server** — the relay sees only ciphertext and fingerprint prefixes; replacing or compromising it yields no plaintext.
- **Private keys never leave the device** — identity keys are generated and used inside a hardware keystore (Android Keystore/TEE); every operation in this stack touches public keys only.
- **Per-session forward secrecy** — ephemeral ECDH; key exchange is identity-signed to stop MITM substitution.
- **Zero message persistence** — clients do not store chat messages (data minimization on top of E2EE).
- **Local backup** — password-derived keys (PBKDF2-HMAC-SHA256, 350k iterations) + AES-256-GCM; the file header is bound into AAD against tampering.
- **Local wallet** — the balance is a *derived* value, not a stored number: an append-only, domain-separated signed transaction history where tampering, deletion, or reordering of any record breaks the hash chain and is caught by full-chain verification. The balance never touches a server, never enters a backup file.
- **Single spendable balance (v3.39)** — custody/margin accounts merged into one total; sufficiency checks and balance derivation always use the total, enforced by the keystore-side authoritative ledger (prevents blind-signing and overspending). Legacy dual-account transfers net to zero against the total, so no existing signed chain breaks on upgrade; a high-water sequence number blocks old-backup replays.
- **Authoritative full reconciliation (v3.39)** — `full=1` full-chain pull rebuilds a local mirror from the authoritative ledger after reinstall or fork, ending rejection loops caused by sequence desync.
- **Daily fuel-subsidy idempotence (v3.39)** — issuance follows the authoritative ledger; the reconciliation response carries the day's GRANT idempotence marker, so reinstalling the client cannot double-claim.
- **Wallet handover (v3.38)** — device migration with zero private-key copies: the old key signs a HANDOVER terminal transaction transferring the full balance (v3.39+: the total; the old chain can sign nothing afterward); the new device verifies the handover certificate and accepts via GENESIS. The certificate binds the new public key inside the old key's signature — no substitution.
- **Binder IPC direct channel (v3.40)** — Engine↔Vault communication upgraded from cross-app activity hops to a signature-permission-protected Binder channel (some ROMs show a confirmation dialog on every cross-app hop — twice per signing round on the old channel). The cryptographic contract is unchanged (callback signatures, result inside the signature scope); only the transport changed. The legacy channel remains as automatic fallback, so both apps can upgrade independently.
- **Daily dedupe (v3.45)** — subsidy anti-abuse without any account system: before claiming, the client sends `GRANT_CHECK(h, day)` over an authenticated connection, where `h = SHA-256("spark-grant-dedupe/1" ‖ day ‖ deviceSeed)` is an **unlinkable** per-day device hash (days cannot be correlated with each other; the relay cannot track a device across days). The relay atomically checks-and-occupies the day's set and answers `GRANT_ACK(allowed)`. The device seed prefers a TEE/DRM-derived value (stable across reinstalls of the same package name); after local memory is wiped, the relay is the only external memory that an uninstall cannot kill. Defense in depth: amount whitelist (`WalletGrant.DAILY_GRANT_AMOUNT`) and a "memo must equal the signing side's current day" gate (clock-skew sealing).
- **Deployment boundary (v3.45.4)** — the relay's dedupe set is in-process memory; anti-abuse assumes **single-instance deployment** — multiple instances require `h`-sharded routing first (design finalized in [ARCHITECTURE.md](ARCHITECTURE.md)); scale vertically before considering instances.

Full architecture and trust-domain breakdown: [ARCHITECTURE.md](ARCHITECTURE.md).

## What is NOT here (and why)

| Excluded | Reason |
|---|---|
| Android clients / key-vault app | product implementations, closed-source |
| relay-server | commercial private deployment deliverable; the relay is **stateless** (forwards ciphertext only, stores no user data), so its security does not depend on source secrecy |
| server-side ledger design | undisclosed commercial design |
| deployment/ops documentation | internal assets |

## Delivery form

This repository targets protocol audit: it contains the protocol stack source and tests only, no deployment materials — the operations of security infrastructure cannot be condensed into a single install command. The product ships as cloud apps and commercial private deployments; building and running it yourself under AGPL-3.0 is outside product support scope.

## Reporting vulnerabilities

**Do not report security issues via public GitHub issues.** Use the private channel; process and bounty tiers are in [SECURITY.md](SECURITY.md). Breaks of the E2EE cryptographic layer (T1) receive the highest severity.

## Disclaimer

This repository is provided as-is; it is not a production-readiness promise and carries no warranty.
