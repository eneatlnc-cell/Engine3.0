# Architecture Overview · [中文版](ARCHITECTURE.zh-CN.md)

## Component topology (full product; this repository contains only the shaded part)

```
┌───────────────────────── Android device ───────────────────────┐
│  ┌──────────┐   Binder direct channel (v3.40)   ┌──────────┐   │
│  │  Engine   │◄── challenge / sign requests ────│  Vault   │   │
│  │  client   │─── callbacks (Binder + sig) ────►│ key vault│   │
│  │ (closed)  │   [legacy: signature-level IPC]  │ (closed) │   │
│  └────┬─────┘                                   └────┬─────┘   │
│       │ session/group keys (memory only)             │ Keystore/TEE
└───────┼──────────────────────────────────────────────┼─────────┘
        │ TLS + E2EE ciphertext                        │ zero network
        ▼                                              ▼ permission
┌──────────────┐                                        (physical
│ relay server  │  stateless pipe for messages ·        isolation)
└──────────────┘  forwards ciphertext only · closed (commercial)
```

  ▓▓ This repository ▓▓ = core-crypto / core-protocol / core-ipc / core-wallet
  (the protocol stack both clients depend on; byte-identical on both sides)

## Trust-domain partitioning

| Domain | Trust assumption | If compromised |
| --- | --- | --- |
| Vault (incl. TEE) | The only trust anchor | Private key leak = identity forgery |
| Client process memory | Device itself trusted | Session key leak = in-session messages decryptable (cleared on restart) |
| Relay operator | **Zero trust** | Sees only ciphertext + fingerprint prefixes; can neither decrypt nor profile |
| Network | Hostile | TLS against traffic inspection; E2EE against a malicious relay |

## Cryptography stack (entirely in this repository)

| Capability | Construction | Entry point |
| --- | --- | --- |
| Identity | P-256 ECDSA; SHA-256 fingerprint (first 16 B) as node ID | `EcdsaOperations` / `KeyFingerprint` |
| Session key agreement | Per-session ECDH (P-256) + HKDF; public-key exchange identity-signed against MITM | `EcdhKeyAgreement` |
| Message encryption | AES-256-GCM; AAD binds both fingerprints + sequence number (blocks cross-session / cross-identity replay) | `AesGcmCipher` / `MessageEnvelope` |
| Relay authentication | Challenge–response (signed inside Vault); private key never leaves the device | `SignalAuth` |
| Identity key lifecycle | Zero key export (v3.72+): identity keys generated/rotated inside the Vault TEE and not exportable (`identityinit`/`identityrotate`); Engine only ever sees public keys. `KeyPayloadSerializer` keeps an *import-compat* channel only for legacy Vault migration codes (export side removed) | `KeyPayloadSerializer` / `IdentityRotationStatement` / `SubIdentityCredential` |
| Local backup | PBKDF2-HMAC-SHA256 (350k iterations) password-derived key + AES-256-GCM; cleartext header in AAD | `BackupFormat` / `BackupPayload` |
| Cross-app callbacks | Callback signature covers sessionId+status+ts+result — tamper-evident | `IpcContract` |
| Engine↔Vault direct link | v3.40 Binder channel: signature-permission-protected binding (only same-certificate endpoints connect), byte-exact transaction descriptors, callbacks delivered over Binder (no cross-app activity dialogs), automatic fallback to the legacy Activity channel | `VaultIpcBinder` |
| SPARK billing protocol | SPARK-V1 domain-separated HTTP signature (fp‖ts‖nonce‖SHA-256(body)), metering constants (1 KB = 10 SPARK, daily grant 1,000), error codes & request models | `SparkLedger` |
| Local wallet | Append-only signed transaction ledger: canonical serialization (fixed field order), domain-separated signatures (`SPARK-WALLET-TX-V1`, not interchangeable with the identity signature domain), `prevTxHash` chain, balance = derivation over history, full-chain verification (replay/rollback/chain-break detection), incremental verification (v3.59, removes O(n²) re-verification), concurrency atomization (mutex) | `WalletTx` / `WalletLedger` |
| Double-spend defense | v3.74 blinded probe `DupProbe`: SHA256(domain‖SHA256(wallet pubkey)‖u64(seq)), irreversible & unlinkable; claimed via a separate unauthenticated endpoint (three-state granted=true/false/null) | `DupProbe` / `ProtocolSerializer` |
| Identity rotation | v3.73: the retiring sub-identity private key signs an "authorized successor" statement; v3.76: the master DID key signs sub-identity derivation credentials; verifiers check against the master public key | `IdentityRotationStatement` / `SubIdentityCredential` |
| Offline delivery | v3.53 relay offline queue (`MSG_ACK`, three-state queued/delivered/rejected); v3.56 group backlog custody & flush | `MessageEnvelope` / `ProtocolSerializer` |
| Graffiti wall | v3.56–v3.81 public message surface: cards (≤300 tokens, ≤90 KB image), comments (≤100 tokens, one per fingerprint per card), view counts (fingerprint-deduped), paging (`GRAFFITI_PAGE_END/MORE`) | `MessageEnvelope` / `SparkLedger` |

## Data residency (privacy red lines)

| Data | Where it lives |
| --- | --- |
| Chat messages | Memory only, never on disk |
| Contacts / markers | Local only; backups go into a user-held encrypted file (`BackupFormat`) |
| SPARK balance | Local signed ledger only (`core-wallet`): balance = derivation over signed history; never in backup files, never on the server |
| Identity private keys | Key vault only, Keystore-encrypted |
| Server side | No user data of any kind; SPARK billing balances stay off the server (avoids a fingerprint-indexed transaction graph) |

## Deployment topology boundary (an honest note on daily-grant dedupe)

"No message state" does not mean "no state": the relay process holds three
in-memory tables — a connection registry (fingerprint → session), a group
fan-out subscription table, and a daily-grant dedupe table
(day → set of unlinkable hashes). All three are process-memory only and never
touch disk. **The anti-abuse guarantee of the daily-grant dedupe assumes
single-instance deployment**: with naive horizontal scaling, each instance
keeps an independent dedupe memory, and a reinstalled device can poll
instances to claim multiple grants (abuse yield ∝ number of instances).

The finalized sharding design (must be implemented *before* any
multi-instance scale-out): `h` is computed client-side (known before the
connection is established); grant verification runs over a separate
short-lived connection whose URL carries the first hex character of `h`
(16 buckets); the L7 load balancer routes consistently per bucket — the same
device on the same day always lands on the same instance, dedupe semantics do
not dilute with instance count, and no shared storage is introduced (the
zero-on-disk red line stays intact). The compliant path when capacity runs
out is vertical scaling (bigger single instance; the three tables are
naturally globally consistent there).

Audit perspective: any claim that "grant anti-abuse remains intact under
multi-instance deployment" should first be checked against whether this
sharding has actually been implemented.
