---
title: Keys and encryption
summary: How saved keys and tokens are stored, where the master key lives, and how hosted differs.
---

# Keys and encryption

Saved keys and tokens are always encrypted. A plaintext key exists only in memory, for the request that uses it.

## Self-hosted

Every value is sealed with envelope encryption:

1. A fresh 32-byte data key is generated for the value.
2. The value is encrypted with it (AES-256-GCM).
3. The data key is encrypted with the master key (AES-256-GCM) and stored beside the value.

Each sealed value also records which sealer made it, so data opened with the wrong one fails with a clear error instead of returning garbage.

| What | Stored as | Readable back? |
| --- | --- | --- |
| A saved key | Sealed once, however many environments link it | Only by the proxy and edge, per request. The dashboard, API and CLI can replace it, never show it |
| A proxy token | Sealed, plus its SHA-256 hash | Lookups use the hash. The sealed copy lets `keystub run` hand the same worktree its token again |

Self-hosted sealing is deliberately simple: one master key opens every saved key, in every environment. A link is a plain record (environment, service, key ID) with nothing secret in it, so linking a key into another environment or switching a link decrypts and re-encrypts nothing. Whoever holds the master key and the data folder can read every key; that's the same boundary as before saved keys.

### The master key

`--secrets` picks where it lives. The default, `auto`, takes the first that applies:

| Source | When | Notes |
| --- | --- | --- |
| `env` | `KEYSTUB_MASTER_KEY` is set (64 hex characters) | For servers, e.g. a Fly or Railway secret |
| `keychain` | On a Mac | One login-keychain item, `dev.keystub.master-key`, per data folder. An old `master.key` file moves into it on first start and the file is deleted |
| `file` | Anywhere else | `master.key` beside the data, mode 0600. Fine for tests; weaker than the others |

Data sealed with one master key can't be opened with another: copying a data folder to a new place on a Mac gives it a new Keychain key, so its keys won't open. Move the master key with it (`--secrets env`).

Not built yet: rotating the master key, and KMS or Vault as the master key's home.

## Hosted

Hosted keeps keys apart by environment, so one environment's private key opens no other environment's keys, and the control plane can store keys without being able to read any. That is the main difference from self-hosted, where one master key opens everything. For saved keys:

- A saved key's data key is sealed once for each environment that links it, to that environment's public key. The request path uses only the environment's own seal.
- A second seal goes to the account's vault key pair, whose private key is wrapped by the account key and held only by the data plane. The data plane uses it to add a seal when the key is linked into another environment; the control plane still decrypts nothing.
- Setting or replacing a value seals it to the vault and to every linked environment in one write.

Hosted's layers:

Four layers, so a leak at one layer exposes as little as possible and no slow call sits on the request path.

| Layer | Encrypts | Lives in |
| --- | --- | --- |
| Root key | Account keys | A Worker secret on the data-plane Worker only; KMS only to create, rotate and back it up |
| Account key | Environment private keys, and the vault private key | D1, wrapped by the root key, or by the customer's own KMS key (bring your own key) |
| Environment key pair (X25519) | Data keys of that environment | Public key readable by the control plane; private key wrapped by the account key |
| Data key | One saved key or one token | Beside the value it seals |

- Data keys are sealed to the environment's public key, so the control plane can store new secrets without being able to read any.
- Unwrapped account and environment keys are cached only in Worker memory, keyed by id and version, for minutes. Real keys are decrypted per request and never cached.
- Nothing plaintext is ever written to KV, D1, R2 or logs.
