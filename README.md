# Secrets File Vault

[![CI](https://git.zem.systems/muxcore/secrets-file/actions/workflows/ci.yml/badge.svg)](https://git.zem.systems/muxcore/secrets-file/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.26-blue)](https://go.dev/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

**AES-256-GCM encrypted file-backed secrets vault for MuxCore.**

A MuxCore sidecar module that stores secrets in a local JSON file, encrypting each value with AES-256-GCM under a 32-byte master key. Provides the `secrets` capability via gRPC (`Get` / `Set` / `Delete` / `List`).

---

## How It Works

```
Module request ──→ secrets-file (gRPC) ──→ AES-256-GCM vault ──→ secrets.json
```

Each secret is stored as `{"n": <nonce>, "d": <ciphertext>}`. The master key never leaves the process; values are decrypted only on `Get`. AES-GCM additional authenticated data binds each ciphertext to its secret name so JSON entry swaps fail closed.

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRETS_MASTER_KEY` | `` | Hex-encoded 32-byte master key (**takes precedence** over `SECRETS_KEY_FILE`) |
| `SECRETS_KEY_FILE` | `` | Path to hex-encoded master key file; must exist unless bootstrapping via `SECRETS_MASTER_KEY` (persisted on first start) |
| `SECRETS_STORE` | `secrets.json` | Encrypted secrets store path |
| `SECRETS_GRPC_ADDR` | `127.0.0.1:9550` | gRPC listen address (loopback by default) |
| `SECRETS_ALLOWED_ROOT` | parent of store/key | Directory that `store_path` and `key_file` settings must stay under |
| `SECRETS_MODULE_TOKEN` / `MUXCORE_MODULE_TOKEN` | `` | Optional bearer token for direct gRPC clients |

### Admin settings keys

| Key | Description |
|-----|-------------|
| `store_path` | Encrypted JSON store path (copies secrets when changed) |
| `key_file` | Master key file path (must already exist; no auto-mint) |
| `rotate_master_key` | Set to `true` to re-encrypt all secrets under a new key |
| `secret_count` | Read-only count of stored secrets |

---

## Backup and restore

Back up **both** the encrypted store (`SECRETS_STORE`) and the master key file (`SECRETS_KEY_FILE`) together. Restoring only one leaves ciphertext unreadable. For migrations, copy both files atomically while the module is stopped.

---

## Quick Start

```bash
go build -o secrets-file ./cmd/module

export MUXCORE_INSECURE_DISABLE_TLS=true
export SECRETS_MASTER_KEY="$(openssl rand -hex 32)"
export SECRETS_KEY_FILE=/var/lib/secrets-file/master.key
export SECRETS_STORE=/var/lib/secrets-file/secrets.json
./secrets-file --muxcore-mesh-addr localhost:9090
```

On first start with `SECRETS_MASTER_KEY` set, the key is written to `SECRETS_KEY_FILE` (mode `0600`) so later restarts can omit the env var.

---

## Capability

`secrets` — Encrypted secrets storage

## License

GPL-3.0
