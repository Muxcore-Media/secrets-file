# Secrets File Vault

[![CI](https://git.zem.systems/muxcore/secrets-file/actions/workflows/ci.yml/badge.svg)](https://github.com/Muxcore-Media/secrets-file/actions)
[![Go Version](https://img.shields.io/badge/Go-1.26-blue)](https://go.dev/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

**AES-256-GCM encrypted file-backed secrets vault for MuxCore.**

A MuxCore sidecar module that stores secrets in a local JSON file, encrypting each value with AES-256-GCM under a 32-byte master key. Provides the `secrets` capability via gRPC (`Get` / `Set` / `Delete` / `List`).

---

## How It Works

```
Module request ──→ secrets-file (gRPC) ──→ AES-256-GCM vault ──→ secrets.json
```

Each secret is stored as `{"n": <nonce>, "d": <ciphertext>}`. The master key never leaves the process; values are decrypted only on `Get`.

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRETS_MASTER_KEY` | `` | Hex-encoded 32-byte master key (takes precedence) |
| `SECRETS_KEY_FILE` | `` | Path to hex-encoded master key file (auto-created if missing) |
| `SECRETS_STORE` | `secrets.json` | Encrypted secrets store path |
| `SECRETS_GRPC_ADDR` | `127.0.0.1:9550` | gRPC listen address (loopback by default) |

gRPC uses **TLS by default**. Auto-generated dev certificates are stored alongside the secrets store (or under `SECRETS_TLS_DIR`). Set `MUXCORE_INSECURE_DISABLE_TLS=true` for plaintext dev only. Override certs with `MUXCORE_TLS_CERT` / `MUXCORE_TLS_KEY` or `SECRETS_TLS_CERT` / `SECRETS_TLS_KEY`.

---

## Quick Start

```bash
go build -o secrets-file ./cmd/module

export MUXCORE_INSECURE_DISABLE_TLS=true
export SECRETS_MASTER_KEY="$(openssl rand -hex 32)"
./secrets-file --muxcore-mesh-addr localhost:9090
```

---

## Capability

`secrets` — Encrypted secrets storage

## License

GPL-3.0
