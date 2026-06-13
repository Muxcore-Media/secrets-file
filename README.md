# Secrets File

AES-256-GCM encrypted file-backed secrets vault for MuxCore.

Stores secrets encrypted at rest using AES-256-GCM with a 32-byte master key. Secrets are persisted to a JSON file. The master key can be provided via file or environment variable; if neither exists, a new key is auto-generated.

## Configuration

| Env / Flag | Default | Description |
|---|---|---|
| `SECRETS_MASTER_KEY` | — | Hex-encoded 32-byte master key (overrides key file) |
| `SECRETS_KEY_FILE` / `--key-file` | — | Path to master key file (auto-generated if missing) |
| `SECRETS_STORE` / `--store` | `secrets.json` | Path to encrypted secrets store |
| `SECRETS_GRPC_ADDR` / `--grpc-addr` | `:9500` | gRPC listen address |

## RPCs

- `Get(key)` — retrieve a decrypted secret
- `Set(key, value)` — encrypt and store a secret
- `Delete(key)` — remove a secret
- `List()` — list all secret keys (no values exposed)

## Security

- AES-256-GCM encryption with random nonces
- Master key must be exactly 32 bytes (64 hex chars)
- Secrets flushed to disk atomically (temp file + rename)
- Secrets cleared from memory on `Close()`
