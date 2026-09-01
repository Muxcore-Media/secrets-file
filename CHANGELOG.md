# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.6] — 2026-08-10

### Changed

- Advertise `settings` capability for admin-ui Settings discovery

## [0.1.5] — 2026-08-31

### Added

- Admin settings: `store_path`, `key_file`, `rotate_master_key`, read-only `secret_count`
- Live vault reload on settings changes with secret copy on store migration
- gRPC auth (mesh identity or module token) on `SecretsService`
- `--health-check` for Docker/systemd probes
- Path confinement via `SECRETS_ALLOWED_ROOT`
- Master key rotation and env-to-file bootstrap persistence

### Changed

- Default bind `127.0.0.1:9550`; `Info().HTTPAddr` no longer set
- Corrupt store fails closed on open; AES-GCM AAD binds ciphertext to secret name
- Atomic persist with fsync; Forgejo CI runs `golangci-lint` and `go test -race`

### Fixed

- gRPC `Get` maps decrypt failures to `FailedPrecondition` (not `NotFound`)
- Refuse missing `key_file` in settings (no silent key mint)

## [0.1.4] — 2026-08-10

### Fixed

- Sync Info()/muxcore.json version to **0.1.4**.

## [0.1.3] — 2026-08-10

### Added

- Test that master key (and store when present) are created `0600`

## [0.1.0]

### Added

- AES-256-GCM encrypted file-backed secrets vault module
- gRPC `secrets` capability: `Get` / `Set` / `Delete` / `List`
- Master key via `SECRETS_MASTER_KEY` or `SECRETS_KEY_FILE`
