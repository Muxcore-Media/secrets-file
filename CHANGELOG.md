# Changelog


## [0.1.6] — 2026-08-10

### Changed

- Advertise `settings` capability for admin-ui Settings discovery

## [0.1.4] — 2026-08-10

### Fixed
- Sync Info()/muxcore.json version to **0.1.4**.

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.8] - 2026-10-05


### Changed
- Reported version comes from muxcore.json (ADR-0021); built on core v0.6.12 / sdk/go/module v0.6.3 (mesh enrollment, ADR-0017).

## [0.1.7] - 2026-10-05

### Changed
- CI runs on GitHub-hosted runners from the umbrella template; retired-origin workflows removed.
- Dependencies resolve from published GitHub tags (no filesystem `replace`); requires core v0.6.0.

## [0.1.3] — 2026-08-10

### Added

- Test that master key (and store when present) are created `0600`


## [0.1.0]

### Added

- AES-256-GCM encrypted file-backed secrets vault module
- gRPC `secrets` capability: `Get` / `Set` / `Delete` / `List`
- Master key via `SECRETS_MASTER_KEY` or `SECRETS_KEY_FILE` (auto-create)
