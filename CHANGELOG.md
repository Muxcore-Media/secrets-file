# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Secrets proto definition and generated Go code
- AES-256-GCM encrypted file-backed secrets vault (Get/Set/Delete/List)
- Master key management: env var, file, or auto-generation
- Verified `internal/vault`: 7 existing tests pass
- Server tests: get/set/delete/list, persistence across restarts, health check
- Atomic persist with temp file + rename pattern
- Secrets cleared from memory on Close()
- Contract declaration with `MinCoreVersion: 0.4.0`

### Changed

- Makefile/Dockerfile/docker-compose/systemd: your-module → secrets-file
