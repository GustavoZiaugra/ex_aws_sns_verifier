# Changelog

## [0.2.1] — 2026-06-05

### Added

- Support for Elixir 1.20.0 and OTP 29
- CI: quality checks (format, credo, dialyzer) now run inside the test matrix on every OTP/Elixir combination

### Fixed

- Elixir 1.20 compatibility: verified clean compilation, tests, credo, and dialyzer on OTP 29

### Changed

- Updated `ex_doc` 0.40.2 → 0.40.3 (dev-only)
- Test coverage: 61.63% → 81.98% with new tests for `Url`, `Cert`, and `HttpClient` modules

## [0.2.0] — 2026-05-16

### Added

- `ExAwsSnsVerifier.Plug` — a Plug behaviour module for verifying SNS messages in Plug/Phoenix pipelines
- `{:plug, "~> 1.0"}` runtime dependency

## [0.1.0] — 2026-05-13

Initial release.

### Added

- RSA-SHA256 signature verification for `Notification`, `SubscriptionConfirmation`, and `UnsubscribeConfirmation` messages
- Canonical string construction per AWS SNS specification
- URL hardening: HTTPS enforcement, host whitelist (`sns.<region>.amazonaws.com`), no credentials in URL, `.pem` extension for certs
- Certificate fetching via `:httpc` with automatic caching in `:persistent_term` (24h TTL)
- Configurable timestamp window for replay protection
- Topic ARN allowlist for origin restriction
- Pluggable HTTP client via `ExAwsSnsVerifier.Cert.HttpClientBehaviour`
- `ExAwsSnsVerifier.Plug` for Phoenix/Plug integration (module stub)
- Comprehensive test suite with locally generated RSA keypairs
- CI workflow with OTP 26–29 × Elixir 1.16–1.20 matrix
- Full credo and dialyzer compliance
