# Changelog

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
- CI workflow with OTP 26/27/28 × Elixir 1.16–1.19 matrix
- Full credo and dialyzer compliance
