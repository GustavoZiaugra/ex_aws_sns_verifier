# Changelog

## 0.1.0 — 2026-05-13

### Added

- Initial release.
- `ExAwsSnsVerifier.verify/2` and `ExAwsSnsVerifier.verify!/2` for RSA-SHA256
  signature verification of SNS Notification, SubscriptionConfirmation, and
  UnsubscribeConfirmation messages.
- Topic ARN allowlist, timestamp replay-window, region-allowlisted
  SigningCertURL validation.
- `:persistent_term`-backed cert cache with 24-hour TTL (replaceable via
  `:cert_cache` option).
- Pluggable HTTP client (`:httpc` by default, zero runtime deps).
- `ExAwsSnsVerifier.Plug` — a Plug adapter for Phoenix / Plug pipelines.
- Full unit-test coverage with locally generated RSA keypairs.
