# ExAwsSnsVerifier

[![CI](https://github.com/GustavoZiaugra/ex_aws_sns_verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/GustavoZiaugra/ex_aws_sns_verifier/actions/workflows/ci.yml)
[![Hex.pm](https://img.shields.io/hexpm/v/ex_aws_sns_verifier)](https://hex.pm/packages/ex_aws_sns_verifier)
[![Hex Docs](https://img.shields.io/badge/docs-hexpm-blue)](https://hexdocs.pm/ex_aws_sns_verifier)
[![Downloads](https://img.shields.io/hexpm/dt/ex_aws_sns_verifier)](https://hex.pm/packages/ex_aws_sns_verifier)
[![License](https://img.shields.io/hexpm/l/ex_aws_sns_verifier)](https://github.com/GustavoZiaugra/ex_aws_sns_verifier/blob/main/LICENSE)

**Verify AWS SNS HTTPS message authenticity — RSA-SHA256 signature verification for Elixir applications.**

ExAwsSnsVerifier validates `Notification`, `SubscriptionConfirmation`, and `UnsubscribeConfirmation` payloads sent via the AWS SNS HTTPS transport. It is the Elixir equivalent of Ruby's [`Aws::SNS::MessageVerifier`](https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html).

No runtime dependencies — uses `:public_key` for RSA verification and `:httpc` for certificate fetching.

## Features

- 🔐 **RSA-SHA256 verification** — validates `SignatureVersion 2` signatures using the AWS signing certificate
- 📬 **All message types** — `Notification`, `SubscriptionConfirmation`, and `UnsubscribeConfirmation`
- 🛡️ **Topic ARN allowlist** — restrict which topics are accepted
- 🔒 **URL hardening** — enforces HTTPS, host whitelist (`sns.<region>.amazonaws.com`), no credentials in URL, `.pem` extension for certs
- ⏰ **Replay protection** — configurable timestamp window (default: 1 hour)
- 🗄️ **Cert caching** — `:persistent_term`-backed cache with 24-hour TTL
- 🔌 **Pluggable HTTP client** — swap in Tesla, Req, Finch, or any custom client
- 🧩 **Plug integration** — `ExAwsSnsVerifier.Plug` for Phoenix / Plug pipelines
- ⚡ **Consistent error handling** — `verify/2` returns `{:ok, payload}` or `{:error, reason}`; `verify!/2` raises
- 📦 **Zero runtime dependencies** — no Jason, no HTTPoison, no extra baggage
- 🧪 **Fully tested** — matrix across OTP 26–28 and Elixir 1.16–1.19

## Installation

Add `ex_aws_sns_verifier` to your `mix.exs`:

```elixir
def deps do
  [
    {:ex_aws_sns_verifier, "~> 0.2.0"}
  ]
end
```

Then run:

```bash
mix deps.get
```

## Quick Start

### 1. One-shot verification

Pass the raw JSON body and a set of allowed topic ARNs:

```elixir
raw_body = ~s({
  "Type": "Notification",
  "MessageId": "22b80b92-fdea-4c2c-8f9d-bdfb0c7bf324",
  "TopicArn": "arn:aws:sns:us-east-1:123456789012:MyTopic",
  "Message": "Hello from SNS!",
  "Timestamp": "2026-05-13T12:00:00.000Z",
  "SignatureVersion": "2",
  "Signature": "...",
  "SigningCertURL": "https://sns.us-east-1.amazonaws.com/...pem",
  ...
})

opts = [
  allowed_topic_arns: ["arn:aws:sns:us-east-1:123456789012:MyTopic"]
]

{:ok, payload} = ExAwsSnsVerifier.verify(raw_body, opts)
```

### 2. With a Verifier struct (reusable config)

```elixir
verifier = ExAwsSnsVerifier.new(
  allowed_topic_arns: ["arn:aws:sns:us-east-1:123456789012:MyTopic"],
  timestamp_window_seconds: 300  # 5 minutes
)

{:ok, payload} = ExAwsSnsVerifier.verify(verifier, raw_body)
```

### 3. Raise on failure

```elixir
payload = ExAwsSnsVerifier.verify!(raw_body, opts)
# Raises ExAwsSnsVerifier.VerificationError on failure
```

### 4. With a Plug pipeline

```elixir
# In your router or endpoint
plug ExAwsSnsVerifier.Plug,
     allowed_topic_arns: ["arn:aws:sns:us-east-1:123456789012:MyTopic"]
```

The plug reads the raw body, verifies the SNS signature, and assigns `{:ok, payload}` or `{:error, reason}` to `conn.assigns.sns_verification`. On failure, the connection is halted with `403`.

## Configuration

### Verifier options

| Option | Default | Description |
|--------|---------|-------------|
| `allowed_topic_arns` | *(required)* | List of allowed TopicArn values |
| `allowed_regions` | All commercial regions | List of AWS regions for SigningCertURL validation |
| `timestamp_window_seconds` | `3600` | Replay protection window in seconds |
| `http_client` | `ExAwsSnsVerifier.Cert.HttpClient` | Module implementing `get/1` for cert fetching |
| `cert_cache` | `ExAwsSnsVerifier.Cert.Cache` | Module implementing `get/1` and `put/2` |

### Custom HTTP client

Swap in your own HTTP client (Tesla, Req, Finch, etc.):

```elixir
defmodule MyApp.MyHttpClient do
  @behaviour ExAwsSnsVerifier.Cert.HttpClientBehaviour

  @impl true
  def get(url) do
    # Return {:ok, body} or {:error, reason}
    Req.get!(url).body
  end
end

verifier = ExAwsSnsVerifier.new(
  allowed_topic_arns: ["..."],
  http_client: MyApp.MyHttpClient
)
```

### Custom cert cache

```elixir
defmodule MyApp.MyCache do
  @behaviour ExAwsSnsVerifier.Cert.CacheBehaviour  # get/1, put/2

  @impl true
  def get(key), do: # ...
  @impl true
  def put(key, value), do: # ...
end
```

## Error Reasons

`verify/2` returns `{:error, reason}` with one of the following atoms:

| Error | Meaning |
|-------|---------|
| `:invalid_json` | Body is not valid JSON |
| `:unknown_message_type` | `Type` is not Notification/SubscriptionConfirmation/UnsubscribeConfirmation |
| `:missing_signature_version` | No `SignatureVersion` field |
| `:unsupported_signature_version` | Only Version 2 (SHA256) supported |
| `:missing_timestamp` | No `Timestamp` field |
| `:invalid_timestamp` | Timestamp is not valid ISO 8601 |
| `:timestamp_out_of_window` | Message is outside the replay window |
| `:missing_topic_arn` | No `TopicArn` field |
| `:no_allowed_topics` | Allowlist is empty |
| `:topic_not_allowed` | TopicArn not in allowlist |
| `:missing_signature` | No `Signature` field |
| `:invalid_signature_encoding` | Signature is not valid Base64 |
| `:invalid_cert_url` | SigningCertURL failed host/path validation |
| `:missing_signing_cert_url` | No `SigningCertURL` field |
| `:signature_invalid` | RSA-SHA256 signature does not verify |

## How it works

1. **Parse** — decodes the JSON body
2. **Validate type** — confirms one of the three supported message types
3. **Validate signature version** — only `SignatureVersion 2` (RSA-SHA256)
4. **Validate timestamp** — checks the message is within the replay window
5. **Validate topic** — confirms the `TopicArn` is in the allowlist
6. **Build canonical string** — constructs the signed payload per AWS spec
7. **Fetch cert** — downloads and caches the signing certificate from `SigningCertURL`
8. **Verify signature** — RSA-SHA256 verification using `:public_key`

## Development

```bash
git clone https://github.com/GustavoZiaugra/ex_aws_sns_verifier.git
cd ex_aws_sns_verifier
mix deps.get
mix compile --warnings-as-errors

# Run tests
mix test

# Quality checks
mix format --check-formatted
mix credo --strict
mix dialyzer

# Generate docs
mix docs
```

## Links

- [AWS SNS Message Verification Docs](https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html)
- [Hex.pm](https://hex.pm/packages/ex_aws_sns_verifier)
- [HexDocs](https://hexdocs.pm/ex_aws_sns_verifier)

## License

MIT © [Gustavo Ziaugra](https://github.com/GustavoZiaugra)
