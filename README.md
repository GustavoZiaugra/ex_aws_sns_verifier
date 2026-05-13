# ExAwsSnsVerifier

[![Hex.pm](https://img.shields.io/hexpm/v/ex_aws_sns_verifier.svg)](https://hex.pm/packages/ex_aws_sns_verifier)
[![CI](https://github.com/GustavoZiaugra/ex_aws_sns_verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/GustavoZiaugra/ex_aws_sns_verifier/actions)
[![Hex.pm](https://img.shields.io/hexpm/l/ex_aws_sns_verifier.svg)](https://github.com/GustavoZiaugra/ex_aws_sns_verifier/blob/main/LICENSE)
[![Hex Docs](https://img.shields.io/badge/hex-docs-blueviolet.svg)](https://hexdocs.pm/ex_aws_sns_verifier)

Verify the authenticity of AWS SNS HTTPS messages in Elixir. RSA-SHA256 signature
verification for `Notification`, `SubscriptionConfirmation`, and `UnsubscribeConfirmation`
payloads — the Elixir equivalent of Ruby's `Aws::SNS::MessageVerifier`.

## Features

✨ **RSA-SHA256 verification** — validates signatures using AWS's SigningCertURL  
🔒 **URL hardening** — enforces HTTPS, host whitelist (`sns.<region>.amazonaws.com`), no credentials in URL, `.pem` extension for certs  
⏰ **Replay protection** — configurable timestamp window (default: 1 hour)  
📋 **Topic allowlist** — restricts which TopicArn values are accepted  
🧩 **Pluggable HTTP client** — swap in Tesla, Req, Finch, or `:httpc` default  
💾 **Automatic cert caching** — `:persistent_term`-backed with 24h TTL  
⚠️ **Descriptive error reasons** — atoms like `:signature_invalid`, `:topic_not_allowed`, `:timestamp_out_of_window`

## Installation

Add `ex_aws_sns_verifier` to your `mix.exs`:

```elixir
def deps do
  [
    {:ex_aws_sns_verifier, "~> 0.1.0"}
  ]
end
```

## Usage

### One-shot verification

```elixir
raw_body = ~s({"Type": "Notification", ...})
opts = [allowed_topic_arns: ["arn:aws:sns:us-east-1:123456789012:MyTopic"]]

{:ok, payload} = ExAwsSnsVerifier.verify(raw_body, opts)
# or
payload = ExAwsSnsVerifier.verify!(raw_body, opts)
```

### With Verifier struct

```elixir
verifier = ExAwsSnsVerifier.new(
  allowed_topic_arns: ["arn:aws:sns:us-east-1:123456789012:MyTopic"],
  timestamp_window_seconds: 300  # 5 minutes
)

{:ok, payload} = ExAwsSnsVerifier.verify(verifier, raw_body)
```

### Plug integration

Use with Phoenix controllers or Plug pipelines:

```elixir
# In a router or pipeline
plug ExAwsSnsVerifier.Plug, allowed_topic_arns: ["arn:aws:sns:..."]
```

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `allowed_topic_arns` | (required) | List of allowed SNS topic ARNs |
| `allowed_regions` | All commercial regions | AWS regions for cert URL validation |
| `timestamp_window_seconds` | `3600` | Replay protection window |
| `http_client` | `:httpc` | Module implementing `get/1` |
| `cert_cache` | `:persistent_term` | Module implementing `get/1` and `put/2` |

### Custom HTTP client

```elixir
defmodule MyApp.HttpClient do
  @behaviour ExAwsSnsVerifier.Cert.HttpClientBehaviour

  def get(url) do
    # Your HTTP implementation (Req, Finch, Tesla, etc.)
    {:ok, body}
  end
end

ExAwsSnsVerifier.new(
  allowed_topic_arns: ["..."],
  http_client: MyApp.HttpClient
)
```

## Error Reasons

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

## Development

```bash
git clone https://github.com/GustavoZiaugra/ex_aws_sns_verifier.git
cd ex_aws_sns_verifier
mix deps.get
mix test
mix credo --strict
mix dialyzer
```

## License

MIT © [Gustavo Ziaugra](https://github.com/GustavoZiaugra)
