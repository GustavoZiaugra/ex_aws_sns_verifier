# ExAwsSnsVerifier

![CI](https://github.com/GustavoZiaugra/ex_aws_sns_verifier/actions/workflows/ci.yml/badge.svg)
[![Hex Version](https://img.shields.io/hexpm/v/ex_aws_sns_verifier)](https://hex.pm/packages/ex_aws_sns_verifier)

**Verify AWS SNS HTTPS message authenticity in Elixir.**  
The Elixir equivalent of Ruby's `Aws::SNS::MessageVerifier`.

> Every major ecosystem ships an AWS-blessed SNS message validator — except Elixir.
> This library fills that gap.

## Installation

```elixir
def deps do
  [
    {:ex_aws_sns_verifier, "~> 0.1.0"}
  ]
end
```

## Usage

```elixir
opts = [
  allowed_topic_arns: ["arn:aws:sns:us-east-1:123456789012:MyTopic"]
]

case ExAwsSnsVerifier.verify(raw_body, opts) do
  {:ok, payload} -> handle_message(payload)
  {:error, reason} -> {:error, :unauthorized}
end
```

## Documentation

Full docs at [hexdocs.pm/ex_aws_sns_verifier](https://hexdocs.pm/ex_aws_sns_verifier).

## License

MIT.
