defmodule ExAwsSnsVerifier do
  @moduledoc """
  Verify the authenticity of AWS SNS HTTPS messages.

  This is the Elixir equivalent of Ruby's `Aws::SNS::MessageVerifier`, filling a
  gap in the Elixir ecosystem. It verifies RSA-SHA256 (SignatureVersion 2)
  signatures on `Notification`, `SubscriptionConfirmation`, and
  `UnsubscribeConfirmation` payloads.

  ## Usage

  ### One-shot verification

      raw_body = ~s({\"Type\": \"Notification\", ...})
      opts = [allowed_topic_arns: [\"arn:aws:sns:us-east-1:123456789012:MyTopic\"]]

      {:ok, payload} = ExAwsSnsVerifier.verify(raw_body, opts)
      # or
      payload = ExAwsSnsVerifier.verify!(raw_body, opts)

  ### With Verifier struct (reused config)

      verifier = ExAwsSnsVerifier.new(allowed_topic_arns: [\"...\"])
      {:ok, payload} = ExAwsSnsVerifier.verify(verifier, raw_body)

  ### Error reasons

  On failure, `verify/2` returns `{:error, reason}` where reason is one of:

      :invalid_cert_url           — SigningCertURL does not pass host validation
      :topic_not_allowed          — TopicArn not in allowed list
      :unsupported_signature_version — Only SignatureVersion 2 (SHA256) supported
      :type_header_mismatch       — Message Type header does not match JSON
      :timestamp_out_of_window    — Message timestamp is outside the replay window
      :missing_field              — Required field is missing from message body
      :signature_invalid          — RSA-SHA256 signature does not verify
      {:cert_fetch_failed, status} — HTTP error fetching signing cert
      :invalid_subscribe_url      — SubscribeURL fails host validation
  """

  defstruct [
    :allowed_topic_arns,
    :allowed_regions,
    :timestamp_window_seconds,
    :http_client,
    :cert_cache
  ]

  @type t :: %__MODULE__{
          allowed_topic_arns: [String.t()],
          allowed_regions: [String.t()],
          timestamp_window_seconds: pos_integer(),
          http_client: module(),
          cert_cache: module()
        }

  @default_regions ~w(
    us-east-1 us-east-2 us-west-1 us-west-2
    eu-west-1 eu-west-2 eu-west-3 eu-central-1 eu-north-1
    ap-east-1 ap-south-1 ap-southeast-1 ap-southeast-2 ap-northeast-1 ap-northeast-2 ap-northeast-3
    sa-east-1 me-south-1 ca-central-1 af-south-1
  )

  @default_timestamp_window 3_600

  @doc """
  Create a new `ExAwsSnsVerifier` struct with persistent configuration.

  ## Options

    * `:allowed_topic_arns` — list of allowed TopicArn values (required)
    * `:allowed_regions` — list of AWS regions for SigningCertURL validation
      (defaults to all commercial regions)
    * `:timestamp_window_seconds` — replay window in seconds (default: 3600)
    * `:http_client` — module implementing `get/1` for cert fetching
      (default: `ExAwsSnsVerifier.Cert.HttpClient`, which uses `:httpc`)
    * `:cert_cache` — module implementing `get/1` and `put/2` for cert caching
      (default: `ExAwsSnsVerifier.Cert.Cache` using `:persistent_term`)
  """
  @spec new(keyword()) :: t()
  def new(opts \\ []) do
    %__MODULE__{
      allowed_topic_arns: Keyword.fetch!(opts, :allowed_topic_arns),
      allowed_regions: Keyword.get(opts, :allowed_regions, @default_regions),
      timestamp_window_seconds:
        Keyword.get(opts, :timestamp_window_seconds, @default_timestamp_window),
      http_client: Keyword.get(opts, :http_client, ExAwsSnsVerifier.Cert.HttpClient),
      cert_cache: Keyword.get(opts, :cert_cache, ExAwsSnsVerifier.Cert.Cache)
    }
  end

  @doc """
  Verify the authenticity of a raw SNS message body.

  Returns `{:ok, decoded_payload}` on success or `{:error, reason}` on failure.
  """
  @spec verify(String.t() | t(), keyword() | String.t()) :: {:ok, map()} | {:error, atom()}
  def verify(verifier_or_body, opts_or_body \\ [])

  def verify(%__MODULE__{} = verifier, raw_body) when is_binary(raw_body) do
    do_verify(verifier, raw_body)
  end

  def verify(raw_body, opts) when is_binary(raw_body) do
    verifier = new(opts)
    do_verify(verifier, raw_body)
  end

  @doc """
  Same as `verify/2` but raises `ExAwsSnsVerifier.VerificationError` on failure.
  """
  @spec verify!(String.t() | t(), keyword() | String.t()) :: map()
  def verify!(verifier_or_body, opts_or_body \\ [])

  def verify!(%__MODULE__{} = verifier, raw_body) when is_binary(raw_body) do
    case do_verify(verifier, raw_body) do
      {:ok, payload} -> payload
      {:error, reason} -> raise ExAwsSnsVerifier.VerificationError, reason: reason
    end
  end

  def verify!(raw_body, opts) when is_binary(raw_body) do
    verify!(new(opts), raw_body)
  end

  # ── private ────────────────────────────────────────────────────────────────

  defp do_verify(verifier, raw_body) do
    with {:ok, payload} <- decode_json(raw_body),
         :ok <- validate_type(payload),
         :ok <- validate_signature_version(payload),
         :ok <- validate_timestamp(verifier, payload),
         :ok <- validate_topic_arn(verifier, payload),
         {:ok, canonical} <- ExAwsSnsVerifier.Canonical.build(payload),
         {:ok, signature} <- decode_signature(payload),
         {:ok, public_key} <- ExAwsSnsVerifier.Cert.fetch(verifier, payload) do
      if verify_rsa_sha256(canonical, signature, public_key) do
        {:ok, payload}
      else
        {:error, :signature_invalid}
      end
    end
  end

  defp decode_json(raw_body) when is_binary(raw_body) do
    case Jason.decode(raw_body) do
      {:ok, payload} -> {:ok, payload}
      {:error, _} -> {:error, :invalid_json}
    end
  end

  defp validate_type(%{"Type" => type})
       when type in ~w(Notification SubscriptionConfirmation UnsubscribeConfirmation),
       do: :ok

  defp validate_type(_), do: {:error, :unknown_message_type}

  defp validate_signature_version(%{"SignatureVersion" => "2"}), do: :ok

  defp validate_signature_version(%{"SignatureVersion" => "1"}),
    do: {:error, :unsupported_signature_version}

  defp validate_signature_version(_), do: {:error, :missing_signature_version}

  defp validate_timestamp(verifier, %{"Timestamp" => timestamp}) do
    case DateTime.from_iso8601(timestamp) do
      {:ok, dt, _} ->
        now = DateTime.utc_now()
        diff = DateTime.diff(now, dt, :second)

        if abs(diff) <= verifier.timestamp_window_seconds,
          do: :ok,
          else: {:error, :timestamp_out_of_window}

      {:error, _} ->
        {:error, :invalid_timestamp}
    end
  end

  defp validate_timestamp(_verifier, _), do: {:error, :missing_timestamp}

  defp validate_topic_arn(%{allowed_topic_arns: arns}, %{"TopicArn" => arn})
       when is_list(arns) and arns != [] do
    if arn in arns, do: :ok, else: {:error, :topic_not_allowed}
  end

  defp validate_topic_arn(%{allowed_topic_arns: []}, _), do: {:error, :no_allowed_topics}
  defp validate_topic_arn(_verifier, _), do: {:error, :missing_topic_arn}

  defp decode_signature(%{"Signature" => sig}) when is_binary(sig) do
    case Base.decode64(sig) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, :invalid_signature_encoding}
    end
  end

  defp decode_signature(_), do: {:error, :missing_signature}

  defp verify_rsa_sha256(canonical, signature, public_key) do
    :public_key.verify(canonical, :sha256, signature, public_key)
  end
end
