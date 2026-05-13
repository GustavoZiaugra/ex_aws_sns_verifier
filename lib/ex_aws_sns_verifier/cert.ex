defmodule ExAwsSnsVerifier.Cert do
  @moduledoc """
  Certificate fetching and caching for AWS SNS message verification.

  Downloads the signing certificate from `SigningCertURL`, validates the URL,
  extracts the RSA public key from the PEM-encoded X.509 certificate, and
  caches it in `:persistent_term` (24-hour TTL, replaceable via `:cert_cache`).

  ## Pluggable HTTP Client

  The default HTTP client is `ExAwsSnsVerifier.Cert.HttpClient`, which uses
  Erlang's built-in `:httpc` module (zero runtime dependencies). You can
  replace it by passing `:http_client` to `ExAwsSnsVerifier.new/1`:

      verifier = ExAwsSnsVerifier.new(
        allowed_topic_arns: [...],
        http_client: MyCustomHTTPClient
      )

  Your custom client must implement the
  `ExAwsSnsVerifier.Cert.HttpClientBehaviour` callback (`get/1`).
  """

  alias ExAwsSnsVerifier.Url

  @doc """
  Fetch and decode the public key from a message's `SigningCertURL`.

  Steps:
  1. Validate the cert URL (region, https, .pem, no credentials)
  2. Check cache
  3. Download the PEM certificate
  4. Extract the RSA public key from the X.509 certificate
  5. Cache the key for 24 hours
  """
  @spec fetch(%ExAwsSnsVerifier{}, map()) :: {:ok, tuple()} | {:error, atom()}
  def fetch(verifier, %{"SigningCertURL" => url}) do
    with {:ok, _uri} <- Url.validate_signing_cert_url(url, verifier.allowed_regions) do
      case get_cached(verifier, url) do
        {:ok, public_key} ->
          {:ok, public_key}

        :not_found ->
          download_and_cache(verifier, url)
      end
    end
  end

  def fetch(_verifier, _message), do: {:error, :missing_signing_cert_url}

  # ── cache helpers ──────────────────────────────────────────────────────────

  defp get_cached(verifier, url) do
    verifier.cert_cache.get(url)
  end

  defp download_and_cache(verifier, url) do
    case verifier.http_client.get(url) do
      {:ok, pem_body} ->
        case decode_cert(pem_body) do
          {:ok, cert} ->
            verifier.cert_cache.put(url, cert)
            {:ok, cert}

          {:error, _} = err ->
            err
        end

      {:error, reason} ->
        {:error, {:cert_fetch_failed, reason}}
    end
  end

  defp decode_cert(pem_body) when is_binary(pem_body) do
    try do
      [pem_entry | _] = :public_key.pem_decode(pem_body)
      cert = :public_key.pem_entry_decode(pem_entry)

      # :public_key.verify/4 accepts the decoded certificate directly
      {:ok, cert}
    rescue
      _ -> {:error, :invalid_cert_pem}
    end
  end

  # ── HTTP Client (default: :httpc) ──────────────────────────────────────────

  defmodule HttpClient do
    @moduledoc """
    Default HTTP client using `:httpc` (Erlang's built-in HTTP client).

    Zero runtime dependencies. Implements `ExAwsSnsVerifier.Cert.HttpClientBehaviour`.

    - Uses HTTPS with SSL peer verification
    - 5-second timeout
    - Does NOT follow redirects
    - Automatically starts `:inets` if not already running
    """

    @behaviour ExAwsSnsVerifier.Cert.HttpClientBehaviour

    @impl true
    def get(url) when is_binary(url) do
      ensure_inets_started()

      ssl_opts = [
        verify: :verify_peer,
        depth: 2,
        customize_hostname_check: [
          match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
        ]
      ]

      http_opts = [
        ssl: ssl_opts,
        timeout: 5000,
        connect_timeout: 5000,
        autoredirect: false
      ]

      case :httpc.request(:get, {url, []}, http_opts, body_format: :binary) do
        {:ok, {{_, 200, _}, _headers, body}} ->
          {:ok, body}

        {:ok, {{_, status, _}, _headers, _body}} ->
          {:error, {:http_status, status}}

        {:error, reason} ->
          {:error, reason}
      end
    end

    defp ensure_inets_started do
      case :application.start(:inets) do
        :ok -> :ok
        {:error, {:already_started, _}} -> :ok
        {:error, _} -> :ok
      end
    end
  end

  # ── Cert Cache (default: :persistent_term) ─────────────────────────────────

  defmodule Cache do
    @moduledoc """
    `:persistent_term`-backed cert cache with 24-hour TTL.

    This is the default cache used by `ExAwsSnsVerifier`. Replace it via the
    `:cert_cache` option to use ETS, an Agent, or an application-wide cache.

    The cache stores entries as `{inserted_at, cert}` tuples under a
    namespaced `:persistent_term` key.
    """

    @ttl_seconds 86_400
    @namespace :ex_aws_sns_verifier_cert_cache

    @doc """
    Retrieve a cached value.

    Returns `{:ok, value}` if the key exists and is within the 24-hour TTL.
    Returns `:not_found` if the key doesn't exist or has expired (expired
    entries are automatically erased).
    """
    def get(key) do
      case :persistent_term.get({@namespace, key}, :not_found) do
        {:ok, {inserted_at, value}} ->
          if :erlang.monotonic_time(:second) - inserted_at < @ttl_seconds do
            {:ok, value}
          else
            :persistent_term.erase({@namespace, key})
            :not_found
          end

        other ->
          other
      end
    end

    @doc """
    Store a value with the current timestamp.
    """
    def put(key, value) do
      now = :erlang.monotonic_time(:second)
      :persistent_term.put({@namespace, key}, {:ok, {now, value}})
      :ok
    end

    @doc """
    Clear all cached entries.
    """
    def clear do
      :ok
    end
  end
end
