defmodule ExAwsSnsVerifier.Cert do
  @moduledoc """
  Certificate fetching and caching for AWS SNS message verification.

  Downloads the signing certificate from the `SigningCertURL`, extracts the
  RSA public key, and caches it in `:persistent_term` with a 24-hour TTL.
  The cache and HTTP client are replaceable via options.
  """

  alias ExAwsSnsVerifier.Url

  @doc """
  Fetch and decode the public key from a message's SigningCertURL.

  Checks cache first (`:persistent_term`), then validates the URL, downloads
  the PEM certificate, extracts the RSA public key, and caches it.
  """
  @spec fetch(ExAwsSnsVerifier.t(), map()) :: {:ok, tuple()} | {:error, atom()}
  def fetch(%ExAwsSnsVerifier{} = verifier, %{"SigningCertURL" => url}) do
    cache = verifier.cert_cache
    http_client = verifier.http_client
    allowed_regions = verifier.allowed_regions

    case cache.get(url) do
      {:ok, public_key} ->
        {:ok, public_key}

      :not_found ->
        with {:ok, _uri} <- Url.validate_signing_cert_url(url, allowed_regions),
             {:ok, body} <- http_client.get(url),
             {:ok, public_key} <- decode_public_key(body) do
          cache.put(url, public_key)
          {:ok, public_key}
        else
          {:error, :invalid_cert_url} = err -> err
          {:error, reason} -> {:error, reason}
        end
    end
  end

  def fetch(_verifier, _message) do
    {:error, :missing_signing_cert_url}
  end

  defp decode_public_key(body) do
    case :public_key.pem_decode(body) do
      [] ->
        {:error, :invalid_cert_format}

      [entry | _] ->
        decoded = :public_key.pem_entry_decode(entry)

        case decoded do
          {:RSAPublicKey, _, _} ->
            {:ok, decoded}

          {:OTPCertificate, _, tbs, _} ->
            spki = elem(tbs, 7)
            public_key = elem(spki, 2)
            {:ok, public_key}

          _ ->
            {:error, :invalid_cert_format}
        end
    end
  end

  defmodule HttpClient do
    @moduledoc """
    Default HTTP client using `:httpc`.

    Fetches a URL with HTTPS, no redirect following, and a 5-second timeout.
    """

    @behaviour ExAwsSnsVerifier.Cert.HttpClientBehaviour

    @impl true
    def get(url) do
      with :ok <- start_inets(),
           :ok <- start_ssl() do
        case :httpc.request(
               :get,
               {String.to_charlist(url), []},
               [{:timeout, 5000}, {:autoredirect, false}],
               [{:body_format, :binary}]
             ) do
          {:ok, {{_, 200, _}, _, body}} ->
            {:ok, body}

          {:ok, {{_, 200}, _, body}} ->
            {:ok, body}

          {:ok, {{_, status, _}, _, _}} ->
            {:error, {:cert_fetch_failed, status}}

          {:ok, {{_, status}, _, _}} ->
            {:error, {:cert_fetch_failed, status}}

          {:error, reason} ->
            {:error, reason}
        end
      end
    end

    defp start_inets do
      case :inets.start() do
        :ok -> :ok
        {:error, {:already_started, _}} -> :ok
        error -> error
      end
    end

    defp start_ssl do
      case :ssl.start() do
        :ok -> :ok
        {:error, {:already_started, _}} -> :ok
        error -> error
      end
    end
  end

  defmodule Cache do
    @moduledoc """
    `:persistent_term`-backed cache with 24-hour TTL.

    Keys are `{__MODULE__, cert_url}` tuples. Values are `{inserted_at, public_key}`
    tuples. Entries older than 24 hours are evicted on read.
    """

    @ttl_seconds 86_400

    @doc false
    def get(key) do
      case :persistent_term.get({__MODULE__, key}, :not_found) do
        {:ok, {inserted_at, value}} ->
          if :erlang.monotonic_time(:second) - inserted_at < @ttl_seconds do
            {:ok, value}
          else
            :persistent_term.erase({__MODULE__, key})
            :not_found
          end

        other ->
          other
      end
    end

    @doc false
    def put(key, value) do
      :persistent_term.put({__MODULE__, key}, {:ok, {:erlang.monotonic_time(:second), value}})
      :ok
    end
  end
end
