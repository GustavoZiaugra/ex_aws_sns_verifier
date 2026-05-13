defmodule ExAwsSnsVerifier.Cert do
  @moduledoc """
  Certificate fetching and caching for AWS SNS message verification.

  Downloads the signing certificate from the `SigningCertURL`, extracts the
  RSA public key, and caches it in `:persistent_term` with a 24-hour TTL.
  The cache and HTTP client are replaceable via options.
  """

  @doc """
  Fetch and decode the public key from a message's SigningCertURL.

  Checks cache first (`:persistent_term`), then validates the URL, downloads
  the PEM certificate, extracts the RSA public key, and caches it.
  """
  @spec fetch(%ExAwsSnsVerifier{}, map()) :: {:ok, tuple()} | {:error, atom()}
  def fetch(verifier, %{"SigningCertURL" => url}) do
    # TODO: implement cert fetch with cache
    {:error, :not_implemented}
  end

  def fetch(_verifier, _message) do
    {:error, :missing_signing_cert_url}
  end

  @doc """
  Default HTTP client using `:httpc`.

  Fetches a URL with HTTPS, no redirect following, and a 5-second timeout.
  """
  defmodule HttpClient do
    @behaviour ExAwsSnsVerifier.Cert.HttpClientBehaviour

    @impl true
    def get(url) do
      # TODO: implement :httpc-based fetch
      {:error, :not_implemented}
    end
  end

  @doc """
  Default cert cache using `:persistent_term` with 24-hour TTL.
  """
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
            :erase.call({__MODULE__, key})
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
