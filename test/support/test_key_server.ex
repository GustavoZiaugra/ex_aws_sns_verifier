defmodule ExAwsSnsVerifier.TestKeyServer do
  @moduledoc """
  ETS-backed key server for integration tests.

  Generates fresh RSA-2048 keypairs and stores them keyed by cert URL
  so the test HTTP client and cert cache can serve them.
  """
  @name :ex_sns_verifier_test_keys

  def start_link do
    case :ets.info(@name) do
      :undefined ->
        :ets.new(@name, [:named_table, :public, :set])
        :ok
      _ ->
        :ok
    end
  end

  @doc """
  Generate a keypair and store for a URL.

  Returns `{private_key, public_key}` where:
    - `private_key` is the full `{:RSAPrivateKey, :"two-prime", ...}` record
    - `public_key` is `{:RSAPublicKey, modulus, exponent}`
  """
  def generate_for_url(url) do
    pk = :public_key.generate_key({:rsa, 2048, 65_537})

    # In OTP 28: {RSAPrivateKey, two_prime, modulus, pubExp, privExp, ...}
    modulus = elem(pk, 2)
    pub_exp = elem(pk, 3)
    pub_key = {:RSAPublicKey, modulus, pub_exp}

    :ets.insert(@name, {url, pub_key, pk})
    {pk, pub_key}
  end

  @doc """
  Get the cached public key for a URL.
  """
  def get_public_key(url) do
    case :ets.lookup(@name, url) do
      [{^url, pub_key, _pk}] -> {:ok, pub_key}
      _ -> :not_found
    end
  end
end

defmodule ExAwsSnsVerifier.TestCertCache do
  @moduledoc """
  ETS-based cert cache for testing.
  """
  def get(url) do
    ExAwsSnsVerifier.TestKeyServer.get_public_key(url)
  end

  def put(_url, _value) do
    :ok
  end
end

defmodule ExAwsSnsVerifier.TestHttpClient do
  @moduledoc """
  Test HTTP client that returns the PEM cert.
  For the test flow, the cert is pre-cached so this is never called.
  """
  @behaviour ExAwsSnsVerifier.Cert.HttpClientBehaviour

  @impl true
  def get(_url) do
    # Should not be called if cache is pre-populated
    {:error, :unexpected_http_call}
  end
end
