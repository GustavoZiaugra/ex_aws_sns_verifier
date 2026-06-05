defmodule ExAwsSnsVerifier.CertTest do
  use ExUnit.Case

  alias ExAwsSnsVerifier.Cert

  setup do
    # Ensure ETS table exists for key server
    ExAwsSnsVerifier.TestKeyServer.start_link()

    # Clean up any persistent_term entries from previous test runs
    for {key, _value} <- :persistent_term.get() do
      if match?({ExAwsSnsVerifier.Cert.Cache, _}, key) do
        :persistent_term.erase(key)
      end
    end

    :ok
  end

  describe "fetch/2" do
    test "returns error when SigningCertURL is missing" do
      verifier = ExAwsSnsVerifier.new(allowed_topic_arns: ["arn:test"])

      assert {:error, :missing_signing_cert_url} =
               Cert.fetch(verifier, %{"Type" => "Notification"})
    end

    test "returns error for invalid cert URL" do
      verifier = ExAwsSnsVerifier.new(allowed_topic_arns: ["arn:test"])

      message = %{
        "SigningCertURL" => "http://evil.com/cert.pem"
      }

      assert {:error, :invalid_cert_url} = Cert.fetch(verifier, message)
    end

    test "returns public key from cache hit" do
      cert_url = "https://sns.us-east-1.amazonaws.com/cached-key.pem"
      {_pk, pub} = ExAwsSnsVerifier.TestKeyServer.generate_for_url(cert_url)

      verifier =
        ExAwsSnsVerifier.new(
          allowed_topic_arns: ["arn:test"],
          cert_cache: ExAwsSnsVerifier.TestCertCache
        )

      assert {:ok, ^pub} = Cert.fetch(verifier, %{"SigningCertURL" => cert_url})
    end

    test "fetches, decodes, and caches public key on cache miss with valid PEM" do
      cert_url = "https://sns.us-east-1.amazonaws.com/fresh-key.pem"
      {_pk, pub} = ExAwsSnsVerifier.TestKeyServer.generate_for_url(cert_url)

      # Use a mock HTTP client that returns the public key PEM
      defmodule MockHttpClient do
        @behaviour ExAwsSnsVerifier.Cert.HttpClientBehaviour

        def get(url) do
          case ExAwsSnsVerifier.TestKeyServer.get_public_key(url) do
            {:ok, {:RSAPublicKey, n, e}} ->
              pem_entry = :public_key.pem_entry_encode(:RSAPublicKey, {:RSAPublicKey, n, e})
              {:ok, :public_key.pem_encode([pem_entry])}

            other ->
              other
          end
        end
      end

      verifier =
        ExAwsSnsVerifier.new(
          allowed_topic_arns: ["arn:aws:sns:us-east-1:123456789012:MyTopic"],
          cert_cache: ExAwsSnsVerifier.Cert.Cache,
          http_client: MockHttpClient,
          allowed_regions: ["us-east-1"]
        )

      # First call should fetch and cache
      assert {:ok, fetched_pub} = Cert.fetch(verifier, %{"SigningCertURL" => cert_url})
      assert fetched_pub == pub

      # Second call should hit the cache
      assert {:ok, cached_pub} = Cert.fetch(verifier, %{"SigningCertURL" => cert_url})
      assert cached_pub == pub
    end

    test "returns error when HTTP client fails" do
      defmodule FailingHttpClient do
        @behaviour ExAwsSnsVerifier.Cert.HttpClientBehaviour
        def get(_url), do: {:error, :network_error}
      end

      verifier =
        ExAwsSnsVerifier.new(
          allowed_topic_arns: ["arn:aws:sns:us-east-1:123456789012:MyTopic"],
          cert_cache: ExAwsSnsVerifier.Cert.Cache,
          http_client: FailingHttpClient,
          allowed_regions: ["us-east-1"]
        )

      message = %{
        "SigningCertURL" => "https://sns.us-east-1.amazonaws.com/test.pem"
      }

      assert {:error, :network_error} = Cert.fetch(verifier, message)
    end

    test "returns error for invalid PEM format" do
      defmodule BadPemHttpClient do
        @behaviour ExAwsSnsVerifier.Cert.HttpClientBehaviour
        def get(_url), do: {:ok, "not-valid-pem-data"}
      end

      verifier =
        ExAwsSnsVerifier.new(
          allowed_topic_arns: ["arn:aws:sns:us-east-1:123456789012:MyTopic"],
          cert_cache: ExAwsSnsVerifier.Cert.Cache,
          http_client: BadPemHttpClient,
          allowed_regions: ["us-east-1"]
        )

      message = %{
        "SigningCertURL" => "https://sns.us-east-1.amazonaws.com/test.pem"
      }

      assert {:error, :invalid_cert_format} = Cert.fetch(verifier, message)
    end
  end

  describe "Cache" do
    test "stores and retrieves values" do
      key = "https://sns.us-east-1.amazonaws.com/cache-test.pem"
      value = {:RSAPublicKey, 1, 2}

      assert :not_found = Cert.Cache.get(key)
      assert :ok = Cert.Cache.put(key, value)
      assert {:ok, ^value} = Cert.Cache.get(key)
    end

    test "evicts expired entries" do
      key = "https://sns.us-east-1.amazonaws.com/expired.pem"
      value = {:RSAPublicKey, 1, 2}

      # Insert with an old timestamp by manipulating persistent_term directly
      old_time = :erlang.monotonic_time(:second) - 100_000
      :persistent_term.put({Cert.Cache, key}, {:ok, {old_time, value}})

      assert :not_found = Cert.Cache.get(key)
      # Verify it was erased
      assert :not_found = :persistent_term.get({Cert.Cache, key}, :not_found)
    end

    test "returns :not_found for missing keys" do
      assert :not_found = Cert.Cache.get("non-existent-url")
    end
  end
end
