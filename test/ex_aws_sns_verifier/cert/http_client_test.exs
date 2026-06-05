defmodule ExAwsSnsVerifier.Cert.HttpClientTest do
  use ExUnit.Case

  alias ExAwsSnsVerifier.Cert.HttpClient

  describe "get/1" do
    test "returns error for connection refused" do
      # Port 1 is unlikely to have a listener, should fail immediately
      assert {:error, _reason} = HttpClient.get("http://127.0.0.1:1/test.pem")
    end

    test "returns error for invalid URL" do
      assert {:error, _reason} = HttpClient.get("not_a_valid_url")
    end

    test "handles already started inets/ssl gracefully on subsequent calls" do
      # First call starts inets/ssl
      result1 = HttpClient.get("http://127.0.0.1:1/test.pem")
      assert match?({:error, _}, result1)

      # Second call should handle :already_started gracefully
      result2 = HttpClient.get("http://127.0.0.1:1/test.pem")
      assert match?({:error, _}, result2)
    end
  end
end
