defmodule ExAwsSnsVerifier.UrlTest do
  use ExUnit.Case, async: true

  alias ExAwsSnsVerifier.Url

  @allowed_regions ["us-east-1", "eu-west-1"]

  describe "validate_signing_cert_url/2" do
    test "accepts valid HTTPS SNS cert URL with .pem extension" do
      url = "https://sns.us-east-1.amazonaws.com/test.pem"

      assert {:ok, %URI{scheme: "https", host: "sns.us-east-1.amazonaws.com"}} =
               Url.validate_signing_cert_url(url, @allowed_regions)
    end

    test "accepts AWS China endpoint" do
      url = "https://sns.us-east-1.amazonaws.com.cn/test.pem"

      assert {:ok, %URI{host: "sns.us-east-1.amazonaws.com.cn"}} =
               Url.validate_signing_cert_url(url, @allowed_regions)
    end

    test "rejects HTTP scheme" do
      url = "http://sns.us-east-1.amazonaws.com/test.pem"
      assert {:error, :invalid_cert_url} = Url.validate_signing_cert_url(url, @allowed_regions)
    end

    test "rejects invalid host" do
      url = "https://evil.example.com/test.pem"
      assert {:error, :invalid_cert_url} = Url.validate_signing_cert_url(url, @allowed_regions)
    end

    test "rejects host with wrong region" do
      url = "https://sns.ap-south-1.amazonaws.com/test.pem"
      assert {:error, :invalid_cert_url} = Url.validate_signing_cert_url(url, @allowed_regions)
    end

    test "rejects URL without .pem extension" do
      url = "https://sns.us-east-1.amazonaws.com/test.crt"
      assert {:error, :invalid_cert_url} = Url.validate_signing_cert_url(url, @allowed_regions)
    end

    test "rejects URL with userinfo (credentials)" do
      url = "https://user:pass@sns.us-east-1.amazonaws.com/test.pem"
      assert {:error, :invalid_cert_url} = Url.validate_signing_cert_url(url, @allowed_regions)
    end

    test "rejects URL with missing host" do
      url = "https:///test.pem"
      assert {:error, :invalid_cert_url} = Url.validate_signing_cert_url(url, @allowed_regions)
    end

    test "rejects non-URL strings" do
      assert {:error, :invalid_cert_url} =
               Url.validate_signing_cert_url("not-a-url", @allowed_regions)
    end

    test "rejects empty string" do
      assert {:error, :invalid_cert_url} = Url.validate_signing_cert_url("", @allowed_regions)
    end
  end

  describe "validate_subscribe_url/2" do
    test "accepts valid HTTPS SNS subscribe URL" do
      url = "https://sns.us-east-1.amazonaws.com/confirm"

      assert {:ok, %URI{scheme: "https", host: "sns.us-east-1.amazonaws.com"}} =
               Url.validate_subscribe_url(url, @allowed_regions)
    end

    test "accepts subscribe URL without .pem extension" do
      url = "https://sns.us-east-1.amazonaws.com/confirm"
      assert {:ok, _} = Url.validate_subscribe_url(url, @allowed_regions)
    end

    test "rejects HTTP scheme for subscribe URL" do
      url = "http://sns.us-east-1.amazonaws.com/confirm"
      assert {:error, :invalid_subscribe_url} = Url.validate_subscribe_url(url, @allowed_regions)
    end

    test "rejects invalid host for subscribe URL" do
      url = "https://evil.example.com/confirm"
      assert {:error, :invalid_subscribe_url} = Url.validate_subscribe_url(url, @allowed_regions)
    end

    test "rejects subscribe URL with userinfo" do
      url = "https://user:pass@sns.us-east-1.amazonaws.com/confirm"
      assert {:error, :invalid_subscribe_url} = Url.validate_subscribe_url(url, @allowed_regions)
    end
  end

  describe "hostname_regex/1" do
    test "builds regex matching allowed regions" do
      regex = Url.hostname_regex(["us-east-1", "eu-west-1"])
      assert Regex.match?(regex, "sns.us-east-1.amazonaws.com")
      assert Regex.match?(regex, "sns.eu-west-1.amazonaws.com")
      assert Regex.match?(regex, "sns.us-east-1.amazonaws.com.cn")
      refute Regex.match?(regex, "sns.ap-south-1.amazonaws.com")
      refute Regex.match?(regex, "evil.example.com")
    end

    test "single region regex" do
      regex = Url.hostname_regex(["us-west-2"])
      assert Regex.match?(regex, "sns.us-west-2.amazonaws.com")
      refute Regex.match?(regex, "sns.us-east-1.amazonaws.com")
    end
  end
end
