defmodule ExAwsSnsVerifier.UrlTest do
  use ExUnit.Case, async: true

  alias ExAwsSnsVerifier.Url

  @allowed_regions ~w(us-east-1 us-east-2 eu-west-1)

  describe "validate_signing_cert_url/2" do
    test "accepts valid HTTPS URL in allowed region" do
      url = "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-abc123.pem"
      assert {:ok, %URI{}} = Url.validate_signing_cert_url(url, @allowed_regions)
    end

    test "accepts valid .cn URL" do
      url = "https://sns.us-east-1.amazonaws.com.cn/SimpleNotificationService-abc123.pem"
      assert {:ok, %URI{}} = Url.validate_signing_cert_url(url, @allowed_regions)
    end

    test "rejects HTTP scheme" do
      url = "http://sns.us-east-1.amazonaws.com/SimpleNotificationService-abc123.pem"
      assert {:error, :invalid_url_scheme} = Url.validate_signing_cert_url(url, @allowed_regions)
    end

    test "rejects host outside allowed regions" do
      url = "https://sns.eu-south-2.amazonaws.com/SimpleNotificationService-abc123.pem"

      assert {:error, :invalid_cert_url_host} =
               Url.validate_signing_cert_url(url, @allowed_regions)
    end

    test "rejects URL with userinfo" do
      url = "https://user:pass@sns.us-east-1.amazonaws.com/SimpleNotificationService-abc123.pem"

      assert {:error, :url_contains_credentials} =
               Url.validate_signing_cert_url(url, @allowed_regions)
    end

    test "rejects non-.pem extension" do
      url = "https://sns.us-east-1.amazonaws.com/cert.html"

      assert {:error, :invalid_cert_url_extension} =
               Url.validate_signing_cert_url(url, @allowed_regions)
    end

    test "rejects missing path" do
      url = "https://sns.us-east-1.amazonaws.com"

      assert {:error, :invalid_cert_url_extension} =
               Url.validate_signing_cert_url(url, @allowed_regions)
    end

    test "rejects invalid URL string" do
      assert {:error, :invalid_url} = Url.validate_signing_cert_url("not-a-url", @allowed_regions)
    end

    test "rejects empty string" do
      assert {:error, :invalid_url} = Url.validate_signing_cert_url("", @allowed_regions)
    end
  end

  describe "validate_subscribe_url/2" do
    test "accepts valid subscribe URL" do
      url =
        "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&TopicArn=arn:aws:sns:us-east-1:123:MyTopic&Token=abc"

      assert {:ok, %URI{}} = Url.validate_subscribe_url(url, @allowed_regions)
    end

    test "rejects HTTP scheme" do
      url = "http://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription"
      assert {:error, :invalid_url_scheme} = Url.validate_subscribe_url(url, @allowed_regions)
    end

    test "rejects host outside allowed regions" do
      url = "https://sns.il-central-1.amazonaws.com/?Action=ConfirmSubscription"
      assert {:error, :invalid_cert_url_host} = Url.validate_subscribe_url(url, @allowed_regions)
    end

    test "rejects URL with userinfo" do
      url = "https://user:pass@sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription"

      assert {:error, :url_contains_credentials} =
               Url.validate_subscribe_url(url, @allowed_regions)
    end
  end

  describe "hostname_regex/1" do
    test "matches valid region hosts" do
      regex = Url.hostname_regex(@allowed_regions)
      assert Regex.match?(regex, "sns.us-east-1.amazonaws.com")
      assert Regex.match?(regex, "sns.us-east-2.amazonaws.com")
      assert Regex.match?(regex, "sns.eu-west-1.amazonaws.com")
      assert Regex.match?(regex, "sns.us-east-1.amazonaws.com.cn")
    end

    test "rejects invalid region hosts" do
      regex = Url.hostname_regex(@allowed_regions)
      refute Regex.match?(regex, "sns.cn-north-1.amazonaws.com")
      refute Regex.match?(regex, "example.com")
      refute Regex.match?(regex, "sns.us-east-1.evil.com")
    end
  end
end
