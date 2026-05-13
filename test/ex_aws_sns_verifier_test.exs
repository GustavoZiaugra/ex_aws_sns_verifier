defmodule ExAwsSnsVerifierTest do
  use ExUnit.Case

  alias ExAwsSnsVerifier.TestSupport

  @topic_arn "arn:aws:sns:us-east-1:123456789012:MyTopic"
  @cert_url "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-abc123.pem"

  setup do
    # Generate a fresh keypair for each test, stored for this cert URL
    {pk, pub_key} = ExAwsSnsVerifier.TestKeyServer.generate_for_url(@cert_url)
    {:ok, %{private_key: pk, public_key: pub_key}}
  end

  describe "verify/2 — full integration" do
    test "verifies a Notification payload with Subject", %{private_key: pk} do
      payload = TestSupport.build_notification_payload(topic_arn: @topic_arn)
      canonical = TestSupport.canonical_for_notification(payload)
      signature = TestSupport.sign_message(canonical, pk)

      raw_body =
        payload
        |> Map.put("Signature", signature)
        |> Jason.encode!()

      assert {:ok, result} =
               ExAwsSnsVerifier.verify(raw_body,
                 allowed_topic_arns: [@topic_arn],
                 cert_cache: ExAwsSnsVerifier.TestCertCache,
                 http_client: ExAwsSnsVerifier.TestHttpClient
               )

      assert result["Type"] == "Notification"
      assert result["TopicArn"] == @topic_arn
    end

    test "verifies a Notification payload without Subject", %{private_key: pk} do
      payload = TestSupport.build_notification_payload(topic_arn: @topic_arn, subject: nil)
      canonical = TestSupport.canonical_for_notification(payload)
      signature = TestSupport.sign_message(canonical, pk)

      raw_body =
        payload
        |> Map.put("Signature", signature)
        |> Jason.encode!()

      assert {:ok, _result} =
               ExAwsSnsVerifier.verify(raw_body,
                 allowed_topic_arns: [@topic_arn],
                 cert_cache: ExAwsSnsVerifier.TestCertCache,
                 http_client: ExAwsSnsVerifier.TestHttpClient
               )
    end

    test "verifies a SubscriptionConfirmation payload", %{private_key: pk} do
      payload = TestSupport.build_subscription_confirmation_payload(topic_arn: @topic_arn)
      canonical = TestSupport.canonical_for_confirmation(payload)
      signature = TestSupport.sign_message(canonical, pk)

      raw_body =
        payload
        |> Map.put("Signature", signature)
        |> Jason.encode!()

      assert {:ok, result} =
               ExAwsSnsVerifier.verify(raw_body,
                 allowed_topic_arns: [@topic_arn],
                 cert_cache: ExAwsSnsVerifier.TestCertCache,
                 http_client: ExAwsSnsVerifier.TestHttpClient
               )

      assert result["Type"] == "SubscriptionConfirmation"
    end

    test "verifies an UnsubscribeConfirmation payload", %{private_key: pk} do
      payload =
        TestSupport.build_subscription_confirmation_payload(topic_arn: @topic_arn)
        |> Map.put("Type", "UnsubscribeConfirmation")

      canonical = TestSupport.canonical_for_confirmation(payload)
      signature = TestSupport.sign_message(canonical, pk)

      raw_body =
        payload
        |> Map.put("Signature", signature)
        |> Jason.encode!()

      assert {:ok, result} =
               ExAwsSnsVerifier.verify(raw_body,
                 allowed_topic_arns: [@topic_arn],
                 cert_cache: ExAwsSnsVerifier.TestCertCache,
                 http_client: ExAwsSnsVerifier.TestHttpClient
               )

      assert result["Type"] == "UnsubscribeConfirmation"
    end
  end

  describe "verify/2 — error cases" do
    test "returns error for tampered Signature", %{private_key: pk} do
      payload = TestSupport.build_notification_payload(topic_arn: @topic_arn)
      canonical = TestSupport.canonical_for_notification(payload)
      signature = TestSupport.sign_message(canonical, pk)

      # Decode, flip a byte, re-encode to keep valid base64
      decoded = Base.decode64!(signature)
      <<_::8, rest::binary>> = decoded
      wrong_sig = Base.encode64(<<0::8, rest::binary>>)

      raw_body =
        payload
        |> Map.put("Signature", wrong_sig)
        |> Jason.encode!()

      assert {:error, :signature_invalid} =
               ExAwsSnsVerifier.verify(raw_body,
                 allowed_topic_arns: [@topic_arn],
                 cert_cache: ExAwsSnsVerifier.TestCertCache,
                 http_client: ExAwsSnsVerifier.TestHttpClient
               )
    end

    test "returns error for invalid JSON" do
      assert {:error, :invalid_json} =
               ExAwsSnsVerifier.verify("not json",
                 allowed_topic_arns: [@topic_arn],
                 cert_cache: ExAwsSnsVerifier.TestCertCache,
                 http_client: ExAwsSnsVerifier.TestHttpClient
               )
    end

    test "returns error for unknown message type" do
      raw = Jason.encode!(%{"Type" => "Unknown"})

      assert {:error, :unknown_message_type} =
               ExAwsSnsVerifier.verify(raw,
                 allowed_topic_arns: [@topic_arn],
                 cert_cache: ExAwsSnsVerifier.TestCertCache,
                 http_client: ExAwsSnsVerifier.TestHttpClient
               )
    end

    test "returns error for SignatureVersion 1" do
      payload = TestSupport.build_notification_payload(topic_arn: @topic_arn)
      payload = Map.put(payload, "SignatureVersion", "1")

      assert {:error, :unsupported_signature_version} =
               ExAwsSnsVerifier.verify(Jason.encode!(payload),
                 allowed_topic_arns: [@topic_arn],
                 cert_cache: ExAwsSnsVerifier.TestCertCache,
                 http_client: ExAwsSnsVerifier.TestHttpClient
               )
    end

    test "returns error for missing SignatureVersion" do
      payload = TestSupport.build_notification_payload(topic_arn: @topic_arn)
      payload = Map.drop(payload, ["SignatureVersion"])

      assert {:error, :missing_signature_version} =
               ExAwsSnsVerifier.verify(Jason.encode!(payload),
                 allowed_topic_arns: [@topic_arn],
                 cert_cache: ExAwsSnsVerifier.TestCertCache,
                 http_client: ExAwsSnsVerifier.TestHttpClient
               )
    end

    test "returns error when TopicArn not allowed" do
      payload =
        TestSupport.build_notification_payload(
          topic_arn: "arn:aws:sns:us-east-1:1:OtherTopic"
        )

      assert {:error, :topic_not_allowed} =
               ExAwsSnsVerifier.verify(Jason.encode!(payload),
                 allowed_topic_arns: [@topic_arn],
                 cert_cache: ExAwsSnsVerifier.TestCertCache,
                 http_client: ExAwsSnsVerifier.TestHttpClient
               )
    end

    test "returns error for missing TopicArn" do
      payload = TestSupport.build_notification_payload(topic_arn: @topic_arn)
      payload = Map.drop(payload, ["TopicArn"])

      assert {:error, :missing_topic_arn} =
               ExAwsSnsVerifier.verify(Jason.encode!(payload),
                 allowed_topic_arns: [@topic_arn],
                 cert_cache: ExAwsSnsVerifier.TestCertCache,
                 http_client: ExAwsSnsVerifier.TestHttpClient
               )
    end

    test "returns error for missing SigningCertURL" do
      payload = TestSupport.build_notification_payload(topic_arn: @topic_arn)
      payload = Map.drop(payload, ["SigningCertURL"])

      assert {:error, :missing_signing_cert_url} =
               ExAwsSnsVerifier.verify(Jason.encode!(payload),
                 allowed_topic_arns: [@topic_arn],
                 cert_cache: ExAwsSnsVerifier.TestCertCache,
                 http_client: ExAwsSnsVerifier.TestHttpClient
               )
    end

    test "returns error for invalid cert URL host" do
      payload =
        TestSupport.build_notification_payload(
          topic_arn: @topic_arn,
          signing_cert_url: "https://evil.com/cert.pem"
        )

      assert {:error, :invalid_cert_url_host} =
               ExAwsSnsVerifier.verify(Jason.encode!(payload),
                 allowed_topic_arns: [@topic_arn],
                 cert_cache: ExAwsSnsVerifier.TestCertCache,
                 http_client: ExAwsSnsVerifier.TestHttpClient
               )
    end

    test "returns error for missing Signature" do
      payload = TestSupport.build_notification_payload(topic_arn: @topic_arn)
      payload = Map.drop(payload, ["Signature"])

      assert {:error, :missing_signature} =
               ExAwsSnsVerifier.verify(Jason.encode!(payload),
                 allowed_topic_arns: [@topic_arn],
                 cert_cache: ExAwsSnsVerifier.TestCertCache,
                 http_client: ExAwsSnsVerifier.TestHttpClient
               )
    end

    test "returns error for missing Timestamp" do
      payload = TestSupport.build_notification_payload(topic_arn: @topic_arn)
      payload = Map.drop(payload, ["Timestamp"])

      assert {:error, :missing_timestamp} =
               ExAwsSnsVerifier.verify(Jason.encode!(payload),
                 allowed_topic_arns: [@topic_arn],
                 cert_cache: ExAwsSnsVerifier.TestCertCache,
                 http_client: ExAwsSnsVerifier.TestHttpClient
               )
    end
  end

  describe "verify!/2" do
    test "returns payload on success", %{private_key: pk} do
      payload = TestSupport.build_notification_payload(topic_arn: @topic_arn)
      canonical = TestSupport.canonical_for_notification(payload)
      signature = TestSupport.sign_message(canonical, pk)

      raw_body =
        payload
        |> Map.put("Signature", signature)
        |> Jason.encode!()

      assert %{"Type" => "Notification"} =
               ExAwsSnsVerifier.verify!(raw_body,
                 allowed_topic_arns: [@topic_arn],
                 cert_cache: ExAwsSnsVerifier.TestCertCache,
                 http_client: ExAwsSnsVerifier.TestHttpClient
               )
    end

    test "raises on failure" do
      assert_raise ExAwsSnsVerifier.VerificationError, fn ->
        ExAwsSnsVerifier.verify!("invalid json",
          allowed_topic_arns: [@topic_arn],
          cert_cache: ExAwsSnsVerifier.TestCertCache,
          http_client: ExAwsSnsVerifier.TestHttpClient
        )
      end
    end
  end

  describe "new/1" do
    test "creates verifier struct with defaults" do
      verifier = ExAwsSnsVerifier.new(allowed_topic_arns: [@topic_arn])
      assert verifier.allowed_topic_arns == [@topic_arn]
      assert is_list(verifier.allowed_regions)
      assert length(verifier.allowed_regions) > 10
      assert verifier.timestamp_window_seconds == 3_600
      assert verifier.http_client == ExAwsSnsVerifier.Cert.HttpClient
      assert verifier.cert_cache == ExAwsSnsVerifier.Cert.Cache
    end

    test "creates verifier struct with overrides" do
      verifier =
        ExAwsSnsVerifier.new(
          allowed_topic_arns: [@topic_arn],
          allowed_regions: ["us-east-1"],
          timestamp_window_seconds: 300,
          http_client: :custom_client,
          cert_cache: :custom_cache
        )

      assert verifier.allowed_regions == ["us-east-1"]
      assert verifier.timestamp_window_seconds == 300
      assert verifier.http_client == :custom_client
      assert verifier.cert_cache == :custom_cache
    end

    test "requires allowed_topic_arns" do
      assert_raise KeyError, fn ->
        ExAwsSnsVerifier.new()
      end
    end
  end

  describe "Verifier struct API" do
    test "verify/2 accepts verifier struct", %{private_key: pk} do
      payload = TestSupport.build_notification_payload(topic_arn: @topic_arn)
      canonical = TestSupport.canonical_for_notification(payload)
      signature = TestSupport.sign_message(canonical, pk)

      raw_body =
        payload
        |> Map.put("Signature", signature)
        |> Jason.encode!()

      verifier =
        ExAwsSnsVerifier.new(
          allowed_topic_arns: [@topic_arn],
          cert_cache: ExAwsSnsVerifier.TestCertCache,
          http_client: ExAwsSnsVerifier.TestHttpClient
        )

      assert {:ok, _result} = ExAwsSnsVerifier.verify(verifier, raw_body)
    end

    test "verify!/2 accepts verifier struct", %{private_key: pk} do
      payload = TestSupport.build_notification_payload(topic_arn: @topic_arn)
      canonical = TestSupport.canonical_for_notification(payload)
      signature = TestSupport.sign_message(canonical, pk)

      raw_body =
        payload
        |> Map.put("Signature", signature)
        |> Jason.encode!()

      verifier =
        ExAwsSnsVerifier.new(
          allowed_topic_arns: [@topic_arn],
          cert_cache: ExAwsSnsVerifier.TestCertCache,
          http_client: ExAwsSnsVerifier.TestHttpClient
        )

      assert %{"Type" => "Notification"} = ExAwsSnsVerifier.verify!(verifier, raw_body)
    end
  end
end
