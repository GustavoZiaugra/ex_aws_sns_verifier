defmodule ExAwsSnsVerifierTest do
  use ExUnit.Case
  doctest ExAwsSnsVerifier

  @cert_url "https://sns.us-east-1.amazonaws.com/test-key.pem"
  @topic_arn "arn:aws:sns:us-east-1:123456789012:MyTopic"
  @verifier ExAwsSnsVerifier.new(
              allowed_topic_arns: [@topic_arn],
              cert_cache: ExAwsSnsVerifier.TestCertCache
            )

  setup do
    {pk, pub} = ExAwsSnsVerifier.TestKeyServer.generate_for_url(@cert_url)
    %{private_key: pk, public_key: pub}
  end

  describe "verify/2" do
    test "returns {:ok, payload} for a valid signed Notification", %{private_key: pk} do
      {raw, _payload} =
        ExAwsSnsVerifier.TestSupport.build_signed_notification(pk, %{
          topic_arn: @topic_arn,
          signing_cert_url: @cert_url
        })

      assert {:ok, result} = ExAwsSnsVerifier.verify(@verifier, raw)
      assert result["Type"] == "Notification"
      assert result["TopicArn"] == @topic_arn
    end

    test "returns {:error, :topic_not_allowed} for non-allowlisted topic", %{private_key: pk} do
      {raw, _payload} =
        ExAwsSnsVerifier.TestSupport.build_signed_notification(pk, %{
          topic_arn: "arn:aws:sns:us-east-1:999999999999:EvilTopic",
          signing_cert_url: @cert_url
        })

      assert {:error, :topic_not_allowed} = ExAwsSnsVerifier.verify(@verifier, raw)
    end

    test "returns {:error, :invalid_json} for malformed body" do
      assert {:error, :invalid_json} = ExAwsSnsVerifier.verify(@verifier, "not-json")
    end

    test "returns {:error, :unknown_message_type} for unsupported type" do
      raw = Jason.encode!(%{"Type" => "SomethingElse"})
      assert {:error, :unknown_message_type} = ExAwsSnsVerifier.verify(@verifier, raw)
    end

    test "returns {:error, :unsupported_signature_version} for version 1" do
      raw =
        Jason.encode!(%{
          "Type" => "Notification",
          "SignatureVersion" => "1",
          "MessageId" => "id",
          "TopicArn" => @topic_arn,
          "Message" => "test",
          "Timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
        })

      assert {:error, :unsupported_signature_version} = ExAwsSnsVerifier.verify(@verifier, raw)
    end

    test "returns {:error, :signature_invalid} for tampered signature", %{private_key: pk} do
      {raw, _payload} =
        ExAwsSnsVerifier.TestSupport.build_signed_notification(pk, %{
          topic_arn: @topic_arn,
          signing_cert_url: @cert_url
        })

      # Corrupt the signature by flipping a byte
      decoded = Jason.decode!(raw)
      sig = decoded["Signature"]
      decoded_sig = Base.decode64!(sig)
      <<_::8, rest::binary>> = decoded_sig
      corrupted_sig = Base.encode64(<<0::8, rest::binary>>)
      corrupted = Map.put(decoded, "Signature", corrupted_sig)

      assert {:error, :signature_invalid} =
               ExAwsSnsVerifier.verify(@verifier, Jason.encode!(corrupted))
    end

    test "returns {:error, :missing_signing_cert_url} when no SigningCertURL" do
      raw =
        Jason.encode!(%{
          "Type" => "Notification",
          "SignatureVersion" => "2",
          "Signature" => "AAAA",
          "MessageId" => "id",
          "TopicArn" => @topic_arn,
          "Message" => "test",
          "Timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
        })

      assert {:error, :missing_signing_cert_url} = ExAwsSnsVerifier.verify(@verifier, raw)
    end

    test "returns {:error, :missing_timestamp} when Timestamp is missing" do
      raw = Jason.encode!(%{"Type" => "Notification", "SignatureVersion" => "2"})
      assert {:error, :missing_timestamp} = ExAwsSnsVerifier.verify(@verifier, raw)
    end

    test "returns {:error, :invalid_cert_url} for HTTP cert URL", %{private_key: pk} do
      verifier =
        ExAwsSnsVerifier.new(
          allowed_topic_arns: [@topic_arn],
          cert_cache: ExAwsSnsVerifier.TestCertCache
        )

      {raw, _payload} =
        ExAwsSnsVerifier.TestSupport.build_signed_notification(pk, %{
          topic_arn: @topic_arn,
          signing_cert_url: "http://sns.us-east-1.amazonaws.com/key.pem"
        })

      assert {:error, :invalid_cert_url} = ExAwsSnsVerifier.verify(verifier, raw)
    end

    test "returns {:error, :timestamp_out_of_window} for old timestamp", %{private_key: pk} do
      old_ts = DateTime.utc_now() |> DateTime.add(-7200, :second) |> DateTime.to_iso8601()

      verifier =
        ExAwsSnsVerifier.new(
          allowed_topic_arns: [@topic_arn],
          cert_cache: ExAwsSnsVerifier.TestCertCache,
          timestamp_window_seconds: 300
        )

      {raw, _payload} =
        ExAwsSnsVerifier.TestSupport.build_signed_notification(pk, %{
          topic_arn: @topic_arn,
          signing_cert_url: @cert_url,
          timestamp: old_ts
        })

      assert {:error, :timestamp_out_of_window} = ExAwsSnsVerifier.verify(verifier, raw)
    end
  end

  describe "verify!/2" do
    test "returns payload on success", %{private_key: pk} do
      {raw, _payload} =
        ExAwsSnsVerifier.TestSupport.build_signed_notification(pk, %{
          topic_arn: @topic_arn,
          signing_cert_url: @cert_url
        })

      assert %{"Type" => "Notification"} = ExAwsSnsVerifier.verify!(@verifier, raw)
    end

    test "raises on failure" do
      assert_raise ExAwsSnsVerifier.VerificationError, fn ->
        ExAwsSnsVerifier.verify!(@verifier, "not-json")
      end
    end
  end

  describe "new/1" do
    test "requires allowed_topic_arns" do
      assert_raise KeyError, fn ->
        ExAwsSnsVerifier.new()
      end
    end

    test "sets default values" do
      v = ExAwsSnsVerifier.new(allowed_topic_arns: ["arn:test"])
      assert v.timestamp_window_seconds == 3600
      assert v.cert_cache == ExAwsSnsVerifier.Cert.Cache
      assert v.http_client == ExAwsSnsVerifier.Cert.HttpClient
      assert v.allowed_regions |> is_list()
    end
  end
end
