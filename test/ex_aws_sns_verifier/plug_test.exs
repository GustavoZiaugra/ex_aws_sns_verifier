defmodule ExAwsSnsVerifier.PlugTest do
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  @cert_url "https://sns.us-east-1.amazonaws.com/test-key.pem"
  @topic_arn "arn:aws:sns:us-east-1:123456789012:MyTopic"

  setup do
    {pk, _pub} = ExAwsSnsVerifier.TestKeyServer.generate_for_url(@cert_url)
    %{private_key: pk}
  end

  describe "call/2" do
    test "passes through and assigns {:ok, payload} for a valid signed Notification", %{
      private_key: pk
    } do
      {raw, _payload} =
        ExAwsSnsVerifier.TestSupport.build_signed_notification(pk, %{
          topic_arn: @topic_arn,
          signing_cert_url: @cert_url
        })

      conn =
        :post
        |> conn("/sns-endpoint", raw)
        |> put_req_header("content-type", "text/plain")
        |> ExAwsSnsVerifier.Plug.call(
          ExAwsSnsVerifier.Plug.init(
            allowed_topic_arns: [@topic_arn],
            cert_cache: ExAwsSnsVerifier.TestCertCache
          )
        )

      assert conn.status == nil
      assert conn.halted == false
      assert {:ok, payload} = conn.assigns.sns_verification
      assert payload["Type"] == "Notification"
      assert payload["TopicArn"] == @topic_arn
    end

    test "halts with 403 and assigns {:error, reason} for invalid body" do
      conn =
        :post
        |> conn("/sns-endpoint", "not-json")
        |> put_req_header("content-type", "text/plain")
        |> ExAwsSnsVerifier.Plug.call(
          ExAwsSnsVerifier.Plug.init(
            allowed_topic_arns: [@topic_arn],
            cert_cache: ExAwsSnsVerifier.TestCertCache
          )
        )

      assert conn.status == 403
      assert conn.halted == true
      assert {:error, :invalid_json} = conn.assigns.sns_verification
    end

    test "halts with 403 for non-allowlisted topic", %{private_key: pk} do
      {raw, _payload} =
        ExAwsSnsVerifier.TestSupport.build_signed_notification(pk, %{
          topic_arn: "arn:aws:sns:us-east-1:999999999999:EvilTopic",
          signing_cert_url: @cert_url
        })

      conn =
        :post
        |> conn("/sns-endpoint", raw)
        |> put_req_header("content-type", "text/plain")
        |> ExAwsSnsVerifier.Plug.call(
          ExAwsSnsVerifier.Plug.init(
            allowed_topic_arns: [@topic_arn],
            cert_cache: ExAwsSnsVerifier.TestCertCache
          )
        )

      assert conn.status == 403
      assert conn.halted == true
      assert {:error, :topic_not_allowed} = conn.assigns.sns_verification
    end

    test "passes through for SubscriptionConfirmation", %{private_key: pk} do
      payload =
        ExAwsSnsVerifier.TestSupport.build_subscribe_payload(%{
          topic_arn: @topic_arn,
          signing_cert_url: @cert_url
        })

      {:ok, canonical} = ExAwsSnsVerifier.Canonical.build(payload)

      signed =
        Map.put(payload, "Signature", ExAwsSnsVerifier.TestSupport.sign_canonical(canonical, pk))

      raw = Jason.encode!(signed)

      conn =
        :post
        |> conn("/sns-endpoint", raw)
        |> put_req_header("content-type", "text/plain")
        |> ExAwsSnsVerifier.Plug.call(
          ExAwsSnsVerifier.Plug.init(
            allowed_topic_arns: [@topic_arn],
            cert_cache: ExAwsSnsVerifier.TestCertCache
          )
        )

      assert conn.status == nil
      assert conn.halted == false
      assert {:ok, payload_result} = conn.assigns.sns_verification
      assert payload_result["Type"] == "SubscriptionConfirmation"
    end
  end
end
