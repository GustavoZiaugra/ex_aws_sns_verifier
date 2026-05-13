defmodule ExAwsSnsVerifier.PlugTest do
  use ExUnit.Case, async: true

  alias ExAwsSnsVerifier.TestSupport

  @topic_arn "arn:aws:sns:us-east-1:123456789012:MyTopic"
  @cert_url "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-abc123.pem"

  setup do
    {pk, _pub_key} = ExAwsSnsVerifier.TestKeyServer.generate_for_url(@cert_url)
    {:ok, %{private_key: pk}}
  end

  defp build_conn(body, content_type \\ "application/json") do
    Plug.Test.conn(:post, "/hook/sns", body)
    |> Map.put(:req_headers, [{"content-type", content_type}])
  end

  describe "call/2" do
    test "assigns sns_message on valid payload", %{private_key: pk} do
      payload = TestSupport.build_notification_payload(topic_arn: @topic_arn)
      canonical = TestSupport.canonical_for_notification(payload)
      signature = TestSupport.sign_message(canonical, pk)

      raw_body =
        payload
        |> Map.put("Signature", signature)
        |> Jason.encode!()

      conn =
        build_conn(raw_body)
        |> ExAwsSnsVerifier.Plug.call(
          allowed_topic_arns: [@topic_arn],
          cert_cache: ExAwsSnsVerifier.TestCertCache,
          http_client: ExAwsSnsVerifier.TestHttpClient
        )

      assert conn.assigns.sns_message["Type"] == "Notification"
      assert conn.assigns.sns_verified == true
      assert conn.halted == false
    end

    test "halts on invalid payload", %{private_key: pk} do
      payload = TestSupport.build_notification_payload(topic_arn: @topic_arn)
      canonical = TestSupport.canonical_for_notification(payload)
      signature = TestSupport.sign_message(canonical, pk)

      # Tampered signature
      decoded = Base.decode64!(signature)
      <<_::8, rest::binary>> = decoded
      wrong_sig = Base.encode64(<<0::8, rest::binary>>)

      raw_body =
        payload
        |> Map.put("Signature", wrong_sig)
        |> Jason.encode!()

      conn =
        build_conn(raw_body)
        |> ExAwsSnsVerifier.Plug.call(
          allowed_topic_arns: [@topic_arn],
          cert_cache: ExAwsSnsVerifier.TestCertCache,
          http_client: ExAwsSnsVerifier.TestHttpClient
        )

      assert conn.halted == true
      assert conn.status == 400
    end

    test "raises on missing allowed_topic_arns" do
      raw_body = Jason.encode!(%{"Type" => "Notification"})

      assert_raise KeyError, fn ->
        build_conn(raw_body)
        |> ExAwsSnsVerifier.Plug.call([])
      end
    end

    test "halts on unreadable body" do
      conn =
        build_conn("")
        |> Map.put(:req_headers, [])
        |> ExAwsSnsVerifier.Plug.call(
          allowed_topic_arns: [@topic_arn],
          body_reader: fn _conn -> {:error, :closed} end
        )

      assert conn.halted == true
      assert conn.status == 400
    end
  end
end
