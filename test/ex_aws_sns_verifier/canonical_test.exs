defmodule ExAwsSnsVerifier.CanonicalTest do
  use ExUnit.Case, async: true

  alias ExAwsSnsVerifier.Canonical
  alias ExAwsSnsVerifier.TestSupport

  describe "build/1 for Notification" do
    test "includes Subject field when present" do
      payload = TestSupport.build_notification_payload(message: "Hello", subject: "Test Alert")
      {:ok, result} = Canonical.build(payload)

      assert result ==
               "Message\nHello\nMessageId\n#{payload["MessageId"]}\nSubject\nTest Alert\nTimestamp\n#{payload["Timestamp"]}\nTopicArn\n#{payload["TopicArn"]}\nType\nNotification\n"
    end

    test "omits Subject when nil" do
      payload = TestSupport.build_notification_payload(message: "Hello", subject: nil)
      {:ok, result} = Canonical.build(payload)

      refute result =~ "Subject"
      assert result =~ "Message\nHello\n"
      assert result =~ "Type\nNotification\n"
    end

    test "omits Subject when empty string" do
      payload = TestSupport.build_notification_payload(message: "Hello", subject: "")
      {:ok, result} = Canonical.build(payload)

      refute result =~ "Subject"
    end

    test "with multiline message" do
      payload = TestSupport.build_notification_payload(message: "line1\nline2\nline3")
      {:ok, result} = Canonical.build(payload)

      assert result =~ "Message\nline1\nline2\nline3\n"
    end

    test "trailing newline is present" do
      payload = TestSupport.build_notification_payload()
      {:ok, result} = Canonical.build(payload)

      assert String.ends_with?(result, "\n")
    end

    test "returns error on missing required field" do
      assert {:error, :missing_field} = Canonical.build(%{"Type" => "Notification"})
    end
  end

  describe "build/1 for SubscriptionConfirmation" do
    test "includes all required fields" do
      payload =
        TestSupport.build_subscription_confirmation_payload(
          message: "Subscribe please",
          token: "tok-123"
        )

      {:ok, result} = Canonical.build(payload)

      assert result =~ "Message\nSubscribe please\n"
      assert result =~ "SubscribeURL\n"
      assert result =~ "Tok"
      assert result =~ "tok-123"
      assert result =~ "SubscriptionConfirmation"
      assert String.ends_with?(result, "\n")
    end
  end

  describe "build/1 for UnsubscribeConfirmation" do
    test "includes all required fields" do
      payload =
        TestSupport.build_subscription_confirmation_payload()
        |> Map.put("Type", "UnsubscribeConfirmation")

      {:ok, result} = Canonical.build(payload)
      assert result =~ "UnsubscribeConfirmation"
      assert String.ends_with?(result, "\n")
    end
  end

  describe "build/1 for unknown type" do
    test "returns error" do
      assert {:error, :unknown_message_type} = Canonical.build(%{"Type" => "UnknownType"})
      assert {:error, :unknown_message_type} = Canonical.build(%{})
    end
  end
end
