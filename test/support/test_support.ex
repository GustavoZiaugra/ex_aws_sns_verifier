defmodule ExAwsSnsVerifier.TestSupport do
  @moduledoc """
  Test helpers for generating RSA keypairs, signing SNS payloads, and
  building sample message fixtures.

  All tests use locally generated keypairs — no live AWS calls needed.
  """

  @doc """
  Generate an RSA-2048 keypair for testing.

  Returns `{public_key, private_key}` where:
    - `public_key` is `{:RSAPublicKey, modulus, exponent}`
    - `private_key` is the full `{:RSAPrivateKey, ...}` record
  """
  def generate_keypair do
    pk = :public_key.generate_key({:rsa, 2048, 65_537})
    pub_key = {:RSAPublicKey, elem(pk, 2), elem(pk, 3)}
    {pub_key, pk}
  end

  @doc """
  Sign a canonical string with a private key using RSA-SHA256.

  Returns Base64-encoded signature for inclusion in SNS payload JSON.
  """
  def sign_message(canonical_string, private_key) when is_binary(canonical_string) do
    signature = :public_key.sign(canonical_string, :sha256, private_key)
    Base.encode64(signature)
  end

  @doc """
  Build a valid Notification payload map.

  Accepts overrides via opts.
  """
  def build_notification_payload(opts \\ []) do
    base = %{
      "Type" => "Notification",
      "MessageId" => opts[:message_id] || "77921629-9873-4c0b-82e6-123456789abc",
      "TopicArn" => opts[:topic_arn] || "arn:aws:sns:us-east-1:123456789012:MyTopic",
      "Message" => opts[:message] || ~s({"default":"Hello from SNS"}),
      "Timestamp" => opts[:timestamp] || DateTime.utc_now() |> DateTime.to_iso8601(),
      "SignatureVersion" => "2",
      "Signature" => opts[:signature] || "BASE64_SIGNATURE",
      "SigningCertURL" =>
        opts[:signing_cert_url] ||
          "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-abc123.pem",
      "UnsubscribeURL" => ""
    }

    if opts[:subject] == nil do
      base
    else
      Map.put(base, "Subject", opts[:subject] || "Test Subject")
    end
  end

  @doc """
  Build a valid SubscriptionConfirmation payload map.
  """
  def build_subscription_confirmation_payload(opts \\ []) do
    %{
      "Type" => "SubscriptionConfirmation",
      "MessageId" => opts[:message_id] || "c335b12f-0a26-45b7-8f5e-abc123def456",
      "Token" =>
        opts[:token] ||
          "2336412f37fb687f5d51e6e2425c464c8b5c40d9c1b6d6b1d4c7a5b8e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f",
      "TopicArn" => opts[:topic_arn] || "arn:aws:sns:us-east-1:123456789012:MyTopic",
      "Message" =>
        opts[:message] ||
          "You have chosen to subscribe to the topic arn:aws:sns:us-east-1:123456789012:MyTopic.\nTo confirm the subscription, visit the SubscribeURL included in this message.",
      "SubscribeURL" =>
        opts[:subscribe_url] ||
          "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&TopicArn=arn:aws:sns:us-east-1:123456789012:MyTopic&Token=2336412f37fb687f5d51e6e2425c464c8b5c40d9c1b6d6b1d4c7a5b8e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f",
      "Timestamp" => opts[:timestamp] || DateTime.utc_now() |> DateTime.to_iso8601(),
      "SignatureVersion" => "2",
      "Signature" => opts[:signature] || "BASE64_SIGNATURE",
      "SigningCertURL" =>
        opts[:signing_cert_url] ||
          "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-abc123.pem"
    }
  end

  @doc """
  Build a canonical string for a Notification message.

  Matches the output of `ExAwsSnsVerifier.Canonical.build/1`.
  """
  def canonical_for_notification(payload) do
    [
      "Message\n#{payload["Message"]}\n",
      "MessageId\n#{payload["MessageId"]}\n",
      if(payload["Subject"] && payload["Subject"] != "",
        do: "Subject\n#{payload["Subject"]}\n"
      ),
      "Timestamp\n#{payload["Timestamp"]}\n",
      "TopicArn\n#{payload["TopicArn"]}\n",
      "Type\n#{payload["Type"]}\n"
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.join()
  end

  @doc """
  Build a canonical string for SubscriptionConfirmation/UnsubscribeConfirmation.
  """
  def canonical_for_confirmation(payload) do
    [
      "Message\n#{payload["Message"]}\n",
      "MessageId\n#{payload["MessageId"]}\n",
      "SubscribeURL\n#{payload["SubscribeURL"]}\n",
      "Timestamp\n#{payload["Timestamp"]}\n",
      "Token\n#{payload["Token"]}\n",
      "TopicArn\n#{payload["TopicArn"]}\n",
      "Type\n#{payload["Type"]}\n"
    ]
    |> Enum.join()
  end
end
