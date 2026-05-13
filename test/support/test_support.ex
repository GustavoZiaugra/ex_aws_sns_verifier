defmodule ExAwsSnsVerifier.TestSupport do
  @moduledoc false

  @doc """
  Build an SNS notification payload that matches the canonical string specification.
  """
  def build_notification_payload(opts \\ []) do
    %{
      "Type" => "Notification",
      "MessageId" => opts[:message_id] || "test-message-id",
      "TopicArn" => opts[:topic_arn] || "arn:aws:sns:us-east-1:123456789012:MyTopic",
      "Subject" => opts[:subject] || "Test Subject",
      "Message" => opts[:message] || "Hello from SNS!",
      "Timestamp" => opts[:timestamp] || DateTime.utc_now() |> DateTime.to_iso8601(),
      "SignatureVersion" => opts[:signature_version] || "2",
      "Signature" => opts[:signature] || "",
      "SigningCertURL" =>
        opts[:signing_cert_url] || "https://sns.us-east-1.amazonaws.com/key.pem",
      "SubscribeURL" => opts[:subscribe_url] || "https://sns.us-east-1.amazonaws.com/confirm",
      "UnsubscribeURL" =>
        opts[:unsubscribe_url] || "https://sns.us-east-1.amazonaws.com/unsubscribe"
    }
  end

  @doc """
  Build an SNS SubscriptionConfirmation payload.
  """
  def build_subscribe_payload(opts \\ []) do
    %{
      "Type" => "SubscriptionConfirmation",
      "MessageId" => opts[:message_id] || "test-sub-message-id",
      "TopicArn" => opts[:topic_arn] || "arn:aws:sns:us-east-1:123456789012:MyTopic",
      "Message" => opts[:message] || "You have chosen to subscribe...",
      "Timestamp" => opts[:timestamp] || DateTime.utc_now() |> DateTime.to_iso8601(),
      "SignatureVersion" => opts[:signature_version] || "2",
      "Signature" => opts[:signature] || "",
      "SigningCertURL" =>
        opts[:signing_cert_url] || "https://sns.us-east-1.amazonaws.com/key.pem",
      "SubscribeURL" => opts[:subscribe_url] || "https://sns.us-east-1.amazonaws.com/confirm",
      "Token" => opts[:token] || "test-token-123"
    }
  end

  @doc """
  Sign a canonical string with a private key and return base64-encoded signature.
  """
  def sign_canonical(canonical, private_key) do
    signature = :public_key.sign(canonical, :sha256, private_key)
    Base.encode64(signature)
  end

  @doc """
  Generate a full signed notification payload ready for the verify pipeline.
  Returns the raw JSON body and the private key used.
  """
  def build_signed_notification(private_key, opts \\ []) do
    payload = build_notification_payload(opts)
    {:ok, canonical} = ExAwsSnsVerifier.Canonical.build(payload)
    sig = sign_canonical(canonical, private_key)
    signed = Map.put(payload, "Signature", sig)
    {Jason.encode!(signed), signed}
  end
end
