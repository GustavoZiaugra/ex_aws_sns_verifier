defmodule ExAwsSnsVerifier.TestSupport do
  @moduledoc false

  @notification_fields %{
    "Type" => "Notification",
    "MessageId" => "test-message-id",
    "TopicArn" => "arn:aws:sns:us-east-1:123456789012:MyTopic",
    "Subject" => "Test Subject",
    "Message" => "Hello from SNS!",
    "SignatureVersion" => "2",
    "Signature" => "",
    "SigningCertURL" => "https://sns.us-east-1.amazonaws.com/key.pem",
    "SubscribeURL" => "https://sns.us-east-1.amazonaws.com/confirm",
    "UnsubscribeURL" => "https://sns.us-east-1.amazonaws.com/unsubscribe"
  }

  @subscribe_fields %{
    "Type" => "SubscriptionConfirmation",
    "MessageId" => "test-sub-message-id",
    "TopicArn" => "arn:aws:sns:us-east-1:123456789012:MyTopic",
    "Message" => "You have chosen to subscribe...",
    "SignatureVersion" => "2",
    "Signature" => "",
    "SigningCertURL" => "https://sns.us-east-1.amazonaws.com/key.pem",
    "SubscribeURL" => "https://sns.us-east-1.amazonaws.com/confirm",
    "Token" => "test-token-123"
  }

  @key_mapping %{
    message_id: "MessageId",
    topic_arn: "TopicArn",
    subject: "Subject",
    message: "Message",
    signature_version: "SignatureVersion",
    signature: "Signature",
    signing_cert_url: "SigningCertURL",
    subscribe_url: "SubscribeURL",
    unsubscribe_url: "UnsubscribeURL",
    token: "Token",
    timestamp: "Timestamp"
  }

  def build_notification_payload(opts_or_map \\ []) do
    overrides = normalize_opts(opts_or_map)
    timestamp = Map.get(overrides, "Timestamp", DateTime.utc_now() |> DateTime.to_iso8601())
    @notification_fields |> Map.merge(overrides) |> Map.put("Timestamp", timestamp)
  end

  def build_subscribe_payload(opts_or_map \\ []) do
    overrides = normalize_opts(opts_or_map)
    timestamp = Map.get(overrides, "Timestamp", DateTime.utc_now() |> DateTime.to_iso8601())
    @subscribe_fields |> Map.merge(overrides) |> Map.put("Timestamp", timestamp)
  end

  defp normalize_opts(opts) when is_list(opts) do
    Enum.into(opts, %{}, fn {k, v} -> {Map.get(@key_mapping, k, Atom.to_string(k)), v} end)
  end

  defp normalize_opts(map) when is_map(map) do
    Map.new(map, fn {k, v} -> {Map.get(@key_mapping, k, Atom.to_string(k)), v} end)
  end

  def sign_canonical(canonical, private_key) do
    :public_key.sign(canonical, :sha256, private_key) |> Base.encode64()
  end

  def build_signed_notification(private_key, opts_or_map \\ []) do
    payload = build_notification_payload(opts_or_map)
    {:ok, canonical} = ExAwsSnsVerifier.Canonical.build(payload)
    signed = Map.put(payload, "Signature", sign_canonical(canonical, private_key))
    {Jason.encode!(signed), signed}
  end
end
