defmodule ExAwsSnsVerifier.Canonical do
  @moduledoc """
  Construct the canonical string for SNS message signature verification.

  Per AWS documentation, the canonical string is built from specific message
  fields joined with newlines. The exact fields depend on the message type
  (Notification vs SubscriptionConfirmation/UnsubscribeConfirmation).
  """

  @doc """
  Build the canonical string to be used for signature verification.

  The returned string must have a trailing newline appended before being passed
  to `:public_key.verify/4`.
  """
  @spec build(map()) :: {:ok, String.t()} | {:error, atom()}
  def build(%{"Type" => "Notification"} = message) do
    with {:ok, message_val} <- fetch(message, "Message"),
         {:ok, message_id} <- fetch(message, "MessageId"),
         {:ok, timestamp} <- fetch(message, "Timestamp"),
         {:ok, topic_arn} <- fetch(message, "TopicArn"),
         {:ok, type} <- fetch(message, "Type") do
      parts = [
        "Message\n#{message_val}\n",
        "MessageId\n#{message_id}\n",
        optional_part(message, "Subject"),
        optional_part(message, "SubscribeURL"),
        "Timestamp\n#{timestamp}\n",
        "TopicArn\n#{topic_arn}\n",
        "Type\n#{type}\n"
      ]

      {:ok, Enum.join(parts)}
    end
  end

  def build(%{"Type" => type} = message)
      when type in ~w(SubscriptionConfirmation UnsubscribeConfirmation) do
    with {:ok, message_val} <- fetch(message, "Message"),
         {:ok, message_id} <- fetch(message, "MessageId"),
         {:ok, subscribe_url} <- fetch(message, "SubscribeURL"),
         {:ok, timestamp} <- fetch(message, "Timestamp"),
         {:ok, token} <- fetch(message, "Token"),
         {:ok, topic_arn} <- fetch(message, "TopicArn"),
         {:ok, type} <- fetch(message, "Type") do
      parts = [
        "Message\n#{message_val}\n",
        "MessageId\n#{message_id}\n",
        "SubscribeURL\n#{subscribe_url}\n",
        "Timestamp\n#{timestamp}\n",
        "Token\n#{token}\n",
        "TopicArn\n#{topic_arn}\n",
        "Type\n#{type}\n"
      ]

      {:ok, Enum.join(parts)}
    end
  end

  def build(_message) do
    {:error, :unknown_message_type}
  end

  defp fetch(map, key) do
    case Map.fetch(map, key) do
      :error -> {:error, :missing_field}
      ok -> ok
    end
  end

  defp optional_part(message, key) do
    case Map.get(message, key) do
      nil -> ""
      value -> "#{key}\n#{value}\n"
    end
  end
end
