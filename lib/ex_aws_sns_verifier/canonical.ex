defmodule ExAwsSnsVerifier.Canonical do
  @moduledoc """
  Construct the canonical string for SNS message signature verification.

  Per [AWS documentation](
  https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html),
  the canonical string is built from specific message fields, each on its own
  line (`key\\nvalue\\n`), with no extra whitespace. The result has a trailing
  newline, which is required by `:public_key.verify/4`.

  The exact fields differ by message type:

  - **Notification**: `Message`, `MessageId`, `Subject` (if present &
    non-empty), `Timestamp`, `TopicArn`, `Type`
  - **SubscriptionConfirmation / UnsubscribeConfirmation**: `Message`,
    `MessageId`, `SubscribeURL`, `Timestamp`, `Token`, `TopicArn`, `Type`
  """

  @doc """
  Build the canonical string for signature verification.

  Follows the same algorithm as Ruby's `Aws::SNS::MessageVerifier`: each
  signable key present in the message is emitted as `key\\nvalue\\n`, joined
  in the order of the signable key list.

  Returns `{:ok, canonical_string}` or `{:error, reason}`.
  """
  @spec build(map()) :: {:ok, String.t()} | {:error, atom()}
  def build(%{"Type" => "Notification"} = message) do
    with {:ok, msg} <- required(message, "Message"),
         {:ok, msg_id} <- required(message, "MessageId"),
         {:ok, ts} <- required(message, "Timestamp"),
         {:ok, arn} <- required(message, "TopicArn") do
      subject = message["Subject"]

      parts = [
        "Message\n#{msg}\n",
        "MessageId\n#{msg_id}\n",
        if(subject && subject != "", do: "Subject\n#{subject}\n"),
        "Timestamp\n#{ts}\n",
        "TopicArn\n#{arn}\n",
        "Type\nNotification\n"
      ]

      {:ok, Enum.join(Enum.reject(parts, &is_nil/1))}
    end
  end

  def build(%{"Type" => type} = message)
      when type in ~w(SubscriptionConfirmation UnsubscribeConfirmation) do
    with {:ok, msg} <- required(message, "Message"),
         {:ok, msg_id} <- required(message, "MessageId"),
         {:ok, url} <- required(message, "SubscribeURL"),
         {:ok, ts} <- required(message, "Timestamp"),
         {:ok, token} <- required(message, "Token"),
         {:ok, arn} <- required(message, "TopicArn") do
      {:ok,
       "Message\n#{msg}\nMessageId\n#{msg_id}\nSubscribeURL\n#{url}\nTimestamp\n#{ts}\nToken\n#{token}\nTopicArn\n#{arn}\nType\n#{type}\n"}
    end
  end

  def build(_message) do
    {:error, :unknown_message_type}
  end

  # ── helper ─────────────────────────────────────────────────────────────────

  defp required(message, key) do
    case message[key] do
      nil -> {:error, :missing_field}
      val when is_binary(val) -> {:ok, val}
    end
  end
end
