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
    # TODO: implement Notification canonical string
    {:error, :not_implemented}
  end

  def build(%{"Type" => type} = message)
      when type in ~w(SubscriptionConfirmation UnsubscribeConfirmation) do
    # TODO: implement management message canonical string
    {:error, :not_implemented}
  end

  def build(_message) do
    {:error, :unknown_message_type}
  end
end
