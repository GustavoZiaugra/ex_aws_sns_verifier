defmodule ExAwsSnsVerifier.VerificationError do
  defexception [:reason]

  @impl true
  def message(%{reason: reason}) do
    "SNS message verification failed: #{inspect(reason)}"
  end
end
