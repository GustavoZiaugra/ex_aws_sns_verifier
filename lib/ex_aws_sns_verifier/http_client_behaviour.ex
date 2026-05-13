defmodule ExAwsSnsVerifier.Cert.HttpClientBehaviour do
  @moduledoc """
  Behaviour for pluggable HTTP clients used to fetch signing certificates.

  Implement this module to use a custom HTTP client (Tesla, Req, Finch, etc.)
  instead of the default `:httpc`-based client.
  """

  @doc """
  Fetch the contents of a URL. Must return `{:ok, body}` or `{:error, reason}`.
  """
  @callback get(url :: String.t()) :: {:ok, String.t()} | {:error, term()}
end
