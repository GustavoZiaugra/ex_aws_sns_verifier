defmodule ExAwsSnsVerifier.TestCertCache do
  @moduledoc false
  @behaviour ExAwsSnsVerifier.Cert.HttpClientBehaviour

  @doc false
  def get(url), do: ExAwsSnsVerifier.TestKeyServer.get_public_key(url)

  @doc false
  def put(_url, _value), do: :ok
end
