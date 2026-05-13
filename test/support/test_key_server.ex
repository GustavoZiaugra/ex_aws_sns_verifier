defmodule ExAwsSnsVerifier.TestKeyServer do
  @moduledoc false

  @table :ex_aws_sns_test_keys

  def start_link do
    case :ets.info(@table) do
      :undefined ->
        _ = :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
        :ok

      _ ->
        :ok
    end
  end

  def generate_for_url(url) do
    rsa_key = :public_key.generate_key({:rsa, 2048, 65_537})
    public_key = {:RSAPublicKey, elem(rsa_key, 2), elem(rsa_key, 3)}
    :ets.insert(@table, {url, public_key, rsa_key})
    {rsa_key, public_key}
  end

  def get_public_key(url) do
    case :ets.lookup(@table, url) do
      [{^url, public_key, _private_key}] -> {:ok, public_key}
      _ -> :not_found
    end
  end
end
