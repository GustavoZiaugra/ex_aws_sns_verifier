defmodule ExAwsSnsVerifier.Plug do
  @moduledoc """
  Plug integration for verifying AWS SNS HTTPS message authenticity in
  Plug and Phoenix pipelines.

  Reads the raw request body, runs it through `ExAwsSnsVerifier.verify/2`,
  and assigns the result to `conn.assigns.sns_verification`.

  ## Usage

      plug ExAwsSnsVerifier.Plug,
           allowed_topic_arns: ["arn:aws:sns:us-east-1:123456789012:MyTopic"]

  On success (`{:ok, payload}`), the connection passes through. On failure
  (`{:error, reason}`), the connection is halted with `403 Forbidden`.

  ## Options

  Accepts the same options as `ExAwsSnsVerifier.new/1`:

    * `:allowed_topic_arns` — list of allowed TopicArn values (required)
    * `:allowed_regions` — list of AWS regions for SigningCertURL validation
    * `:timestamp_window_seconds` — replay protection window (default: 3600)
    * `:http_client` — custom HTTP client module
    * `:cert_cache` — custom cert cache module

  ### Body reader

  The `:body_reader` option allows overriding how the raw body is read from
  the connection. Default: `{Plug.Conn, :read_body, []}`.

      plug ExAwsSnsVerifier.Plug,
           allowed_topic_arns: ["..."],
           body_reader: {MyApp, :read_body, []}
  """

  @behaviour Plug

  import Plug.Conn, only: [assign: 3, halt: 1, send_resp: 3]

  defstruct [:verifier, :body_reader]

  @type t :: %__MODULE__{
          verifier: ExAwsSnsVerifier.t(),
          body_reader: {module(), atom(), list()}
        }

  @doc false
  @impl true
  def init(opts) do
    {verifier_opts, plug_opts} =
      Keyword.split(opts, [
        :allowed_topic_arns,
        :allowed_regions,
        :timestamp_window_seconds,
        :http_client,
        :cert_cache
      ])

    body_reader = Keyword.get(plug_opts, :body_reader, {Plug.Conn, :read_body, []})

    %__MODULE__{
      verifier: ExAwsSnsVerifier.new(verifier_opts),
      body_reader: body_reader
    }
  end

  @doc false
  @impl true
  def call(conn, %__MODULE__{verifier: verifier, body_reader: {mod, fun, args}}) do
    case apply(mod, fun, [conn | args]) do
      {:ok, raw_body, conn} ->
        verify_and_assign(conn, verifier, raw_body)

      {:more, raw_body, conn} ->
        verify_and_assign(conn, verifier, raw_body)

      {:error, _reason} ->
        assign(conn, :sns_verification, {:error, :body_read_failed})
        |> halt()
        |> send_resp(403, "SNS verification failed: failed to read request body")
    end
  end

  defp verify_and_assign(conn, verifier, raw_body) do
    case ExAwsSnsVerifier.verify(verifier, raw_body) do
      {:ok, payload} ->
        assign(conn, :sns_verification, {:ok, payload})

      {:error, reason} ->
        assign(conn, :sns_verification, {:error, reason})
        |> halt()
        |> send_resp(403, "SNS verification failed: #{reason}")
    end
  end
end
