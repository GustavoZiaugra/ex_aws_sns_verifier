defmodule ExAwsSnsVerifier.Plug do
  @moduledoc """
  A Plug for verifying AWS SNS message authenticity in a Plug/Phoenix pipeline.

  ## Usage

  In a Phoenix router (or any Plug pipeline):

      pipeline :sns do
        plug ExAwsSnsVerifier.Plug,
          allowed_topic_arns: ["arn:aws:sns:us-east-1:123456789012:MyTopic"]
      end

      scope "/hook", MyAppWeb do
        pipe_through :sns
        post "/sns", SNSController, :notification
      end

  When verification succeeds, the decoded JSON payload is assigned to
  `conn.assigns.sns_message`.

  When verification fails, the Plug halts the connection with a 400 or 500
  status and returns the error reason in the body.

  ## Options

  All options are forwarded to `ExAwsSnsVerifier.new/1`:

    * `:allowed_topic_arns` — **required**, list of allowed TopicArn values
    * `:allowed_regions` — list of AWS regions (default: all commercial)
    * `:timestamp_window_seconds` — replay window (default: 3600)
    * `:http_client` — custom HTTP client module
    * `:cert_cache` — custom cert cache module
    * `:body_reader` — custom function to read the request body
      (default: reads from `conn` via `Plug.Conn.read_body/1`)
      Signature: `(Plug.Conn.t()) :: {:ok, binary(), Plug.Conn.t()}`
  """

  @behaviour Plug

  @type option :: {:body_reader, function()} | {:allowed_topic_arns, [String.t()]} | term()

  @impl true
  @spec init(keyword()) :: keyword()
  def init(opts) do
    opts
  end

  @impl true
  @spec call(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
  def call(conn, opts) do
    body_reader = Keyword.get(opts, :body_reader, &default_body_reader/1)
    verify_opts = Keyword.delete(opts, :body_reader)

    verifier = ExAwsSnsVerifier.new(verify_opts)

    case body_reader.(conn) do
      {:ok, raw_body, conn} ->
        verify_message(conn, verifier, raw_body)

      {:error, reason} ->
        halt_conn(conn, 400, "Failed to read body: #{inspect(reason)}")
    end
  end

  # ── private ────────────────────────────────────────────────────────────────

  defp default_body_reader(conn) do
    Plug.Conn.read_body(conn, length: 200_000, read_length: 200_000)
  end

  defp verify_message(conn, verifier, raw_body) do
    case ExAwsSnsVerifier.verify(verifier, raw_body) do
      {:ok, payload} ->
        conn
        |> Plug.Conn.assign(:sns_message, payload)
        |> Plug.Conn.assign(:sns_verified, true)

      {:error, reason} ->
        halt_conn(conn, 400, "SNS verification failed: #{reason}")
    end
  end

  defp halt_conn(conn, status, message) do
    conn
    |> Plug.Conn.put_resp_content_type("text/plain")
    |> Plug.Conn.send_resp(status, message)
    |> Plug.Conn.halt()
  end
end
