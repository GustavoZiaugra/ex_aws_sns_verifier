defmodule ExAwsSnsVerifier.Url do
  @moduledoc """
  URL host validation helpers for AWS SNS signing cert and subscribe URLs.

  Hardens `SigningCertURL` and `SubscribeURL` parsing by:
  - Requiring HTTPS scheme
  - Validating host matches `sns.<region>.amazonaws.com(.cn)?` pattern
  - Rejecting URLs with userinfo (credentials in URL)
  - Requiring `.pem` extension for cert URLs
  """

  @doc """
  Validate and parse a SigningCertURL.

  Returns `{:ok, uri}` on success or `{:error, :invalid_cert_url}` on failure.

  Validation rules:
  1. Must be HTTPS
  2. Host must match `sns.<region>.amazonaws.com` or `.com.cn`
  3. The region must be in the allowed_regions list
  4. Must not contain userinfo (credentials in URL)
  5. Path must end in `.pem`
  """
  @spec validate_signing_cert_url(String.t(), [String.t()]) :: {:ok, URI.t()} | {:error, atom()}
  def validate_signing_cert_url(url, allowed_regions) when is_binary(url) do
    with {:ok, uri} <- parse_url(url),
         :ok <- validate_https(uri),
         :ok <- validate_no_userinfo(uri),
         :ok <- validate_aws_host(uri, allowed_regions),
         :ok <- validate_pem_extension(uri) do
      {:ok, uri}
    else
      {:error, _} = err -> err
    end
  end

  def validate_signing_cert_url(_url, _allowed_regions), do: {:error, :invalid_cert_url}

  @doc """
  Validate and parse a SubscribeURL.

  Returns `{:ok, uri}` on success or `{:error, :invalid_subscribe_url}` on failure.

  Validation rules:
  1. Must be HTTPS
  2. Host must match `sns.<region>.amazonaws.com` or `.com.cn`
  3. The region must be in the allowed_regions list
  4. Must not contain userinfo (credentials in URL)
  """
  @spec validate_subscribe_url(String.t(), [String.t()]) :: {:ok, URI.t()} | {:error, atom()}
  def validate_subscribe_url(url, allowed_regions) when is_binary(url) do
    with {:ok, uri} <- parse_url(url),
         :ok <- validate_https(uri),
         :ok <- validate_no_userinfo(uri),
         :ok <- validate_aws_host(uri, allowed_regions) do
      {:ok, uri}
    else
      {:error, _} = err -> err
    end
  end

  def validate_subscribe_url(_url, _allowed_regions), do: {:error, :invalid_subscribe_url}

  @doc """
  Build a hostname regex pattern from a list of allowed AWS regions.
  """
  @spec hostname_regex([String.t()]) :: Regex.t()
  def hostname_regex(allowed_regions) do
    escaped = Enum.map(allowed_regions, &Regex.escape/1)
    ~r/^sns\.(?:#{Enum.join(escaped, "|")})\.amazonaws\.com(\.cn)?$/i
  end

  # ── private ────────────────────────────────────────────────────────────────

  defp parse_url(url) do
    uri = URI.parse(url)

    if uri.scheme in ~w(https http) and uri.host != nil and uri.host != "" do
      {:ok, uri}
    else
      {:error, :invalid_url}
    end
  end

  defp validate_https(%URI{scheme: "https"}), do: :ok
  defp validate_https(_uri), do: {:error, :invalid_url_scheme}

  defp validate_no_userinfo(%URI{userinfo: nil}), do: :ok
  defp validate_no_userinfo(_uri), do: {:error, :url_contains_credentials}

  defp validate_aws_host(%URI{host: host}, allowed_regions) do
    regex = hostname_regex(allowed_regions)

    if Regex.match?(regex, host) do
      :ok
    else
      {:error, :invalid_cert_url_host}
    end
  end

  defp validate_pem_extension(%URI{path: path}) when is_binary(path) do
    if String.ends_with?(String.downcase(path), ".pem") do
      :ok
    else
      {:error, :invalid_cert_url_extension}
    end
  end

  defp validate_pem_extension(_uri), do: {:error, :invalid_cert_url_extension}
end
