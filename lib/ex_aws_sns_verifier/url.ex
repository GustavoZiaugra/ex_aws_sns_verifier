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
  """
  @spec validate_signing_cert_url(String.t(), [String.t()]) :: {:ok, URI.t()} | {:error, atom()}
  def validate_signing_cert_url(url, allowed_regions) do
    case do_validate(url, allowed_regions, require_pem: true) do
      {:ok, uri} -> {:ok, uri}
      {:error, _} -> {:error, :invalid_cert_url}
    end
  end

  @doc """
  Validate and parse a SubscribeURL.

  Returns `{:ok, uri}` on success or `{:error, :invalid_subscribe_url}` on failure.
  """
  @spec validate_subscribe_url(String.t(), [String.t()]) :: {:ok, URI.t()} | {:error, atom()}
  def validate_subscribe_url(url, allowed_regions) do
    case do_validate(url, allowed_regions, require_pem: false) do
      {:ok, uri} -> {:ok, uri}
      {:error, _} -> {:error, :invalid_subscribe_url}
    end
  end

  @doc """
  Build a hostname regex pattern from a list of allowed AWS regions.

  Matches `sns.<region>.amazonaws.com` and `sns.<region>.amazonaws.com.cn`.
  """
  @spec hostname_regex([String.t()]) :: Regex.t()
  def hostname_regex(allowed_regions) do
    ~r/^sns\.(?:#{Enum.join(allowed_regions, "|")})\.amazonaws\.com(\.cn)?$/
  end

  defp do_validate(url, allowed_regions, opts) do
    case URI.parse(url) do
      %URI{scheme: "https", host: host, userinfo: nil} = uri when not is_nil(host) ->
        regex = hostname_regex(allowed_regions)

        cond do
          not Regex.match?(regex, host) ->
            {:error, :invalid_host}

          Keyword.get(opts, :require_pem, false) and not String.ends_with?(url, ".pem") ->
            {:error, :invalid_extension}

          true ->
            {:ok, uri}
        end

      %URI{scheme: scheme} when scheme != "https" ->
        {:error, :not_https}

      %URI{userinfo: userinfo} when not is_nil(userinfo) ->
        {:error, :userinfo_not_allowed}

      _ ->
        {:error, :invalid_url}
    end
  end
end
