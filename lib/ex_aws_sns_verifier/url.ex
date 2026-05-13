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
    # TODO: implement cert URL validation
    {:error, :not_implemented}
  end

  @doc """
  Validate and parse a SubscribeURL.

  Returns `{:ok, uri}` on success or `{:error, :invalid_subscribe_url}` on failure.
  """
  @spec validate_subscribe_url(String.t(), [String.t()]) :: {:ok, URI.t()} | {:error, atom()}
  def validate_subscribe_url(url, allowed_regions) do
    # TODO: implement subscribe URL validation
    {:error, :not_implemented}
  end

  @doc """
  Build a hostname regex pattern from a list of allowed AWS regions.

  Matches `sns.<region>.amazonaws.com` and `sns.<region>.amazonaws.com.cn`.
  """
  @spec hostname_regex([String.t()]) :: Regex.t()
  def hostname_regex(allowed_regions) do
    # TODO: implement hostname regex builder
    ~r/^sns\.(?:#{Enum.join(allowed_regions, "|")})\.amazonaws\.com(\.cn)?$/
  end
end
