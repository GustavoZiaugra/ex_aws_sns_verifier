defmodule ExAwsSnsVerifier.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/GustavoZiaugra/ex_aws_sns_verifier"

  def project do
    [
      app: :ex_aws_sns_verifier,
      version: @version,
      elixir: "~> 1.16",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),
      description: description(),
      package: package(),
      source_url: @source_url,
      docs: docs(),
      dialyzer: dialyzer(),

    ]
  end

  def cli do
    [preferred_envs: [dialyzer: :test, credo: :test]]
  end

  def application do
    [extra_applications: [:logger, :crypto, :public_key, :inets]]
  end

  defp deps do
    [
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp description do
    "Verify AWS SNS HTTPS message authenticity — RSA-SHA256 signature verification " <>
      "for Notification, SubscriptionConfirmation, and UnsubscribeConfirmation payloads. " <>
      "The Elixir equivalent of Ruby's Aws::SNS::MessageVerifier."
  end

  defp package do
    [
      name: :ex_aws_sns_verifier,
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md",
        "AWS SNS Verification Docs" =>
          "https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html"
      }
    ]
  end

  defp docs do
    [
      main: "ExAwsSnsVerifier",
      extras: ["README.md", "CHANGELOG.md"],
      groups_for_modules: [
        Core: [ExAwsSnsVerifier, ExAwsSnsVerifier.Canonical],
        Infrastructure: [ExAwsSnsVerifier.Cert, ExAwsSnsVerifier.Url],
        Integration: [ExAwsSnsVerifier.Plug]
      ],
      source_url: @source_url,
      source_ref: "v#{@version}"
    ]
  end

  defp dialyzer do
    [
      flags: [:error_handling, :race_conditions, :underspecs, :unmatched_returns],
      plt_add_apps: [:mix, :ex_unit]
    ]
  end
end
