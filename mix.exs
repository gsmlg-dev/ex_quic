defmodule Quic.MixProject do
  use Mix.Project

  def project do
    [
      app: :elixir_quic,
      version: "0.2.2",
      description:
        "Experimental QUIC v1 transport, Initial fingerprint observation and client profiles",
      package: package(),
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      warnings_as_errors: true
    ]
  end

  def application do
    [extra_applications: [:crypto, :logger]]
  end

  def cli do
    [preferred_envs: ["test.watch": :test]]
  end

  defp package do
    [
      files: ["lib", "mix.exs", "README.md", "LICENSE"],
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/gsmlg-dev/ex_quic"}
    ]
  end

  defp deps do
    [{:ex_ssl, "== 0.7.2"}]
  end
end
