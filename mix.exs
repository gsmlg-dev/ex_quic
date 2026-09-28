defmodule ExQuic.MixProject do
  use Mix.Project

  def project do
    [
      app: :ex_quic,
      version: "0.1.0",
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

  defp deps do
    [
      {:ex_ssl,
       git: "https://github.com/gsmlg-dev/ex_ssl.git",
       ref: "f1327e0bb7fb2093b8dc2b07e72b26233a739963"}
    ]
  end
end
