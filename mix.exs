defmodule ExQuic.MixProject do
  use Mix.Project

  def project do
    [
      app: :ex_quic,
      version: "0.1.0-dev",
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
       ref: "02eb981f59d4e182d4473e264a9f8b093ec6bf3d",
       runtime: false}
    ]
  end
end
