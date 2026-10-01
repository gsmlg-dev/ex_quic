defmodule Quic.Umbrella.MixProject do
  use Mix.Project

  def project do
    [
      apps_path: "apps",
      version: "0.3.0",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  defp deps do
    # http_core also depends on these apps; resolve them to the umbrella sources.
    [
      {:ex_ssl, path: "apps/ex_ssl", env: Mix.env(), override: true},
      {:elixir_quic, path: "apps/elixir_quic", env: Mix.env(), override: true}
    ]
  end
end
