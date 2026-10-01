defmodule Quic.Umbrella.MixProject do
  use Mix.Project

  def project do
    [
      apps_path: "apps",
      apps: ci_apps(),
      version: "0.3.0",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  defp deps do
    # http_core also depends on these apps; resolve them to the umbrella sources.
    deps = [
      {:ex_ssl, path: "apps/ex_ssl", env: Mix.env(), override: true},
      {:elixir_quic, path: "apps/elixir_quic", env: Mix.env(), override: true}
    ]

    case ci_apps() do
      nil -> deps
      apps -> Enum.filter(deps, fn {app, _options} -> app in apps end)
    end
  end

  defp ci_apps do
    case System.get_env("EX_QUIC_CI_APP") do
      nil -> nil
      "ex_ssl" -> [:ex_ssl]
      "elixir_quic" -> [:ex_ssl, :elixir_quic]
      "elixir_quic_http3" -> [:ex_ssl, :elixir_quic, :elixir_quic_http3]
      other -> raise "invalid EX_QUIC_CI_APP: #{inspect(other)}"
    end
  end
end
