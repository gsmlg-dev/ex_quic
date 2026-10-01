defmodule ReleaseVersions do
  @files [
    {"mix.exs", ~r/(?<=      version: ")[^"]+(?=",)/, nil},
    {"apps/ex_ssl/mix.exs", ~r/(?<=      version: ")[^"]+(?=",)/, nil},
    {"apps/elixir_quic/mix.exs", ~r/(?<=      version: ")[^"]+(?=",)/, nil},
    {"apps/elixir_quic_http3/mix.exs", ~r/(?<=  @version ")[^"]+(?=")/, nil},
    {"apps/elixir_quic/mix.exs",
     ~r/(?<=\{:ex_ssl, ")[^"]+(?=", in_umbrella: true, hex: :ex_ssl\})/, "== "},
    {"apps/elixir_quic_http3/mix.exs",
     ~r/(?<=\{:elixir_quic, ")[^"]+(?=", in_umbrella: true, hex: :elixir_quic\})/, "== "}
  ]

  def run([mode, version]) when mode in ["prepare", "validate"] do
    unless Regex.match?(~r/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/, version),
      do: raise("release version must be stable major.minor.patch")

    contents =
      Enum.reduce(@files, %{}, fn {path, regex, prefix}, acc ->
        source = Map.get(acc, path, File.read!(path))
        matches = Regex.scan(regex, source)
        unless length(matches) == 1, do: raise("expected exactly one release field in #{path}")
        wanted = (prefix || "") <> version

        updated =
          case mode do
            "prepare" ->
              Regex.replace(regex, source, fn _ -> wanted end)

            "validate" ->
              unless matches == [[wanted]], do: raise("release identity mismatch in #{path}")
              source
          end

        Map.put(acc, path, updated)
      end)

    verify_locked_dependencies!(version)

    if mode == "prepare" do
      Enum.each(contents, fn {path, source} -> File.write!(path, source) end)
    end

    IO.puts("release sources and locked external requirements validated for #{version}")
  end

  def run(_), do: raise("usage: elixir scripts/release/versions.exs prepare|validate VERSION")

  defp verify_locked_dependencies!(version) do
    Mix.start()
    lock = Mix.Dep.Lock.read("mix.lock")
    internal = %{elixir_quic: version, ex_ssl: version, elixir_quic_http3: version}

    # Check every locked external dependency, including transitive packages. Umbrella
    # overrides must not hide requirements that Hex consumers will have to solve.
    Enum.each(lock, fn {package, entry} ->
      case entry do
        {:hex, _, _, _, _, dependencies, _, _} ->
          Enum.each(dependencies, fn {name, requirement, _options} ->
            if Map.has_key?(internal, name) and not Version.match?(version, requirement) do
              raise "#{package} requires #{name} #{requirement}, incompatible with #{version}; see https://github.com/gsmlg-dev/http_fetch/issues/16"
            end
          end)

        _ ->
          :ok
      end
    end)
  end
end

ReleaseVersions.run(System.argv())
