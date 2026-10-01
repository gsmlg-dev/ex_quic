defmodule ReleaseArchives do
  def run([version, directory]) do
    Mix.start()
    Mix.Hex.start()

    for package <- ["ex_ssl", "elixir_quic", "elixir_quic_http3"] do
      archive = Path.join(directory, "#{package}-#{version}.tar")
      {:ok, result} = :mix_hex_tarball.unpack(File.read!(archive), :none)
      metadata = result.metadata

      unless metadata["name"] == package and metadata["version"] == version do
        raise "incorrect Hex archive identity: #{archive}"
      end

      case package do
        "elixir_quic" -> require_sibling!(metadata, "ex_ssl", version)
        "elixir_quic_http3" -> require_sibling!(metadata, "elixir_quic", version)
        _ -> :ok
      end
    end

    IO.puts("all three Hex archive identities and sibling requirements validated")
  end

  def run(_), do: raise("usage: elixir scripts/release/archives.exs VERSION ARCHIVE_DIR")

  defp require_sibling!(metadata, name, version) do
    requirement = get_in(metadata, ["requirements", name])

    unless requirement && requirement["requirement"] == "== #{version}" &&
             requirement["optional"] == false do
      raise "Hex archive #{metadata["name"]} lacks required #{name} == #{version}"
    end
  end
end

ReleaseArchives.run(System.argv())
