import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = Path(__file__).resolve().parent


def load_hex_packages():
    spec = importlib.util.spec_from_file_location("hex_packages", SCRIPT_DIR / "hex_packages.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hex_packages = load_hex_packages()


def load_github_assets():
    import sys

    sys.modules["hex_packages"] = hex_packages
    spec = importlib.util.spec_from_file_location("github_assets", SCRIPT_DIR / "github_assets.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


github_assets = load_github_assets()


class VersionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for relative in (
            "mix.exs",
            "mix.lock",
            "apps/ex_ssl/mix.exs",
            "apps/elixir_quic/mix.exs",
            "apps/elixir_quic_http3/mix.exs",
        ):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)

    def command(self, mode, version):
        return subprocess.run(
            ["elixir", str(SCRIPT_DIR / "versions.exs"), mode, version],
            cwd=self.root,
            text=True,
            capture_output=True,
        )

    def compatible_lock(self):
        lock = self.root / "mix.lock"
        lock.write_text(
            '%{"http_core": {:hex, :http_core, "0.16.0", "hash", [:mix], '
            '[{:elixir_quic, "== 1.0.0", [optional: false]}, '
            '{:ex_ssl, "== 1.0.0", [optional: false]}], "hexpm", "hash"}}\n'
        )

    def incompatible_lock(self, optional=False):
        lock = self.root / "mix.lock"
        lock.write_text(
            '%{"http_core": {:hex, :http_core, "0.16.0", "hash", [:mix], '
            f'[{{:elixir_quic, "~> 0.3.0", [optional: {str(optional).lower()}]}}, '
            '{:ex_ssl, "~> 0.7.2", [optional: false]}], "hexpm", "hash"}}\n'
        )

    def test_current_external_requirements_block_before_edits(self):
        self.incompatible_lock()
        before = (self.root / "mix.exs").read_bytes()
        result = self.command("prepare", "1.0.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("http_fetch/issues/16", result.stderr)
        self.assertEqual((self.root / "mix.exs").read_bytes(), before)

    def test_optional_external_requirement_still_constrains_present_sibling(self):
        self.incompatible_lock(optional=True)
        result = self.command("prepare", "1.0.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("http_core requires elixir_quic", result.stderr)

    def test_prepare_updates_all_versions_and_internal_requirements(self):
        self.compatible_lock()
        result = self.command("prepare", "1.0.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        for relative in ("mix.exs", "apps/ex_ssl/mix.exs", "apps/elixir_quic/mix.exs"):
            self.assertIn('version: "1.0.0"', (self.root / relative).read_text())
        http3 = (self.root / "apps/elixir_quic_http3/mix.exs").read_text()
        self.assertIn('@version "1.0.0"', http3)
        self.assertIn('{:elixir_quic, "== 1.0.0", in_umbrella:', http3)
        self.assertIn(
            '{:ex_ssl, "== 1.0.0", in_umbrella:',
            (self.root / "apps/elixir_quic/mix.exs").read_text(),
        )
        self.assertEqual(self.command("validate", "1.0.0").returncode, 0)
        self.assertNotEqual(self.command("validate", "1.0.1").returncode, 0)

    def test_invalid_input_or_malformed_source_cannot_edit(self):
        self.compatible_lock()
        before = (self.root / "mix.exs").read_bytes()
        self.assertNotEqual(self.command("prepare", "1.0.0-rc.1").returncode, 0)
        self.assertEqual((self.root / "mix.exs").read_bytes(), before)
        quic = self.root / "apps/elixir_quic/mix.exs"
        quic.write_text(re.sub(r'version: "[^"]+"', 'version: @version', quic.read_text(), count=1))
        self.assertNotEqual(self.command("prepare", "1.0.0").returncode, 0)
        self.assertEqual((self.root / "mix.exs").read_bytes(), before)

    def test_built_archive_metadata_identity_and_requirements(self):
        archive_dir = self.root / "archives"
        archive_dir.mkdir()
        (self.root / "config").mkdir()
        shutil.copyfile(ROOT / "config/config.exs", self.root / "config/config.exs")
        environment = os.environ.copy()
        environment.pop("EX_QUIC_CI_APP", None)
        for package in hex_packages.PACKAGES:
            source = ROOT / "apps" / package
            destination = self.root / "apps" / package
            shutil.copytree(
                source,
                destination,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns("test", "e2e", "_build"),
            )
        self.compatible_lock()
        self.assertEqual(self.command("prepare", "1.0.0").returncode, 0)
        for package in hex_packages.PACKAGES:
            destination = self.root / "apps" / package
            archive = archive_dir / f"{package}-1.0.0.tar"
            result = subprocess.run(
                ["mix", "hex.build", "--output", str(archive)],
                cwd=destination,
                env=environment,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

        def verify():
            return subprocess.run(
                ["elixir", str(SCRIPT_DIR / "archives.exs"), "1.0.0", str(archive_dir)],
                cwd=self.root,
                text=True,
                capture_output=True,
            )

        result = verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        quic_archive = archive_dir / "elixir_quic-1.0.0.tar"
        good_archive = quic_archive.read_bytes()
        quic_archive.write_bytes((archive_dir / "ex_ssl-1.0.0.tar").read_bytes())
        self.assertIn("incorrect Hex archive identity", verify().stderr)
        quic_archive.write_bytes(good_archive)

        quic_manifest = self.root / "apps/elixir_quic/mix.exs"
        quic_manifest.write_text(quic_manifest.read_text().replace('"== 1.0.0"', '"== 9.9.9"'))
        result = subprocess.run(
            ["mix", "hex.build", "--output", str(quic_archive)],
            cwd=self.root / "apps/elixir_quic",
            env=environment,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("lacks required ex_ssl == 1.0.0", verify().stderr)


class HexTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        for package in hex_packages.PACKAGES:
            (self.directory / f"{package}-1.0.0.tar").write_bytes(package.encode())

    def test_preflight_mismatch_stops_without_publication(self):
        def status(package, _version, _archive):
            if package == "elixir_quic":
                raise RuntimeError("checksum mismatch")
            return "missing"

        with patch.object(hex_packages, "release_status", side_effect=status), patch.object(
            hex_packages.subprocess, "run"
        ) as publish:
            with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                hex_packages.run("publish", "1.0.0", self.directory)
        publish.assert_not_called()

    def test_release_status_parses_registry_checksum(self):
        archive = self.directory / "ex_ssl-1.0.0.tar"
        expected = hashlib.sha256(archive.read_bytes()).hexdigest()

        with patch.object(hex_packages, "urlopen", return_value=io.BytesIO(
            json.dumps({"checksum": expected}).encode()
        )):
            self.assertEqual(hex_packages.release_status("ex_ssl", "1.0.0", archive), "matching")

        with patch.object(hex_packages, "urlopen", return_value=io.BytesIO(
            json.dumps({"checksum": "0" * 64}).encode()
        )):
            with self.assertRaisesRegex(RuntimeError, "differs"):
                hex_packages.release_status("ex_ssl", "1.0.0", archive)

    def test_retry_skips_matching_and_publishes_in_dependency_order(self):
        calls = []

        def status(package, _version, _archive):
            calls.append(package)
            return "missing" if len(calls) <= 3 and package != "ex_ssl" else "matching"

        with patch.object(hex_packages, "release_status", side_effect=status), patch.object(
            hex_packages.subprocess, "run"
        ) as publish, patch.dict("os.environ", {"HEX_API_KEY": "test-key"}):
            hex_packages.run("publish", "1.0.0", self.directory)
        self.assertEqual(calls, [*hex_packages.PACKAGES, *hex_packages.PACKAGES])
        self.assertEqual(
            [str(call.kwargs["cwd"]) for call in publish.call_args_list],
            ["apps/elixir_quic", "apps/elixir_quic_http3"],
        )


class GithubAssetTests(unittest.TestCase):
    def test_existing_mismatch_prevents_all_uploads(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_dir = Path(directory)
            for package in hex_packages.PACKAGES:
                (archive_dir / f"{package}-1.0.0.tar").write_bytes(package.encode())

            release = {"assets": [{"name": "elixir_quic-1.0.0.tar"}]}

            def download(command, **_kwargs):
                Path(command[command.index("--dir") + 1], "elixir_quic-1.0.0.tar").write_bytes(
                    b"different"
                )

            with patch.object(github_assets, "existing_release", return_value=release), patch.object(
                github_assets.subprocess, "run", side_effect=download
            ) as commands, patch.dict(os.environ, {"GITHUB_REPOSITORY": "example/repo"}):
                with self.assertRaisesRegex(RuntimeError, "differs"):
                    github_assets.run("preflight", "1.0.0", archive_dir)
            self.assertEqual(commands.call_count, 1)

    def test_matching_asset_allows_missing_assets_upload(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_dir = Path(directory)
            for package in hex_packages.PACKAGES:
                (archive_dir / f"{package}-1.0.0.tar").write_bytes(package.encode())
            release = {"assets": [{"name": "ex_ssl-1.0.0.tar"}]}

            def command(args, **_kwargs):
                if args[2] == "download":
                    Path(args[args.index("--dir") + 1], "ex_ssl-1.0.0.tar").write_bytes(b"ex_ssl")

            with patch.object(github_assets, "existing_release", return_value=release), patch.object(
                github_assets.subprocess, "run", side_effect=command
            ) as commands, patch.dict(os.environ, {"GITHUB_REPOSITORY": "example/repo"}):
                github_assets.run("complete", "1.0.0", archive_dir)
            self.assertEqual(commands.call_count, 2)
            upload = commands.call_args_list[1].args[0]
            self.assertEqual(upload[:3], ["gh", "release", "upload"])
            self.assertEqual(
                {Path(path).name for path in upload[4:]},
                {"elixir_quic-1.0.0.tar", "elixir_quic_http3-1.0.0.tar"},
            )

    def test_preflight_absent_release_or_missing_assets_never_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_dir = Path(directory)
            for package in hex_packages.PACKAGES:
                (archive_dir / f"{package}-1.0.0.tar").write_bytes(package.encode())

            with patch.object(github_assets, "existing_release", return_value=None), patch.object(
                github_assets.subprocess, "run"
            ) as commands, patch.dict(os.environ, {"GITHUB_REPOSITORY": "example/repo"}):
                github_assets.run("preflight", "1.0.0", archive_dir)
            commands.assert_not_called()

            with patch.object(github_assets, "existing_release", return_value={"assets": []}), patch.object(
                github_assets.subprocess, "run"
            ) as commands, patch.dict(os.environ, {"GITHUB_REPOSITORY": "example/repo"}):
                github_assets.run("preflight", "1.0.0", archive_dir)
            commands.assert_not_called()


if __name__ == "__main__":
    unittest.main()
