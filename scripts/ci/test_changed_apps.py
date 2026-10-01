import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from changed_apps import ALL, select_apps


SCRIPT = Path(__file__).with_name("changed_apps.py")


def run_cli(cwd, *args):
    with tempfile.TemporaryDirectory() as output_dir:
        output_file = Path(output_dir) / "output"
        result = subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            cwd=cwd,
            env={**os.environ, "GITHUB_OUTPUT": str(output_file)},
            capture_output=True,
            text=True,
        )
        return result, output_file.read_text() if output_file.exists() else ""


class SelectAppsTest(unittest.TestCase):
    def test_direct_app_ownership_and_quic_scripts(self):
        self.assertEqual(select_apps(["apps/ex_ssl/lib/ssl.ex"], "test.yml"), ["ex_ssl"])
        self.assertEqual(
            select_apps(["apps/elixir_quic/lib/quic.ex", "scripts/interop/run.exs"], "e2e.yml"),
            ["elixir_quic"],
        )
        self.assertEqual(
            select_apps(["apps/elixir_quic_http3/lib/quic_http3.ex"], "ci.yml"),
            ["elixir_quic_http3"],
        )

    def test_multi_app_and_shared_changes(self):
        self.assertEqual(
            select_apps(["apps/ex_ssl/a", "apps/elixir_quic_http3/b"], "ci.yml"),
            ["ex_ssl", "elixir_quic_http3"],
        )
        for path in ("mix.exs", "mix.lock", "config/config.exs", "scripts/ci/changed_apps.py"):
            with self.subTest(path=path):
                self.assertEqual(select_apps([path], "test.yml"), ALL)

    def test_workflow_ownership_and_docs_only(self):
        self.assertEqual(select_apps([".github/workflows/ci.yml"], "ci.yml"), ALL)
        self.assertEqual(select_apps([".github/workflows/ci.yml"], "test.yml"), [])
        self.assertEqual(select_apps(["docs/testing.md", "README.md"], "ci.yml"), [])
        self.assertEqual(select_apps([".github/workflows/changes.yml"], "e2e.yml"), ALL)

    def test_deleted_and_renamed_paths_are_classified(self):
        # git diff --no-renames yields a deleted old path and an added new path.
        self.assertEqual(select_apps(["apps/ex_ssl/removed.ex"], "ci.yml"), ["ex_ssl"])
        self.assertEqual(
            select_apps(["apps/ex_ssl/old.ex", "apps/elixir_quic/new.ex"], "ci.yml"),
            ["ex_ssl", "elixir_quic"],
        )


class ChangedAppsCLITest(unittest.TestCase):
    def test_initial_push_manual_choice_and_invalid_choice(self):
        with tempfile.TemporaryDirectory() as directory:
            args = ("--workflow", "e2e.yml", "--event", "push", "--base", "0" * 40)
            result, output = run_cli(directory, *args)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('apps=["ex_ssl","elixir_quic","elixir_quic_http3"]', output)

            for module, expected in (
                ("all", ALL),
                ("ex_ssl", ["ex_ssl"]),
                ("elixir_quic", ["elixir_quic"]),
                ("elixir_quic_http3", ["elixir_quic_http3"]),
            ):
                result, output = run_cli(
                    directory,
                    "--workflow", "e2e.yml", "--event", "workflow_dispatch",
                    "--manual-module", module,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("apps=" + json.dumps(expected, separators=(",", ":")), output)

            result, _ = run_cli(
                directory, "--workflow", "e2e.yml", "--event", "workflow_dispatch",
                "--manual-module", "unknown",
            )
            self.assertNotEqual(result.returncode, 0)

    def test_git_range_rename_deletion_and_docs_only(self):
        with tempfile.TemporaryDirectory() as directory:
            def git(*args):
                return subprocess.check_output(["git", *args], cwd=directory, text=True).strip()

            def write(path, content):
                target = Path(directory) / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content)

            git("init", "-q")
            git("config", "user.name", "Workflow Test")
            git("config", "user.email", "workflow@example.invalid")
            write("apps/ex_ssl/old.ex", "old")
            write("apps/elixir_quic/deleted.ex", "delete")
            write("README.md", "initial")
            git("add", ".")
            git("commit", "-qm", "baseline")
            base = git("rev-parse", "HEAD")

            write("README.md", "docs only")
            git("add", ".")
            git("commit", "-qm", "docs")
            docs_head = git("rev-parse", "HEAD")
            result, output = run_cli(
                directory, "--workflow", "test.yml", "--event", "push",
                "--base", base, "--head", docs_head,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output, "apps=[]\nhas_changes=false\n")

            (Path(directory) / "apps/elixir_quic_http3").mkdir()
            git("mv", "apps/ex_ssl/old.ex", "apps/elixir_quic_http3/new.ex")
            git("rm", "apps/elixir_quic/deleted.ex")
            git("commit", "-qm", "rename and delete")
            result, output = run_cli(
                directory, "--workflow", "ci.yml", "--event", "push",
                "--base", base, "--head", git("rev-parse", "HEAD"),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                output,
                'apps=["ex_ssl","elixir_quic","elixir_quic_http3"]\nhas_changes=true\n',
            )


if __name__ == "__main__":
    unittest.main()
