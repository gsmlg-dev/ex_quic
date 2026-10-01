#!/usr/bin/env python3
"""Select directly changed umbrella apps for a GitHub Actions workflow."""

import argparse
import json
import os
import subprocess
from pathlib import Path


APPS = ("ex_ssl", "elixir_quic", "elixir_quic_http3")
ALL = list(APPS)
QUIC_SCRIPTS = ("scripts/interop/", "scripts/phase1/", "scripts/datagram/")
SHARED = ("mix.exs", "mix.lock", ".formatter.exs")


def select_apps(paths, workflow):
    selected = set()
    own_workflow = f".github/workflows/{workflow}"

    for path in paths:
        if (
            path in SHARED
            or path == own_workflow
            or path == ".github/workflows/changes.yml"
            or path.startswith(("config/", "scripts/ci/"))
        ):
            return ALL
        for app in APPS:
            if path.startswith(f"apps/{app}/"):
                selected.add(app)
        if path.startswith(QUIC_SCRIPTS):
            selected.add("elixir_quic")

    return [app for app in APPS if app in selected]


def changed_paths(base, head):
    if not base or set(base) == {"0"}:
        return None
    result = subprocess.run(
        ["git", "diff", "--name-only", "--no-renames", "-z", base, head],
        capture_output=True,
        check=False,
    )
    if result.returncode:
        return None
    # --no-renames reports both the deleted source and added destination.
    return [os.fsdecode(path) for path in result.stdout.split(b"\0") if path]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workflow", required=True, choices=("ci.yml", "test.yml", "e2e.yml"))
    parser.add_argument("--event", required=True)
    parser.add_argument("--base", default="")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--manual-module", default="")
    args = parser.parse_args()

    if args.event == "workflow_dispatch":
        if args.manual_module not in (*APPS, "all"):
            parser.error("manual E2E module must be all or an umbrella app")
        apps = ALL if args.manual_module == "all" else [args.manual_module]
    else:
        paths = changed_paths(args.base, args.head)
        apps = ALL if paths is None else select_apps(paths, args.workflow)

    output = f"apps={json.dumps(apps, separators=(',', ':'))}\nhas_changes={'true' if apps else 'false'}\n"
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with Path(github_output).open("a", encoding="utf-8") as handle:
            handle.write(output)
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
