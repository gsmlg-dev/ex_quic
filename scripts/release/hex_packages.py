"""Preflight and publish the three immutable Hex archives for one release."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.request import urlopen


PACKAGES = ("ex_ssl", "elixir_quic", "elixir_quic_http3")


def release_status(package, version, archive):
    url = f"https://hex.pm/api/packages/{package}/releases/{version}"
    try:
        with urlopen(url, timeout=20) as response:
            metadata = json.load(response)
    except HTTPError as error:
        if error.code == 404:
            return "missing"
        raise RuntimeError(f"Hex registry check for {package} failed: HTTP {error.code}") from error
    except URLError as error:
        raise RuntimeError(f"Hex registry check for {package} failed: {error.reason}") from error

    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    if metadata.get("checksum", "").lower() != actual:
        raise RuntimeError(f"Existing Hex package {package} {version} differs from release archive")
    return "matching"


def run(mode, version, archive_dir):
    if mode not in ("preflight", "publish"):
        raise ValueError("expected preflight or publish")
    if not version or any(character not in "0123456789." for character in version):
        raise ValueError("invalid release version")

    archives = {package: archive_dir / f"{package}-{version}.tar" for package in PACKAGES}
    for package, archive in archives.items():
        if not archive.is_file():
            raise RuntimeError(f"missing Hex archive: {archive}")

    # Inspect every package before the first registry write, even on a retry.
    statuses = {
        package: release_status(package, version, archives[package]) for package in PACKAGES
    }
    if mode == "preflight":
        for package, status in statuses.items():
            print(f"{package}: {status}")
        return

    if not os.environ.get("HEX_API_KEY"):
        raise RuntimeError("HEX_API_KEY must publish ex_ssl, elixir_quic, and elixir_quic_http3")
    for package in PACKAGES:
        if statuses[package] == "missing":
            subprocess.run(
                ["mix", "hex.publish", "package", "--yes"],
                cwd=Path("apps") / package,
                check=True,
            )
        # A successful CLI exit alone does not establish registry publication.
        if release_status(package, version, archives[package]) != "matching":
            raise RuntimeError(f"Hex verification failed for {package} {version}")
        print(f"Verified Hex package {package} {version}")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 4:
            raise ValueError("usage: hex_packages.py preflight|publish VERSION ARCHIVE_DIR")
        run(sys.argv[1], sys.argv[2], Path(sys.argv[3]))
    except (RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
