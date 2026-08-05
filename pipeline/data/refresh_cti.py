"""Download the pinned CWE/CAPEC/ATT&CK catalogues into data/.

Reads versions from data/VERSIONS.txt and fetches exactly those releases.
Idempotent unless --force. Usage: python -m pipeline.data.refresh_cti [--force]
"""

from __future__ import annotations

import argparse
import re
import urllib.request
import zipfile
from pathlib import Path

# Repo root = three levels up from this file (pipeline/data/refresh_cti.py).
ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
VERSIONS = DATA / "VERSIONS.txt"


def read_pins() -> dict[str, str]:
    """Parse ``key = value`` lines from ``data/VERSIONS.txt`` (comments ignored)."""
    pins: dict[str, str] = {}
    for line in VERSIONS.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        match = re.match(r"([\w.]+)\s*=\s*(.+)", line)
        if match:
            pins[match.group(1)] = match.group(2).strip()
    return pins


def _download(url: str, dest: Path, force: bool) -> bool:
    """Download ``url`` to ``dest``; return True if fetched, False if skipped."""
    if dest.exists() and not force:
        print(f"  skip (exists): {dest.relative_to(ROOT)}")
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"  GET {url}")
    urllib.request.urlretrieve(url, dest)  # noqa: S310 (pinned MITRE https URLs)
    print(f"  -> {dest.relative_to(ROOT)} ({dest.stat().st_size:,} bytes)")
    return True


def fetch_cwe(version: str, force: bool) -> None:
    """Download and unzip the pinned CWE catalogue XML."""
    zip_path = DATA / "cwe" / f"cwec_v{version}.xml.zip"
    url = f"https://cwe.mitre.org/data/xml/cwec_v{version}.xml.zip"
    if _download(url, zip_path, force):
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(zip_path.parent)
        print(f"  unzipped -> {zip_path.parent.relative_to(ROOT)}/")


def fetch_capec(version: str, force: bool) -> None:
    """Download the pinned CAPEC catalogue XML."""
    dest = DATA / "capec" / f"capec_v{version}.xml"
    url = f"https://capec.mitre.org/data/xml/capec_v{version}.xml"
    _download(url, dest, force)


def fetch_attack(version: str, force: bool) -> None:
    """Download the pinned ATT&CK Enterprise STIX 2.1 bundle."""
    dest = DATA / "attack" / f"enterprise-attack-{version}.json"
    url = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        f"master/enterprise-attack/enterprise-attack-{version}.json"
    )
    _download(url, dest, force)


def refresh(force: bool = False) -> None:
    """Fetch all pinned O4 catalogues into ``data/``."""
    pins = read_pins()
    print(f"Refreshing CTI catalogues per {VERSIONS.relative_to(ROOT)}")
    print("CWE:")
    fetch_cwe(pins["cwe_version"], force)
    print("CAPEC:")
    fetch_capec(pins["capec_version"], force)
    print("ATT&CK:")
    fetch_attack(pins["attack_version"], force)
    print("Done.")


def main(argv: list[str] | None = None) -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(prog="pipeline.data.refresh_cti")
    parser.add_argument(
        "--force", action="store_true", help="re-download even if files exist"
    )
    args = parser.parse_args(argv)
    refresh(force=args.force)


if __name__ == "__main__":
    main()
