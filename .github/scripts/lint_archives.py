#!/usr/bin/env python3
"""Parse the archive directory and invoke the Go linter for each entry."""

import argparse
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def extract_entries(content: str) -> list[tuple[str, str, str | None]]:
    """Read the repository's simple Markdown table, not general Markdown."""
    entries = []
    for line in content.splitlines():
        if not line.startswith("|"):
            continue
        cells = line.split("|")
        if len(cells) < 4:
            continue
        origin = cells[1].strip()
        if origin == "Log Origin" or not origin.strip("-: "):
            continue
        location = cells[2].strip().removesuffix(" †")
        torrent = re.search(r"\[\.torrent\]\(([^)]+)\)", cells[3])
        entries.append((origin, location, torrent[1] if torrent else None))
    return entries


def lint_entries(entries: list[tuple[str, str, str | None]]) -> bool:
    print(f"Found {len(entries)} archive entries", flush=True)
    passed = True
    for origin, location, torrent in entries:
        if "https://" not in location and "http://" not in location:
            print(f"SKIP: {origin}: no archive URL ({location})", flush=True)
            continue
        command = ["go", "run", "./cmd/lint-archives", "-origin", origin, "-url", location]
        if torrent:
            command += ["-torrent", torrent]
        if subprocess.run(command, cwd=ROOT).returncode != 0:
            passed = False
    print("All checks passed!" if passed else "Linting failed!", flush=True)
    return passed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--readme", type=Path, default=ROOT / "README.md")
    args = parser.parse_args()
    entries = extract_entries(args.readme.read_text())
    return 0 if lint_entries(entries) else 1


if __name__ == "__main__":
    raise SystemExit(main())
