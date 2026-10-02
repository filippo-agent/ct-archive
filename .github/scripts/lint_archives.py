#!/usr/bin/env python3
"""Parse the archive directory and invoke the Go linter for each entry."""

import argparse
import os
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
    print(f"Checking {len(entries)} archive entries", flush=True)
    failed = 0
    for origin, location, torrent in entries:
        if "https://" not in location and "http://" not in location:
            print(f"SKIP {origin}: no archive URL", flush=True)
            continue
        command = ["go", "run", "./cmd/lint-archives", "-origin", origin, "-url", location]
        if torrent:
            command += ["-torrent", torrent]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        output = result.stdout
        # The checker already reports failures; omit go run's redundant footer.
        stderr = result.stderr.removesuffix("exit status 1\n")
        if stderr:
            output += f"FAIL {origin}: go run\n{stderr}"
        if result.returncode != 0:
            failed += 1
            if os.environ.get("GITHUB_ACTIONS") == "true":
                message = output.strip() or f"FAIL {origin}: go run failed"
                message = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
                print(f"::error::{message}", flush=True)
                continue
        print(output, end="", flush=True)
    print(f"Finished: {failed} failed", flush=True)
    return failed == 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--readme", type=Path, default=ROOT / "README.md")
    args = parser.parse_args()
    entries = extract_entries(args.readme.read_text())
    return 0 if lint_entries(entries) else 1


if __name__ == "__main__":
    raise SystemExit(main())
