#!/usr/bin/env python3
"""Parse the archive directory and invoke the Go linter for each entry."""

import argparse
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
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


def lint_entry(entry: tuple[str, str, str | None]) -> tuple[bool, str]:
    origin, location, torrent = entry
    if "https://" not in location and "http://" not in location:
        return True, f"SKIP {origin}: no archive URL\n"
    command = ["go", "run", "./cmd/lint-archives", "-origin", origin, "-url", location]
    if torrent:
        command += ["-torrent", torrent]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    output = result.stdout
    # The checker already reports failures; omit go run's redundant footer.
    stderr = result.stderr.removesuffix("exit status 1\n")
    if stderr:
        output += f"FAIL {origin}: go run\n{stderr}"
    passed = result.returncode == 0
    if not passed and os.environ.get("GITHUB_ACTIONS") == "true":
        lines = []
        for line in output.splitlines():
            if not line.startswith("FAIL "):
                message = line.strip().replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
                line = f"::error::{message}"
            lines.append(line)
        output = "\n".join(lines) + "\n"
    return passed, output


def lint_entries(entries: list[tuple[str, str, str | None]]) -> bool:
    print(f"Checking {len(entries)} archive entries", flush=True)
    failed = 0
    # Overlap network waits without overwhelming archive hosts.
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(lint_entry, entry) for entry in entries]
        for future in as_completed(futures):
            passed, output = future.result()
            # Print completed entries together, so diagnostics don't interleave.
            print(output, end="", flush=True)
            failed += not passed
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
