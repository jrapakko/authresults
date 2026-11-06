# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Fail if uv.lock holds a file uploaded less than 7 days before a reference time.

``UV_LOCKED`` only checks that uv.lock matches pyproject.toml; it does not
re-check the upload times recorded in the lock. This script does.

The reference time defaults to the committer date of ``HEAD``, clamped to the
current time so that a future-dated commit cannot widen the window. Usage::

    python scripts/check_lock_cooldown.py [--lock uv.lock] [--reference ISO-8601]
"""

import argparse
import subprocess
import sys
import tomllib
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

COOLDOWN = timedelta(days=7)
SPAN = "P7D"


def _upload_times(lock: dict[str, Any]) -> Iterator[tuple[str, datetime]]:
    for package in lock.get("package", []):
        label = f"{package['name']} {package.get('version', '')}".rstrip()
        files = [package.get("sdist", {}), *package.get("wheels", [])]
        for file in files:
            if "upload-time" in file:
                yield label, datetime.fromisoformat(file["upload-time"])


def check(lock_text: str, reference: datetime) -> list[str]:
    """Return one problem per offending file; an empty list means the lock is fine."""
    lock = tomllib.loads(lock_text)
    problems = []
    span = lock.get("options", {}).get("exclude-newer-span")
    if span != SPAN:
        problems.append(f"options.exclude-newer-span is {span!r}, expected {SPAN!r}")
    cutoff = reference - COOLDOWN
    problems.extend(
        f"{label}: uploaded {uploaded.isoformat()}, after cutoff {cutoff.isoformat()}"
        for label, uploaded in _upload_times(lock)
        if uploaded > cutoff
    )
    return problems


def _head_commit_time() -> datetime:
    out = subprocess.run(
        ["git", "show", "-s", "--format=%cI", "HEAD"],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return datetime.fromisoformat(out.strip())


def _parse_reference(text: str) -> datetime:
    """Parse an ISO 8601 time; a time without an offset is taken as UTC."""
    value = datetime.fromisoformat(text)
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def default_reference(now: datetime | None = None) -> datetime:
    """Return ``min(HEAD committer time, now)``."""
    return min(_head_commit_time(), now or datetime.now(UTC))


def main(argv: Sequence[str] | None = None) -> int:
    """Run the check from the command line."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--lock", type=Path, default=Path("uv.lock"))
    parser.add_argument("--reference", type=_parse_reference)
    args = parser.parse_args(argv)
    reference: datetime = args.reference or default_reference()
    problems = check(args.lock.read_text(encoding="utf-8"), reference)
    for problem in problems:
        print(problem, file=sys.stderr)  # noqa: T201
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
