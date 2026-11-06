# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

import importlib.util
import os
import runpy
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_lock_cooldown.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_lock_cooldown", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cooldown = _load()

LOCK = """\
version = 1

[options]
exclude-newer-span = "P7D"

[[package]]
name = "demo"
version = "1.0"
sdist = {{ url = "x", upload-time = "2026-10-01T00:00:00Z" }}
wheels = [{{ url = "y", upload-time = "{wheel_time}" }}]

[[package]]
name = "local"
source = {{ virtual = "." }}
"""
REFERENCE = datetime(2026, 11, 6, tzinfo=UTC)


def test_real_lock_is_past_cooldown() -> None:
    text = (ROOT / "uv.lock").read_text(encoding="utf-8")
    assert cooldown.check(text, datetime.now(UTC)) == []


def test_file_exactly_at_cutoff_passes() -> None:
    lock = LOCK.format(wheel_time="2026-10-30T00:00:00Z")
    assert cooldown.check(lock, REFERENCE) == []


def test_recent_upload_fails() -> None:
    lock = LOCK.format(wheel_time="2026-10-30T00:00:01Z")
    (problem,) = cooldown.check(lock, REFERENCE)
    assert problem.startswith("demo 1.0: uploaded 2026-10-30T00:00:01")


def test_missing_span_fails() -> None:
    lock = LOCK.format(wheel_time="2026-10-01T00:00:00Z").replace(
        'exclude-newer-span = "P7D"', ""
    )
    assert cooldown.check(lock, REFERENCE) == [
        "options.exclude-newer-span is None, expected 'P7D'"
    ]


def test_main_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    good = tmp_path / "good.lock"
    good.write_text(LOCK.format(wheel_time="2026-10-01T00:00:00Z"), encoding="utf-8")
    bad = tmp_path / "bad.lock"
    bad.write_text(LOCK.format(wheel_time="2026-11-05T00:00:00Z"), encoding="utf-8")
    ref = ["--reference", REFERENCE.isoformat()]
    assert cooldown.main(["--lock", str(good), *ref]) == 0
    assert cooldown.main(["--lock", str(bad), *ref]) == 1
    assert "demo 1.0" in capsys.readouterr().err


def _git_repo(path: Path, monkeypatch: pytest.MonkeyPatch, commit_date: str) -> None:
    """Create a git repo at *path* whose HEAD has the given committer date."""
    for key, value in {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_DATE": commit_date,
    }.items():
        monkeypatch.setenv(key, value)
    for args in (["init", "-q"], ["commit", "-q", "--allow-empty", "-m", "x"]):
        subprocess.run(["git", *args], cwd=path, check=True)  # noqa: S603, S607
    monkeypatch.chdir(path)


def _write_lock(path: Path, wheel_time: str) -> str:
    path.write_text(LOCK.format(wheel_time=wheel_time), encoding="utf-8")
    return str(path)


def test_default_reference_is_head_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git_repo(tmp_path, monkeypatch, REFERENCE.isoformat())
    at_cutoff = _write_lock(tmp_path / "a.lock", "2026-10-30T00:00:00Z")
    after_cutoff = _write_lock(tmp_path / "b.lock", "2026-10-30T00:00:01Z")
    assert cooldown.main(["--lock", at_cutoff]) == 0
    assert cooldown.main(["--lock", after_cutoff]) == 1


def test_future_head_commit_is_clamped_to_now(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git_repo(tmp_path, monkeypatch, "2030-01-01T00:00:00Z")
    assert cooldown.default_reference(now=REFERENCE) == REFERENCE
    assert cooldown.default_reference() <= datetime.now(UTC)
    # Would pass against the 2030 commit date; must fail against now.
    fresh = _write_lock(tmp_path / "c.lock", datetime.now(UTC).isoformat())
    assert cooldown.main(["--lock", fresh]) == 1


def test_older_head_commit_is_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git_repo(tmp_path, monkeypatch, REFERENCE.isoformat())
    later = datetime(2031, 1, 1, tzinfo=UTC)
    assert cooldown.default_reference(now=later) == REFERENCE


def test_run_as_script(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lock = _write_lock(tmp_path / "d.lock", "2026-10-01T00:00:00Z")
    argv = ["check_lock_cooldown.py", "--lock", lock, "--reference", "2026-11-06"]
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(str(SCRIPT), run_name="__main__")
    assert exc.value.code == 0
