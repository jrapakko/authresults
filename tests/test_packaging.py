# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Checks on the built distributions: pure Python, no runtime dependencies.

The wheel and sdist are built with the locked ``flit_core`` into a temporary
directory. Set ``AUTHRESULTS_WHEEL`` and ``AUTHRESULTS_SDIST`` to the paths of
already built files (as CI does after ``uv build``) to check those instead.

Both file lists are checked against an allowlist, so a stray file (a native
extension, a vendored package, a dotfile, a cache directory) fails the test.
"""

import email.parser
import email.policy
import importlib.metadata
import os
import re
import tarfile
import tomllib
import zipfile
from collections.abc import Callable, Iterator
from email.message import Message
from pathlib import Path

import pytest
from flit_core import buildapi  # type: ignore[import-untyped]

import authresults

ROOT = Path(__file__).resolve().parent.parent
NAME = "authresults"
VERSION = authresults.__version__
MODULE = r"[a-z_][a-z0-9_]*\.py"

WHEEL_DIST_INFO = {
    f"{NAME}-{VERSION}.dist-info/{name}"
    for name in ("METADATA", "WHEEL", "RECORD", "licenses/LICENSE", "licenses/NOTICE")
}
SDIST_TOP_LEVEL = {
    "PKG-INFO",
    "pyproject.toml",
    "README.md",
    "LICENSE",
    "NOTICE",
    "CHANGELOG.md",
    "build-constraints.txt",
    "uv.lock",
}


def _built(
    tmp_path_factory: pytest.TempPathFactory, env: str, build: Callable[[str], str]
) -> Path:
    given = os.environ.get(env)
    if given:
        return Path(given)
    out = tmp_path_factory.mktemp("dist")
    with pytest.MonkeyPatch.context() as mp:
        mp.chdir(ROOT)
        name = build(str(out))
    return out / name


@pytest.fixture(scope="module")
def wheel(tmp_path_factory: pytest.TempPathFactory) -> Iterator[zipfile.ZipFile]:
    path = _built(tmp_path_factory, "AUTHRESULTS_WHEEL", buildapi.build_wheel)
    with zipfile.ZipFile(path) as zf:
        yield zf


@pytest.fixture(scope="module")
def sdist(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tarfile.TarFile]:
    path = _built(tmp_path_factory, "AUTHRESULTS_SDIST", buildapi.build_sdist)
    with tarfile.open(path) as tf:
        yield tf


def _parse(data: bytes) -> Message:
    return email.parser.BytesParser(policy=email.policy.compat32).parsebytes(data)


def _wheel_meta(wheel: zipfile.ZipFile, name: str) -> Message:
    return _parse(wheel.read(f"{NAME}-{VERSION}.dist-info/{name}"))


def _check_core_metadata(meta: Message) -> None:
    assert meta.get_all("Requires-Dist") is None
    assert meta["Name"] == NAME
    assert meta["Version"] == VERSION
    assert meta["License-Expression"] == "Apache-2.0"
    assert meta["Requires-Python"] == ">=3.11"


def test_wheel_is_pure_python(wheel: zipfile.ZipFile) -> None:
    meta = _wheel_meta(wheel, "WHEEL")
    assert meta.get_all("Tag") == ["py3-none-any"]
    assert meta["Root-Is-Purelib"] == "true"


def test_wheel_has_no_runtime_dependencies(wheel: zipfile.ZipFile) -> None:
    _check_core_metadata(_wheel_meta(wheel, "METADATA"))


def test_wheel_contents_allowlist(wheel: zipfile.ZipFile) -> None:
    names = set(wheel.namelist())
    unexpected = sorted(
        n
        for n in names - WHEEL_DIST_INFO
        if n != f"{NAME}/py.typed" and not re.fullmatch(rf"{NAME}/{MODULE}", n)
    )
    assert unexpected == []
    assert names >= WHEEL_DIST_INFO | {f"{NAME}/__init__.py", f"{NAME}/py.typed"}


def test_sdist_contents_allowlist(sdist: tarfile.TarFile) -> None:
    prefix = f"{NAME}-{VERSION}/"
    members = sdist.getmembers()
    assert all(m.isfile() for m in members)
    names = {m.name for m in members}
    assert all(n.startswith(prefix) for n in names)
    rel = {n.removeprefix(prefix) for n in names}
    unexpected = sorted(
        n
        for n in rel - SDIST_TOP_LEVEL
        if n != f"src/{NAME}/py.typed"
        and not re.fullmatch(rf"(src/{NAME}|tests|scripts)/{MODULE}", n)
    )
    assert unexpected == []
    assert rel >= SDIST_TOP_LEVEL | {f"src/{NAME}/__init__.py", f"src/{NAME}/py.typed"}


REDACT_MODULES = ("redact.py", "_redact.py")  # AL3d: python -m authresults.redact


def test_wheel_has_the_redaction_helper(wheel: zipfile.ZipFile) -> None:
    names = set(wheel.namelist())
    assert {f"{NAME}/{m}" for m in REDACT_MODULES} <= names
    # The only entry point is ``python -m``: no console script.
    assert not any(n.endswith("entry_points.txt") for n in names)


def test_sdist_has_the_redaction_helper(sdist: tarfile.TarFile) -> None:
    names = set(sdist.getnames())
    assert {f"{NAME}-{VERSION}/src/{NAME}/{m}" for m in REDACT_MODULES} <= names


def test_sdist_metadata(sdist: tarfile.TarFile) -> None:
    member = sdist.extractfile(f"{NAME}-{VERSION}/PKG-INFO")
    assert member is not None
    _check_core_metadata(_parse(member.read()))


def test_build_constraint_matches_lock() -> None:
    text = (ROOT / "build-constraints.txt").read_text(encoding="utf-8")
    match = re.search(r"^flit-core==(\S+)", text, re.MULTILINE)
    assert match is not None
    assert match.group(1) == importlib.metadata.version("flit-core")


# AL4: the README is the PyPI page (docs/plans/al4.md section 6).


def _long_description(data: bytes) -> tuple[str | None, str]:
    """The content type and the body of a core metadata file.

    Parsed from text, so a non-ASCII README compares as text.
    """
    meta = email.parser.Parser(policy=email.policy.compat32).parsestr(
        data.decode("utf-8")
    )
    body = meta.get_payload()
    assert isinstance(body, str)
    return meta["Description-Content-Type"], body


def _sdist_pkg_info(sdist: tarfile.TarFile) -> bytes:
    member = sdist.extractfile(f"{NAME}-{VERSION}/PKG-INFO")
    assert member is not None
    return member.read()


def test_long_description_is_the_readme(
    wheel: zipfile.ZipFile, sdist: tarfile.TarFile
) -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8").strip()
    for data in (
        wheel.read(f"{NAME}-{VERSION}.dist-info/METADATA"),
        _sdist_pkg_info(sdist),
    ):
        content_type, body = _long_description(data)
        assert content_type == "text/markdown"
        assert body.strip() == readme


def test_project_urls(wheel: zipfile.ZipFile, sdist: tarfile.TarFile) -> None:
    with (ROOT / "pyproject.toml").open("rb") as f:
        urls = tomllib.load(f)["project"]["urls"]
    expected = {f"{label}, {url}" for label, url in urls.items()}
    assert len(expected) == 3  # noqa: PLR2004 - Source, Issues, Changelog
    for meta in (_wheel_meta(wheel, "METADATA"), _parse(_sdist_pkg_info(sdist))):
        assert expected <= set(meta.get_all("Project-URL") or [])


@pytest.mark.skipif(
    ".dev" in VERSION,
    reason="release-only: a dev version keeps its classifier (al4 section 13.4)",
)
def test_release_classifier(wheel: zipfile.ZipFile, sdist: tarfile.TarFile) -> None:
    # AU-Q74: 0.1.0 is an alpha. Active from the release commit on.
    for meta in (_wheel_meta(wheel, "METADATA"), _parse(_sdist_pkg_info(sdist))):
        assert "Development Status :: 3 - Alpha" in (meta.get_all("Classifier") or [])
