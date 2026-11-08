# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Line-based checks on the release files (AL4).

Spec: ``docs/plans/al4.md`` sections 3, 5 and 6. There is no YAML parser in
the dev group, so the workflows and issue forms are read as text and must
keep the 2-space layout of the plan's ``publish.yml`` skeleton. A reformatted
file fails these tests loudly rather than passing silently.

From an unpacked sdist, which ships no ``.github/``, the module skips
(section 13.8).
"""

import re
from pathlib import Path

import pytest

import authresults

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
PUBLISH = WORKFLOWS / "publish.yml"
ISSUE_TEMPLATES = ROOT / ".github" / "ISSUE_TEMPLATE"
CHANGELOG = ROOT / "CHANGELOG.md"
REPO = "https://github.com/jrapakko/authresults"

if not WORKFLOWS.is_dir():  # section 13.8: an unpacked sdist ships no .github/
    pytest.skip(
        "needs .github/workflows (not shipped in the sdist)", allow_module_level=True
    )

PUBLISH_JOBS = ("publish-testpypi", "publish-pypi")
BUILD_COMMAND = "uv build --build-constraints build-constraints.txt --require-hashes"
_USES = re.compile(r"uses: [\w.-]+/[\w./-]+@[0-9a-f]{40} # v\d+(\.\d+)*$")
_JOB = re.compile(r"  ([\w-]+):\s*(?:#.*)?")


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _top_level_block(lines: list[str], key: str) -> list[str]:
    """The lines under a column-0 ``key:`` up to the next column-0 line."""
    start = lines.index(f"{key}:")
    block: list[str] = []
    for line in lines[start + 1 :]:
        if line and not line.startswith((" ", "#")):
            break
        block.append(line)
    return block


def _jobs(lines: list[str]) -> dict[str, list[str]]:
    jobs: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in _top_level_block(lines, "jobs"):
        match = _JOB.fullmatch(line)
        if match:
            current = jobs.setdefault(match.group(1), [])
        elif current is not None:
            current.append(line)
    return jobs


def _code(lines: list[str]) -> str:
    """The lines joined, without full-line comments (the skeleton's header
    comment names ``id-token: write`` and "no secrets.")."""
    return "\n".join(line for line in lines if not line.lstrip().startswith("#"))


def _stripped(lines: list[str]) -> list[str]:
    return [line.strip() for line in lines]


def _run_texts(lines: list[str]) -> list[str]:
    """The text of every ``run:`` value: inline, or a block at deeper indent."""
    texts: list[str] = []
    i = 0
    while i < len(lines):
        match = re.fullmatch(r"( *)(- )?run:\s*(.*)", lines[i])
        i += 1
        if match is None:
            continue
        value = match.group(3)
        if not re.fullmatch(r"[|>][+-]?", value):
            texts.append(value)
            continue
        key_indent = len(match.group(1)) + len(match.group(2) or "")
        body: list[str] = []
        while i < len(lines) and (
            not lines[i].strip() or _indent(lines[i]) > key_indent
        ):
            body.append(lines[i])
            i += 1
        texts.append("\n".join(body))
    return texts


def _steps_using(lines: list[str], action: str) -> list[list[str]]:
    """Each step whose ``uses:`` names *action*, up to the next step."""
    steps: list[list[str]] = []
    for i, line in enumerate(lines):
        if not re.fullmatch(rf" *- uses: {re.escape(action)}@.*", line):
            continue
        dash = _indent(line)
        step = [line]
        for following in lines[i + 1 :]:
            if following.strip() and _indent(following) <= dash:
                break
            step.append(following)
        steps.append(step)
    return steps


# Helpers checked on planted text, so the publish.yml tests below rest on
# behaviour seen to work.

_PLANTED = """\
name: X

on:
  push:
    tags: ["v*"]

jobs:
  one:
    steps:
      - uses: astral-sh/setup-uv@0000000000000000000000000000000000000000 # v1.0.0
        with:
          enable-cache: false
      - run: echo ${{ a }}
      - name: b
        run: |
          echo one
            ${{ b }}

          echo two
      - run: echo three
  two:                     # a comment
    steps:
      - run: >-
          echo four
"""


def test_line_helpers() -> None:
    lines = _PLANTED.splitlines()
    assert _stripped(_top_level_block(lines, "on")) == ["push:", 'tags: ["v*"]', ""]
    jobs = _jobs(lines)
    assert list(jobs) == ["one", "two"]
    assert _run_texts(jobs["one"]) == [
        "echo ${{ a }}",
        "          echo one\n            ${{ b }}\n\n          echo two",
        "echo three",
    ]
    assert _run_texts(jobs["two"]) == ["          echo four"]
    steps = _steps_using(lines, "astral-sh/setup-uv")
    assert len(steps) == 1
    assert "enable-cache: false" in _stripped(steps[0])


# 1. Every workflow (acceptance criterion 7).

_ALL_WORKFLOWS = sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])


def test_publish_workflow_exists() -> None:
    assert PUBLISH in _ALL_WORKFLOWS


@pytest.fixture(params=_ALL_WORKFLOWS, ids=lambda p: p.name)
def workflow(request: pytest.FixtureRequest) -> list[str]:
    path: Path = request.param
    return _lines(path)


def test_uses_pinned_by_sha_with_version(workflow: list[str]) -> None:
    uses = [line for line in workflow if re.match(r" *(- )?uses:", line)]
    assert uses
    assert [line for line in uses if not _USES.search(line)] == []


def test_top_level_permissions_empty(workflow: list[str]) -> None:
    assert "permissions: {}" in workflow


def test_no_secrets_or_pull_request_target(workflow: list[str]) -> None:
    text = _code(workflow)
    assert "pull_request_target" not in text
    assert "secrets." not in text


def test_checkout_does_not_persist_credentials(workflow: list[str]) -> None:
    checkouts = [line for line in workflow if "uses: actions/checkout@" in line]
    persist = [
        line for line in workflow if line.strip() == "persist-credentials: false"
    ]
    assert len(checkouts) == len(persist)


def test_setup_uv_without_cache(workflow: list[str]) -> None:
    for step in _steps_using(workflow, "astral-sh/setup-uv"):
        assert "enable-cache: false" in _stripped(step)


# 2. publish.yml (acceptance criterion 8).


@pytest.fixture(scope="module")
def publish() -> list[str]:
    return _lines(PUBLISH)


@pytest.fixture(scope="module")
def jobs(publish: list[str]) -> dict[str, list[str]]:
    return _jobs(publish)


def _meaningful(lines: list[str]) -> list[str]:
    return [s for s in _stripped(lines) if s and not s.startswith("#")]


def test_publish_triggers(publish: list[str]) -> None:
    assert _meaningful(_top_level_block(publish, "on")) == [
        "push:",
        'tags: ["v*"]',
        "workflow_dispatch:",
    ]


def test_publish_jobs(jobs: dict[str, list[str]]) -> None:
    assert list(jobs) == ["build", *PUBLISH_JOBS, "github-release"]


def test_publish_build_job(jobs: dict[str, list[str]]) -> None:
    build = jobs["build"]
    text = _code(build)
    assert "contents: read" in _stripped(build)
    assert "id-token" not in text
    assert BUILD_COMMAND in text


def test_publish_build_checks_tag_and_dist(jobs: dict[str, list[str]]) -> None:
    text = _code(jobs["build"])
    # The tagged commit is on main.
    assert "git merge-base --is-ancestor" in text
    assert "origin/main" in text
    # The tag is "v" + __version__.
    assert "__version__" in text
    assert '"v$version"' in text
    # Exactly one wheel and one sdist, named for the version.
    assert "authresults-$version-py3-none-any.whl" in text
    assert "authresults-$version.tar.gz" in text


FINAL_VERSION_PATTERN = r"^[0-9]+\.[0-9]+\.[0-9]+$"


def test_publish_build_refuses_non_final_on_tags(jobs: dict[str, list[str]]) -> None:
    # Section 14.2a (red-team L1): on a tag run, a version with a dev, a, b,
    # rc or local part is refused. One run block of the build job tests
    # $version against the final-release pattern and is tied to the push event.
    blocks = [
        t
        for t in _run_texts(jobs["build"])
        if FINAL_VERSION_PATTERN in t and "$version" in t and "push" in t
    ]
    assert len(blocks) == 1
    assert "exit 1" in blocks[0]


def test_id_token_only_in_publish_jobs(
    publish: list[str], jobs: dict[str, list[str]]
) -> None:
    with_id_token = {name for name, body in jobs.items() if "id-token" in _code(body)}
    assert with_id_token == set(PUBLISH_JOBS)
    for name in PUBLISH_JOBS:
        assert any(s.startswith("id-token: write") for s in _stripped(jobs[name]))
    assert "id-token" not in _code(publish[: publish.index("jobs:")])


def test_contents_write_only_in_github_release(
    publish: list[str], jobs: dict[str, list[str]]
) -> None:
    with_write = {
        name for name, body in jobs.items() if "contents: write" in _code(body)
    }
    assert with_write == {"github-release"}
    assert "contents: write" not in _code(publish[: publish.index("jobs:")])


def _if_line(body: list[str]) -> str:
    found = [s for s in _stripped(body) if s.startswith("if:")]
    assert len(found) == 1
    return found[0]


def test_publish_pypi_job(jobs: dict[str, list[str]]) -> None:
    body = jobs["publish-pypi"]
    assert "name: pypi" in _stripped(body)
    assert "refs/tags/v" in _if_line(body)


def test_publish_testpypi_job(jobs: dict[str, list[str]]) -> None:
    body = jobs["publish-testpypi"]
    assert "name: testpypi" in _stripped(body)
    condition = _if_line(body)
    assert "workflow_dispatch" in condition
    assert "refs/heads/main" in condition
    assert "repository-url: https://test.pypi.org/legacy/" in _stripped(body)


@pytest.mark.parametrize("name", PUBLISH_JOBS)
def test_publish_jobs_only_download(jobs: dict[str, list[str]], name: str) -> None:
    text = _code(jobs[name])
    assert "actions/checkout" not in text
    assert not re.search(r"\buv\b", text)
    assert "uses: pypa/gh-action-pypi-publish@" in text
    assert "uses: actions/download-artifact@" in text


@pytest.mark.parametrize("name", PUBLISH_JOBS)
def test_publish_jobs_check_dist(jobs: dict[str, list[str]], name: str) -> None:
    runs = "\n".join(_run_texts(jobs[name]))
    assert "-eq 2" in runs
    assert "dist/*.whl" in runs
    assert "dist/*.tar.gz" in runs


def test_github_release_job(jobs: dict[str, list[str]]) -> None:
    body = _stripped(jobs["github-release"])
    assert "contents: write" in [s.split("#")[0].strip() for s in body]
    needs = [s for s in body if s.startswith("needs:")]
    assert len(needs) == 1
    assert "publish-pypi" in needs[0]


def test_no_expressions_in_run(publish: list[str]) -> None:
    assert [t for t in _run_texts(publish) if "${{" in t] == []


# 3. Issue template (acceptance criterion 9).


@pytest.mark.parametrize(
    "needle",
    [
        "python -m authresults.redact",
        "RFC 2606",
        "RFC 5737",
        "reason",
        "position",
        "known_shape",
        "--show-originals",
        "security/advisories/new",
    ],
)
def test_issue_form(needle: str) -> None:
    text = (ISSUE_TEMPLATES / "header-shape.yml").read_text(encoding="utf-8")
    assert needle in text


def test_issue_form_domain_checkbox_mentions_vendor_hostnames() -> None:
    # Section 14.7 (red-team L4): the redaction helper keeps vendor hostnames.
    lines = _lines(ISSUE_TEMPLATES / "header-shape.yml")
    start = lines.index("  - type: checkboxes")
    labels = [
        s.removeprefix("- label:").strip()
        for s in _stripped(lines[start:])
        if s.startswith("- label:")
    ]
    domain = [label for label in labels if label.lower().startswith("domains")]
    assert len(domain) == 1
    assert "vendor" in domain[0].lower()
    assert "hostname" in domain[0].lower()


def test_issue_config() -> None:
    lines = _lines(ISSUE_TEMPLATES / "config.yml")
    assert "blank_issues_enabled: true" in lines  # AU-Q78
    assert "security/advisories/new" in "\n".join(lines)


# 4. Version and CHANGELOG (acceptance criterion 10).

_VERSION = re.compile(r"(\d+\.\d+\.\d+)(\.dev\d+)?")


def _changelog_problems(text: str, version: str) -> list[str]:
    match = _VERSION.fullmatch(version)
    if match is None:
        return [f"version {version!r}"]
    lines = text.splitlines()
    problems = [] if "## [Unreleased]" in lines else ["no ## [Unreleased]"]
    base = match.group(1)
    headings = [i for i, line in enumerate(lines) if line.startswith(f"## [{base}]")]
    if match.group(2):
        return problems + (["heading for an unreleased version"] if headings else [])
    dated = [
        i
        for i in headings
        if re.fullmatch(
            rf"## \[{re.escape(base)}\] - \d{{4}}-\d{{2}}-\d{{2}}", lines[i]
        )
    ]
    if len(dated) != 1 or len(headings) != 1:
        return [*problems, "no single dated heading"]
    link = f"[{base}]: {REPO}/releases/tag/v{base}"
    if link not in lines:
        problems.append("no link line")
    body = []
    for line in lines[dated[0] + 1 :]:
        if line.startswith("## ["):
            break
        body.append(line)
    if not any(line.strip() and not line.startswith("[") for line in body):
        problems.append("empty section")
    return problems


_RELEASED = f"""\
# Changelog

## [Unreleased]

## [1.2.3] - 2026-11-09

### Added

- Something.

## [1.2.2] - 2026-10-01

- Older.

[Unreleased]: {REPO}/compare/v1.2.3...HEAD
[1.2.3]: {REPO}/releases/tag/v1.2.3
"""


def test_changelog_rule_on_planted_text() -> None:
    assert _changelog_problems(_RELEASED, "1.2.3") == []
    assert _changelog_problems(_RELEASED, "1.2.4.dev0") == []
    assert _changelog_problems(_RELEASED, "1.2.3.dev0") == [
        "heading for an unreleased version"
    ]
    assert _changelog_problems(_RELEASED, "1.2.4") == ["no single dated heading"]
    assert _changelog_problems(_RELEASED, "1.2") == ["version '1.2'"]
    undated = _RELEASED.replace("## [1.2.3] - 2026-11-09", "## [1.2.3]")
    assert _changelog_problems(undated, "1.2.3") == ["no single dated heading"]
    unlinked = _RELEASED.replace(f"[1.2.3]: {REPO}/releases/tag/v1.2.3\n", "")
    assert _changelog_problems(unlinked, "1.2.3") == ["no link line"]
    empty = _RELEASED.replace("### Added\n\n- Something.\n\n", "")
    assert _changelog_problems(empty, "1.2.3") == ["empty section"]
    no_unreleased = _RELEASED.replace("## [Unreleased]\n\n", "")
    assert _changelog_problems(no_unreleased, "1.2.3") == ["no ## [Unreleased]"]


def test_version_format() -> None:
    assert _VERSION.fullmatch(authresults.__version__)


def test_changelog_matches_version() -> None:
    text = CHANGELOG.read_text(encoding="utf-8")
    assert _changelog_problems(text, authresults.__version__) == []
