# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Checks on ``README.md``, which is also the PyPI page (AL4).

Spec: ``docs/plans/al4.md`` sections 4, 6 and 13. The bodies of the
``pycon`` blocks run under stdlib ``doctest`` as one test in file order, with
one shared namespace (section 13.1: only the bodies, so a closing fence is
never read as expected output). Each ``python`` block runs on its own through
``runpy.run_path``, and the recipes it defines are then exercised on synthetic
values with RFC 2606 names.

From an unpacked sdist (no git, no ``.github/``, no ``docs/``), only the checks
that need those skip (section 13.8); the rest needs only ``README.md`` and the
package.
"""

import ast
import doctest
import ipaddress
import logging
import re
import runpy
import subprocess
from collections.abc import Callable
from pathlib import Path
from types import FunctionType
from typing import Any, NamedTuple

import pytest

from authresults import (
    AuthenticationResults,
    AuthResultsError,
    Deviation,
    ErrorReason,
    KnownShape,
    _registry,
    parse,
)

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
REPO = "https://github.com/jrapakko/authresults"
BLOB = f"{REPO}/blob/main/"
ISSUE_FORM_URL = f"{REPO}/issues/new?template=header-shape.yml"
MAX_LINES = 550
MIN_DOCTESTS = 12

H2 = [
    "Install",
    "Quick start",
    "What it does and does not do",
    "Using it on received mail",
    "The result model",
    "Strict and lenient parsing",
    "Errors",
    "Helpers",
    "Shapes known from real software",
    "Seeing a refusal on real mail?",
    "Redacting a value for a report",
    "Versioning and stability",
    "Security",
    "Contributing and licence",
]
STRICT_H3 = [
    "Characters in unquoted values",
    'A missing ";" between results',
    "X- fields such as X-TM-Authentication-Results",
    "Non-ASCII input",
]
TSPECIALS_HEADING = "Characters in unquoted values"


class Block(NamedTuple):
    lang: str
    line: int  # 1-based line of the opening fence
    body: str


class Readme(NamedTuple):
    text: str
    blocks: list[Block]
    prose: list[tuple[int, str]]  # (1-based line number, line) outside fences


_FENCE = re.compile(r"( *)```\s*([\w+-]*)\s*")


def _split(text: str) -> Readme:
    blocks: list[Block] = []
    prose: list[tuple[int, str]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        opened = _FENCE.fullmatch(lines[i])
        if opened is None:
            prose.append((i + 1, lines[i]))
            i += 1
            continue
        indent = len(opened.group(1))
        start = i
        body: list[str] = []
        i += 1
        while i < len(lines) and not re.fullmatch(r" *```\s*", lines[i]):
            body.append(lines[i][indent:] if lines[i][:indent].isspace() else lines[i])
            i += 1
        assert i < len(lines), f"unclosed fence at line {start + 1}"
        body_text = "\n".join(body) + "\n" if body else ""
        blocks.append(Block(opened.group(2).lower(), start + 1, body_text))
        i += 1
    return Readme(text, blocks, prose)


@pytest.fixture(scope="module")
def readme() -> Readme:
    return _split(README.read_text(encoding="utf-8"))


def _headings(readme: Readme) -> list[tuple[int, str]]:
    found = []
    for _, line in readme.prose:
        match = re.fullmatch(r"(#{1,6})\s+(.+?)\s*", line)
        if match:
            found.append((len(match.group(1)), match.group(2)))
    return found


def _section(readme: Readme, level: int, title: str) -> str:
    """The prose and blocks under one heading, up to the next of its level."""
    lines = readme.text.splitlines()
    start = None
    for number, line in readme.prose:
        match = re.fullmatch(r"(#{1,6})\s+(.+?)\s*", line)
        if match is None:
            continue
        if start is None:
            if len(match.group(1)) == level and match.group(2) == title:
                start = number
        elif len(match.group(1)) <= level:
            return "\n".join(lines[start : number - 1])
    assert start is not None, f"no heading {'#' * level} {title}"
    return "\n".join(lines[start:])


def _blocks(readme: Readme, lang: str) -> list[Block]:
    return [b for b in readme.blocks if b.lang == lang]


# 1. Headings (acceptance criterion 3).


def test_h1_is_the_project_name(readme: Readme) -> None:
    headings = _headings(readme)
    assert headings[0] == (1, "authresults")
    assert [h for h in headings if h[0] == 1] == [(1, "authresults")]


def test_h2_headings_in_order(readme: Readme) -> None:
    h2 = [title for level, title in _headings(readme) if level == 2]  # noqa: PLR2004
    present = [title for title in h2 if title in H2]
    assert present == H2


def test_strict_parsing_subsections_in_order(readme: Readme) -> None:
    section = _split(_section(readme, 2, "Strict and lenient parsing"))
    h3 = [title for level, title in _headings(section) if level == 3]  # noqa: PLR2004
    assert [title for title in h3 if title in STRICT_H3] == STRICT_H3


def test_within_the_line_ceiling(readme: Readme) -> None:
    assert len(readme.text.splitlines()) <= MAX_LINES


# 2. Doctest (acceptance criterion 2).


def test_pycon_and_python_fences_kept_apart(readme: Readme) -> None:
    assert _blocks(readme, "pycon"), "no pycon blocks"
    for block in _blocks(readme, "pycon"):
        assert re.search(r"^>>> ", block.body, re.MULTILINE), block.line
    for block in _blocks(readme, "python"):
        assert ">>>" not in block.body, block.line


def _pycon_text(readme: Readme) -> str:
    """The ``pycon`` bodies at their README line numbers; all else blank."""
    lines = [""] * len(readme.text.splitlines())
    for block in _blocks(readme, "pycon"):
        body = block.body.splitlines()
        lines[block.line : block.line + len(body)] = body
    return "\n".join(lines) + "\n"


def test_pycon_text_keeps_line_numbers() -> None:
    sample = _split("x\n```pycon\n>>> 1\n1\n```\n>>> 2\n```pycon\n>>> 3\n```\n")
    assert _pycon_text(sample) == "\n\n>>> 1\n1\n\n\n\n>>> 3\n\n"


def test_doctest_pycon_blocks(readme: Readme) -> None:
    test = doctest.DocTestParser().get_doctest(
        _pycon_text(readme), {}, "README.md", str(README), 0
    )
    runner = doctest.DocTestRunner(optionflags=doctest.ELLIPSIS)
    report: list[str] = []
    result = runner.run(test, out=report.append)
    assert result.failed == 0, "".join(report)
    assert result.attempted >= MIN_DOCTESTS


# 3. Script blocks (acceptance criterion 2).


@pytest.fixture(scope="module")
def namespaces(
    readme: Readme, tmp_path_factory: pytest.TempPathFactory
) -> list[dict[str, Any]]:
    out = tmp_path_factory.mktemp("readme")
    found = []
    for block in _blocks(readme, "python"):
        path = out / f"block_line_{block.line}.py"
        path.write_text(block.body, encoding="utf-8")
        found.append(runpy.run_path(str(path), run_name="readme_block"))
    return found


def _defined(namespaces: list[dict[str, Any]], name: str) -> Any:  # noqa: ANN401
    owners = [ns for ns in namespaces if name in ns]
    assert owners, f"no python block defines {name}"
    return owners[0][name]


def test_python_blocks_run(namespaces: list[dict[str, Any]]) -> None:
    assert namespaces, "no python blocks"


@pytest.mark.parametrize(
    "name",
    [
        "trusted_results",
        "dmarc_pass",
        "dkim_pass_domains",
        "EXPECTED_DEVIATIONS",
        "parse_or_log",
    ],
)
def test_recipe_is_defined(namespaces: list[dict[str, Any]], name: str) -> None:
    _defined(namespaces, name)


# 4. trusted_results.

OUR_ID = "mx.example.net"
RECEIVED = (
    "Received: from mail.example.org by mx.example.net; Sat, 07 Nov 2026 10:00:00 +0000"
)
OURS = f"Authentication-Results: {OUR_ID}; dkim=pass header.d=example.com"


def _message(*fields: str) -> bytes:
    head = "\r\n".join(("From: a@example.com", *fields, "Subject: t"))
    return (head + "\r\n\r\nbody\r\n").encode("utf-8")


TrustedResults = Callable[[bytes, str], AuthenticationResults | None]


@pytest.fixture(scope="module")
def trusted_results(namespaces: list[dict[str, Any]]) -> TrustedResults:
    found: TrustedResults = _defined(namespaces, "trusted_results")
    return found


def test_trusted_results_above_received(trusted_results: TrustedResults) -> None:
    got = trusted_results(_message(OURS, RECEIVED), OUR_ID)
    assert isinstance(got, AuthenticationResults)
    assert got.authserv_id == OUR_ID
    assert [(r.method, r.result) for r in got.results] == [("dkim", "pass")]


def test_trusted_results_name_case_insensitive(trusted_results: TrustedResults) -> None:
    lower = OURS.replace("Authentication-Results", "authentication-RESULTS")
    got = trusted_results(_message(lower, RECEIVED), OUR_ID)
    assert isinstance(got, AuthenticationResults)


@pytest.mark.parametrize(
    "fields",
    [
        pytest.param((RECEIVED, OURS), id="below received"),
        pytest.param(
            (OURS.replace(OUR_ID, "other.example.net"), RECEIVED), id="other id"
        ),
        pytest.param((OURS, OURS, RECEIVED), id="two with our id"),
        pytest.param((OURS,), id="no received"),
        pytest.param(
            (
                OURS,
                f"Authentication-Results: {OUR_ID}; dkim=pass header.d=exämple.com",
                RECEIVED,
            ),
            id="non-ascii candidate",
        ),
        pytest.param(
            (OURS, f"Authentication-Results: {OUR_ID}; none ({'a' * 9000})", RECEIVED),
            id="oversize candidate",
        ),
        pytest.param(
            ("Authentication-Results: dkim=pass header.d=example.com", RECEIVED),
            id="missing authserv-id",
        ),
    ],
)
def test_trusted_results_refuses(
    trusted_results: TrustedResults, fields: tuple[str, ...]
) -> None:
    assert trusted_results(_message(*fields), OUR_ID) is None


def test_trusted_results_folded(trusted_results: TrustedResults) -> None:
    folded = f"Authentication-Results: {OUR_ID};\r\n\tdkim=pass header.d=example.com"
    got = trusted_results(_message(folded, RECEIVED), OUR_ID)
    assert isinstance(got, AuthenticationResults)
    assert got.authserv_id == OUR_ID
    dkim = got.results_for("dkim")
    assert [r.result for r in dkim] == ["pass"]
    prop = dkim[0].get_unique("header", "d")
    assert prop is not None
    assert prop.value == "example.com"


# 5. dmarc_pass.

DmarcPass = Callable[[AuthenticationResults, str], bool]


@pytest.fixture(scope="module")
def dmarc_pass(namespaces: list[dict[str, Any]]) -> DmarcPass:
    found: DmarcPass = _defined(namespaces, "dmarc_pass")
    return found


def test_expected_deviations_is_empty(namespaces: list[dict[str, Any]]) -> None:
    assert _defined(namespaces, "EXPECTED_DEVIATIONS") == frozenset()


def test_dmarc_pass_true(dmarc_pass: DmarcPass) -> None:
    ar = parse(f"{OUR_ID}; dmarc=pass header.from=example.com")
    assert dmarc_pass(ar, "Example.COM") is True


MISSING_SEMICOLON = (
    f"{OUR_ID}; dmarc=pass header.from=example.com;"
    " dkim=pass spf=pass smtp.mailfrom=example.com"
)


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(
            f"{OUR_ID}; dkim=fail (dmarc=pass header.from=example.com)"
            " header.d=example.com",
            id="only in a comment",
        ),
        pytest.param(
            f"{OUR_ID}; dmarc=pass header.from=example.com header.from=example.com",
            id="duplicate header.from",
        ),
        pytest.param(
            f"{OUR_ID}; dmarc=pass header.from=example.org", id="other domain"
        ),
        pytest.param(
            f"{OUR_ID}; dmarc=passed header.from=example.com", id="unregistered"
        ),
        pytest.param(
            f"{OUR_ID}; dmarc=pass header.from=example.com;"
            " dmarc=pass header.from=example.com",
            id="two dmarc results",
        ),
        pytest.param(MISSING_SEMICOLON, id="deviation"),
    ],
)
def test_dmarc_pass_false(dmarc_pass: DmarcPass, value: str) -> None:
    assert dmarc_pass(parse(value), "example.com") is False


def test_dmarc_pass_deviation_case_is_a_deviation() -> None:
    assert Deviation.BARE_PROPERTY in parse(MISSING_SEMICOLON).deviations


# 6. dkim_pass_domains.

DkimPassDomains = Callable[[AuthenticationResults], frozenset[str]]


@pytest.fixture(scope="module")
def dkim_pass_domains(namespaces: list[dict[str, Any]]) -> DkimPassDomains:
    found: DkimPassDomains = _defined(namespaces, "dkim_pass_domains")
    return found


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param(
            f"{OUR_ID}; dkim=pass header.d=Example.COM",
            frozenset({"example.com"}),
            id="header.d",
        ),
        pytest.param(
            f"{OUR_ID}; dkim=pass header.i=@sub.example.com",
            frozenset({"sub.example.com"}),
            id="header.i",
        ),
        pytest.param(
            f"{OUR_ID}; dkim=fail header.d=example.com; dkim=pass header.d=example.org",
            frozenset({"example.org"}),
            id="fail ignored",
        ),
        pytest.param(
            f"{OUR_ID}; dkim=pass header.d=example.org;"
            " dkim=pass header.d=example.com header.d=example.net",
            frozenset(),
            id="duplicate header.d",
        ),
    ],
)
def test_dkim_pass_domains(
    dkim_pass_domains: DkimPassDomains, value: str, expected: frozenset[str]
) -> None:
    assert dkim_pass_domains(parse(value)) == expected


# 6b. Section 14.1 (red-team M1): accepting PVALUE_TSPECIALS re-opens the
# balanced-bracket field splitting, so the decision block defines a safer
# check, no_bracketed_values(results): True only if no property has "<",
# ">", "[" or "]" in its raw text (section 14.10: header.b is not exempt, as
# a DKIM signature is base64). The recipe's deviation check calls it whenever
# PVALUE_TSPECIALS is in EXPECTED_DEVIATIONS (section 14.9).

GUARD = "no_bracketed_values"
INJECTED_DKIM = (
    f"{OUR_ID}; spf=fail smtp.mailfrom=<x>; dkim=pass header.d=bank.example"
    " header.b=<>; dkim=fail header.d=evil.example header.b=Ab+/cd="
)
INJECTED_DMARC = (
    f"{OUR_ID}; spf=fail smtp.mailfrom=<x>; dmarc=pass header.from=bank.example"
    " header.b=<>"
)
INJECTED_SIGNATURE = (  # section 14.10: the split hides in header.b itself
    f"{OUR_ID}; dkim=fail header.b=<x>; dkim=pass header.d=bank.example"
    " header.b=<>; dmarc=pass header.from=bank.example"
)
INJECTED = [INJECTED_DKIM, INJECTED_DMARC, INJECTED_SIGNATURE]
INJECTED_IDS = ["dkim", "dmarc", "signature"]
LEGIT_SIGNATURE = f"{OUR_ID}; dkim=pass header.d=example.com header.b=Ab+/cd="

Guard = Callable[[AuthenticationResults], bool]


@pytest.fixture(scope="module")
def guard(namespaces: list[dict[str, Any]]) -> Guard:
    found: Guard = _defined(namespaces, GUARD)
    return found


def test_guard_is_in_the_decision_block(namespaces: list[dict[str, Any]]) -> None:
    owners = [ns for ns in namespaces if "EXPECTED_DEVIATIONS" in ns]
    assert owners
    assert GUARD in owners[0]
    assert owners[0]["EXPECTED_DEVIATIONS"] == frozenset()


@pytest.fixture
def tspecials_accepted(
    dkim_pass_domains: DkimPassDomains, monkeypatch: pytest.MonkeyPatch
) -> frozenset[Deviation]:
    """The decision block as a caller who accepts PVALUE_TSPECIALS runs it."""
    accepted = frozenset({Deviation.PVALUE_TSPECIALS})
    assert isinstance(dkim_pass_domains, FunctionType)
    block_globals = dkim_pass_domains.__globals__
    monkeypatch.setitem(block_globals, "EXPECTED_DEVIATIONS", accepted)
    return accepted


@pytest.mark.parametrize("value", INJECTED, ids=INJECTED_IDS)
def test_injected_values_carry_only_the_tspecials_deviation(value: str) -> None:
    assert parse(value).deviations == {Deviation.PVALUE_TSPECIALS}


def test_injection_passes_the_bare_deviation_comparison(
    tspecials_accepted: frozenset[Deviation],
) -> None:
    # Section 14.9: the repro is real at the parse level. With the deviation
    # accepted, a bare "deviations <= EXPECTED_DEVIATIONS" lets each injected
    # value through, carrying a pass for bank.example.
    dkim = parse(INJECTED_DKIM)
    assert dkim.deviations <= tspecials_accepted
    assert any(
        r.result == "pass"
        and (d := r.get_unique("header", "d")) is not None
        and d.value == "bank.example"
        for r in dkim.results_for("dkim")
    )
    dmarc = parse(INJECTED_DMARC)
    assert dmarc.deviations <= tspecials_accepted
    assert [r.result for r in dmarc.results_for("dmarc")] == ["pass"]
    header_from = dmarc.results_for("dmarc")[0].get_unique("header", "from")
    assert header_from is not None
    assert header_from.value == "bank.example"
    signature = parse(INJECTED_SIGNATURE)
    assert signature.deviations <= tspecials_accepted
    assert [r.result for r in signature.results_for("dkim")] == ["fail", "pass"]
    assert [r.result for r in signature.results_for("dmarc")] == ["pass"]


@pytest.mark.usefixtures("tspecials_accepted")
@pytest.mark.parametrize("value", INJECTED, ids=INJECTED_IDS)
def test_recipe_refuses_the_injection_with_the_deviation_accepted(
    guard: Guard,
    dkim_pass_domains: DkimPassDomains,
    dmarc_pass: DmarcPass,
    value: str,
) -> None:
    # Section 14.9: the guard is wired into the recipe's deviation check.
    results = parse(value)
    assert guard(results) is False
    assert "bank.example" not in dkim_pass_domains(results)
    assert dmarc_pass(results, "bank.example") is False


@pytest.mark.usefixtures("tspecials_accepted")
def test_guard_passes_an_unquoted_signature(
    guard: Guard, dkim_pass_domains: DkimPassDomains
) -> None:
    results = parse(LEGIT_SIGNATURE)
    assert Deviation.PVALUE_TSPECIALS in results.deviations
    assert guard(results) is True
    assert dkim_pass_domains(results) == {"example.com"}


@pytest.mark.parametrize(
    "value", [*INJECTED, LEGIT_SIGNATURE], ids=[*INJECTED_IDS, "legit"]
)
def test_no_pass_with_the_default_deviations(
    dkim_pass_domains: DkimPassDomains, dmarc_pass: DmarcPass, value: str
) -> None:
    results = parse(value)
    assert dkim_pass_domains(results) == frozenset()
    assert dmarc_pass(results, "bank.example") is False
    assert dmarc_pass(results, "example.com") is False


def _paragraph(lines: list[str], start: int, step: int) -> list[str]:
    """The paragraph next to index *start* in direction *step* (-1 or 1)."""
    i = start
    while 0 <= i < len(lines) and not lines[i].strip():
        i += step
    found: list[str] = []
    while 0 <= i < len(lines) and lines[i].strip():
        found.append(lines[i])
        i += step
    return found


def _around_block(readme: Readme, block: Block) -> str:
    """A block's body plus the prose paragraph just before and just after."""
    lines = readme.text.splitlines()
    first = block.line - 1  # index of the opening fence
    last = first + len(block.body.splitlines()) + 1  # index of the closing fence
    before = _paragraph(lines, first - 1, -1)[::-1]
    after = _paragraph(lines, last + 1, 1)
    return "\n".join([*before, block.body, *after])


def test_around_block() -> None:
    sample = _split("a\n\nb\nc\n\n```python\nx = 1\n```\n\nd\n\ne\n")
    assert _around_block(sample, sample.blocks[0]) == "b\nc\nx = 1\n\nd"


def _guard_context(readme: Readme) -> str:
    """The guard's block and adjacent prose, flattened, comment markers dropped
    (so a phrase may wrap across "#" lines)."""
    owners = [
        b
        for b in _blocks(readme, "python")
        if re.search(rf"^def {GUARD}\(", b.body, re.MULTILINE)
    ]
    assert owners, f"no python block defines {GUARD}"
    around = re.sub(r"(?m)^\s*#+\s?", "", _around_block(readme, owners[0]))
    return " ".join(around.split())


def test_guard_suggestion_names_the_bracket_splitting(readme: Readme) -> None:
    text = _guard_context(readme)
    assert "bracket" in text.lower()
    assert (
        TSPECIALS_HEADING.lower() in text.lower()
        or "#characters-in-unquoted-values" in text
    )


def test_guard_note_says_legitimate_values_are_refused(readme: Readme) -> None:
    # Section 14.10: the check also refuses legitimate bracketed values.
    assert "legitimate" in _guard_context(readme).lower()


# 7. parse_or_log.

ParseOrLog = Callable[[str], AuthenticationResults | None]


@pytest.fixture(scope="module")
def parse_or_log(namespaces: list[dict[str, Any]]) -> ParseOrLog:
    found: ParseOrLog = _defined(namespaces, "parse_or_log")
    return found


def _refusal(value: str) -> AuthResultsError:
    with pytest.raises(AuthResultsError) as caught:
        parse(value)
    return caught.value


def test_parse_or_log_tagged_refusal(
    parse_or_log: ParseOrLog, caplog: pytest.LogCaptureFixture
) -> None:
    value = "qxsecret.test/4ABCD; dkim=none"
    err = _refusal(value)
    caplog.set_level(logging.WARNING)
    assert parse_or_log(value) is None
    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.args == (err.reason, err.position, err.known_shape)
    assert err.known_shape is KnownShape.AUTHSERV_ID_JOB_ID
    assert record.exc_info is None
    assert "qxsecret" not in record.getMessage()
    assert "qxsecret" not in repr(record.args)


def test_parse_or_log_untagged_refusal(
    parse_or_log: ParseOrLog, caplog: pytest.LogCaptureFixture
) -> None:
    value = f"{OUR_ID}; dkim=pass (unterminated"
    err = _refusal(value)
    assert err.known_shape is None
    caplog.set_level(logging.WARNING)
    assert parse_or_log(value) is None
    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.args == (err.reason, err.position, None)
    assert "known_shape=None" in record.getMessage()


def test_parse_or_log_accepted(
    parse_or_log: ParseOrLog, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING)
    got = parse_or_log(f"{OUR_ID}; dkim=pass header.d=example.com")
    assert isinstance(got, AuthenticationResults)
    assert caplog.records == []


# 8. Closed sets covered (acceptance criterion 3).


@pytest.mark.parametrize(
    "member",
    [*ErrorReason, *Deviation, *KnownShape],
    ids=lambda m: f"{type(m).__name__}.{m.name}",
)
def test_closed_set_member_named(
    readme: Readme, member: ErrorReason | Deviation | KnownShape
) -> None:
    # Section 13.5: in backticks, as its lowercase value.
    assert f"`{member.value}`" in readme.text


# 9. Required strings (acceptance criterion 3).


@pytest.mark.parametrize(
    "needle",
    [
        _registry.LAST_UPDATED,
        "python -m authresults.redact",
        "--show-originals",
        "X-TM-Authentication-Results",
        "MemoryError",
        "RecursionError",
        "Experimental",
    ],
)
def test_names(readme: Readme, needle: str) -> None:
    assert needle in readme.text


@pytest.mark.parametrize("char", list("/=?:[]<>"))
def test_pvalue_tspecials_characters(readme: Readme, char: str) -> None:
    section = _section(readme, 3, TSPECIALS_HEADING)
    assert "PVALUE_TSPECIALS" in section
    assert char in section


# Section 14.4 (red-team L3, verifier V1): most ARC values are refused by
# parse(); only one without an authserv-id reads as a missing-id field.

_MISSING_ID = "reads as a field with a missing id"


def _arc_claim_problems(text: str) -> list[str]:
    flat = " ".join(text.split())
    problems = []
    if "passed to `parse()` reads as" in flat:
        problems.append("unqualified ARC claim")
    for match in re.finditer(re.escape(_MISSING_ID), flat):
        sentence = re.split(r"[.:]\s", flat[: match.start()])[-1]
        if "without an authserv-id" not in sentence:
            problems.append("missing-id claim without its condition")
    return problems


def test_arc_claim_rule() -> None:
    good = (
        "Refuse it: an ARC value passed to `parse()` is usually refused, and one\n"
        "without an authserv-id reads as a field with a missing id and an"
        " unregistered `i=1` result."
    )
    assert _arc_claim_problems(good) == []
    bad = (
        "Refuse it: an ARC value passed to `parse()` reads as a field with a\n"
        "missing id."
    )
    assert _arc_claim_problems(bad) == [
        "unqualified ARC claim",
        "missing-id claim without its condition",
    ]


def test_arc_claim_is_qualified(readme: Readme) -> None:
    assert _arc_claim_problems(readme.text) == []


# 10. Links (acceptance criterion 3).

_INLINE_LINK = re.compile(r"\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
_AUTOLINK = re.compile(r"<([A-Za-z][A-Za-z0-9+.-]*:[^>\s]*)>")
_REF_DEF = re.compile(r"\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s.*)?")


def _links(readme: Readme) -> list[str]:
    found: list[str] = []
    for _, line in readme.prose:
        found += _INLINE_LINK.findall(line)
        found += _AUTOLINK.findall(line)
        ref = _REF_DEF.fullmatch(line)
        if ref:
            found.append(ref.group(1))
    return found


def test_link_extraction() -> None:
    sample = _split(
        "[a](https://x.example/a) <https://x.example/b> [c](docs/c.md)\n"
        '[d](#d "t")\n[e]: SECURITY.md\n```sh\n[f](g.md)\n```\n'
    )
    assert _links(sample) == [
        "https://x.example/a",
        "docs/c.md",
        "https://x.example/b",
        "#d",
        "SECURITY.md",
    ]


def test_links_are_absolute(readme: Readme) -> None:
    links = _links(readme)
    assert links, "no links"
    relative = [u for u in links if not u.startswith(("https://", "#"))]
    assert relative == []


def _tracked() -> set[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        check=True,
    ).stdout.decode("utf-8")
    return set(filter(None, out.split("\0")))


_NO_GIT = pytest.mark.skipif(
    not (ROOT / ".git").exists(),
    reason="needs a git checkout (not available from an unpacked sdist)",
)
_NO_GITHUB = pytest.mark.skipif(
    not (ROOT / ".github").is_dir(),
    reason="needs .github/ (not shipped in the sdist)",
)


@_NO_GIT
def test_blob_links_name_tracked_files(readme: Readme) -> None:
    tracked = _tracked()
    paths = [
        re.split(r"[#?]", u.removeprefix(BLOB))[0]
        for u in _links(readme)
        if u.startswith(BLOB)
    ]
    missing = [p for p in paths if p not in tracked or not (ROOT / p).is_file()]
    assert missing == []


@pytest.mark.parametrize(
    "path",
    [
        "docs/refused-shapes.md",
        "docs/plan.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "LICENSE",
        "NOTICE",
    ],
)
def test_required_blob_link(readme: Readme, path: str) -> None:
    targets = {re.split(r"[#?]", u)[0] for u in _links(readme)}
    assert BLOB + path in targets


def test_issue_form_link(readme: Readme) -> None:
    assert ISSUE_FORM_URL in readme.text


@_NO_GITHUB
def test_issue_form_file_exists() -> None:
    assert (ROOT / ".github" / "ISSUE_TEMPLATE" / "header-shape.yml").is_file()


# 11. No real names or addresses in examples.

_ALLOWED_SUFFIXES = (".example", ".test", ".invalid")
_ALLOWED_NAMES = ("example.com", "example.net", "example.org")
_DOMAIN = re.compile(r"(?<![\w.@-])((?:[\w-]+\.)+[^\W\d_][\w-]*)(?![\w.-]*=)")
_QUAD = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_DOC_NETS = [
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
]
_QUOTED = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"")


def _string_constants(source: str) -> list[str]:
    return [
        node.value
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]


def _example_strings(block: Block) -> list[str]:
    """The string literals in a block, and the quoted text in doctest output."""
    if block.lang == "python":
        return _string_constants(block.body)
    found: list[str] = []
    for example in doctest.DocTestParser().get_examples(block.body):
        found += _string_constants(example.source)
        found += [q[1:-1] for q in _QUOTED.findall(example.want)]
    return found


def _bad_domains(strings: list[str]) -> list[str]:
    bad = []
    for text in strings:
        for token in _DOMAIN.findall(text):
            name = token.lower()
            ok = name.endswith(_ALLOWED_SUFFIXES) or any(
                name == n or name.endswith("." + n) for n in _ALLOWED_NAMES
            )
            if not ok:
                bad.append(token)
    return bad


def _bad_quads(text: str) -> list[str]:
    bad = []
    for quad in _QUAD.findall(text):
        try:
            addr = ipaddress.ip_address(quad)
        except ValueError:
            bad.append(quad)
            continue
        if not any(addr in net for net in _DOC_NETS):
            bad.append(quad)
    return bad


def test_example_scan_flags() -> None:
    assert (
        _bad_domains(["mx.example.net; header.d=bank.example x=sub.example.com"]) == []
    )
    assert _bad_domains(["smtp.mailfrom=example.com header.i=@a.test"]) == []
    assert _bad_domains(["mail.realbank.com", "badexample.com"]) == [
        "mail.realbank.com",
        "badexample.com",
    ]
    assert _bad_quads("192.0.2.1 203.0.113.9 0.1.0") == []
    assert _bad_quads("10.0.0.1 192.0.3.1") == ["10.0.0.1", "192.0.3.1"]


def test_examples_use_reserved_names(readme: Readme) -> None:
    blocks = _blocks(readme, "pycon") + _blocks(readme, "python")
    bad = {b.line: _bad_domains(_example_strings(b)) for b in blocks}
    assert {line: names for line, names in bad.items() if names} == {}


def test_examples_use_documentation_addresses(readme: Readme) -> None:
    blocks = _blocks(readme, "pycon") + _blocks(readme, "python")
    bad = {b.line: _bad_quads(b.body) for b in blocks}
    assert {line: quads for line, quads in bad.items() if quads} == {}
