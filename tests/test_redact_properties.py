# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Hypothesis properties P1 to P5 of the redaction helper, and the
``--show-originals`` property (``docs/plans/al3d.md`` sections 8 and 13).

- P1 never raises; ASCII output; exact character counts.
- P2 no leak: planted ``qx`` secrets never reach stdout or stderr, and the
  output passes the text-only oracle.
- P3 same structure for every accepted value.
- P4 refusals kept, unless the fault lies in replaced text (AU-Q68).
- P5 idempotent on its own output (R13).
- With ``--show-originals``, stdout is the same and stderr differs only on
  the replacement lines, apart from the first line and the ``replaced (...)``
  header line, which change by design (section 14 item 16).

The profile (``ci`` or ``nightly``) comes from ``HYPOTHESIS_PROFILE``
(``tests/_hypothesis_profiles.py``).
"""

from typing import Final

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from authresults import ErrorReason, _redact
from authresults._tokenizer import control

from . import cases_vendor
from ._hypothesis_profiles import TIMEOUT
from ._redact_strategies import (
    Call,
    Source,
    case_sources,
    check_spans,
    doc_ipv6_runs,
    edited,
    header_text,
    inside,
    ipv6_value,
    model_values,
    oracle_problems,
    outcome,
    refusal,
    run_cli,
    secret_values,
)

pytestmark = pytest.mark.timeout(TIMEOUT)

HEAD: Final = "authresults.redact: best effort; read the output before posting it"
HEAD_SHOWN: Final = (
    "authresults.redact: best effort; ORIGINALS SHOWN BELOW: do not post this report"
)
HEADER: Final = "replaced (originals not shown):"
HEADER_SHOWN: Final = "replaced (originals shown):"


def _call(value: str) -> Call:
    return "parse_arc" if value.startswith("i=1;") else "parse"


# --- P1 -----------------------------------------------------------------------


def _check_any(value: str) -> _redact.Redaction:
    result = _redact.redact(value)
    assert result.complete
    assert result.text.isascii()
    assert all(c.isprintable() or c in "\t\r\n" for c in result.text)
    controls = sum(1 for c in value if control(c) and c not in "\t\r\n")
    non_ascii = sum(1 for c in value if c >= "\x80" and not control(c))
    assert (result.controls, result.non_ascii) == (controls, non_ascii)
    check_spans(value, result)
    return result


@given(header_text())
def test_p1_never_raises(value: str) -> None:
    _check_any(value)


# --- P2 -----------------------------------------------------------------------


@given(secret_values())
def test_p2_no_leak(value: str) -> None:
    result = _redact.redact(value)
    assert result.complete
    assert "qx" not in result.text.lower()
    assert oracle_problems(result.text, cases_vendor.VENDOR_HOSTNAMES) == []
    code, out, err = run_cli(value.encode())
    assert code == 0
    assert out == result.text.encode("ascii") + b"\n"
    assert b"qx" not in err.lower()
    # Section 19: no IPv6 placeholder equals a kept doc IPv6 by value.
    placeholders = {
        r.placeholder for r in result.replacements if r.kind is _redact.Kind.IPV6
    }
    kept = {
        ipv6_value(run) for run in doc_ipv6_runs(result.text) if run not in placeholders
    }
    assert not kept & {ipv6_value(p) for p in placeholders}
    # P5 on the same values (section 17 item 8).
    second = _redact.redact(result.text)
    assert second.complete
    assert second.text == result.text
    assert second.replacements == ()
    assert (second.free_text, second.non_ascii, second.controls) == (0, 0, 0)
    assert second.spans == ()


def test_p2_values_mostly_parse() -> None:
    # Section 16 item 2: P3 and P4 over P2 values must mostly see accepted
    # values, and still some refusals.
    accepted: list[bool] = []

    @settings(
        max_examples=200,
        derandomize=True,
        database=None,
        suppress_health_check=list(HealthCheck),
    )
    @given(secret_values())
    def collect(value: str) -> None:
        accepted.append(outcome(value, _call(value), {})[0] == "accepted")

    collect()
    assert len(accepted) >= 100  # noqa: PLR2004
    assert sum(accepted) * 2 >= len(accepted)
    assert sum(accepted) < len(accepted)


# --- P3 -----------------------------------------------------------------------


def _same_structure(source: Source) -> None:
    value, call, kwargs = source
    before = outcome(value, call, kwargs)
    if before[0] != "accepted":
        return
    result = _redact.redact(value)
    assert result.complete
    assert outcome(result.text, call, kwargs) == before


def test_p3_case_table() -> None:
    sources = case_sources()
    assert len(sources) >= 700  # noqa: PLR2004 - the whole table (section 15)
    failures = []
    for index, source in enumerate(sources):
        try:
            _same_structure(source)
        except AssertionError:
            failures.append(index)
    assert failures == []


@given(model_values())
def test_p3_models(source: Source) -> None:
    _same_structure(source)


@given(secret_values())
def test_p3_secret_values(value: str) -> None:
    _same_structure((value, _call(value), {}))


# --- P4 -----------------------------------------------------------------------


def _refusal_kept(source: Source) -> None:
    value, call, kwargs = source
    err = refusal(value, call, kwargs)
    if err is None or err.reason is ErrorReason.TOO_LONG:
        return
    result = _redact.redact(value)
    if not result.complete:
        return
    if err.position is not None and inside(err.position, result.spans):
        return
    after = refusal(result.text, call, kwargs)
    assert after is not None
    assert (after.reason, after.known_shape) == (err.reason, err.known_shape)


def test_p4_case_table() -> None:
    failures = []
    for index, source in enumerate(case_sources()):
        try:
            _refusal_kept(source)
        except AssertionError:
            failures.append(index)
    assert failures == []


@st.composite
def _edited_sources(draw: st.DrawFn) -> Source:
    value, call, kwargs = draw(st.sampled_from(case_sources()))
    return draw(edited(value)), call, kwargs


@given(_edited_sources())
def test_p4_edits(source: Source) -> None:
    _refusal_kept(source)


@given(secret_values().flatmap(edited))
def test_p4_edited_secret_values(value: str) -> None:
    _refusal_kept((value, _call(value), {}))


# --- P5 -----------------------------------------------------------------------


def _idempotent(value: str) -> None:
    first = _redact.redact(value)
    if not first.complete:
        return
    second = _redact.redact(first.text)
    assert second.complete
    assert second.text == first.text
    assert second.replacements == ()
    assert (second.free_text, second.non_ascii, second.controls) == (0, 0, 0)
    assert second.spans == ()


@given(header_text())
def test_p5_idempotent_any_text(value: str) -> None:
    _idempotent(value)


# --- section 13: --show-originals ----------------------------------------------


@given(st.one_of(secret_values(), header_text()))
def test_show_originals_changes_only_the_report(value: str) -> None:
    data = value.encode("utf-8", "surrogatepass")
    code, out, err = run_cli(data)
    shown_code, shown_out, shown_err = run_cli(data, "--show-originals")
    assert (shown_code, shown_out) == (code, out)
    if code != 0:
        assert shown_err == err
        return
    plain = err.decode("ascii").splitlines()
    shown = shown_err.decode("ascii").splitlines()
    assert len(shown) == len(plain)
    assert (plain[0], shown[0]) == (HEAD, HEAD_SHOWN)
    assert plain[1].startswith(HEADER)
    assert shown[1] == HEADER_SHOWN + plain[1].removeprefix(HEADER)
    replaced = sum(1 for line in plain if line.startswith("  "))
    for i in range(2, 2 + replaced):
        assert shown[i].startswith(plain[i] + " <- ")
        assert shown[i].isascii()
        assert shown[i].isprintable()
    assert shown[2 + replaced :] == plain[2 + replaced :]
    assert b"qx" not in err.lower()
