# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Implementer's unit tests of the redaction helper (AL3d).

They pin choices the plan (``docs/plans/al3d.md``) leaves open, each found by
the P3 to P5 properties; the rule each one refines is named in its case.
Secrets are synthetic ``qx`` names.
"""

import io
import runpy
import sys
from typing import Final

import pytest

from authresults import _redact

from ._redact_strategies import check_spans, outcome, run_cli

Case = tuple[str, str]

CASES: Final[dict[str, Case]] = {
    # R9: a trailing dot is copied, so "ptype.=" does not become a domain
    # placeholder that reads as a propspec (P4).
    "trailing dot after a ptype": (
        "qx.test; dkim=pass header.=qxv",
        "a.example; dkim=pass header.=tok1",
    ),
    "trailing dot after a domain": (
        "qx.test; spf=pass smtp.mailfrom=bob@qx.test.",
        "a.example; spf=pass smtp.mailfrom=user1@a.example.",
    ),
    # 17.1: digits after "/" that are not a method version.
    "job digits after a keyword id": ("qxhost/5551234567; none", "tok1/job1; none"),
    "short digits after a method": ("qx.test; dkim/12 x", "a.example; dkim/12 tok1"),
    # 17.4: a dotted doc IPv6 is replaced.
    "dotted doc ipv6": (
        "qx.test; iprev=pass policy.ip=2001:db8::1.2.3.4",
        "a.example; iprev=pass policy.ip=2001:db8::1",
    ),
    "trailing dot in a local-part": (
        "qx.test; spf=pass smtp.mailfrom=bob.@qx.test",
        "a.example; spf=pass smtp.mailfrom=user1.@a.example",
    ),
    "only dots before @": (
        "qx.test; spf=pass smtp.mailfrom=..@qx.test",
        "a.example; spf=pass smtp.mailfrom=user1..@a.example",
    ),
    # 18.2: a doc-prefixed run is kept only when well formed.
    "doc ipv6 with two ::": (
        "qx.test; iprev=pass policy.ip=2001:db8::1::2",
        "a.example; iprev=pass policy.ip=2001:db8::1",
    ),
    "doc ipv6 with a five-digit group": (
        "qx.test; iprev=pass policy.ip=2001:db8::12345",
        "a.example; iprev=pass policy.ip=2001:db8::1",
    ),
    "doc ipv6 short without ::": (
        "qx.test; iprev=pass policy.ip=2001:db8:1:2",
        "a.example; iprev=pass policy.ip=2001:db8::1",
    ),
    "doc ipv6 with nine groups": (
        "qx.test; iprev=pass policy.ip=2001:db8:1:2:3:4:5:6:7",
        "a.example; iprev=pass policy.ip=2001:db8::1",
    ),
    "doc ipv6 with seven groups and ::": (
        "qx.test; iprev=pass policy.ip=2001:db8:1:2:3:4::5",
        "a.example; iprev=pass policy.ip=2001:db8:1:2:3:4::5",
    ),
    "doc ipv6 ending in ::": (
        "qx.test; iprev=pass policy.ip=2001:db8::",
        "a.example; iprev=pass policy.ip=2001:db8::",
    ),
    "failed hex run seen again": (
        "qx.test; dkim=pass policy.d=ab:cd",
        "a.example; dkim=pass policy.d=tok1:tok2",
    ),
    "ipv6 after a split character": (
        "qx.test; dkim=pass policy.d=qx/fd00::1",
        "a.example; dkim=pass policy.d=tok1/2001:db8::1",
    ),
    "kept domain as a propspec": (
        "qx.test; dkim=pass a.example=1",
        "b.example; dkim=pass a.example=1",
    ),
    "only dots": ("qx.test; dkim=pass policy.d=..", "a.example; dkim=pass policy.d=.."),
    # R8: a quoted local-part with a fold stays free text, so the fold and
    # LF_FOLDING are kept (P3).
    "folded quoted local-part": (
        'qx.test; spf=pass smtp.mailfrom="qx\n bob"@qx.test',
        'a.example; spf=pass smtp.mailfrom="...\n ..."@a.example',
    ),
    # R9 step 1: "::" starts a piece only where a piece may start (P5).
    "colons inside a word": ("qxfd00::1; none", "tok1::1; none"),
    "colons after a separator": (
        "qx.test; iprev=pass policy.ip=[::1]",
        "a.example; iprev=pass policy.ip=[2001:db8::1]",
    ),
    # R9 step 1 (section 16 item 1): the tail glued to an IPv6 piece is its
    # own piece; a domain there is tok_N, so the next pass reads the same.
    "hex run into a word": (
        "qx.test; iprev=pass policy.ip=fd00::1g",
        "a.example; iprev=pass policy.ip=2001:db8::1tok1",
    ),
    "domain glued to ipv6": (
        "qx.test; iprev=pass policy.ip=fd00::1z.qx.test",
        "a.example; iprev=pass policy.ip=2001:db8::1tok_1",
    ),
    "glued tail before a split character": (
        "qx.test; iprev=pass policy.ip=fd00::1%x/qx",
        "a.example; iprev=pass policy.ip=2001:db8::1tok_1/tok1",
    ),
    # R9 step 0: a base64-shaped run of kept pieces is not a signature (P5).
    "kept pieces in base64 context": (
        "qx.test; dkim=pass header.b=tok_1=tok1=tok2=1",
        "a.example; dkim=pass header.b=tok_1=tok1=tok2=1",
    ),
    # R5: a quoted value at the start never reaches the ARC prefix lookahead.
    "quote at the start": ('"x( 1; none', '"...'),
    # R5, AU-Q35: before "/" and no method-version, the word is rewritten.
    "keyword id with a job id": ("qxhost/QX1A; none", "tok1/tok2; none"),
    "method with a version": ("dkim/1 = pass", "dkim/1 = pass"),
    "quoted method version": (
        'qx.test; dkim/"qx 1"=pass',
        'a.example; dkim/"..."=pass',
    ),
    # Paths the hand-written cases above do not reach.
    "kept base64 placeholder": (
        "qx.test; dkim=pass header.b=b64-7/=",
        "a.example; dkim=pass header.b=b64-7/=",
    ),
    "dotted quad over 255": (
        "qx.test; iprev=pass policy.ip=10.0.0.256",
        "a.example; iprev=pass policy.ip=b.example",
    ),
    "escaped quote, unterminated": (
        'qx.test; dkim=pass reason="qx\\"',
        'a.example; dkim=pass reason="...',
    ),
    "kept quoted local-part": (
        'qx.test; spf=pass smtp.mailfrom="user5"@qx.test',
        'a.example; spf=pass smtp.mailfrom="user5"@a.example',
    ),
    "empty quoted local-part": (
        'qx.test; spf=pass smtp.mailfrom=""@qx.test',
        'a.example; spf=pass smtp.mailfrom=""@a.example',
    ),
    "i without =": ("i qx; none", "i tok1; none"),
    "placeholder ptype": (
        "qx.test; dkim=pass tok3.qxq=1",
        "a.example; dkim=pass tok3.prop1=1",
    ),
    "empty job id": ("qx.test/; none", "a.example/; none"),
    "kept job id": ("qx.test/job4; none", "a.example/job4; none"),
    "quoted method": ('qx.test; "qx y"', 'a.example; "..."'),
    "quoted result": ('qx.test; dkim="qx y"', 'a.example; dkim="..."'),
    # AU-Q69: a renamed property keeps its own name as the pvalue context.
    "renamed property keeps its context": (
        "qx.test; dkim=pass header.bh=Ef+gh",
        "a.example; dkim=pass header.tok1=b64-1",
    ),
}


@pytest.mark.parametrize(("value", "text"), CASES.values(), ids=CASES.keys())
def test_choice(value: str, text: str) -> None:
    first = _redact.redact(value)
    assert first.text == text
    check_spans(value, first)
    second = _redact.redact(first.text)
    assert (second.text, second.replacements, second.free_text) == (text, (), 0)


@pytest.mark.parametrize(
    "value",
    [
        "qx.test; dkim=pass header.=qxv",
        'qx.test; spf=pass smtp.mailfrom="qx\n bob"@qx.test',
        "qxhost/QX1A; none",
        "qx.test; spf=pass smtp.mailfrom=bob.@qx.test",
    ],
)
def test_choice_keeps_the_parse(value: str) -> None:
    redacted = _redact.redact(value).text
    assert outcome(redacted, "parse", {}) == outcome(value, "parse", {})


@pytest.mark.parametrize(
    "helper",
    [_redact.domain_label, _redact.ipv4_placeholder, _redact.ipv6_placeholder],
)
def test_placeholder_helpers_start_at_one(helper: object) -> None:
    assert callable(helper)
    with pytest.raises(ValueError, match="out of range"):
        helper(0)


def test_cli_field_name_needs_a_colon() -> None:
    code, out, err = run_cli(b"Authentication-Results qx.test; none")
    assert code == 0
    assert out == b"tok1 a.example; none\n"
    assert b"input:" not in err


def test_cli_show_originals_escapes_backslash() -> None:
    data = b'qx.test; spf=pass smtp.mailfrom="q\\x"@qx.test'
    code, _, err = run_cli(data, "--show-originals")
    assert code == 0
    assert b"  user1 local-part x1 <- q\\\\x\n" in err


def test_cli_main_guard_without_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    # Section 17 item 7: with no stderr there is nothing to write; exit 3.
    stdout = io.BytesIO()
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"qx.test; none")))
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(stdout))
    monkeypatch.setattr(sys, "stderr", None)
    monkeypatch.setattr(sys, "argv", ["redact"])
    monkeypatch.delitem(sys.modules, "authresults.redact", raising=False)
    with pytest.raises(SystemExit) as info:
        runpy.run_module("authresults.redact", run_name="__main__")
    assert info.value.code == 3  # noqa: PLR2004
    assert stdout.getvalue() == b""
