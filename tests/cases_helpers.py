# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""``domain_of`` and ``ascii_domain`` (PLAN.md 2.5, AU-Q15b, AU-Q33a)."""

from authresults import ErrorReason

from ._case import Case
from .cases_grammar import LyingStr, StrSubclass

_DOMAIN_OF = "PLAN.md 2.5 domain_of; AU-Q33a"
_ASCII_DOMAIN = "PLAN.md 2.5 ascii_domain; AU-Q33a"
_Q58_CLARIFIED = (
    "; AU-Q58 clarification (round 2 M1: the bracketed text must pass the "
    "unbracketed address check, AU-Q24 and G10"
)


def _d(case_id: str, value: str, expected: str | None, note: str = "") -> Case:
    return Case(
        id=f"domain_of {case_id}",
        call="domain_of",
        value=value,
        expected=expected,
        cite=_DOMAIN_OF + note,
    )


def _a(case_id: str, value: str, expected: str | None, note: str = "") -> Case:
    return Case(
        id=f"ascii_domain {case_id}",
        call="ascii_domain",
        value=value,
        expected=expected,
        cite=_ASCII_DOMAIN + note,
    )


CASES: tuple[Case, ...] = (
    _d("address", "a@example.com", "example.com"),
    _d("empty local-part", "@example.com", "example.com"),
    _d("no @", "example.com", "example.com", " (the whole value if no @)"),
    _d("last @ wins", "a@b@example.com", "example.com", " (after the last @)"),
    _d("quoted local-part", '"a@b"@example.com', "example.com"),
    _d("case kept", "a@Example.COM", "Example.COM", " (no lowercasing)"),
    _d("no stripping", " a@example.com ", "example.com ", " (no CFWS stripping)"),
    _d("u-label", "a@b\u00fccher.example", "b\u00fccher.example"),
    _d("nothing after @", "a@", None, " (None only when empty)"),
    _d("lone @", "@", None),
    _d("empty", "", None),
    # AU-Q58: one enclosing <local@domain> is stripped; any other value with
    # : [ ] < or > gives None.
    _d(
        "au-q58 angle address",
        "<noreply@mail.example.com>",
        "mail.example.com",
        "; AU-Q58 (exactly < local-part @ domain >: the domain)",
    ),
    _d(
        "au-q58 angle address then @",
        "<evil@evil.example>@good.example",
        None,
        "; AU-Q58 (not exactly one enclosing <...>: None)",
    ),
    _d(
        "au-q58 unclosed <",
        "<user@example.com",
        None,
        "; AU-Q58 (a < with no closing >: None)",
    ),
    _d(
        "au-q58 ip literal",
        "a@[192.0.2.1]",
        None,
        "; AU-Q58 (a domain with [ ]: None)",
    ),
    _d(
        "au-q58 angle ip literal",
        "<a@[192.0.2.1]>",
        None,
        "; AU-Q58 (stripped, the domain still holds [ ]: None)",
    ),
    _d("au-q58 null path", "<>", None, "; AU-Q58 (no local-part @ domain: None)"),
    # AU-Q58 clarification (AL3c red-team round 2 M1): the text inside the
    # brackets must be exactly what the parser's unbracketed address check
    # accepts (AU-Q24, G10).
    _d(
        "au-q58 bracketed two @",
        "<evil@evil.example@good.example>",
        None,
        _Q58_CLARIFIED + "; two @: None)",
    ),
    _d(
        "au-q58 bracketed empty local-part before @@",
        "<a@@good.example>",
        None,
        _Q58_CLARIFIED + "; a@@: None)",
    ),
    _d(
        "au-q58 bracketed double dot",
        "<a..b@good.example>",
        None,
        _Q58_CLARIFIED + "; a..b is not a dot-atom: None)",
    ),
    _d(
        "au-q58 bracketed lone dot local-part",
        "<.@good.example>",
        None,
        _Q58_CLARIFIED + "; . is not a dot-atom: None)",
    ),
    _d(
        "au-q58 bracketed single-label domain",
        "<a@b>",
        None,
        _Q58_CLARIFIED + "; one label: None)",
    ),
    _d(
        "au-q58 bracketed address control",
        "<user@mail.example.com>",
        "mail.example.com",
        _Q58_CLARIFIED + "; a valid address: its domain)",
    ),
    _d(
        "au-q58 bracketed empty local-part",
        "<@x.example>",
        "x.example",
        _Q58_CLARIFIED + "; the unbracketed path accepts @x.example, an "
        "empty local-part, G10: its domain)",
    ),
    # AU-Q58 clarification: a quoted local-part is one the unbracketed path
    # accepts (G10), so the bracketed address gives its domain.
    _d(
        "au-q58 bracketed quoted local-part",
        '<"a"@example.com>',
        "example.com",
        _Q58_CLARIFIED + "; a quoted local-part, G10: its domain)",
    ),
    _d(
        "au-q58 bracketed quoted local-part with space",
        '<"a b"@example.com>',
        "example.com",
        _Q58_CLARIFIED + "; a quoted local-part with a space, G10: its domain)",
    ),
    _d(
        "au-q58 bracketed quoted local-part with @",
        '<"a@evil"@good.example>',
        "good.example",
        _Q58_CLARIFIED + "; the @ inside the quoted local-part is not the "
        "address @: the domain after the closing quote)",
    ),
    _d(
        "au-q58 bracketed quoted local-part single-label domain",
        '<"a"@b>',
        None,
        _Q58_CLARIFIED + "; one label, refused unbracketed: None)",
    ),
    Case(
        id="domain_of str subclass",
        call="domain_of",
        value=StrSubclass("a@example.com"),
        expected="example.com",
        cite=_DOMAIN_OF + "; AU-Q38 rule 3 (a str subclass is normalised to an "
        "exact str)",
    ),
    Case(
        id="domain_of str subclass lying accessors",
        call="domain_of",
        value=LyingStr("a@example.com"),
        expected="example.com",
        cite=_DOMAIN_OF + "; AU-Q38 rule 3 (the underlying text, not __str__)",
    ),
    Case(
        id="domain_of bytes",
        call="domain_of",
        value=b"a@example.com",
        expected=ErrorReason.INVALID_TYPE,
        position=None,
        cite=_DOMAIN_OF + "; AU-Q15b (INVALID_TYPE for a non-str)",
    ),
    Case(
        id="domain_of none",
        call="domain_of",
        value=None,
        expected=ErrorReason.INVALID_TYPE,
        position=None,
        cite=_DOMAIN_OF + "; AU-Q15b",
    ),
    _a("lowercased", "Example.COM", "example.com"),
    _a("already lower", "example.com", "example.com"),
    _a("single label", "localhost", "localhost", " (single labels accepted)"),
    _a("a-label", "xn--bcher-kva.example", "xn--bcher-kva.example"),
    _a("a-label upper", "XN--BCHER-KVA.example", "xn--bcher-kva.example"),
    _a("hyphen inside", "a-b.example", "a-b.example"),
    _a("digits", "1.2", "1.2", " (Let-dig includes DIGIT)"),
    _a("leading zero label", "0123", "0123"),
    _a(
        "long label",
        "a" * 300 + ".example",
        "a" * 300 + ".example",
        " (no length limits)",
    ),
    _a("trailing dot", "example.com.", None),
    _a("leading dot", ".example", None),
    _a("empty label", "a..b", None),
    _a("empty", "", None),
    _a("underscore", "a_b.example", None),
    _a("at sign", "a@example.com", None),
    _a("u-label", "b\u00fccher.example", None, " (any non-ASCII character)"),
    _a("kelvin sign", "\u212aexample.com", None, " (ascii_lower only; no K)"),
    _a("label starts with -", "-a.example", None, " (sub-domain = Let-dig [Ldh-str])"),
    _a("label ends with -", "a-.example", None, " (Ldh-str ends in Let-dig)"),
    _a("space", " example.com", None, " (no stripping)"),
    Case(
        id="ascii_domain str subclass",
        call="ascii_domain",
        value=StrSubclass("Example.COM"),
        expected="example.com",
        cite=_ASCII_DOMAIN + "; AU-Q38 rule 3 (a str subclass is normalised to "
        "an exact str)",
    ),
    Case(
        id="ascii_domain str subclass lying accessors",
        call="ascii_domain",
        value=LyingStr("Example.COM"),
        expected="example.com",
        cite=_ASCII_DOMAIN + "; AU-Q38 rule 3 (the underlying text, not __str__)",
    ),
    Case(
        id="ascii_domain bytes",
        call="ascii_domain",
        value=b"example.com",
        expected=ErrorReason.INVALID_TYPE,
        position=None,
        cite=_ASCII_DOMAIN + "; AU-Q15b",
    ),
)
