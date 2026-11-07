# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""``domain_of`` and ``ascii_domain`` (PLAN.md 2.5, AU-Q15b, AU-Q33a)."""

from authresults import ErrorReason

from ._case import Case
from .cases_grammar import LyingStr, StrSubclass

_DOMAIN_OF = "PLAN.md 2.5 domain_of; AU-Q33a"
_ASCII_DOMAIN = "PLAN.md 2.5 ascii_domain; AU-Q33a"


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
