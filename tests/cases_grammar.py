# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Grammar cases from PLAN.md section 3 and 3.1 (G1 to G16, AU-Q16 to AU-Q34).

Positions are 0-based character offsets. Cases with several defects exist
only to test the order of checks (AU-Q16).
"""

from collections.abc import Iterator

from authresults import (
    ArcAuthenticationResults,
    AuthenticationResults,
    Deviation,
    ErrorReason,
    Property,
)

from ._case import Case, Options, ar, bare, prop, res

_E = ErrorReason
_STRICT = "PLAN.md 2.4 (strict_syntax: the first deviation raises DEVIATION)"
_REG = "PLAN.md 2.4 and 3.1 G16 (require_registered); AU-Q31"
_ASCII = "G14, AU-Q18a (ascii_only=False)"


class StrSubclass(str):
    """A ``str`` subclass (AL2b: normalised to an exact ``str`` first)."""

    __slots__ = ()


class LyingLength(str):
    """A ``str`` subclass whose ``__len__`` lies (AL2b: must not skip TOO_LONG)."""

    __slots__ = ()

    def __len__(self) -> int:
        return 0


class LyingStr(str):
    """A ``str`` subclass whose text accessors lie (AL3a red-team F10).

    Normalising with ``str(value)``, indexing or iterating would read the lie;
    the underlying text must be what is parsed.
    """

    __slots__ = ()

    def __str__(self) -> str:
        return "evil.example; dmarc=pass header.from=bank.example"

    def __getitem__(self, key: object) -> str:
        return "x"

    def __iter__(self) -> Iterator[str]:
        return iter("evil.example; dmarc=pass")

    def __contains__(self, key: object) -> bool:
        return False


_D_PASS = res("dkim", "pass", registered=True)
_D_FAIL = res("dkim", "fail", registered=True)
_HD = prop("header", "d", "example.com", registered=True)
_D_PASS_HD = res("dkim", "pass", _HD, registered=True)


def _dkim_s(value: str, raw: str) -> Property:
    return prop("header", "s", value, raw=raw, quoted=True, registered=True)


def _spf_mailfrom(value: str) -> AuthenticationResults:
    return ar(
        "example.com",
        res(
            "spf",
            "pass",
            prop("smtp", "mailfrom", value, registered=True),
            registered=True,
        ),
    )


_REJECT: tuple[Case, ...] = (
    Case(
        id="empty spaces",
        value="   ",
        expected=_E.EMPTY,
        position=None,
        cite="PLAN.md 3 reject list (only WSP or FWS is EMPTY); AU-Q16",
    ),
    Case(
        id="empty tab",
        value=" \t",
        expected=_E.EMPTY,
        position=None,
        cite="PLAN.md 3 reject list; AU-Q16",
    ),
    Case(
        id="empty fws",
        value="\r\n ",
        expected=_E.EMPTY,
        position=None,
        cite="PLAN.md 3 reject list; G5 (CRLF WSP is FWS); AU-Q16",
    ),
    Case(
        id="empty obs-fws",
        value=" \r\n \r\n\t",
        expected=_E.EMPTY,
        position=None,
        cite="PLAN.md 3 reject list; G5 (obs-FWS accepted); AU-Q16",
    ),
    Case(
        id="comment only",
        value="(c)",
        expected=_E.SYNTAX,
        position=3,
        cite="PLAN.md 3 reject list (only comments is SYNTAX); AU-Q16 "
        "(SYNTAX at len(value) at end of input)",
    ),
    Case(
        id="comment only with spaces",
        value=" (c) ",
        expected=_E.SYNTAX,
        position=5,
        cite="PLAN.md 3 reject list; AU-Q16",
    ),
    Case(
        id="only id short",
        value="example.com",
        expected=_E.SYNTAX,
        position=11,
        cite="G1 (1*resinfo: the authserv-id alone is SYNTAX at len(value))",
    ),
    Case(
        id="id then ;",
        value="example.com;",
        expected=_E.SYNTAX,
        position=12,
        cite="G8, AU-Q28 (example.com; is SYNTAX); AU-Q16 (end of input)",
    ),
    Case(
        id="id version then ;",
        value="example.com 1;",
        expected=_E.SYNTAX,
        position=14,
        cite="PLAN.md 3 Separators (; after the version with nothing after it)",
    ),
    Case(
        id="double ;",
        value="example.com;; dkim=pass",
        expected=_E.SYNTAX,
        position=12,
        cite="G8, AU-Q28 (;; is SYNTAX)",
    ),
    Case(
        id="double ; after result",
        value="example.com; dkim=pass;; spf=pass",
        expected=_E.SYNTAX,
        position=23,
        cite="G8, AU-Q28",
    ),
    Case(
        id="double ; at end",
        value="example.com; dkim=pass;;",
        expected=_E.SYNTAX,
        position=23,
        cite="G8, AU-Q28 (TRAILING_SEMICOLON is one final ; plus CFWS only)",
    ),
    Case(
        id="no method",
        value="example.com; =pass",
        expected=_E.SYNTAX,
        position=13,
        cite="PLAN.md 3 reject list (=pass)",
    ),
    Case(
        id="no result",
        value="example.com; dkim=",
        expected=_E.SYNTAX,
        position=18,
        cite="PLAN.md 3 reject list (dkim=); end of input",
    ),
    Case(
        id="no =",
        value="example.com; dkim pass",
        expected=_E.SYNTAX,
        position=18,
        cite="PLAN.md 3 reject list (dkim pass)",
    ),
    Case(
        id="quoted string after result",
        value='example.com; dkim=pass"x"',
        expected=_E.SYNTAX,
        position=22,
        cite='G4 (dkim=pass"x" is SYNTAX at the quote; spot 10 is required)',
    ),
    Case(
        id="property without ptype",
        value="example.com; dkim=pass .from=x",
        expected=_E.SYNTAX,
        position=23,
        cite="PLAN.md 3 reject list (.from=x)",
    ),
    Case(
        id="property without name",
        value="example.com; dkim=pass header.=x",
        expected=_E.SYNTAX,
        position=30,
        cite="PLAN.md 3 reject list (header.=x)",
    ),
    Case(
        id="property without value",
        value="example.com; dkim=pass header.d=",
        expected=_E.SYNTAX,
        position=32,
        cite="PLAN.md 3 reject list (header.d=); end of input",
    ),
    Case(
        id="space inside value",
        value="example.com; dkim=pass header.d=example .com",
        expected=_E.SYNTAX,
        position=40,
        cite="PLAN.md 3 reject list (header.d=example .com)",
    ),
    Case(
        id="ptype without property",
        value="example.com; dkim=pass header.",
        expected=_E.SYNTAX,
        position=30,
        cite="PLAN.md 3 reject list (a ptype with no property); end of input",
    ),
    Case(
        id="ptype.property without =",
        value="example.com; dkim=pass header.d",
        expected=_E.SYNTAX,
        position=31,
        cite="G1 propspec; end of input",
    ),
    Case(
        id="method ends in -",
        value="example.com; dkim-=pass",
        expected=_E.SYNTAX,
        position=13,
        cite="G3 (a run ending in - is SYNTAX at the run's first character)",
    ),
    Case(
        id="result ends in -",
        value="example.com; dkim=pass-",
        expected=_E.SYNTAX,
        position=18,
        cite="G3; AU-Q16 refinement 3",
    ),
    Case(
        id="ptype ends in -",
        value="example.com; dkim=pass header-.d=x",
        expected=_E.SYNTAX,
        position=23,
        cite="G3; AU-Q16 refinement 3",
    ),
    Case(
        id="method with _",
        value="example.com; dk_im=pass",
        expected=_E.SYNTAX,
        position=15,
        cite="PLAN.md 3 reject list (SYNTAX at the _); G3",
    ),
    Case(
        id="property with _",
        value="example.com; dkim=pass header.d_x=y",
        expected=_E.SYNTAX,
        position=31,
        cite="PLAN.md 3 reject list (SYNTAX at the _); G3",
    ),
    Case(
        id="result joined to property",
        value="example.com; dkim=passheader.d=x",
        expected=_E.SYNTAX,
        position=28,
        cite="G3 (. ends the keyword), G4 spot 10 (CFWS required)",
    ),
    Case(
        id="result joined to reason",
        value="example.com; dkim=failreason=x",
        expected=_E.SYNTAX,
        position=28,
        cite="G3, G4 spot 8 (CFWS required before reason)",
    ),
    Case(
        id="result with version",
        value="example.com; dkim=pass/1",
        expected=_E.SYNTAX,
        position=22,
        cite="G1 (result = Keyword; no version after the result)",
    ),
    Case(
        id="stray close paren",
        value="example.com; none )",
        expected=_E.SYNTAX,
        position=18,
        cite="G4, G7",
    ),
    Case(
        id="results before none",
        value="example.com; dkim=pass; none",
        expected=_E.SYNTAX,
        position=28,
        cite="G1 (none and the resinfo list exclude each other); end of input",
    ),
    Case(
        id="tspecial in authserv-id /",
        value="a/b; none",
        expected=_E.SYNTAX,
        position=2,
        cite="AU-Q35 (a first token followed by / is a method), G1 "
        "(method-version = 1*DIGIT: SYNTAX at the b); AU-Q30",
    ),
    Case(
        id="tspecial in authserv-id @",
        value="a@b; none",
        expected=_E.SYNTAX,
        position=1,
        cite="AU-Q30",
    ),
)

_KEYWORDS: tuple[Case, ...] = (
    Case(
        id="method starts with digit",
        value="example.com; 1dkim=pass",
        expected=ar("example.com", res("1dkim", "pass", registered=False)),
        cite="G3 (a keyword may start with a digit or -)",
    ),
    Case(
        id="method starts with -",
        value="example.com; -dkim=pass",
        expected=ar("example.com", res("-dkim", "pass", registered=False)),
        cite="G3 (a keyword may start with a digit or -)",
    ),
    Case(
        id="keyword case",
        value="example.com; DKIM=Pass Header.D=Example.COM",
        expected=ar(
            "example.com",
            res(
                "dkim",
                "pass",
                prop("header", "d", "Example.COM", registered=True),
                registered=True,
            ),
        ),
        cite="PLAN.md 2.5, G13, AU-Q34 (keywords lowercased, values kept)",
    ),
    Case(
        id="special smtp verb case",
        value="example.com; rrvs=pass smtp.RcptTo=user@example.com",
        expected=ar(
            "example.com",
            res(
                "rrvs",
                "pass",
                prop("smtp", "rcptto", "user@example.com", registered=True),
                registered=True,
            ),
        ),
        cite="G1 (special-smtp-verb), G13 (literals case-insensitive), G16 (rrvs)",
    ),
    Case(
        id="mailfrom upper case",
        value="example.com; spf=pass SMTP.MAILFROM=example.net",
        expected=ar(
            "example.com",
            res(
                "spf",
                "pass",
                prop("smtp", "mailfrom", "example.net", registered=True),
                registered=True,
            ),
        ),
        cite="G1, G13",
    ),
)

_PAYLOAD: tuple[Case, ...] = (
    Case(
        id="authserv-id empty quoted",
        value='""; none',
        expected=ar("", none=True),
        cite='AU-Q30 ("" is accepted as the empty string)',
    ),
    Case(
        id="authserv-id quoted with space",
        value='"mx example"; none',
        expected=ar("mx example", none=True),
        cite="AU-Q30 (the unquoted content), G6",
    ),
    Case(
        id="authserv-id quoted-pair",
        value='"a\\"b\\\\c"; none',
        expected=ar('a"b\\c', none=True),
        cite="AU-Q30 (quoted-pairs resolved), G6",
    ),
    Case(
        id="authserv-id case kept",
        value="Example.COM; none",
        expected=ar("Example.COM", none=True),
        cite="PLAN.md 2.5 (authserv-id kept exactly), AU-Q30",
    ),
    Case(
        id="authserv-id joined to digits",
        value="example.com1; none",
        expected=ar("example.com1", none=True),
        cite="G3 (digits are token characters); G4 spot 2 (CFWS before a version)",
    ),
    Case(
        id="quoted authserv-id then version",
        value='"x" 1; none',
        expected=ar("x", none=True, version_given=True),
        cite="G4 spot 2, G11",
    ),
    Case(
        id="quoted authserv-id joined to version",
        value='"x"1; none',
        expected=_E.SYNTAX,
        position=3,
        cite="G4 spot 2 (CFWS required between authserv-id and version), AU-Q25",
    ),
    Case(
        id="version with comment as separator",
        value="example.com(c)1; none",
        expected=ar("example.com", none=True, version_given=True),
        cite="G4 (a comment alone satisfies a required spot)",
    ),
    Case(
        id="version 01",
        value="example.com 01; none",
        expected=ar("example.com", none=True, version_given=True),
        cite="G11 (leading zeros accepted), AU-Q24",
    ),
    Case(
        id="version 0001 with comment",
        value="example.com 0001 (c); none",
        expected=ar("example.com", none=True, version_given=True),
        cite="G11, AU-Q24",
    ),
    Case(
        id="version 1.0",
        value="example.com 1.0; none",
        expected=_E.SYNTAX,
        position=13,
        cite="G11 (1.0 is SYNTAX at the .)",
    ),
    Case(
        id="version 0",
        value="example.com 0; none",
        expected=_E.UNSUPPORTED_VERSION,
        position=12,
        cite="G11 (anything other than 1 after stripping zeros)",
    ),
    Case(
        id="version 10",
        value="example.com 10; none",
        expected=_E.UNSUPPORTED_VERSION,
        position=12,
        cite="G11",
    ),
    Case(
        id="version 5000 digits",
        value="example.com " + "9" * 5000 + "; none",
        expected=_E.UNSUPPORTED_VERSION,
        position=12,
        cite="G11, AU-Q24; PLAN.md 3.1 corrections item 9 (no int() on a long run)",
    ),
    Case(
        id="version 1 after 4999 zeros",
        value="example.com " + "0" * 4999 + "1; none",
        expected=ar("example.com", none=True, version_given=True),
        cite="G11, AU-Q24 (compared as digits with leading zeros stripped)",
    ),
    Case(
        id="version then digits after comment",
        value="example.com 1(c)0; none",
        expected=_E.SYNTAX,
        position=16,
        cite="G4 spot 14 (no CFWS inside digits)",
    ),
    Case(
        id="version 2 before double ;",
        value="example.com 2;;",
        expected=_E.UNSUPPORTED_VERSION,
        position=12,
        cite="AU-Q16 (parse errors leftmost); RFC 8601 2.6 via G11",
    ),
)

_NONE: tuple[Case, ...] = (
    Case(
        id="none upper case with comment",
        value="example.com; NONE (x)",
        expected=ar("example.com", none=True),
        cite="G7 (; NONE (x) is valid)",
    ),
    Case(
        id="none mixed case no space",
        value="example.com;NoNe",
        expected=ar("example.com", none=True),
        cite="G7, G13",
    ),
    Case(
        id="none with CFWS everywhere",
        value="example.com (a) ; (b) none (c) ",
        expected=ar("example.com", none=True),
        cite="G7 (CFWS allowed around none), G1",
    ),
    Case(
        id="none after htab",
        value="example.com;\tnone",
        expected=ar("example.com", none=True),
        cite="G4, G5 (HTAB is WSP)",
    ),
    Case(
        id="none then ;",
        value="example.com; none;",
        expected=_E.SYNTAX,
        position=17,
        cite="G7 (SYNTAX at the first character after none and its CFWS)",
    ),
    Case(
        id="none then result",
        value="example.com; none; dkim=pass",
        expected=_E.SYNTAX,
        position=17,
        cite="G7",
    ),
    Case(
        id="none then word",
        value="example.com; none x",
        expected=_E.SYNTAX,
        position=18,
        cite="G7",
    ),
    Case(
        id="none then comment and word",
        value="example.com; none (c) x",
        expected=_E.SYNTAX,
        position=22,
        cite="G7",
    ),
    Case(
        id="none as method",
        value="example.com; none=pass",
        expected=ar("example.com", res("none", "pass", registered=False)),
        cite="G7, AU-Q21 (follow the ABNF: method none, unregistered)",
    ),
    Case(
        id="none as method with version",
        value="example.com; none/1=pass",
        expected=ar("example.com", res("none", "pass", version=1, registered=False)),
        cite="G7, AU-Q21",
    ),
    Case(
        id="none prefix method",
        value="example.com; nonex=pass",
        expected=ar("example.com", res("nonex", "pass", registered=False)),
        cite="G7 (whole-token match)",
    ),
)

_METHOD: tuple[Case, ...] = (
    Case(
        id="method version with CFWS",
        value="example.com; dkim / 1 = pass",
        expected=ar("example.com", res("dkim", "pass", version=1, registered=True)),
        cite="G4 spots 6 and 7; G11; AU-Q15e",
    ),
    Case(
        id="method version 01",
        value="example.com; dkim/01=pass",
        expected=ar("example.com", res("dkim", "pass", version=1, registered=True)),
        cite="G11 (leading zeros stripped), AU-Q24",
    ),
    Case(
        id="method version 2",
        value="example.com; dkim/2=pass",
        expected=ar("example.com", res("dkim", "pass", version=2, registered=False)),
        cite="G11 (kept, registered=False), PLAN.md 2.4",
    ),
    Case(
        id="method version 0",
        value="example.com; dkim/0=pass",
        expected=ar("example.com", res("dkim", "pass", version=0, registered=False)),
        cite="G11",
    ),
    Case(
        id="method version 9 digits",
        value="example.com; dkim/123456789=pass",
        expected=ar(
            "example.com", res("dkim", "pass", version=123456789, registered=False)
        ),
        cite="G11, AU-Q24 (up to 9 significant digits)",
    ),
    Case(
        id="method version 10 digits",
        value="example.com; dkim/1234567890=pass",
        expected=_E.SYNTAX,
        position=18,
        cite="G11, AU-Q24 (more than 9 significant digits: SYNTAX at the first digit)",
    ),
    Case(
        id="method version 10 digits one significant",
        value="example.com; dkim/0000000001=pass",
        expected=ar("example.com", res("dkim", "pass", version=1, registered=True)),
        cite="G11, AU-Q24 (significant digits only)",
    ),
    Case(
        id="method version 5000 digits",
        value="example.com; dkim/" + "1" * 5000 + "=pass",
        expected=_E.SYNTAX,
        position=18,
        cite="G11, AU-Q24; PLAN.md 3.1 corrections item 9",
    ),
    Case(
        id="method version empty",
        value="example.com; dkim/=pass",
        expected=_E.SYNTAX,
        position=18,
        cite="G1 (method-version = 1*DIGIT)",
    ),
    Case(
        id="method version 1.0",
        value="example.com; dkim/1.0=pass",
        expected=_E.SYNTAX,
        position=19,
        cite="G1, G11",
    ),
    Case(
        id="method version digits split by comment",
        value="example.com; dkim/1(c)0=pass",
        expected=_E.SYNTAX,
        position=22,
        cite="G4 spot 14 (no CFWS inside digits)",
    ),
    Case(
        id="comment inside method",
        value="example.com; dk(c)im=pass",
        expected=_E.SYNTAX,
        position=18,
        cite="G4 spot 14 (no CFWS inside a keyword)",
    ),
    Case(
        id="comments around methodspec",
        value="example.com(a);(b)dkim(c)=(d)pass",
        expected=ar("example.com", _D_PASS),
        cite="G4 spots 4, 5 and 7",
    ),
)

_REASON: tuple[Case, ...] = (
    Case(
        id="reason token",
        value="example.com; dkim=fail reason=bad",
        expected=ar("example.com", res("dkim", "fail", reason="bad", registered=True)),
        cite="G1 reasonspec, G8",
    ),
    Case(
        id="reason quoted upper case literal",
        value='example.com; dkim=fail REASON = "bad sig"',
        expected=ar(
            "example.com", res("dkim", "fail", reason="bad sig", registered=True)
        ),
        cite="G1, G13 (literals case-insensitive), G4 spot 9",
    ),
    Case(
        id="reason empty quoted",
        value='example.com; dkim=fail reason=""',
        expected=ar("example.com", res("dkim", "fail", reason="", registered=True)),
        cite='G6 (an empty "" is allowed)',
    ),
    Case(
        id="reason after comment",
        value="example.com; dkim=fail(c)reason=x",
        expected=ar("example.com", res("dkim", "fail", reason="x", registered=True)),
        cite="G4 spot 8 (a comment satisfies the required CFWS)",
    ),
    Case(
        id="reason CFWS around =",
        value="example.com; dkim=fail reason (c) = (c) x",
        expected=ar("example.com", res("dkim", "fail", reason="x", registered=True)),
        cite="G4 spot 9",
    ),
    Case(
        id="reason then property",
        value="example.com; dkim=fail reason=x header.d=example.com",
        expected=ar(
            "example.com", res("dkim", "fail", _HD, reason="x", registered=True)
        ),
        cite="G1 resinfo, G8",
    ),
    Case(
        id="reason comment then property",
        value="example.com; dkim=fail reason=x(c)header.d=example.com",
        expected=ar(
            "example.com", res("dkim", "fail", _HD, reason="x", registered=True)
        ),
        cite="G4 spot 10 (a comment satisfies it)",
    ),
    Case(
        id="reason quoted joined to property",
        value='example.com; dkim=fail reason="x"header.d=y',
        expected=_E.SYNTAX,
        position=33,
        cite='G6, AU-Q25 (reason="x"header.d=y is SYNTAX)',
    ),
    Case(
        id="reason then next result",
        value="example.com; dkim=fail reason=x; spf=pass",
        expected=ar(
            "example.com",
            res("dkim", "fail", reason="x", registered=True),
            res("spf", "pass", registered=True),
        ),
        cite="G1",
    ),
    Case(
        id="duplicate reason",
        value="example.com; dkim=fail reason=a reason=b",
        expected=_E.DUPLICATE_REASON,
        position=32,
        cite="G8, AU-Q26 (DUPLICATE_REASON at the second reason)",
    ),
    Case(
        id="duplicate reason after property",
        value="example.com; dkim=fail reason=a header.d=x reason=b",
        expected=_E.DUPLICATE_REASON,
        position=43,
        cite="G8, AU-Q26 (a second reason anywhere in the resinfo)",
    ),
    Case(
        id="duplicate reason mixed case",
        value="example.com; dkim=fail reason=a REASON=b",
        expected=_E.DUPLICATE_REASON,
        position=32,
        cite="G8 (any case)",
    ),
    Case(
        id="duplicate reason CFWS before =",
        value="example.com; dkim=fail reason=a reason (c) =b",
        expected=_E.DUPLICATE_REASON,
        position=32,
        cite="G8 (followed by optional CFWS and =)",
    ),
    Case(
        id="duplicate reason before later syntax error",
        value="example.com; dkim=fail reason=a reason=b;;",
        expected=_E.DUPLICATE_REASON,
        position=32,
        cite="G8; AU-Q16 (parse errors in detection order)",
    ),
    Case(
        id="reason after property",
        value="example.com; dkim=fail header.d=x reason=b",
        expected=_E.SYNTAX,
        position=34,
        cite="G8, AU-Q6 (a first reason after a property is SYNTAX)",
    ),
    Case(
        id="reason as ptype",
        value="example.com; dkim=fail reason.x=y",
        expected=ar(
            "example.com",
            res(
                "dkim",
                "fail",
                prop("reason", "x", "y", registered=False),
                registered=True,
            ),
        ),
        cite="G8, AU-Q26 (reason.x=y is a propspec)",
    ),
    Case(
        id="reason then reason as ptype",
        value="example.com; dkim=fail reason=a reason.x=y",
        expected=ar(
            "example.com",
            res(
                "dkim",
                "fail",
                prop("reason", "x", "y", registered=False),
                reason="a",
                registered=True,
            ),
        ),
        cite="G8 (only reason followed by optional CFWS and = is a reason)",
    ),
    Case(
        id="reason address form",
        value="example.com; dkim=fail reason=a@b",
        expected=_E.SYNTAX,
        position=31,
        cite="G8 (the reason value is value only: SYNTAX at @)",
    ),
    Case(
        id="reason with /",
        value="example.com; dkim=fail reason=a/b",
        expected=_E.SYNTAX,
        position=31,
        cite="G8, AU-Q22 (no PVALUE_TSPECIALS for reason)",
    ),
    Case(
        id="reason without value",
        value="example.com; dkim=fail reason=",
        expected=_E.SYNTAX,
        position=30,
        cite="G1 reasonspec; end of input",
    ),
)

_CFWS: tuple[Case, ...] = (
    Case(
        id="quoted value joined to next property",
        value='example.com; dkim=pass header.s="a"header.d=b',
        expected=ar(
            "example.com",
            res(
                "dkim",
                "pass",
                _dkim_s("a", '"a"'),
                prop("header", "d", "b", registered=True),
                registered=True,
            ),
        ),
        cite="G4 spot 12 (optional), AU-Q25",
    ),
    Case(
        id="comment joins properties",
        value="example.com; dkim=pass header.d=a.example(c)header.s=x",
        expected=ar(
            "example.com",
            res(
                "dkim",
                "pass",
                prop("header", "d", "a.example", registered=True),
                prop("header", "s", "x", registered=True),
                registered=True,
            ),
        ),
        cite="G4 (header.d=a.example(c)header.s=x is valid)",
    ),
    Case(
        id="spaces around dot and =",
        value="example.com; dkim=pass header . d = x",
        expected=ar(
            "example.com",
            res(
                "dkim",
                "pass",
                prop("header", "d", "x", registered=True),
                registered=True,
            ),
        ),
        cite="G4 spots 11 and 12; G9",
    ),
    Case(
        id="space before ;",
        value="example.com; dkim=pass header.d= x ;spf=pass",
        expected=ar(
            "example.com",
            res(
                "dkim",
                "pass",
                prop("header", "d", "x", registered=True),
                registered=True,
            ),
            res("spf", "pass", registered=True),
        ),
        cite="G4 spots 4, 5 and 12",
    ),
    Case(
        id="trailing comment",
        value="example.com; dkim=pass (c) ",
        expected=ar("example.com", _D_PASS),
        cite="G4 spot 13",
    ),
    Case(
        id="leading comment",
        value=" (c) example.com; none",
        expected=ar("example.com", none=True),
        cite="G4 spot 1",
    ),
    Case(
        id="space before first ;",
        value="example.com ; dkim=pass",
        expected=ar("example.com", _D_PASS),
        cite="G4 spot 4",
    ),
    Case(
        id="comment inside authserv-id",
        value="exam(c)ple.com; none",
        expected=_E.SYNTAX,
        position=7,
        cite="G4 spot 14 (no CFWS inside a token)",
    ),
    Case(
        id="comment inside pvalue",
        value="example.com; dkim=pass header.d=exa(c)mple.com",
        expected=_E.SYNTAX,
        position=46,
        cite="G4 spot 14; mple.com reads as a propspec with no = (end of input)",
    ),
    Case(
        id="quote inside comment",
        value='example.com; none (a"b)',
        expected=ar("example.com", none=True),
        cite="PLAN.md 3 Comments (a quote inside a comment is comment text)",
    ),
    Case(
        id="quoted-pair paren inside comment",
        value="example.com; none (a\\)b)",
        expected=ar("example.com", none=True),
        cite="G4 (quoted-pairs work inside comments)",
    ),
)

_FOLDING: tuple[Case, ...] = (
    Case(
        id="lf folding",
        value="example.com;\n dkim=pass",
        expected=ar("example.com", _D_PASS, deviations=(Deviation.LF_FOLDING,)),
        cite="G5 (LF WSP is FWS plus LF_FOLDING)",
    ),
    Case(
        id="lf folding strict",
        value="example.com;\n dkim=pass",
        kwargs={"strict_syntax": True},
        expected=_E.DEVIATION,
        position=12,
        deviation=Deviation.LF_FOLDING,
        cite=_STRICT + "; G5 (at the LF)",
    ),
    Case(
        id="obs-fws whitespace-only line",
        value="example.com;\r\n \r\n dkim=pass",
        expected=ar("example.com", _D_PASS),
        cite="G5, AU-Q29 (obs-FWS accepted, no deviation)",
    ),
    Case(
        id="obs-fws tabs",
        value="example.com;\r\n\t\r\n\tdkim=pass",
        expected=ar("example.com", _D_PASS),
        cite="G5, AU-Q29",
    ),
    Case(
        id="several folds",
        value="example.com;\r\n \r\n\t\r\n  dkim=pass",
        expected=ar("example.com", _D_PASS),
        cite="G5, AU-Q29",
    ),
    Case(
        id="bare cr",
        value="example.com;\r dkim=pass",
        expected=_E.CONTROL_CHAR,
        position=12,
        cite="G5 (a bare CR is CONTROL_CHAR at the CR)",
    ),
    Case(
        id="crlf without wsp",
        value="example.com;\r\ndkim=pass",
        expected=_E.CONTROL_CHAR,
        position=12,
        cite="G5, AU-Q38 rule 1 (CRLF not followed by WSP: at the CR)",
    ),
    Case(
        id="lf without wsp",
        value="example.com;\ndkim=pass",
        expected=_E.CONTROL_CHAR,
        position=12,
        cite="G5 (LF not followed by WSP, at the LF)",
    ),
    Case(
        id="trailing lf",
        value="example.com; none\n",
        expected=_E.CONTROL_CHAR,
        position=17,
        cite="G1, G5, AU-Q29 (a trailing LF is CONTROL_CHAR)",
    ),
    Case(
        id="trailing crlf",
        value="example.com; none\r\n",
        expected=_E.CONTROL_CHAR,
        position=17,
        cite="G1, AU-Q29 (a trailing CRLF is CONTROL_CHAR), AU-Q38 rule 1 (at the CR)",
    ),
    Case(
        id="nul",
        value="example.com;\x00 none",
        expected=_E.CONTROL_CHAR,
        position=12,
        cite="PLAN.md 3 Folding (NUL is CONTROL_CHAR)",
    ),
    Case(
        id="del in comment",
        value="example.com; none (\x7f)",
        expected=_E.CONTROL_CHAR,
        position=19,
        cite="PLAN.md 3 Folding (DEL is CONTROL_CHAR, even in a comment)",
    ),
    Case(
        id="c0 control in comment",
        value="example.com; none (\x01)",
        expected=_E.CONTROL_CHAR,
        position=19,
        cite="PLAN.md 3 Folding (C0 controls except HTAB)",
    ),
    Case(
        id="vertical tab",
        value="example.com;\x0bnone",
        expected=_E.CONTROL_CHAR,
        position=12,
        cite="PLAN.md 3 Folding (C0 controls except HTAB)",
    ),
    Case(
        id="c1 control non-ascii mode",
        value="example.com; none (\x85)",
        kwargs={"ascii_only": False},
        expected=_E.CONTROL_CHAR,
        position=19,
        cite="G14, AU-Q29 (C1 controls stay CONTROL_CHAR)",
    ),
    Case(
        id="lone surrogate non-ascii mode",
        value="example.com; none (\udcff)",
        kwargs={"ascii_only": False},
        expected=_E.CONTROL_CHAR,
        position=19,
        cite="PLAN.md 2.2 (CONTROL_CHAR includes lone surrogates), AU-Q29",
    ),
    Case(
        id="c1 control ascii_only",
        value="example.com; none (\x85)",
        expected=_E.CONTROL_CHAR,
        position=19,
        cite="AU-Q37 (a C1 control is CONTROL_CHAR regardless of ascii_only)",
    ),
    Case(
        id="lone surrogate ascii_only",
        value="example.com; none (\udcff)",
        expected=_E.CONTROL_CHAR,
        position=19,
        cite="AU-Q37 (a lone surrogate is CONTROL_CHAR regardless of ascii_only)",
    ),
    Case(
        id="c1 control before non-ascii",
        value="example.com; none (\x85\u00fc)",
        expected=_E.CONTROL_CHAR,
        position=19,
        cite="AU-Q37, AU-Q16 (character scan, leftmost wins)",
    ),
    Case(
        id="non-ascii before c1 control",
        value="example.com; none (\u00fc\x85)",
        expected=_E.NON_ASCII,
        position=19,
        cite="AU-Q37, AU-Q16 (character scan, leftmost wins)",
    ),
    Case(
        id="backslash cr in comment",
        value="example.com; none (a\\\r\n b)",
        expected=_E.CONTROL_CHAR,
        position=21,
        cite="G5, AU-Q29 (backslash then CR: CONTROL_CHAR at the CR)",
    ),
    Case(
        id="backslash lf in comment",
        value="example.com; none (a\\\n b)",
        expected=_E.CONTROL_CHAR,
        position=21,
        cite="G5, AU-Q29 (backslash then LF: CONTROL_CHAR at the LF)",
    ),
    Case(
        id="backslash cr in quoted string",
        value='example.com; dkim=pass reason="a\\\r\n b"',
        expected=_E.CONTROL_CHAR,
        position=33,
        cite="G5, AU-Q29",
    ),
    Case(
        id="fold inside quoted string",
        value='example.com; dkim=pass header.s="a\r\n b"',
        expected=ar(
            "example.com",
            res("dkim", "pass", _dkim_s("a b", '"a\r\n b"'), registered=True),
        ),
        cite="G6 (fold line breaks removed, WSP kept), G10 and AU-Q18c (kept in raw)",
    ),
    Case(
        id="lf fold inside quoted string",
        value='example.com; dkim=pass header.s="a\n b"',
        expected=ar(
            "example.com",
            res("dkim", "pass", _dkim_s("a b", '"a\n b"'), registered=True),
            deviations=(Deviation.LF_FOLDING,),
        ),
        cite="G5, G6",
    ),
    Case(
        id="quoted-pairs resolved",
        value='example.com; dkim=pass header.s="a\\"b\\\\c\\ d"',
        expected=ar(
            "example.com",
            res(
                "dkim",
                "pass",
                _dkim_s('a"b\\c d', '"a\\"b\\\\c\\ d"'),
                registered=True,
            ),
        ),
        cite="G6 (quoted-pairs resolved; raw is the source slice)",
    ),
    Case(
        id="parens inside quoted string",
        value='example.com; dkim=pass header.s="(x)"',
        expected=ar(
            "example.com",
            res("dkim", "pass", _dkim_s("(x)", '"(x)"'), registered=True),
        ),
        cite="G6 (qtext includes parens)",
    ),
    Case(
        id="unterminated quoted string",
        value='example.com; dkim=pass header.s="abc',
        expected=_E.UNTERMINATED_QUOTED_STRING,
        position=32,
        cite="G6 (at the opening quote)",
    ),
    Case(
        id="unterminated quoted string escaped quote",
        value='example.com; dkim=pass header.s="a\\"',
        expected=_E.UNTERMINATED_QUOTED_STRING,
        position=32,
        cite="G6 (the escaped quote does not close it)",
    ),
    Case(
        id="unterminated quoted string with paren",
        value='example.com; dkim=pass header.s="(',
        expected=_E.UNTERMINATED_QUOTED_STRING,
        position=32,
        cite="G6",
    ),
    Case(
        id="unterminated nested comment",
        value="example.com; none (a (b)",
        expected=_E.UNTERMINATED_COMMENT,
        position=18,
        cite="G4 (at the outermost unclosed paren)",
    ),
    Case(
        id="unterminated second comment",
        value="example.com; none (a) (b",
        expected=_E.UNTERMINATED_COMMENT,
        position=22,
        cite="G4",
    ),
    Case(
        id="unterminated comment with quote",
        value='example.com; none (a "',
        expected=_E.UNTERMINATED_COMMENT,
        position=18,
        cite="PLAN.md 3 Comments (a quote inside a comment is ctext)",
    ),
    Case(
        id="nesting 17 default",
        value="example.com; none " + "(" * 17 + ")" * 17,
        expected=_E.NESTING_TOO_DEEP,
        position=34,
        cite="G4 (NESTING_TOO_DEEP at the first paren beyond the limit 16)",
    ),
)

_TSPECIAL_NAMES = {"\\": "backslash"}  # pytest escapes a backslash in ids

_TSPECIALS: tuple[Case, ...] = tuple(
    Case(
        id=f"tspecial {_TSPECIAL_NAMES.get(char, char)} in pvalue",
        value=f"example.com; dkim=pass header.b=a{char}b",
        expected=_E.SYNTAX,
        position=33,
        cite="G10 rule 4, AU-Q22 (< > , : [ ] \\ are SYNTAX in an unquoted pvalue)",
    )
    for char in "<>,:[]\\"
)

_DEVIATIONS: tuple[Case, ...] = (
    Case(
        id="pvalue tspecials",
        value="example.com; dkim=pass header.b=Ab+/cd=",
        expected=ar(
            "example.com",
            res(
                "dkim",
                "pass",
                prop("header", "b", "Ab+/cd=", registered=True),
                registered=True,
            ),
            deviations=(Deviation.PVALUE_TSPECIALS,),
        ),
        cite="G10 rule 3, AU-Q22",
    ),
    Case(
        id="pvalue tspecials strict",
        value="example.com; dkim=pass header.b=Ab+/cd=",
        kwargs={"strict_syntax": True},
        expected=_E.DEVIATION,
        position=35,
        deviation=Deviation.PVALUE_TSPECIALS,
        cite=_STRICT + "; AU-Q16 (at the first / = ?)",
    ),
    Case(
        id="pvalue tspecials ?",
        value="example.com; dkim=pass header.b=a?b",
        expected=ar(
            "example.com",
            res(
                "dkim",
                "pass",
                prop("header", "b", "a?b", registered=True),
                registered=True,
            ),
            deviations=(Deviation.PVALUE_TSPECIALS,),
        ),
        cite="G10 rule 3, AU-Q22",
    ),
    Case(
        id="pvalue tspecials = strict",
        value="example.com; dkim=pass header.b=a=b",
        kwargs={"strict_syntax": True},
        expected=_E.DEVIATION,
        position=33,
        deviation=Deviation.PVALUE_TSPECIALS,
        cite=_STRICT + "; AU-Q16",
    ),
    Case(
        id="pvalue tspecials leading / strict",
        value="example.com; dkim=pass header.b=/x",
        kwargs={"strict_syntax": True},
        expected=_E.DEVIATION,
        position=32,
        deviation=Deviation.PVALUE_TSPECIALS,
        cite=_STRICT + "; AU-Q16",
    ),
    Case(
        id="srs address has no deviation",
        value="example.com; spf=pass smtp.mailfrom=SRS0=x=y@fwd.example",
        kwargs={"strict_syntax": True},
        expected=_spf_mailfrom("SRS0=x=y@fwd.example"),
        cite="G10 rule 1 (/ = ? before @ are local-part atext, no deviation)",
    ),
    Case(
        id="local-part with / and ? has no deviation",
        value="example.com; spf=pass smtp.mailfrom=a/b?c@example.com",
        kwargs={"strict_syntax": True},
        expected=_spf_mailfrom("a/b?c@example.com"),
        cite="G10 rule 1, AU-Q22",
    ),
    Case(
        id="bare property",
        value="example.com; dmarc=pass action=none",
        expected=ar(
            "example.com",
            res("dmarc", "pass", bare("action", "none"), registered=True),
            deviations=(Deviation.BARE_PROPERTY,),
        ),
        cite="G9, AU-Q27",
    ),
    Case(
        id="bare property strict",
        value="example.com; dmarc=pass action=none",
        kwargs={"strict_syntax": True},
        expected=_E.DEVIATION,
        position=24,
        deviation=Deviation.BARE_PROPERTY,
        cite=_STRICT + "; AU-Q16 refinement 1 (placed at the name)",
    ),
    Case(
        id="bare property with CFWS",
        value="example.com; dmarc=pass action (c) = none",
        expected=ar(
            "example.com",
            res("dmarc", "pass", bare("action", "none"), registered=True),
            deviations=(Deviation.BARE_PROPERTY,),
        ),
        cite="G9 (Keyword [CFWS] = pvalue), AU-Q27",
    ),
    Case(
        id="missing ; gives bare property",
        value="example.com; dkim=pass spf=pass",
        expected=ar(
            "example.com",
            res("dkim", "pass", bare("spf", "pass"), registered=True),
            deviations=(Deviation.BARE_PROPERTY,),
        ),
        cite="AU-Q27 (never an spf result)",
    ),
    Case(
        id="bare property name lowercased",
        value="example.com; dmarc=pass Action=None",
        expected=ar(
            "example.com",
            res("dmarc", "pass", bare("action", "None"), registered=True),
            deviations=(Deviation.BARE_PROPERTY,),
        ),
        cite="AU-Q27 (the name is lowercased), PLAN.md 2.5 (value kept)",
    ),
    Case(
        id="bare property interleaved",
        value=(
            "example.com; dmarc=pass header.from=example.com action=none "
            "policy.dmarc=reject"
        ),
        expected=ar(
            "example.com",
            res(
                "dmarc",
                "pass",
                prop("header", "from", "example.com", registered=True),
                bare("action", "none"),
                prop("policy", "dmarc", "reject", registered=True),
                registered=True,
            ),
            deviations=(Deviation.BARE_PROPERTY,),
        ),
        cite="AU-Q27 (interleaved freely, kept in order)",
    ),
    Case(
        id="bare property quoted value",
        value='example.com; dmarc=pass action="a b"',
        expected=ar(
            "example.com",
            res(
                "dmarc",
                "pass",
                Property(
                    ptype=None,
                    name="action",
                    value="a b",
                    raw='"a b"',
                    quoted=True,
                    registered=False,
                ),
                registered=True,
            ),
            deviations=(Deviation.BARE_PROPERTY,),
        ),
        cite="G9 (bare name=pvalue), G10 (quoted-string pvalue)",
    ),
    Case(
        id="bare property with tspecials",
        value="example.com; dmarc=pass action=a/b",
        expected=ar(
            "example.com",
            res("dmarc", "pass", bare("action", "a/b"), registered=True),
            deviations=(Deviation.BARE_PROPERTY, Deviation.PVALUE_TSPECIALS),
        ),
        cite="AU-Q22 (including a bare-property value), AU-Q27",
    ),
    Case(
        id="bare property with tspecials strict",
        value="example.com; dmarc=pass action=a/b",
        kwargs={"strict_syntax": True},
        expected=_E.DEVIATION,
        position=24,
        deviation=Deviation.BARE_PROPERTY,
        cite=_STRICT + "; AU-Q16 refinement 1 (BARE_PROPERTY detected at the =, "
        "before the /)",
    ),
    Case(
        id="trailing semicolon",
        value="example.com; dkim=pass;",
        expected=ar("example.com", _D_PASS, deviations=(Deviation.TRAILING_SEMICOLON,)),
        cite="G8, AU-Q28",
    ),
    Case(
        id="trailing semicolon strict",
        value="example.com; dkim=pass;",
        kwargs={"strict_syntax": True},
        expected=_E.DEVIATION,
        position=22,
        deviation=Deviation.TRAILING_SEMICOLON,
        cite=_STRICT + "; AU-Q16 (at the ;)",
    ),
    Case(
        id="trailing semicolon with CFWS",
        value="example.com; dkim=pass ; (c) ",
        expected=ar("example.com", _D_PASS, deviations=(Deviation.TRAILING_SEMICOLON,)),
        cite="AU-Q28 (a final ; followed by CFWS alone)",
    ),
    Case(
        id="trailing semicolon folded",
        value="example.com; dkim=pass header.d=example.com;\r\n ",
        expected=ar(
            "example.com", _D_PASS_HD, deviations=(Deviation.TRAILING_SEMICOLON,)
        ),
        cite="AU-Q28",
    ),
    Case(
        id="strict without deviation",
        value="example.com; dkim=pass header.d=example.com",
        kwargs={"strict_syntax": True},
        expected=ar("example.com", _D_PASS_HD),
        cite="PLAN.md 2.4",
    ),
    Case(
        id="arc trailing semicolon",
        call="parse_arc",
        value="i=1; example.org; dkim=pass;",
        expected=ArcAuthenticationResults(
            instance=1,
            payload=ar(
                "example.org", _D_PASS, deviations=(Deviation.TRAILING_SEMICOLON,)
            ),
        ),
        cite="G12 (same payload grammar), AU-Q28",
    ),
    Case(
        id="arc trailing semicolon strict",
        call="parse_arc",
        value="i=1; example.org; dkim=pass;",
        kwargs={"strict_syntax": True},
        expected=_E.DEVIATION,
        position=27,
        deviation=Deviation.TRAILING_SEMICOLON,
        cite=_STRICT + "; G12 (positions count the whole value)",
    ),
)

_MF = "example.com; spf=pass smtp.mailfrom="

_ADDRESS: tuple[Case, ...] = (
    Case(
        id="address quoted local-part",
        value=_MF + '"a b"@example.com',
        expected=_spf_mailfrom('"a b"@example.com'),
        cite="G10 rule 1, AU-Q23 (source text, quotes kept, quoted=False)",
    ),
    Case(
        id="address quoted local-part with quoted-pair",
        value=_MF + '"a\\"b"@example.com',
        expected=_spf_mailfrom('"a\\"b"@example.com'),
        cite="AU-Q23 (quotes and backslashes of a quoted local-part kept)",
    ),
    Case(
        id="address dot-atom local-part",
        value=_MF + "a.b@example.com",
        expected=_spf_mailfrom("a.b@example.com"),
        cite="G10 (dot-atom-text local-part)",
    ),
    Case(
        id="address obs local-part spaces",
        value=_MF + "a . b@x.example",
        expected=_E.SYNTAX,
        position=38,
        cite="G10, AU-Q18b (obs-local-part is SYNTAX)",
    ),
    Case(
        id="address obs local-part quoted word",
        value=_MF + '"a".b@x.example',
        expected=_E.SYNTAX,
        position=39,
        cite='G10, AU-Q18b ("a".b@x.example is SYNTAX)',
    ),
    Case(
        id="address CFWS before @",
        value=_MF + "a (c) @x.example",
        expected=_E.SYNTAX,
        position=42,
        cite="G10, AU-Q18b (no CFWS inside or around the address form)",
    ),
    Case(
        id="address single-label domain",
        value=_MF + "a@localhost",
        expected=_E.SYNTAX,
        position=38,
        cite="AU-Q24 (two or more labels), AU-Q38 rule 2 (no offending character: "
        "at the domain's first character)",
    ),
    Case(
        id="address empty local single-label domain",
        value="example.com; dkim=pass header.i=@localhost",
        expected=_E.SYNTAX,
        position=33,
        cite="AU-Q24 (@localhost is SYNTAX), AU-Q38 rule 2 (at the domain's first "
        "character)",
    ),
    Case(
        id="address trailing dot",
        value=_MF + "a@x.example.",
        expected=_E.SYNTAX,
        position=47,
        cite="G10, AU-Q24 (no trailing dot), AU-Q38 rule 2 (at the dot)",
    ),
    Case(
        id="address label ends with -",
        value=_MF + "a@x-.example",
        expected=_E.SYNTAX,
        position=39,
        cite="G10 (Ldh-str ends in Let-dig), AU-Q38 rule 2 (at the -)",
    ),
    Case(
        id="address space after @",
        value=_MF + "a@ x.example",
        expected=_E.SYNTAX,
        position=38,
        cite="G10, AU-Q18b (no CFWS inside the address form), AU-Q38 rule 2 "
        "(at the space)",
    ),
    Case(
        id="address literal",
        value=_MF + "a@[192.0.2.1]",
        expected=_E.SYNTAX,
        position=38,
        cite="AU-Q24 (no address-literal), G10 rule 4 (SYNTAX at the [)",
    ),
    Case(
        id="address two @",
        value=_MF + "a@b@example.com",
        expected=_E.SYNTAX,
        position=39,
        cite="G10 rule 1 (SYNTAX at the first offending character)",
    ),
    Case(
        id="address label starts with -",
        value=_MF + "a@-x.example",
        expected=_E.SYNTAX,
        position=38,
        cite="G10 (each label Let-dig [Ldh-str])",
    ),
    Case(
        id="address _ in domain",
        value=_MF + "a@x_y.example",
        expected=_E.SYNTAX,
        position=39,
        cite="G10, AU-Q24 (no _ in the domain)",
    ),
    Case(
        id="address double dot in local-part",
        value=_MF + "a..b@x.example",
        expected=_E.SYNTAX,
        position=38,
        cite="G10 (dot-atom-text)",
    ),
    Case(
        id="address leading dot in local-part",
        value=_MF + ".a@x.example",
        expected=_E.SYNTAX,
        position=36,
        cite="G10 (dot-atom-text)",
    ),
    Case(
        id="address comma in local-part",
        value=_MF + "a,b@x.example",
        expected=_E.SYNTAX,
        position=37,
        cite="G10 rule 4 (, is SYNTAX)",
    ),
)


def _reg(case_id: str, value: str, expected: AuthenticationResults, cite: str) -> Case:
    return Case(id=case_id, value=value, expected=expected, cite=_REG + "; " + cite)


_REGISTERED: tuple[Case, ...] = (
    Case(
        id="require registered ok",
        value="example.com; dkim=pass header.d=example.com",
        kwargs={"require_registered": True},
        expected=ar("example.com", _D_PASS_HD),
        cite=_REG,
    ),
    Case(
        id="require registered none",
        value="example.com; none",
        kwargs={"require_registered": True},
        expected=ar("example.com", none=True),
        cite=_REG,
    ),
    Case(
        id="require registered x-dmarc",
        value="example.com; x-dmarc=pass",
        kwargs={"require_registered": True},
        expected=_E.UNREGISTERED,
        position=13,
        cite=_REG + "; AU-Q16 refinement 1 (at the method keyword)",
    ),
    Case(
        id="require registered dmarc=passed",
        value="example.com; dmarc=passed",
        kwargs={"require_registered": True},
        expected=_E.UNREGISTERED,
        position=13,
        cite=_REG + "; AU-Q16 refinement 1",
    ),
    Case(
        id="require registered method version 2",
        value="example.com; dkim/2=pass",
        kwargs={"require_registered": True},
        expected=_E.UNREGISTERED,
        position=13,
        cite=_REG + "; G11 (UNREGISTERED at the method keyword)",
    ),
    Case(
        id="require registered dkim header.from",
        value="example.com; dkim=pass header.from=x",
        kwargs={"require_registered": True},
        expected=_E.UNREGISTERED,
        position=23,
        cite=_REG + "; AU-Q16 refinement 1 (at the ptype)",
    ),
    Case(
        id="require registered bare property",
        value="example.com; dmarc=pass action=none",
        kwargs={"require_registered": True},
        expected=_E.UNREGISTERED,
        position=24,
        cite=_REG + "; AU-Q16 refinement 1 (at the bare name)",
    ),
    Case(
        id="require registered second result",
        value="example.com; dkim=pass; foo=pass",
        kwargs={"require_registered": True},
        expected=_E.UNREGISTERED,
        position=24,
        cite=_REG,
    ),
    Case(
        id="require registered domainkeys fail",
        value="example.com; domainkeys=fail",
        kwargs={"require_registered": True},
        expected=_E.UNREGISTERED,
        position=13,
        cite=_REG + "; G16 (IANA lists no fail for domainkeys)",
    ),
    Case(
        id="require registered sender-id any header",
        value="example.com; sender-id=pass header.x-anything=a",
        kwargs={"require_registered": True},
        expected=ar(
            "example.com",
            res(
                "sender-id",
                "pass",
                prop("header", "x-anything", "a", registered=True),
                registered=True,
            ),
        ),
        cite=_REG + "; G16 (sender-id matches any header.*)",
    ),
    Case(
        id="require registered and strict bare property",
        value="example.com; dmarc=pass action=none",
        kwargs={"require_registered": True, "strict_syntax": True},
        expected=_E.DEVIATION,
        position=24,
        deviation=Deviation.BARE_PROPERTY,
        cite="AU-Q16 refinement 2 (at the same position DEVIATION comes first)",
    ),
    Case(
        id="require registered and strict tspecials",
        value="example.com; dkim=pass header.x=a/b",
        kwargs={"require_registered": True, "strict_syntax": True},
        expected=_E.DEVIATION,
        position=33,
        deviation=Deviation.PVALUE_TSPECIALS,
        cite="AU-Q16 refinement 1 (detection order: the / is met while the "
        "pvalue is read, the property check runs after it)",
    ),
    Case(
        id="require registered and strict result first",
        value="example.com; x=pass action=none",
        kwargs={"require_registered": True, "strict_syntax": True},
        expected=_E.UNREGISTERED,
        position=13,
        cite="AU-Q16 refinement 1 (the result is checked once its keyword is read)",
    ),
    _reg(
        "domainkeys fail unregistered",
        "example.com; domainkeys=fail",
        ar("example.com", res("domainkeys", "fail", registered=False)),
        "G16 (snapshot literal to IANA)",
    ),
    _reg(
        "domainkeys pass deprecated",
        "example.com; domainkeys=pass header.d=example.com header.sender=a@example.com",
        ar(
            "example.com",
            res(
                "domainkeys",
                "pass",
                prop("header", "d", "example.com", registered=True),
                prop("header", "sender", "a@example.com", registered=True),
                registered=True,
            ),
        ),
        "G16 (deprecated entries count as registered)",
    ),
    _reg(
        "spf hardfail deprecated",
        "example.com; spf=hardfail smtp.helo=mx.example.com",
        ar(
            "example.com",
            res(
                "spf",
                "hardfail",
                prop("smtp", "helo", "mx.example.com", registered=True),
                registered=True,
            ),
        ),
        "G16",
    ),
    _reg(
        "dnswl properties",
        "example.com; dnswl=pass dns.zone=list.example policy.ip=127.0.0.2 "
        "policy.txt=x dns.sec=yes",
        ar(
            "example.com",
            res(
                "dnswl",
                "pass",
                prop("dns", "zone", "list.example", registered=True),
                prop("policy", "ip", "127.0.0.2", registered=True),
                prop("policy", "txt", "x", registered=True),
                prop("dns", "sec", "yes", registered=True),
                registered=True,
            ),
        ),
        "G16 (ptype dns)",
    ),
    _reg(
        "dnswl fail unregistered",
        "example.com; dnswl=fail",
        ar("example.com", res("dnswl", "fail", registered=False)),
        "G16 (dnswl results: none, pass, permerror, temperror)",
    ),
    _reg(
        "iprev none unregistered",
        "example.com; iprev=none",
        ar("example.com", res("iprev", "none", registered=False)),
        "G16 (iprev results: fail, pass, permerror, temperror)",
    ),
    _reg(
        "smime identifer as registered",
        "example.com; smime=pass body.smime-identifer=x body.smime-identifier=y",
        ar(
            "example.com",
            res(
                "smime",
                "pass",
                prop("body", "smime-identifer", "x", registered=True),
                prop("body", "smime-identifier", "y", registered=False),
                registered=True,
            ),
        ),
        "G16 (smime-identifer, sic, as registered)",
    ),
    _reg(
        "arc properties",
        "example.com; arc=pass smtp.remote-ip=192.0.2.1 header.oldest-pass=0",
        ar(
            "example.com",
            res(
                "arc",
                "pass",
                prop("smtp", "remote-ip", "192.0.2.1", registered=True),
                prop("header", "oldest-pass", "0", registered=True),
                registered=True,
            ),
        ),
        "G16",
    ),
    _reg(
        "vbr properties",
        "example.com; vbr=pass header.md=example.com header.mv=example.net",
        ar(
            "example.com",
            res(
                "vbr",
                "pass",
                prop("header", "md", "example.com", registered=True),
                prop("header", "mv", "example.net", registered=True),
                registered=True,
            ),
        ),
        "G16",
    ),
    _reg(
        "dkim-atps header.from",
        "example.com; dkim-atps=pass header.from=example.com",
        ar(
            "example.com",
            res(
                "dkim-atps",
                "pass",
                prop("header", "from", "example.com", registered=True),
                registered=True,
            ),
        ),
        "G16",
    ),
    _reg(
        "dkim-adsp discard",
        "example.com; dkim-adsp=discard header.from=example.com",
        ar(
            "example.com",
            res(
                "dkim-adsp",
                "discard",
                prop("header", "from", "example.com", registered=True),
                registered=True,
            ),
        ),
        "G16 (deprecated, counts as registered)",
    ),
    _reg(
        "auth smtp.mailfrom",
        "example.com; auth=pass smtp.mailfrom=a@example.com",
        ar(
            "example.com",
            res(
                "auth",
                "pass",
                prop("smtp", "mailfrom", "a@example.com", registered=True),
                registered=True,
            ),
        ),
        "G16",
    ),
    _reg(
        "dkim policy header.a",
        "example.com; dkim=policy header.a=rsa-sha256",
        ar(
            "example.com",
            res(
                "dkim",
                "policy",
                prop("header", "a", "rsa-sha256", registered=True),
                registered=True,
            ),
        ),
        "G16",
    ),
    _reg(
        "rrvs unknown",
        "example.com; rrvs=unknown",
        ar("example.com", res("rrvs", "unknown", registered=True)),
        "G16",
    ),
    _reg(
        "unknown ptype",
        "example.com; dkim=pass x.d=y",
        ar(
            "example.com",
            res("dkim", "pass", prop("x", "d", "y", registered=False), registered=True),
        ),
        "G16 (x is not a registered ptype)",
    ),
)

_NON_ASCII: tuple[Case, ...] = (
    Case(
        id="utf-8 comment",
        value="example.com; none (\u00fc)",
        kwargs={"ascii_only": False},
        expected=ar("example.com", none=True),
        cite=_ASCII + " (comment)",
    ),
    Case(
        id="utf-8 comment ascii_only",
        value="example.com; none (\u00fc)",
        expected=_E.NON_ASCII,
        position=19,
        cite="G14 (ascii_only=True: NON_ASCII at the first non-ASCII character)",
    ),
    Case(
        id="utf-8 quoted reason",
        value='example.com; dkim=pass reason="\u00fc"',
        kwargs={"ascii_only": False},
        expected=ar(
            "example.com", res("dkim", "pass", reason="\u00fc", registered=True)
        ),
        cite=_ASCII + " (quoted-string)",
    ),
    Case(
        id="utf-8 authserv-id token",
        value="b\u00fccher.example; none",
        kwargs={"ascii_only": False},
        expected=ar("b\u00fccher.example", none=True),
        cite=_ASCII + " (unquoted token value, a judgement call)",
    ),
    Case(
        id="utf-8 authserv-id token ascii_only",
        value="b\u00fccher.example; none",
        expected=_E.NON_ASCII,
        position=1,
        cite="G14",
    ),
    Case(
        id="utf-8 authserv-id quoted",
        value='"b\u00fc"; none',
        kwargs={"ascii_only": False},
        expected=ar("b\u00fc", none=True),
        cite=_ASCII,
    ),
    Case(
        id="utf-8 pvalue token",
        value="example.com; dmarc=pass header.from=b\u00fccher.example",
        kwargs={"ascii_only": False},
        expected=ar(
            "example.com",
            res(
                "dmarc",
                "pass",
                prop("header", "from", "b\u00fccher.example", registered=True),
                registered=True,
            ),
        ),
        cite=_ASCII + "; PLAN.md 2.5 (no IDNA)",
    ),
    Case(
        id="utf-8 reason token",
        value="example.com; dkim=fail reason=\u00fc",
        kwargs={"ascii_only": False},
        expected=ar(
            "example.com", res("dkim", "fail", reason="\u00fc", registered=True)
        ),
        cite=_ASCII,
    ),
    Case(
        id="utf-8 local-part",
        value=_MF + "j\u00f6@example.com",
        kwargs={"ascii_only": False},
        expected=_spf_mailfrom("j\u00f6@example.com"),
        cite=_ASCII + " (dot-atom local-part, RFC 6531/6532 atext)",
    ),
    Case(
        id="utf-8 quoted local-part",
        value=_MF + '"j\u00f6 x"@example.com',
        kwargs={"ascii_only": False},
        expected=_spf_mailfrom('"j\u00f6 x"@example.com'),
        cite=_ASCII + "; AU-Q23",
    ),
    Case(
        id="utf-8 domain label",
        value=_MF + "a@b\u00fccher.example",
        kwargs={"ascii_only": False},
        expected=_spf_mailfrom("a@b\u00fccher.example"),
        cite=_ASCII + " (domain-name label, no IDNA check)",
    ),
    Case(
        id="utf-8 bare property value",
        value="example.com; dmarc=pass action=\u00fc",
        kwargs={"ascii_only": False},
        expected=ar(
            "example.com",
            res("dmarc", "pass", bare("action", "\u00fc"), registered=True),
            deviations=(Deviation.BARE_PROPERTY,),
        ),
        cite=_ASCII + "; AU-Q27",
    ),
    Case(
        id="utf-8 not normalised",
        value='example.com; dkim=pass reason="u\u0308"',
        kwargs={"ascii_only": False},
        expected=ar(
            "example.com", res("dkim", "pass", reason="u\u0308", registered=True)
        ),
        cite="G14 (no normalisation: values are returned as given)",
    ),
    Case(
        id="kelvin sign in dkim",
        value="example.com; d\u212aim=pass",
        kwargs={"ascii_only": False},
        expected=_E.SYNTAX,
        position=14,
        cite="PLAN.md 2.5 and G14 (look-alike keywords: SYNTAX at that character)",
    ),
    Case(
        id="kelvin sign in dkim ascii_only",
        value="example.com; d\u212aim=pass",
        expected=_E.NON_ASCII,
        position=14,
        cite="PLAN.md 2.5 (the character scan raises NON_ASCII first)",
    ),
    Case(
        id="long s in spf",
        value="example.com; \u017fpf=pass",
        kwargs={"ascii_only": False},
        expected=_E.SYNTAX,
        position=13,
        cite="PLAN.md 2.5 and G14",
    ),
    Case(
        id="long s in result",
        value="example.com; dkim=pa\u017fs",
        kwargs={"ascii_only": False},
        expected=_E.SYNTAX,
        position=20,
        cite="G14 (never UTF-8 in a result keyword)",
    ),
    Case(
        id="long s in property",
        value="example.com; dkim=pass header.\u017f=x",
        kwargs={"ascii_only": False},
        expected=_E.SYNTAX,
        position=30,
        cite="G14 (never UTF-8 in a property keyword)",
    ),
    Case(
        id="cyrillic e in ptype",
        value="example.com; dkim=pass h\u0435ader.d=x",
        kwargs={"ascii_only": False},
        expected=_E.SYNTAX,
        position=24,
        cite="G14 (never UTF-8 in a ptype)",
    ),
    Case(
        id="cyrillic e in none",
        value="example.com; non\u0435",
        kwargs={"ascii_only": False},
        expected=_E.SYNTAX,
        position=16,
        cite="G14 (never UTF-8 in none)",
    ),
    Case(
        id="cyrillic e in reason",
        value="example.com; dkim=pass r\u0435ason=x",
        kwargs={"ascii_only": False},
        expected=_E.SYNTAX,
        position=24,
        cite="G14 (never UTF-8 in reason)",
    ),
    Case(
        id="fullwidth digit version",
        value="example.com \uff11; none",
        kwargs={"ascii_only": False},
        expected=_E.SYNTAX,
        position=12,
        cite="G14 (never UTF-8 in digits)",
    ),
    Case(
        id="arabic-indic digit method version",
        value="example.com; dkim/\u0661=pass",
        kwargs={"ascii_only": False},
        expected=_E.SYNTAX,
        position=18,
        cite="G14 (never UTF-8 in digits)",
    ),
)

_PRECEDENCE: tuple[Case, ...] = (
    Case(
        id="too long before control",
        value="\x00" * 8193,
        expected=_E.TOO_LONG,
        position=8192,
        cite="PLAN.md 2.1, AU-Q16 (length before the character scan)",
    ),
    Case(
        id="invalid type before length",
        value=b"x" * 9000,
        expected=_E.INVALID_TYPE,
        position=None,
        cite="PLAN.md 2.1, AU-Q16 (type first)",
    ),
    Case(
        id="control before unterminated comment",
        value="example.com; none (\x00",
        expected=_E.CONTROL_CHAR,
        position=19,
        cite="AU-Q16 (the scan runs before the tokeniser pass)",
    ),
    Case(
        id="non-ascii before syntax",
        value="example.com;; (\u00fc)",
        expected=_E.NON_ASCII,
        position=15,
        cite="AU-Q16 (the scan runs before the parse)",
    ),
    Case(
        id="non-ascii before control",
        value="example.com; none (\u00fc\x00)",
        expected=_E.NON_ASCII,
        position=19,
        cite="AU-Q16 (character scan, leftmost wins)",
    ),
    Case(
        id="control before non-ascii",
        value="example.com; none (\x00\u00fc)",
        expected=_E.CONTROL_CHAR,
        position=19,
        cite="AU-Q16 (character scan, leftmost wins)",
    ),
    Case(
        id="unterminated comment before syntax",
        value="example.com;; (",
        expected=_E.UNTERMINATED_COMMENT,
        position=14,
        cite="AU-Q16 (the tokeniser pass runs before the parse)",
    ),
    Case(
        id="unterminated quoted string before syntax",
        value=';; "',
        expected=_E.UNTERMINATED_QUOTED_STRING,
        position=3,
        cite="AU-Q16",
    ),
    Case(
        id="nesting before syntax",
        value=";;" + "(" * 17 + ")" * 17,
        expected=_E.NESTING_TOO_DEEP,
        position=18,
        cite="AU-Q16 (tokeniser pass before the parse)",
    ),
    Case(
        id="nesting before unterminated quoted string",
        value="example.com; none " + "(" * 17 + ")" * 17 + ' "',
        expected=_E.NESTING_TOO_DEEP,
        position=34,
        cite="AU-Q16 (tokeniser faults: leftmost)",
    ),
    Case(
        id="control only",
        value="\x00",
        expected=_E.CONTROL_CHAR,
        position=0,
        cite="AU-Q16 (EMPTY is decided after the scan)",
    ),
    Case(
        id="space then control",
        value=" \x00",
        expected=_E.CONTROL_CHAR,
        position=1,
        cite="AU-Q16",
    ),
    Case(
        id="strict lf folding before syntax",
        value="example.com;\n dkim=pass;;",
        kwargs={"strict_syntax": True},
        expected=_E.DEVIATION,
        position=12,
        deviation=Deviation.LF_FOLDING,
        cite="AU-Q16 (LF_FOLDING under strict is raised by the scan)",
    ),
    Case(
        id="lenient lf folding then syntax",
        value="example.com;\n dkim=pass;;",
        expected=_E.SYNTAX,
        position=24,
        cite="G8, G5",
    ),
    Case(
        id="strict lf folding before control",
        value="example.com;\n dkim=pass\x00",
        kwargs={"strict_syntax": True},
        expected=_E.DEVIATION,
        position=12,
        deviation=Deviation.LF_FOLDING,
        cite="AU-Q16 (scan, leftmost wins)",
    ),
    Case(
        id="control before strict lf folding",
        value="example.com;\x00\n dkim=pass",
        kwargs={"strict_syntax": True},
        expected=_E.CONTROL_CHAR,
        position=12,
        cite="AU-Q16 (scan, leftmost wins)",
    ),
    Case(
        id="strict lf folding before unterminated quoted string",
        value='example.com; dkim=pass header.s="a\n b',
        kwargs={"strict_syntax": True},
        expected=_E.DEVIATION,
        position=34,
        deviation=Deviation.LF_FOLDING,
        cite="AU-Q16 (scan before the tokeniser pass)",
    ),
    Case(
        id="lenient lf folding then unterminated quoted string",
        value='example.com; dkim=pass header.s="a\n b',
        expected=_E.UNTERMINATED_QUOTED_STRING,
        position=32,
        cite="G6, AU-Q16",
    ),
    Case(
        id="unregistered before later syntax",
        value="example.com; x=pass;;",
        kwargs={"require_registered": True},
        expected=_E.UNREGISTERED,
        position=13,
        cite="AU-Q16 refinement 1 (detection order)",
    ),
    Case(
        id="syntax before property registration",
        value="example.com; dkim=pass header.d=;x=pass",
        kwargs={"require_registered": True},
        expected=_E.SYNTAX,
        position=32,
        cite="AU-Q16 refinement 1 (the property is checked once its pvalue is read)",
    ),
)

_GET_UNIQUE: tuple[Case, ...] = (
    Case(
        id="get_unique duplicate",
        call="get_unique",
        value="example.com; dmarc=pass header.from=a.example header.from=b.example",
        lookup=("header", "from"),
        expected=_E.DUPLICATE_PROPERTY,
        position=None,
        cite="PLAN.md 2.2 (get_unique raises DUPLICATE_PROPERTY), AU-Q16",
    ),
    Case(
        id="get_unique bare duplicate",
        call="get_unique",
        value="example.com; dmarc=pass action=a action=b",
        lookup=(None, "action"),
        expected=_E.DUPLICATE_PROPERTY,
        position=None,
        cite="PLAN.md 2.2; G9 (repeated properties kept in order)",
    ),
    Case(
        id="get_unique single case-insensitive",
        call="get_unique",
        value="example.com; dmarc=pass header.from=a.example",
        lookup=("HEADER", "From"),
        expected=prop("header", "from", "a.example", registered=True),
        cite="PLAN.md 2.2, AU-Q15d (arguments lowercased)",
    ),
    Case(
        id="get_unique not found",
        call="get_unique",
        value="example.com; dmarc=pass header.from=a.example",
        lookup=("header", "d"),
        expected=None,
        cite="PLAN.md 2.2",
    ),
)

_TYPES: tuple[Case, ...] = (
    Case(
        id="invalid type bytes",
        value=b"example.com; none",
        expected=_E.INVALID_TYPE,
        position=None,
        cite="PLAN.md 2.1 (anything not a str is INVALID_TYPE), AU-Q16",
    ),
    Case(
        id="invalid type none",
        value=None,
        expected=_E.INVALID_TYPE,
        position=None,
        cite="PLAN.md 2.1",
    ),
    Case(
        id="invalid type int",
        value=1,
        expected=_E.INVALID_TYPE,
        position=None,
        cite="PLAN.md 2.1",
    ),
    Case(
        id="invalid type bytearray",
        value=bytearray(b"example.com; none"),
        expected=_E.INVALID_TYPE,
        position=None,
        cite="PLAN.md 2.1",
    ),
    Case(
        id="arc invalid type bytes",
        call="parse_arc",
        value=b"i=1; example.org; none",
        expected=_E.INVALID_TYPE,
        position=None,
        cite="PLAN.md 2.1, AL2b row (parse_arc too)",
    ),
    Case(
        id="str subclass",
        value=StrSubclass("example.com; none"),
        expected=ar("example.com", none=True),
        cite="AL2b row (a str subclass is normalised to an exact str first)",
    ),
    Case(
        id="str subclass lying length",
        value=LyingLength("x" * 8193),
        expected=_E.TOO_LONG,
        position=8192,
        cite="AL2b row (a lying __len__ must not bypass TOO_LONG)",
    ),
    Case(
        id="arc str subclass",
        call="parse_arc",
        value=StrSubclass("i=1; example.org; none"),
        expected=ArcAuthenticationResults(
            instance=1, payload=ar("example.org", none=True)
        ),
        cite="AL2b row",
    ),
)

_Q35 = (
    "AU-Q35 (missing authserv-id: the first token is followed, after CFWS, by = or /)"
)
_MISSING = (Deviation.MISSING_AUTHSERV_ID,)

_MISSING_ID: tuple[Case, ...] = (
    Case(
        id="missing authserv-id",
        value="dkim=pass",
        expected=ar(None, _D_PASS, deviations=_MISSING),
        cite=_Q35 + "; lenient: authserv_id=None, recorded",
    ),
    Case(
        id="missing authserv-id strict",
        value="dkim=pass",
        kwargs={"strict_syntax": True},
        expected=_E.DEVIATION,
        position=0,
        deviation=Deviation.MISSING_AUTHSERV_ID,
        cite=_Q35 + "; strict: DEVIATION at the first method keyword",
    ),
    Case(
        id="missing authserv-id after leading CFWS",
        value=" (c) spf=pass smtp.mailfrom=example.net; dkim=fail",
        expected=ar(
            None,
            res(
                "spf",
                "pass",
                prop("smtp", "mailfrom", "example.net", registered=True),
                registered=True,
            ),
            _D_FAIL,
            deviations=_MISSING,
        ),
        cite=_Q35 + "; G4 spot 1",
    ),
    Case(
        id="missing authserv-id after leading CFWS strict",
        value=" (c) spf=pass smtp.mailfrom=example.net; dkim=fail",
        kwargs={"strict_syntax": True},
        expected=_E.DEVIATION,
        position=5,
        deviation=Deviation.MISSING_AUTHSERV_ID,
        cite=_Q35 + "; strict: at the first method keyword",
    ),
    Case(
        id="missing authserv-id CFWS before =",
        value="dkim (c) = pass",
        expected=ar(None, _D_PASS, deviations=_MISSING),
        cite=_Q35 + " (followed after CFWS by =)",
    ),
    Case(
        id="missing authserv-id method version",
        value="dkim/1=pass; spf=fail",
        expected=ar(
            None,
            res("dkim", "pass", version=1, registered=True),
            res("spf", "fail", registered=True),
            deviations=_MISSING,
        ),
        cite=_Q35 + " (followed by /)",
    ),
    Case(
        id="missing authserv-id version-looking token",
        value="2=pass",
        expected=ar(None, res("2", "pass", registered=False), deviations=_MISSING),
        cite=_Q35 + "; G3 (a keyword may start with a digit): a method, not "
        "UNSUPPORTED_VERSION (a version only follows an authserv-id, G1)",
    ),
    Case(
        id="missing authserv-id version-looking token strict",
        value="2=pass",
        kwargs={"strict_syntax": True},
        expected=_E.DEVIATION,
        position=0,
        deviation=Deviation.MISSING_AUTHSERV_ID,
        cite=_Q35 + "; strict",
    ),
    Case(
        id="missing authserv-id with trailing semicolon",
        value="dkim=pass;",
        expected=ar(
            None,
            _D_PASS,
            deviations=(Deviation.MISSING_AUTHSERV_ID, Deviation.TRAILING_SEMICOLON),
        ),
        cite=_Q35 + "; AU-Q28",
    ),
    Case(
        id="missing authserv-id with trailing semicolon strict",
        value="dkim=pass;",
        kwargs={"strict_syntax": True},
        expected=_E.DEVIATION,
        position=0,
        deviation=Deviation.MISSING_AUTHSERV_ID,
        cite=_Q35 + "; AU-Q16 (the first deviation raises)",
    ),
    Case(
        id="missing authserv-id require_registered",
        value="dkim=pass header.d=example.com",
        kwargs={"require_registered": True},
        expected=ar(None, _D_PASS_HD, deviations=_MISSING),
        cite=_Q35 + "; a deviation, not a registration fault (PLAN.md 2.4)",
    ),
    Case(
        id="dotted first token then =",
        value="mx.example=pass",
        expected=_E.SYNTAX,
        position=10,
        cite="AU-Q39 (only a keyword-shaped first token can be a method; a "
        "dotted token is the authserv-id, and the = after it is SYNTAX)",
    ),
    Case(
        id="quoted first token then =",
        value='"dkim"=pass',
        expected=_E.SYNTAX,
        position=6,
        cite="AU-Q39 (a quoted first token is the authserv-id)",
    ),
    Case(
        id="keyword-shaped authserv-id then ;",
        value="dkim; none",
        expected=ar("dkim", none=True),
        cite="AU-Q39, AU-Q35 (not followed by = or /: the authserv-id)",
    ),
    Case(
        id="authserv-id then result without ;",
        value="mx.example dmarc=pass",
        expected=_E.SYNTAX,
        position=11,
        cite="AU-Q39, G1 (after the authserv-id and CFWS only a version or ; "
        "may follow)",
    ),
    Case(
        id="none alone is an authserv-id",
        value="none",
        expected=_E.SYNTAX,
        position=4,
        cite="AU-Q35 (none is not followed by = or /, so it is the authserv-id); "
        "G1 (the authserv-id alone is SYNTAX at len(value))",
    ),
    Case(
        id="arc missing authserv-id",
        call="parse_arc",
        value="i=1; dkim=pass",
        expected=ArcAuthenticationResults(
            instance=1, payload=ar(None, _D_PASS, deviations=_MISSING)
        ),
        cite=_Q35 + "; G12 (same payload grammar)",
    ),
    Case(
        id="arc missing authserv-id strict",
        call="parse_arc",
        value="i=1; dkim=pass",
        kwargs={"strict_syntax": True},
        expected=_E.DEVIATION,
        position=5,
        deviation=Deviation.MISSING_AUTHSERV_ID,
        cite=_Q35 + "; G12 (positions count the whole value)",
    ),
)

_COMMENT_SEMICOLONS: tuple[Case, ...] = (
    Case(
        id="semicolon in comment flat",
        value=(
            "example.com; dkim=fail (; dmarc=pass header.from=x;) header.d=example.com"
        ),
        expected=ar("example.com", res("dkim", "fail", _HD, registered=True)),
        cite="G4 (comment content is never data; ctext includes ; and =)",
    ),
    Case(
        id="semicolon in comment nested",
        value=(
            "example.com; dkim=fail (a (; dmarc=pass header.from=x;) b) "
            "header.d=example.com"
        ),
        expected=ar("example.com", res("dkim", "fail", _HD, registered=True)),
        cite="G4 (nested comments, depth counter)",
    ),
    Case(
        id="semicolon in comment inside property list",
        value=(
            "example.com; dkim=pass header.d=example.com "
            "(; dmarc=pass header.from=x;) header.s=s1"
        ),
        expected=ar(
            "example.com",
            res(
                "dkim",
                "pass",
                _HD,
                prop("header", "s", "s1", registered=True),
                registered=True,
            ),
        ),
        cite="G4 spot 12",
    ),
    Case(
        id="semicolon in comment at end",
        value="example.com; dkim=pass (; dmarc=pass header.from=x;)",
        expected=ar("example.com", _D_PASS),
        cite="G4 spot 13",
    ),
    Case(
        id="semicolon in comment between results",
        value="example.com; dkim=pass; (; dmarc=pass;) spf=fail",
        expected=ar("example.com", _D_PASS, res("spf", "fail", registered=True)),
        cite="G4 spot 5",
    ),
    Case(
        id="semicolon in comment after authserv-id",
        value="example.com (; dmarc=pass;); none",
        expected=ar("example.com", none=True),
        cite="G4 spot 4, G7",
    ),
)


def _prefix(
    case_id: str, value: str, model: AuthenticationResults, position: int, note: str
) -> tuple[Case, Case]:
    cite = "G16, AU-Q31 (whole-name match: " + note + ")"
    return (
        Case(id=case_id, value=value, expected=model, cite=cite),
        Case(
            id=case_id + " require_registered",
            value=value,
            kwargs={"require_registered": True},
            expected=_E.UNREGISTERED,
            position=position,
            cite=cite + "; AU-Q16 refinement 1",
        ),
    )


_PREFIX_NAMES: tuple[Case, ...] = (
    *_prefix(
        "method with registered prefix",
        "example.com; dkimx=pass",
        ar("example.com", res("dkimx", "pass", registered=False)),
        13,
        "dkimx is not dkim",
    ),
    *_prefix(
        "method that is a registered prefix",
        "example.com; dki=pass",
        ar("example.com", res("dki", "pass", registered=False)),
        13,
        "dki is not dkim",
    ),
    *_prefix(
        "method and property with registered prefixes",
        "example.com; dmarc-x=pass header.fromx=a",
        ar(
            "example.com",
            res(
                "dmarc-x",
                "pass",
                prop("header", "fromx", "a", registered=False),
                registered=False,
            ),
        ),
        13,
        "dmarc-x is not dmarc; the result is checked first",
    ),
    *_prefix(
        "property with registered prefix",
        "example.com; dkim=pass header.dd=x",
        ar(
            "example.com",
            res(
                "dkim",
                "pass",
                prop("header", "dd", "x", registered=False),
                registered=True,
            ),
        ),
        23,
        "header.dd is not header.d",
    ),
    *_prefix(
        "dmarc property with registered prefix",
        "example.com; dmarc=pass header.fromx=a",
        ar(
            "example.com",
            res(
                "dmarc",
                "pass",
                prop("header", "fromx", "a", registered=False),
                registered=True,
            ),
        ),
        24,
        "header.fromx is not header.from",
    ),
    *_prefix(
        "spf property with registered prefix",
        "example.com; spf=pass smtp.mailfromx=a",
        ar(
            "example.com",
            res(
                "spf",
                "pass",
                prop("smtp", "mailfromx", "a", registered=False),
                registered=True,
            ),
        ),
        22,
        "smtp.mailfromx is not smtp.mailfrom",
    ),
    *_prefix(
        "ptype with registered prefix",
        "example.com; dkim=pass headerx.d=x",
        ar(
            "example.com",
            res(
                "dkim",
                "pass",
                prop("headerx", "d", "x", registered=False),
                registered=True,
            ),
        ),
        23,
        "headerx is not header",
    ),
    *_prefix(
        "result with registered prefix",
        "example.com; dkim=passx",
        ar("example.com", res("dkim", "passx", registered=False)),
        13,
        "passx is not pass",
    ),
    *_prefix(
        "result that is a registered prefix",
        "example.com; dkim=pas",
        ar("example.com", res("dkim", "pas", registered=False)),
        13,
        "pas is not pass",
    ),
)

_QUOTED_WSP: tuple[Case, ...] = (
    Case(
        id="quoted authserv-id leading space",
        value='" mx.example"; none',
        expected=ar(" mx.example", none=True),
        cite="G6 (the content between the quotes), AU-Q30 (kept exactly)",
    ),
    Case(
        id="quoted authserv-id tab only",
        value='"\t"; none',
        expected=ar("\t", none=True),
        cite="G6 (WSP inside a quoted-string is kept), AU-Q30",
    ),
    Case(
        id="quoted pvalue leading and trailing space",
        value='example.com; dmarc=pass header.from=" bank.example "',
        expected=ar(
            "example.com",
            res(
                "dmarc",
                "pass",
                prop(
                    "header",
                    "from",
                    " bank.example ",
                    raw='" bank.example "',
                    quoted=True,
                    registered=True,
                ),
                registered=True,
            ),
        ),
        cite="G6 (value kept exactly), G10",
    ),
    Case(
        id="quoted reason leading space trailing tab",
        value='example.com; dkim=fail reason=" x\t"',
        expected=ar("example.com", res("dkim", "fail", reason=" x\t", registered=True)),
        cite="G6",
    ),
    Case(
        id="quoted value fold before content",
        value='example.com; dkim=pass header.s="\r\n x"',
        expected=ar(
            "example.com",
            res("dkim", "pass", _dkim_s(" x", '"\r\n x"'), registered=True),
        ),
        cite="G6 (fold line break removed, WSP kept), AU-Q18c (raw kept)",
    ),
)

_SMALL_TRIGGERS: tuple[Case, ...] = (
    Case(
        id="reasonable is a bare property",
        value="example.com; dkim=pass reasonable=x",
        expected=ar(
            "example.com",
            res("dkim", "pass", bare("reasonable", "x"), registered=True),
            deviations=(Deviation.BARE_PROPERTY,),
        ),
        cite="G8 (only the whole keyword reason is a reason), AU-Q27",
    ),
    Case(
        id="reason-code is a bare property",
        value="example.com; dkim=pass reason-code=x",
        expected=ar(
            "example.com",
            res("dkim", "pass", bare("reason-code", "x"), registered=True),
            deviations=(Deviation.BARE_PROPERTY,),
        ),
        cite="G8, G3 (- is a keyword character), AU-Q27",
    ),
    Case(
        id="arc non-ascii digit position",
        call="parse_arc",
        value="i=\u0661; example.org; none",
        kwargs={"ascii_only": False},
        expected=_E.SYNTAX,
        position=2,
        cite="G12, G14 (never UTF-8 in digits), AU-Q32 (no digits is SYNTAX)",
    ),
    Case(
        id="version with plus sign",
        value="example.com +1; none",
        expected=_E.SYNTAX,
        position=12,
        cite="G11 (1*DIGIT, no sign)",
    ),
    Case(
        id="version with underscore",
        value="example.com 1_0; none",
        expected=_E.SYNTAX,
        position=13,
        cite="G11 (1*DIGIT)",
    ),
    Case(
        id="method version with plus sign",
        value="example.com; dkim/+1=pass",
        expected=_E.SYNTAX,
        position=18,
        cite="G11",
    ),
    Case(
        id="method version with underscore",
        value="example.com; dkim/1_0=pass",
        expected=_E.SYNTAX,
        position=19,
        cite="G11",
    ),
    Case(
        id="arc position with plus sign",
        call="parse_arc",
        value="i=+1; example.org; none",
        expected=_E.SYNTAX,
        position=2,
        cite="G12, AU-Q32 (no digits)",
    ),
    Case(
        id="arc position with underscore",
        call="parse_arc",
        value="i=1_0; example.org; none",
        expected=_E.SYNTAX,
        position=3,
        cite="G12, AU-Q32 (like i=1x)",
    ),
    Case(
        id="no-break space is not WSP",
        value="example.com;\u00a0none",
        kwargs={"ascii_only": False},
        expected=_E.CONTROL_CHAR,
        position=12,
        cite="RFC 5234 B.1 via G3 (WSP = SP / HTAB only), G14; AU-Q41 (Zs is "
        "CONTROL_CHAR at its offset: the scan runs before the parse)",
    ),
    Case(
        id="ideographic space is not WSP",
        value="example.com; dkim=pass\u3000header.d=x",
        kwargs={"ascii_only": False},
        expected=_E.CONTROL_CHAR,
        position=22,
        cite="RFC 5234 B.1 via G3, G14; AU-Q41 (Zs is CONTROL_CHAR at its offset)",
    ),
    Case(
        id="line separator is not WSP",
        value="example.com; dkim=\u2028pass",
        kwargs={"ascii_only": False},
        expected=_E.CONTROL_CHAR,
        position=18,
        cite="RFC 5234 B.1 via G3, G14; AU-Q41 (Zl is CONTROL_CHAR at its offset)",
    ),
    Case(
        id="quoted-pair in reason resolved",
        value='example.com; dkim=fail reason="a\\"b\\\\c"',
        expected=ar(
            "example.com", res("dkim", "fail", reason='a"b\\c', registered=True)
        ),
        cite="G6 (quoted-pairs resolved), G8",
    ),
    Case(
        id="duplicate header.from kept at parse time",
        value="example.com; dmarc=pass header.from=a.example header.from=b.example",
        expected=ar(
            "example.com",
            res(
                "dmarc",
                "pass",
                prop("header", "from", "a.example", registered=True),
                prop("header", "from", "b.example", registered=True),
                registered=True,
            ),
        ),
        cite="G9 (repeated properties kept in order); PLAN.md 2.2 "
        "(DUPLICATE_PROPERTY only from get_unique)",
    ),
    Case(
        id="duplicate bare names kept at parse time",
        value="example.com; dmarc=pass action=a action=b",
        expected=ar(
            "example.com",
            res(
                "dmarc",
                "pass",
                bare("action", "a"),
                bare("action", "b"),
                registered=True,
            ),
            deviations=(Deviation.BARE_PROPERTY,),
        ),
        cite="G9, AU-Q27; PLAN.md 2.2",
    ),
    Case(
        id="str subclass lying accessors",
        value=LyingStr("example.com; none"),
        expected=ar("example.com", none=True),
        cite="AL2b row (normalise a str subclass to an exact str first); the "
        "underlying text is parsed, not __str__, __getitem__ or __iter__",
    ),
    Case(
        id="arc str subclass lying accessors",
        call="parse_arc",
        value=LyingStr("i=1; example.org; none"),
        expected=ArcAuthenticationResults(
            instance=1, payload=ar("example.org", none=True)
        ),
        cite="AL2b row",
    ),
)

# AU-Q41: Unicode space separators (Zs other than SP, Zl, Zp) and format
# characters (Cf) are CONTROL_CHAR at their offset in every position, under
# either ascii_only setting (checked before non-ASCII, as AU-Q37). The
# characters are named by code point and category, from Unicode 17.0.0.
_Q41 = "AU-Q41 (Zs other than SP, Zl, Zp and Cf are CONTROL_CHAR at the offset)"

_Q41_CHARS: tuple[tuple[str, str], ...] = (
    ("U+00A0", "\u00a0"),  # Zs NO-BREAK SPACE
    ("U+2000", "\u2000"),  # Zs EN QUAD
    ("U+3000", "\u3000"),  # Zs IDEOGRAPHIC SPACE
    ("U+2028", "\u2028"),  # Zl LINE SEPARATOR
    ("U+2029", "\u2029"),  # Zp PARAGRAPH SEPARATOR
    ("U+202E", "\u202e"),  # Cf RIGHT-TO-LEFT OVERRIDE
    ("U+200B", "\u200b"),  # Cf ZERO WIDTH SPACE
    ("U+200D", "\u200d"),  # Cf ZERO WIDTH JOINER
    ("U+FEFF", "\ufeff"),  # Cf ZERO WIDTH NO-BREAK SPACE (BOM)
    ("U+00AD", "\u00ad"),  # Cf SOFT HYPHEN
    ("U+2066", "\u2066"),  # Cf LEFT-TO-RIGHT ISOLATE
)

# (position name, text before the character, text after it, offset). The
# offset is the length of the text before, written out.
_Q41_SPOTS: tuple[tuple[str, str, str, int], ...] = (
    ("authserv-id", "exa", "mple.com; none", 3),
    ("unquoted value", "example.com; dkim=pass header.s=a", "b", 33),
    ("domain after @", _MF + "a@b", "c.example", 39),
    ("comment", "example.com; none (a", "b)", 20),
    ("quoted-string", 'example.com; dkim=fail reason="a', 'b"', 32),
    ("keyword", "example.com; dk", "im=pass", 15),
)

_AU_Q41_MATRIX: tuple[Case, ...] = tuple(
    Case(
        id=f"au-q41 {code} in {spot}{suffix}",
        value=before + char + after,
        kwargs=kwargs,
        expected=_E.CONTROL_CHAR,
        position=offset,
        cite=_Q41 + note,
    )
    for code, char in _Q41_CHARS
    for spot, before, after, offset in _Q41_SPOTS
    for suffix, kwargs, note in (
        ("", Options(ascii_only=False), ", even with ascii_only=False"),
        (" ascii_only", Options(), ", before NON_ASCII (as AU-Q37)"),
    )
)

_AU_Q41: tuple[Case, ...] = (
    *_AU_Q41_MATRIX,
    Case(
        id="au-q41 bom at start",
        value="\ufeffexample.com; none",
        kwargs={"ascii_only": False},
        expected=_E.CONTROL_CHAR,
        position=0,
        cite=_Q41 + " (a leading BOM is not stripped)",
    ),
    Case(
        id="au-q41 c0 control before format char",
        value="example.com; none (a\x00b\u200b)",
        kwargs={"ascii_only": False},
        expected=_E.CONTROL_CHAR,
        position=20,
        cite=_Q41 + "; AU-Q16 (character scan, leftmost wins)",
    ),
    Case(
        id="au-q41 format char before c0 control",
        value="example.com; none (a\u200bb\x00)",
        kwargs={"ascii_only": False},
        expected=_E.CONTROL_CHAR,
        position=20,
        cite=_Q41 + "; AU-Q16 (character scan, leftmost wins)",
    ),
    Case(
        id="au-q41 nbsp before c0 control",
        value="example.com; none (ab\u00a0\x00)",
        expected=_E.CONTROL_CHAR,
        position=21,
        cite=_Q41 + "; AU-Q16 (character scan, leftmost wins)",
    ),
    Case(
        id="au-q41 c0 control before nbsp",
        value="example.com; none (ab\x00\u00a0)",
        expected=_E.CONTROL_CHAR,
        position=21,
        cite=_Q41 + "; AU-Q16 (character scan, leftmost wins)",
    ),
    Case(
        id="au-q41 non-ascii before format char ascii_only",
        value="example.com; none (\u00fc\u200b)",
        expected=_E.NON_ASCII,
        position=19,
        cite=_Q41 + "; AU-Q16 and AU-Q37 (leftmost wins; the per-character "
        "check order only matters within one character)",
    ),
    Case(
        id="au-q41 format char before non-ascii ascii_only",
        value="example.com; none (\u200b\u00fc)",
        expected=_E.CONTROL_CHAR,
        position=19,
        cite=_Q41 + "; AU-Q16 (character scan, leftmost wins)",
    ),
    Case(
        id="au-q41 non-ascii then format char",
        value="example.com; none (\u00fc\u200b)",
        kwargs={"ascii_only": False},
        expected=_E.CONTROL_CHAR,
        position=20,
        cite=_Q41 + "; G14 (the u-umlaut is allowed in a comment)",
    ),
    Case(
        id="au-q41 format char before syntax",
        value="example.com;; (\u200b)",
        kwargs={"ascii_only": False},
        expected=_E.CONTROL_CHAR,
        position=15,
        cite=_Q41 + "; AU-Q16 (the scan runs before the parse)",
    ),
    Case(
        id="au-q41 format char before unterminated comment",
        value="example.com; none (\u202e",
        kwargs={"ascii_only": False},
        expected=_E.CONTROL_CHAR,
        position=19,
        cite=_Q41 + "; AU-Q16 (the scan runs before the tokeniser pass)",
    ),
    Case(
        id="au-q41 non-ascii letters still accepted",
        value="b\u00fccher.example; dkim=fail reason=caf\u00e9 "
        "header.d=\u4f8b\u5b50.example",
        kwargs={"ascii_only": False},
        expected=ar(
            "b\u00fccher.example",
            res(
                "dkim",
                "fail",
                prop("header", "d", "\u4f8b\u5b50.example", registered=True),
                reason="caf\u00e9",
                registered=True,
            ),
        ),
        cite=_Q41 + " (letters are not Zs, Zl, Zp or Cf); G14, AU-Q18a",
    ),
)

CASES: tuple[Case, ...] = (
    *_COMMENT_SEMICOLONS,
    *_PREFIX_NAMES,
    *_QUOTED_WSP,
    *_SMALL_TRIGGERS,
    *_MISSING_ID,
    *_REJECT,
    *_KEYWORDS,
    *_PAYLOAD,
    *_NONE,
    *_METHOD,
    *_REASON,
    *_CFWS,
    *_FOLDING,
    *_TSPECIALS,
    *_DEVIATIONS,
    *_ADDRESS,
    *_REGISTERED,
    *_NON_ASCII,
    *_PRECEDENCE,
    *_GET_UNIQUE,
    *_TYPES,
    *_AU_Q41,
)
