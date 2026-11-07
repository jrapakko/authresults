# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""``to_value()``: only the forms AU-Q17 pins (and AU-Q15a, AU-Q33b).

The canonical form: the authserv-id, `` <version>`` only if
``version_given``, then ``; none`` or ``; method[/v]=result[ reason=V]
[ ptype.name=V]...`` on one line with single spaces, no comments and no
folding. ``V`` is bare if it is a token (the parser's token class) or an
address form, otherwise quoted with a backslash before ``"`` and ``\\``.
Errors have ``position=None``.
"""

from authresults import (
    AuthenticationResults,
    Deviation,
    ErrorReason,
    Property,
    Result,
)

from ._case import Case, Options, ar, bare, prop, res

_Q17 = "AU-Q17 (canonical form)"
_Q33 = "AU-Q33b (SYNTAX with position=None for a model that cannot be written)"


def _one(result: Result) -> AuthenticationResults:
    return ar("example.com", result)


def _ok(case_id: str, model: AuthenticationResults, text: str, note: str) -> Case:
    return Case(
        id=f"to_value {case_id}",
        call="to_value",
        value=model,
        expected=text,
        cite=_Q17 + note,
    )


def _bad(
    case_id: str,
    model: AuthenticationResults,
    reason: ErrorReason,
    note: str,
    *,
    ascii_only: bool = True,
) -> Case:
    return Case(
        id=f"to_value {case_id}",
        call="to_value",
        value=model,
        kwargs=Options() if ascii_only else Options(ascii_only=False),
        expected=reason,
        position=None,
        cite=note,
    )


_HD = prop("header", "d", "example.com", registered=True)


def _from(case_id: str, value: str, text: str, note: str) -> Case:
    """dmarc=fail with header.from=value, serialised."""
    return _ok(
        case_id,
        _one(
            res(
                "dmarc",
                "fail",
                prop("header", "from", value, registered=True),
                registered=True,
            )
        ),
        "example.com; dmarc=fail header.from=" + text,
        note,
    )


def _id(case_id: str, authserv_id: str, text: str) -> Case:
    return _ok(
        case_id,
        ar(authserv_id, none=True),
        text + "; none",
        "; AU-Q38 rule 4 (the authserv-id follows the V rule)",
    )


_NOT_ADDRESS = (
    " (contains @ but is not [local-part]@domain-name, so it is quoted; "
    "AL3a red-team F1)"
)

_AT_VALUES: tuple[Case, ...] = (
    _from(
        "at value injection",
        "x; dmarc=pass header.from=a@bank.example",
        '"x; dmarc=pass header.from=a@bank.example"',
        _NOT_ADDRESS,
    ),
    _from(
        "at value space in local-part",
        "a b@example.com",
        '"a b@example.com"',
        _NOT_ADDRESS,
    ),
    _from("at value space in domain", "a@b c.example", '"a@b c.example"', _NOT_ADDRESS),
    _from(
        "at value quoted word then atext",
        '"a"x@example.com',
        '"\\"a\\"x@example.com"',
        _NOT_ADDRESS + " (obs-local-part, AU-Q18b)",
    ),
    _from(
        "at value single-label domain",
        "a@localhost",
        '"a@localhost"',
        _NOT_ADDRESS + " (AU-Q24: two or more labels)",
    ),
    _from("at value trailing dot", "a@x.example.", '"a@x.example."', _NOT_ADDRESS),
    _from(
        "at value address-literal",
        "a@[192.0.2.1]",
        '"a@[192.0.2.1]"',
        _NOT_ADDRESS + " (AU-Q24)",
    ),
    _from("at value empty domain", "a@", '"a@"', _NOT_ADDRESS),
    _from("at value lone at", "@", '"@"', _NOT_ADDRESS),
    _from(
        "at value two at signs", "a@b@example.com", '"a@b@example.com"', _NOT_ADDRESS
    ),
    _from(
        "at value double dot", "a..b@example.com", '"a..b@example.com"', _NOT_ADDRESS
    ),
    _from("at value semicolon", "a;b@example.com", '"a;b@example.com"', _NOT_ADDRESS),
    _from("at value parens", "a(b)@example.com", '"a(b)@example.com"', _NOT_ADDRESS),
    _from(
        "at value underscore in domain",
        "a@x_y.example",
        '"a@x_y.example"',
        _NOT_ADDRESS,
    ),
    _from(
        "at value label starts with -", "a@-x.example", '"a@-x.example"', _NOT_ADDRESS
    ),
    _from(
        "at value trailing semicolon",
        "a@example.com;",
        '"a@example.com;"',
        _NOT_ADDRESS,
    ),
    _from(
        "at value quoted then injection",
        '"x"; dmarc=pass header.from="y"@bank.example',
        '"\\"x\\"; dmarc=pass header.from=\\"y\\"@bank.example"',
        _NOT_ADDRESS + " (AL3a red-team N3)",
    ),
    _from(
        "at value escaped closing quote",
        '"a\\"@example.com',
        '"\\"a\\\\\\"@example.com"',
        _NOT_ADDRESS + " (the closing quote is escaped: no quoted-string ends)",
    ),
    _from(
        "at value two quoted words",
        '"a" "b"@example.com',
        '"\\"a\\" \\"b\\"@example.com"',
        _NOT_ADDRESS + " (obs-local-part with CFWS, AU-Q18b)",
    ),
    _from(
        "at value unterminated opening quote",
        '"a@example.com',
        '"\\"a@example.com"',
        _NOT_ADDRESS,
    ),
    _from(
        "at value quote inside atom",
        'a"b"@example.com',
        '"a\\"b\\"@example.com"',
        _NOT_ADDRESS,
    ),
    _from(
        "at value quoted domain label",
        '"a"@x"y".example',
        '"\\"a\\"@x\\"y\\".example"',
        _NOT_ADDRESS + " (domain-name labels are LDH only)",
    ),
    _from(
        "at value trailing word",
        "a@example.com b",
        '"a@example.com b"',
        _NOT_ADDRESS,
    ),
)

_IDS: tuple[Case, ...] = (
    _id("authserv-id with ;", "x;dmarc=pass", '"x;dmarc=pass"'),
    _id("authserv-id with =", "a=b", '"a=b"'),
    _id("authserv-id with /", "a/b", '"a/b"'),
    _id("authserv-id with @", "a@b", '"a@b"'),
    _id("authserv-id with paren", "a(b", '"a(b"'),
    _id("authserv-id with backslash", "a\\b", '"a\\\\b"'),
    _id("authserv-id leading space", " mx.example", '" mx.example"'),
    _id("authserv-id token bare", "mx.example", "mx.example"),
)

_Q41 = (
    "AU-Q41 (to_value refuses Zs other than SP, Zl, Zp and Cf in any written "
    "field: CONTROL_CHAR, position=None"
)


def _q41(field_name: str, model: AuthenticationResults) -> tuple[Case, ...]:
    """The same model under both ascii_only settings."""
    return (
        _bad(
            f"au-q41 {field_name} non-ascii mode",
            model,
            ErrorReason.CONTROL_CHAR,
            _Q41 + ", even with ascii_only=False)",
            ascii_only=False,
        ),
        _bad(
            f"au-q41 {field_name} ascii_only",
            model,
            ErrorReason.CONTROL_CHAR,
            _Q41 + ", before NON_ASCII as AU-Q37)",
        ),
    )


_AU_Q41: tuple[Case, ...] = (
    *_q41("zero width space in authserv-id", ar("exa\u200bmple.com", none=True)),
    *_q41(
        "no-break space in reason",
        _one(res("dkim", "fail", reason="a\u00a0b", registered=True)),
    ),
    *_q41(
        "bidi override in property value",
        _one(
            res(
                "dkim",
                "pass",
                prop("header", "s", "a\u202eb", registered=True),
                registered=True,
            )
        ),
    ),
    Case(
        id="to_value au-q41 non-ascii letters still written",
        call="to_value",
        value=ar(
            "b\u00fccher.example",
            res(
                "dkim",
                "fail",
                prop("header", "d", "\u4f8b\u5b50.example", registered=True),
                reason="caf\u00e9",
                registered=True,
            ),
        ),
        kwargs={"ascii_only": False},
        expected="b\u00fccher.example; dkim=fail reason=caf\u00e9 "
        "header.d=\u4f8b\u5b50.example",
        cite=_Q17 + "; AU-Q41 (letters are not Zs, Zl, Zp or Cf); AL3a-R "
        "refinement 1 (the token class includes UTF-8 under ascii_only=False)",
    ),
)

CASES: tuple[Case, ...] = (
    *_AT_VALUES,
    _ok(
        "empty property value quoted",
        _one(
            res(
                "dmarc",
                "pass",
                prop("policy", "dmarc", "", registered=True),
                registered=True,
            )
        ),
        'example.com; dmarc=pass policy.dmarc=""',
        " (an empty value is not a token; AL3a red-team N6)",
    ),
    _ok(
        "htab in reason quoted",
        _one(res("dkim", "fail", reason="a\tb", registered=True)),
        'example.com; dkim=fail reason="a\tb"',
        "; AU-Q40 (HTAB is WSP: quoted, the tab written as is)",
    ),
    _ok(
        "htab in property value quoted",
        _one(
            res(
                "dkim",
                "pass",
                prop("header", "s", "a\tb", registered=True),
                registered=True,
            )
        ),
        'example.com; dkim=pass header.s="a\tb"',
        "; AU-Q40",
    ),
    _ok(
        "htab only reason quoted",
        _one(res("dkim", "fail", reason="\t", registered=True)),
        'example.com; dkim=fail reason="\t"',
        "; AU-Q40",
    ),
    _bad(
        "vertical tab in reason",
        _one(res("dkim", "fail", reason="a\x0bb", registered=True)),
        ErrorReason.CONTROL_CHAR,
        "AU-Q40 (every control other than HTAB stays CONTROL_CHAR), AU-Q15a",
    ),
    _bad(
        "cr in property value",
        _one(
            res(
                "dkim",
                "pass",
                prop("header", "s", "a\rb", registered=True),
                registered=True,
            )
        ),
        ErrorReason.CONTROL_CHAR,
        "AU-Q40, AU-Q15a",
    ),
    *_IDS,
    _bad(
        "c1 control non-ascii mode",
        _one(res("dkim", "fail", reason="a\x85b", registered=True)),
        ErrorReason.CONTROL_CHAR,
        "AU-Q15a, AU-Q37 (a C1 control is CONTROL_CHAR regardless of ascii_only)",
        ascii_only=False,
    ),
    _bad(
        "lone surrogate non-ascii mode",
        _one(
            res(
                "dkim",
                "pass",
                prop("header", "s", "a\udcffb", registered=True),
                registered=True,
            )
        ),
        ErrorReason.CONTROL_CHAR,
        "AU-Q15a, AU-Q37 (a lone surrogate is CONTROL_CHAR)",
        ascii_only=False,
    ),
    _bad(
        "c1 control in authserv-id non-ascii mode",
        ar("x\x85", none=True),
        ErrorReason.CONTROL_CHAR,
        "AU-Q15a, AU-Q37",
        ascii_only=False,
    ),
    _bad(
        "c1 control ascii_only",
        _one(res("dkim", "fail", reason="a\x85b", registered=True)),
        ErrorReason.CONTROL_CHAR,
        "AU-Q37 consequence (CONTROL_CHAR regardless of ascii_only, not NON_ASCII)",
    ),
    _bad(
        "lone surrogate ascii_only",
        _one(
            res(
                "dkim",
                "pass",
                prop("header", "s", "a\udcffb", registered=True),
                registered=True,
            )
        ),
        ErrorReason.CONTROL_CHAR,
        "AU-Q37 consequence (CONTROL_CHAR regardless of ascii_only, not NON_ASCII)",
    ),
    _bad(
        "c1 control in authserv-id ascii_only",
        ar("x\x85", none=True),
        ErrorReason.CONTROL_CHAR,
        "AU-Q37 consequence (CONTROL_CHAR regardless of ascii_only, not NON_ASCII)",
    ),
    _bad(
        "bare property named reason",
        _one(res("dmarc", "pass", bare("reason", "x"), registered=True)),
        ErrorReason.SYNTAX,
        "AU-Q26 consequence (coordinator, 2026-11-06): reason is never a bare "
        "property, so to_value refuses one (position=None)",
    ),
    _ok("none", ar("example.com", none=True), "example.com; none", ""),
    _ok(
        "version given",
        ar("example.com", none=True, version_given=True),
        "example.com 1; none",
        " (version only if version_given)",
    ),
    _ok(
        "result",
        _one(res("dkim", "pass", registered=True)),
        "example.com; dkim=pass",
        "",
    ),
    _ok(
        "method version",
        _one(res("dkim", "pass", version=1, registered=True)),
        "example.com; dkim/1=pass",
        "",
    ),
    _ok(
        "reason token",
        _one(res("dkim", "fail", reason="bad", registered=True)),
        "example.com; dkim=fail reason=bad",
        "",
    ),
    _ok(
        "reason quoted",
        _one(res("dkim", "fail", reason="bad sig", registered=True)),
        'example.com; dkim=fail reason="bad sig"',
        " (not a token: quoted)",
    ),
    _ok(
        "reason escapes",
        _one(res("dkim", "fail", reason='a"b\\c', registered=True)),
        'example.com; dkim=fail reason="a\\"b\\\\c"',
        " (backslash before quote and backslash)",
    ),
    _ok(
        "reason empty",
        _one(res("dkim", "fail", reason="", registered=True)),
        'example.com; dkim=fail reason=""',
        " (an empty string is not a token)",
    ),
    _ok(
        "reason with @ quoted",
        _one(res("dkim", "fail", reason="a@example.com", registered=True)),
        'example.com; dkim=fail reason="a@example.com"',
        "; AL3a-R refinement 1 (a reason is never written in address form)",
    ),
    _ok(
        "property token",
        _one(res("dkim", "pass", _HD, registered=True)),
        "example.com; dkim=pass header.d=example.com",
        "",
    ),
    _ok(
        "property address form",
        _one(
            res(
                "dkim",
                "pass",
                prop("header", "i", "@example.com", registered=True),
                registered=True,
            )
        ),
        "example.com; dkim=pass header.i=@example.com",
        "; AL3a-R refinement 2 (address form written as is)",
    ),
    _ok(
        "property quoted address form",
        _one(
            res(
                "spf",
                "pass",
                prop("smtp", "mailfrom", '"a b"@example.com', registered=True),
                registered=True,
            )
        ),
        'example.com; spf=pass smtp.mailfrom="a b"@example.com',
        "; AL3a-R refinement 2, AU-Q23",
    ),
    _ok(
        "property needs quotes",
        _one(
            res(
                "dmarc",
                "fail",
                prop(
                    "header",
                    "from",
                    "x; dmarc=pass",
                    raw="x",
                    quoted=True,
                    registered=True,
                ),
                registered=True,
            )
        ),
        'example.com; dmarc=fail header.from="x; dmarc=pass"',
        " (raw is not used)",
    ),
    _ok(
        "property tspecials quoted",
        AuthenticationResults(
            authserv_id="example.com",
            version=1,
            version_given=False,
            none=False,
            results=(
                res(
                    "dkim",
                    "pass",
                    prop("header", "b", "Ab+/cd=", registered=True),
                    registered=True,
                ),
            ),
            deviations=frozenset({Deviation.PVALUE_TSPECIALS}),
        ),
        'example.com; dkim=pass header.b="Ab+/cd="',
        " (not a token and not an address form; deviations are not written)",
    ),
    _ok(
        "quoted flag ignored for a token",
        _one(
            res(
                "dkim",
                "pass",
                prop("header", "s", "abc", raw='"abc"', quoted=True, registered=True),
                registered=True,
            )
        ),
        "example.com; dkim=pass header.s=abc",
        " (V is bare if it is a token)",
    ),
    _ok(
        "bare property",
        _one(res("dmarc", "pass", bare("action", "none"), registered=True)),
        "example.com; dmarc=pass action=none",
        " (a bare property comes out as name=value)",
    ),
    _ok(
        "reason before properties",
        _one(
            res(
                "dkim",
                "pass",
                _HD,
                prop("header", "s", "s1", registered=True),
                reason="ok",
                registered=True,
            )
        ),
        "example.com; dkim=pass reason=ok header.d=example.com header.s=s1",
        "",
    ),
    _ok(
        "several results",
        ar(
            "example.com",
            res("dkim", "pass", _HD, registered=True),
            res(
                "spf",
                "fail",
                prop("smtp", "mailfrom", "example.net", registered=True),
                registered=True,
            ),
        ),
        "example.com; dkim=pass header.d=example.com; "
        "spf=fail smtp.mailfrom=example.net",
        "",
    ),
    _ok(
        "unregistered kept",
        _one(res("x-dmarc", "passed", registered=False)),
        "example.com; x-dmarc=passed",
        " (registered flags are not written)",
    ),
    Case(
        id="to_value utf-8 non-ascii mode",
        call="to_value",
        value=_one(
            res(
                "dmarc",
                "pass",
                prop("header", "from", "b\u00fccher.example", registered=True),
                registered=True,
            )
        ),
        kwargs={"ascii_only": False},
        expected="example.com; dmarc=pass header.from=b\u00fccher.example",
        cite=_Q17 + "; AL3a-R refinement 1 (the token class includes UTF-8 "
        "under ascii_only=False)",
    ),
    _ok(
        "authserv-id with space quoted",
        ar("mx example", none=True),
        '"mx example"; none',
        "; AU-Q38 rule 4 (the authserv-id follows the V rule)",
    ),
    _ok(
        "authserv-id empty quoted",
        ar("", none=True),
        '""; none',
        "; AU-Q38 rule 4",
    ),
    _ok(
        "authserv-id escapes",
        ar('a"b', none=True),
        '"a\\"b"; none',
        "; AU-Q38 rule 4 (backslash before the quote)",
    ),
    _bad(
        "missing authserv-id",
        ar(None, res("dkim", "pass", registered=True)),
        ErrorReason.SYNTAX,
        "AU-Q35 (to_value on authserv_id=None raises SYNTAX, position=None)",
    ),
    _bad(
        "utf-8 ascii_only",
        _one(
            res(
                "dmarc",
                "pass",
                prop("header", "from", "b\u00fccher.example", registered=True),
                registered=True,
            )
        ),
        ErrorReason.NON_ASCII,
        "AU-Q15a (NON_ASCII, position=None)",
    ),
    _bad(
        "crlf in value",
        _one(res("dkim", "fail", reason="a\r\nX-Injected: 1", registered=True)),
        ErrorReason.CONTROL_CHAR,
        "PLAN.md 1 and AU-Q15a (CR and LF refused: no header injection)",
    ),
    _bad(
        "nul in property",
        _one(
            res(
                "dkim",
                "pass",
                prop("header", "s", "a\x00b", registered=True),
                registered=True,
            )
        ),
        ErrorReason.CONTROL_CHAR,
        "AU-Q15a",
    ),
    _bad(
        "lf in authserv-id",
        AuthenticationResults(
            authserv_id="example.com\nX: y",
            version=1,
            version_given=False,
            none=True,
            results=(),
            deviations=frozenset(),
        ),
        ErrorReason.CONTROL_CHAR,
        "AU-Q15a",
    ),
    _bad(
        "method not lowercase",
        _one(res("DKIM", "pass", registered=True)),
        ErrorReason.SYNTAX,
        _Q33 + " (a keyword field that is not lowercase Ldh-str)",
    ),
    _bad(
        "method with _",
        _one(res("dk_im", "pass", registered=True)),
        ErrorReason.SYNTAX,
        _Q33,
    ),
    _bad(
        "result with space",
        _one(res("dkim", "pa ss", registered=True)),
        ErrorReason.SYNTAX,
        _Q33,
    ),
    _bad(
        "ptype not lowercase",
        _one(
            res(
                "dkim",
                "pass",
                prop("Header", "d", "x", registered=True),
                registered=True,
            )
        ),
        ErrorReason.SYNTAX,
        _Q33,
    ),
    _bad(
        "none with results",
        AuthenticationResults(
            authserv_id="example.com",
            version=1,
            version_given=False,
            none=True,
            results=(res("dkim", "pass", registered=True),),
            deviations=frozenset(),
        ),
        ErrorReason.SYNTAX,
        _Q33 + " (none=True with results)",
    ),
    _bad(
        "version 2",
        AuthenticationResults(
            authserv_id="example.com",
            version=2,
            version_given=True,
            none=True,
            results=(),
            deviations=frozenset(),
        ),
        ErrorReason.SYNTAX,
        _Q33 + " (version != 1)",
    ),
    _bad(
        "negative method version",
        _one(res("dkim", "pass", version=-1, registered=False)),
        ErrorReason.SYNTAX,
        _Q33,
    ),
    _bad(
        "method version 10 digits",
        _one(res("dkim", "pass", version=1234567890, registered=False)),
        ErrorReason.SYNTAX,
        _Q33 + " (longer than 9 digits)",
    ),
    _bad(
        "bare name not a keyword",
        _one(
            res(
                "dmarc",
                "pass",
                Property(
                    ptype=None,
                    name="a b",
                    value="x",
                    raw="x",
                    quoted=False,
                    registered=False,
                ),
                registered=True,
            )
        ),
        ErrorReason.SYNTAX,
        _Q33 + " (ptype=None with a name that is not a keyword)",
    ),
    *_AU_Q41,
)
