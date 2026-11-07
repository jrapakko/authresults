# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""The 28 spike cases, named and valued exactly as in the 2026-11-05 spike.

Expectations: PLAN.md 3.1 "Spike cases under 3.1" (the table), with AU-Q14
(deep nesting), AU-Q22 (``header.b``), AU-Q27 (bare ``action``) and AU-Q31
(the ``(method, ptype, property)`` triple decides ``Property.registered``).
"""

from authresults import Deviation, ErrorReason

from ._case import Case, ar, bare, prop, res

_SPIKE = "spike case (2026-11-05); PLAN.md 3.1 spike-case table row "

GOOD = (
    "mx.google.com; dkim=pass header.i=@example.com header.s=s1 header.b=Ab+/cd=; "
    "spf=pass (google.com: domain of a@example.com designates 192.0.2.1 as "
    "permitted sender) "
    "smtp.mailfrom=a@example.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) "
    "header.from=example.com"
)

_DKIM_D = res(
    "dkim", "pass", prop("header", "d", "example.com", registered=True), registered=True
)
_DMARC_FROM = res(
    "dmarc",
    "pass",
    prop("header", "from", "example.com", registered=True),
    registered=True,
)

CASES: tuple[Case, ...] = (
    Case(
        id="google-like good",
        value=GOOD,
        expected=ar(
            "mx.google.com",
            res(
                "dkim",
                "pass",
                prop("header", "i", "@example.com", registered=True),
                prop("header", "s", "s1", registered=True),
                prop("header", "b", "Ab+/cd=", registered=True),
                registered=True,
            ),
            res(
                "spf",
                "pass",
                prop("smtp", "mailfrom", "a@example.com", registered=True),
                registered=True,
            ),
            _DMARC_FROM,
            deviations=(Deviation.PVALUE_TSPECIALS,),
        ),
        cite=_SPIKE + "1; G10 (address form, PVALUE_TSPECIALS), AU-Q22, AU-Q23",
    ),
    Case(
        id="header.d form",
        value=(
            "mx.google.com; dkim=pass header.d=example.com; "
            "dmarc=pass header.from=example.com"
        ),
        expected=ar("mx.google.com", _DKIM_D, _DMARC_FROM),
        cite=_SPIKE + "2",
    ),
    Case(
        id="upper case",
        value=(
            "MX.Google.COM; DKIM=PASS header.d=EXAMPLE.com; "
            "DMARC=Pass Header.From=Example.COM"
        ),
        expected=ar(
            "MX.Google.COM",
            res(
                "dkim",
                "pass",
                prop("header", "d", "EXAMPLE.com", registered=True),
                registered=True,
            ),
            res(
                "dmarc",
                "pass",
                prop("header", "from", "Example.COM", registered=True),
                registered=True,
            ),
        ),
        cite=_SPIKE + "3; 2.5 (keywords lowercased, values kept), AU-Q34",
    ),
    Case(
        id="version 1",
        value=(
            "mx.google.com 1; dkim=pass header.d=example.com; "
            "dmarc=pass header.from=example.com"
        ),
        expected=ar("mx.google.com", _DKIM_D, _DMARC_FROM, version_given=True),
        cite=_SPIKE + "4; G11",
    ),
    Case(
        id="version 2",
        value="mx.google.com 2; dmarc=pass header.from=example.com",
        expected=ErrorReason.UNSUPPORTED_VERSION,
        position=14,
        cite=_SPIKE + "5; G11 (UNSUPPORTED_VERSION at the first digit)",
    ),
    Case(
        id="pass in comment",
        value="mx.google.com; dkim=fail (dmarc=pass) header.d=example.com",
        expected=ar(
            "mx.google.com",
            res(
                "dkim",
                "fail",
                prop("header", "d", "example.com", registered=True),
                registered=True,
            ),
        ),
        cite=_SPIKE + "6; G4 (comment content is never data)",
    ),
    Case(
        id="nested comment",
        value="mx.google.com; dkim=fail (a (dmarc=pass) b) header.d=example.com",
        expected=ar(
            "mx.google.com",
            res(
                "dkim",
                "fail",
                prop("header", "d", "example.com", registered=True),
                registered=True,
            ),
        ),
        cite=_SPIKE + "7; G4",
    ),
    Case(
        id="arc comment carrying dmarc=pass",
        value=(
            "mx.google.com; arc=pass (i=1 spf=pass dkim=pass dkdomain=example.com "
            "dmarc=pass fromdomain=example.com)"
        ),
        expected=ar("mx.google.com", res("arc", "pass", registered=True)),
        cite=_SPIKE + "8; G4",
    ),
    Case(
        id="x-dmarc",
        value=(
            "mx.google.com; dkim=pass header.d=example.com; "
            "x-dmarc=pass header.from=example.com"
        ),
        expected=ar(
            "mx.google.com",
            _DKIM_D,
            res(
                "x-dmarc",
                "pass",
                prop("header", "from", "example.com", registered=False),
                registered=False,
            ),
        ),
        cite=_SPIKE + "9; AU-Q31 answered: the (method, ptype, property) triple",
    ),
    Case(
        id="dmarc=passed",
        value=(
            "mx.google.com; dkim=pass header.d=example.com; "
            "dmarc=passed header.from=example.com"
        ),
        expected=ar(
            "mx.google.com",
            _DKIM_D,
            res(
                "dmarc",
                "passed",
                prop("header", "from", "example.com", registered=True),
                registered=False,
            ),
        ),
        cite=_SPIKE + "10; G16 (results per method; the property triple exists)",
    ),
    Case(
        id="pass in quoted string",
        value=(
            "mx.google.com; dkim=pass header.d=example.com; "
            'dmarc=fail header.from="x; dmarc=pass"'
        ),
        expected=ar(
            "mx.google.com",
            _DKIM_D,
            res(
                "dmarc",
                "fail",
                prop(
                    "header",
                    "from",
                    "x; dmarc=pass",
                    raw='"x; dmarc=pass"',
                    quoted=True,
                    registered=True,
                ),
                registered=True,
            ),
        ),
        cite=_SPIKE + "11; G6, G10 (quoted-string pvalue)",
    ),
    Case(
        id="quoted value with ; and =",
        value=(
            'mx.google.com; dkim=pass header.d=example.com header.s="a;b=c"; '
            "dmarc=pass header.from=example.com"
        ),
        expected=ar(
            "mx.google.com",
            res(
                "dkim",
                "pass",
                prop("header", "d", "example.com", registered=True),
                prop(
                    "header", "s", "a;b=c", raw='"a;b=c"', quoted=True, registered=True
                ),
                registered=True,
            ),
            _DMARC_FROM,
        ),
        cite=_SPIKE + "12; G6",
    ),
    Case(
        id="untrusted id",
        value=(
            "evil.example; dkim=pass header.d=example.com; "
            "dmarc=pass header.from=example.com"
        ),
        expected=ar("evil.example", _DKIM_D, _DMARC_FROM),
        cite=_SPIKE + "13",
    ),
    Case(
        id="from in other result",
        value=(
            "mx.google.com; dkim=pass header.d=example.com "
            "header.from=example.com; dmarc=pass"
        ),
        expected=ar(
            "mx.google.com",
            res(
                "dkim",
                "pass",
                prop("header", "d", "example.com", registered=True),
                prop("header", "from", "example.com", registered=False),
                registered=True,
            ),
            res("dmarc", "pass", registered=True),
        ),
        cite=_SPIKE + "14; AU-Q31 answered: (dkim, header, from) is not registered",
    ),
    Case(
        id="lookalike from",
        value=(
            "mx.google.com; dkim=pass header.d=example.com; "
            "dmarc=pass header.from=examp1e.com"
        ),
        expected=ar(
            "mx.google.com",
            _DKIM_D,
            res(
                "dmarc",
                "pass",
                prop("header", "from", "examp1e.com", registered=True),
                registered=True,
            ),
        ),
        cite=_SPIKE + "15",
    ),
    Case(
        id="idna a-label",
        value=(
            "mx.google.com; dkim=pass header.d=xn--bcher-kva.example; "
            "dmarc=pass header.from=xn--bcher-kva.example"
        ),
        expected=ar(
            "mx.google.com",
            res(
                "dkim",
                "pass",
                prop("header", "d", "xn--bcher-kva.example", registered=True),
                registered=True,
            ),
            res(
                "dmarc",
                "pass",
                prop("header", "from", "xn--bcher-kva.example", registered=True),
                registered=True,
            ),
        ),
        cite=_SPIKE + "16; 2.5 (values as given, no IDNA)",
    ),
    Case(
        id="idna u-label",
        value="mx.google.com; dmarc=pass header.from=b\u00fccher.example",
        expected=ErrorReason.NON_ASCII,
        position=39,
        cite=_SPIKE + "17; G14 (ascii_only=True default: NON_ASCII at the character)",
    ),
    Case(
        id="none",
        value="mx.google.com; none",
        expected=ar("mx.google.com", none=True),
        cite=_SPIKE + "18; G7",
    ),
    Case(
        id="nonexistent prefix",
        value="mx.google.com; nonexistent=pass",
        expected=ar("mx.google.com", res("nonexistent", "pass", registered=False)),
        cite=_SPIKE + "19; G7 (the keyword must match as a whole token)",
    ),
    Case(
        id="reason=",
        value=(
            'mx.google.com; dmarc=pass reason="looks ok; trust me" '
            "header.from=example.com; dkim=pass header.d=example.com"
        ),
        expected=ar(
            "mx.google.com",
            res(
                "dmarc",
                "pass",
                prop("header", "from", "example.com", registered=True),
                reason="looks ok; trust me",
                registered=True,
            ),
            _DKIM_D,
        ),
        cite=_SPIKE + "20; G8",
    ),
    Case(
        id="policy.*",
        value=(
            "mx.google.com; dkim=pass header.d=example.com; "
            "dmarc=pass policy.dmarc=reject header.from=example.com"
        ),
        expected=ar(
            "mx.google.com",
            _DKIM_D,
            res(
                "dmarc",
                "pass",
                prop("policy", "dmarc", "reject", registered=True),
                prop("header", "from", "example.com", registered=True),
                registered=True,
            ),
        ),
        cite=_SPIKE + "21; G16 (dmarc: header.from, policy.dmarc)",
    ),
    Case(
        id="unknown ptype (microsoft style)",
        value=(
            "spf.protection.outlook.com; dmarc=pass action=none header.from=example.com"
        ),
        expected=ar(
            "spf.protection.outlook.com",
            res(
                "dmarc",
                "pass",
                bare("action", "none"),
                prop("header", "from", "example.com", registered=True),
                registered=True,
            ),
            deviations=(Deviation.BARE_PROPERTY,),
        ),
        cite=_SPIKE + "22; G9, AU-Q27",
    ),
    Case(
        id="empty",
        value="",
        expected=ErrorReason.EMPTY,
        position=None,
        cite=_SPIKE + "23; AU-Q16 (EMPTY has no position)",
    ),
    Case(
        id="only id",
        value="mx.google.com",
        expected=ErrorReason.SYNTAX,
        position=13,
        cite=_SPIKE + "24; G1 (SYNTAX at len(value))",
    ),
    Case(
        id="garbled",
        value="\x00\xff;;==((",
        expected=ErrorReason.CONTROL_CHAR,
        position=0,
        cite=_SPIKE + "25; AU-Q16 (character scan, leftmost wins)",
    ),
    Case(
        id="unclosed comment",
        value="mx.google.com; dmarc=pass (oops header.from=example.com",
        expected=ErrorReason.UNTERMINATED_COMMENT,
        position=26,
        cite=_SPIKE + "26; G4 (at the outermost unclosed paren)",
    ),
    Case(
        id="deep nesting",
        value="mx.google.com; dmarc=pass " + "(" * 5000 + ")" * 5000,
        expected=ErrorReason.TOO_LONG,
        position=8192,
        cite=_SPIKE + "27; AU-Q14 (length is checked first; TOO_LONG at max_length)",
    ),
    Case(
        id="deep nesting (within cap)",
        value="mx.google.com; dmarc=pass " + "(" * 4000 + ")" * 4000,
        expected=ErrorReason.NESTING_TOO_DEEP,
        position=42,
        cite=_SPIKE + "27, within-cap variant; AU-Q14 (the 17th paren, offset 42)",
    ),
    Case(
        id="folded",
        value=(
            "mx.google.com;\r\n dkim=pass header.d=example.com;\r\n"
            "\tdmarc=pass header.from=example.com"
        ),
        expected=ar("mx.google.com", _DKIM_D, _DMARC_FROM),
        cite=_SPIKE + "28; G5 (CRLF SP and CRLF HTAB, no deviation)",
    ),
)
