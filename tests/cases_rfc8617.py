# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""``ARC-Authentication-Results`` cases (RFC 8617; PLAN.md 3.1 G12, AU-Q32).

The Appendix B values are the field bodies after the field name and the
space after the colon, with the printed lines joined by CRLF. Source:
https://www.rfc-editor.org/rfc/rfc8617.txt (read 2026-11-06).
"""

from authresults import ArcAuthenticationResults, ErrorReason

from ._case import Case, ar, prop, res

_HOW = "; leading SP after the colon dropped, printed lines joined by CRLF"
_APPX = "IETF RFC 8617, Appendix B (unmodified excerpt)" + _HOW
_G12 = "PLAN.md 3.1 G12 and AU-Q32"

_I3_PAYLOAD = (
    "clochette.example.org; spf=fail\r\n"
    "    smtp.from=jqd@d1.example; dkim=fail (512-bit key)\r\n"
    "    header.i=@d1.example; dmarc=fail; arc=pass (as.2.gmail.example=pass,\r\n"
    "    ams.2.gmail.example=pass, as.1.lists.example.org=pass,\r\n"
    "    ams.1.lists.example.org=fail (message has been altered))"
)

_SIMPLE = "example.org; spf=pass smtp.mailfrom=example.net"
_SIMPLE_MODEL = ar(
    "example.org",
    res(
        "spf",
        "pass",
        prop("smtp", "mailfrom", "example.net", registered=True),
        registered=True,
    ),
)


def _arc(instance: int) -> ArcAuthenticationResults:
    return ArcAuthenticationResults(instance=instance, payload=_SIMPLE_MODEL)


CASES: tuple[Case, ...] = (
    Case(
        id="rfc8617 B AAR i=3",
        call="parse_arc",
        value="i=3; " + _I3_PAYLOAD,
        expected=ArcAuthenticationResults(
            instance=3,
            payload=ar(
                "clochette.example.org",
                res(
                    "spf",
                    "fail",
                    prop("smtp", "from", "jqd@d1.example", registered=False),
                    registered=True,
                ),
                res(
                    "dkim",
                    "fail",
                    prop("header", "i", "@d1.example", registered=True),
                    registered=True,
                ),
                res("dmarc", "fail", registered=True),
                res("arc", "pass", registered=True),
            ),
        ),
        cite=_APPX + "; smtp.from is not registered for spf (G16)",
    ),
    Case(
        id="rfc8617 B A-R",
        value=_I3_PAYLOAD,
        expected=ar(
            "clochette.example.org",
            res(
                "spf",
                "fail",
                prop("smtp", "from", "jqd@d1.example", registered=False),
                registered=True,
            ),
            res(
                "dkim",
                "fail",
                prop("header", "i", "@d1.example", registered=True),
                registered=True,
            ),
            res("dmarc", "fail", registered=True),
            res("arc", "pass", registered=True),
        ),
        cite="IETF RFC 8617, Appendix B, the Authentication-Results field "
        "(unmodified excerpt)" + _HOW,
    ),
    Case(
        id="rfc8617 B AAR i=2",
        call="parse_arc",
        value=(
            "i=2; gmail.example; spf=fail\r\n"
            "    smtp.from=jqd@d1.example; dkim=fail (512-bit key)\r\n"
            "    header.i=@example.org; dmarc=fail; arc=pass\r\n"
            "    (as.1.lists.example.org=pass, ams.1.lists.example.org=pass)"
        ),
        expected=ArcAuthenticationResults(
            instance=2,
            payload=ar(
                "gmail.example",
                res(
                    "spf",
                    "fail",
                    prop("smtp", "from", "jqd@d1.example", registered=False),
                    registered=True,
                ),
                res(
                    "dkim",
                    "fail",
                    prop("header", "i", "@example.org", registered=True),
                    registered=True,
                ),
                res("dmarc", "fail", registered=True),
                res("arc", "pass", registered=True),
            ),
        ),
        cite=_APPX,
    ),
    Case(
        id="rfc8617 B AAR i=1",
        call="parse_arc",
        value=(
            "i=1; lists.example.org; spf=pass\r\n"
            "    smtp.mfrom=jqd@d1.example; dkim=pass (512-bit key)\r\n"
            "    header.i=@d1.example; dmarc=pass"
        ),
        expected=ArcAuthenticationResults(
            instance=1,
            payload=ar(
                "lists.example.org",
                res(
                    "spf",
                    "pass",
                    prop("smtp", "mfrom", "jqd@d1.example", registered=False),
                    registered=True,
                ),
                res(
                    "dkim",
                    "pass",
                    prop("header", "i", "@d1.example", registered=True),
                    registered=True,
                ),
                res("dmarc", "pass", registered=True),
            ),
        ),
        cite=_APPX + "; smtp.mfrom is not registered for spf (G16)",
    ),
    Case(
        id="arc i=0",
        call="parse_arc",
        value="i=0; " + _SIMPLE,
        expected=ErrorReason.BAD_ARC_INSTANCE,
        position=2,
        cite=_G12 + " (0 is out of range; at the first digit)",
    ),
    Case(
        id="arc i=1",
        call="parse_arc",
        value="i=1; " + _SIMPLE,
        expected=_arc(1),
        cite=_G12,
    ),
    Case(
        id="arc i=50",
        call="parse_arc",
        value="i=50; " + _SIMPLE,
        expected=_arc(50),
        cite=_G12 + " (RFC 8617 4.2.1: 1-50 inclusive)",
    ),
    Case(
        id="arc i=51",
        call="parse_arc",
        value="i=51; " + _SIMPLE,
        expected=ErrorReason.BAD_ARC_INSTANCE,
        position=2,
        cite=_G12 + " (51 is out of range)",
    ),
    Case(
        id="arc i=99",
        call="parse_arc",
        value="i=99; " + _SIMPLE,
        expected=ErrorReason.BAD_ARC_INSTANCE,
        position=2,
        cite=_G12,
    ),
    Case(
        id="arc i=01",
        call="parse_arc",
        value="i=01; " + _SIMPLE,
        expected=_arc(1),
        cite=_G12 + "; AU-Q18d answered (i=01 means 1)",
    ),
    Case(
        id="arc i=09",
        call="parse_arc",
        value="i=09; " + _SIMPLE,
        expected=_arc(9),
        cite=_G12 + "; AU-Q18d",
    ),
    Case(
        id="arc i=00",
        call="parse_arc",
        value="i=00; " + _SIMPLE,
        expected=ErrorReason.BAD_ARC_INSTANCE,
        position=2,
        cite=_G12,
    ),
    Case(
        id="arc i=001",
        call="parse_arc",
        value="i=001; " + _SIMPLE,
        expected=ErrorReason.BAD_ARC_INSTANCE,
        position=2,
        cite=_G12 + " (3 or more digits)",
    ),
    Case(
        id="arc i=100",
        call="parse_arc",
        value="i=100; " + _SIMPLE,
        expected=ErrorReason.BAD_ARC_INSTANCE,
        position=2,
        cite=_G12,
    ),
    Case(
        id="arc i 5000 digits",
        call="parse_arc",
        value="i=" + "1" * 5000 + "; " + _SIMPLE,
        expected=ErrorReason.BAD_ARC_INSTANCE,
        position=2,
        cite=_G12 + "; PLAN.md 3.1 corrections item 9 (no int() on a long run)",
    ),
    Case(
        id="arc I=1",
        call="parse_arc",
        value="I=1; " + _SIMPLE,
        expected=ErrorReason.SYNTAX,
        position=0,
        cite=_G12 + " (RFC 8617 3.9 %s, RFC 7405 2.1: i is case-sensitive)",
    ),
    Case(
        id="arc missing instance",
        call="parse_arc",
        value=_SIMPLE,
        expected=ErrorReason.SYNTAX,
        position=0,
        cite=_G12 + " (missing i)",
    ),
    Case(
        id="arc i then dot",
        call="parse_arc",
        value="i.example; none",
        expected=ErrorReason.SYNTAX,
        position=1,
        cite=_G12 + " (no = after i)",
    ),
    Case(
        id="arc missing =",
        call="parse_arc",
        value="i 1; " + _SIMPLE,
        expected=ErrorReason.SYNTAX,
        position=2,
        cite=_G12,
    ),
    Case(
        id="arc no digits",
        call="parse_arc",
        value="i=; " + _SIMPLE,
        expected=ErrorReason.SYNTAX,
        position=2,
        cite=_G12,
    ),
    Case(
        id="arc missing ;",
        call="parse_arc",
        value="i=1 " + _SIMPLE,
        expected=ErrorReason.SYNTAX,
        position=4,
        cite=_G12,
    ),
    Case(
        id="arc i=1x",
        call="parse_arc",
        value="i=1x; " + _SIMPLE,
        expected=ErrorReason.SYNTAX,
        position=3,
        cite=_G12 + " (i=1x is SYNTAX; at the first character that cannot continue)",
    ),
    Case(
        id="arc instance only",
        call="parse_arc",
        value="i=1",
        expected=ErrorReason.SYNTAX,
        position=3,
        cite=_G12 + "; AU-Q16 (SYNTAX at len(value) at end of input)",
    ),
    Case(
        id="arc instance and ; only",
        call="parse_arc",
        value="i=1;",
        expected=ErrorReason.SYNTAX,
        position=4,
        cite=_G12 + "; G1 (authres-payload needs an authserv-id)",
    ),
    Case(
        id="arc CFWS around instance",
        call="parse_arc",
        value=" (a) i (b) = (c) 7 (d) ; " + _SIMPLE,
        expected=_arc(7),
        cite=_G12 + " (RFC 8617 3.9 and 4.1.1 put [CFWS] at each of these spots)",
    ),
    Case(
        id="arc folded instance",
        call="parse_arc",
        value="i=2;\r\n " + _SIMPLE,
        expected=_arc(2),
        cite=_G12 + "; G5",
    ),
    Case(
        id="arc none payload",
        call="parse_arc",
        value="i=1; example.org 1; none",
        expected=ArcAuthenticationResults(
            instance=1, payload=ar("example.org", none=True, version_given=True)
        ),
        cite=_G12 + "; G7, G11",
    ),
    Case(
        id="arc lookalike i",
        call="parse_arc",
        value="\u0456=1; " + _SIMPLE,
        kwargs={"ascii_only": False},
        expected=ErrorReason.SYNTAX,
        position=0,
        cite=_G12 + "; G14 (never UTF-8 in the ARC i)",
    ),
    Case(
        id="arc lookalike i ascii_only",
        call="parse_arc",
        value="\u0456=1; " + _SIMPLE,
        expected=ErrorReason.NON_ASCII,
        position=0,
        cite="PLAN.md 3 Non-ASCII (G14): NON_ASCII from the character scan",
    ),
    Case(
        id="arc payload error position",
        call="parse_arc",
        value="i=1; example.org;;",
        expected=ErrorReason.SYNTAX,
        position=17,
        cite=_G12 + "; G8 (;; is SYNTAX); positions count the whole value",
    ),
)
