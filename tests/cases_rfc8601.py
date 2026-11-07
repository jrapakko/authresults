# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""RFC 8601 example header fields, unmodified (AU-Q19, PLAN.md 3.1 G18, G19).

Each value is the field body after ``Authentication-Results:``. The single
space after the colon is dropped as the field separator (both readings are
``[CFWS]``); the printed lines are joined by CRLF, and each continuation
line keeps its printed leading whitespace (valid FWS). Source:
https://www.rfc-editor.org/rfc/rfc8601.txt (read 2026-11-06).
"""

from authresults import ErrorReason

from ._case import Case, ar, prop, res

_HOW = "; leading SP after the colon dropped, printed lines joined by CRLF"


def _cite(where: str) -> str:
    return f"IETF RFC 8601, {where} (unmodified excerpt)" + _HOW


B7 = (
    "foo.example.net (foobar) 1 (baz);\r\n"
    "           dkim (Because I like it) / 1 (One yay) = (wait for it) fail\r\n"
    "             policy (A dot can go here) . (like that) expired\r\n"
    "             (this surprised me) = (as I wasn't expecting it) 1362471462"
)

CASES: tuple[Case, ...] = (
    Case(
        id="rfc8601 B.2",
        value="example.org 1; none",
        expected=ar("example.org", none=True, version_given=True),
        cite=_cite("Appendix B.2"),
    ),
    Case(
        id="rfc8601 B.3",
        value="example.com;\r\n                  spf=pass smtp.mailfrom=example.net",
        expected=ar(
            "example.com",
            res(
                "spf",
                "pass",
                prop("smtp", "mailfrom", "example.net", registered=True),
                registered=True,
            ),
        ),
        cite=_cite("Appendix B.3"),
    ),
    Case(
        id="rfc8601 B.4 first field",
        value=(
            "example.com;\r\n"
            "                  auth=pass (cram-md5) smtp.auth=sender@example.net;\r\n"
            "                  spf=pass smtp.mailfrom=example.net"
        ),
        expected=ar(
            "example.com",
            res(
                "auth",
                "pass",
                prop("smtp", "auth", "sender@example.net", registered=True),
                registered=True,
            ),
            res(
                "spf",
                "pass",
                prop("smtp", "mailfrom", "example.net", registered=True),
                registered=True,
            ),
        ),
        cite=_cite("Appendix B.4, first field"),
    ),
    Case(
        id="rfc8601 B.4 second field",
        value="example.com; iprev=pass\r\n                  policy.iprev=192.0.2.200",
        expected=ar(
            "example.com",
            res(
                "iprev",
                "pass",
                prop("policy", "iprev", "192.0.2.200", registered=True),
                registered=True,
            ),
        ),
        cite=_cite("Appendix B.4, second field"),
    ),
    Case(
        id="rfc8601 B.5 first field",
        value=(
            "example.com;\r\n"
            "                  dkim=pass (good signature) header.d=example.com"
        ),
        expected=ar(
            "example.com",
            res(
                "dkim",
                "pass",
                prop("header", "d", "example.com", registered=True),
                registered=True,
            ),
        ),
        cite=_cite("Appendix B.5, first field"),
    ),
    Case(
        id="rfc8601 B.5 second field",
        value=(
            "example.com;\r\n"
            "                  auth=pass (cram-md5) smtp.auth=sender@example.com;\r\n"
            "                  spf=fail smtp.mailfrom=example.com"
        ),
        expected=ar(
            "example.com",
            res(
                "auth",
                "pass",
                prop("smtp", "auth", "sender@example.com", registered=True),
                registered=True,
            ),
            res(
                "spf",
                "fail",
                prop("smtp", "mailfrom", "example.com", registered=True),
                registered=True,
            ),
        ),
        cite=_cite("Appendix B.5, second field"),
    ),
    Case(
        id="rfc8601 B.6 first field",
        value=(
            "example.com;\r\n"
            '              dkim=pass reason="good signature"\r\n'
            "                header.i=@mail-router.example.net;\r\n"
            '              dkim=fail reason="bad signature"\r\n'
            "                header.i=@newyork.example.com"
        ),
        expected=ar(
            "example.com",
            res(
                "dkim",
                "pass",
                prop("header", "i", "@mail-router.example.net", registered=True),
                reason="good signature",
                registered=True,
            ),
            res(
                "dkim",
                "fail",
                prop("header", "i", "@newyork.example.com", registered=True),
                reason="bad signature",
                registered=True,
            ),
        ),
        cite=_cite("Appendix B.6, first field"),
    ),
    Case(
        id="rfc8601 B.6 second field",
        value=(
            "example.net;\r\n"
            "              dkim=pass (good signature) header.i=@newyork.example.com"
        ),
        expected=ar(
            "example.net",
            res(
                "dkim",
                "pass",
                prop("header", "i", "@newyork.example.com", registered=True),
                registered=True,
            ),
        ),
        cite=_cite("Appendix B.6, second field"),
    ),
    Case(
        id="rfc8601 B.7",
        value=B7,
        expected=ar(
            "foo.example.net",
            res(
                "dkim",
                "fail",
                prop("policy", "expired", "1362471462", registered=False),
                version=1,
                registered=True,
            ),
            version_given=True,
        ),
        cite=_cite("Appendix B.7") + "; expected parse from PLAN.md 3.1 G19",
    ),
    Case(
        id="rfc8601 B.7 require_registered",
        value=B7,
        kwargs={"require_registered": True},
        expected=ErrorReason.UNREGISTERED,
        position=B7.index("policy"),
        cite=_cite("Appendix B.7")
        + "; policy.expired is not registered for dkim (G16); UNREGISTERED at "
        "the ptype (AU-Q16 refinement 1)",
    ),
    Case(
        id="rfc8601 2.7.6",
        value=(
            "example.com;\r\n                  foo=pass bar.baz=blob (2 of 3 tests OK)"
        ),
        expected=ar(
            "example.com",
            res(
                "foo",
                "pass",
                prop("bar", "baz", "blob", registered=False),
                registered=False,
            ),
        ),
        cite=_cite("Section 2.7.6"),
    ),
)
