# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Shapes from public vendor documentation (AU-Q19), read 2026-11-06.

Rewrites, per case in ``rewrite``: names to RFC 2606/6761 names, addresses
to RFC 5737/3849 ranges, selectors and signatures replaced; the vendors' own
service hostnames are kept (``VENDOR_HOSTNAMES``). Where a documented value
departs from the grammar the expectation follows PLAN.md, not the vendor.
The pages were read through WebFetch, which returns quotes of at most 125
characters; line layout and indentation are as the fetch reported them.
"""

from authresults import Deviation, ErrorReason

from ._case import Case, ar, bare, prop, res

READ = "2026-11-06"

VENDOR_HOSTNAMES = frozenset(
    {
        "mx.google.com",
        "google.com",
        "atlas321.free.mail.ne1.yahoo.com",
    }
)

_MS_TROUBLESHOOT = (
    "https://learn.microsoft.com/en-us/defender-office-365/"
    "email-authentication-troubleshoot"
)
_VALIMAIL = "https://www.valimail.com/?p=1212"
_POSTMARK = "https://postmarkapp.com/guides/dmarc"

_NO_ID = (
    "; AU-Q35 (no authserv-id: the first token is followed by =, so it is a "
    "method; authserv_id=None and MISSING_AUTHSERV_ID)"
)
_NO_ID_STRICT = (
    "; AU-Q35 (strict_syntax: DEVIATION at the first method keyword); PLAN.md 2.4"
)
_FOLD = "printed lines joined with CRLF"
_REFETCHED = (
    "; re-verified against the page on 2026-11-06 (second WebFetch, after the "
    "verifier's fetch was blocked)"
)

_MS_BOTH_FAIL = (
    "spf=fail smtp.mailfrom=example.com;\r\n"
    " dkim=fail header.d=example.com; dmarc=fail action=quarantine;\r\n"
    " compauth=fail reason=000"
)

_MS_READ_RESULTS = (
    "spf=fail (sender IP is 198.51.100.50)\r\n"
    " smtp.mailfrom=example.com; dkim=pass (signature was verified)\r\n"
    " header.d=example.com; dmarc=fail action=quarantine\r\n"
    " header.from=example.com; compauth=fail reason=000"
)

_MS_VALIMAIL = (
    "spf=pass (sender IP is 192.0.2.48)\r\n"
    " smtp.mailfrom=example.com; dkim=pass (signature was verified)\r\n"
    " header.d=example.com;dmarc=pass action=none\r\n"
    " header.from=example.com;compauth=pass reason=100"
)

_YAHOO = (
    "atlas321.free.mail.ne1.yahoo.com;\r\n"
    " dkim=pass header.i=@example.com header.s=sel1;\r\n"
    " spf=pass smtp.mailfrom=example.com;\r\n"
    " dmarc=pass(p=REJECT) header.from=example.com;"
)

_FROM = prop("header", "from", "example.com", registered=True)
_MAILFROM = prop("smtp", "mailfrom", "example.com", registered=True)
_HD = prop("header", "d", "example.com", registered=True)
_NO_ID_DEVIATIONS = (Deviation.MISSING_AUTHSERV_ID, Deviation.BARE_PROPERTY)

_MS_BOTH_FAIL_REWRITE = "the documentation's fictional domain -> example.com; " + _FOLD
_MS_READ_RESULTS_REWRITE = (
    "the documentation's fictional domain -> example.com; private IPv4 "
    "address -> an RFC 5737 address; " + _FOLD
)
_MS_VALIMAIL_REWRITE = (
    "the sender's domain -> example.com; public IPv4 address -> an RFC 5737 "
    "address; " + _FOLD + ", one-SP indentation as shown" + _REFETCHED
)
_YAHOO_REWRITE = (
    "the sender's domain -> example.com; DKIM selector replaced; "
    + _FOLD
    + ", one-SP indentation as shown"
    + _REFETCHED
)

CASES: tuple[Case, ...] = (
    Case(
        id="vendor microsoft both fail",
        value=_MS_BOTH_FAIL,
        expected=ar(
            None,
            res("spf", "fail", _MAILFROM, registered=True),
            res("dkim", "fail", _HD, registered=True),
            res("dmarc", "fail", bare("action", "quarantine"), registered=True),
            res("compauth", "fail", reason="000", registered=False),
            deviations=_NO_ID_DEVIATIONS,
        ),
        url=_MS_TROUBLESHOOT,
        read=READ,
        rewrite=_MS_BOTH_FAIL_REWRITE,
        cite="Microsoft Learn, Troubleshoot email authentication, 'SPF and DKIM "
        "both fail' example header"
        + _NO_ID
        + "; G9 and AU-Q27 (bare action), G16 (compauth is not registered)",
    ),
    Case(
        id="vendor microsoft both fail strict",
        value=_MS_BOTH_FAIL,
        kwargs={"strict_syntax": True},
        expected=ErrorReason.DEVIATION,
        position=0,
        deviation=Deviation.MISSING_AUTHSERV_ID,
        url=_MS_TROUBLESHOOT,
        read=READ,
        rewrite=_MS_BOTH_FAIL_REWRITE,
        cite="Microsoft Learn, Troubleshoot email authentication, 'SPF and DKIM "
        "both fail' example header" + _NO_ID_STRICT,
    ),
    Case(
        id="vendor microsoft read results",
        value=_MS_READ_RESULTS,
        expected=ar(
            None,
            res("spf", "fail", _MAILFROM, registered=True),
            res("dkim", "pass", _HD, registered=True),
            res(
                "dmarc",
                "fail",
                bare("action", "quarantine"),
                _FROM,
                registered=True,
            ),
            res("compauth", "fail", reason="000", registered=False),
            deviations=_NO_ID_DEVIATIONS,
        ),
        url=_MS_TROUBLESHOOT,
        read=READ,
        rewrite=_MS_READ_RESULTS_REWRITE,
        cite="Microsoft Learn, Troubleshoot email authentication, 'Read "
        "authentication results in message headers' example header"
        + _NO_ID
        + "; G9 and AU-Q27 (bare action), G16 (compauth), G8 (reason=000)",
    ),
    Case(
        id="vendor microsoft read results strict",
        value=_MS_READ_RESULTS,
        kwargs={"strict_syntax": True},
        expected=ErrorReason.DEVIATION,
        position=0,
        deviation=Deviation.MISSING_AUTHSERV_ID,
        url=_MS_TROUBLESHOOT,
        read=READ,
        rewrite=_MS_READ_RESULTS_REWRITE,
        cite="Microsoft Learn, Troubleshoot email authentication, 'Read "
        "authentication results in message headers' example header" + _NO_ID_STRICT,
    ),
    Case(
        id="vendor microsoft via valimail",
        value=_MS_VALIMAIL,
        expected=ar(
            None,
            res("spf", "pass", _MAILFROM, registered=True),
            res("dkim", "pass", _HD, registered=True),
            res("dmarc", "pass", bare("action", "none"), _FROM, registered=True),
            res("compauth", "pass", reason="100", registered=False),
            deviations=_NO_ID_DEVIATIONS,
        ),
        url=_VALIMAIL,
        read=READ,
        rewrite=_MS_VALIMAIL_REWRITE,
        cite="Valimail, Email headers 101, Microsoft example"
        + _NO_ID
        + "; G9 and AU-Q27 (bare action), G16 (compauth)",
    ),
    Case(
        id="vendor microsoft via valimail strict",
        value=_MS_VALIMAIL,
        kwargs={"strict_syntax": True},
        expected=ErrorReason.DEVIATION,
        position=0,
        deviation=Deviation.MISSING_AUTHSERV_ID,
        url=_VALIMAIL,
        read=READ,
        rewrite=_MS_VALIMAIL_REWRITE,
        cite="Valimail, Email headers 101, Microsoft example" + _NO_ID_STRICT,
    ),
    Case(
        id="vendor gmail via valimail",
        value=(
            "mx.google.com;\r\n"
            "           dkim=pass header.i=@example.com header.s=sel1 "
            "header.b=AbCd1234;\r\n"
            "           spf=pass (google.com: domain of sender@example.com "
            "designates 192.0.2.41 as permitted sender) "
            "smtp.mailfrom=sender@example.com;\r\n"
            "           dmarc=pass (p=REJECT sp=REJECT dis=NONE) "
            "header.from=example.com"
        ),
        expected=ar(
            "mx.google.com",
            res(
                "dkim",
                "pass",
                prop("header", "i", "@example.com", registered=True),
                prop("header", "s", "sel1", registered=True),
                prop("header", "b", "AbCd1234", registered=True),
                registered=True,
            ),
            res(
                "spf",
                "pass",
                prop("smtp", "mailfrom", "sender@example.com", registered=True),
                registered=True,
            ),
            res("dmarc", "pass", _FROM, registered=True),
        ),
        url=_VALIMAIL,
        read=READ,
        rewrite="the sender's domain -> example.com; the page's redacted "
        "local-part -> sender; public IPv4 address -> an RFC 5737 address; DKIM "
        "selector replaced; header.b signature replaced (same length and "
        "character classes); "
        + _FOLD
        + ", 11-SP indentation as shown, smtp.mailfrom on the spf line"
        + _REFETCHED,
        cite="Valimail, Email headers 101, Gmail example",
    ),
    Case(
        id="vendor yahoo via valimail",
        value=_YAHOO,
        expected=ar(
            "atlas321.free.mail.ne1.yahoo.com",
            res(
                "dkim",
                "pass",
                prop("header", "i", "@example.com", registered=True),
                prop("header", "s", "sel1", registered=True),
                registered=True,
            ),
            res("spf", "pass", _MAILFROM, registered=True),
            res("dmarc", "pass", _FROM, registered=True),
            deviations=(Deviation.TRAILING_SEMICOLON,),
        ),
        url=_VALIMAIL,
        read=READ,
        rewrite=_YAHOO_REWRITE,
        cite="Valimail, Email headers 101, Yahoo example; G8 and AU-Q28 "
        "(final ; is TRAILING_SEMICOLON); G4 (pass(p=REJECT): a comment "
        "satisfies spot 10)",
    ),
    Case(
        id="vendor yahoo via valimail strict",
        value=_YAHOO,
        kwargs={"strict_syntax": True},
        expected=ErrorReason.DEVIATION,
        position=len(_YAHOO) - 1,
        deviation=Deviation.TRAILING_SEMICOLON,
        url=_VALIMAIL,
        read=READ,
        rewrite=_YAHOO_REWRITE,
        cite="Valimail, Email headers 101, Yahoo example; PLAN.md 2.4 "
        "(strict_syntax); AU-Q16 (DEVIATION at the ;)",
    ),
    Case(
        id="vendor gmail via postmark",
        value=(
            "mx.google.com;\r\n"
            "  spf=pass (google.com: domain of bounces@bounces.example.com "
            "designates 192.0.2.117 as permitted sender) "
            "smtp.mail=bounces@bounces.example.com;\r\n"
            "  dkim=pass header.i=@example.com;\r\n"
            "  dmarc=pass (p=NONE dis=NONE) header.from=example.com"
        ),
        expected=ar(
            "mx.google.com",
            res(
                "spf",
                "pass",
                prop("smtp", "mail", "bounces@bounces.example.com", registered=False),
                registered=True,
            ),
            res(
                "dkim",
                "pass",
                prop("header", "i", "@example.com", registered=True),
                registered=True,
            ),
            res("dmarc", "pass", _FROM, registered=True),
        ),
        url=_POSTMARK,
        read=READ,
        rewrite="the sender's domain -> example.com; the bounce address -> "
        "bounces@bounces.example.com; public IPv4 address -> an RFC 5737 "
        "address; "
        + _FOLD
        + ", two-SP indentation as shown, smtp.mail on the spf line (layout "
        "re-checked against the page on 2026-11-06)",
        cite="Postmark, DMARC guide (updated 2025-11-14), Gmail example; G16 "
        "(smtp.mail, as documented, is not registered for spf)",
    ),
)
