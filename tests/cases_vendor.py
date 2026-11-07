# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Shapes from public vendor documentation (AU-Q19), read 2026-11-06.

Rewrites, per case in ``rewrite``: names to RFC 2606/6761 names, addresses
to RFC 5737/3849 ranges, selectors and signatures replaced; the vendors' own
service hostnames are kept (``VENDOR_HOSTNAMES``). Where a documented value
departs from the grammar the expectation follows PLAN.md, not the vendor.
The pages were read through WebFetch, which returns quotes of at most 125
characters; line layout and indentation are as the fetch reported them.

AL3c additions (read 2026-11-07, ``READ_AL3C``) also come from third-party
guides and from open-source projects' public test fixtures and source code
(AU-Q44), each pinned to a URL or commit permalink. "Built" means put
together from the format strings of a pinned source file, with only the
variable parts filled in; each such case says which parts are literals.
Values with ``< > : [ ]`` in an unquoted property value are accepted under
``PVALUE_TSPECIALS`` (AU-Q45, AU-Q53), with brackets that pair up (AU-Q57).
"""

from authresults import ArcAuthenticationResults, Deviation, ErrorReason

from ._case import Case, ar, bare, prop, res

READ = "2026-11-06"

VENDOR_HOSTNAMES = frozenset(
    {
        "mx.google.com",
        "google.com",
        "atlas321.free.mail.ne1.yahoo.com",
        # AL3c (read 2026-11-07)
        "atlas206.aol.mail.ne1.yahoo.com",
        "bimi.icloud.com",
        "dkim-verifier.icloud.com",
        "mx2.messagingengine.com",
        "mx.zohomail360.com",
        "mx.zohomail.eu",
        "zohomail.eu",
        "mx.zoho.com",
        "zoho.com",
        "ppops.net",
        "mimecast.com",
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

# --- AL3c additions (AU-Q44), read 2026-11-07 --------------------------------

READ_AL3C = "2026-11-07"

_MS_DMARC = (
    "https://learn.microsoft.com/en-us/defender-office-365/"
    "email-authentication-dmarc-configure"
)
_POSTMARK_ARC = (
    "https://postmarkapp.com/blog/what-is-arc-or-authenticated-received-chain"
)
_CHATMAIL = (
    "https://github.com/chatmail/core/blob/"
    "5f1d54100f4558426cdea5e4b7c67bf64c834e76/test-data/message/"
    "dkimchecks-2022-09-28/"
)
_FASTMAIL = "https://www.fastmail.com/blog/spf-dkim-dmarc/"
_ZOHO_API = "https://www.zoho.com/mail360/help/api/fetch-email-header.html"
_PROOFPOINT_GUIDE = (
    "https://seanthegeek.net/assets/wp-content/uploads/2018/06/"
    "Proofpoint-Email-Authentication-Guide.pdf"
)
_CISCO_PDF = (
    "https://www.cisco.com/c/dam/en/us/products/collateral/security/"
    "esa-spf-dkim-dmarc.pdf"
)
_OPENDKIM = (
    "https://github.com/trusteddomainproject/OpenDKIM/blob/"
    "ba29fa57b2455143dd86973c2229d6f7b8e16d9b/opendkim/opendkim.c"
    "#L10755-L10785"
)
_OPENDMARC = (
    "https://github.com/trusteddomainproject/OpenDMARC/blob/"
    "9cebf724d601452d1a671ed5331551dbc18df83a/opendmarc/opendmarc.c"
)
_RSPAMD = (
    "https://github.com/rspamd/rspamd/blob/"
    "50bde752aa6da5cd987fefb7291a1e94e0c77ba8/lualib/lua_auth_results.lua"
    "#L114-L268"
)
_EXIM = "https://github.com/Exim/exim/blob/d46a6727798fc48d1756190a6d46d19216348c25/"
_POLICYD_SPF_PERL = (
    "https://launchpad.net/postfix-policyd-spf-perl/trunk/2.011/+download/"
    "postfix-policyd-spf-perl-2.011.tar.gz"
)

_AU_Q45 = (
    "; AU-Q45 (amends AU-Q22: < > : [ ] in an unquoted property value are "
    "accepted as written under PVALUE_TSPECIALS)"
)
_AU_Q45_STRICT = (
    "; AU-Q45; PLAN.md 2.4 (strict_syntax); AU-Q16 (DEVIATION at the first tspecial)"
)
_BUILT = "built from the pinned source: "
_EXIM_FOLD = "Exim appends each result as ';' LF TAB, written as CRLF TAB on the wire"

_MS_OREJECT = (
    "spf=pass (sender IP is 198.51.100.10)\r\n"
    "  smtp.mailfrom=bounces.example.net; dkim=pass (signature was verified)\r\n"
    "  header.d=example.net; dmarc=fail action=oreject\r\n"
    "  header.from=example.com;compauth=fail reason=000"
)
_MS_OREJECT_REWRITE = (
    "the documentation's two fictional domains -> example.net and "
    "example.com; " + _FOLD + ", two-SP indentation as shown"
)

_AOL = (
    "atlas206.aol.mail.ne1.yahoo.com;\r\n"
    " dkim=unknown;\r\n"
    " spf=none smtp.mailfrom=example.net;\r\n"
    " dmarc=unknown header.from=example.net;"
)

_FASTMAIL_VALUE = (
    "mx2.messagingengine.com;\r\n"
    "    dkim=pass (2048-bit rsa key) header.d=example.com "
    "header.i=@example.com header.b=AbCd123/;\r\n"
    "    dmarc=pass header.from=example.com;\r\n"
    "    spf=pass smtp.mailfrom=sender@example.com smtp.helo=mx2.example.com"
)
_FASTMAIL_REWRITE = (
    "the sender's domain -> example.com; the sender's local-part -> sender; "
    "the sender's HELO host -> mx2.example.com; header.b signature replaced "
    "(same length, the trailing / kept); " + _FOLD + ", four-SP indentation "
    "as shown"
)

_ZOHO_ARC = (
    "i=1; mx.zohomail360.com;\r\n"
    "\tdkim=pass  header.i=mail.example.com;\r\n"
    "\tspf=pass  smtp.mailfrom=bounces@apps.example.com;\r\n"
    "\tdmarc=pass header.from=<sender@mail.example.com>"
)
_ZOHO_ARC_REWRITE = (
    "the documentation's fictional company domains -> mail.example.com and "
    "apps.example.com; the bounce local-part (with a tag) -> bounces; the "
    "From local-part -> sender; the JSON string's escaped CRLF TAB folds and "
    "double spaces kept"
)

_CISCO = (
    "mx1.example.net; dkim=pass (signature verified)\r\n"
    " header.i=sender@news.example.com; dmarc=pass (p=none dis=none) "
    "d=news.example.com"
)
_CISCO_REWRITE = (
    "the receiving host -> mx1.example.net; the sender's address -> "
    "sender@news.example.com and its domain -> news.example.com; the printed "
    "line break (page layout) -> CRLF plus one SP"
)

_OPENDKIM_VALUE = (
    "mail.example.com;\r\n"
    "\tdkim=pass (2048-bit key; unprotected) header.d=example.com "
    "header.i=@example.com header.a=rsa-sha256 header.s=sel1 header.b=Ab/dE+12"
)
_OPENDKIM_REWRITE = (
    _BUILT + "the literals dkim=, ' (%u-bit key; %s)' and the header.* labels; "
    "filled in: the authserv-id, 2048, unprotected, domain, identity, "
    "algorithm, selector and an 8-character header.b prefix that keeps a /; "
    "OpenDKIM folds with LF TAB past its margin, written as CRLF TAB"
)

_EXIM_IPV6 = (
    "mail.example.com;\r\n\tiprev=pass (host.example.net) smtp.remote-ip=2001:db8::1"
)
_EXIM_IPV6_REWRITE = (
    _BUILT + "the literals ';' LF TAB 'iprev=pass (', ')' and ' smtp.remote-ip=' "
    "(authres_iprev); filled in: the authserv-id, the client host name and an "
    "RFC 3849 client address, written unquoted as Exim does; " + _EXIM_FOLD
)
_EXIM_NULL = "mail.example.com;\r\n\tspf=none smtp.mailfrom=<>"
_EXIM_NULL_REWRITE = (
    _BUILT + "the literals ';' LF TAB 'spf=' and ' smtp.mailfrom=<>' (the "
    "branch taken with no sender domain and no HELO name); filled in: the "
    "authserv-id and the SPF result none; " + _EXIM_FOLD
)
_EXIM_HELO = "mail.example.com;\r\n\tspf=pass smtp.helo=[192.0.2.1]"
_EXIM_HELO_REWRITE = (
    _BUILT + "the literals ';' LF TAB 'spf=' and ' smtp.helo='; filled in: the "
    "authserv-id, the SPF result and an IP-literal HELO argument with an RFC "
    "5737 address, written unquoted as Exim does; " + _EXIM_FOLD
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
    # --- AL3c additions (AU-Q44), read 2026-11-07 -----------------------------
    Case(
        id="vendor microsoft dmarc oreject",
        value=_MS_OREJECT,
        expected=ar(
            None,
            res(
                "spf",
                "pass",
                prop("smtp", "mailfrom", "bounces.example.net", registered=True),
                registered=True,
            ),
            res(
                "dkim",
                "pass",
                prop("header", "d", "example.net", registered=True),
                registered=True,
            ),
            res("dmarc", "fail", bare("action", "oreject"), _FROM, registered=True),
            res("compauth", "fail", reason="000", registered=False),
            deviations=_NO_ID_DEVIATIONS,
        ),
        url=_MS_DMARC,
        read=READ_AL3C,
        rewrite=_MS_OREJECT_REWRITE,
        cite="Microsoft Learn, Set up DMARC, 'Diagnose alignment failures from "
        "message headers' example header"
        + _NO_ID
        + "; G9 and AU-Q27 (bare action), G16 (compauth is not registered)",
    ),
    Case(
        id="vendor microsoft dmarc oreject strict",
        value=_MS_OREJECT,
        kwargs={"strict_syntax": True},
        expected=ErrorReason.DEVIATION,
        position=0,
        deviation=Deviation.MISSING_AUTHSERV_ID,
        url=_MS_DMARC,
        read=READ_AL3C,
        rewrite=_MS_OREJECT_REWRITE,
        cite="Microsoft Learn, Set up DMARC, 'Diagnose alignment failures from "
        "message headers' example header" + _NO_ID_STRICT,
    ),
    Case(
        id="vendor gmail arc via postmark",
        call="parse_arc",
        value=(
            "i=1; mx.google.com;\r\n"
            "       dkim=pass header.i=@example.com header.s=sel1 "
            "header.b=AbCd1234;\r\n"
            "       dkim=pass header.i=@example.net header.s=sel2 "
            "header.b=EfGh5678;\r\n"
            "       spf=pass (google.com: domain of bounces@bounces.example.com "
            "designates 192.0.2.124 as permitted sender) "
            "smtp.mailfrom=bounces@bounces.example.com;\r\n"
            "       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=example.com"
        ),
        expected=ArcAuthenticationResults(
            instance=1,
            payload=ar(
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
                    "dkim",
                    "pass",
                    prop("header", "i", "@example.net", registered=True),
                    prop("header", "s", "sel2", registered=True),
                    prop("header", "b", "EfGh5678", registered=True),
                    registered=True,
                ),
                res(
                    "spf",
                    "pass",
                    prop(
                        "smtp",
                        "mailfrom",
                        "bounces@bounces.example.com",
                        registered=True,
                    ),
                    registered=True,
                ),
                res("dmarc", "pass", _FROM, registered=True),
            ),
        ),
        url=_POSTMARK_ARC,
        read=READ_AL3C,
        rewrite="the two signing domains -> example.com and example.net; the "
        "bounce address -> bounces@bounces.example.com; public IPv4 address -> "
        "an RFC 5737 address; DKIM selectors and header.b signatures replaced; "
        + _FOLD
        + ", seven-SP indentation as shown",
        cite="Postmark, What is ARC, the ARC-Authentication-Results example "
        "Gmail wrote (third-party guide, AU-Q44); G12 (i=1); RFC 8617 4.1.1",
    ),
    Case(
        id="vendor aol unknown results",
        value=_AOL,
        expected=ar(
            "atlas206.aol.mail.ne1.yahoo.com",
            res("dkim", "unknown", registered=False),
            res(
                "spf",
                "none",
                prop("smtp", "mailfrom", "example.net", registered=True),
                registered=True,
            ),
            res(
                "dmarc",
                "unknown",
                prop("header", "from", "example.net", registered=True),
                registered=False,
            ),
            deviations=(Deviation.TRAILING_SEMICOLON,),
        ),
        url=_CHATMAIL + "alice@aol.com/alice@delta.blinzeln.de",
        read=READ_AL3C,
        rewrite="the sender's domain -> example.net; the file's LF line ends "
        "-> CRLF, one-SP indentation as in the file",
        cite="chatmail/core public test fixture (AU-Q44), a header an AOL "
        "account received; G16 and AU-Q31 (unknown is not a registered dkim or "
        "dmarc result: kept with registered=False); AU-Q28 (final ; is "
        "TRAILING_SEMICOLON)",
    ),
    Case(
        id="vendor aol unknown results strict",
        value=_AOL,
        kwargs={"strict_syntax": True},
        expected=ErrorReason.DEVIATION,
        position=126,
        deviation=Deviation.TRAILING_SEMICOLON,
        url=_CHATMAIL + "alice@aol.com/alice@delta.blinzeln.de",
        read=READ_AL3C,
        rewrite="the sender's domain -> example.net; the file's LF line ends "
        "-> CRLF, one-SP indentation as in the file",
        cite="chatmail/core public test fixture (AU-Q44); PLAN.md 2.4 "
        "(strict_syntax); AU-Q16 (DEVIATION at the final ;)",
    ),
    Case(
        id="vendor fastmail blog",
        value=_FASTMAIL_VALUE,
        expected=ar(
            "mx2.messagingengine.com",
            res(
                "dkim",
                "pass",
                _HD,
                prop("header", "i", "@example.com", registered=True),
                prop("header", "b", "AbCd123/", registered=True),
                registered=True,
            ),
            res("dmarc", "pass", _FROM, registered=True),
            res(
                "spf",
                "pass",
                prop("smtp", "mailfrom", "sender@example.com", registered=True),
                prop("smtp", "helo", "mx2.example.com", registered=True),
                registered=True,
            ),
            deviations=(Deviation.PVALUE_TSPECIALS,),
        ),
        url=_FASTMAIL,
        read=READ_AL3C,
        rewrite=_FASTMAIL_REWRITE,
        cite="Fastmail blog, SPF, DKIM and DMARC, the example header; G10 rule "
        "3 and AU-Q22 (the / in an unquoted header.b is PVALUE_TSPECIALS)",
    ),
    Case(
        id="vendor fastmail blog strict",
        value=_FASTMAIL_VALUE,
        kwargs={"strict_syntax": True},
        expected=ErrorReason.DEVIATION,
        position=118,
        deviation=Deviation.PVALUE_TSPECIALS,
        url=_FASTMAIL,
        read=READ_AL3C,
        rewrite=_FASTMAIL_REWRITE,
        cite="Fastmail blog, SPF, DKIM and DMARC, the example header; PLAN.md "
        "2.4 (strict_syntax); AU-Q16 (DEVIATION at the /)",
    ),
    Case(
        id="vendor icloud bimi quoted reason",
        value='bimi.icloud.com; bimi=skipped reason="insufficient dmarc"',
        expected=ar(
            "bimi.icloud.com",
            res("bimi", "skipped", reason="insufficient dmarc", registered=False),
        ),
        url=_CHATMAIL + "alice@icloud.com/alice@gmail.com",
        read=READ_AL3C,
        rewrite="nothing needed rewriting (the authserv-id is the vendor's own host)",
        cite="chatmail/core public test fixture (AU-Q44), one of four "
        "single-result fields an iCloud account received; G6 and G8 (quoted "
        "reason value, quotes removed); G16 (bimi is not in the snapshot)",
    ),
    Case(
        id="vendor icloud dkim tab fold",
        value=(
            "dkim-verifier.icloud.com;\r\n"
            "\tdkim=pass (2048-bit key) header.d=example.com "
            "header.i=@example.com header.b=AbCd1234"
        ),
        expected=ar(
            "dkim-verifier.icloud.com",
            res(
                "dkim",
                "pass",
                _HD,
                prop("header", "i", "@example.com", registered=True),
                prop("header", "b", "AbCd1234", registered=True),
                registered=True,
            ),
        ),
        url=_CHATMAIL + "alice@icloud.com/alice@gmail.com",
        read=READ_AL3C,
        rewrite="the sender's domain -> example.com; header.b signature "
        "replaced; the file's LF TAB fold -> CRLF TAB",
        cite="chatmail/core public test fixture (AU-Q44), an iCloud account's "
        "dkim field; G5 (CRLF TAB is FWS)",
    ),
    Case(
        id="vendor zoho arc angle address",
        call="parse_arc",
        value=_ZOHO_ARC,
        expected=ArcAuthenticationResults(
            instance=1,
            payload=ar(
                "mx.zohomail360.com",
                res(
                    "dkim",
                    "pass",
                    prop("header", "i", "mail.example.com", registered=True),
                    registered=True,
                ),
                res(
                    "spf",
                    "pass",
                    prop(
                        "smtp", "mailfrom", "bounces@apps.example.com", registered=True
                    ),
                    registered=True,
                ),
                res(
                    "dmarc",
                    "pass",
                    prop(
                        "header",
                        "from",
                        "<sender@mail.example.com>",
                        registered=True,
                    ),
                    registered=True,
                ),
                deviations=(Deviation.PVALUE_TSPECIALS,),
            ),
        ),
        url=_ZOHO_API,
        read=READ_AL3C,
        rewrite=_ZOHO_ARC_REWRITE,
        cite="Zoho Mail360 API, Get email header, sample response, the i=1 "
        "ARC-Authentication-Results set" + _AU_Q45,
    ),
    Case(
        id="vendor zoho arc angle address strict",
        call="parse_arc",
        value=_ZOHO_ARC,
        kwargs={"strict_syntax": True},
        expected=ErrorReason.DEVIATION,
        position=142,
        deviation=Deviation.PVALUE_TSPECIALS,
        url=_ZOHO_API,
        read=READ_AL3C,
        rewrite=_ZOHO_ARC_REWRITE,
        cite="Zoho Mail360 API, Get email header, sample response, the i=1 "
        "ARC-Authentication-Results set" + _AU_Q45_STRICT + " (the <)",
    ),
    Case(
        id="vendor zoho eu",
        value=(
            "mx.zohomail.eu;\r\n"
            "\tdkim=pass;\r\n"
            "\tspf=pass (zohomail.eu: domain of _spf.example.net designates "
            "198.51.100.68 as permitted sender)  smtp.mailfrom=sender@example.net;"
            "\r\n"
            "\tdmarc=pass(p=none dis=none)  header.from=example.net"
        ),
        expected=ar(
            "mx.zohomail.eu",
            res("dkim", "pass", registered=True),
            res(
                "spf",
                "pass",
                prop("smtp", "mailfrom", "sender@example.net", registered=True),
                registered=True,
            ),
            res(
                "dmarc",
                "pass",
                prop("header", "from", "example.net", registered=True),
                registered=True,
            ),
        ),
        url=_CHATMAIL + "alice@zohomail.eu/alice@gmail.com",
        read=READ_AL3C,
        rewrite="the sender's domain -> example.net (the SPF include host -> "
        "_spf.example.net); the sender's local-part -> sender; public IPv4 "
        "address -> an RFC 5737 address; the file's LF TAB folds -> CRLF TAB, "
        "double spaces kept",
        cite="chatmail/core public test fixture (AU-Q44), a header a Zoho EU "
        "account received; G4 (pass(p=none dis=none): a comment satisfies spot "
        "10, and a resinfo with no propspec is valid, G2)",
    ),
    Case(
        id="vendor proofpoint via guide",
        value=(
            "ppops.net;\r\n"
            "      spf=pass smtp.mailfrom=sender@example.com;\r\n"
            "      dkim=pass header.s=sel1 header.d=example.com;\r\n"
            "      dmarc=pass header.from=example.com"
        ),
        expected=ar(
            "ppops.net",
            res(
                "spf",
                "pass",
                prop("smtp", "mailfrom", "sender@example.com", registered=True),
                registered=True,
            ),
            res(
                "dkim",
                "pass",
                prop("header", "s", "sel1", registered=True),
                _HD,
                registered=True,
            ),
            res("dmarc", "pass", _FROM, registered=True),
        ),
        url=_PROOFPOINT_GUIDE,
        read=READ_AL3C,
        rewrite="the sender's address -> sender@example.com and its domain -> "
        "example.com; DKIM selector replaced; the PDF's printed lines joined "
        "with CRLF, six-SP indentation as the layout extraction shows",
        cite="Proofpoint Email Authentication Guide (third-party guide hosted "
        "by its author, AU-Q44), Troubleshooting, the header from ppops.net",
    ),
    Case(
        id="vendor cisco esa dmarc",
        value=_CISCO,
        expected=ar(
            "mx1.example.net",
            res(
                "dkim",
                "pass",
                prop("header", "i", "sender@news.example.com", registered=True),
                registered=True,
            ),
            res("dmarc", "pass", bare("d", "news.example.com"), registered=True),
            deviations=(Deviation.BARE_PROPERTY,),
        ),
        url=_CISCO_PDF,
        read=READ_AL3C,
        rewrite=_CISCO_REWRITE,
        cite="Cisco, Email Authentication Best Practices (PDF), the DMARC "
        "verification example; G9 and AU-Q27 (bare d= is BARE_PROPERTY)",
    ),
    Case(
        id="vendor cisco esa dmarc strict",
        value=_CISCO,
        kwargs={"strict_syntax": True},
        expected=ErrorReason.DEVIATION,
        position=113,
        deviation=Deviation.BARE_PROPERTY,
        url=_CISCO_PDF,
        read=READ_AL3C,
        rewrite=_CISCO_REWRITE,
        cite="Cisco, Email Authentication Best Practices (PDF), the DMARC "
        "verification example; PLAN.md 2.4 (strict_syntax); AU-Q16 (DEVIATION "
        "at the bare name)",
    ),
    Case(
        id="vendor opendkim header.b with slash",
        value=_OPENDKIM_VALUE,
        expected=ar(
            "mail.example.com",
            res(
                "dkim",
                "pass",
                _HD,
                prop("header", "i", "@example.com", registered=True),
                prop("header", "a", "rsa-sha256", registered=True),
                prop("header", "s", "sel1", registered=True),
                prop("header", "b", "Ab/dE+12", registered=True),
                registered=True,
            ),
            deviations=(Deviation.PVALUE_TSPECIALS,),
        ),
        url=_OPENDKIM,
        read=READ_AL3C,
        rewrite=_OPENDKIM_REWRITE,
        cite="OpenDKIM, the per-signature Authentication-Results code; G4 (the "
        "; inside the comment is comment text); G10 rule 3 and AU-Q22 (an "
        "unquoted base64 header.b with / is PVALUE_TSPECIALS)",
    ),
    Case(
        id="vendor opendkim header.b with slash strict",
        value=_OPENDKIM_VALUE,
        kwargs={"strict_syntax": True},
        expected=ErrorReason.DEVIATION,
        position=146,
        deviation=Deviation.PVALUE_TSPECIALS,
        url=_OPENDKIM,
        read=READ_AL3C,
        rewrite=_OPENDKIM_REWRITE,
        cite="OpenDKIM, the per-signature Authentication-Results code; PLAN.md "
        "2.4 (strict_syntax); AU-Q16 (DEVIATION at the /)",
    ),
    Case(
        id="vendor opendmarc dmarc pass",
        value="mail.example.com; dmarc=pass (p=none dis=none) header.from=example.com",
        expected=ar(
            "mail.example.com",
            res("dmarc", "pass", _FROM, registered=True),
        ),
        url=_OPENDMARC + "#L3745-L3753",
        read=READ_AL3C,
        rewrite=_BUILT + "the literals '; dmarc=', ' (p=', ' dis=', ') "
        "header.from='; filled in: the authserv-id, pass, none, none and the "
        "From domain (AuthservIDWithJobID off)",
        cite="OpenDMARC, the dmarc Authentication-Results format string",
    ),
    Case(
        id="vendor opendmarc spf tempfail",
        value="mail.example.com; spf=tempfail smtp.mailfrom=example.com",
        expected=ar(
            "mail.example.com",
            res("spf", "tempfail", _MAILFROM, registered=False),
        ),
        url=_OPENDMARC + "#L3085-L3138",
        read=READ_AL3C,
        rewrite=_BUILT + "the literals '; spf=', tempfail and ' smtp.mailfrom='; "
        "filled in: the authserv-id and the envelope domain",
        cite="OpenDMARC, the spf Authentication-Results format string and its "
        "tempfail result; G16 and AU-Q31 (tempfail is not a registered spf "
        "result: kept with registered=False)",
    ),
    Case(
        id="vendor rspamd quoted header.b",
        value=(
            "mx.example.net; dkim=pass header.d=example.com header.s=sel1 "
            'header.b="Ab/dE+12"; spf=pass (mx.example.net: domain of '
            "sender@example.com designates 192.0.2.10 as permitted sender) "
            "smtp.mailfrom=sender@example.com"
        ),
        expected=ar(
            "mx.example.net",
            res(
                "dkim",
                "pass",
                _HD,
                prop("header", "s", "sel1", registered=True),
                prop(
                    "header",
                    "b",
                    "Ab/dE+12",
                    raw='"Ab/dE+12"',
                    quoted=True,
                    registered=True,
                ),
                registered=True,
            ),
            res(
                "spf",
                "pass",
                prop("smtp", "mailfrom", "sender@example.com", registered=True),
                registered=True,
            ),
        ),
        url=_RSPAMD,
        read=READ_AL3C,
        rewrite=_BUILT + "the literals dkim=, header.d=, header.s=, header.b=, "
        "the spf comment format and smtp.mailfrom=, joined with '; ' before "
        "folding; filled in: the authserv-id, domain, selector, an 8-character "
        "header.b with / (quoted by the quoting helper), sender and an RFC "
        "5737 client address",
        cite="rspamd, the Authentication-Results generator; G6 (a quoted "
        "header.b has quoted=True and no deviation)",
    ),
    Case(
        id="vendor exim iprev and arc",
        value=(
            "example.com;\r\n"
            "\tiprev=pass (localhost) smtp.remote-ip=192.0.2.1;\r\n"
            "\tarc=pass (i=1) header.s=sel arc.oldest-pass=1 smtp.remote-ip=192.0.2.1"
        ),
        expected=ar(
            "example.com",
            res(
                "iprev",
                "pass",
                prop("smtp", "remote-ip", "192.0.2.1", registered=False),
                registered=True,
            ),
            res(
                "arc",
                "pass",
                prop("header", "s", "sel", registered=False),
                prop("arc", "oldest-pass", "1", registered=False),
                prop("smtp", "remote-ip", "192.0.2.1", registered=True),
                registered=True,
            ),
        ),
        url=_EXIM + "test/mail/4560.a",
        read=READ_AL3C,
        rewrite="the test suite's authserv-id -> example.com; the loopback "
        "address -> an RFC 5737 address; the file's LF TAB folds -> CRLF TAB",
        cite="Exim public test suite expected mail output (AU-Q44), the second "
        "message's Authentication-Results; G16 and AU-Q31 (iprev registers "
        "policy.iprev, not smtp.remote-ip; header.s and Exim's own oldest-pass "
        "property are not registered for arc; all kept)",
    ),
    Case(
        id="vendor exim ipv6 remote-ip",
        value=_EXIM_IPV6,
        expected=ar(
            "mail.example.com",
            res(
                "iprev",
                "pass",
                prop("smtp", "remote-ip", "2001:db8::1", registered=False),
                registered=True,
            ),
            deviations=(Deviation.PVALUE_TSPECIALS,),
        ),
        url=_EXIM + "src/src/expand.c",
        read=READ_AL3C,
        rewrite=_EXIM_IPV6_REWRITE,
        cite="Exim, authres_iprev" + _AU_Q45,
    ),
    Case(
        id="vendor exim ipv6 remote-ip strict",
        value=_EXIM_IPV6,
        kwargs={"strict_syntax": True},
        expected=ErrorReason.DEVIATION,
        position=69,
        deviation=Deviation.PVALUE_TSPECIALS,
        url=_EXIM + "src/src/expand.c",
        read=READ_AL3C,
        rewrite=_EXIM_IPV6_REWRITE,
        cite="Exim, authres_iprev" + _AU_Q45_STRICT + " (the first :)",
    ),
    Case(
        id="vendor exim null sender",
        value=_EXIM_NULL,
        expected=ar(
            "mail.example.com",
            res(
                "spf",
                "none",
                prop("smtp", "mailfrom", "<>", registered=True),
                registered=True,
            ),
            deviations=(Deviation.PVALUE_TSPECIALS,),
        ),
        url=_EXIM + "src/src/miscmods/spf.c",
        read=READ_AL3C,
        rewrite=_EXIM_NULL_REWRITE,
        cite="Exim, the spf authres function (the Stalwart mail-auth unit test "
        "expects the same smtp.mailfrom=<>)" + _AU_Q45,
    ),
    Case(
        id="vendor exim null sender strict",
        value=_EXIM_NULL,
        kwargs={"strict_syntax": True},
        expected=ErrorReason.DEVIATION,
        position=43,
        deviation=Deviation.PVALUE_TSPECIALS,
        url=_EXIM + "src/src/miscmods/spf.c",
        read=READ_AL3C,
        rewrite=_EXIM_NULL_REWRITE,
        cite="Exim, the spf authres function" + _AU_Q45_STRICT + " (the <)",
    ),
    Case(
        id="vendor exim ip-literal helo",
        value=_EXIM_HELO,
        expected=ar(
            "mail.example.com",
            res(
                "spf",
                "pass",
                prop("smtp", "helo", "[192.0.2.1]", registered=True),
                registered=True,
            ),
            deviations=(Deviation.PVALUE_TSPECIALS,),
        ),
        url=_EXIM + "src/src/miscmods/spf.c",
        read=READ_AL3C,
        rewrite=_EXIM_HELO_REWRITE,
        cite="Exim, the spf authres function (OpenDMARC and Haraka write the "
        "HELO argument unquoted too)" + _AU_Q45,
    ),
    Case(
        id="vendor exim ip-literal helo strict",
        value=_EXIM_HELO,
        kwargs={"strict_syntax": True},
        expected=ErrorReason.DEVIATION,
        position=39,
        deviation=Deviation.PVALUE_TSPECIALS,
        url=_EXIM + "src/src/miscmods/spf.c",
        read=READ_AL3C,
        rewrite=_EXIM_HELO_REWRITE,
        cite="Exim, the spf authres function" + _AU_Q45_STRICT + " (the [)",
    ),
    Case(
        id="vendor postfix policyd-spf-perl localhost",
        value="mx.example.com; none (SPF not checked for localhost)",
        expected=ar("mx.example.com", none=True),
        url=_POLICYD_SPF_PERL,
        read=READ_AL3C,
        rewrite=_BUILT + "the literal '; none (SPF not checked for localhost)' "
        "after the PREPEND field name (release tarball, sha256 51e295c8bfc714f7"
        "e827bd39d674430a9da9ce1658339b7c6cc2537949d82d61); filled in: the host "
        "name",
        cite="postfix-policyd-spf-perl, the localhost exemption; G7 (; none "
        "with a comment after it)",
    ),
)
