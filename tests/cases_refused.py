# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Pinning cases for docs/refused-shapes.md (AL3c, AU-Q52).

One case per entry. Each pins today's outcome, including ``known_shape``,
and carries the accepting expectation in a comment beside it, so
re-enabling a shape is: amend that case (PLAN.md 6.4), change the parser
branch the entry names, and move the entry to the "re-enabled" section.

Provenance and rewriting follow ``tests/cases_vendor.py`` (AU-Q19 as amended
by AU-Q44): each value is rewritten to RFC 2606/6761 names and RFC 5737/3849
addresses, with the source URL, read date and rewrite note per case.
"""

from authresults import Deviation, ErrorReason

from ._case import Case, ar, bare, prop, res

READ = "2026-11-07"

_EXIM = "https://github.com/Exim/exim/blob/d46a6727798fc48d1756190a6d46d19216348c25/"
_MS_ABOUT = (
    "https://learn.microsoft.com/en-us/defender-office-365/email-authentication-about"
)
_OPENDKIM_JOB_ID = (
    "https://github.com/trusteddomainproject/OpenDKIM/blob/"
    "ba29fa57b2455143dd86973c2229d6f7b8e16d9b/opendkim/opendkim.c"
    "#L14535-L14558"
)
_ZOHO_COMMUNITY = (
    "https://help.zoho.com/portal/en/community/topic/"
    "authentication-results-header-format-incorrect"
)

_MIMECAST = (
    "https://mimecastsupport.zendesk.com/hc/en-us/articles/"
    "34000468841107-Policies-DNS-Authentication-Overview"
)
_MIMECAST_VALUE = (
    "mimecast.com; spf=pass (spfCheck: domain of _spf.example.com designates "
    "192.0.2.195 as permitted sender) client-ip=192.0.2.195; "
    "envelope-from=sender@example.com; helo=mail.example.com; dkim=pass "
    "header.i=@example.com; dmarc=pass (p=allow dis=allow) header.from=example.com"
)
_MIMECAST_REWRITE = (
    "the sender's domains (and the SPF include host) -> example.com and "
    "_spf.example.com; public IPv4 address -> an RFC 5737 address; the "
    "sender's address -> sender@example.com; the HELO host -> "
    "mail.example.com; the page's typo 'envelope- from' (a space after the "
    "hyphen) fixed to envelope-from (as published it is SYNTAX at the space, "
    "untagged); one line as published; the page body was read through the "
    "help centre's public article API (the HTML page is behind a bot check)"
)

_FOLD = "printed lines joined with CRLF"

CASES: tuple[Case, ...] = (
    # Accepting expectation (AU-Q46, if revisited after 0.1.0): parse_arc
    # returns instance 1 with authserv-id "example.com", the leading
    # smtp.remote-ip=192.0.2.1 kept in a new model field for properties
    # outside any result, and the result arc=none (registered), flagged by a
    # new deviation for the leading property.
    Case(
        id="refused exim arc leading property",
        call="parse_arc",
        value="i=1; example.com; smtp.remote-ip=192.0.2.1;\r\n\tarc=none",
        expected=ErrorReason.SYNTAX,
        position=22,
        known_shape="exim_arc_leading_property",
        url=_EXIM + "test/mail/4560.a",
        read=READ,
        rewrite="the test suite's authserv-id -> example.com; the loopback "
        "address -> an RFC 5737 address; the LF TAB fold Exim writes -> CRLF TAB",
        cite="Exim public test suite expected mail output (AU-Q44), the "
        "ARC-Authentication-Results Exim signs (format string in "
        "arc_sign_append_aar); AU-Q46 (refused: a property (ptype, dot, "
        "property, value) where a method belongs is SYNTAX at the . that "
        "ends the method keyword); "
        "AU-Q52 (EXIM_ARC_LEADING_PROPERTY)",
    ),
    # Accepting expectation (AU-Q48, if revisited): ar(None, spf=none
    # (smtp.mailfrom=example.net), dkim=pass (header.d=example.net),
    # dmarc=none (bare action=none, header.from=example.com), compauth=fail
    # reason=001 (unregistered)), with deviations MISSING_AUTHSERV_ID,
    # BARE_PROPERTY and a new deviation for each stray domain between results.
    Case(
        id="refused microsoft domain between results",
        value=(
            "spf=none (sender IP is 192.0.2.8)\r\n"
            "  smtp.mailfrom=example.net; example.com; dkim=pass\r\n"
            "  (signature was verified) header.d=example.net;\r\n"
            "  example.com; dmarc=none action=none header.from=example.com;\r\n"
            "  compauth=fail reason=001"
        ),
        expected=ErrorReason.SYNTAX,
        position=71,
        known_shape="stray_domain_between_results",
        url=_MS_ABOUT,
        read=READ,
        rewrite="the documentation's fictional sender domain -> example.net; "
        "its fictional recipient domain -> example.com; private IPv4 address "
        "-> an RFC 5737 address; " + _FOLD + ", two-SP indentation as shown",
        cite="Microsoft Learn, How email authentication works, Composite "
        "authentication, first example header; AU-Q48 (refused: a bare domain "
        "where a method belongs is SYNTAX at the . that ends the method "
        "keyword); AU-Q35 (no authserv-id, read first); AU-Q52 "
        "(STRAY_DOMAIN_BETWEEN_RESULTS)",
    ),
    # Accepting expectation (AU-Q50, if revisited): ar("mail.example.com",
    # dkim=none (registered)), with the job ID kept (a new model field or a
    # new deviation naming it); strict_syntax refuses at the /.
    Case(
        id="refused opendkim authserv-id job id",
        value="mail.example.com/4ABCD1234;\r\n\tdkim=none",
        expected=ErrorReason.SYNTAX,
        position=16,
        known_shape="authserv_id_job_id",
        url=_OPENDKIM_JOB_ID,
        read=READ,
        rewrite="built from the pinned source: the literals '/', ';' and "
        "dkim=none; filled in: the authserv-id and a placeholder MTA queue ID "
        "(opt-in AuthservIDWithJobID on); OpenDKIM's LF TAB fold -> CRLF TAB",
        cite="OpenDKIM, the authserv-id prefix with AuthservIDWithJobID "
        "(OpenDMARC writes the same prefix); AU-Q39 (a dotted first token is "
        "the authserv-id); AU-Q50 (refused: SYNTAX at the / straight after the "
        "authserv-id); AU-Q52 (AUTHSERV_ID_JOB_ID)",
    ),
    # Accepting expectation (AU-Q51, if revisited): ar("mail.example.com",
    # none=True) or an empty results tuple, flagged by a new deviation for a
    # missing "; none"; strict_syntax refuses at len(value).
    Case(
        id="refused exim authserv-id only",
        value="mail.example.com",
        expected=ErrorReason.SYNTAX,
        position=16,
        known_shape="authserv_id_only",
        url=_EXIM + "src/src/expand.c",
        read=READ,
        rewrite="built from the pinned source: the authresults expansion writes "
        "the authserv-id and '; none', then drops the '; none' (its own comment "
        "says so) before appending results; with no results only the "
        "authserv-id is left; filled in: the authserv-id. Inferred from source, "
        "not seen in real output (AU-Q51)",
        cite="Exim, the authresults expansion (Stalwart mail-auth's Display "
        "writes the same shape with no results); G1 (1*resinfo); AU-Q51 "
        "(refused: SYNTAX at len(value)); AU-Q52 (AUTHSERV_ID_ONLY)",
    ),
    # Accepting expectation: none planned (AU-Q54 rejected moving the keys onto
    # the preceding result across ;). If ever revisited: ar("mimecast.com",
    # spf=pass with client-ip, envelope-from and helo kept as properties,
    # dkim=pass, dmarc=pass), with BARE_PROPERTY and a new deviation.
    Case(
        id="refused mimecast spf details as results",
        value=_MIMECAST_VALUE,
        expected=ErrorReason.SYNTAX,
        position=148,
        known_shape="spf_details_as_results",
        url=_MIMECAST,
        read=READ,
        rewrite=_MIMECAST_REWRITE,
        cite="Mimecast Support, Policies - DNS Authentication Overview (updated "
        "2026-07-30), the example header; AU-Q54 (refused and tagged: after "
        "the ;, envelope-from is read as a method whose result keyword is "
        "sender, and the @ is SYNTAX: CFWS is required after a result, G4); "
        "AU-Q52 (SPF_DETAILS_AS_RESULTS)",
    ),
    # Strict refuses earlier, at the bare client-ip inside the spf result
    # (BARE_PROPERTY, not after a ;), so the AU-Q54 rule does not match there
    # and the DEVIATION carries no tag.
    Case(
        id="refused mimecast spf details as results strict",
        value=_MIMECAST_VALUE,
        kwargs={"strict_syntax": True},
        expected=ErrorReason.DEVIATION,
        position=105,
        deviation=Deviation.BARE_PROPERTY,
        url=_MIMECAST,
        read=READ,
        rewrite=_MIMECAST_REWRITE,
        cite="Mimecast Support, Policies - DNS Authentication Overview, the "
        "example header; PLAN.md 2.4 (strict_syntax); AU-Q16 (DEVIATION at the "
        "bare name client-ip); AU-Q54 (the tag rule needs a key after a ;, so "
        "known_shape is None here)",
    ),
    # AU-Q49: accepted today and kept as is. It is read differently from what
    # the producer meant (a missing ; between dkim and spf), so the entry is
    # logged, but it is not refused, so it has no KnownShape (AU-Q52b).
    # strict_syntax refuses it with DEVIATION (BARE_PROPERTY) at 27.
    Case(
        id="refused zoho missing semicolon",
        value=(
            "mx.zoho.com;\r\n"
            " dkim=pass\r\n"
            " spf=pass (zoho.com: domain of _spf.example.net designates "
            "192.0.2.169 as permitted sender)\r\n"
            " smtp.mailfrom=sender@example.net;"
        ),
        expected=ar(
            "mx.zoho.com",
            res(
                "dkim",
                "pass",
                bare("spf", "pass"),
                prop("smtp", "mailfrom", "sender@example.net", registered=False),
                registered=True,
            ),
            deviations=(Deviation.BARE_PROPERTY, Deviation.TRAILING_SEMICOLON),
        ),
        url=_ZOHO_COMMUNITY,
        read=READ,
        rewrite="the SPF include host -> _spf.example.net; public IPv4 address "
        "-> an RFC 5737 address; the poster's redacted address -> "
        "sender@example.net; the page renders with script, so the layout (read "
        "through WebFetch) is normalised to CRLF plus one SP per printed line",
        cite="Zoho Mail community, a user's report that the header misses a ; "
        "between results (AU-Q49: keep the current reading); AU-Q27 (spf=pass "
        "is a bare property of the dkim result, so results_for spf is empty); "
        "G16 (smtp.mailfrom is not registered for dkim); AU-Q28 (final ;)",
    ),
)
