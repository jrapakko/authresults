# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""A frozen snapshot of the IANA Email Authentication Parameters registries.

Source: https://www.iana.org/assignments/email-auth/email-auth.xml (PLAN.md
3.1 G16). Used only to set the ``registered`` flags. Deprecated entries count
as registered. The snapshot follows IANA literally (AU-Q31): the
``domainkeys`` result names list ``temperror`` twice and have no ``fail``,
so ``domainkeys=fail`` is not registered.

Every registered method version is ``1``.
"""

LAST_UPDATED = "2026-05-22"

# Email Authentication Methods: method -> registered (ptype, property) pairs.
_PROPERTIES: dict[str, frozenset[tuple[str, str]]] = {
    "arc": frozenset({("smtp", "remote-ip"), ("header", "oldest-pass")}),
    "auth": frozenset({("smtp", "auth"), ("smtp", "mailfrom")}),
    "dkim": frozenset(
        {
            ("header", "d"),
            ("header", "i"),
            ("header", "b"),
            ("header", "a"),
            ("header", "s"),
        }
    ),
    "dkim-adsp": frozenset({("header", "from")}),  # deprecated
    "dkim-atps": frozenset({("header", "from")}),
    "dmarc": frozenset({("header", "from"), ("policy", "dmarc")}),
    "dnswl": frozenset(
        {("dns", "zone"), ("policy", "ip"), ("policy", "txt"), ("dns", "sec")}
    ),
    "domainkeys": frozenset(  # deprecated
        {("header", "d"), ("header", "from"), ("header", "sender")}
    ),
    "iprev": frozenset({("policy", "iprev")}),
    "rrvs": frozenset({("smtp", "rcptto")}),
    # deprecated; registered as "header.<name of header field used by PRA>",
    # so any header.* property matches (_ANY_HEADER).
    "sender-id": frozenset(),
    "smime": frozenset(
        {
            ("body", "smime-part"),
            ("body", "smime-identifer"),  # sic, as registered
            ("body", "smime-serial"),
            ("body", "smime-issuer"),
        }
    ),
    "spf": frozenset({("smtp", "mailfrom"), ("smtp", "helo")}),
    "vbr": frozenset({("header", "md"), ("header", "mv")}),
}

_ANY_HEADER = frozenset({"sender-id"})

# Email Authentication Result Names: method -> registered result codes.
_RESULTS: dict[str, frozenset[str]] = {
    "arc": frozenset({"fail", "none", "pass"}),
    "auth": frozenset({"fail", "none", "pass", "permerror", "temperror"}),
    "dkim": frozenset(
        {"fail", "neutral", "none", "pass", "permerror", "policy", "temperror"}
    ),
    "dkim-adsp": frozenset(  # all deprecated
        {
            "discard",
            "fail",
            "none",
            "nxdomain",
            "pass",
            "permerror",
            "temperror",
            "unknown",
        }
    ),
    "dkim-atps": frozenset({"fail", "none", "pass", "permerror", "temperror"}),
    "dmarc": frozenset({"fail", "none", "pass", "permerror", "temperror"}),
    "dnswl": frozenset({"none", "pass", "permerror", "temperror"}),
    # deprecated; IANA lists temperror twice and has no fail (kept literally).
    "domainkeys": frozenset(
        {"temperror", "neutral", "none", "permerror", "policy", "pass"}
    ),
    "iprev": frozenset({"fail", "pass", "permerror", "temperror"}),
    "rrvs": frozenset({"fail", "none", "pass", "permerror", "temperror", "unknown"}),
    "sender-id": frozenset(  # all deprecated
        {
            "fail",
            "hardfail",
            "neutral",
            "none",
            "pass",
            "permerror",
            "policy",
            "softfail",
            "temperror",
        }
    ),
    "smime": frozenset(
        {"fail", "neutral", "none", "pass", "permerror", "policy", "temperror"}
    ),
    "spf": frozenset(
        {
            "fail",
            "hardfail",  # deprecated
            "neutral",
            "none",
            "pass",
            "permerror",
            "policy",
            "softfail",
            "temperror",
        }
    ),
    "vbr": frozenset({"fail", "none", "pass", "permerror", "temperror"}),
}

_EMPTY: frozenset[str] = frozenset()
_NO_PROPERTIES: frozenset[tuple[str, str]] = frozenset()


def result_registered(method: str, version: int | None, result: str) -> bool:
    """Return True for a known method, version absent or 1, listed result."""
    return (version is None or version == 1) and result in _RESULTS.get(method, _EMPTY)


def property_registered(method: str, ptype: str, name: str) -> bool:
    """Return True if the (method, ptype, property) row exists (AU-Q31)."""
    if method in _ANY_HEADER and ptype == "header":
        return True
    return (ptype, name) in _PROPERTIES.get(method, _NO_PROPERTIES)
