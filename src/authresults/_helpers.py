# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Zero-dependency domain helpers for property values."""

from ._checks import ascii_lower, exact_text
from ._errors import call_guarded
from ._lexical import PVALUE_WIDE_TSPECIALS, address_at, is_sub_domain


def domain_of(value: str) -> str | None:
    """Return the part after the last ``@``, or the whole value if there is none.

    One enclosing ``<local-part@domain>`` is stripped first; any other value
    with ``: [ ] < >`` gives ``None`` (AU-Q58).
    """
    return call_guarded(_domain_of, value)


def ascii_domain(value: str) -> str | None:
    """Return the lowercased domain if it is LDH or A-labels only, else ``None``."""
    return call_guarded(_ascii_domain, value)


def _domain_of(value: str) -> str | None:
    """AU-Q33(a): ``None`` when the text after the last ``@`` is empty.

    AU-Q58 and its clarification: exactly ``<`` local-part ``@`` domain
    ``>`` gives the domain, where the inside is what the parser's address
    check accepts unbracketed (``address_at``, as the serializer uses it,
    with non-ASCII allowed as in ``ascii_only=False``); any other bracketed value,
    and any other value holding ``: [ ] < >``, gives ``None``.
    """
    text = exact_text(value)
    if text.startswith("<") and text.endswith(">"):
        return _bracketed_domain(text[1:-1])
    if any(c in PVALUE_WIDE_TSPECIALS for c in text):
        return None
    domain = text[text.rfind("@") + 1 :]
    return domain or None


def _bracketed_domain(inner: str) -> str | None:
    """Return the domain if *inner* is ``[local-part] "@" domain-name`` (G10).

    The local-part is a dot-atom or a quoted-string; the domain follows the
    ``@`` that ``address_at`` found ending it.
    """
    at = address_at(inner)
    return None if at < 0 else inner[at + 1 :]


def _ascii_domain(value: str) -> str | None:
    """AU-Q33(a): dot-separated RFC 5321 4.1.2 ``sub-domain`` labels only."""
    text = exact_text(value)
    if not all(is_sub_domain(label) for label in text.split(".")):
        return None
    return ascii_lower(text)
