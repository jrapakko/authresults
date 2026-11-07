# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Zero-dependency domain helpers for property values."""

from ._checks import ascii_lower, exact_text
from ._errors import call_guarded
from ._lexical import KEYWORD, LET_DIG


def domain_of(value: str) -> str | None:
    """Return the part after the last ``@``, or the whole value if there is none."""
    return call_guarded(_domain_of, value)


def ascii_domain(value: str) -> str | None:
    """Return the lowercased domain if it is LDH or A-labels only, else ``None``."""
    return call_guarded(_ascii_domain, value)


def _domain_of(value: str) -> str | None:
    """AU-Q33(a): ``None`` only when the text after the last ``@`` is empty."""
    text = exact_text(value)
    domain = text[text.rfind("@") + 1 :]
    return domain or None


def _ascii_domain(value: str) -> str | None:
    """AU-Q33(a): dot-separated RFC 5321 4.1.2 ``sub-domain`` labels only."""
    text = exact_text(value)
    if not all(_is_sub_domain(label) for label in text.split(".")):
        return None
    return ascii_lower(text)


def _is_sub_domain(label: str) -> bool:
    """``Let-dig [Ldh-str]``: ASCII LDH, not starting or ending with ``-``."""
    return (
        label.isascii()
        and label != ""
        and label[0] in LET_DIG
        and label[-1] in LET_DIG
        and all(c in KEYWORD for c in label)
    )
