# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Character classes and the address-form checks shared by parser and serializer.

Sources (cited, not copied; AU-Q19): RFC 5321 4.1.2 (``Keyword``,
``Ldh-str``, ``sub-domain``), RFC 2045 5.1 (``token``, ``tspecials``),
RFC 5322 3.2.3 (``atext``, ``dot-atom-text``), RFC 6376 3.5
(``domain-name``), RFC 6531 3.3 and RFC 6532 3.2 (UTF-8). PLAN.md 3.1 G3,
G10 and G14 record the decisions.

Non-ASCII characters count as token, atext and label characters. Callers
only see them with ``ascii_only=False``: the character scan refuses them
otherwise, and C1 controls and lone surrogates are always refused.
"""

_DIGITS = "0123456789"
_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

DIGITS = frozenset(_DIGITS)
WSP = frozenset(" \t")
# Keyword (Ldh-str): ASCII letters, digits and "-", not ending in "-".
KEYWORD = frozenset(_ALPHA + _DIGITS + "-")
LOWER_KEYWORD = frozenset(_ALPHA[26:] + _DIGITS + "-")
LET_DIG = frozenset(_ALPHA + _DIGITS)
# RFC 2045 token: printable US-ASCII except SPACE and the 15 tspecials.
TOKEN = frozenset(_ALPHA + _DIGITS + "!#$%&'*+-.^_`{|}~")
# The tspecials an unquoted pvalue may carry as PVALUE_TSPECIALS (AU-Q22).
PVALUE_TSPECIALS = frozenset("/=?")
# The tspecials outside atext an unquoted pvalue may also carry as
# PVALUE_TSPECIALS (AU-Q45); with "@" they take the run out of the address
# check (AU-Q53).
PVALUE_WIDE_TSPECIALS = frozenset(":[]<>")
# atext: the token characters minus "." plus "/ = ?" (G3).
ATEXT = (TOKEN - {"."}) | PVALUE_TSPECIALS
# Where an unquoted pvalue run ends (G10).
RUN_STOP = frozenset(' \t\r\n();"')

_NOT_FOUND = -1


def is_keyword(word: str) -> bool:
    """Return True for a non-empty ASCII ``Ldh-str`` not ending in ``-``."""
    return (
        word.isascii()
        and word != ""
        and not word.endswith("-")
        and all(c in KEYWORD for c in word)
    )


def is_sub_domain(label: str) -> bool:
    """``Let-dig [Ldh-str]``: ASCII LDH, not starting or ending with ``-``."""
    return (
        label.isascii()
        and label != ""
        and label[0] in LET_DIG
        and label[-1] in LET_DIG
        and all(c in KEYWORD for c in label)
    )


def is_lower_keyword(word: str) -> bool:
    """``is_keyword`` with lowercase letters only (the serialized form)."""
    return is_keyword(word) and all(c in LOWER_KEYWORD for c in word)


def is_token(word: str) -> bool:
    """Return True for a non-empty token (non-ASCII allowed, AU-Q18a)."""
    return word != "" and all(c in TOKEN or c >= "\x80" for c in word)


def dot_atom_fault(text: str, start: int, end: int) -> int:
    """Check ``text[start:end]`` as an optional dot-atom-text local-part.

    Return the offset of the first character that breaks it, or -1. An empty
    local-part is allowed (``[local-part] "@"``).
    """
    if start == end:
        return _NOT_FOUND
    i = start
    while True:
        j = i
        while j < end and (text[j] in ATEXT or text[j] >= "\x80"):
            j += 1
        if j == i:
            return i
        if j == end:
            return _NOT_FOUND
        if text[j] != ".":
            return j
        i = j + 1


def _label_end(text: str, i: int, end: int) -> int:
    while i < end and (text[i] in KEYWORD or text[i] >= "\x80"):
        i += 1
    return i


def domain_fault(text: str, start: int, end: int) -> int:
    """Check ``text[start:end]`` as a domain-name of two or more labels.

    Return the offset of the offending character, or -1 (AU-Q24, AU-Q38(2)):
    the character itself where one exists, the dot of a trailing dot, and
    the domain's first character for an empty or single-label domain.
    """
    i = start
    labels = 0
    while True:
        if i == end:
            return i - 1 if i > start else start
        if not (text[i] in LET_DIG or text[i] >= "\x80"):
            return i
        j = _label_end(text, i, end)
        if text[j - 1] == "-":
            return j - 1
        labels += 1
        if j == end:
            return _NOT_FOUND if labels > 1 else start
        if text[j] != ".":
            return j
        i = j + 1


def address_fault(text: str) -> bool:
    """Return True unless *text* is exactly ``[local-part] "@" domain-name``.

    The local-part is a dot-atom-text or a quoted-string (G10). Used by the
    serializer, which writes such a value bare (AU-Q17, AU-Q23).
    """
    return address_at(text) < 0


def address_at(text: str) -> int:
    """Return the offset of the ``@`` that ends the local-part, or -1.

    -1 unless *text* is exactly ``[local-part] "@" domain-name`` (see
    ``address_fault``); for a quoted local-part this is the ``@`` after the
    closing quote, not the first ``@``.
    """
    end = len(text)
    if text.startswith('"'):
        at = _quoted_span(text)
        if at >= end or text[at] != "@":
            return _NOT_FOUND
    else:
        at = text.find("@")
        if at < 0 or dot_atom_fault(text, 0, at) >= 0:
            return _NOT_FOUND
    return _NOT_FOUND if domain_fault(text, at + 1, end) >= 0 else at


def _quoted_span(text: str) -> int:
    """Return the end of the leading quoted-string, or the length of *text*."""
    i = 1
    end = len(text)
    while i < end:
        if text[i] == "\\":
            i += 2
        elif text[i] == '"':
            return i + 1
        else:
            i += 1
    return end
