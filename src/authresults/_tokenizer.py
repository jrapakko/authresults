# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""The stages before the grammar: character scan, then comments and quotes.

PLAN.md 2.1 and AU-Q16 fix the order: the character scan of the whole value
(``CONTROL_CHAR``, ``NON_ASCII``, ``LF_FOLDING``), the ``EMPTY`` check, then
one pass that delimits every top-level comment and quoted-string
(``UNTERMINATED_*``, ``NESTING_TOO_DEEP``), first fault met wins (AU-Q36).
Both are linear: comments use a depth counter, never recursion.

Folding (RFC 5322 3.2.2 and 4.2, G5, AU-Q29): CRLF followed by WSP is FWS,
LF followed by WSP is FWS plus ``LF_FOLDING``, any other CR or LF is a
control. Comments and quoted-strings are RFC 5322 3.2.2 and 3.2.4 (G4, G6).
"""

from ._errors import AuthResultsError, ErrorReason
from ._lexical import WSP
from ._unicode import is_space_or_format

_CR_LF = frozenset("\r\n")


def control(c: str) -> bool:
    """Return True for a character refused in every position.

    C0 (except HTAB, which callers allow), DEL, C1, lone surrogates (AU-Q29,
    AU-Q37), and non-ASCII space separators and format characters (AU-Q41).
    """
    return (
        c < " "
        or "\x7f" <= c <= "\x9f"
        or "\ud800" <= c <= "\udfff"
        or (c > "\x9f" and is_space_or_format(c))
    )


def _line_break(text: str, i: int) -> bool:
    """Check the CR or LF at *i*; return True if it is an LF fold.

    A CRLF not followed by WSP is a control at the CR, a bare LF not followed
    by WSP one at the LF (AU-Q38(1)).
    """
    if text[i] == "\r":
        if text[i + 1 : i + 2] != "\n" or text[i + 2 : i + 3] not in WSP:
            raise AuthResultsError(ErrorReason.CONTROL_CHAR, i)
        return False
    if i > 0 and text[i - 1] == "\r":
        return False
    if text[i + 1 : i + 2] not in WSP:
        raise AuthResultsError(ErrorReason.CONTROL_CHAR, i)
    return True


def scan(text: str, *, ascii_only: bool, strict: bool) -> bool:
    """Scan every character; return True if there is an LF fold.

    Raises ``CONTROL_CHAR``, ``NON_ASCII`` (with *ascii_only*) or, with
    *strict*, ``DEVIATION`` for an LF fold, at the leftmost offending
    character; a control wins over non-ASCII at the same character.
    """
    if text.isascii() and text.isprintable():
        return False
    lf_fold = False
    for i, c in enumerate(text):
        if " " <= c < "\x7f" or c == "\t":
            continue
        if c in _CR_LF:
            if _line_break(text, i):
                if strict:
                    raise AuthResultsError(ErrorReason.DEVIATION, i)
                lf_fold = True
            continue
        if control(c):
            raise AuthResultsError(ErrorReason.CONTROL_CHAR, i)
        if ascii_only:
            raise AuthResultsError(ErrorReason.NON_ASCII, i)
    return lf_fold


def _check_pair(text: str, i: int) -> None:
    """Refuse a quoted-pair backslash at *i* that escapes a CR or LF (obs-qp)."""
    if text[i + 1 : i + 2] in _CR_LF:
        raise AuthResultsError(ErrorReason.CONTROL_CHAR, i + 1)


def _comment_end(text: str, start: int, max_depth: int) -> int:
    """Return the offset after the comment opened at *start*."""
    depth = 0
    i = start
    end = len(text)
    while i < end:
        c = text[i]
        if c == "(":
            depth += 1
            if depth > max_depth:
                raise AuthResultsError(ErrorReason.NESTING_TOO_DEEP, i)
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        elif c == "\\":
            _check_pair(text, i)
            i += 1
        i += 1
    raise AuthResultsError(ErrorReason.UNTERMINATED_COMMENT, start)


def _quoted_end(text: str, start: int) -> int:
    """Return the offset after the quoted-string opened at *start*."""
    i = start + 1
    quote = text.find('"', i)
    while quote >= 0:
        backslash = text.find("\\", i, quote)
        if backslash < 0:
            return quote + 1
        _check_pair(text, backslash)
        i = backslash + 2
        if quote < i:
            quote = text.find('"', i)
    raise AuthResultsError(ErrorReason.UNTERMINATED_QUOTED_STRING, start)


def delimit(text: str, max_depth: int) -> dict[int, int]:
    """Map the start of each top-level comment and quoted-string to its end.

    Each ``find`` resumes after the last region, so the pass is linear.
    """
    ends: dict[int, int] = {}
    paren = text.find("(")
    quote = text.find('"')
    while paren >= 0 or quote >= 0:
        if quote < 0 or 0 <= paren < quote:
            start = paren
            end = _comment_end(text, paren, max_depth)
        else:
            start = quote
            end = _quoted_end(text, quote)
        ends[start] = end
        if 0 <= paren < end:
            paren = text.find("(", end)
        if 0 <= quote < end:
            quote = text.find('"', end)
    return ends


def unquote(text: str, start: int, end: int) -> str:
    """Return the content of the quoted-string ``text[start:end]`` (G6).

    Quoted-pairs are resolved and fold line breaks removed (WSP kept). The
    character scan guarantees every CR is followed by LF.
    """
    i = start + 1
    stop = end - 1
    inner = text[i:stop]
    if "\\" not in inner and "\n" not in inner:
        return inner
    pieces: list[str] = []
    backslash = _find(text, "\\", i, stop)
    lf = _find(text, "\n", i, stop)
    while i < stop:
        if backslash < lf:
            pieces.append(text[i:backslash])
            pieces.append(text[backslash + 1])
            i = backslash + 2
            backslash = _find(text, "\\", i, stop)
        elif lf < stop:
            pieces.append(text[i:lf].removesuffix("\r"))
            i = lf + 1
            lf = _find(text, "\n", i, stop)
        else:
            pieces.append(text[i:stop])
            i = stop
    return "".join(pieces)


def _find(text: str, char: str, start: int, stop: int) -> int:
    found = text.find(char, start, stop)
    return stop if found < 0 else found
