# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""The grammar of RFC 8601 2.2 (and the RFC 8617 3.9 instance), one pass.

The rules are cited, not copied (AU-Q19); PLAN.md section 3 and 3.1 (G1 to
G16) record every decision, and the AU-Q numbers below point to section 11.
The parser reads characters left to right with constant lookahead. It never
backtracks and never recurses; comments and quoted-strings were delimited
beforehand (``_tokenizer.delimit``), so skipping one is a single jump.

Two lexical classes (G3): a keyword (``Ldh-str``, ASCII only) where the
ABNF has ``Keyword`` or a literal, a token (RFC 2045) where it has
``value``; a pvalue is a token, a quoted-string or an address (G10).
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING

from . import _registry
from ._checks import ascii_lower, exact_text
from ._errors import AuthResultsError, Deviation, ErrorReason
from ._lexical import (
    DIGITS,
    KEYWORD,
    PVALUE_TSPECIALS,
    RUN_STOP,
    TOKEN,
    domain_fault,
    dot_atom_fault,
    is_keyword,
)
from ._model import ArcAuthenticationResults, AuthenticationResults, Property, Result
from ._tokenizer import delimit, scan, unquote

if TYPE_CHECKING:
    from ._api import _Options

_FWS = frozenset(" \t\r\n")
_METHOD_FOLLOW = frozenset("=/")
_MAX_METHOD_VERSION_DIGITS = 9  # AU-Q24
_MAX_INSTANCE_DIGITS = 2  # RFC 8617 3.9: 1*2DIGIT
_MAX_INSTANCE = 50  # RFC 8617 3.9 and 4.2.1


@dataclass(slots=True)
class _Cursor:
    """The value being parsed, its delimited regions and the options."""

    text: str
    size: int
    ends: dict[int, int]
    options: "_Options"
    found: set[Deviation]


def _start(value: object, options: "_Options") -> _Cursor:
    """Type, length, character scan, ``EMPTY``, then the delimiting pass."""
    text = exact_text(value)
    if len(text) > options.max_length:
        raise AuthResultsError(ErrorReason.TOO_LONG, options.max_length)
    found: set[Deviation] = set()
    if scan(text, ascii_only=options.ascii_only, strict=options.strict_syntax):
        found.add(Deviation.LF_FOLDING)
    if not text.strip(" \t\r\n"):
        raise AuthResultsError(ErrorReason.EMPTY)
    ends = delimit(text, options.max_comment_depth)
    return _Cursor(text, len(text), ends, options, found)


def parse_value(value: object, options: "_Options") -> AuthenticationResults:
    """Parse one ``Authentication-Results`` value."""
    cur = _start(value, options)
    return _payload(cur, 0)


def parse_arc_value(value: object, options: "_Options") -> ArcAuthenticationResults:
    """Parse one ``ARC-Authentication-Results`` value (RFC 8617 4.1.1, G12)."""
    cur = _start(value, options)
    instance, after = _instance(cur)
    return ArcAuthenticationResults(instance=instance, payload=_payload(cur, after))


# --- small readers ----------------------------------------------------------


def _peek(cur: _Cursor, i: int) -> str:
    return cur.text[i] if i < cur.size else ""


def _syntax(i: int) -> AuthResultsError:
    return AuthResultsError(ErrorReason.SYNTAX, i)


def _cfws(cur: _Cursor, i: int) -> int:
    """Skip FWS and comments (the scan already checked every fold)."""
    text = cur.text
    while i < cur.size:
        c = text[i]
        if c in _FWS:
            i += 1
        elif c == "(":
            i = cur.ends[i]
        else:
            break
    return i


def _run_end(cur: _Cursor, i: int, chars: frozenset[str]) -> int:
    text = cur.text
    while i < cur.size and text[i] in chars:
        i += 1
    return i


def _keyword_end(cur: _Cursor, i: int) -> int:
    """Return the end of the keyword at *i*; ``SYNTAX`` there if malformed (G3).

    The run is built from ASCII keyword characters only, so the
    ``ascii_lower`` applied to it later can map nothing else.
    """
    end = _run_end(cur, i, KEYWORD)
    if end == i or cur.text[end - 1] == "-":
        raise _syntax(i)
    return end


def _keyword(cur: _Cursor, i: int, end: int) -> str:
    return ascii_lower(cur.text[i:end])


def _token_end(cur: _Cursor, i: int) -> int:
    text = cur.text
    while i < cur.size and (text[i] in TOKEN or text[i] >= "\x80"):
        i += 1
    return i


def _value(cur: _Cursor, i: int) -> tuple[str, int, bool]:
    """Read a ``value`` at *i*: (content, end, is_token); empty is ``SYNTAX``."""
    if _peek(cur, i) == '"':
        end = cur.ends[i]
        return unquote(cur.text, i, end), end, False
    end = _token_end(cur, i)
    if end == i:
        raise _syntax(i)
    return cur.text[i:end], end, True


def _deviate(cur: _Cursor, deviation: Deviation, i: int) -> None:
    if cur.options.strict_syntax:
        raise AuthResultsError(ErrorReason.DEVIATION, i)
    cur.found.add(deviation)


def _unregistered(cur: _Cursor, i: int) -> None:
    if cur.options.require_registered:
        raise AuthResultsError(ErrorReason.UNREGISTERED, i)


def _digits_end(cur: _Cursor, i: int) -> int:
    end = _run_end(cur, i, DIGITS)
    if end == i:
        raise _syntax(i)
    return end


# --- the payload ------------------------------------------------------------


def _payload(cur: _Cursor, i: int) -> AuthenticationResults:
    """``[CFWS] authserv-id [CFWS version] (no-result / 1*resinfo) [CFWS]``."""
    start = _cfws(cur, i)
    if start == cur.size:
        raise _syntax(start)
    authserv_id, end, is_token = _value(cur, start)
    after = _cfws(cur, end)
    if is_token and _peek(cur, after) in _METHOD_FOLLOW and is_keyword(authserv_id):
        # AU-Q35, AU-Q39: a keyword-shaped first token followed by = or / is
        # the first method; the authserv-id is missing.
        _deviate(cur, Deviation.MISSING_AUTHSERV_ID, start)
        result, semicolon = _resinfo(cur, start)
        return _results(cur, None, version_given=False, first=result, at=semicolon)
    version_given = after > end and _peek(cur, after) in DIGITS
    if version_given:
        after = _version(cur, after)
    if _peek(cur, after) != ";":
        raise _syntax(after)
    return _results(cur, authserv_id, version_given=version_given, first=None, at=after)


def _version(cur: _Cursor, i: int) -> int:
    """``authres-version``: digits compared without ``int()`` (AU-Q24)."""
    end = _digits_end(cur, i)
    if cur.text[i:end].lstrip("0") != "1":
        raise AuthResultsError(ErrorReason.UNSUPPORTED_VERSION, i)
    return _cfws(cur, end)


def _is_none(cur: _Cursor, i: int) -> bool:
    """``none`` at *i* as the no-result (G7), with only CFWS after it."""
    end = _run_end(cur, i, KEYWORD)
    if _keyword(cur, i, end) != "none":
        return False
    after = _cfws(cur, end)
    if _peek(cur, after) in _METHOD_FOLLOW:
        return False  # the method "none" (AU-Q21)
    if after != cur.size:
        raise _syntax(after)
    return True


def _results(
    cur: _Cursor,
    authserv_id: str | None,
    *,
    version_given: bool,
    first: Result | None,
    at: int,
) -> AuthenticationResults:
    """Read the ``;``-separated results; *at* is the first ``;`` or the end."""
    results: list[Result] = [] if first is None else [first]
    none = False
    while at < cur.size:
        semicolon = at
        start = _cfws(cur, at + 1)
        if start == cur.size and results:
            _deviate(cur, Deviation.TRAILING_SEMICOLON, semicolon)
            break
        if not results and _is_none(cur, start):
            none = True
            break
        if len(results) == cur.options.max_results:
            raise AuthResultsError(ErrorReason.TOO_MANY_RESULTS, semicolon)
        result, at = _resinfo(cur, start)
        results.append(result)
    return AuthenticationResults(
        authserv_id=authserv_id,
        version=1,
        version_given=version_given,
        none=none,
        results=tuple(results),
        deviations=frozenset(cur.found),
    )


# --- one result -------------------------------------------------------------


def _method_version(cur: _Cursor, i: int) -> tuple[int, int]:
    """``method-version`` at *i*: (value, end); over 9 digits is ``SYNTAX``."""
    end = _digits_end(cur, i)
    significant = cur.text[i:end].lstrip("0")
    if len(significant) > _MAX_METHOD_VERSION_DIGITS:
        raise _syntax(i)
    return (int(significant) if significant else 0), end


def _resinfo(cur: _Cursor, start: int) -> tuple[Result, int]:
    """``methodspec [CFWS reasonspec] [CFWS 1*propspec]`` from the method.

    Returns the result and the offset of the next ``;`` or the end.
    """
    end = _keyword_end(cur, start)
    method = _keyword(cur, start, end)
    after = _cfws(cur, end)
    version = None
    if _peek(cur, after) == "/":
        version, end = _method_version(cur, _cfws(cur, after + 1))
        after = _cfws(cur, end)
    if _peek(cur, after) != "=":
        raise _syntax(after)
    result_start = _cfws(cur, after + 1)
    end = _keyword_end(cur, result_start)
    result = _keyword(cur, result_start, end)
    registered = _registry.result_registered(method, version, result)
    if not registered:
        _unregistered(cur, start)
    reason, properties, after = _items(cur, method, end)
    return Result(
        method=method,
        method_version=version,
        result=result,
        reason=reason,
        properties=properties,
        registered=registered,
    ), after


def _items(
    cur: _Cursor, method: str, i: int
) -> tuple[str | None, tuple[Property, ...], int]:
    """Read the optional reason and the properties after a result ending at *i*.

    CFWS is required before the reason and before the first property, and
    optional between properties (G4 spots 8, 10 and 12).
    """
    reason: str | None = None
    properties: list[Property] = []
    need_cfws = True
    while True:
        start = _cfws(cur, i)
        if _peek(cur, start) in {"", ";"}:
            return reason, tuple(properties), start
        if need_cfws and start == i:
            raise _syntax(start)
        end = _keyword_end(cur, start)
        after = _cfws(cur, end)
        follow = _peek(cur, after)
        if follow == ".":
            _count(cur, properties, start)
            prop, i = _propspec(cur, method, start, end, after)
        elif follow == "=" and _keyword(cur, start, end) == "reason":
            if reason is not None:
                raise AuthResultsError(ErrorReason.DUPLICATE_REASON, start)
            if properties:
                raise _syntax(start)  # AU-Q6, AU-Q26
            reason, i, _ = _value(cur, _cfws(cur, after + 1))
            need_cfws = True
            continue
        elif follow == "=":
            _deviate(cur, Deviation.BARE_PROPERTY, start)
            _count(cur, properties, start)
            prop, i = _bare(cur, start, end, after)
        else:
            raise _syntax(after)
        properties.append(prop)
        need_cfws = False


def _count(cur: _Cursor, properties: list[Property], start: int) -> None:
    if len(properties) == cur.options.max_properties:
        raise AuthResultsError(ErrorReason.TOO_MANY_PROPERTIES, start)


def _propspec(
    cur: _Cursor, method: str, start: int, end: int, dot: int
) -> tuple[Property, int]:
    """``ptype [CFWS] "." [CFWS] property [CFWS] "=" pvalue`` (G9)."""
    name_start = _cfws(cur, dot + 1)
    name_end = _keyword_end(cur, name_start)
    equals = _cfws(cur, name_end)
    if _peek(cur, equals) != "=":
        raise _syntax(equals)
    value, raw, quoted, after = _pvalue(cur, equals + 1)
    ptype = _keyword(cur, start, end)
    name = _keyword(cur, name_start, name_end)
    registered = _registry.property_registered(method, ptype, name)
    if not registered:
        _unregistered(cur, start)
    return Property(
        ptype=ptype,
        name=name,
        value=value,
        raw=raw,
        quoted=quoted,
        registered=registered,
    ), after


def _bare(cur: _Cursor, start: int, end: int, equals: int) -> tuple[Property, int]:
    """Read a bare ``name=pvalue`` property, never registered (AU-Q27)."""
    value, raw, quoted, after = _pvalue(cur, equals + 1)
    _unregistered(cur, start)
    return Property(
        ptype=None,
        name=_keyword(cur, start, end),
        value=value,
        raw=raw,
        quoted=quoted,
        registered=False,
    ), after


# --- pvalue -----------------------------------------------------------------


def _pvalue(cur: _Cursor, i: int) -> tuple[str, str, bool, int]:
    """Read a pvalue after ``=``: (value, raw, quoted, end) (G10).

    A quoted-string, an address ``[local-part] "@" domain-name`` (value is
    its source text with folds unfolded, raw the exact text; AU-Q23,
    AU-Q42), or a token, with ``/ = ?`` accepted as
    ``PVALUE_TSPECIALS`` (AU-Q22). No CFWS inside (AU-Q18b).
    """
    start = _cfws(cur, i)
    text = cur.text
    if _peek(cur, start) == '"':
        end = cur.ends[start]
        if _peek(cur, end) != "@":
            return unquote(text, start, end), text[start:end], True, end
        end = _address_end(cur, end + 1)
        raw = text[start:end]
        # AU-Q42: folds in the quoted local-part are unfolded by removing the
        # line break (RFC 5322 2.2.3); the scan made every CR part of a CRLF.
        return raw.replace("\r\n", "").replace("\n", ""), raw, False, end
    end = start
    while end < cur.size and text[end] not in RUN_STOP:
        end += 1
    if end == start:
        raise _syntax(start)
    at = text.find("@", start, end)
    if at >= 0:
        _raise_at(dot_atom_fault(text, start, at))
        _raise_at(domain_fault(text, at + 1, end))
    else:
        _check_token(cur, start, end)
    return text[start:end], text[start:end], False, end


def _address_end(cur: _Cursor, domain: int) -> int:
    """Check the domain-name after a quoted local-part's ``@``."""
    end = domain
    while end < cur.size and cur.text[end] not in RUN_STOP:
        end += 1
    _raise_at(domain_fault(cur.text, domain, end))
    return end


def _raise_at(fault: int) -> None:
    if fault >= 0:
        raise _syntax(fault)


def _check_token(cur: _Cursor, start: int, end: int) -> None:
    """Check a pvalue run with no ``@``: token characters, ``/ = ?`` flagged."""
    text = cur.text
    flagged = False
    for i in range(start, end):
        c = text[i]
        if c in TOKEN or c >= "\x80":
            continue
        if c not in PVALUE_TSPECIALS:
            raise _syntax(i)
        if not flagged:
            _deviate(cur, Deviation.PVALUE_TSPECIALS, i)
            flagged = True


# --- ARC --------------------------------------------------------------------


def _instance(cur: _Cursor) -> tuple[int, int]:
    """``instance [CFWS] ";"`` (RFC 8617 3.9, 4.1.1; G12, AU-Q32).

    Returns the instance and the offset after the ``;``.
    """
    i = _cfws(cur, 0)
    if _peek(cur, i) != "i":  # %s"i": case-sensitive
        raise _syntax(i)
    i = _cfws(cur, i + 1)
    if _peek(cur, i) != "=":
        raise _syntax(i)
    start = _cfws(cur, i + 1)
    end = _digits_end(cur, start)
    if end - start > _MAX_INSTANCE_DIGITS:
        raise AuthResultsError(ErrorReason.BAD_ARC_INSTANCE, start)
    instance = int(cur.text[start:end])
    if not 1 <= instance <= _MAX_INSTANCE:
        raise AuthResultsError(ErrorReason.BAD_ARC_INSTANCE, start)
    i = _cfws(cur, end)
    if _peek(cur, i) != ";":
        raise _syntax(i)
    return instance, i + 1
