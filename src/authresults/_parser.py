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
from ._errors import AuthResultsError, Deviation, ErrorReason, KnownShape
from ._lexical import (
    DIGITS,
    KEYWORD,
    PVALUE_TSPECIALS,
    PVALUE_WIDE_TSPECIALS,
    RUN_STOP,
    TOKEN,
    domain_fault,
    dot_atom_fault,
    is_keyword,
    is_sub_domain,
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
# RFC 7208 9.1 Received-SPF keys (docs/refused-shapes.md, AU-Q54).
_SPF_KEYS = frozenset(
    {
        "client-ip",
        "envelope-from",
        "helo",
        "receiver",
        "identity",
        "mechanism",
        "problem",
    }
)
_DOMAIN_END = frozenset({";", ""})
_LDH_DOT = KEYWORD | {"."}


@dataclass(slots=True)
class _Cursor:
    """The value being parsed, its delimited regions and the options."""

    text: str
    size: int
    ends: dict[int, int]
    options: "_Options"
    found: set[Deviation]
    arc: bool


def _start(value: object, options: "_Options", *, arc: bool) -> _Cursor:
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
    return _Cursor(text, len(text), ends, options, found, arc)


def parse_value(value: object, options: "_Options") -> AuthenticationResults:
    """Parse one ``Authentication-Results`` value."""
    cur = _start(value, options, arc=False)
    return _payload(cur, 0)


def parse_arc_value(value: object, options: "_Options") -> ArcAuthenticationResults:
    """Parse one ``ARC-Authentication-Results`` value (RFC 8617 4.1.1, G12)."""
    cur = _start(value, options, arc=True)
    instance, after = _instance(cur)
    return ArcAuthenticationResults(instance=instance, payload=_payload(cur, after))


# --- small readers ----------------------------------------------------------


def _peek(cur: _Cursor, i: int) -> str:
    return cur.text[i] if i < cur.size else ""


def _syntax(i: int, shape: KnownShape | None = None) -> AuthResultsError:
    return AuthResultsError(ErrorReason.SYNTAX, i, known_shape=shape)


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
        result, semicolon = _resinfo(cur, start, first=True, after_semicolon=False)
        return _results(cur, None, version_given=False, first=result, at=semicolon)
    version_given = after > end and _peek(cur, after) in DIGITS
    if version_given:
        after = _version(cur, after)
    if _peek(cur, after) != ";":
        # docs/refused-shapes.md: "Job ID appended to the authserv-id" and
        # "Authserv-id with no results and no none" (AU-Q51: quick to
        # re-enable, see _id_shape).
        shape = _id_shape(cur, after, end, is_token=is_token, version=version_given)
        raise _syntax(after, shape)
    return _results(cur, authserv_id, version_given=version_given, first=None, at=after)


def _id_shape(
    cur: _Cursor, after: int, end: int, *, is_token: bool, version: bool
) -> KnownShape | None:
    """Tag the refusal of a missing ``;`` after the authserv-id (error path).

    *after* is where the ``;`` belongs, *end* the end of the authserv-id,
    *version* whether an authres-version came between them.
    """
    if after == end and is_token and _peek(cur, after) == "/":
        # docs/refused-shapes.md, "Job ID appended to the authserv-id"
        # (AU-Q50): a / straight after an unquoted authserv-id.
        return KnownShape.AUTHSERV_ID_JOB_ID
    if after == cur.size and not version:
        # docs/refused-shapes.md, "Authserv-id with no results and no none"
        # (AU-Q51, AU-Q56): the authserv-id, then only CFWS, then the end.
        # Quick to re-enable: amend the pinning case "refused exim
        # authserv-id only" and accept here (a new deviation for the
        # missing "; none").
        return KnownShape.AUTHSERV_ID_ONLY
    return None


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
        result, at = _resinfo(cur, start, first=not results, after_semicolon=True)
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


def _resinfo(
    cur: _Cursor, start: int, *, first: bool, after_semicolon: bool
) -> tuple[Result, int]:
    """``methodspec [CFWS reasonspec] [CFWS 1*propspec]`` from the method.

    Returns the result and the offset of the next ``;`` or the end. *first*
    marks the payload's first resinfo, *after_semicolon* one that follows a
    ``;``; both only steer the shape tags on the error path.
    """
    end = _keyword_end(cur, start)
    method = _keyword(cur, start, end)
    after = _cfws(cur, end)
    version = None
    if _peek(cur, after) == "/":
        version, end = _method_version(cur, _cfws(cur, after + 1))
        after = _cfws(cur, end)
    if _peek(cur, after) != "=":
        # docs/refused-shapes.md: "Exim ARC-Authentication-Results leading
        # property" and "Bare domain between results" (see _dot_shape).
        direct = version is None and after == end
        shape = _dot_shape(cur, start, after, first=first) if direct else None
        raise _syntax(after, shape)
    if after_semicolon and method in _SPF_KEYS:
        try:
            return _result(cur, method, version, start, after)
        except AuthResultsError as err:
            # docs/refused-shapes.md, "Received-SPF keys written as results"
            # (AU-Q54): any SYNTAX inside a key=... resinfo after a ;.
            if err.reason is ErrorReason.SYNTAX:
                err.known_shape = KnownShape.SPF_DETAILS_AS_RESULTS
            raise
    return _result(cur, method, version, start, after)


def _dot_shape(cur: _Cursor, start: int, dot: int, *, first: bool) -> KnownShape | None:
    """Tag a refusal at a ``.`` straight after a method keyword (error path).

    One token of lookahead after the ``.`` (AU-Q56).
    """
    if _peek(cur, dot) != ".":
        return None
    token = dot + 1
    if first:
        # docs/refused-shapes.md, "Exim ARC-Authentication-Results leading
        # property" (AU-Q46): ptype.property= where the first method belongs.
        end = _run_end(cur, token, KEYWORD)
        is_property = (
            cur.arc
            and is_keyword(cur.text[token:end])
            and _peek(cur, _cfws(cur, end)) == "="
        )
        return KnownShape.EXIM_ARC_LEADING_PROPERTY if is_property else None
    # docs/refused-shapes.md, "Bare domain between results" (AU-Q48): the
    # method keyword at *start* and the rest of a domain, every label an
    # RFC 5321 sub-domain and the last with a letter, then ; or the end.
    end = _run_end(cur, token, _LDH_DOT)
    labels = cur.text[start:end].split(".")
    is_domain = (
        all(is_sub_domain(label) for label in labels)
        and any(c.isalpha() for c in labels[-1])
        and _peek(cur, _cfws(cur, end)) in _DOMAIN_END
    )
    return KnownShape.STRAY_DOMAIN_BETWEEN_RESULTS if is_domain else None


def _result(
    cur: _Cursor, method: str, version: int | None, start: int, equals: int
) -> tuple[Result, int]:
    """Read from the ``=`` after the methodspec to the next ``;`` or the end."""
    result_start = _cfws(cur, equals + 1)
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
            # docs/refused-shapes.md, "Received-SPF keys written as results"
            # (AU-Q54): the branch that refuses envelope-from=sender@... (the
            # @ after the result keyword); the tag is set in _resinfo.
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
            # docs/refused-shapes.md, the Zoho entry, Missing `;` between
            # results (AU-Q49, read differently, kept): spf=pass there is a
            # bare property of this result. Re-enabling the producer's reading
            # would end this result when the bare name is a method keyword
            # followed by = and a result keyword, and start a new resinfo
            # there (with a new deviation) instead of calling _bare.
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
    """Read a bare ``name=pvalue`` property, never registered (AU-Q27).

    docs/refused-shapes.md, the Zoho entry on a missing ``;`` (AU-Q49): the
    re-enabling change is made in ``_items`` before this is called; this
    reader itself stays as it is.
    """
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
    if at < 0:
        _check_token(cur, start, end, address=False)
    elif any(text[i] in PVALUE_WIDE_TSPECIALS for i in range(start, end)):
        # AU-Q53: an @ run with : [ ] < > is kept as written, not an address.
        _check_token(cur, start, end, address=True)
    else:
        _raise_at(dot_atom_fault(text, start, at))
        _raise_at(domain_fault(text, at + 1, end))
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


def _check_token(cur: _Cursor, start: int, end: int, *, address: bool) -> None:
    """Check a pvalue run not read as an address: token characters (G10).

    ``/ = ?`` (AU-Q22) and ``: [ ] < >`` (AU-Q45) are ``PVALUE_TSPECIALS``,
    flagged at the first one. In a run with ``@`` (*address*, AU-Q53) the
    ``@`` and ``/ = ?`` pass and the flag sits at the first ``: [ ] < >``.
    Brackets must pair up (AU-Q57, see ``_Brackets``). The flag and the
    first fault are found in one pass, then the leftmost wins, ``SYNTAX``
    on a tie (AU-Q16; ``<x`` is ``SYNTAX`` at the ``<`` in strict mode too).
    """
    text = cur.text
    flag = -1
    fault = -1
    brackets = _Brackets(start, end, angle=text[start] == "<")
    for i in range(start, end):
        c = text[i]
        if c in TOKEN or c >= "\x80":
            continue
        if c in PVALUE_WIDE_TSPECIALS or (c in PVALUE_TSPECIALS and not address):
            if flag < 0:
                flag = i
            if not brackets.accept(text, i):
                fault = i
                break
        elif not address or (c != "@" and c not in PVALUE_TSPECIALS):
            fault = i
            break
    else:
        fault = brackets.unclosed()
    if fault >= 0 and not 0 <= flag < fault:
        raise _syntax(fault)
    if flag >= 0:
        _deviate(cur, Deviation.PVALUE_TSPECIALS, flag)
    if fault >= 0:
        raise _syntax(fault)


@dataclass(slots=True)
class _Brackets:
    """AU-Q57: the bracket rule for one unquoted pvalue run ``[start, end)``.

    A ``<`` only as the first character, its ``>`` as the last; at most one
    ``[``, its ``]`` last or directly before that final ``>``. ``:`` and the
    other flagged characters always pass.
    """

    start: int
    end: int
    angle: bool  # the run opens with "<"
    closed: bool = False  # its ">" was seen
    square: int = -1  # offset of the open "[", or -1
    squares: int = 0  # how many "[" were seen

    def accept(self, text: str, i: int) -> bool:
        """Return False if the character at *i* breaks the rule."""
        c = text[i]
        if c == "<":
            return i == self.start
        if c == ">":
            self.closed = self.angle and i == self.end - 1
            return self.closed
        if c == "[":
            self.squares += 1
            self.square = i
            return self.squares == 1
        if c == "]":
            last = self.end - 1
            before_angle = self.angle and i == last - 1 and text[last] == ">"
            if self.square < 0 or not (i == last or before_angle):
                return False
            self.square = -1
        return True

    def unclosed(self) -> int:
        """At the end of the run: the offset of an unclosed opener, or -1."""
        if self.angle and not self.closed:
            return self.start
        return self.square


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
