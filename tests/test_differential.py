# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Differential test against authres 1.2.0 (PLAN.md 4; AL3b row).

authres is a dev-only oracle: it is in the dev group, never in the wheel.
On inputs both parsers accept, the normalised tuple (authserv-id, version
given, then per result method, method version, result, reason and the
``(ptype, name, value)`` properties) must match. Every difference that is
normalised away or set aside below has its own test that runs authres and
shows it; a set-aside applies only when the two parses actually differ and
the difference has that exact shape.

Known differences:

1. authres drops a bare property (``action=none``); we keep it, flagged
   ``BARE_PROPERTY`` (spike 4a).
2. authres raises ``RecursionError`` on deep comment nesting; we raise
   ``AuthResultsError`` (``NESTING_TOO_DEEP``).
3. authres matches ``none`` and ``reason`` as prefixes (spike 4 item 4), so
   it refuses ``nonexistent=pass``, ``reasonable.x=y`` and the method
   ``none`` (``none=pass``, ``none/1=pass``); we match whole keywords (G7,
   G8) and read ``none`` as a method (AU-Q21).
4. authres accepts only the ptypes smtp, header, body and policy, and
   silently drops a property with another ptype, IANA's ``dns`` included
   (the header still parses); we keep it.
5. authres keeps quoted-pair escapes in values; we resolve them and keep the
   source in ``raw`` (G6).
6. Found at AL3b: authres drops a quoted pvalue unless ``;`` or the end
   follows it (its look-ahead); the properties after it are kept. We keep
   it (G4 spot 12, AU-Q25).
7. Found at AL3b: authres reads too little of a run of comments with FWS
   between them (each of its CFWS calls takes at most one FWS, of one
   fold). Where the run is longer than its calls at that spot can take,
   what follows is lost: ``dkim=pass (a) (b) reason=x`` loses the reason,
   ``header.s="a" ()\\r\\n \\r\\n ()`` loses the property. RFC 5322
   3.2.2 CFWS is any run of FWS and comments (G4), and we read it all.
   A comment with FWS on both sides where it reads only once fails the
   same way (`` () mx.example; none`` is refused). Shorter runs, and runs
   at spots it reads twice, agree.
8. Found at AL3b: authres refuses a quoted authserv-id and a token one that
   is not a dot-atom (``.a``, ``a..b``); RFC 8601 2.2 makes the authserv-id
   a ``value`` (token or quoted-string), and we read both (AU-Q30).
9. Found at AL3b: authres refuses an empty quoted reason (``reason=""``)
   and misreads an empty quoted pvalue followed by a property, taking the
   next property's text as its value; ``""`` is a valid quoted-string (G6).
10. A value with no authserv-id: authres refuses it when properties follow
    the first result (``spf=pass smtp.mailfrom=x.example``), and otherwise
    reads the first methodspec as a dot-atom authserv-id (``dkim/1=pass;
    spf=fail`` gives the id ``dkim/1=pass``); we read it and record
    ``MISSING_AUTHSERV_ID`` (AU-Q35).

11. Found at AL3b: authres refuses a leading zero in the authserv-id version
    (``mx.example 01; none`` raises ``UnsupportedVersionError``); we read it
    as version 1 (AU-Q24). Leading zeros in a method version agree.
12. Found at AL3c: authres refuses ``:``, ``[``, ``]``, ``<`` and ``>`` in
    an unquoted pvalue (``smtp.remote-ip=2001:db8::1``, ``smtp.mailfrom=<>``,
    ``smtp.mailfrom=a@[192.0.2.1]``); we keep the value as written, flagged
    ``PVALUE_TSPECIALS``, when its brackets pair up (AU-Q45, AU-Q53, AU-Q57).

Normalised away or checked, each with its test:

- authres lowercases the authserv-id. The ids are compared lowercased, and
  ours is checked separately against the source text (AU-Q30), so a wrong
  case on our side still fails.
- It keeps fold line breaks in quoted pvalues (we unfold, G6).
- It writes HTAB, CR and LF in a reason as ``?``. Set aside only for a
  result whose own reason, read from the source outside comments and
  quoted-strings, holds one of them, and only if each side equals its own
  reading of that source text.
- It reads ``""@x.example`` as ``@x.example`` (we keep the source text,
  AU-Q23).

Blind spot: where authres drops a property (1, 4, 6), our reading of it is
not checked by this test; the case table and the properties cover it.

The generated values avoid the shapes of 3, 8, 9 and 11 (``models(
compatible=True)``, no leading zero in the authserv-id version) and of 12
(the canonical form quotes a value with these characters) and put one
comment per CFWS spot (7), so authres accepts every generated value and the
comparison runs.
"""

import dataclasses
import itertools
import re
from collections.abc import Iterator
from typing import Any

import authres  # type: ignore[import-untyped]
import pytest
from hypothesis import given
from hypothesis import strategies as st

from authresults import (
    AuthenticationResults,
    AuthResultsError,
    Deviation,
    ErrorReason,
    Property,
    parse,
)

from . import (
    cases_grammar,
    cases_redteam,
    cases_rfc8601,
    cases_spike,
    cases_vendor,
)
from ._hypothesis_profiles import TIMEOUT
from ._strategies import (
    AUTHRES_PTYPES,
    Slot,
    cfws,
    join,
    layout_of,
    models,
    slot_indexes,
)

pytestmark = pytest.mark.timeout(TIMEOUT)

_MAX_ORACLE_LENGTH = 2000  # authres re-scans the rest of the text per token


def _authres(value: str) -> object | None:
    """authres's parse, or None if it refuses (any exception counts)."""
    try:
        header: object = authres.AuthenticationResultsHeader.parse_value(value)
    except Exception:  # noqa: BLE001 - the oracle's refusals are not checked
        return None
    return header


def _ours(value: str) -> AuthenticationResults | None:
    try:
        return parse(value)
    except AuthResultsError:
        return None


# Difference 7: a comment, FWS, then another comment ahead of "reason".
_PAIR = re.compile(r"\\(.)", re.DOTALL)
_NON_PRINTABLE = re.compile(r"[^\x20-\x7e]")


def _oracle_text(text: str | None) -> str | None:
    """authres's value as we would give it: folds removed and, except in an
    address with a quoted local-part (kept verbatim, AU-Q23), escapes
    resolved."""
    if text is None:
        return None
    text = text.replace("\r\n", "").replace("\n", "")
    if text.startswith('"') and '"@' in text:
        return text
    return _PAIR.sub(r"\1", text)


def _normalised_theirs(header: object) -> list[Any]:
    results = []
    for r in header.results:  # type: ignore[attr-defined]
        version = None if r.version is None else int(r.version)
        reason = _oracle_text(r.reason)
        properties = tuple(
            (p.type, p.name, _oracle_text(p.value)) for p in r.properties
        )
        results.append([r.method, version, r.result, reason, properties])
    return [header.authserv_id, header.version is not None, results]  # type: ignore[attr-defined]


def _normalised_ours(
    model: AuthenticationResults, *, unreadable: bool = False
) -> list[Any]:
    """Our parse as nested lists, the authserv-id lowercased as authres
    gives it; *unreadable* leaves out the properties authres drops
    (differences 1, 4 and 6)."""
    results = []
    for r in model.results:
        properties = tuple(
            (
                p.ptype,
                p.name,
                p.value.removeprefix('""') if p.value.startswith('""@') else p.value,
            )
            for i, p in enumerate(r.properties)
            if not (unreadable and _unreadable(r.properties, i))
        )
        results.append([r.method, r.method_version, r.result, r.reason, properties])
    authserv_id = None if model.authserv_id is None else model.authserv_id.lower()
    return [authserv_id, model.version_given, results]


def _unreadable(properties: tuple[Property, ...], i: int) -> bool:
    p = properties[i]
    return (
        p.ptype is None  # difference 1
        or p.ptype not in AUTHRES_PTYPES  # difference 4
        or (p.quoted and i < len(properties) - 1)  # difference 6
    )


# --- the source text, read independently of both parsers ------------------


@dataclasses.dataclass(frozen=True)
class _Source:
    """Top-level structure of a value: the ``;``-separated segments, and the
    spans of the comments and quoted-strings outside any other one."""

    segments: tuple[tuple[int, int], ...]
    comments: tuple[tuple[int, int], ...]
    quoted: tuple[tuple[int, int], ...]


def _span_end(value: str, start: int) -> int:
    """The end of the comment or quoted-string opening at *start*."""
    quote = value[start] == '"'
    depth = 0
    i = start
    while i < len(value):
        c = value[i]
        if c == "\\":
            i += 2
            continue
        if quote and c == '"' and i > start:
            return i + 1
        if not quote and c == "(":
            depth += 1
        elif not quote and c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(value)


def _source(value: str) -> _Source:
    cuts = [-1]
    comments: list[tuple[int, int]] = []
    quoted: list[tuple[int, int]] = []
    i = 0
    while i < len(value):
        c = value[i]
        if c in '("':
            end = _span_end(value, i)
            (quoted if c == '"' else comments).append((i, end))
            i = end
            continue
        if c == ";":
            cuts.append(i)
        i += 1
    cuts.append(len(value))
    segments = tuple((a + 1, b) for a, b in itertools.pairwise(cuts))
    return _Source(segments, tuple(comments), tuple(quoted))


def _skip_cfws(value: str, i: int, src: _Source, end: int) -> int:
    while i < end:
        if value[i] in " \t\r\n":
            i += 1
            continue
        span = next((e for s, e in src.comments if s == i), None)
        if span is None:
            break
        i = span
    return i


def _inside(i: int, spans: tuple[tuple[int, int], ...]) -> bool:
    return any(s <= i < e for s, e in spans)


def _value_at(value: str, i: int, src: _Source, end: int) -> tuple[int, int]:
    """The span of the token or quoted-string at *i*."""
    if i < end and value[i] == '"':
        return i, next(e for s, e in src.quoted if s == i)
    j = i
    while j < end and value[j] not in ' \t\r\n();"':
        j += 1
    return i, j


def _reason_raw(
    value: str, src: _Source, segment: tuple[int, int]
) -> tuple[int, str] | None:
    """The offset of the ``reason`` keyword and the raw text of its value in
    *segment*, read outside comments and quoted-strings (G8)."""
    start, end = segment
    lower = value.lower()
    at = lower.find("reason", start, end)
    while at >= 0:
        boundary = at > start and value[at - 1] in " \t\r\n)"
        if boundary and not _inside(at, src.comments + src.quoted):
            j = _skip_cfws(value, at + len("reason"), src, end)
            if j < end and value[j] == "=":
                k = _skip_cfws(value, j + 1, src, end)
                a, b = _value_at(value, k, src, end)
                return at, value[a:b]
        at = lower.find("reason", at + 1, end)
    return None


def _source_id(value: str, src: _Source) -> str:
    """The authserv-id as written: a token, or a quoted-string's content."""
    start, end = src.segments[0]
    a, b = _value_at(value, _skip_cfws(value, start, src, end), src, end)
    raw = value[a:b]
    if raw.startswith('"'):
        return _PAIR.sub(r"\1", raw[1:-1].replace("\r\n", "").replace("\n", ""))
    return raw


def _our_reason(raw: str) -> str:
    """Our reading of a reason's raw value (G6: unfold, resolve pairs)."""
    if not raw.startswith('"'):
        return raw
    return _PAIR.sub(r"\1", raw[1:-1].replace("\r\n", "").replace("\n", ""))


def _their_reason(raw: str) -> str:
    """authres's reading, as ``_oracle_text`` gives it: every character
    outside printable ASCII (CR, LF, HTAB) becomes ``?``, pairs then resolved."""
    if not raw.startswith('"'):
        return raw
    return _PAIR.sub(r"\1", _NON_PRINTABLE.sub("?", raw[1:-1]))


def _comment_run_before(
    src: _Source, segment: tuple[int, int], at: int, value: str
) -> bool:
    """True if two top-level comments, with only FWS between them, sit in
    *segment* before offset *at* (difference 7's shape)."""
    inside = [c for c in src.comments if segment[0] <= c[0] and c[1] <= at]
    return any(
        b[0] > a[1]
        and value[a[1] : b[0]].strip(" \t\r\n") == ""
        and value[a[1] : b[0]] != ""
        for a, b in itertools.pairwise(inside)
    )


def _explain_reasons(
    mine: list[Any], other: list[Any], value: str, src: _Source, first: int
) -> list[str]:
    """Set aside reason mismatches of the two known shapes (7, and HTAB or
    a fold), each checked against that result's own reason in the source."""
    labels = []
    for index, (mine_r, other_r) in enumerate(zip(mine, other, strict=True)):
        if mine_r[3] == other_r[3]:
            continue
        segment = src.segments[first + index]
        found = _reason_raw(value, src, segment)
        if found is None or mine_r[3] != _our_reason(found[1]):
            continue
        at, raw = found
        if other_r[3] is None and _comment_run_before(src, segment, at, value):
            mine_r[3] = None
            labels.append("CFWS before reason (7)")
        elif any(c in raw for c in "\t\r\n") and other_r[3] == _their_reason(raw):
            mine_r[3] = other_r[3]
            labels.append("HTAB or fold in a reason")
    return labels


def _explain(ours: AuthenticationResults, theirs: object, value: str) -> str:
    """Name the known differences that account for a mismatch, or fail."""
    src = _source(value)
    if ours.authserv_id is not None:
        # authres lowercases the id; ours must be the source text exactly.
        assert ours.authserv_id == _source_id(value, src), value
    mine = _normalised_ours(ours)
    other = _normalised_theirs(theirs)
    if mine == other:
        return "compared"
    labels = []
    adjusted = _normalised_ours(ours, unreadable=True)
    if adjusted != mine:
        labels.append("properties authres drops (1, 4, 6)")
    first_segment = 1
    if ours.authserv_id is None:
        first_segment = 0
        if adjusted[2]:
            # Difference 10: authres takes the first methodspec as the id.
            first = adjusted[2].pop(0)
            adjusted[0] = other[0]
            assert other[0] in {
                f"{first[0]}/{first[1]}={first[2]}",
                f"{first[0]}={first[2]}",
            }, value
            first_segment = 1
            labels.append("missing authserv-id (10)")
    if len(adjusted[2]) == len(other[2]):
        labels += _explain_reasons(adjusted[2], other[2], value, src, first_segment)
    assert labels, value
    assert adjusted == other, value
    return "set aside: " + ", ".join(sorted(set(labels)))


def _compare(value: str) -> str:
    """Compare both parsers on *value*; return what happened."""
    ours = _ours(value)
    theirs = _authres(value) if len(value) <= _MAX_ORACLE_LENGTH else None
    if ours is None or theirs is None:
        return "not both accepted"
    return _explain(ours, theirs, value)


def _corpus() -> Iterator[str]:
    for module in (
        cases_spike,
        cases_rfc8601,
        cases_grammar,
        cases_vendor,
        cases_redteam,
    ):
        for case in module.CASES:
            if case.call == "parse" and type(case.value) is str and not case.kwargs:
                yield case.value


_CORPUS = sorted(set(_corpus()))


def test_case_table_values_agree() -> None:
    outcomes = [_compare(value) for value in _CORPUS]
    # The comparison must actually happen for a good share of the table.
    assert outcomes.count("compared") >= 50  # noqa: PLR2004


@given(data=st.data())
def test_generated_values_agree(data: st.DataObject) -> None:
    model = data.draw(models(compatible=True))
    # The canonical form: authres accepts it, and only the known shapes differ.
    assert _compare(model.to_value()) != "not both accepted"
    # Leading zeros in method versions only (difference 11).
    layout = layout_of(
        model,
        zeros=data.draw(st.integers(0, 2)),
        version_zeros=0,
        pair_every=data.draw(st.sampled_from((0, 0, 1, 2))),
    )
    chosen = data.draw(st.lists(st.sampled_from(slot_indexes(layout)), max_size=3))
    fills = {}
    for index in chosen:
        slot = layout[index]
        assert isinstance(slot, Slot)
        # One comment per spot, FWS on one side: longer runs are difference 7.
        fills[index] = data.draw(cfws(slot, ascii_only=True, tight=True))
    assert _compare(join(layout, fills)) != "not both accepted"


# --- each known difference, shown against authres 1.2.0 ---------------------


def test_difference_1_bare_property_dropped_by_authres() -> None:
    value = "mx.example; dmarc=pass action=none header.from=x.example"
    theirs = authres.AuthenticationResultsHeader.parse_value(value)
    assert [(p.type, p.name) for p in theirs.results[0].properties] == [
        ("header", "from")
    ]
    ours = parse(value)
    assert [(p.ptype, p.name) for p in ours.results[0].properties] == [
        (None, "action"),
        ("header", "from"),
    ]
    assert Deviation.BARE_PROPERTY in ours.deviations


def test_difference_2_deep_nesting_recursion_error_in_authres() -> None:
    value = "mx.example; dkim=pass " + "(" * 2000 + ")" * 2000
    with pytest.raises(RecursionError):
        authres.AuthenticationResultsHeader.parse_value(value)
    with pytest.raises(AuthResultsError) as info:
        parse(value)
    assert info.value.reason is ErrorReason.NESTING_TOO_DEEP


@pytest.mark.parametrize(
    ("value", "method", "ptype", "name"),
    [
        ("mx.example; nonexistent=pass", "nonexistent", None, None),
        ("mx.example; dkim=pass reasonable.x=y", "dkim", "reasonable", "x"),
        ("mx.example; none=pass", "none", None, None),
        ("mx.example; none/1=pass", "none", None, None),
    ],
    ids=["none prefix", "reason prefix", "method none", "method none/1"],
)
def test_difference_3_prefix_match_in_authres(
    value: str, method: str, ptype: str | None, name: str | None
) -> None:
    with pytest.raises(authres.core.AuthResError):
        authres.AuthenticationResultsHeader.parse_value(value)
    ours = parse(value)
    assert ours.results[0].method == method
    if ptype is not None:
        assert [(p.ptype, p.name) for p in ours.results[0].properties] == [
            (ptype, name)
        ]


def test_difference_4_other_ptypes_dropped_by_authres() -> None:
    value = "mx.example; dnswl=pass dns.zone=list.example policy.ip=192.0.2.1"
    theirs = authres.AuthenticationResultsHeader.parse_value(value)
    assert [(p.type, p.name) for p in theirs.results[0].properties] == [
        ("policy", "ip")
    ]
    ours = parse(value)
    assert [(p.ptype, p.name, p.registered) for p in ours.results[0].properties] == [
        ("dns", "zone", True),
        ("policy", "ip", True),
    ]


def test_difference_5_quoted_pairs_kept_raw_by_authres() -> None:
    value = 'mx.example; dkim=pass reason="a\\"b" header.s="c\\\\d"'
    theirs = authres.AuthenticationResultsHeader.parse_value(value)
    assert theirs.results[0].reason == 'a\\"b'
    assert theirs.results[0].properties[0].value == "c\\\\d"
    ours = parse(value)
    assert ours.results[0].reason == 'a"b'
    prop = ours.results[0].properties[0]
    assert (prop.value, prop.raw, prop.quoted) == ("c\\d", '"c\\\\d"', True)


def _theirs(value: str) -> object:
    return authres.AuthenticationResultsHeader.parse_value(value)


def _their_properties(value: str, index: int = 0) -> list[tuple[str, str, str]]:
    header = _theirs(value)
    result = header.results[index]  # type: ignore[attr-defined]
    return [(p.type, p.name, p.value) for p in result.properties]


def test_difference_6_quoted_pvalue_not_last_dropped_by_authres() -> None:
    value = 'mx.example; dkim=pass header.s="a" header.d=b.example header.i=c'
    assert _their_properties(value) == [
        ("header", "d", "b.example"),
        ("header", "i", "c"),
    ]
    ours = parse(value)
    assert [(p.ptype, p.name, p.value) for p in ours.results[0].properties] == [
        ("header", "s", "a"),
        ("header", "d", "b.example"),
        ("header", "i", "c"),
    ]
    assert _compare(value) == "set aside: properties authres drops (1, 4, 6)"
    # Last before ";" or the end, a quoted pvalue is read by both.
    assert _compare('mx.example; dkim=pass header.s="a"; spf=pass') == "compared"


def test_difference_7_cfws_before_reason_cut_short_by_authres() -> None:
    value = "mx.example; dkim=pass (a) (b) reason=x"
    assert _theirs(value).results[0].reason is None  # type: ignore[attr-defined]
    assert parse(value).results[0].reason == "x"
    assert _compare(value) == "set aside: CFWS before reason (7)"
    # The same comment run elsewhere is read by both.
    assert _compare("mx.example; dkim=pass header.d=y (a) (b) header.s=z") == (
        "compared"
    )
    assert _compare("mx.example; dkim=pass (a) reason=x") == "compared"
    value = 'mx.example; dkim=pass header.s="a" ()\r\n \r\n ()'
    assert _their_properties(value) == []
    assert [p.name for p in parse(value).results[0].properties] == ["s"]
    value = " () mx.example; none"
    with pytest.raises(authres.core.AuthResError):
        _theirs(value)
    assert parse(value).none
    assert _compare("() mx.example; none") == "compared"


@pytest.mark.parametrize(
    ("value", "authserv_id"),
    [
        ('"mx example"; none', "mx example"),
        ('"mx.example"; none', "mx.example"),
        (".mx.example; none", ".mx.example"),
        ("mx..example; none", "mx..example"),
    ],
    ids=["quoted", "quoted token", "leading dot", "double dot"],
)
def test_difference_8_authserv_id_value_refused_by_authres(
    value: str, authserv_id: str
) -> None:
    with pytest.raises(authres.core.AuthResError):
        _theirs(value)
    assert parse(value).authserv_id == authserv_id


def test_difference_9_empty_quoted_strings_in_authres() -> None:
    value = 'mx.example; dkim=pass reason=""'
    with pytest.raises(authres.core.AuthResError):
        _theirs(value)
    assert parse(value).results[0].reason == ""
    value = 'mx.example; dkim=pass header.s="" header.d=x.example'
    assert _their_properties(value) == [("header", "s", "header.d=x.example")]
    ours = parse(value)
    assert [(p.ptype, p.name, p.value) for p in ours.results[0].properties] == [
        ("header", "s", ""),
        ("header", "d", "x.example"),
    ]


def test_difference_10_missing_authserv_id_in_authres() -> None:
    value = "spf=pass smtp.mailfrom=x.example"
    with pytest.raises(authres.core.AuthResError):
        _theirs(value)
    ours = parse(value)
    assert ours.authserv_id is None
    assert Deviation.MISSING_AUTHSERV_ID in ours.deviations
    value = "dkim/1=pass; spf=fail"
    theirs = _theirs(value)
    assert theirs.authserv_id == "dkim/1=pass"  # type: ignore[attr-defined]
    assert [r.method for r in theirs.results] == ["spf"]  # type: ignore[attr-defined]
    ours = parse(value)
    assert ours.authserv_id is None
    assert [r.method for r in ours.results] == ["dkim", "spf"]
    assert _compare(value) == "set aside: missing authserv-id (10)"


# --- normalisations, each shown against authres 1.2.0 -----------------------


def test_authserv_id_lowercased_by_authres() -> None:
    value = "MX.Example; none"
    assert _theirs(value).authserv_id == "mx.example"  # type: ignore[attr-defined]
    assert parse(value).authserv_id == "MX.Example"
    assert _compare(value) == "compared"


def test_fold_kept_in_quoted_pvalue_by_authres() -> None:
    value = 'mx.example; dkim=pass header.s="a\r\n b"'
    assert _their_properties(value) == [("header", "s", "a\r\n b")]
    assert parse(value).results[0].properties[0].value == "a b"
    assert _compare(value) == "compared"


def test_htab_in_reason_written_as_question_mark_by_authres() -> None:
    value = 'mx.example; dkim=pass reason="a\tb"'
    assert _theirs(value).results[0].reason == "a?b"  # type: ignore[attr-defined]
    assert parse(value).results[0].reason == "a\tb"
    assert _compare(value) == "set aside: HTAB or fold in a reason"


def test_fold_in_reason_written_as_question_marks_by_authres() -> None:
    value = 'mx.example; dkim=pass reason="a\r\n b"'
    assert _theirs(value).results[0].reason == "a?? b"  # type: ignore[attr-defined]
    assert parse(value).results[0].reason == "a b"
    assert _compare(value) == "set aside: HTAB or fold in a reason"


def test_empty_quoted_local_part_lost_by_authres() -> None:
    value = 'mx.example; spf=pass smtp.mailfrom=""@x.example'
    assert _their_properties(value) == [("smtp", "mailfrom", "@x.example")]
    assert parse(value).results[0].properties[0].value == '""@x.example'
    assert _compare(value) == "compared"


@pytest.mark.parametrize(
    ("value", "wrong"),
    [
        ('mx.example; dkim=pass reason="a\r\n b"', "ab"),
        ('mx.example; dkim=pass reason="a\r\n b"', "a  b"),
        ('mx.example; dkim=pass reason="a\r\n b"', "a b c"),
        ('mx.example;\r\n dkim=pass reason="a??b"', "ab"),
        ('mx.example;\r\n dkim=pass reason="a??b"', "a b"),
        ('mx.example; dkim=pass reason="a\n b"', "ab"),
        # No fold at all, but "??" in the source (verifier V1).
        ('mx.example; dkim=pass reason="a?? b"', "a b"),
        # A fold elsewhere in the value, "??" in the reason.
        ('mx.example;\r\n dkim=pass reason="a?? b"', "a b"),
        ('mx.example; dkim=pass (\r\n x) reason="a?? b"', "a b"),
    ],
)
def test_fold_set_aside_never_hides_a_wrong_reason(value: str, wrong: str) -> None:
    theirs = _theirs(value)
    ours = parse(value)
    doctored = dataclasses.replace(
        ours, results=(dataclasses.replace(ours.results[0], reason=wrong),)
    )
    with pytest.raises(AssertionError):
        _explain(doctored, theirs, value)
    # The real parse is explained (or equal), never refused.
    assert _explain(ours, theirs, value) in {
        "compared",
        "set aside: HTAB or fold in a reason",
    }


def _doctored(value: str, index: int, reason: str) -> AuthenticationResults:
    ours = parse(value)
    results = list(ours.results)
    results[index] = dataclasses.replace(results[index], reason=reason)
    return dataclasses.replace(ours, results=tuple(results))


@pytest.mark.parametrize(
    ("value", "index", "invented"),
    [
        # "reason" only inside a comment: there is no reason to set aside.
        ("mx.example; spf=pass smtp.mailfrom=x.example (x) (reason)", 0, "invented"),
        # The comment run belongs to the dkim result, not to spf.
        ("mx.example; dkim=pass (a) (b) reason=x; spf=pass", 1, "bogus"),
        # The dkim reason is x; a different one is not hidden either.
        ("mx.example; dkim=pass (a) (b) reason=x; spf=pass", 0, "y"),
    ],
)
def test_cfws_set_aside_never_hides_an_invented_reason(
    value: str, index: int, invented: str
) -> None:
    with pytest.raises(AssertionError):
        _explain(_doctored(value, index, invented), _theirs(value), value)


@pytest.mark.parametrize(
    ("value", "wrong"),
    [("mx.example; none", "MX.EXAMPLE"), ("MX.Example; none", "mx.example")],
)
def test_authserv_id_case_never_hidden(value: str, wrong: str) -> None:
    doctored = dataclasses.replace(parse(value), authserv_id=wrong)
    assert _normalised_ours(doctored)[0] == _normalised_theirs(_theirs(value))[0]
    with pytest.raises(AssertionError):
        _explain(doctored, _theirs(value), value)


def test_difference_11_leading_zero_version_refused_by_authres() -> None:
    value = "mx.example 01; none"
    with pytest.raises(authres.core.AuthResError):
        _theirs(value)
    ours = parse(value)
    assert (ours.version, ours.version_given) == (1, True)
    assert _compare("mx.example; dkim/01=pass") == "compared"


@pytest.mark.parametrize(
    "value",
    [
        "example.com; dkim=pass header.b=<a>",
        "example.com; dkim=pass header.b=[a]",
        "example.com; spf=pass smtp.remote-ip=2001:db8::1",
        "example.com; spf=pass smtp.helo=[192.0.2.1]",
        "example.com; spf=pass smtp.mailfrom=<>",
        "example.com; spf=pass smtp.mailfrom=a@[192.0.2.1]",
        "example.com; dmarc=pass header.from=<sender@mail.example.com>",
    ],
)
def test_difference_12_wide_tspecials_refused_by_authres(value: str) -> None:
    with pytest.raises(authres.core.AuthResError):
        _theirs(value)
    ours = parse(value)
    written = value.rsplit("=", 1)[1]
    assert [p.value for p in ours.results[0].properties] == [written]
    assert ours.deviations == {Deviation.PVALUE_TSPECIALS}
