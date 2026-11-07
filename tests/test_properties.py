# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Hypothesis properties 1 to 5 (PLAN.md 4; AL3b row).

1. Any text returns or raises ``AuthResultsError``, never ``INTERNAL``.
2. Model, ``to_value()``, ``parse()`` gives an equal model (AU-Q17), and
   ``to_value()`` is then a fixed point.
3. A comment at any CFWS spot leaves the parse unchanged; injection text in
   a comment or a quoted value never adds a result.
4. Any SP replaced by CRLF SP, or any keyword's case changed, leaves the
   parse unchanged (``i`` excluded, G12; ``raw`` outside AU-Q17).
5. ``"(" * n`` gives ``NESTING_TOO_DEEP`` or ``UNTERMINATED_COMMENT``.

The profile (``ci`` or ``nightly``) comes from ``HYPOTHESIS_PROFILE``
(``tests/_hypothesis_profiles.py``).
"""

import collections
import dataclasses
import re
from collections.abc import Callable

import pytest
from hypothesis import HealthCheck, event, example, given, settings
from hypothesis import strategies as st

from authresults import (
    ArcAuthenticationResults,
    AuthenticationResults,
    AuthResultsError,
    ErrorReason,
    ascii_domain,
    domain_of,
    parse,
    parse_arc,
)

from ._hypothesis_profiles import TIMEOUT
from ._strategies import (
    INJECTION,
    CommentMode,
    Layout,
    Piece,
    Slot,
    cfws,
    comparable,
    join,
    layout_of,
    models,
    quote,
    slot_indexes,
)

pytestmark = pytest.mark.timeout(TIMEOUT)

_MESSAGE = re.compile(r"[a-z_]+( at position \d+)?")

Payload = AuthenticationResults | ArcAuthenticationResults


def _check_error(err: AuthResultsError) -> None:
    """The closed error set, with no input text in the message (PLAN.md 2.3)."""
    assert type(err) is AuthResultsError
    assert type(err.reason) is ErrorReason
    assert err.reason is not ErrorReason.INTERNAL
    assert _MESSAGE.fullmatch(str(err))


def _payload(parsed: Payload) -> AuthenticationResults:
    return parsed.payload if isinstance(parsed, ArcAuthenticationResults) else parsed


# --- property 1: never INTERNAL ---------------------------------------------

# Header-ish fragments, so random text reaches deep into the grammar.
_FRAGMENTS = (
    *("example.com", "mx.example", "i=1;", "i", "I", "1", "01", "2", "none"),
    *("dkim", "spf", "dmarc", "arc", "pass", "fail", "reason", "header", "smtp"),
    *("d", "from", "mailfrom", "policy", "dns", "action", "x@y.example", '"a"@b.c'),
    *(".", "=", ";", "/", "@", "(", ")", '"', "\\", "-", "_", "?", ",", "<", "["),
    *(" ", "\t", "\r\n ", "\n ", "\r\n", "\r", "\n", "\\\r", "\\\n", "\x00", "\x7f"),
    *("\x85", "\u00a0", "\u200b", "\u202e", "\ufeff", "\ud800", "\u212a", "\u017f"),
    *("\u00e9", "\u4e2d", "\U0001f600", "(" * 17, ")" * 3, ";" * 2, INJECTION),
)

_ANY_TEXT = st.one_of(
    st.text(),
    st.text(st.characters(min_codepoint=0xD800, max_codepoint=0xDFFF)),
    st.lists(
        st.one_of(st.sampled_from(_FRAGMENTS), st.text(max_size=3)), max_size=40
    ).map("".join),
)

# Edits applied to a valid value, so most inputs reach deep into the grammar:
# (kind, offset, text, count). A splice repeats its text (up to 70 times),
# which crosses the default result and property limits; "at_space" inserts
# at a token boundary.
_EDITS = st.lists(
    st.tuples(
        st.sampled_from(("insert", "delete", "replace", "splice", "at_space")),
        st.integers(0, 2**16),
        st.one_of(
            st.sampled_from(_FRAGMENTS),
            st.sampled_from(
                (" reason=x", " header.d=x", "; dkim=pass", " 2", "i=0;", "i=51;")
            ),
            st.text(max_size=3),
        ),
        st.integers(1, 70),
    ),
    max_size=3,
)


def _edit(text: str, edits: list[tuple[str, int, str, int]]) -> str:
    for kind, offset, piece, count in edits:
        i = offset % (len(text) + 1)
        if kind == "insert":
            text = text[:i] + piece + text[i:]
        elif kind == "delete":
            text = text[:i] + text[i + count % 8 :]
        elif kind == "replace":
            text = text[:i] + piece + text[i + len(piece) :]
        elif kind == "splice":
            text = text[:i] + piece * count + text[i:]
        else:  # at a space: a token boundary, where structure goes
            spaces = [j for j, c in enumerate(text) if c == " "] or [len(text)]
            j = spaces[offset % len(spaces)]
            text = text[:j] + piece + text[j:]
    return text


_ARC_PREFIXES = ("i=1; ", "i=7;", "i = 01 ;", "i=50; ", "i=0; ", "i=51; ", "i=123; ")


@st.composite
def _seeded(draw: st.DrawFn) -> tuple[str, bool]:
    """A valid value (sometimes ARC, sometimes without an authserv-id), then
    up to three edits."""
    ascii_only = draw(st.integers(0, 3)) < 3  # noqa: PLR2004
    missing_id = draw(st.integers(0, 4)) == 4  # noqa: PLR2004
    model = draw(models(ascii_only=ascii_only, missing_id=missing_id))
    layout = layout_of(
        model,
        zeros=draw(st.integers(0, 2)),
        pair_every=draw(st.sampled_from((0, 0, 1, 3))),
        version=draw(st.sampled_from((None, None, None, "2", "10", "0001"))),
    )
    fills = {}
    for index in draw(st.lists(st.sampled_from(slot_indexes(layout)), max_size=2)):
        slot = layout[index]
        assert isinstance(slot, Slot)
        fills[index] = draw(cfws(slot, ascii_only=ascii_only))
    arc = draw(st.booleans())
    text = (draw(st.sampled_from(_ARC_PREFIXES)) if arc else "") + join(layout, fills)
    if "reason=" in text and draw(st.integers(0, 7)) == 7:  # noqa: PLR2004
        # A second reason (G8: DUPLICATE_REASON at the later one).
        at = text.index("reason=")
        text = text[:at] + "reason=dup " + text[at:]
    edits = [] if draw(st.integers(0, 4)) < 2 else draw(_EDITS)  # noqa: PLR2004
    return _edit(text, edits), arc


_RAW: st.SearchStrategy[tuple[object, bool]] = st.one_of(
    st.tuples(_ANY_TEXT, st.booleans()),
    st.tuples(st.sampled_from(("", " ", "\t", "\r\n ", " \r\n\t")), st.booleans()),
    st.tuples(st.sampled_from((None, b"x", 1, 1.5, ["x"])), st.booleans()),
)
# Three draws in four start from a valid value; the rest are raw text,
# whitespace or a non-str.
_INPUTS: st.SearchStrategy[tuple[object, bool]] = st.integers(0, 3).flatmap(
    lambda k: _RAW if k == 3 else _seeded()  # noqa: PLR2004
)


def _limit(default: int, small: int = 20) -> st.SearchStrategy[int]:
    """The default seven times out of eight, else a small limit."""
    return st.integers(0, 7).flatmap(
        lambda k: st.integers(1, small) if k == 7 else st.just(default)  # noqa: PLR2004
    )


_SOMETIMES = st.integers(0, 3).map(lambda k: k == 3)  # noqa: PLR2004

_OPTIONS = st.fixed_dictionaries(
    {
        "max_length": _limit(8192, 400),
        "max_results": _limit(64, 3),
        "max_properties": _limit(64, 3),
        "max_comment_depth": _limit(16, 4),
        "ascii_only": st.booleans(),
        "strict_syntax": _SOMETIMES,
        "require_registered": _SOMETIMES,
    }
)


def _exercise(value: object, options: dict[str, int | bool], arc: bool) -> list[str]:  # noqa: FBT001
    """Parse, then serialize and query the result; return the outcomes."""
    call: Callable[..., Payload] = parse_arc if arc else parse
    try:
        parsed = call(value, **options)
    except AuthResultsError as err:
        _check_error(err)
        return [str(err.reason)]
    payload = _payload(parsed)
    assert type(payload) is AuthenticationResults
    outcomes = ["parse_arc ok" if arc else "parse ok"]
    try:
        payload.to_value(ascii_only=bool(options.get("ascii_only", True)))
    except AuthResultsError as err:
        _check_error(err)
    for result in payload.results:
        assert payload.results_for(result.method)
        for prop in result.properties:
            try:
                result.get_unique(prop.ptype, prop.name)
            except AuthResultsError as err:
                _check_error(err)
                outcomes.append(str(err.reason))
    return outcomes


@given(value_arc=_INPUTS, options=_OPTIONS)
@example(value_arc=("(" * 8192, False), options={})
@example(value_arc=("i=1; " + "\\" * 30, True), options={"ascii_only": False})
def test_any_text_never_internal(
    value_arc: tuple[object, bool], options: dict[str, int | bool]
) -> None:
    for outcome in _exercise(*value_arc[:1], options, value_arc[1]):
        event(outcome)


def test_property_1_reaches_every_outcome() -> None:
    """2,000 fixed draws reach every reason but INTERNAL, and parse often."""
    seen: collections.Counter[str] = collections.Counter()

    @settings(
        max_examples=2_000,
        derandomize=True,
        database=None,
        deadline=None,
        suppress_health_check=list(HealthCheck),
    )
    @given(value_arc=_INPUTS, options=_OPTIONS)
    def run(value_arc: tuple[object, bool], options: dict[str, int | bool]) -> None:
        seen.update(set(_exercise(value_arc[0], options, value_arc[1])))

    run()
    total = 2_000
    reasons = {str(r) for r in ErrorReason} - {str(ErrorReason.INTERNAL)}
    assert reasons <= set(seen), sorted(reasons - set(seen))
    assert seen["parse ok"] >= total // 10, seen
    assert seen["parse_arc ok"] >= total // 20, seen


@given(text=st.one_of(_ANY_TEXT, _seeded().map(lambda pair: pair[0])))
def test_helpers_never_internal(text: str) -> None:
    # AU-Q33(a): a str never raises; the answer is a str or None.
    for helper in (domain_of, ascii_domain):
        result = helper(text)
        assert result is None or type(result) is str


# --- property 2: round trip (AU-Q17) ----------------------------------------


@given(data=st.data(), ascii_only=st.booleans())
def test_round_trip(data: st.DataObject, ascii_only: bool) -> None:  # noqa: FBT001
    model = data.draw(models(ascii_only=ascii_only))
    text = model.to_value(ascii_only=ascii_only)
    parsed = parse(text, ascii_only=ascii_only)
    assert comparable(parsed) == comparable(model)
    assert parsed.to_value(ascii_only=ascii_only) == text


# --- property 3: comments and injection -------------------------------------


@st.composite
def _laid_out(
    draw: st.DrawFn, *, ascii_only: bool
) -> tuple[AuthenticationResults, Layout, int | None]:
    missing = draw(st.integers(0, 4)) == 0  # AU-Q35, lenient
    model = draw(models(ascii_only=ascii_only, missing_id=missing))
    arc = draw(st.one_of(st.none(), st.integers(1, 50)))
    layout = layout_of(
        model,
        zeros=draw(st.integers(0, 2)),
        arc_instance=arc,
        pair_every=draw(st.sampled_from((0, 0, 1, 2))),
    )
    return model, layout, arc


def _parse_layout(text: str, arc: int | None, *, ascii_only: bool) -> Payload:
    if arc is None:
        return parse(text, ascii_only=ascii_only)
    parsed = parse_arc(text, ascii_only=ascii_only)
    assert parsed.instance == arc
    return parsed


@given(data=st.data(), ascii_only=st.booleans())
def test_comments_change_nothing(data: st.DataObject, ascii_only: bool) -> None:  # noqa: FBT001
    model, layout, arc = data.draw(_laid_out(ascii_only=ascii_only))
    base = _parse_layout(join(layout), arc, ascii_only=ascii_only)
    assert comparable(_payload(base)) == comparable(model)
    chosen = data.draw(
        st.lists(st.sampled_from(slot_indexes(layout)), min_size=1, max_size=4)
    )
    fills = {}
    for index in chosen:
        slot = layout[index]
        assert isinstance(slot, Slot)
        fills[index] = data.draw(cfws(slot, ascii_only=ascii_only))
    injected = _parse_layout(join(layout, fills), arc, ascii_only=ascii_only)
    assert injected == base
    assert len(_payload(injected).results) == len(model.results)


@st.composite
def _with_injected_value(draw: st.DrawFn) -> tuple[AuthenticationResults, int | None]:
    """A model with the injection text in its authserv-id, a reason, a value
    or a quoted local-part of an address value; sometimes an ARC payload."""
    model = draw(models())
    text = draw(st.sampled_from(("", "x", "a b", '"', "\\"))) + INJECTION
    targets: list[tuple[int, int | None, bool]] = [(-1, None, False)]
    for r, result in enumerate(model.results):
        targets.append((r, None, False))
        for k in range(len(result.properties)):
            targets += [(r, k, False), (r, k, True)]
    r, i, local = draw(st.sampled_from(targets))
    arc = draw(st.one_of(st.none(), st.integers(1, 50)))
    if r < 0:
        return dataclasses.replace(model, authserv_id=text), arc
    results = list(model.results)
    if i is None:
        results[r] = dataclasses.replace(results[r], reason=text)
    else:
        value = quote(text) + "@x.example" if local else text  # AU-Q23
        properties = list(results[r].properties)
        properties[i] = dataclasses.replace(properties[i], value=value, raw=value)
        results[r] = dataclasses.replace(results[r], properties=tuple(properties))
    return dataclasses.replace(model, results=tuple(results)), arc


@given(model_arc=_with_injected_value())
def test_injection_in_quoted_value_adds_no_result(
    model_arc: tuple[AuthenticationResults, int | None],
) -> None:
    model, arc = model_arc
    text = model.to_value()
    if arc is None:
        parsed = parse(text)
    else:
        arc_parsed = parse_arc(f"i={arc}; {text}")
        assert arc_parsed.instance == arc
        parsed = arc_parsed.payload
    assert len(parsed.results) == len(model.results)
    assert [r.method for r in parsed.results] == [r.method for r in model.results]
    assert comparable(parsed) == comparable(model)


# --- property 4: folding and keyword case -----------------------------------


@st.composite
def _commented_text(
    draw: st.DrawFn, *, ascii_only: bool
) -> tuple[str, int | None, Layout, dict[int, str]]:
    """A value with comments in some CFWS spots; the comments may already
    hold folds and quoted-pairs (``any``) or not (``fold_safe``)."""
    _, layout, arc = draw(_laid_out(ascii_only=ascii_only))
    mode: CommentMode = draw(st.sampled_from(("fold_safe", "any")))
    chosen = draw(st.lists(st.sampled_from(slot_indexes(layout)), max_size=3))
    fills = {}
    for index in chosen:
        slot = layout[index]
        assert isinstance(slot, Slot)
        fills[index] = draw(cfws(slot, ascii_only=ascii_only, mode=mode))
    return join(layout, fills), arc, layout, fills


def _foldable(text: str, i: int) -> bool:
    r"""An SP that may become CRLF SP: not the WSP of an existing fold (after
    an LF) and not the second half of a quoted-pair (an odd run of ``\``
    before it)."""
    if text[i] != " " or (i > 0 and text[i - 1] == "\n"):
        return False
    run = len(text[:i]) - len(text[:i].rstrip("\\"))
    return run % 2 == 0


@given(data=st.data(), ascii_only=st.booleans())
def test_crlf_before_any_space_changes_nothing(
    data: st.DataObject,
    ascii_only: bool,  # noqa: FBT001
) -> None:
    text, arc, _, _ = data.draw(_commented_text(ascii_only=ascii_only))
    spaces = [i for i in range(len(text)) if _foldable(text, i)]
    if not spaces:
        text, spaces = " " + text, [0]
    base = _parse_layout(text, arc, ascii_only=ascii_only)
    chosen = data.draw(st.sets(st.sampled_from(spaces), min_size=1))
    folded = "".join("\r\n " if i in chosen else c for i, c in enumerate(text))
    parsed = _parse_layout(folded, arc, ascii_only=ascii_only)
    assert comparable(_payload(parsed)) == comparable(_payload(base))
    if isinstance(base, ArcAuthenticationResults):
        assert isinstance(parsed, ArcAuthenticationResults)
        assert parsed.instance == base.instance


@given(data=st.data(), ascii_only=st.booleans())
def test_keyword_case_changes_nothing(data: st.DataObject, ascii_only: bool) -> None:  # noqa: FBT001
    _, arc, layout, fills = data.draw(_commented_text(ascii_only=ascii_only))
    base = _parse_layout(join(layout, fills), arc, ascii_only=ascii_only)
    changed: list[Slot | Piece] = []
    for item in layout:
        if isinstance(item, Piece) and item.keyword:
            upper = data.draw(st.lists(st.booleans(), min_size=len(item.text)))
            text = "".join(
                c.upper() if flip else c
                for c, flip in zip(item.text, upper, strict=False)
            )
            changed.append(Piece(text, keyword=True))
        else:
            changed.append(item)
    parsed = _parse_layout(join(tuple(changed), fills), arc, ascii_only=ascii_only)
    assert parsed == base


# --- property 5: depth ------------------------------------------------------

_PREFIXES = (
    ("", parse),
    ("example.com; dkim=pass ", parse),
    ("example.com ", parse),
    ('"', parse),
    ("i=1; example.com; spf=pass reason=", parse_arc),
    ("", parse_arc),
)


@given(
    prefix=st.sampled_from(_PREFIXES),
    n=st.integers(1, 8192),
    depth=st.one_of(st.just(16), st.integers(1, 8192)),
)
@example(prefix=("", parse), n=8192, depth=16)
@example(prefix=("", parse), n=8192, depth=8192)
def test_open_parens_never_recurse(
    prefix: tuple[str, Callable[..., Payload]], n: int, depth: int
) -> None:
    head, call = prefix
    n = min(n, 8192 - len(head))
    value = head + "(" * n
    with pytest.raises(AuthResultsError) as info:
        call(value, max_comment_depth=depth)
    _check_error(info.value)
    if head == '"':
        # The quote opens first, so the parens are its content (G6).
        assert info.value.reason is ErrorReason.UNTERMINATED_QUOTED_STRING
        assert info.value.position == 0
    elif n > depth:
        # AU-Q36: the first fault met, at the first "(" over the limit.
        assert info.value.reason is ErrorReason.NESTING_TOO_DEEP
        assert info.value.position == len(head) + depth
    else:
        # AU-Q16: at the outermost unclosed "(".
        assert info.value.reason is ErrorReason.UNTERMINATED_COMMENT
        assert info.value.position == len(head)
