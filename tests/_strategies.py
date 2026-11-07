# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Hypothesis strategies shared by the property and differential tests.

``models()`` draws a model the parser can produce. ``layouts()`` writes one
as a value cut into pieces, with a ``Slot`` at every place where RFC 8601
2.2 allows CFWS (PLAN.md 3.1 G4, spots 1 to 13), so a test can put comments,
folds or case changes exactly where the grammar allows them.

The ``registered`` flags are taken from the snapshot in
``authresults._registry`` (its entries are pinned by the case table and the
AL2b registry tests); these strategies test syntax, not the snapshot.
"""

import functools
import re
import string
from dataclasses import dataclass
from typing import Final, Literal

from hypothesis import strategies as st

from authresults import AuthenticationResults, Deviation, Property, Result, _registry

# --- character classes (PLAN.md 3 and 3.1 G3, G6, G10, G14) ---------------

_LDH: Final = string.ascii_lowercase + string.digits + "-"
_LET_DIG: Final = string.ascii_lowercase + string.digits
# RFC 2045 token: printable US-ASCII except SPACE and the tspecials.
TOKEN_CHARS: Final = frozenset(
    string.ascii_letters + string.digits + "!#$%&'*+-.^_`{|}~"
)
_ATEXT: Final = "".join(sorted((TOKEN_CHARS - {"."}) | set("/=?")))
_PRINTABLE: Final = "".join(chr(c) for c in range(0x20, 0x7F))

# Categories refused everywhere (AU-Q29, AU-Q37, AU-Q41) or unassigned.
_REFUSED_CATEGORIES: Final = ("Cc", "Cs", "Zs", "Zl", "Zp", "Cf", "Cn")

INJECTION: Final = "; dmarc=pass header.from=x"  # PLAN.md 4, property 3

_METHODS: Final = (*sorted(_registry._RESULTS), "none", "x-dmarc", "compauth")  # noqa: SLF001
_RESULT_NAMES: Final = ("pass", "fail", "none", "neutral", "softfail", "temperror")
_PTYPES: Final = ("smtp", "header", "body", "policy", "dns", "reason")
# The ptypes authres 1.2.0 accepts (spike 4).
AUTHRES_PTYPES: Final = ("smtp", "header", "body", "policy")


def quote(text: str, pair_every: int = 0) -> str:
    r"""A quoted-string with ``\`` before ``"`` and ``\`` (G6).

    With *pair_every* > 0, every *pair_every*-th other character that may
    follow a backslash (VCHAR or WSP) is also written as an unneeded
    quoted-pair, such as ``\a``, ``\ `` or a backslash before HTAB.
    """
    out = []
    for i, c in enumerate(text):
        needed = c in '"\\'
        optional = pair_every > 0 and i % pair_every == 0 and " " <= c <= "~"
        optional = optional or (pair_every > 0 and i % pair_every == 0 and c == "\t")
        out.append("\\" + c if needed or optional else c)
    return '"' + "".join(out) + '"'


@functools.cache
def non_ascii() -> st.SearchStrategy[str]:
    """Non-ASCII characters the character scan lets through (G14)."""
    return st.characters(min_codepoint=0x80, exclude_categories=_REFUSED_CATEGORIES)


@functools.cache
def text_chars(*, ascii_only: bool) -> st.SearchStrategy[str]:
    """Characters allowed in a value: printable ASCII, HTAB, and UTF-8 if allowed."""
    ascii_chars = st.sampled_from(_PRINTABLE + "\t")
    return ascii_chars if ascii_only else st.one_of(ascii_chars, non_ascii())


@functools.cache
def keywords() -> st.SearchStrategy[str]:
    """A lowercase ``Ldh-str`` (RFC 5321 4.1.2): LDH, not ending in ``-``."""
    return st.builds(
        lambda head, tail: head + tail,
        st.text(_LDH, max_size=6),
        st.sampled_from(_LET_DIG),
    )


@functools.cache
def _named(names: tuple[str, ...]) -> st.SearchStrategy[str]:
    return st.one_of(st.sampled_from(names), keywords())


# --- values -----------------------------------------------------------------


@functools.cache
def _dot_atom(*, ascii_only: bool) -> st.SearchStrategy[str]:
    atext = st.sampled_from(_ATEXT)
    chars = atext if ascii_only else st.one_of(atext, non_ascii())
    return st.lists(st.text(chars, min_size=1, max_size=5), min_size=1, max_size=3).map(
        ".".join
    )


@functools.cache
def _quoted_local(*, ascii_only: bool) -> st.SearchStrategy[str]:
    return st.builds(
        quote,
        st.text(text_chars(ascii_only=ascii_only), max_size=6),
        st.sampled_from((0, 0, 1, 2)),
    )


@functools.cache
def _domain(*, ascii_only: bool) -> st.SearchStrategy[str]:
    label = st.builds(
        lambda head, tail: head + tail,
        st.sampled_from(_LET_DIG),
        st.text(_LDH, max_size=4).filter(lambda t: not t.endswith("-")),
    )
    if not ascii_only:
        label = st.one_of(label, st.text(non_ascii(), min_size=1, max_size=3))
    return st.lists(label, min_size=2, max_size=3).map(".".join)


@functools.cache
def addresses(*, ascii_only: bool) -> st.SearchStrategy[str]:
    """``[local-part] "@" domain-name`` with no CFWS (G10, AU-Q18b, AU-Q24)."""
    local = st.one_of(
        st.just(""),
        _dot_atom(ascii_only=ascii_only),
        _quoted_local(ascii_only=ascii_only),
    )
    return st.builds(lambda a, b: a + "@" + b, local, _domain(ascii_only=ascii_only))


@functools.cache
def values(*, ascii_only: bool) -> st.SearchStrategy[str]:
    """Any value text: tokens, free text, and text carrying the injection."""
    chars = text_chars(ascii_only=ascii_only)
    token = st.text(st.sampled_from(sorted(TOKEN_CHARS)), min_size=1, max_size=8)
    return st.one_of(
        token,
        st.text(chars, max_size=12),
        st.builds(lambda a, b: a + INJECTION + b, st.text(chars, max_size=4), token),
    )


# --- models -----------------------------------------------------------------


@functools.cache
def _compatible_values() -> st.SearchStrategy[str]:
    return values(ascii_only=True).filter(bool)


@functools.cache
def _compatible_methods() -> st.SearchStrategy[str]:
    return _named(_METHODS).filter(lambda m: not m.startswith("none"))


@functools.cache
def _compatible_id() -> st.SearchStrategy[str]:
    """A token that is also a dot-atom: no leading, trailing or double dot."""
    atom = st.text(st.sampled_from(sorted(TOKEN_CHARS - {"."})), min_size=1, max_size=5)
    return st.lists(atom, min_size=1, max_size=3).map(".".join)


@st.composite
def _property(
    draw: st.DrawFn, method: str, *, ascii_only: bool, compatible: bool
) -> Property:
    ptype: str | None
    if not compatible and draw(st.integers(0, 4)) == 0:
        # A bare property (AU-Q27); never named reason (AU-Q26).
        name = draw(_named(("action", "policy", "x")).filter(lambda n: n != "reason"))
        ptype = None
    else:
        ptype = draw(st.sampled_from(AUTHRES_PTYPES) if compatible else _named(_PTYPES))
        name = draw(_named(("d", "i", "b", "s", "from", "mailfrom", "helo", "expired")))
    text = _compatible_values() if compatible else values(ascii_only=ascii_only)
    value = draw(st.one_of(text, addresses(ascii_only=ascii_only)))
    registered = ptype is not None and _registry.property_registered(
        method, ptype, name
    )
    return Property(
        ptype=ptype,
        name=name,
        value=value,
        raw=value,
        quoted=False,
        registered=registered,
    )


@st.composite
def _result(draw: st.DrawFn, *, ascii_only: bool, compatible: bool) -> Result:
    method = draw(_compatible_methods() if compatible else _named(_METHODS))
    version = draw(st.one_of(st.none(), st.just(1), st.integers(0, 999_999_999)))
    result = draw(_named(_RESULT_NAMES))
    text = _compatible_values() if compatible else values(ascii_only=ascii_only)
    reason = draw(st.one_of(st.none(), text))
    properties = draw(
        st.lists(
            _property(method, ascii_only=ascii_only, compatible=compatible), max_size=4
        )
    )
    return Result(
        method=method,
        method_version=version,
        result=result,
        reason=reason,
        properties=tuple(properties),
        registered=_registry.result_registered(method, version, result),
    )


@st.composite
def models(
    draw: st.DrawFn,
    *,
    ascii_only: bool = True,
    compatible: bool = False,
    missing_id: bool = False,
) -> AuthenticationResults:
    """A model whose canonical form parses back to it (AU-Q17).

    *compatible* keeps to what authres 1.2.0 reads, so the differential
    compares rather than skips (each left-out shape has its own test in
    ``tests/test_differential.py``): the ptypes ``smtp``, ``header``,
    ``body`` and ``policy``; no bare property; a dot-atom authserv-id that
    needs no quotes; no method starting with ``none``; no empty value.

    *missing_id* gives a model with no authserv-id and at least one result
    (``MISSING_AUTHSERV_ID``, AU-Q35), which ``layout_of`` can write but
    ``to_value`` refuses.
    """
    results = draw(
        st.lists(
            _result(ascii_only=ascii_only, compatible=compatible),
            min_size=1 if missing_id else 0,
            max_size=4,
        )
    )
    deviations = set()
    if any(p.ptype is None for r in results for p in r.properties):
        deviations.add(Deviation.BARE_PROPERTY)
    if missing_id:
        deviations.add(Deviation.MISSING_AUTHSERV_ID)
        authserv_id = None
    else:
        authserv_id = draw(
            _compatible_id() if compatible else values(ascii_only=ascii_only)
        )
    return AuthenticationResults(
        authserv_id=authserv_id,
        version=1,
        version_given=False if missing_id else draw(st.booleans()),
        none=not results,
        results=tuple(results),
        deviations=frozenset(deviations),
    )


def comparable(model: AuthenticationResults) -> object:
    """AU-Q17 round-trip equality: every field except ``Property.raw`` and
    ``Property.quoted``, and ``deviations`` without the three that the
    canonical form cannot carry."""
    dropped = {
        Deviation.PVALUE_TSPECIALS,
        Deviation.TRAILING_SEMICOLON,
        Deviation.LF_FOLDING,
    }
    return (
        model.authserv_id,
        model.version,
        model.version_given,
        model.none,
        tuple(
            (
                r.method,
                r.method_version,
                r.result,
                r.reason,
                tuple((p.ptype, p.name, p.value, p.registered) for p in r.properties),
                r.registered,
            )
            for r in model.results
        ),
        model.deviations - dropped,
    )


# --- layouts: a value with its CFWS spots marked ------------------------------


@dataclass(frozen=True, slots=True)
class Slot:
    """A CFWS spot (G4): ``default`` is the text written there, ``required``
    means at least one FWS or comment must stay."""

    default: str
    required: bool


@dataclass(frozen=True, slots=True)
class Piece:
    """Literal text; ``keyword`` marks text matched case-insensitively (G13)."""

    text: str
    keyword: bool = False


Item = Slot | Piece
Layout = tuple[Item, ...]

_OPT: Final = Slot("", required=False)
_SPACE: Final = Slot(" ", required=False)
_REQ: Final = Slot(" ", required=True)


def _is_bare_value(text: str) -> bool:
    """True if *text* can be written unquoted as a token (G3, AU-Q18a)."""
    return text != "" and all(c in TOKEN_CHARS or c >= "\x80" for c in text)


_NA: Final = "\u0080-\U0010ffff"
_ADDRESS: Final = re.compile(
    rf"(?:(?:[{re.escape(_ATEXT)}{_NA}]+(?:\.[{re.escape(_ATEXT)}{_NA}]+)*)?"
    rf'|"(?:[^"\\]|\\.)*")'
    rf"@[A-Za-z0-9{_NA}](?:[A-Za-z0-9{_NA}-]*[A-Za-z0-9{_NA}])?"
    rf"(?:\.[A-Za-z0-9{_NA}](?:[A-Za-z0-9{_NA}-]*[A-Za-z0-9{_NA}])?)+",
    re.DOTALL,
)


def is_address(text: str) -> bool:
    """``[local-part] "@" domain-name`` as G10 reads it (no CFWS, no obs forms)."""
    return _ADDRESS.fullmatch(text) is not None


def _value_text(text: str, *, address: bool, pair_every: int = 0) -> str:
    if _is_bare_value(text) or address:
        return text
    return quote(text, pair_every)


def _digits(number: int, zeros: int) -> str:
    return "0" * zeros + str(number)


def _property_items(prop: Property, pair_every: int) -> list[Item]:
    items: list[Item] = []
    if prop.ptype is not None:
        items += [Piece(prop.ptype, keyword=True), _OPT, Piece("."), _OPT]
    items += [Piece(prop.name, keyword=True), _OPT, Piece("="), _OPT]
    address = is_address(prop.value)
    items.append(Piece(_value_text(prop.value, address=address, pair_every=pair_every)))
    return items


def _result_items(result: Result, zeros: int, pair_every: int) -> list[Item]:
    items: list[Item] = [Piece(result.method, keyword=True), _OPT]
    if result.method_version is not None:
        items += [Piece("/"), _OPT, Piece(_digits(result.method_version, zeros)), _OPT]
    items += [Piece("="), _OPT, Piece(result.result, keyword=True)]
    if result.reason is not None:
        reason = _value_text(result.reason, address=False, pair_every=pair_every)
        items += [
            _REQ,
            Piece("reason", keyword=True),
            _OPT,
            Piece("="),
            _OPT,
            Piece(reason),
        ]
    for prop in result.properties:
        # Spot 10 is required; spot 12 is optional, but a token pvalue needs
        # some separation from the next propspec, so it is kept non-empty.
        items.append(_REQ)
        items += _property_items(prop, pair_every)
    return items


def layout_of(  # noqa: PLR0913 - independent knobs of the writer
    model: AuthenticationResults,
    *,
    zeros: int = 0,
    version_zeros: int | None = None,
    arc_instance: int | None = None,
    pair_every: int = 0,
    version: str | None = None,
) -> Layout:
    """Write *model* as pieces and slots; joined with the defaults it is a
    valid value. *zeros* adds leading zeros to the numbers (AU-Q24), and
    *version_zeros*, if given, to the authserv-id version instead.
    *pair_every* writes unneeded quoted-pairs in quoted values (``quote``).
    *version*, if given, replaces the version digits (to write e.g. ``2``).
    A model without an authserv-id starts with its first result (AU-Q35).
    """
    items: list[Item] = []
    if arc_instance is not None:
        # RFC 8617 3.9 and 4.1.1 (G12): optional CFWS around "i", "=" and
        # the position (1*2DIGIT, so one leading zero only below 10).
        lead = min(zeros, 1) if arc_instance < 10 else 0  # noqa: PLR2004
        items += [_OPT, Piece("i"), _OPT, Piece("="), _OPT]
        items += [Piece(_digits(arc_instance, lead)), _OPT, Piece(";")]
    results = list(model.results)
    if model.authserv_id is None:
        assert results
        assert not model.version_given
        items += [_OPT, *_result_items(results.pop(0), zeros, pair_every)]
    else:
        authserv_id = _value_text(
            model.authserv_id, address=False, pair_every=pair_every
        )
        items += [_OPT, Piece(authserv_id)]
    if model.version_given:
        lead = zeros if version_zeros is None else version_zeros
        items += [_REQ, Piece(_digits(1, lead) if version is None else version)]
    if model.none:
        items += [_OPT, Piece(";"), _SPACE, Piece("none", keyword=True)]
    for result in results:
        items += [_OPT, Piece(";"), _SPACE]
        items += _result_items(result, zeros, pair_every)
    items.append(_OPT)
    return tuple(items)


def join(layout: Layout, fills: dict[int, str] | None = None) -> str:
    """The value text; slot ``i`` holds ``fills[i]`` if given, else its default."""
    fills = fills or {}
    return "".join(
        fills.get(i, item.default) if isinstance(item, Slot) else item.text
        for i, item in enumerate(layout)
    )


def slot_indexes(layout: Layout) -> list[int]:
    return [i for i, item in enumerate(layout) if isinstance(item, Slot)]


# --- comments (G4) ----------------------------------------------------------

CommentMode = Literal["any", "fold_safe"]


@functools.cache
def comments(*, ascii_only: bool, mode: CommentMode = "any") -> st.SearchStrategy[str]:
    r"""A comment of nested ctext, quoted-pairs and FWS, depth at most 16.

    ``fold_safe`` leaves out folds and ``\`` before WSP, so every SP in it
    can later become CRLF SP (property 4).
    """
    ctext_ascii = "".join(c for c in _PRINTABLE if c not in "()\\ ")
    ctext = st.sampled_from(ctext_ascii)
    if not ascii_only:
        ctext = st.one_of(ctext, non_ascii())
    pair_chars = ctext_ascii + "()\\" + ("" if mode == "fold_safe" else " \t")
    fws = ("", " ", "\t") if mode == "fold_safe" else ("", " ", "\t", "\r\n ", "\r\n\t")
    leaf = st.one_of(
        st.text(ctext, min_size=1, max_size=6),
        st.sampled_from(pair_chars).map(lambda c: "\\" + c),
        st.sampled_from(fws),
        st.just(INJECTION),
    )

    def nest(inner: st.SearchStrategy[str]) -> st.SearchStrategy[str]:
        return st.lists(inner, max_size=4).map(lambda parts: "(" + "".join(parts) + ")")

    # Sometimes as deep as the default max_comment_depth (16) allows.
    deep = st.builds(
        lambda depth, text: "(" * depth + text + ")" * depth,
        st.integers(1, 16),
        st.text(ctext, max_size=4),
    )
    return st.one_of(nest(st.recursive(leaf, nest, max_leaves=8)), deep)


@st.composite
def cfws(
    draw: st.DrawFn,
    slot: Slot,
    *,
    ascii_only: bool,
    mode: CommentMode = "any",
    tight: bool = False,
) -> str:
    """Text for *slot*: one or two comments, with FWS around them.

    *tight* gives one comment with the slot's default on at most one side,
    the most CFWS authres 1.2.0 reads in one go (the differential).
    """
    if tight:
        comment = draw(comments(ascii_only=ascii_only, mode=mode))
        side = draw(st.sampled_from(("", slot.default)))
        return draw(st.sampled_from((side + comment, comment + side)))
    fws = st.sampled_from(
        ("", " ", "\t", "  ") if mode == "fold_safe" else ("", " ", "\r\n ")
    )
    parts = [draw(st.sampled_from(("", slot.default)))]
    for comment in draw(
        st.lists(comments(ascii_only=ascii_only, mode=mode), min_size=1, max_size=2)
    ):
        parts += [draw(fws), comment, draw(fws)]
    return "".join(parts)
