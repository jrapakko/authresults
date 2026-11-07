# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""AL2b's own tests: registry snapshot, serializer edges, round trip, fuzz.

These sit beside the case table (PLAN.md 6, AL2b row: own unit tests in new
files only). AL3b audits which branches only they cover (6.5).
"""

import dataclasses
import itertools
import random
import sys
import unicodedata

import pytest

from authresults import (
    ArcAuthenticationResults,
    AuthenticationResults,
    AuthResultsError,
    Deviation,
    ErrorReason,
    Property,
    Result,
    _registry,
    _unicode,
    parse,
    parse_arc,
)

from . import (
    cases_grammar,
    cases_redteam,
    cases_rfc8601,
    cases_rfc8617,
    cases_spike,
    cases_vendor,
)
from ._case import Case, ar, prop, res


def test_registry_last_updated() -> None:
    # PLAN.md 3.1 G16: the IANA XML <updated> date the snapshot was taken at.
    assert _registry.LAST_UPDATED == "2026-05-22"


def test_registry_domainkeys_followed_literally() -> None:
    # AU-Q31: IANA lists domainkeys temperror twice and no fail.
    assert _registry.result_registered("domainkeys", None, "temperror")
    assert not _registry.result_registered("domainkeys", None, "fail")


def test_registry_version_and_sender_id() -> None:
    assert _registry.result_registered("dkim", 1, "pass")
    assert not _registry.result_registered("dkim", 2, "pass")
    assert _registry.property_registered("sender-id", "header", "anything")
    assert not _registry.property_registered("sender-id", "smtp", "mailfrom")


# --- to_value of models the grammar cannot express (AU-Q33(b)) ---------------

_MODEL = ar("example.com", res("dkim", "pass", registered=True))


def _with_result(**changes: object) -> AuthenticationResults:
    result = dataclasses.replace(_MODEL.results[0], **changes)  # type: ignore[arg-type]
    return dataclasses.replace(_MODEL, results=(result,))


@pytest.mark.parametrize(
    "model",
    [
        pytest.param(_with_result(method=1), id="method not a str"),
        pytest.param(_with_result(method_version=True), id="method version bool"),
        pytest.param(dataclasses.replace(_MODEL, version=True), id="version bool"),
        pytest.param(dataclasses.replace(_MODEL, results=()), id="no results"),
        pytest.param(
            _with_result(properties=(prop("header", "d", 5, registered=True),)),  # type: ignore[arg-type]
            id="value not a str",
        ),
    ],
)
def test_to_value_refuses_inexpressible_models(model: AuthenticationResults) -> None:
    with pytest.raises(AuthResultsError) as info:
        model.to_value()
    assert info.value.reason is ErrorReason.SYNTAX
    assert info.value.position is None


def test_to_value_quotes_a_bad_quoted_local_part() -> None:
    model = ar(
        "example.com",
        res(
            "spf",
            "pass",
            prop("smtp", "mailfrom", '"a\\', registered=True),
            registered=True,
        ),
    )
    assert model.to_value() == 'example.com; spf=pass smtp.mailfrom="\\"a\\\\"'


# --- round trip over the case table's valid values (AU-Q17) ------------------

_ROUND_TRIP_IGNORED = frozenset(
    {Deviation.PVALUE_TSPECIALS, Deviation.TRAILING_SEMICOLON, Deviation.LF_FOLDING}
)


def _comparable(model: AuthenticationResults) -> object:
    results = tuple(
        dataclasses.replace(
            r,
            properties=tuple(
                dataclasses.replace(p, raw="", quoted=False) for p in r.properties
            ),
        )
        for r in model.results
    )
    return dataclasses.replace(
        model, results=results, deviations=model.deviations - _ROUND_TRIP_IGNORED
    )


def _payload(case: Case) -> AuthenticationResults | None:
    expected = case.expected
    if isinstance(expected, ArcAuthenticationResults):
        return expected.payload
    return expected if isinstance(expected, AuthenticationResults) else None


def _valid_cases() -> list[Case]:
    """Valid str values; a missing authserv-id is not serialised (AU-Q35)."""
    modules = (
        cases_spike,
        cases_rfc8601,
        cases_rfc8617,
        cases_grammar,
        cases_vendor,
        cases_redteam,
    )
    return [
        c
        for m in modules
        for c in m.CASES
        if c.call in {"parse", "parse_arc"}
        and type(c.value) is str
        and (payload := _payload(c)) is not None
        and payload.authserv_id is not None
    ]


@pytest.mark.parametrize("case", _valid_cases(), ids=lambda c: c.id)
def test_round_trip(case: Case) -> None:
    kwargs = case.kwargs.copy()
    value = str(case.value)
    first = (
        parse_arc(value, **kwargs).payload
        if case.call == "parse_arc"
        else parse(value, **kwargs)
    )
    text = first.to_value(ascii_only=False)
    kwargs.pop("strict_syntax", None)
    kwargs["ascii_only"] = False
    second = parse(text, **kwargs)
    assert _comparable(second) == _comparable(first)
    assert second.to_value(ascii_only=False) == text


# --- no INTERNAL for arbitrary input (PLAN.md 2.3) ----------------------------

_ALPHABET = (
    'abcdikmnoprsx019.-_;=/@"\\()<>,:[]? \t\r\n\x00\x7f\x85\u00fc\u212a'
    "dkim spf dmarc none reason header.d= smtp.mailfrom= i=1 "
)


def test_fuzz_never_internal() -> None:
    rng = random.Random(8601)  # noqa: S311 - reproducible test input, not crypto
    words = [*_ALPHABET, "dkim", "pass", "none", "reason", "header", "(", '"']
    seen: set[ErrorReason] = set()
    for _ in range(20_000):
        value = "".join(rng.choice(words) for _ in range(rng.randrange(40)))
        for call in (parse, parse_arc):
            for ascii_only in (True, False):
                try:
                    call(value, ascii_only=ascii_only)
                except AuthResultsError as err:
                    seen.add(err.reason)
    assert ErrorReason.INTERNAL not in seen
    assert ErrorReason.SYNTAX in seen


def test_exact_text_ignores_class_lies() -> None:
    class Liar:
        @property  # type: ignore[misc]
        def __class__(self) -> type:
            return str

    with pytest.raises(AuthResultsError) as info:
        parse(Liar())  # type: ignore[arg-type]
    assert info.value.reason is ErrorReason.INVALID_TYPE


def test_models_built_by_the_parser_are_the_public_types() -> None:
    parsed = parse("example.com; dkim=pass header.d=x")
    assert type(parsed.results[0]) is Result
    assert type(parsed.results[0].properties[0]) is Property


# --- the AU-Q41 table ---------------------------------------------------------


def test_space_format_table_sorted_and_disjoint() -> None:
    ranges = _unicode.RANGES
    assert all(first <= last for first, last in ranges)
    assert all(a[1] < b[0] for a, b in itertools.pairwise(ranges))


@pytest.mark.skipif(
    unicodedata.unidata_version != _unicode.UNICODE_VERSION,
    reason="the running Python's Unicode data is another version",
)
def test_space_format_table_matches_unicodedata() -> None:
    assert _unicode.UNICODE_VERSION == "17.0.0"
    categories = {"Zs", "Zl", "Zp", "Cf"}
    for point in range(sys.maxunicode + 1):
        char = chr(point)
        expected = point != 0x20 and unicodedata.category(char) in categories  # noqa: PLR2004
        assert _unicode.is_space_or_format(char) is expected, hex(point)


# --- caller-built models of the wrong shape (AL2b red-team L1 to L3) ---------


def _model(**fields: object) -> AuthenticationResults:
    values: dict[str, object] = {
        "authserv_id": "mx",
        "version": 1,
        "version_given": False,
        "none": False,
        "results": (res("dkim", "pass", registered=True),),
        "deviations": frozenset(),
    }
    values.update(fields)
    return AuthenticationResults(**values)  # type: ignore[arg-type]


def _result(properties: object) -> Result:
    return Result(
        method="dkim",
        method_version=None,
        result="pass",
        reason=None,
        properties=properties,  # type: ignore[arg-type]
        registered=True,
    )


_BAD_MODELS = {
    # L1: flags that are not bool
    "none None": _model(none=None, results=()),
    "none empty str": _model(none="", results=()),
    "none empty list": _model(none=[], results=()),
    "version_given str": _model(version_given="no"),
    # L2: wrong container or element types
    "results None": _model(results=None),
    "results (None,)": _model(results=(None,)),
    "results str": _model(results="ab"),
    "properties None": _model(results=(_result(None),)),
    "properties (None,)": _model(results=(_result((None,)),)),
    "deviations set": _model(deviations=set()),
    "deviations of str": _model(deviations=frozenset({"lf_folding"})),
}


@pytest.mark.parametrize("model", _BAD_MODELS.values(), ids=_BAD_MODELS.keys())
def test_to_value_refuses_malformed_shapes(model: AuthenticationResults) -> None:
    with pytest.raises(AuthResultsError) as info:
        model.to_value()
    assert info.value.reason is ErrorReason.SYNTAX
    assert info.value.position is None


def _prop(**fields: object) -> Property:
    good = prop("header", "d", "x", registered=True)
    return dataclasses.replace(good, **fields)  # type: ignore[arg-type]


_BAD_RESULTS = {
    "properties None": _result(None),
    "properties (None,)": _result((None,)),
    "properties str": _result("ab"),
    "ptype not str": _result((_prop(ptype=1),)),
    "name not str": _result((_prop(name=None),)),
}


@pytest.mark.parametrize("result", _BAD_RESULTS.values(), ids=_BAD_RESULTS.keys())
def test_accessors_refuse_malformed_results(result: Result) -> None:
    # L3: the closed error set, never TypeError or AttributeError.
    for call in (result.get, result.get_unique):
        with pytest.raises(AuthResultsError) as info:
            call("header", "d")
        assert info.value.reason is ErrorReason.SYNTAX
        assert info.value.position is None


@pytest.mark.parametrize(
    "model",
    [
        _model(results=None),
        _model(results=(None,)),
        _model(results="ab"),
        _model(results=(dataclasses.replace(_result(()), method=1),)),  # type: ignore[arg-type]
    ],
    ids=["None", "(None,)", "str", "method not str"],
)
def test_results_for_refuses_malformed_models(model: AuthenticationResults) -> None:
    with pytest.raises(AuthResultsError) as info:
        model.results_for("dkim")
    assert info.value.reason is ErrorReason.SYNTAX


def test_accessors_still_refuse_str_subclasses() -> None:
    # AU-Q43: caller keywords, so a str subclass stays INVALID_TYPE.
    class Sub(str):
        __slots__ = ()

    result = parse("mx; dkim=pass header.d=x").results[0]
    with pytest.raises(AuthResultsError) as info:
        result.get(Sub("header"), "d")
    assert info.value.reason is ErrorReason.INVALID_TYPE
    with pytest.raises(AuthResultsError) as info:
        _model().results_for(Sub("dkim"))
    assert info.value.reason is ErrorReason.INVALID_TYPE


def test_m1_round_trip_keeps_the_unfolded_address() -> None:
    first = parse('mx.example; spf=pass smtp.mailfrom="a\r\n b"@x.example')
    text = first.to_value()
    assert text == 'mx.example; spf=pass smtp.mailfrom="a b"@x.example'
    second = parse(text)
    assert second.results[0].properties[0].value == '"a b"@x.example'
    assert _comparable(second) == _comparable(first)
