# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""The public API surface: names, enums, errors, the guard, keywords, models."""

import dataclasses
import enum
import pickle
import re
import traceback
from collections.abc import Callable
from types import ModuleType
from typing import Any

import pytest

import authresults
from authresults import (
    ArcAuthenticationResults,
    AuthenticationResults,
    AuthResultsError,
    Deviation,
    ErrorReason,
    Property,
    Result,
    _api,
    _helpers,
    _model,
    ascii_domain,
    domain_of,
    parse,
    parse_arc,
)
from authresults._checks import ascii_lower
from authresults._errors import InternalCause

PUBLIC_NAMES = {
    "parse",
    "parse_arc",
    "AuthenticationResults",
    "ArcAuthenticationResults",
    "Result",
    "Property",
    "ErrorReason",
    "Deviation",
    "AuthResultsError",
    "domain_of",
    "ascii_domain",
}
REASONS = [
    "INVALID_TYPE",
    "EMPTY",
    "TOO_LONG",
    "NON_ASCII",
    "CONTROL_CHAR",
    "UNTERMINATED_COMMENT",
    "UNTERMINATED_QUOTED_STRING",
    "NESTING_TOO_DEEP",
    "SYNTAX",
    "UNSUPPORTED_VERSION",
    "TOO_MANY_RESULTS",
    "TOO_MANY_PROPERTIES",
    "DUPLICATE_REASON",
    "DUPLICATE_PROPERTY",
    "DEVIATION",
    "UNREGISTERED",
    "BAD_ARC_INSTANCE",
    "INTERNAL",
]
DEVIATIONS = ["BARE_PROPERTY", "PVALUE_TSPECIALS", "TRAILING_SEMICOLON", "LF_FOLDING"]
MESSAGE = re.compile(r"[a-z_]+( at position \d+)?")

ENTRY_POINTS: list[Callable[..., object]] = [parse, parse_arc]
LIMITS = ["max_length", "max_results", "max_properties", "max_comment_depth"]
FLAGS = ["ascii_only", "strict_syntax", "require_registered"]


class BoomInt(int):
    """An int whose comparisons raise."""

    def __lt__(self, other: object) -> bool:
        raise RuntimeError(other)


class LiarInt(int):
    """An int whose comparisons always say False."""

    def __lt__(self, other: object) -> bool:
        return False

    def __gt__(self, other: object) -> bool:
        return False


class Size(enum.IntEnum):
    EIGHT = 8


BAD_LIMITS: list[Any] = [
    0,
    -1,
    True,
    False,
    "8",
    8.0,
    None,
    BoomInt(5),
    LiarInt(-1),
    Size.EIGHT,
]
BAD_FLAGS: list[Any] = [0, 1, "yes", "", None]
NOT_STR: list[Any] = ["v", b"v", 123, None, object()]


# --- names ------------------------------------------------------------------


def test_all_is_exactly_the_public_names() -> None:
    assert set(authresults.__all__) == PUBLIC_NAMES
    assert len(authresults.__all__) == len(PUBLIC_NAMES)


@pytest.mark.parametrize("name", sorted(PUBLIC_NAMES))
def test_each_public_name_imports(name: str) -> None:
    namespace: dict[str, object] = {}
    exec(f"from authresults import {name}", namespace)  # noqa: S102
    assert namespace[name] is getattr(authresults, name)


# --- enums ------------------------------------------------------------------


def test_error_reason_members() -> None:
    assert [m.name for m in ErrorReason] == REASONS
    assert all(m.value == m.name.lower() for m in ErrorReason)


def test_deviation_members() -> None:
    assert [m.name for m in Deviation] == DEVIATIONS
    assert all(m.value == m.name.lower() for m in Deviation)


# --- the error --------------------------------------------------------------


@pytest.mark.parametrize("reason", list(ErrorReason))
@pytest.mark.parametrize("position", [None, 0, 42])
def test_error_message_format(reason: ErrorReason, position: int | None) -> None:
    err = AuthResultsError(reason, position)
    assert isinstance(err, ValueError)
    assert err.reason is reason
    assert err.position == position
    assert MESSAGE.fullmatch(str(err))
    expected = (
        reason.value if position is None else f"{reason.value} at position {position}"
    )
    assert str(err) == expected


def test_error_position_defaults_to_none() -> None:
    err = AuthResultsError(ErrorReason.EMPTY)
    assert err.position is None
    assert str(err) == "empty"


@pytest.mark.parametrize(
    ("reason", "position"),
    [
        (SECRET_TEXT := "alice@victim.example", None),
        ("syntax", None),
        (None, None),
        (ErrorReason.SYNTAX, SECRET_TEXT),
        (ErrorReason.SYNTAX, "3"),
        (ErrorReason.SYNTAX, True),
        (ErrorReason.SYNTAX, 3.0),
        (ErrorReason.SYNTAX, BoomInt(3)),
        (ErrorReason.SYNTAX, -1),
    ],
    ids=repr,
)
def test_error_rejects_bad_arguments(reason: object, position: object) -> None:
    with pytest.raises(TypeError) as info:
        AuthResultsError(reason, position)  # type: ignore[arg-type]
    assert SECRET_TEXT not in str(info.value)
    assert str(info.value) in {
        "reason must be an ErrorReason",
        "position must be an int of at least 0, or None",
    }


def test_error_pickles() -> None:
    err = AuthResultsError(ErrorReason.SYNTAX, 7)
    copy = pickle.loads(pickle.dumps(err))  # noqa: S301
    assert type(copy) is AuthResultsError
    assert (copy.reason, copy.position, str(copy)) == (ErrorReason.SYNTAX, 7, str(err))


# --- the guard --------------------------------------------------------------

SECRET = "alice.secret@victim.example"  # noqa: S105 - an address, not a password
EMPTY_MODEL = AuthenticationResults(
    authserv_id="mx.example",
    version=1,
    version_given=False,
    none=True,
    results=(),
    deviations=frozenset(),
)


@dataclasses.dataclass(frozen=True)
class Guarded:
    """A public callable that reads input, and the internal it guards."""

    module: ModuleType
    internal: str
    call: Callable[[], object]


GUARDED = {
    "parse": Guarded(_api, "_parse_payload", lambda: parse(SECRET)),
    "parse_arc": Guarded(_api, "_parse_arc_value", lambda: parse_arc(SECRET)),
    "to_value": Guarded(_model, "_serialize", EMPTY_MODEL.to_value),
    "domain_of": Guarded(_helpers, "_domain_of", lambda: domain_of(SECRET)),
    "ascii_domain": Guarded(_helpers, "_ascii_domain", lambda: ascii_domain(SECRET)),
}
guarded = pytest.mark.parametrize("target", GUARDED.values(), ids=GUARDED.keys())


def _patch(
    monkeypatch: pytest.MonkeyPatch, target: Guarded, make: Callable[[], BaseException]
) -> None:
    def boom(*_args: object, **_kwargs: object) -> object:
        raise make()

    monkeypatch.setattr(target.module, target.internal, boom)


def _raise_from_input_text() -> BaseException:
    # What a careless internal might do: an error whose text holds the input.
    with pytest.raises(ValueError, match="invalid literal") as info:
        int(SECRET)
    return info.value


def _with_context() -> AuthResultsError:
    # Raised while handling an error whose text holds the input.
    def inner() -> None:
        try:
            int(SECRET)
        except ValueError:
            raise AuthResultsError(ErrorReason.SYNTAX, 3)  # noqa: B904

    with pytest.raises(AuthResultsError) as info:
        inner()
    assert info.value.__context__ is not None
    return info.value


def _with_cause() -> AuthResultsError:
    # Chained explicitly from an error whose text holds the input.
    def inner() -> None:
        raise AuthResultsError(ErrorReason.SYNTAX, 3) from ValueError(SECRET)

    with pytest.raises(AuthResultsError) as info:
        inner()
    assert info.value.__cause__ is not None
    return info.value


def _with_note() -> AuthResultsError:
    err = AuthResultsError(ErrorReason.SYNTAX, 3)
    err.add_note(SECRET)
    return err


LEAKY_ERRORS = {"context": _with_context, "cause": _with_cause, "note": _with_note}


@guarded
def test_guard_wraps_exception_as_internal(
    monkeypatch: pytest.MonkeyPatch, target: Guarded
) -> None:
    _patch(monkeypatch, target, lambda: RuntimeError(SECRET))
    with pytest.raises(AuthResultsError) as info:
        target.call()
    err = info.value
    assert err.reason is ErrorReason.INTERNAL
    assert err.position is None
    assert str(err) == "internal"
    assert isinstance(err.__cause__, InternalCause)
    assert err.__cause__.type_name == "RuntimeError"
    assert err.__cause__.args == ("RuntimeError",)
    assert err.__cause__.__traceback__ is not None
    assert err.__context__ is None


@guarded
def test_internal_traceback_holds_no_input_text(
    monkeypatch: pytest.MonkeyPatch, target: Guarded
) -> None:
    _patch(monkeypatch, target, _raise_from_input_text)
    with pytest.raises(AuthResultsError) as info:
        target.call()
    rendered = "".join(traceback.format_exception(info.value))
    assert "ValueError" in rendered
    assert SECRET not in rendered


@guarded
@pytest.mark.parametrize("make", LEAKY_ERRORS.values(), ids=LEAKY_ERRORS.keys())
def test_guard_passes_auth_results_error_through(
    monkeypatch: pytest.MonkeyPatch,
    target: Guarded,
    make: Callable[[], AuthResultsError],
) -> None:
    original = make()
    _patch(monkeypatch, target, lambda: original)
    with pytest.raises(AuthResultsError) as info:
        target.call()
    err = info.value
    assert err is original
    assert (err.reason, err.position) == (ErrorReason.SYNTAX, 3)
    assert err.__suppress_context__ is True
    assert err.__cause__ is None
    assert not hasattr(err, "__notes__")
    rendered = "".join(traceback.format_exception(err))
    assert SECRET not in rendered


@guarded
def test_guard_keeps_an_internal_cause_passing_through(
    monkeypatch: pytest.MonkeyPatch, target: Guarded
) -> None:
    # An INTERNAL from an inner guard keeps its sanitised cause.
    inner = Guarded(_api, "_parse_payload", lambda: parse(SECRET))
    _patch(monkeypatch, inner, lambda: RuntimeError(SECRET))
    with pytest.raises(AuthResultsError) as first:
        inner.call()
    original = first.value
    _patch(monkeypatch, target, lambda: original)
    with pytest.raises(AuthResultsError) as info:
        target.call()
    assert info.value is original
    assert isinstance(info.value.__cause__, InternalCause)
    assert info.value.__cause__.type_name == "RuntimeError"


@guarded
@pytest.mark.parametrize("make", [KeyboardInterrupt, lambda: SystemExit(3)])
def test_guard_lets_base_exceptions_through(
    monkeypatch: pytest.MonkeyPatch,
    target: Guarded,
    make: Callable[[], BaseException],
) -> None:
    exc = make()
    _patch(monkeypatch, target, lambda: exc)
    with pytest.raises(BaseException) as info:  # noqa: PT011
        target.call()
    assert info.value is exc


# --- keyword validation -----------------------------------------------------


@pytest.mark.parametrize("entry", ENTRY_POINTS)
@pytest.mark.parametrize("keyword", LIMITS)
@pytest.mark.parametrize("bad", BAD_LIMITS, ids=repr)
@pytest.mark.parametrize("value", NOT_STR, ids=repr)
def test_bad_limit_raises_value_error(
    entry: Callable[..., object], keyword: str, bad: object, value: object
) -> None:
    with pytest.raises(ValueError, match=f"^{keyword} must be") as info:
        entry(value, **{keyword: bad})
    assert type(info.value) is ValueError


@pytest.mark.parametrize("entry", ENTRY_POINTS)
@pytest.mark.parametrize("keyword", FLAGS)
@pytest.mark.parametrize("bad", BAD_FLAGS, ids=repr)
@pytest.mark.parametrize("value", NOT_STR, ids=repr)
def test_bad_flag_raises_value_error(
    entry: Callable[..., object], keyword: str, bad: object, value: object
) -> None:
    with pytest.raises(ValueError, match=f"^{keyword} must be a bool$") as info:
        entry(value, **{keyword: bad})
    assert type(info.value) is ValueError


@pytest.mark.parametrize("bad", BAD_FLAGS, ids=repr)
def test_to_value_bad_flag_raises_value_error(
    monkeypatch: pytest.MonkeyPatch, bad: object
) -> None:
    def must_not_run(*_args: object, **_kwargs: object) -> str:
        raise AssertionError

    monkeypatch.setattr(_model, "_serialize", must_not_run)
    with pytest.raises(ValueError, match=r"^ascii_only must be a bool$") as info:
        EMPTY_MODEL.to_value(ascii_only=bad)  # type: ignore[arg-type]
    assert type(info.value) is ValueError


@pytest.mark.parametrize("entry", ENTRY_POINTS)
def test_keywords_are_keyword_only(entry: Callable[..., object]) -> None:
    with pytest.raises(TypeError):
        entry("x", 8192)


# --- models -----------------------------------------------------------------


def _prop(ptype: str | None, name: str, value: str) -> Property:
    return Property(
        ptype=ptype, name=name, value=value, raw=value, quoted=False, registered=True
    )


FROM_A = _prop("header", "from", "a.example")
FROM_B = _prop("header", "from", "b.example")
MAILFROM = _prop("smtp", "mailfrom", "x@a.example")
BARE = _prop(None, "action", "none")


def _result(method: str, *props: Property) -> Result:
    return Result(
        method=method,
        method_version=None,
        result="pass",
        reason=None,
        properties=props,
        registered=True,
    )


DMARC = _result("dmarc", FROM_A, MAILFROM, BARE)
DKIM_1 = _result("dkim", FROM_A, FROM_B)
DKIM_2 = _result("dkim")
MODEL = AuthenticationResults(
    authserv_id="mx.example",
    version=1,
    version_given=False,
    none=False,
    results=(DKIM_1, DMARC, DKIM_2),
    deviations=frozenset({Deviation.BARE_PROPERTY}),
)
ARC = ArcAuthenticationResults(instance=1, payload=MODEL)
MODELS: list[object] = [FROM_A, DMARC, MODEL, ARC]


@pytest.mark.parametrize("model", MODELS, ids=lambda m: type(m).__name__)
def test_models_are_frozen_and_slotted(model: object) -> None:
    assert dataclasses.is_dataclass(model)
    assert not hasattr(model, "__dict__")
    field = dataclasses.fields(model)[0].name
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(model, field, None)


@pytest.mark.parametrize(
    "cls", [Property, Result, AuthenticationResults, ArcAuthenticationResults]
)
def test_model_fields_have_no_defaults(cls: type) -> None:
    for field in dataclasses.fields(cls):
        assert field.default is dataclasses.MISSING
        assert field.default_factory is dataclasses.MISSING


def test_results_for_matches_in_order_and_ignores_case() -> None:
    assert MODEL.results_for("dkim") == (DKIM_1, DKIM_2)
    assert MODEL.results_for("DKIM") == (DKIM_1, DKIM_2)
    assert MODEL.results_for("DMARC") == (DMARC,)
    assert MODEL.results_for("spf") == ()


def test_get_returns_all_matches_in_order() -> None:
    assert DKIM_1.get("header", "from") == (FROM_A, FROM_B)
    assert DKIM_1.get("HEADER", "From") == (FROM_A, FROM_B)
    assert DMARC.get("smtp", "mailfrom") == (MAILFROM,)
    assert DMARC.get("smtp", "from") == ()
    assert DMARC.get("header", "mailfrom") == ()


def test_get_bare_property_with_none_ptype() -> None:
    assert DMARC.get(None, "ACTION") == (BARE,)
    assert DMARC.get("header", "action") == ()


def test_get_unique() -> None:
    assert DMARC.get_unique("Header", "FROM") is FROM_A
    assert DMARC.get_unique("header", "d") is None
    assert DMARC.get_unique(None, "action") is BARE


def test_get_unique_refuses_duplicates() -> None:
    with pytest.raises(AuthResultsError) as info:
        DKIM_1.get_unique("header", "from")
    assert info.value.reason is ErrorReason.DUPLICATE_PROPERTY
    assert info.value.position is None


class EvilStr(str):
    """A str subclass whose methods must never be called."""

    __slots__ = ()

    def lower(self) -> str:
        raise RuntimeError(self)

    def translate(self, table: object) -> str:  # noqa: ARG002
        raise RuntimeError(self)


ACCESSOR_BAD_ARGS: dict[str, Callable[[], object]] = {
    "results_for(None)": lambda: MODEL.results_for(None),  # type: ignore[arg-type]
    "results_for(1)": lambda: MODEL.results_for(1),  # type: ignore[arg-type]
    "results_for(bytes)": lambda: MODEL.results_for(b"dkim"),  # type: ignore[arg-type]
    "results_for(str subclass)": lambda: MODEL.results_for(EvilStr("dkim")),
    "get(1, name)": lambda: DMARC.get(1, "from"),  # type: ignore[arg-type]
    "get(ptype, None)": lambda: DMARC.get("header", None),  # type: ignore[arg-type]
    "get(str subclass, name)": lambda: DMARC.get(EvilStr("header"), "from"),
    "get(ptype, str subclass)": lambda: DMARC.get("header", EvilStr("from")),
    "get_unique(None, None)": lambda: DMARC.get_unique(None, None),  # type: ignore[arg-type]
    "get_unique(bytes, name)": lambda: DMARC.get_unique(b"header", "from"),  # type: ignore[arg-type]
}


@pytest.mark.parametrize(
    "call", ACCESSOR_BAD_ARGS.values(), ids=ACCESSOR_BAD_ARGS.keys()
)
def test_accessors_refuse_non_str(call: Callable[[], object]) -> None:
    with pytest.raises(AuthResultsError) as info:
        call()
    assert info.value.reason is ErrorReason.INVALID_TYPE
    assert info.value.position is None


def test_accessors_fold_ascii_case_only() -> None:
    kelvin_dkim = "D\u212aIM"  # KELVIN SIGN, which str.lower() maps to "k"
    long_s_smtp = "\u017fmtp"  # LATIN SMALL LETTER LONG S, casefold() gives "s"
    assert kelvin_dkim.lower() == "dkim"
    assert MODEL.results_for(kelvin_dkim) == ()
    assert MODEL.results_for("\u017fpf") == ()
    assert DMARC.get(long_s_smtp, "mailfrom") == ()
    assert DMARC.get("smtp", "MAILFROM") == (MAILFROM,)
    assert DMARC.get_unique("header", "FRO\u1d39") is None


def test_ascii_lower_maps_only_a_to_z() -> None:
    assert ascii_lower("ABCXYZ abcxyz 0-9_.") == "abcxyz abcxyz 0-9_."
    assert ascii_lower("\u00c0\u212a\u0130\u017f") == "\u00c0\u212a\u0130\u017f"
