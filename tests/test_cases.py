# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Run the case table (PLAN.md 4 and 6.2).

A case still waiting on an AL2a stub raises ``Pending`` (xfailed by the hook
in ``tests/_pending.py`` for ids in ``PENDING_IDS``); any other failure, a
wrong answer or an ``INTERNAL`` from a real bug, fails hard.
"""

import sys
from collections.abc import Callable
from typing import cast

import pytest

from authresults import (
    AuthenticationResults,
    AuthResultsError,
    ErrorReason,
    ascii_domain,
    domain_of,
    parse,
    parse_arc,
)
from authresults._errors import InternalCause

from . import (
    cases_grammar,
    cases_helpers,
    cases_limits,
    cases_redteam,
    cases_rfc8601,
    cases_rfc8617,
    cases_spike,
    cases_to_value,
    cases_vendor,
)
from ._case import ANY_POSITION, Case, Pending, fingerprint

# The case table runs only under the guards in tests/conftest.py, which
# imports this module while it loads (AL3a round 3, N1). Without them (for
# example --noconftest) importing the table is an error, and each case checks
# that the guard module is a registered plugin.
_GUARD = sys.modules.get(f"{__package__}.conftest")
if _GUARD is None:
    _MSG = "tests/conftest.py (the case-table guards) is not loaded"
    raise RuntimeError(_MSG)

ALL_CASES: tuple[Case, ...] = (
    *cases_spike.CASES,
    *cases_rfc8601.CASES,
    *cases_rfc8617.CASES,
    *cases_grammar.CASES,
    *cases_vendor.CASES,
    *cases_limits.CASES,
    *cases_helpers.CASES,
    *cases_to_value.CASES,
    *cases_redteam.CASES,
)


def is_stub_error(err: AuthResultsError) -> bool:
    """True only for the AL2a stub error (PLAN.md 6.2, exact detection)."""
    return (
        err.reason is ErrorReason.INTERNAL
        and isinstance(err.__cause__, InternalCause)
        and err.__cause__.type_name == "NotImplementedError"
    )


def _run(case: Case) -> object:
    value = case.value
    if case.call == "parse":
        return parse(cast("str", value), **case.kwargs)
    if case.call == "parse_arc":
        return parse_arc(cast("str", value), **case.kwargs)
    if case.call == "domain_of":
        return domain_of(cast("str", value))
    if case.call == "ascii_domain":
        return ascii_domain(cast("str", value))
    if case.call == "to_value":
        model = cast("AuthenticationResults", value)
        return model.to_value(ascii_only=case.kwargs.get("ascii_only", True))
    assert case.lookup is not None
    parsed = parse(cast("str", value), **case.kwargs)
    return parsed.results[0].get_unique(*case.lookup)


def _check_error(case: Case, err: AuthResultsError) -> None:
    """The reason, the position and an error object that carries no input."""
    assert isinstance(case.expected, ErrorReason), f"unexpected error {err.reason}"
    assert type(err) is AuthResultsError
    assert err.reason is case.expected
    assert type(err.reason) is ErrorReason
    if case.position is not ANY_POSITION:
        assert err.position == case.position
        assert type(err.position) is type(case.position)
    # PLAN.md 2.3: the message, args and repr never contain input text.
    message = (
        str(err.reason)
        if err.position is None
        else f"{err.reason} at position {err.position}"
    )
    assert str(err) == message
    assert err.args == (message,)
    assert repr(err) == f"AuthResultsError({message!r})"
    assert set(vars(err)) == {"reason", "position"}
    assert not hasattr(err, "__notes__")
    # No cause rides along (the expected reason is never INTERNAL).
    assert err.__cause__ is None
    # No context shows either: none was set (an error raised before or outside
    # the guard, e.g. Result.get_unique), or the guard suppressed it.
    assert err.__context__ is None or err.__suppress_context__ is True


def _params() -> list[object]:
    params: list[object] = []
    for case in ALL_CASES:
        marks = [] if case.timeout is None else [pytest.mark.timeout(case.timeout)]
        params.append(pytest.param(case, id=case.id, marks=marks))
    return params


@pytest.mark.parametrize("case", _params())
def test_case(
    case: Case,
    request: pytest.FixtureRequest,
    *,
    _run: Callable[[Case], object] = _run,  # noqa: PT019, PT028
    _check_error: Callable[[Case, AuthResultsError], None] = _check_error,  # noqa: PT019, PT028
    _is_stub: Callable[[AuthResultsError], bool] = is_stub_error,  # noqa: PT019, PT028
    _fingerprint: Callable[[object], object] = fingerprint,  # noqa: PT019, PT028
) -> None:
    # The helpers are bound as defaults at definition time, so rebinding the
    # module attributes later (from a conftest or plugin) cannot swap them.
    assert request.config.pluginmanager.is_registered(_GUARD)
    try:
        actual = _run(case)
    except AuthResultsError as err:
        if _is_stub(err):
            raise Pending from None
        _check_error(case, err)
        return
    assert not isinstance(case.expected, ErrorReason), "expected an error"
    assert actual == case.expected
    assert _fingerprint(actual) == _fingerprint(case.expected)
