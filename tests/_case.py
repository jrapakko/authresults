# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""The case-table record, model factories and the type fingerprint.

Every expectation in ``tests/cases_*.py`` was derived from the RFCs and
PLAN.md section 3 and 3.1, never from an implementation. The factories build
the real dataclasses, so mypy checks the table against the public API; they
only shorten the spelling (``frozenset`` of deviations, ``raw`` defaulting to
``value``), they compute nothing.
"""

import dataclasses
from dataclasses import dataclass, field
from typing import Final, Literal, TypedDict

import pytest

from authresults import (
    ArcAuthenticationResults,
    AuthenticationResults,
    Deviation,
    ErrorReason,
    Property,
    Result,
)


class _AnyPosition:
    """Marker: the case pins the reason, not the offset (AU-Q16)."""

    def __repr__(self) -> str:
        return "ANY_POSITION"


class _Unset:
    """Marker: no position given (only valid for a case that does not raise)."""

    def __repr__(self) -> str:
        return "UNSET"


ANY_POSITION: Final = _AnyPosition()
UNSET: Final = _Unset()


# Where the pending hook (tests/_pending.py) leaves the ids it marks, so the
# permanent guards in tests/conftest.py can check every xfail against them.
PENDING_KEY: Final = pytest.StashKey[frozenset[str]]()


class Pending(Exception):  # noqa: N818 - a signal, not an error to handle
    """Raised by ``tests/test_cases.py`` when a case hits an AL2a stub.

    Defined here, not in ``tests/_pending.py``, so the frozen files keep
    importing cleanly after AL2b deletes that module (PLAN.md 6.2).
    """


Call = Literal[
    "parse", "parse_arc", "domain_of", "ascii_domain", "to_value", "get_unique"
]

Expected = (
    AuthenticationResults
    | ArcAuthenticationResults
    | Property
    | ErrorReason
    | str
    | None
)


class Options(TypedDict, total=False):
    """Keyword arguments for ``parse``/``parse_arc`` (``to_value``: ascii_only)."""

    max_length: int
    max_results: int
    max_properties: int
    max_comment_depth: int
    ascii_only: bool
    strict_syntax: bool
    require_registered: bool


@dataclass(frozen=True, slots=True)
class Case:
    """One row of the case table.

    - ``value``: the input (a ``str``, or a non-``str`` for ``INVALID_TYPE``;
      an ``AuthenticationResults`` for ``to_value``).
    - ``expected``: the model, helper result or serialised string, or the
      ``ErrorReason`` that must be raised.
    - ``position``: for an error, an ``int``, ``None`` or ``ANY_POSITION``.
    - ``deviation``: for a strict ``DEVIATION`` case, the deviation it tests.
    - ``lookup``: for ``get_unique``, the ``(ptype, name)`` asked of result 0.
    - ``url``, ``read``, ``rewrite``: vendor provenance.
    - ``timeout``: seconds, for the timing cases.
    """

    id: str
    value: object
    expected: Expected
    cite: str
    call: Call = "parse"
    kwargs: Options = field(default_factory=Options)
    position: int | _AnyPosition | _Unset | None = UNSET
    deviation: Deviation | None = None
    lookup: tuple[str | None, str] | None = None
    url: str | None = None
    read: str | None = None
    rewrite: str | None = None
    timeout: float | None = None


def prop(  # noqa: PLR0913 - mirrors the Property fields
    ptype: str,
    name: str,
    value: str,
    *,
    registered: bool,
    raw: str | None = None,
    quoted: bool = False,
) -> Property:
    """A ``ptype.name=value`` property; ``raw`` defaults to ``value``."""
    return Property(
        ptype=ptype,
        name=name,
        value=value,
        raw=value if raw is None else raw,
        quoted=quoted,
        registered=registered,
    )


def bare(name: str, value: str, *, raw: str | None = None) -> Property:
    """A bare ``name=value`` property (``BARE_PROPERTY``), never registered."""
    return Property(
        ptype=None,
        name=name,
        value=value,
        raw=value if raw is None else raw,
        quoted=False,
        registered=False,
    )


def res(
    method: str,
    result: str,
    *properties: Property,
    registered: bool,
    version: int | None = None,
    reason: str | None = None,
) -> Result:
    """One result."""
    return Result(
        method=method,
        method_version=version,
        result=result,
        reason=reason,
        properties=tuple(properties),
        registered=registered,
    )


def ar(
    authserv_id: str | None,
    *results: Result,
    version_given: bool = False,
    none: bool = False,
    deviations: tuple[Deviation, ...] = (),
) -> AuthenticationResults:
    """One payload; ``version`` is always 1 (any other is an error)."""
    return AuthenticationResults(
        authserv_id=authserv_id,
        version=1,
        version_given=version_given,
        none=none,
        results=tuple(results),
        deviations=frozenset(deviations),
    )


def fingerprint(obj: object) -> object:
    """Describe *obj* by exact types as well as values.

    ``==`` alone accepts a ``set`` for a ``frozenset``, a ``list`` for a
    ``tuple``, ``1`` for ``True`` and a plain ``str`` for a ``Deviation``;
    comparing fingerprints too does not.
    """
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return (
            type(obj),
            tuple(
                (f.name, fingerprint(getattr(obj, f.name)))
                for f in dataclasses.fields(obj)
            ),
        )
    if type(obj) is tuple:
        return (tuple, tuple(fingerprint(item) for item in obj))
    if type(obj) is frozenset:
        return (frozenset, tuple(sorted((type(i).__name__, str(i)) for i in obj)))
    return (type(obj), obj)
