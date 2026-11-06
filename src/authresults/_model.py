# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""The immutable result model."""

from dataclasses import dataclass

from ._checks import check_flag, keyword_arg
from ._errors import AuthResultsError, Deviation, ErrorReason, call_guarded


@dataclass(frozen=True, slots=True)
class Property:
    """One ``ptype.name=value`` property of a result."""

    ptype: str | None
    name: str
    value: str
    raw: str
    quoted: bool
    registered: bool


@dataclass(frozen=True, slots=True)
class Result:
    """One ``method[/version]=result`` entry with its reason and properties."""

    method: str
    method_version: int | None
    result: str
    reason: str | None
    properties: tuple[Property, ...]
    registered: bool

    def get(self, ptype: str | None, name: str) -> tuple[Property, ...]:
        """Return every property with this ptype and name, in order.

        Both are matched ASCII-case-insensitively. Pass ``None`` as ``ptype``
        for a bare ``name=value`` property. A non-``str`` argument raises
        ``AuthResultsError(INVALID_TYPE)``; a non-ASCII one matches nothing.
        """
        want_ptype = None if ptype is None else keyword_arg(ptype)
        want_name = keyword_arg(name)
        return tuple(
            p for p in self.properties if p.ptype == want_ptype and p.name == want_name
        )

    def get_unique(self, ptype: str | None, name: str) -> Property | None:
        """Return the one matching property, ``None`` if there is none.

        Raises ``AuthResultsError(DUPLICATE_PROPERTY)`` if there are several.
        """
        found = self.get(ptype, name)
        if len(found) > 1:
            raise AuthResultsError(ErrorReason.DUPLICATE_PROPERTY)
        return found[0] if found else None


@dataclass(frozen=True, slots=True)
class AuthenticationResults:
    """One parsed ``Authentication-Results`` value.

    ``authserv_id`` is ``None`` only when the value has none (recorded as
    ``Deviation.MISSING_AUTHSERV_ID``).
    """

    authserv_id: str | None
    version: int
    version_given: bool
    none: bool
    results: tuple[Result, ...]
    deviations: frozenset[Deviation]

    def results_for(self, method: str) -> tuple[Result, ...]:
        """Return every result for this method, in order.

        Matched ASCII-case-insensitively. A non-``str`` argument raises
        ``AuthResultsError(INVALID_TYPE)``; a non-ASCII one matches nothing.
        """
        want = keyword_arg(method)
        return tuple(r for r in self.results if r.method == want)

    def to_value(self, *, ascii_only: bool = True) -> str:
        """Serialize to the canonical header field value.

        Raises ``AuthResultsError`` (``CONTROL_CHAR`` or ``NON_ASCII``) rather
        than produce a value that could inject a header, and ``ValueError``
        if ``ascii_only`` is not a ``bool``.
        """
        check_flag("ascii_only", ascii_only)
        return call_guarded(_serialize, self, ascii_only=ascii_only)


@dataclass(frozen=True, slots=True)
class ArcAuthenticationResults:
    """One parsed ``ARC-Authentication-Results`` value: ``i=`` plus the payload."""

    instance: int
    payload: AuthenticationResults


def _serialize(model: AuthenticationResults, *, ascii_only: bool) -> str:
    raise NotImplementedError
