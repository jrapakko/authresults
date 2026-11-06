# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""The public entry points ``parse`` and ``parse_arc``."""

from dataclasses import dataclass

from ._checks import check_flag, check_limit
from ._errors import call_guarded
from ._model import ArcAuthenticationResults, AuthenticationResults


@dataclass(frozen=True, slots=True)
class _Options:
    max_length: int
    max_results: int
    max_properties: int
    max_comment_depth: int
    ascii_only: bool
    strict_syntax: bool
    require_registered: bool


def _options(  # noqa: PLR0913 - mirrors the public keyword set of parse()
    *,
    max_length: int,
    max_results: int,
    max_properties: int,
    max_comment_depth: int,
    ascii_only: bool,
    strict_syntax: bool,
    require_registered: bool,
) -> _Options:
    """Validate the keywords (a caller bug raises ``ValueError``)."""
    check_limit("max_length", max_length)
    check_limit("max_results", max_results)
    check_limit("max_properties", max_properties)
    check_limit("max_comment_depth", max_comment_depth)
    check_flag("ascii_only", ascii_only)
    check_flag("strict_syntax", strict_syntax)
    check_flag("require_registered", require_registered)
    return _Options(
        max_length=max_length,
        max_results=max_results,
        max_properties=max_properties,
        max_comment_depth=max_comment_depth,
        ascii_only=ascii_only,
        strict_syntax=strict_syntax,
        require_registered=require_registered,
    )


def parse(  # noqa: PLR0913 - the keyword-only limits and flags are the public API
    value: str,
    *,
    max_length: int = 8192,
    max_results: int = 64,
    max_properties: int = 64,
    max_comment_depth: int = 16,
    ascii_only: bool = True,
    strict_syntax: bool = False,
    require_registered: bool = False,
) -> AuthenticationResults:
    """Parse one ``Authentication-Results`` header field value.

    Raises ``ValueError`` for an invalid keyword argument (before ``value`` is
    read) and ``AuthResultsError`` for anything wrong with ``value``.
    """
    options = _options(
        max_length=max_length,
        max_results=max_results,
        max_properties=max_properties,
        max_comment_depth=max_comment_depth,
        ascii_only=ascii_only,
        strict_syntax=strict_syntax,
        require_registered=require_registered,
    )
    return call_guarded(_parse_payload, value, options)


def parse_arc(  # noqa: PLR0913 - same keywords as parse(), spelled out
    value: str,
    *,
    max_length: int = 8192,
    max_results: int = 64,
    max_properties: int = 64,
    max_comment_depth: int = 16,
    ascii_only: bool = True,
    strict_syntax: bool = False,
    require_registered: bool = False,
) -> ArcAuthenticationResults:
    """Parse one ``ARC-Authentication-Results`` header field value.

    ``max_length`` counts the whole value, including ``i=``. Errors as for
    ``parse``.
    """
    options = _options(
        max_length=max_length,
        max_results=max_results,
        max_properties=max_properties,
        max_comment_depth=max_comment_depth,
        ascii_only=ascii_only,
        strict_syntax=strict_syntax,
        require_registered=require_registered,
    )
    return call_guarded(_parse_arc_value, value, options)


def _parse_payload(value: str, options: _Options) -> AuthenticationResults:
    raise NotImplementedError


def _parse_arc_value(value: str, options: _Options) -> ArcAuthenticationResults:
    raise NotImplementedError
