# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""The closed error set: reasons, deviations, the exception and its guard."""

import contextlib
import enum
from collections.abc import Callable
from typing import ParamSpec, TypeVar

_P = ParamSpec("_P")
_R = TypeVar("_R")


class ErrorReason(enum.StrEnum):
    """Why a value was refused.

    Closed: grows only by a release.
    """

    INVALID_TYPE = enum.auto()
    EMPTY = enum.auto()
    TOO_LONG = enum.auto()
    NON_ASCII = enum.auto()
    CONTROL_CHAR = enum.auto()
    UNTERMINATED_COMMENT = enum.auto()
    UNTERMINATED_QUOTED_STRING = enum.auto()
    NESTING_TOO_DEEP = enum.auto()
    SYNTAX = enum.auto()
    UNSUPPORTED_VERSION = enum.auto()
    TOO_MANY_RESULTS = enum.auto()
    TOO_MANY_PROPERTIES = enum.auto()
    DUPLICATE_REASON = enum.auto()
    DUPLICATE_PROPERTY = enum.auto()
    DEVIATION = enum.auto()
    UNREGISTERED = enum.auto()
    BAD_ARC_INSTANCE = enum.auto()
    INTERNAL = enum.auto()


class Deviation(enum.StrEnum):
    """A known real-world departure from the grammar.

    Closed: grows only by a release, with a fixture that justifies it.
    """

    BARE_PROPERTY = enum.auto()
    PVALUE_TSPECIALS = enum.auto()
    TRAILING_SEMICOLON = enum.auto()
    LF_FOLDING = enum.auto()
    MISSING_AUTHSERV_ID = enum.auto()


class AuthResultsError(ValueError):
    """The only exception the parser raises for any ``str`` input.

    The message is ``"<reason>"`` or ``"<reason> at position <n>"`` and never
    contains input text.
    """

    reason: ErrorReason
    position: int | None

    def __init__(self, reason: ErrorReason, position: int | None = None) -> None:
        """Create the error from a reason and an optional character offset.

        A wrong argument type is a caller bug and raises ``TypeError``, whose
        message does not repeat the argument.
        """
        if type(reason) is not ErrorReason:
            msg = "reason must be an ErrorReason"
            raise TypeError(msg)
        if position is not None and (type(position) is not int or position < 0):
            msg = "position must be an int of at least 0, or None"
            raise TypeError(msg)
        message = (
            str(reason) if position is None else f"{reason} at position {position}"
        )
        super().__init__(message)
        self.reason = reason
        self.position = position

    def __reduce__(
        self,
    ) -> tuple[type["AuthResultsError"], tuple[ErrorReason, int | None]]:
        """Pickle by reason and position, not by message."""
        return (type(self), (self.reason, self.position))


class InternalCause(Exception):  # noqa: N818 - a stand-in, not an error to catch
    """Private stand-in set as ``__cause__`` of an ``INTERNAL`` error.

    It carries only the original exception's type name (``type_name``, the
    ``__qualname__``, e.g. ``"NotImplementedError"``) and its traceback, never
    its message or arguments, so no input text reaches a logged traceback.
    Not public API; tests may rely on ``type_name``.
    """

    type_name: str

    def __init__(self, type_name: str) -> None:
        """Record the original exception's type name."""
        super().__init__(type_name)
        self.type_name = type_name


def call_guarded(
    function: Callable[_P, _R], /, *args: _P.args, **kwargs: _P.kwargs
) -> _R:
    """Call *function*, keeping the closed error set.

    - ``AuthResultsError`` passes through as the same object, with its context
      suppressed, its ``__cause__`` dropped (unless it is an ``InternalCause``)
      and its ``__notes__`` removed, so no input text rides along.
    - Any other ``Exception`` becomes ``AuthResultsError(INTERNAL)``, chained
      from an ``InternalCause`` that carries the original type name and
      traceback only.
    - ``BaseException`` that is not an ``Exception`` (``KeyboardInterrupt``,
      ``SystemExit``) is not caught.
    """
    try:
        return function(*args, **kwargs)
    except AuthResultsError as err:
        if not isinstance(err.__cause__, InternalCause):
            err.__cause__ = None
        err.__suppress_context__ = True
        with contextlib.suppress(AttributeError):
            del err.__notes__
        raise
    except Exception as exc:  # noqa: BLE001 - the guard's whole purpose
        cause = InternalCause(type(exc).__qualname__).with_traceback(exc.__traceback__)
    # Raised outside the handler, so the original is not attached as context.
    raise AuthResultsError(ErrorReason.INTERNAL) from cause
