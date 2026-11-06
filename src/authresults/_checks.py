# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Argument checks and ASCII-only case folding.

Keyword checks raise ``ValueError`` (a caller bug) and run before any input is
read. They compare exact types, so ``int`` and ``str`` subclasses, whose
methods could raise or lie, are never trusted.
"""

from ._errors import AuthResultsError, ErrorReason

_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def check_limit(name: str, limit: int) -> None:
    """Raise ``ValueError`` unless *limit* is an exact ``int`` of at least 1."""
    if type(limit) is not int or limit < 1:
        msg = f"{name} must be an int of at least 1"
        raise ValueError(msg)


def check_flag(name: str, flag: object) -> None:
    """Raise ``ValueError`` unless *flag* is ``True`` or ``False``."""
    if flag is not True and flag is not False:
        msg = f"{name} must be a bool"
        raise ValueError(msg)


def ascii_lower(text: str) -> str:
    """Lowercase A to Z only; every other character is left as it is.

    ``str.lower`` would also map e.g. U+212A KELVIN SIGN to ``k``. *text* must
    be an exact ``str`` (see ``keyword_arg``).
    """
    return text.translate(_ASCII_LOWER)


def keyword_arg(text: str) -> str:
    """Return the ASCII-lowercased lookup argument, or raise ``INVALID_TYPE``."""
    if type(text) is not str:
        raise AuthResultsError(ErrorReason.INVALID_TYPE)
    return ascii_lower(text)
