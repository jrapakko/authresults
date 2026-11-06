# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Zero-dependency domain helpers for property values."""

from ._errors import call_guarded


def domain_of(value: str) -> str | None:
    """Return the part after the last ``@``, or the whole value if there is none."""
    return call_guarded(_domain_of, value)


def ascii_domain(value: str) -> str | None:
    """Return the lowercased domain if it is LDH or A-labels only, else ``None``."""
    return call_guarded(_ascii_domain, value)


def _domain_of(value: str) -> str | None:
    raise NotImplementedError


def _ascii_domain(value: str) -> str | None:
    raise NotImplementedError
