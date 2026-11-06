# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Parser for RFC 8601 ``Authentication-Results`` header field values."""

from ._api import parse, parse_arc
from ._errors import AuthResultsError, Deviation, ErrorReason
from ._helpers import ascii_domain, domain_of
from ._model import ArcAuthenticationResults, AuthenticationResults, Property, Result

__version__ = "0.1.0.dev0"

__all__ = [
    "ArcAuthenticationResults",
    "AuthResultsError",
    "AuthenticationResults",
    "Deviation",
    "ErrorReason",
    "Property",
    "Result",
    "ascii_domain",
    "domain_of",
    "parse",
    "parse_arc",
]
