# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""AL2a stubs: every input-reading callable answers INTERNAL. Deleted at AL2b."""

from collections.abc import Callable

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

MODEL = AuthenticationResults(
    authserv_id="mx.example",
    version=1,
    version_given=False,
    none=True,
    results=(),
    deviations=frozenset(),
)

CALLS: dict[str, Callable[[], object]] = {
    "parse": lambda: parse("x"),
    "parse_arc": lambda: parse_arc("x"),
    "to_value": MODEL.to_value,
    "to_value_non_ascii": lambda: MODEL.to_value(ascii_only=False),
    "domain_of": lambda: domain_of("x"),
    "ascii_domain": lambda: ascii_domain("x"),
}


@pytest.mark.parametrize("call", CALLS.values(), ids=CALLS.keys())
def test_stub_raises_internal_from_not_implemented(call: Callable[[], object]) -> None:
    with pytest.raises(AuthResultsError) as info:
        call()
    assert info.value.reason is ErrorReason.INTERNAL
    assert info.value.position is None
    assert isinstance(info.value.__cause__, InternalCause)
    assert info.value.__cause__.type_name == "NotImplementedError"
