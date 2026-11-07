# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Red-team repros found during AL2b (PLAN.md 6, AL2b row).

Empty at AL3a. AL2b appends each repro verbatim, with its expected outcome
and a cite; this file is the one case module outside the frozen-file diff.
"""

from typing import cast

from authresults import AuthenticationResults, Deviation, ErrorReason, Property, Result

from ._case import Case, ar, prop, res

_M1_CITE = (
    "AL2b red-team M1; AU-Q42 (folds in a quoted local-part are unfolded in "
    "value by removing the line break, RFC 5322 2.2.3; raw keeps the fold)"
)

_L_CITE = (
    "AL2b red-team L1 to L3; AU-Q33(b) (to_value raises SYNTAX with "
    "position=None for a model it cannot write); PLAN.md 2.3 and CLAUDE.md "
    "(closed error set: never TypeError or AttributeError)"
)


def _model(
    *,
    authserv_id: object = "mx.example",
    none: object = False,
    results: object = None,
) -> AuthenticationResults:
    """A caller-built model; the fields given may have the wrong type."""
    return AuthenticationResults(
        authserv_id=cast("str", authserv_id),
        version=1,
        version_given=False,
        none=cast("bool", none),
        results=cast(
            "tuple[Result, ...]",
            (res("dkim", "pass", registered=True),) if results is None else results,
        ),
        deviations=frozenset(),
    )


def _result(properties: object) -> Result:
    return Result(
        method="dkim",
        method_version=None,
        result="pass",
        reason=None,
        properties=cast("tuple[Property, ...]", properties),
        registered=True,
    )


def _malformed(case_id: str, model: AuthenticationResults) -> Case:
    return Case(
        id=f"redteam {case_id}",
        call="to_value",
        value=model,
        expected=ErrorReason.SYNTAX,
        position=None,
        cite=_L_CITE,
    )


CASES: tuple[Case, ...] = (
    Case(
        id="redteam M1 crlf fold in quoted local-part",
        value='mx.example; spf=pass smtp.mailfrom="a\r\n b"@x.example',
        expected=ar(
            "mx.example",
            res(
                "spf",
                "pass",
                prop(
                    "smtp",
                    "mailfrom",
                    '"a b"@x.example',
                    raw='"a\r\n b"@x.example',
                    registered=True,
                ),
                registered=True,
            ),
        ),
        cite=_M1_CITE,
    ),
    Case(
        id="redteam M1 lf fold in quoted local-part",
        value='mx.example; spf=pass smtp.mailfrom="a\n b"@x.example',
        expected=ar(
            "mx.example",
            res(
                "spf",
                "pass",
                prop(
                    "smtp",
                    "mailfrom",
                    '"a b"@x.example',
                    raw='"a\n b"@x.example',
                    registered=True,
                ),
                registered=True,
            ),
            deviations=(Deviation.LF_FOLDING,),
        ),
        cite=_M1_CITE + "; G5 (LF plus WSP is LF_FOLDING)",
    ),
    # AL3b coverage audit: these branches were covered only by
    # tests/test_parser_units.py; the expectations follow AU-Q33(b).
    _malformed("L1 to_value none is not a bool", _model(none=None, results=())),
    _malformed(
        "L2 to_value results is a list",
        _model(results=[res("dkim", "pass", registered=True)]),
    ),
    _malformed(
        "L2 to_value properties is a list",
        _model(results=(_result([]),)),
    ),
    _malformed("L2 to_value authserv-id is not a str", _model(authserv_id=1)),
)
