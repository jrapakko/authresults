# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Red-team repros found during AL2b (PLAN.md 6, AL2b row).

Empty at AL3a. AL2b appends each repro verbatim, with its expected outcome
and a cite; this file is the one case module outside the frozen-file diff.
"""

from authresults import Deviation

from ._case import Case, ar, prop, res

_M1_CITE = (
    "AL2b red-team M1; AU-Q42 (folds in a quoted local-part are unfolded in "
    "value by removing the line break, RFC 5322 2.2.3; raw keeps the fold)"
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
)
