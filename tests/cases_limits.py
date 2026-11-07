# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Each limit at N and N+1, at the default and at 1 and 2, both entry points.

Sources: PLAN.md 2.1 (limits and defaults, AU-Q4), G4 (``NESTING_TOO_DEEP``
at the first paren beyond the limit), G9 (``TOO_MANY_PROPERTIES`` at the
ptype or bare name of property N+1, bare ones counted), AU-Q16 (positions:
``TOO_LONG`` at ``max_length``, ``TOO_MANY_RESULTS`` at the ``;`` of result
N+1) and AU-Q15c (``max_length`` counts the whole ARC value). The rows are
generated; every expected model is still written from those rules, not from
an implementation.
"""

from authresults import (
    ArcAuthenticationResults,
    AuthenticationResults,
    Deviation,
    ErrorReason,
)

from ._case import Call, Case, Options, ar, bare, prop, res

_ARC_PREFIX = "i=1; "
_DEFAULTS = {
    "max_length": 8192,
    "max_results": 64,
    "max_properties": 64,
    "max_comment_depth": 16,
}
_CITE = "PLAN.md 2.1 and AU-Q4 (limits); AU-Q16 (positions); "


def _wrap(
    call: Call, model: AuthenticationResults
) -> AuthenticationResults | ArcAuthenticationResults:
    if call == "parse_arc":
        return ArcAuthenticationResults(instance=1, payload=model)
    return model


def _options(limit: str, n: int, *, default: bool) -> Options:
    if default:
        return Options()
    if limit == "max_length":
        return Options(max_length=n)
    if limit == "max_results":
        return Options(max_results=n)
    if limit == "max_properties":
        return Options(max_properties=n)
    return Options(max_comment_depth=n)


def _length_cases(call: Call, n: int, *, default: bool) -> tuple[Case, Case]:
    prefix = _ARC_PREFIX if call == "parse_arc" else ""
    tag = f"{call} max_length={'default' if default else n}"
    head = prefix + "example.com; dkim=pass header.d="
    if n > len(head):
        pad = "a" * (n - len(head))
        at_n = Case(
            id=f"{tag} at N",
            call=call,
            value=head + pad,
            kwargs=_options("max_length", n, default=default),
            expected=_wrap(
                call,
                ar(
                    "example.com",
                    res(
                        "dkim",
                        "pass",
                        prop("header", "d", pad, registered=True),
                        registered=True,
                    ),
                ),
            ),
            cite=_CITE + "a value of exactly max_length parses",
        )
        over = head + pad + "a"
    else:
        # Too short for any valid value: the length check passes and the
        # parse ends at end of input (G1 for parse, G12 for parse_arc).
        short = "ix"[:n] if call == "parse_arc" else "xy"[:n]
        at_n = Case(
            id=f"{tag} at N",
            call=call,
            value=short,
            kwargs=_options("max_length", n, default=default),
            expected=ErrorReason.SYNTAX,
            position=1 if call == "parse_arc" else n,
            known_shape=None if call == "parse_arc" else "authserv_id_only",
            cite=_CITE + "the length check passes at N; then SYNTAX (parse_arc: i then "
            "end of input or x is SYNTAX at offset 1, G12; parse: an "
            "authserv-id alone is SYNTAX at len(value), G1, with the "
            "AUTHSERV_ID_ONLY tag, AU-Q52 and AU-Q51)",
        )
        over = "i=1"[: n + 1] if call == "parse_arc" else "xyz"[: n + 1]
    return (
        at_n,
        Case(
            id=f"{tag} at N+1",
            call=call,
            value=over,
            kwargs=_options("max_length", n, default=default),
            expected=ErrorReason.TOO_LONG,
            position=n,
            cite=_CITE + "TOO_LONG at max_length",
        ),
    )


def _results_cases(call: Call, n: int, *, default: bool) -> tuple[Case, Case]:
    prefix = _ARC_PREFIX if call == "parse_arc" else ""
    tag = f"{call} max_results={'default' if default else n}"
    one = "; dkim=pass"
    head = prefix + "example.com"
    model = ar("example.com", *(res("dkim", "pass", registered=True),) * n)
    return (
        Case(
            id=f"{tag} at N",
            call=call,
            value=head + one * n,
            kwargs=_options("max_results", n, default=default),
            expected=_wrap(call, model),
            cite=_CITE + "N results parse",
        ),
        Case(
            id=f"{tag} at N+1",
            call=call,
            value=head + one * (n + 1),
            kwargs=_options("max_results", n, default=default),
            expected=ErrorReason.TOO_MANY_RESULTS,
            position=len(head) + n * len(one),
            cite=_CITE + "TOO_MANY_RESULTS at the ; of result N+1",
        ),
    )


def _properties_cases(call: Call, n: int, *, default: bool) -> tuple[Case, Case]:
    prefix = _ARC_PREFIX if call == "parse_arc" else ""
    tag = f"{call} max_properties={'default' if default else n}"
    one = " header.d=x"
    head = prefix + "example.com; dkim=pass"
    model = ar(
        "example.com",
        res(
            "dkim",
            "pass",
            *(prop("header", "d", "x", registered=True),) * n,
            registered=True,
        ),
    )
    return (
        Case(
            id=f"{tag} at N",
            call=call,
            value=head + one * n,
            kwargs=_options("max_properties", n, default=default),
            expected=_wrap(call, model),
            cite=_CITE + "N properties parse",
        ),
        Case(
            id=f"{tag} at N+1",
            call=call,
            value=head + one * (n + 1),
            kwargs=_options("max_properties", n, default=default),
            expected=ErrorReason.TOO_MANY_PROPERTIES,
            position=len(head) + n * len(one) + 1,
            cite=_CITE + "G9: TOO_MANY_PROPERTIES at the ptype of property N+1",
        ),
    )


def _depth_cases(call: Call, n: int, *, default: bool) -> tuple[Case, Case]:
    prefix = _ARC_PREFIX if call == "parse_arc" else ""
    tag = f"{call} max_comment_depth={'default' if default else n}"
    head = prefix + "example.com; none "
    return (
        Case(
            id=f"{tag} at N",
            call=call,
            value=head + "(" * n + ")" * n,
            kwargs=_options("max_comment_depth", n, default=default),
            expected=_wrap(call, ar("example.com", none=True)),
            cite=_CITE + "G4: comments nested N deep parse",
        ),
        Case(
            id=f"{tag} at N+1",
            call=call,
            value=head + "(" * (n + 1) + ")" * (n + 1),
            kwargs=_options("max_comment_depth", n, default=default),
            expected=ErrorReason.NESTING_TOO_DEEP,
            position=len(head) + n,
            cite=_CITE + "G4: NESTING_TOO_DEEP at the first paren beyond the limit",
        ),
    )


def _generated() -> tuple[Case, ...]:
    builders = {
        "max_length": _length_cases,
        "max_results": _results_cases,
        "max_properties": _properties_cases,
        "max_comment_depth": _depth_cases,
    }
    cases: list[Case] = []
    calls: tuple[Call, ...] = ("parse", "parse_arc")
    for limit, build in builders.items():
        for call in calls:
            cases.extend(build(call, _DEFAULTS[limit], default=True))
            for n in (1, 2):
                cases.extend(build(call, n, default=False))
    return tuple(cases)


_EXTRA: tuple[Case, ...] = (
    Case(
        id="max_results=1 none counts as zero",
        value="example.com; none",
        kwargs={"max_results": 1},
        expected=ar("example.com", none=True),
        cite="G7 (none counts as 0 results for max_results)",
    ),
    Case(
        id="max_properties=2 bare property counted",
        value="example.com; dmarc=pass header.from=x action=none policy.dmarc=y",
        kwargs={"max_properties": 2},
        expected=ErrorReason.TOO_MANY_PROPERTIES,
        position=50,
        cite="G9, AU-Q16 refinement 4 (bare properties count; at the ptype of "
        "property N+1)",
    ),
    Case(
        id="max_properties=2 bare property is N+1",
        value="example.com; dmarc=pass header.from=x policy.dmarc=y action=none",
        kwargs={"max_properties": 2},
        expected=ErrorReason.TOO_MANY_PROPERTIES,
        position=53,
        cite="G9 (at the bare name of property N+1)",
    ),
    Case(
        id="max_properties=1 per result",
        value="example.com; dkim=pass header.d=x; spf=pass smtp.mailfrom=y",
        kwargs={"max_properties": 1},
        expected=ar(
            "example.com",
            res(
                "dkim",
                "pass",
                prop("header", "d", "x", registered=True),
                registered=True,
            ),
            res(
                "spf",
                "pass",
                prop("smtp", "mailfrom", "y", registered=True),
                registered=True,
            ),
        ),
        cite="PLAN.md 2.1 (64 properties per result)",
    ),
    Case(
        id="max_properties=1 bare property at N",
        value="example.com; dmarc=pass action=none",
        kwargs={"max_properties": 1},
        expected=ar(
            "example.com",
            res("dmarc", "pass", bare("action", "none"), registered=True),
            deviations=(Deviation.BARE_PROPERTY,),
        ),
        cite="G9",
    ),
)

# The timing cases: 8192 characters each, linear time required (PLAN.md 6,
# AL3a row).
_TIMEOUT = 2.0
_TIMING: tuple[Case, ...] = (
    Case(
        id="timing all ( default depth",
        value="(" * 8192,
        expected=ErrorReason.NESTING_TOO_DEEP,
        position=16,
        timeout=_TIMEOUT,
        cite="G4, AU-Q36 (first fault met by the left-to-right pass wins: the 17th "
        "paren, not UNTERMINATED_COMMENT at 0)",
    ),
    Case(
        id="timing all ( depth 8192",
        value="(" * 8192,
        kwargs={"max_comment_depth": 8192},
        expected=ErrorReason.UNTERMINATED_COMMENT,
        position=0,
        timeout=_TIMEOUT,
        cite="G4 (depth 8192 is not beyond the limit; UNTERMINATED_COMMENT at "
        "the outermost unclosed paren)",
    ),
    Case(
        id="timing ( then ) default depth",
        value="(" * 4096 + ")" * 4096,
        expected=ErrorReason.NESTING_TOO_DEEP,
        position=16,
        timeout=_TIMEOUT,
        cite="G4, AU-Q16 (tokeniser pass before the comment-only SYNTAX)",
    ),
    Case(
        id='timing all "',
        value='"' * 8192,
        expected=ErrorReason.SYNTAX,
        position=2,
        timeout=_TIMEOUT,
        cite='G6 (pairs close; "" is the authserv-id), G1 (then ; or CFWS '
        'is needed: SYNTAX at the third ")',
    ),
    Case(
        id="timing all ;",
        value=";" * 8192,
        expected=ErrorReason.SYNTAX,
        position=0,
        timeout=_TIMEOUT,
        cite="G1 (an authserv-id is required; ; is a tspecial)",
    ),
)

# 1 MiB timing cases (AL3a red-team F7): a quadratic scanner that re-slices
# the rest of the input per character takes about 14 s at 1 MiB on the AL3a
# laptop, a plain linear pass about 0.1 s. The timeout sits between them with
# room for a slower CI runner.
_MIB = 2**20
_MIB_TIMEOUT = 4.0
_QPAIR_HEAD = 'example.com; dkim=pass header.s="'
_QPAIRS = (_MIB - len(_QPAIR_HEAD) - 1) // 2
_FOLDS = (_MIB - len("example.com;") - len("none")) // 3
_MIB_CITE = "PLAN.md 2.1 (one linear pass); AL3a red-team F7; "

_TIMING_MIB: tuple[Case, ...] = (
    Case(
        id="timing 1 MiB all ( default depth",
        value="(" * _MIB,
        kwargs={"max_length": _MIB},
        expected=ErrorReason.NESTING_TOO_DEEP,
        position=16,
        timeout=_MIB_TIMEOUT,
        cite=_MIB_CITE + "G4, AU-Q36 (the 17th paren)",
    ),
    Case(
        id='timing 1 MiB all "',
        value='"' * _MIB,
        kwargs={"max_length": _MIB},
        expected=ErrorReason.SYNTAX,
        position=2,
        timeout=_MIB_TIMEOUT,
        cite=_MIB_CITE + 'G6, G1 (as the 8192 case: SYNTAX at the third ")',
    ),
    Case(
        id="timing 1 MiB all ;",
        value=";" * _MIB,
        kwargs={"max_length": _MIB},
        expected=ErrorReason.SYNTAX,
        position=0,
        timeout=_MIB_TIMEOUT,
        cite=_MIB_CITE + "G1",
    ),
    Case(
        id="timing 1 MiB quoted-pairs",
        value=_QPAIR_HEAD + "\\\\" * _QPAIRS + '"',
        kwargs={"max_length": _MIB},
        expected=ar(
            "example.com",
            res(
                "dkim",
                "pass",
                prop(
                    "header",
                    "s",
                    "\\" * _QPAIRS,
                    raw='"' + "\\\\" * _QPAIRS + '"',
                    quoted=True,
                    registered=True,
                ),
                registered=True,
            ),
        ),
        timeout=_MIB_TIMEOUT,
        cite=_MIB_CITE + "G6 (each backslash pair is a quoted-pair for one backslash)",
    ),
    Case(
        id="timing 1 MiB folds",
        value="example.com;" + "\r\n " * _FOLDS + "none",
        kwargs={"max_length": _MIB},
        expected=ar("example.com", none=True),
        timeout=_MIB_TIMEOUT,
        cite=_MIB_CITE + "G5, AU-Q29 (several folds in a row are obs-FWS)",
    ),
)

# Valid 1 MiB inputs (AL3a red-team N4): every stage must run to the end.
# The comment case catches a parser that removes comments by splicing the
# value (a linear tokeniser pass, then O(n^2) copying per comment).
_COMMENT_HEAD = "example.com "
_COMMENT_TAIL = "; none"
_COMMENTS = (_MIB - len(_COMMENT_HEAD) - len(_COMMENT_TAIL)) // 3
# The two cases with ~95,000 model objects get more room: comparing the
# expected and actual models in the harness alone takes about 1 s.
_MIB_MODEL_TIMEOUT = 10.0
_RESULT = "; dkim=pass"
_RESULTS = (_MIB - len("example.com")) // len(_RESULT)
_PROPERTY = " header.d=x"
_PROPERTIES = (_MIB - len("example.com; dkim=pass")) // len(_PROPERTY)
_PLAIN_HEAD = 'example.com; dkim=pass header.s="'
_PLAIN = _MIB - len(_PLAIN_HEAD) - 1

_TIMING_MIB_VALID: tuple[Case, ...] = (
    Case(
        id="timing 1 MiB comments",
        value=_COMMENT_HEAD + "(a)" * _COMMENTS + _COMMENT_TAIL,
        kwargs={"max_length": _MIB},
        expected=ar("example.com", none=True),
        timeout=_MIB_TIMEOUT,
        cite=_MIB_CITE + "G4 (CFWS before ;, comments discarded), AL3a red-team N4",
    ),
    Case(
        id="timing 1 MiB results",
        value="example.com" + _RESULT * _RESULTS,
        kwargs={"max_length": _MIB, "max_results": _MIB},
        expected=ar("example.com", *(res("dkim", "pass", registered=True),) * _RESULTS),
        timeout=_MIB_MODEL_TIMEOUT,
        cite=_MIB_CITE + "G1 (1*resinfo), AL3a red-team N4",
    ),
    Case(
        id="timing 1 MiB properties",
        value="example.com; dkim=pass" + _PROPERTY * _PROPERTIES,
        kwargs={"max_length": _MIB, "max_properties": _MIB},
        expected=ar(
            "example.com",
            res(
                "dkim",
                "pass",
                *(prop("header", "d", "x", registered=True),) * _PROPERTIES,
                registered=True,
            ),
        ),
        timeout=_MIB_MODEL_TIMEOUT,
        cite=_MIB_CITE + "G9 (repeated properties kept in order), AL3a red-team N4",
    ),
    Case(
        id="timing 1 MiB quoted string",
        value=_PLAIN_HEAD + "a" * _PLAIN + '"',
        kwargs={"max_length": _MIB},
        expected=ar(
            "example.com",
            res(
                "dkim",
                "pass",
                prop(
                    "header",
                    "s",
                    "a" * _PLAIN,
                    raw='"' + "a" * _PLAIN + '"',
                    quoted=True,
                    registered=True,
                ),
                registered=True,
            ),
        ),
        timeout=_MIB_TIMEOUT,
        cite=_MIB_CITE + "G6, AL3a red-team N4",
    ),
)

CASES: tuple[Case, ...] = (
    *_generated(),
    *_EXTRA,
    *_TIMING,
    *_TIMING_MIB,
    *_TIMING_MIB_VALID,
)
