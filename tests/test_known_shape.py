# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""AL3c's own tests: the KnownShape tag (AU-Q52, AU-Q54, AU-Q56) and the
wider PVALUE_TSPECIALS (AU-Q45, AU-Q53).

They sit beside the case table, which pins every docs/refused-shapes.md
entry; these add the near misses each detection rule must not tag, the edges
of the error object, and the edges of the unquoted pvalue run.
"""

import copy
import pickle

import pytest

from authresults import (
    AuthResultsError,
    Deviation,
    ErrorReason,
    KnownShape,
    parse,
    parse_arc,
)

_S = KnownShape
_ONLY = KnownShape.AUTHSERV_ID_ONLY
_JOB = KnownShape.AUTHSERV_ID_JOB_ID
_STRAY = KnownShape.STRAY_DOMAIN_BETWEEN_RESULTS
_EXIM = KnownShape.EXIM_ARC_LEADING_PROPERTY
_SPF = KnownShape.SPF_DETAILS_AS_RESULTS
_SYN = ErrorReason.SYNTAX

# --- the error object -------------------------------------------------------


def test_known_shape_members() -> None:
    assert [(m.name, m.value) for m in KnownShape] == [
        ("EXIM_ARC_LEADING_PROPERTY", "exim_arc_leading_property"),
        ("STRAY_DOMAIN_BETWEEN_RESULTS", "stray_domain_between_results"),
        ("AUTHSERV_ID_JOB_ID", "authserv_id_job_id"),
        ("AUTHSERV_ID_ONLY", "authserv_id_only"),
        ("SPF_DETAILS_AS_RESULTS", "spf_details_as_results"),
    ]


def test_known_shape_defaults_to_none() -> None:
    err = AuthResultsError(ErrorReason.SYNTAX, 3)
    assert err.known_shape is None
    assert vars(err) == {
        "reason": ErrorReason.SYNTAX,
        "position": 3,
        "known_shape": None,
    }


def test_known_shape_stays_out_of_the_message() -> None:
    err = AuthResultsError(ErrorReason.SYNTAX, 3, known_shape=_S.AUTHSERV_ID_ONLY)
    assert str(err) == "syntax at position 3"
    assert err.args == ("syntax at position 3",)
    assert repr(err) == "AuthResultsError('syntax at position 3')"


@pytest.mark.parametrize("shape", [None, *KnownShape])
def test_error_pickles_and_copies_with_the_tag(shape: KnownShape | None) -> None:
    err = AuthResultsError(ErrorReason.SYNTAX, 7, known_shape=shape)
    for twin in (
        pickle.loads(pickle.dumps(err)),  # noqa: S301
        copy.copy(err),
        copy.deepcopy(err),
    ):
        assert type(twin) is AuthResultsError
        assert (twin.reason, twin.position, twin.known_shape, str(twin)) == (
            ErrorReason.SYNTAX,
            7,
            shape,
            str(err),
        )


@pytest.mark.parametrize(
    ("reason", "shape"),
    [
        (ErrorReason.SYNTAX, "authserv_id_only"),
        (ErrorReason.SYNTAX, 1),
        (ErrorReason.INTERNAL, _S.AUTHSERV_ID_ONLY),
        (ErrorReason.INVALID_TYPE, _S.AUTHSERV_ID_ONLY),
        (ErrorReason.DEVIATION, _S.AUTHSERV_ID_ONLY),
        (ErrorReason.UNREGISTERED, _S.SPF_DETAILS_AS_RESULTS),
        (ErrorReason.EMPTY, _S.AUTHSERV_ID_ONLY),
    ],
    ids=repr,
)
def test_error_rejects_bad_known_shape(reason: ErrorReason, shape: object) -> None:
    with pytest.raises(TypeError) as info:
        AuthResultsError(reason, known_shape=shape)  # type: ignore[arg-type]
    assert str(info.value) == (
        "known_shape must be a KnownShape or None, and None for this reason"
    )


# --- detection: what each rule tags and what it leaves alone -----------------


def _shape(value: str, *, arc: bool = False, **kwargs: bool) -> object:
    with pytest.raises(AuthResultsError) as info:
        (parse_arc if arc else parse)(value, **kwargs)
    return info.value.reason, info.value.position, info.value.known_shape


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        # AUTHSERV_ID_ONLY: a token or quoted id, then only CFWS.
        ('"mx example"', (_SYN, 12, _ONLY)),
        ("mx.example (c) \r\n ", (_SYN, 18, _ONLY)),
        ("mx.example 1", (_SYN, 12, None)),
        ("mx.example 1 (c)", (_SYN, 16, None)),
        ("mx.example;", (_SYN, 11, None)),
        ("(c)", (_SYN, 3, None)),
        ("mx.example x", (_SYN, 11, None)),
        # AUTHSERV_ID_JOB_ID: a / straight after an unquoted id read as an id.
        ("mx.example/4AB; dkim=none", (_SYN, 10, _JOB)),
        ("mx.example/", (_SYN, 10, _JOB)),
        ("mx.example /4AB; dkim=none", (_SYN, 11, None)),
        ('"mx.example"/4AB; dkim=none', (_SYN, 12, None)),
        ("mailhost/4AB; dkim=none", (_SYN, 10, None)),
        # STRAY_DOMAIN_BETWEEN_RESULTS: only in a resinfo after the first.
        ("mx; dkim=pass; example.com", (_SYN, 22, _STRAY)),
        ("mx; dkim=pass; a.b.c (x);", (_SYN, 16, _STRAY)),
        ("mx; dkim=pass; 192.example", (_SYN, 18, _STRAY)),
        ("mx; dkim=pass; -ex.example", (_SYN, 18, None)),
        ("mx; dkim=pass; ex.-example", (_SYN, 17, None)),
        ("mx; dkim=pass; ex.1-2", (_SYN, 17, None)),
        ("mx; dkim=pass; ex.123", (_SYN, 17, None)),
        ("mx; dkim=pass; example.com x", (_SYN, 22, None)),
        ("mx; dkim=pass; example..com;", (_SYN, 22, None)),
        ("mx; dkim=pass; example.com.;", (_SYN, 22, None)),
        ("mx; dkim=pass; example.;", (_SYN, 22, None)),
        ("mx; dkim=pass; example .com;", (_SYN, 23, None)),
        ("mx; dkim=pass; dkim/1.x;", (_SYN, 21, None)),
        ("mx; example.com; dkim=pass", (_SYN, 11, None)),
        ("mx; dkim=pass; smtp.ip=x", (_SYN, 19, None)),
        # EXIM_ARC_LEADING_PROPERTY is parse_arc only.
        ("mx; smtp.remote-ip=192.0.2.1; arc=none", (_SYN, 8, None)),
        # SPF_DETAILS_AS_RESULTS: a key resinfo after a ;, any SYNTAX in it.
        ("mx; spf=pass; client-ip=192.0.2.1", (_SYN, 27, _SPF)),
        ("mx; spf=pass; Problem=x y", (_SYN, 25, _SPF)),
        ("mx; spf=pass; mechanism=a reason=", (_SYN, 33, _SPF)),
        ("mx; spf=pass; helo; dkim=pass", (_SYN, 18, None)),
        ("mx; spf=pass; helo-x=a@b", (_SYN, 22, None)),
        ("client-ip=192.0.2.1", (_SYN, 13, None)),
    ],
    ids=repr,
)
def test_parse_detection(value: str, expected: object) -> None:
    assert _shape(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("i=1; mx; smtp.remote-ip=192.0.2.1;\r\n\tarc=none", (_SYN, 13, _EXIM)),
        ("i=1; mx; smtp.x (c) = y", (_SYN, 13, _EXIM)),
        ("i=1; mx; smtp.x", (_SYN, 13, None)),
        ("i=1; mx; smtp.x-=y", (_SYN, 13, None)),
        ("i=1; mx; smtp.=y", (_SYN, 13, None)),
        ("i=1; mx; smtp .x=y", (_SYN, 14, None)),
        ("i=1; mx; dkim/1.x=y", (_SYN, 15, None)),
        ("i=1; mx; smtp.x.y=z", (_SYN, 13, None)),
        # The stray-domain rule still applies after the first resinfo.
        ("i=1; mx; dkim=pass; example.com", (_SYN, 27, _STRAY)),
        ("i=1; mx; dkim=pass; smtp.x=y", (_SYN, 24, None)),
    ],
    ids=repr,
)
def test_parse_arc_detection(value: str, expected: object) -> None:
    assert _shape(value, arc=True) == expected


@pytest.mark.parametrize(
    ("value", "kwargs", "expected"),
    [
        # Only SYNTAX is tagged inside a key resinfo.
        (
            "mx; spf=pass; helo=mx.example",
            {"require_registered": True},
            (ErrorReason.UNREGISTERED, 14, None),
        ),
        (
            "mx; spf=pass; helo=pass x=y",
            {"strict_syntax": True},
            (ErrorReason.DEVIATION, 24, None),
        ),
        # Strict: the first refusal decides, and a deviation is never tagged.
        (
            "spf=pass; example.com",
            {"strict_syntax": True},
            (ErrorReason.DEVIATION, 0, None),
        ),
        ("mx; spf=pass; helo=mx.example", {"strict_syntax": True}, (_SYN, 21, _SPF)),
    ],
    ids=repr,
)
def test_detection_with_options(
    value: str, kwargs: dict[str, bool], expected: object
) -> None:
    assert _shape(value, **kwargs) == expected


def test_a_key_resinfo_that_parses_is_kept() -> None:
    result = parse("mx; spf=pass; helo=pass").results[1]
    assert (result.method, result.result, result.registered) == ("helo", "pass", False)


# --- AU-Q45 and AU-Q53: the unquoted pvalue run -------------------------------

_MF = "mx.example; spf=pass smtp.mailfrom="


@pytest.mark.parametrize(
    ("pvalue", "strict_at"),
    [
        ("<>", 0),
        ("<a@b.example>", 0),
        ("a/b@[192.0.2.1]", 4),
        ("a@b.example:25", 11),
        ("a=y?z/w@[x]", 8),
        ("x=y:z", 1),
        ("<a@[192.0.2.1]>", 0),
        ("[192.0.2.1]", 0),
        ("2001:db8::1", 4),
    ],
)
def test_wide_tspecials_kept_as_written(pvalue: str, strict_at: int) -> None:
    model = parse(_MF + pvalue)
    found = model.results[0].properties[0]
    assert (found.value, found.raw, found.quoted) == (pvalue, pvalue, False)
    assert model.deviations == {Deviation.PVALUE_TSPECIALS}
    text = model.to_value()
    assert text == _MF + _quote(pvalue)
    assert parse(text).results[0].properties[0].value == pvalue
    at = len(_MF) + strict_at
    assert _shape(_MF + pvalue, strict_syntax=True) == (ErrorReason.DEVIATION, at, None)


def _quote(text: str) -> str:
    return '"' + text + '"'


@pytest.mark.parametrize(
    ("pvalue", "at"),
    [
        ("a,b@[192.0.2.1]", 1),
        # AU-Q57: the ] that is not last breaks the rule before the ,.
        ("a@[192.0.2.1],x", 12),
        ("<a\\b@c.example>", 2),
        ("a@localhost", 2),
        ("a@b.example/x", 11),
        ("a@b_c.example", 3),
    ],
)
def test_runs_still_refused(pvalue: str, at: int) -> None:
    assert _shape(_MF + pvalue) == (_SYN, len(_MF) + at, None)


@pytest.mark.parametrize(
    ("pvalue", "at", "strict"),
    [
        # AU-Q57: the first bracket that breaks the rule, an unclosed opener
        # at the opener; strict gives DEVIATION at an earlier flagged
        # character, SYNTAX on a tie.
        ("x=y<z", 3, (ErrorReason.DEVIATION, 1)),
        ("a<b", 1, (_SYN, 1)),
        ("<a[b>", 2, (ErrorReason.DEVIATION, 0)),
        ("<a[b", 0, (_SYN, 0)),
        ("a[b", 1, (_SYN, 1)),
        ("[a]>", 2, (ErrorReason.DEVIATION, 0)),
        ("<a]>", 2, (ErrorReason.DEVIATION, 0)),
        ("<a]", 2, (ErrorReason.DEVIATION, 0)),
        ("[a]b", 2, (ErrorReason.DEVIATION, 0)),
        ("<", 0, (_SYN, 0)),
        ("<a>>", 2, (ErrorReason.DEVIATION, 0)),
        ("<a,>", 2, (ErrorReason.DEVIATION, 0)),
        ("a@x<y>", 3, (_SYN, 3)),
    ],
)
def test_brackets_must_pair_up(
    pvalue: str, at: int, strict: tuple[ErrorReason, int]
) -> None:
    assert _shape(_MF + pvalue) == (_SYN, len(_MF) + at, None)
    reason, strict_at = strict
    assert _shape(_MF + pvalue, strict_syntax=True) == (
        reason,
        len(_MF) + strict_at,
        None,
    )


def test_quoted_local_part_keeps_the_address_check() -> None:
    # AU-Q53 covers unquoted runs only.
    assert _shape(_MF + '"a"@[192.0.2.1]') == (_SYN, len(_MF) + 4, None)
