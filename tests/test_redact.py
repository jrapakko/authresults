# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Unit, CLI and timing tests of the redaction helper (AL3d).

Spec: ``docs/plans/al3d.md``, rules R1 to R14, sections 6, 8 (items 1 to 9)
and 13. Every expected output below was written by hand from those rules;
none was produced by the code under test. Secrets are synthetic: ``qx*``
names under ``.test``, RFC 1918 and ULA addresses, invented local-parts.

``authresults._redact`` is not public API; the tests import it directly.
"""

import ast
import dataclasses
import functools
import io
import re
import runpy
import sys
import tomllib
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

import pytest

import authresults
from authresults import AuthResultsError, ErrorReason, _redact, _registry
from authresults import redact as redact_cli

from . import cases_refused, cases_rfc8601, cases_rfc8617, cases_vendor
from ._case import Case, Options
from ._redact_strategies import (
    KEEP_PTYPES,
    RESERVED_NAMES,
    Call,
    check_spans,
    oracle_problems,
    outcome,
    producer_words,
    run_cli,
)

ROOT: Final = Path(__file__).resolve().parent.parent
MIB: Final = 1_048_576
SAME: Final = "<same as the input>"
SECRET: Final = "qxsecret@qxbank.test"  # noqa: S105 - an address, not a password

Rep = tuple[str, str, int]

# --- helpers ------------------------------------------------------------------


@dataclass(frozen=True)
class Want:
    """An expected redaction: text (``SAME`` for unchanged), replacements as
    (placeholder, kind value, count), and the counters."""

    text: str
    reps: tuple[Rep, ...] = ()
    free: int = 0
    non_ascii: int = 0
    controls: int = 0
    arc: bool = False


def rep(placeholder: str, kind: str, count: int = 1) -> Rep:
    return (placeholder, kind, count)


def _a(count: int = 1) -> Rep:
    return rep("a.example", "domain", count)


def _b(count: int = 1) -> Rep:
    return rep("b.example", "domain", count)


def _c(count: int = 1) -> Rep:
    return rep("c.example", "domain", count)


def _user(n: int = 1, count: int = 1) -> Rep:
    return rep(f"user{n}", "local-part", count)


def check(value: str, want: Want) -> _redact.Redaction:
    result = _redact.redact(value)
    assert result.complete
    expected = value if want.text == SAME else want.text
    assert result.text == expected
    assert result.replacements == tuple(
        _redact.Replacement(p, _redact.Kind(k), n) for p, k, n in want.reps
    )
    counters = (result.free_text, result.non_ascii, result.controls, result.arc)
    assert counters == (want.free, want.non_ascii, want.controls, want.arc)
    assert len(result.originals) == len(result.replacements)
    assert all(result.originals)
    check_spans(value, result)
    return result


# --- constants (section 3) ------------------------------------------------------


def _registered_names() -> frozenset[str]:
    results = _registry._RESULTS  # noqa: SLF001 - the snapshot tables
    properties = _registry._PROPERTIES  # noqa: SLF001
    names = set(results) | set(properties)
    for codes in results.values():
        names |= codes
    for pairs in properties.values():
        for ptype, name in pairs:
            names |= {ptype, name}
    return frozenset(names)


def test_constants_match_the_plan() -> None:
    assert _redact.RESERVED_NAMES == RESERVED_NAMES
    assert _redact.KEEP_PTYPES == KEEP_PTYPES
    assert frozenset({"s"}) == _redact.SELECTOR_PROPERTIES
    assert frozenset({"b", "bh"}) == _redact.BASE64_PROPERTIES
    assert _redact.MAX_NUMBER == 999_999  # noqa: PLR2004
    assert _registered_names() == _registry.REGISTERED_NAMES
    extra = {"rsa-sha1", "rsa-sha256", "ed25519-sha256", "quarantine", "reject"}
    extra |= {"oreject", "yes", "no", "ipv6"}
    assert _registered_names() | extra == _redact.SAFE_WORDS
    assert {k.name: k.value for k in _redact.Kind} == {
        "DOMAIN": "domain",
        "IPV4": "ipv4",
        "IPV6": "ipv6",
        "LOCAL_PART": "local-part",
        "SELECTOR": "selector",
        "BASE64": "base64",
        "JOB_ID": "job-id",
        "NUMBER": "number",
        "WORD": "word",
        "PTYPE": "ptype",
        "PROPERTY": "property",
    }
    assert redact_cli.MAX_INPUT_BYTES == MIB
    codes = (
        redact_cli.EXIT_OK,
        redact_cli.EXIT_REFUSED,
        redact_cli.EXIT_USAGE,
        redact_cli.EXIT_INTERNAL,
    )
    assert codes == (0, 1, 2, 3)


def test_producer_words_equal_the_derived_set() -> None:
    # AU-Q69: exactly the unregistered words of the vendor and refused models,
    # plus the RFC 7208 9.1 keys.
    assert producer_words() == _redact.PRODUCER_WORDS
    assert {"action", "bimi", "compauth", "mail", "skipped", "tempfail"} <= (
        producer_words()
    )


def test_keep_hostnames_equal_the_vendor_list() -> None:
    # AU-Q66: equal, not a superset.
    assert cases_vendor.VENDOR_HOSTNAMES == _redact.KEEP_HOSTNAMES


# --- item 1: placeholders and numbering ---------------------------------------------

UNITS: Final = {
    "worked example 1": (
        (
            "mx.qx1.test; dkim=pass (good signature) header.d=qx2.test"
            " header.i=bob@qx2.test header.s=qxsel header.b=Ab+/cd="
        ),
        Want(
            "a.example; dkim=pass (...) header.d=b.example"
            " header.i=user1@b.example header.s=sel1 header.b=b64-1/=",
            (
                _a(),
                _b(2),
                _user(),
                rep("sel1", "selector"),
                rep("b64-1/=", "base64"),
            ),
            free=1,
        ),
    ),
    "ipv4 keyed canonically": (
        "qx.test; iprev=pass smtp.remote-ip=10.0.0.1 policy.iprev=010.000.000.001",
        Want(
            "a.example; iprev=pass smtp.remote-ip=192.0.2.1 policy.iprev=192.0.2.1",
            (_a(), rep("192.0.2.1", "ipv4", 2)),
        ),
    ),
    "ipv6 spellings": (
        (
            "qx.test; iprev=pass smtp.remote-ip=fd00::1 policy.ip=::ffff:10.0.0.1"
            " smtp.helo=[IPv6:fd00::2]"
        ),
        Want(
            "a.example; iprev=pass smtp.remote-ip=2001:db8::1 policy.ip=2001:db8::2"
            " smtp.helo=[IPv6:2001:db8::3]",
            (
                _a(),
                rep("2001:db8::1", "ipv6"),
                rep("2001:db8::2", "ipv6"),
                rep("2001:db8::3", "ipv6"),
            ),
        ),
    ),
    "local-parts plain, quoted and srs": (
        (
            'qx.test; spf=pass smtp.mailfrom=bob@qx.test smtp.helo="bob smith"@qx.test'
            " policy.ip=SRS0=HHH=TT=qx.test=bob@fwd.qx.test"
        ),
        Want(
            'a.example; spf=pass smtp.mailfrom=user1@a.example smtp.helo="user2"'
            "@a.example policy.ip=user3@b.example",
            (_a(3), _user(1), _user(2), _user(3), _b()),
        ),
    ),
    "base64 suffixes": (
        (
            "qx.test; dkim=pass header.b=Ab+cd header.b=Ab/cd header.b=Abcd="
            " header.b=Ab/cd= header.bh=Ef+gh"
        ),
        Want(
            "a.example; dkim=pass header.b=b64-1 header.b=b64-2/ header.b=b64-3="
            " header.b=b64-4/= header.tok1=b64-5",
            (
                _a(),
                rep("b64-1", "base64"),
                rep("b64-2/", "base64"),
                rep("b64-3=", "base64"),
                rep("b64-4/=", "base64"),
                rep("tok1", "word"),
                rep("b64-5", "base64"),
            ),
        ),
    ),
    "long base64 outside b and bh": (
        (
            "qx.test; auth=pass smtp.auth=QUJDREVGR0hJSktMTU5PUA1"
            " policy.txt=abcdefghijklmnop policy.ip=abcdefghijklmno1"
            " policy.x=abcdefghijklmn1"
        ),
        Want(
            "a.example; auth=pass smtp.auth=b64-1 policy.txt=tok1"
            " policy.ip=b64-2 policy.tok2=tok3",
            (
                _a(),
                rep("b64-1", "base64"),
                rep("tok1", "word"),
                rep("b64-2", "base64"),
                rep("tok2", "word"),
                rep("tok3", "word"),
            ),
        ),
    ),
    "job id": (
        "mail.qx.test/4ABCD1234;\r\n\tdkim=none",
        Want("a.example/job1;\r\n\tdkim=none", (_a(), rep("job1", "job-id"))),
    ),
    "numbers": (
        (
            "qx.test; dkim=pass policy.expired=1362471462 policy.x=12345"
            " policy.y=1234 policy.z=0"
        ),
        Want(
            "a.example; dkim=pass policy.tok1=num1 policy.tok2=num2"
            " policy.tok3=1234 policy.tok4=0",
            (
                _a(),
                rep("tok1", "word"),
                rep("num1", "number"),
                rep("tok2", "word"),
                rep("num2", "number"),
                rep("tok3", "word"),
                rep("tok4", "word"),
            ),
        ),
    ),
    "tok and tok_": (
        (
            "qx.test; dkim=pass action=qxword policy.x=qx_word policy.y=qx-"
            " policy.z=qxword"
        ),
        Want(
            "a.example; dkim=pass action=tok1 policy.tok2=tok_1 policy.tok3=tok_2"
            " policy.tok4=tok1",
            (
                _a(),
                rep("tok1", "word", 2),
                rep("tok2", "word"),
                rep("tok_1", "word"),
                rep("tok3", "word"),
                rep("tok_2", "word"),
                rep("tok4", "word"),
            ),
        ),
    ),
    "unknown ptypes": (
        "qx.test; dkim=pass qxp.qxq=1 qxp.qxr=2 qxs.qxq=3",
        Want(
            "a.example; dkim=pass ptype1.prop1=1 ptype1.prop2=2 ptype2.prop1=3",
            (
                _a(),
                rep("ptype1", "ptype", 2),
                rep("prop1", "property", 2),
                rep("prop2", "property"),
                rep("ptype2", "ptype"),
            ),
        ),
    ),
    "kept placeholders are skipped": (
        (
            "a.example; spf=pass smtp.mailfrom=user1@a.example policy.ip=192.0.2.1"
            " policy.txt=tok1 policy.x=2001:db8::1; iprev=pass policy.iprev=10.0.0.9"
            " policy.ip=fd00::9 policy.txt=qxword smtp.mailfrom=bob@qx.test"
        ),
        Want(
            "a.example; spf=pass smtp.mailfrom=user1@a.example policy.ip=192.0.2.1"
            " policy.txt=tok1 policy.tok2=2001:db8::1; iprev=pass"
            " policy.iprev=192.0.2.2 policy.ip=2001:db8::2 policy.txt=tok3"
            " smtp.mailfrom=user2@b.example",
            (
                rep("tok2", "word"),
                rep("192.0.2.2", "ipv4"),
                rep("2001:db8::2", "ipv6"),
                rep("tok3", "word"),
                _user(2),
                _b(),
            ),
        ),
    ),
    "placeholder caps": (
        (
            "qx.test; spf=pass smtp.mailfrom=user1234567@qx.test header.d=abcde.example"
            " policy.x=tok1234567 policy.y=user0"
        ),
        Want(
            "a.example; spf=pass smtp.mailfrom=user1@a.example header.d=b.example"
            " policy.tok1=tok2 policy.tok3=tok4",
            (
                _a(2),
                _user(),
                _b(),
                rep("tok1", "word"),
                rep("tok2", "word"),
                rep("tok3", "word"),
                rep("tok4", "word"),
            ),
        ),
    ),
    "worked example 6": (
        "mx.qx.test; dkim=pass bank.qx.test=1 qxcorp.test=1",
        Want(
            "a.example; dkim=pass b.example=1 ptype1.prop1=1",
            (_a(), _b(), rep("ptype1", "ptype"), rep("prop1", "property")),
        ),
    ),
}


@pytest.mark.parametrize(("value", "want"), UNITS.values(), ids=UNITS.keys())
def test_placeholders(value: str, want: Want) -> None:
    check(value, want)


def test_worked_example_1_spans() -> None:
    value = UNITS["worked example 1"][0]
    result = _redact.redact(value)
    assert result.spans == (
        (0, 11),
        (24, 38),
        (49, 57),
        (67, 70),
        (71, 79),
        (89, 94),
        (104, 111),
    )


def test_originals_keep_distinct_spellings() -> None:
    result = check(
        "QX.test; dkim=pass header.d=qx.TEST",
        Want("a.example; dkim=pass header.d=a.example", (_a(2),)),
    )
    assert result.originals == (("QX.test", "qx.TEST"),)
    first = check(UNITS["worked example 1"][0], UNITS["worked example 1"][1])
    assert first.originals == (
        ("mx.qx1.test",),
        ("qx2.test",),
        ("bob",),
        ("qxsel",),
        ("Ab+/cd=",),
    )


@pytest.mark.parametrize(
    ("n", "label"),
    [
        (1, "a"),
        (26, "z"),
        (27, "aa"),
        (52, "az"),
        (53, "ba"),
        (702, "zz"),
        (703, "aaa"),
        (18_278, "zzz"),
        (18_279, "aaaa"),
        (256_572, "nond"),
        (256_573, "nonf"),  # "none" is skipped
        (475_253, "zzzz"),
    ],
)
def test_domain_label(n: int, label: str) -> None:
    assert _redact.domain_label(n) == label


def test_domain_label_never_none() -> None:
    labels = {_redact.domain_label(n) for n in range(256_000, 257_000)}
    assert "none" not in labels
    assert len(labels) == 1000  # noqa: PLR2004


@pytest.mark.parametrize(
    ("n", "address"),
    [
        (1, "192.0.2.1"),
        (254, "192.0.2.254"),
        (255, "198.51.100.1"),
        (508, "198.51.100.254"),
        (509, "203.0.113.1"),
        (762, "203.0.113.254"),
    ],
)
def test_ipv4_placeholder(n: int, address: str) -> None:
    assert _redact.ipv4_placeholder(n) == address


@pytest.mark.parametrize(
    ("n", "address"),
    [
        (1, "2001:db8::1"),
        (0xFFFF, "2001:db8::ffff"),
        (0x10000, "2001:db8::1:0"),
        (0x12345, "2001:db8::1:2345"),
        (0xFFFFFFFF, "2001:db8::ffff:ffff"),
    ],
)
def test_ipv6_placeholder(n: int, address: str) -> None:
    assert _redact.ipv6_placeholder(n) == address


@pytest.mark.parametrize(
    ("helper", "n"),
    [("domain_label", 475_254), ("ipv4_placeholder", 763), ("ipv6_placeholder", 2**32)],
)
def test_placeholder_helpers_raise_above_cap(helper: str, n: int) -> None:
    # Section 14 item 17.
    functions = {
        "domain_label": _redact.domain_label,
        "ipv4_placeholder": _redact.ipv4_placeholder,
        "ipv6_placeholder": _redact.ipv6_placeholder,
    }
    with pytest.raises(ValueError, match=r".*"):
        functions[helper](n)


def _many_ipv4(count: int) -> str:
    items = "".join(f" policy.ip=10.0.{i // 256}.{i % 256}" for i in range(count))
    return "qx.test; iprev=pass" + items


def test_ipv4_pool_holds_762() -> None:
    result = _redact.redact(_many_ipv4(762))
    assert result.complete
    assert result.text.endswith(" policy.ip=203.0.113.254")
    assert len(result.replacements) == 763  # noqa: PLR2004 - a.example and 762


def test_ipv4_pool_exhausted_at_763() -> None:
    result = _redact.redact(_many_ipv4(763))
    assert not result.complete
    assert (result.text, result.replacements, result.spans) == ("", (), ())


# --- item 2: kept forms -------------------------------------------------------------


@pytest.mark.parametrize("host", sorted(cases_vendor.VENDOR_HOSTNAMES))
def test_vendor_hosts_kept_in_any_case(host: str) -> None:
    value = f"{host}; spf=pass smtp.helo={host.upper()} policy.x={host.title()}"
    text = f"{host}; spf=pass smtp.helo={host.upper()} policy.tok1={host.title()}"
    check(value, Want(text, (rep("tok1", "word"),)))


KEPT: Final = {
    "subdomain of a vendor host": (
        "qx.mx.google.com; none",
        Want("a.example; none", (_a(),)),
    ),
    "reserved names exact": (
        (
            "qx.test; spf=pass smtp.helo=example policy.a=test policy.b=invalid"
            " policy.c=localhost policy.d=example.com policy.e=EXAMPLE.NET"
            " policy.f=example.org"
        ),
        Want(
            "a.example; spf=pass smtp.helo=example policy.a=test policy.b=invalid"
            " policy.tok1=localhost policy.d=example.com policy.tok2=EXAMPLE.NET"
            " policy.tok3=example.org",
            (_a(), rep("tok1", "word"), rep("tok2", "word"), rep("tok3", "word")),
        ),
    ),
    "reserved subdomains and near misses replaced": (
        (
            "qx.test; spf=pass smtp.helo=mail.example.com policy.a=abcd.example"
            " policy.b=abcde.example policy.c=a1.example policy.d=example.co"
            " policy.e=test.example.net"
        ),
        Want(
            "a.example; spf=pass smtp.helo=b.example policy.a=abcd.example"
            " policy.b=c.example policy.tok1=d.example policy.d=e.example"
            " policy.tok2=f.example",
            (
                _a(),
                _b(),
                _c(),
                rep("tok1", "word"),
                rep("d.example", "domain"),
                rep("e.example", "domain"),
                rep("tok2", "word"),
                rep("f.example", "domain"),
            ),
        ),
    ),
    "documentation addresses": (
        (
            "qx.test; iprev=pass policy.a=192.0.2.0 policy.b=198.51.100.255"
            " policy.c=203.0.113.7 policy.d=2001:db8::5 policy.e=2001:0DB8:1::5"
            " policy.f=192.0.3.1 policy.g=2001:db9::1"
        ),
        Want(
            "a.example; iprev=pass policy.a=192.0.2.0 policy.b=198.51.100.255"
            " policy.tok1=203.0.113.7 policy.d=2001:db8::5"
            " policy.tok2=2001:0DB8:1::5 policy.tok3=192.0.2.1"
            " policy.tok4=2001:db8::1",
            (
                _a(),
                rep("tok1", "word"),
                rep("tok2", "word"),
                rep("tok3", "word"),
                rep("192.0.2.1", "ipv4"),
                rep("tok4", "word"),
                rep("2001:db8::1", "ipv6"),
            ),
        ),
    ),
    "safe words": (
        (
            "qx.test; dkim=pass header.a=rsa-sha1 header.a=ed25519-sha256"
            " policy.x=quarantine policy.y=REJECT policy.z=oreject policy.a=yes"
            " policy.b=No policy.c=IPv6 policy.d=temperror policy.e=smime-identifer"
        ),
        Want(
            "a.example; dkim=pass header.a=rsa-sha1 header.a=ed25519-sha256"
            " policy.tok1=quarantine policy.tok2=REJECT policy.tok3=oreject"
            " policy.a=yes policy.b=No policy.tok4=IPv6 policy.d=temperror"
            " policy.tok5=smime-identifer",
            (_a(), *(rep(f"tok{n}", "word") for n in range(1, 6))),
        ),
    ),
    "short numbers": (
        (
            "qx.test; dkim=pass policy.a=0 policy.b=1234 policy.c=0000"
            " policy.d=12345 policy.e=00001"
        ),
        Want(
            "a.example; dkim=pass policy.a=0 policy.b=1234 policy.tok1=0000"
            " policy.d=num1 policy.tok2=num2",
            (
                _a(),
                rep("tok1", "word"),
                rep("num1", "number"),
                rep("tok2", "word"),
                rep("num2", "number"),
            ),
        ),
    ),
}


@pytest.mark.parametrize(("value", "want"), KEPT.values(), ids=KEPT.keys())
def test_kept_forms(value: str, want: Want) -> None:
    check(value, want)


# --- item 3: structure --------------------------------------------------------------

_RFC_CASES: Final = {c.id: c for m in (cases_rfc8601, cases_rfc8617) for c in m.CASES}

_AAR3_TAIL: Final = (
    "a.example; spf=fail\r\n    smtp.from=user1@b.example; dkim=fail (...)\r\n"
    "    header.i=@b.example; dmarc=fail; arc=pass (...\r\n    ...\r\n    ... (...))"
)

RFC: Final = {
    "rfc8601 B.2": Want(SAME),
    "rfc8601 B.3": Want(SAME),
    "rfc8601 B.4 first field": Want(
        "example.com;\r\n                  auth=pass (...) smtp.auth=user1@example.net;"
        "\r\n                  spf=pass smtp.mailfrom=example.net",
        (_user(),),
        free=1,
    ),
    "rfc8601 B.4 second field": Want(SAME),
    "rfc8601 B.5 first field": Want(
        "example.com;\r\n                  dkim=pass (...) header.d=example.com",
        free=1,
    ),
    "rfc8601 B.5 second field": Want(
        "example.com;\r\n                  auth=pass (...) smtp.auth=user1@example.com;"
        "\r\n                  spf=fail smtp.mailfrom=example.com",
        (_user(),),
        free=1,
    ),
    "rfc8601 B.6 first field": Want(
        'example.com;\r\n              dkim=pass reason="..."\r\n'
        "                header.i=@a.example;\r\n"
        '              dkim=fail reason="..."\r\n'
        "                header.i=@b.example",
        (_a(), _b()),
        free=2,
    ),
    "rfc8601 B.6 second field": Want(
        "example.net;\r\n              dkim=pass (...) header.i=@a.example",
        (_a(),),
        free=1,
    ),
    "rfc8601 B.7": Want(
        "a.example (...) 1 (...);\r\n           dkim (...) / 1 (...) = (...) fail\r\n"
        "             policy (...) . (...) tok1\r\n"
        "             (...) = (...) num1",
        (_a(), rep("tok1", "word"), rep("num1", "number")),
        free=9,
    ),
    "rfc8601 2.7.6": Want(
        "example.com;\r\n                  tok1=pass ptype1.prop1=tok2 (...)",
        (
            rep("tok1", "word"),
            rep("ptype1", "ptype"),
            rep("prop1", "property"),
            rep("tok2", "word"),
        ),
        free=1,
    ),
    "rfc8617 B AAR i=3": Want(
        "i=3; " + _AAR3_TAIL, (_a(), _user(), _b(2)), free=5, arc=True
    ),
    "rfc8617 B A-R": Want(_AAR3_TAIL, (_a(), _user(), _b(2)), free=5),
    "rfc8617 B AAR i=2": Want(
        "i=2; a.example; spf=fail\r\n    smtp.from=user1@b.example; dkim=fail (...)"
        "\r\n    header.i=@example.org; dmarc=fail; arc=pass\r\n    (...)",
        (_a(), _user(), _b()),
        free=2,
        arc=True,
    ),
    "rfc8617 B AAR i=1": Want(
        "i=1; a.example; spf=pass\r\n    smtp.tok1=user1@b.example; dkim=pass (...)"
        "\r\n    header.i=@b.example; dmarc=pass",
        (_a(), rep("tok1", "word"), _user(), _b(2)),
        free=1,
        arc=True,
    ),
}


def _call_of(case: Case) -> Call:
    return "parse_arc" if case.call == "parse_arc" else "parse"


@pytest.mark.parametrize(("case_id", "want"), RFC.items(), ids=RFC.keys())
def test_rfc_examples(case_id: str, want: Want) -> None:
    case = _RFC_CASES[case_id]
    assert isinstance(case.value, str)
    result = check(case.value, want)
    call = _call_of(case)
    assert outcome(result.text, call, {}) == outcome(case.value, call, {})


STRUCTURE: Final = {
    "arc prefix": (
        "i=1; qx.test; none",
        Want("i=1; a.example; none", (_a(),), arc=True),
    ),
    "arc prefix with cfws": (
        "i = 01 ; qx.test; none",
        Want("i = 01 ; a.example; none", (_a(),), arc=True),
    ),
    "arc prefix alone": ("i=1;", Want(SAME, arc=True)),
    "no arc prefix without ;": (
        "i=1 qx.test",
        Want("i=tok1 a.example", (rep("tok1", "word"), _a())),
    ),
    "no arc prefix for I": (
        "I=1; qx.test; none",
        Want("I=tok1; a.example; none", (rep("tok1", "word"), _a())),
    ),
    "no arc prefix for 1x": (
        "i=1x; qx.test; none",
        Want("i=tok1; a.example; none", (rep("tok1", "word"), _a())),
    ),
    "au-q35 missing id": (
        "spf=pass smtp.mailfrom=qx.test",
        Want("spf=pass smtp.mailfrom=a.example", (_a(),)),
    ),
    "au-q35 method version": (
        "dkim/1=pass header.d=qx.test",
        Want("dkim/1=pass header.d=a.example", (_a(),)),
    ),
    "au-q35 cfws before =": ("dkim (c) = pass", Want("dkim (...) = pass", free=1)),
    "au-q39 dotted id then =": ("mx.qx.test=pass", Want("a.example=pass", (_a(),))),
    "au-q39 keyword id": ("dkim; none", Want(SAME)),
    "au-q39 single-label id": (
        "qxid; none",
        Want("tok1; none", (rep("tok1", "word"),)),
    ),
    "au-q39 no ; after id": (
        "mx.qx.test dmarc=pass",
        Want("a.example dmarc=pass", (_a(),)),
    ),
    "au-q35 non-digit method version": (
        "a/qx; none",
        Want("a/tok1; none", (rep("tok1", "word"),)),
    ),
    "id with @": (
        "a@qx; none",
        Want("user1@tok1; none", (_user(), rep("tok1", "word"))),
    ),
    "double and trailing ;": (
        "qx.test;; dkim=pass;",
        Want("a.example;; dkim=pass;", (_a(),)),
    ),
    "stray )": (
        "qx.test; dkim=pass) header.d=qx.test",
        Want("a.example; dkim=pass) header.d=a.example", (_a(2),)),
    ),
    "empty": ("", Want(SAME)),
    "whitespace only": (" \t\r\n ", Want(SAME)),
    "uppercase keywords": (
        "QX.TEST; DKIM=PASS HEADER.D=qx.test SMTP.MAILFROM=BOB@QX.TEST",
        Want(
            "a.example; DKIM=PASS HEADER.D=a.example SMTP.MAILFROM=user1@a.example",
            (_a(3), _user()),
        ),
    ),
    "bare cr": ("qx.test;\rdkim=pass", Want("a.example;\rdkim=pass", (_a(),))),
    "bare lf": ("qx.test;\ndkim=pass", Want("a.example;\ndkim=pass", (_a(),))),
}


@pytest.mark.parametrize(("value", "want"), STRUCTURE.values(), ids=STRUCTURE.keys())
def test_structure(value: str, want: Want) -> None:
    check(value, want)


# --- section 14 clarifications ---------------------------------------------------

CLARIFIED: Final = {
    "14.7 every unquoted local-part becomes userN": (
        (
            "qx.test; spf=pass smtp.mailfrom=sender@qx.test smtp.helo=tok1@qx.test"
            " policy.ip=a.example@qx.test policy.x=user123@qx.test"
        ),
        Want(
            "a.example; spf=pass smtp.mailfrom=user1@a.example"
            " smtp.helo=user2@a.example policy.ip=user3@a.example"
            " policy.tok1=user123@a.example",
            (_a(5), _user(1), _user(2), _user(3), rep("tok1", "word")),
        ),
    ),
    "14.8 quoted authserv-id rewritten": (
        '"qx.test"; none',
        Want('"a.example"; none', (_a(),)),
    ),
    "14.8 quoted authserv-id as free text": (
        '"qx test"; none',
        Want('"..."; none', free=1),
    ),
    "14.8 quoted vendor authserv-id kept": ('"mx.google.com"; none', Want(SAME)),
    "14.9 arc prefix after leading cfws": (
        " (a) i (b) = (c) 7 (d) ; qx.test; none",
        Want(
            " (...) i (...) = (...) 7 (...) ; a.example; none",
            (_a(),),
            free=4,
            arc=True,
        ),
    ),
    "14.11 job id with tspecials is a plain run": (
        "qx.test/a@qx.test; none",
        Want("a.example/user1@a.example; none", (_a(2), _user())),
    ),
    "14.11 job id with = is a plain run": (
        "qx.test/4A=B; none",
        Want("a.example/tok1=B; none", (_a(), rep("tok1", "word"))),
    ),
    "14.12 local-part keys": (
        (
            'qx.test; spf=pass smtp.mailfrom=bob@qx.test smtp.helo="bob"@qx.test'
            ' policy.x="b\\ob"@qx.test policy.y=Bob@qx.test'
        ),
        Want(
            'a.example; spf=pass smtp.mailfrom=user1@a.example smtp.helo="user1"'
            '@a.example policy.tok1="user1"@a.example policy.tok2=user2@a.example',
            (_a(5), _user(1, 3), rep("tok1", "word"), rep("tok2", "word"), _user(2)),
        ),
    ),
    "14.12 ipv6, ptype, property and number keys": (
        (
            "qx.test; dkim=pass policy.a=FD00::1 policy.b=fd00::1 qxp.qxq=1 QXP.QXQ=2"
            " policy.c=012345 policy.d=12345 policy.e=012345"
        ),
        Want(
            "a.example; dkim=pass policy.a=2001:db8::1 policy.b=2001:db8::1"
            " ptype1.prop1=1 ptype1.prop1=2 policy.tok1=num1 policy.d=num2"
            " policy.tok2=num1",
            (
                _a(),
                rep("2001:db8::1", "ipv6", 2),
                rep("ptype1", "ptype", 2),
                rep("prop1", "property", 2),
                rep("tok1", "word"),
                rep("num1", "number", 2),
                rep("num2", "number"),
                rep("tok2", "word"),
            ),
        ),
    ),
    "14.13 base64 with = and / outside b and bh": (
        (
            "qx.test; auth=pass smtp.auth=QUJDREVGR0hJSktMTU5P/A=="
            " policy.x=abcdefghijklmnop/= policy.y=abc_def-ghijklmn1"
        ),
        Want(
            "a.example; auth=pass smtp.auth=b64-1/= policy.tok1=b64-2/="
            " policy.tok2=b64-3",
            (
                _a(),
                rep("b64-1/=", "base64"),
                rep("tok1", "word"),
                rep("b64-2/=", "base64"),
                rep("tok2", "word"),
                rep("b64-3", "base64"),
            ),
        ),
    ),
    "14.14 wsp before a backslash before cr": (
        "qx.test; dkim=pass (a \\\r\n b)",
        Want("a.example; dkim=pass (... \\\r\n ...)", (_a(),), free=2),
    ),
}


AU_Q69: Final = {
    "unknown method": (
        "qx.test; qxmethod=pass header.d=qx.test",
        Want("a.example; tok1=pass header.d=a.example", (_a(2), rep("tok1", "word"))),
    ),
    "unknown method and result": (
        "qx.test; reason=qxsecret",
        Want("a.example; tok1=tok2", (_a(), rep("tok1", "word"), rep("tok2", "word"))),
    ),
    "unknown result": (
        "qx.test; dkim=qxsecret",
        Want("a.example; dkim=tok1", (_a(), rep("tok1", "word"))),
    ),
    "unknown bare property": (
        "qx.test; dkim=pass qxbare=1",
        Want("a.example; dkim=pass tok1=1", (_a(), rep("tok1", "word"))),
    ),
    "unknown property under header": (
        "qx.test; dkim=pass header.qxprop=1",
        Want("a.example; dkim=pass header.tok1=1", (_a(), rep("tok1", "word"))),
    ),
    "unknown words keyed ascii-lowercase": (
        "qx.test; QXM=pass; qxm=fail",
        Want("a.example; tok1=pass; tok1=fail", (_a(), rep("tok1", "word", 2))),
    ),
    "producer words stay": (
        (
            "qx.test; bimi=skipped; spf=tempfail smtp.mail=qx.test; compauth=pass"
            " action=none; spf=pass; identity=mailfrom"
        ),
        Want(
            "a.example; bimi=skipped; spf=tempfail smtp.mail=a.example;"
            " compauth=pass action=none; spf=pass; identity=mailfrom",
            (_a(2),),
        ),
    ),
    "mixed-case known words stay": (
        "qx.test; DKIM=Pass Header.D=qx.test; BIMI=Skipped; CompAuth=pass Action=none",
        Want(
            "a.example; DKIM=Pass Header.D=a.example; BIMI=Skipped;"
            " CompAuth=pass Action=none",
            (_a(2),),
        ),
    ),
    "placeholder-shaped words stay": (
        "qx.test; tok7=pass header.prop3=1 qxw=fail",
        Want(
            "a.example; tok7=pass header.prop3=1 tok1=fail",
            (_a(), rep("tok1", "word")),
        ),
    ),
}


@pytest.mark.parametrize(("value", "want"), AU_Q69.values(), ids=AU_Q69.keys())
def test_au_q69_keyword_positions(value: str, want: Want) -> None:
    check(value, want)


@pytest.mark.parametrize(("value", "want"), CLARIFIED.values(), ids=CLARIFIED.keys())
def test_clarified(value: str, want: Want) -> None:
    check(value, want)


# Section 16 item 1: IPv6 glued to other characters.
GLUED: Final = {
    "ipv6 with a zone id": (
        "qx.test; iprev=pass smtp.remote-ip=fd12:3456:7890::1%eth0",
        Want(
            "a.example; iprev=pass smtp.remote-ip=2001:db8::1tok_1",
            (_a(), rep("2001:db8::1", "ipv6"), rep("tok_1", "word")),
        ),
    ),
    "ipv6 with letters glued": (
        "qx.test; iprev=pass policy.iprev=2a00:1450:4001:815::200ez",
        Want(
            "a.example; iprev=pass policy.iprev=2001:db8::1tok1",
            (_a(), rep("2001:db8::1", "ipv6"), rep("tok1", "word")),
        ),
    ),
    "ipv6 before @ (16.7 ii)": (
        "dkim=pass; dkim=pass() arc.d=fd00::0@qx1.test",
        Want(
            "dkim=pass; dkim=pass() arc.d=2001:db8::1@a.example",
            (rep("2001:db8::1", "ipv6"), _a()),
        ),
    ),
    "ipv6 with a domain-shaped tail (16.7 i)": (
        "qx.test; iprev=pass policy.ip=fd00::1z.qx.test",
        Want(
            "a.example; iprev=pass policy.ip=2001:db8::1tok_1",
            (_a(), rep("2001:db8::1", "ipv6"), rep("tok_1", "word")),
        ),
    ),
    "doc ipv6 with a zone id": (
        "qx.test; iprev=pass policy.ip=2001:db8::1%eth0",
        Want(
            "a.example; iprev=pass policy.ip=2001:db8::1tok_1",
            (_a(), rep("tok_1", "word")),
        ),
    ),
}


@pytest.mark.parametrize(("value", "want"), GLUED.values(), ids=GLUED.keys())
def test_glued_ipv6(value: str, want: Want) -> None:
    result = check(value, want)
    groups = {
        g.lower()
        for g in re.findall(r"[0-9A-Fa-f]+", value.rpartition("=")[2])
        if len(g) >= 3  # noqa: PLR2004 - shorter groups match by chance
    } - {"2001", "db8"}
    tokens = {t.lower() for t in re.split(r"[^0-9A-Za-z]", result.text)}
    assert not groups & tokens
    again = _redact.redact(result.text)
    assert again.text == result.text
    assert again.replacements == ()


# Section 17 (fix round 2).
ROUND2: Final = {
    "17.1 authserv-id with digits after /": (
        "mailhost/3456789012; dkim=pass header.d=qx.test",
        Want(
            "tok1/job1; dkim=pass header.d=a.example",
            (rep("tok1", "word"), rep("job1", "job-id"), _a()),
        ),
    ),
    "17.1 digits after / past cfws": (
        "qxhost /5551234567; dkim=pass",
        Want("tok1 /num1; dkim=pass", (rep("tok1", "word"), rep("num1", "number"))),
    ),
    "17.1 method with digits after / and no =": (
        "mx.qx.test; foo/5551234567",
        Want(
            "a.example; tok1/num1",
            (_a(), rep("tok1", "word"), rep("num1", "number")),
        ),
    ),
    "17.1 known method with digits after / and no =": (
        "mx.qx.test; dkim/5551234567 header.d=qx.test",
        Want(
            "a.example; dkim/num1 header.d=b.example",
            (_a(), rep("num1", "number"), _b()),
        ),
    ),
    "17.1 method version kept": (
        "mx.qx.test; dkim/1=pass",
        Want("a.example; dkim/1=pass", (_a(),)),
    ),
    "17.1 long method version kept": (
        "mx.qx.test; dkim/5551234567=pass",
        Want("a.example; dkim/5551234567=pass", (_a(),)),
    ),
    "17.1 long method version kept on the au-q35 path": (
        "dkim/5551234567=pass header.d=qx.test",
        Want("dkim/5551234567=pass header.d=a.example", (_a(),)),
    ),
    "17.2 one version only": (
        "mx.qx.test 0123456789 (qx) 5551234567 (qx) 4155550123; spf=pass",
        Want(
            "a.example 0123456789 (...) num1 (...) num2; spf=pass",
            (_a(), rep("num1", "number"), rep("num2", "number")),
            free=2,
        ),
    ),
    "17.3 long arc instance is not a prefix": (
        "i=987654321; mx.qx.test; arc=pass",
        Want("i=tok1; a.example; arc=pass", (rep("tok1", "word"), _a())),
    ),
    "17.3 four-digit arc instance": (
        "i=9999; qx.test; none",
        Want("i=9999; a.example; none", (_a(),), arc=True),
    ),
    "17.4 doc ipv6 with a dotted quad": (
        "qx.test; dkim=pass header.d=2001:db8::10.1.2.3",
        Want(
            "a.example; dkim=pass header.d=2001:db8::1",
            (_a(), rep("2001:db8::1", "ipv6")),
        ),
    ),
    "17.4 doc ipv6 with dotted hex": (
        "qx.test; dkim=pass header.d=2001:db8::1.cafe.de",
        Want(
            "a.example; dkim=pass header.d=2001:db8::1",
            (_a(), rep("2001:db8::1", "ipv6")),
        ),
    ),
    "17.4 doc ipv6 uppercase with a dotted quad": (
        "qx.test; dkim=pass header.d=2001:DB8:abcd:1234::10.20.30.40",
        Want(
            "a.example; dkim=pass header.d=2001:db8::1",
            (_a(), rep("2001:db8::1", "ipv6")),
        ),
    ),
    "17.4 dotted doc ipv6 replaced, plain one kept": (
        (
            "qx.test; dkim=pass header.d=2001:db8::10.1.2.3"
            " header.d=2001:db8::1.cafe.de header.d=2001:db8::1"
        ),
        Want(
            "a.example; dkim=pass header.d=2001:db8::2 header.d=2001:db8::3"
            " header.d=2001:db8::1",
            (_a(), rep("2001:db8::2", "ipv6"), rep("2001:db8::3", "ipv6")),
        ),
    ),
    **{
        f"17.5 split {split} after a glued tail": (
            f"example.com; dkim=pass x=fd00::1zz{split}bob@qx.test",
            Want(
                f"example.com; dkim=pass tok1=2001:db8::1tok2{split}user1@a.example",
                (
                    rep("tok1", "word"),
                    rep("2001:db8::1", "ipv6"),
                    rep("tok2", "word"),
                    _user(),
                    _a(),
                ),
            ),
        )
        for split in "/=?"
    },
    "17.11 trailing dots of a local-part kept": (
        "qx.test; spf=pass smtp.mailfrom=a.@qx2.test",
        Want(
            "a.example; spf=pass smtp.mailfrom=user1.@b.example", (_a(), _user(), _b())
        ),
    ),
    "18.1 dots-only local-part": (
        "qx.test; spf=pass smtp.mailfrom=...@qx2.test",
        Want(
            "a.example; spf=pass smtp.mailfrom=user1...@b.example",
            (_a(), _user(), _b()),
        ),
    ),
    **{
        f"18.2 malformed doc ipv6 {name}": (
            f"mx.qx.test; x={run}",
            Want(
                "a.example; tok1=2001:db8::1",
                (_a(), rep("tok1", "word"), rep("2001:db8::1", "ipv6")),
            ),
        )
        for name, run in (
            ("long group", "2001:db8:5551234567"),
            ("embedded address", "2001:db8::2a00:1450:4001:815::200e"),
            ("two double colons", "2001:db8::1::2"),
            ("five-digit group", "2001:db8:12345::1"),
            ("nine groups", "2001:db8:1:2:3:4:5:6:7"),
        )
    },
    "18.2 well-formed doc ipv6 kept": (
        "mx.qx.test; x=2001:db8::1 y=2001:DB8:0:0:0:0:0:1 z=2001:0db8:abcd::1",
        Want(
            "a.example; tok1=2001:db8::1 tok2=2001:DB8:0:0:0:0:0:1"
            " tok3=2001:0db8:abcd::1",
            (_a(), rep("tok1", "word"), rep("tok2", "word"), rep("tok3", "word")),
        ),
    ),
    "18.3 non-ascii case gives two placeholders": (
        "mx.qx.test; y=Qx\xc4b z=qx\xe4b",
        Want(
            "a.example; tok1=tok_1 tok2=tok_2",
            (
                _a(),
                rep("tok1", "word"),
                rep("tok_1", "word"),
                rep("tok2", "word"),
                rep("tok_2", "word"),
            ),
            non_ascii=2,
        ),
    ),
    **{
        f"19 kept doc ipv6 {spelling} reserved by value": (
            f"mx.qx.test; spf=pass smtp.remote-ip={spelling} x=fd00::7",
            Want(
                f"a.example; spf=pass smtp.remote-ip={spelling} tok1=2001:db8::2",
                (_a(), rep("tok1", "word"), rep("2001:db8::2", "ipv6")),
            ),
        )
        for spelling in (
            "2001:0db8:0:0:0:0:0:1",
            "2001:db8:0::1",
            "2001:0db8:0000:0000:0000:0000:0000:0001",
        )
    },
    "19 uppercase kept doc ipv6 skipped by the second placeholder": (
        "mx.qx.test; spf=pass smtp.remote-ip=2001:DB8::2 x=fd00::7 y=fd00::8",
        Want(
            "a.example; spf=pass smtp.remote-ip=2001:DB8::2"
            " tok1=2001:db8::1 tok2=2001:db8::3",
            (
                _a(),
                rep("tok1", "word"),
                rep("2001:db8::1", "ipv6"),
                rep("tok2", "word"),
                rep("2001:db8::3", "ipv6"),
            ),
        ),
    ),
    "17.6 word keys ignore case": (
        "mx.qx.test; Qxbob=pass x=qxbob x=Qxbob x=QXBOB",
        Want(
            "a.example; tok1=pass tok2=tok1 tok2=tok1 tok2=tok1",
            (_a(), rep("tok1", "word", 4), rep("tok2", "word", 3)),
        ),
    ),
}


@pytest.mark.parametrize(("value", "want"), ROUND2.values(), ids=ROUND2.keys())
def test_round2(value: str, want: Want) -> None:
    result = check(value, want)
    again = _redact.redact(result.text)
    assert again.text == result.text
    assert again.replacements == ()


@pytest.mark.parametrize(
    ("text", "flagged"),
    [
        ("x=2001:db8::10.1.2.3", True),
        ("x=2001:db8::192.0.2.1", True),
        ("x=2001:db8::1.cafe.de", True),
        ("x=2001:DB8:abcd::10.20.30.40", True),
        ("x=2001:db8::1", False),
        ("x=2001:db8::1tok_1", False),
        ("x=2001:db8:5551234567", True),
        ("x=2001:db8::1::2", True),
        ("x=2001:db8:12345::1", True),
        ("x=2001:db8:1:2:3:4:5:6:7", True),
        ("x=2001:db8:1:2:3:4:5:6", False),
        ("x=2001:DB8:0:0:0:0:0:1", False),
        ("x=2001:0db8:abcd::1", False),
    ],
)
def test_oracle_flags_dotted_doc_ipv6(text: str, *, flagged: bool) -> None:
    # Section 17 items 4 and 8: the P2 oracle catches what V6 let through.
    problems = oracle_problems(text, cases_vendor.VENDOR_HOSTNAMES)
    assert bool(problems) is flagged


def test_clarified_free_text_in_spans() -> None:
    # Section 14 item 17: free-text cores are spans.
    result = _redact.redact("qx.test; none (secret)")
    assert result.spans == ((0, 7), (15, 21))


# --- item 4: free text --------------------------------------------------------------

FREE: Final = {
    "nested": (
        "qx.test; dkim=pass (a (b\\) c) d)",
        Want("a.example; dkim=pass (... (...) ...)", (_a(),), free=3),
    ),
    "fold inside": (
        "qx.test; dkim=pass (a\r\n b)",
        Want("a.example; dkim=pass (...\r\n ...)", (_a(),), free=2),
    ),
    "backslash before cr": (
        "qx.test; dkim=pass (a\\\r\n b)",
        Want("a.example; dkim=pass (...\\\r\n ...)", (_a(),), free=2),
    ),
    "unterminated comment": (
        "qx.test; dkim=pass (abc",
        Want("a.example; dkim=pass (...", (_a(),), free=1),
    ),
    "unterminated quote": (
        'qx.test; dkim=pass reason="abc',
        Want('a.example; dkim=pass reason="...', (_a(),), free=1),
    ),
    "empty comment": (
        "qx.test; dkim=pass ()",
        Want("a.example; dkim=pass ()", (_a(),)),
    ),
    "blank comment": (
        "qx.test; dkim=pass (  )",
        Want("a.example; dkim=pass (  )", (_a(),)),
    ),
    "spaced comment": (
        "qx.test; dkim=pass ( a )",
        Want("a.example; dkim=pass ( ... )", (_a(),), free=1),
    ),
    "already redacted": (
        "qx.test; dkim=pass (...)",
        Want("a.example; dkim=pass (...)", (_a(),)),
    ),
    "quote inside comment": (
        'qx.test; dkim=pass (a "b" c)',
        Want("a.example; dkim=pass (...)", (_a(),), free=1),
    ),
    "quoted reason": (
        'qx.test; dkim=pass reason="good signature"',
        Want('a.example; dkim=pass reason="..."', (_a(),), free=1),
    ),
    "paren inside quoted reason": (
        'qx.test; dkim=pass reason="a (b"',
        Want('a.example; dkim=pass reason="..."', (_a(),), free=1),
    ),
    "fold inside quoted reason": (
        'qx.test; dkim=pass reason="a\r\n b"',
        Want('a.example; dkim=pass reason="...\r\n ..."', (_a(),), free=2),
    ),
    "compauth reason": (
        "qx.test; compauth=fail reason=000",
        Want("a.example; compauth=fail reason=000", (_a(),)),
    ),
    "safe-word reason": (
        "qx.test; dkim=fail reason=policy",
        Want("a.example; dkim=fail reason=policy", (_a(),)),
    ),
    "tspecial reason": (
        "qx.test; dkim=pass reason=a@qx.test",
        Want("a.example; dkim=pass reason=user1@a.example", (_a(2), _user())),
    ),
}


@pytest.mark.parametrize(("value", "want"), FREE.values(), ids=FREE.keys())
def test_free_text(value: str, want: Want) -> None:
    check(value, want)


@pytest.mark.parametrize(
    ("value", "text"),
    [
        ("qx.test; dkim=pass reason=qxword", "a.example; dkim=pass reason=..."),
        ("qx.test; dkim=pass reason=12345", "a.example; dkim=pass reason=..."),
        ("qx.test; dkim=pass reason=qx.word", "a.example; dkim=pass reason=..."),
    ],
)
def test_plain_token_reason(value: str, text: str) -> None:
    # Section 14 item 1: the replaced reason counts in free_text.
    check(value, Want(text, (_a(),), free=1))


# --- item 5: characters -------------------------------------------------------------

_AU_Q41: Final = (
    *(0x00A0, 0x00AD, 0x0600, 0x061C, 0x06DD, 0x070F, 0x0890, 0x08E2, 0x1680),
    *(0x180E, 0x2000, 0x2028, 0x205F, 0x2066, 0x3000, 0xFEFF, 0xFFF9, 0x110BD),
    *(0x110CD, 0x13430, 0x1BCA0, 0x1D173, 0xE0001, 0xE0020),
)
CONTROLS: Final = (
    *(chr(p) for p in _AU_Q41),
    *("\x00", "\x01", "\x0b", "\x0c", "\x1b", "\x1f", "\x7f", "\x80", "\x85"),
    *("\x9f", "\ud800", "\udcff", "\udfff"),
)
NON_ASCII: Final = ("\xe9", "\u212a", "\u0456", "\U0001f600", "\uff1d", "\u037e")

_T = tuple[str, str, tuple[Rep, ...], int]
CHAR_TEMPLATES: Final[dict[str, _T]] = {
    "authserv-id": ("q{c}x.test; none", "a.example; none", (_a(),), 0),
    "comment": ("qx.test; none (a{c}b)", "a.example; none (...)", (_a(),), 1),
    "method": (
        "qx.test; dk{c}im=pass",
        "a.example; tok_1=pass",
        (_a(), rep("tok_1", "word")),
        0,
    ),
    "result": (
        "qx.test; dkim=pa{c}ss",
        "a.example; dkim=tok_1",
        (_a(), rep("tok_1", "word")),
        0,
    ),
    "ptype": (
        "qx.test; dkim=pass hea{c}der.d=qx.test",
        "a.example; dkim=pass b.example=a.example",
        (_a(2), _b()),
        0,
    ),
    "property": (
        "qx.test; dkim=pass header.d{c}=qx.test",
        "a.example; dkim=pass b.example=a.example",
        (_a(2), _b()),
        0,
    ),
    "pvalue": (
        "qx.test; dkim=pass header.d=q{c}x.test",
        "a.example; dkim=pass header.d=b.example",
        (_a(), _b()),
        0,
    ),
    "quoted pvalue": (
        'qx.test; dkim=pass header.d="q{c}x.test"',
        'a.example; dkim=pass header.d="b.example"',
        (_a(), _b()),
        0,
    ),
    "quoted reason": (
        'qx.test; dkim=pass reason="a{c}b"',
        'a.example; dkim=pass reason="..."',
        (_a(),),
        1,
    ),
    "unquoted reason": (
        "qx.test; dkim=pass reason=a{c}b",
        "a.example; dkim=pass reason=tok_1",
        (_a(), rep("tok_1", "word")),
        0,
    ),
    "version": (
        "qx.test 1{c}; none",
        "a.example tok_1; none",
        (_a(), rep("tok_1", "word")),
        0,
    ),
    "local-part": (
        "qx.test; spf=pass smtp.mailfrom=b{c}ob@qx.test",
        "a.example; spf=pass smtp.mailfrom=user1@a.example",
        (_a(2), _user()),
        0,
    ),
    "job id": (
        "qx.test/4A{c}B; none",
        "a.example/job1; none",
        (_a(), rep("job1", "job-id")),
        0,
    ),
}

_CHARS: Final = [(c, True) for c in CONTROLS] + [(c, False) for c in NON_ASCII]


@pytest.mark.parametrize("template", CHAR_TEMPLATES.values(), ids=CHAR_TEMPLATES.keys())
@pytest.mark.parametrize(
    ("char", "is_control"), _CHARS, ids=[ascii(c) for c, _ in _CHARS]
)
def test_characters_in_every_position(
    template: _T, char: str, *, is_control: bool
) -> None:
    pattern, text, reps, free = template
    value = pattern.replace("{c}", char)
    want = Want(
        text,
        reps,
        free=free,
        non_ascii=0 if is_control else 1,
        controls=1 if is_control else 0,
    )
    result = check(value, want)
    assert result.text.isascii()


CHARS: Final = {
    "kelvin dkim": (
        "qx.test; d\u212aim=pass header.d=qx.test",
        Want(
            "a.example; tok_1=pass header.d=a.example",
            (_a(2), rep("tok_1", "word")),
            non_ascii=1,
        ),
    ),
    "non-ascii domain": (
        "qx.test; spf=pass smtp.helo=b\xfccher.qx.test",
        Want("a.example; spf=pass smtp.helo=b.example", (_a(), _b()), non_ascii=1),
    ),
    "bare cr in a comment": (
        "qx.test; dkim=pass (a\rb)",
        Want("a.example; dkim=pass (...\r...)", (_a(),), free=2),
    ),
    "tab kept": ("qx.test;\tnone", Want("a.example;\tnone", (_a(),))),
}


@pytest.mark.parametrize(("value", "want"), CHARS.values(), ids=CHARS.keys())
def test_characters(value: str, want: Want) -> None:
    check(value, want)


# --- item 6: shape cases ------------------------------------------------------------

_SHAPE_CASES: Final = [c for m in (cases_vendor, cases_refused) for c in m.CASES]
_SHAPE_BY_ID: Final = {c.id: c for c in _SHAPE_CASES}

SHAPES: Final = {
    "vendor microsoft both fail": Want(SAME),
    "vendor microsoft read results": Want(
        "spf=fail (...)\r\n smtp.mailfrom=example.com; dkim=pass (...)\r\n"
        " header.d=example.com; dmarc=fail action=quarantine\r\n"
        " header.from=example.com; compauth=fail reason=000",
        free=2,
    ),
    "vendor microsoft via valimail": Want(
        "spf=pass (...)\r\n smtp.mailfrom=example.com; dkim=pass (...)\r\n"
        " header.d=example.com;dmarc=pass action=none\r\n"
        " header.from=example.com;compauth=pass reason=100",
        free=2,
    ),
    "vendor gmail via valimail": Want(
        "mx.google.com;\r\n"
        "           dkim=pass header.i=@example.com header.s=sel1 header.b=b64-1;\r\n"
        "           spf=pass (...) smtp.mailfrom=user1@example.com;\r\n"
        "           dmarc=pass (...) header.from=example.com",
        (rep("b64-1", "base64"), _user()),
        free=2,
    ),
    "vendor yahoo via valimail": Want(
        "atlas321.free.mail.ne1.yahoo.com;\r\n"
        " dkim=pass header.i=@example.com header.s=sel1;\r\n"
        " spf=pass smtp.mailfrom=example.com;\r\n"
        " dmarc=pass(...) header.from=example.com;",
        free=1,
    ),
    "vendor gmail via postmark": Want(
        "mx.google.com;\r\n  spf=pass (...) smtp.mail=user1@a.example;\r\n"
        "  dkim=pass header.i=@example.com;\r\n"
        "  dmarc=pass (...) header.from=example.com",
        (_user(), _a()),
        free=2,
    ),
    "vendor microsoft dmarc oreject": Want(
        "spf=pass (...)\r\n  smtp.mailfrom=a.example; dkim=pass (...)\r\n"
        "  header.d=example.net; dmarc=fail action=oreject\r\n"
        "  header.from=example.com;compauth=fail reason=000",
        (_a(),),
        free=2,
    ),
    "vendor gmail arc via postmark": Want(
        "i=1; mx.google.com;\r\n"
        "       dkim=pass header.i=@example.com header.s=sel1 header.b=b64-1;\r\n"
        "       dkim=pass header.i=@example.net header.s=sel2 header.b=b64-2;\r\n"
        "       spf=pass (...) smtp.mailfrom=user1@a.example;\r\n"
        "       dmarc=pass (...) header.from=example.com",
        (rep("b64-1", "base64"), rep("b64-2", "base64"), _user(), _a()),
        free=2,
        arc=True,
    ),
    "vendor aol unknown results": Want(SAME),
    "vendor fastmail blog": Want(
        "mx2.messagingengine.com;\r\n    dkim=pass (...) header.d=example.com"
        " header.i=@example.com header.b=b64-1/;\r\n"
        "    dmarc=pass header.from=example.com;\r\n"
        "    spf=pass smtp.mailfrom=user1@example.com smtp.helo=a.example",
        (rep("b64-1/", "base64"), _user(), _a()),
        free=1,
    ),
    "vendor icloud bimi quoted reason": Want(
        'bimi.icloud.com; bimi=skipped reason="..."', free=1
    ),
    "vendor icloud dkim tab fold": Want(
        "dkim-verifier.icloud.com;\r\n\tdkim=pass (...) header.d=example.com"
        " header.i=@example.com header.b=b64-1",
        (rep("b64-1", "base64"),),
        free=1,
    ),
    "vendor zoho arc angle address": Want(
        "i=1; mx.zohomail360.com;\r\n\tdkim=pass  header.i=a.example;\r\n"
        "\tspf=pass  smtp.mailfrom=user1@b.example;\r\n"
        "\tdmarc=pass header.from=<user2@a.example>",
        (_a(2), _user(1), _b(), _user(2)),
        arc=True,
    ),
    "vendor zoho eu": Want(
        "mx.zohomail.eu;\r\n\tdkim=pass;\r\n"
        "\tspf=pass (...)  smtp.mailfrom=user1@example.net;\r\n"
        "\tdmarc=pass(...)  header.from=example.net",
        (_user(),),
        free=2,
    ),
    "vendor proofpoint via guide": Want(
        "ppops.net;\r\n      spf=pass smtp.mailfrom=user1@example.com;\r\n"
        "      dkim=pass header.s=sel1 header.d=example.com;\r\n"
        "      dmarc=pass header.from=example.com",
        (_user(),),
    ),
    "vendor cisco esa dmarc": Want(
        "a.example; dkim=pass (...)\r\n"
        " header.i=user1@b.example; dmarc=pass (...) d=b.example",
        (_a(), _user(), _b(2)),
        free=2,
    ),
    "vendor opendkim header.b with slash": Want(
        "a.example;\r\n\tdkim=pass (...) header.d=example.com header.i=@example.com"
        " header.a=rsa-sha256 header.s=sel1 header.b=b64-1/",
        (_a(), rep("b64-1/", "base64")),
        free=1,
    ),
    "vendor opendmarc dmarc pass": Want(
        "a.example; dmarc=pass (...) header.from=example.com", (_a(),), free=1
    ),
    "vendor opendmarc spf tempfail": Want(
        "a.example; spf=tempfail smtp.mailfrom=example.com", (_a(),)
    ),
    "vendor rspamd quoted header.b": Want(
        'a.example; dkim=pass header.d=example.com header.s=sel1 header.b="b64-1/";'
        " spf=pass (...) smtp.mailfrom=user1@example.com",
        (_a(), rep("b64-1/", "base64"), _user()),
        free=1,
    ),
    "vendor exim iprev and arc": Want(
        "example.com;\r\n\tiprev=pass (...) smtp.remote-ip=192.0.2.1;\r\n"
        "\tarc=pass (...) header.s=sel1 arc.oldest-pass=1 smtp.remote-ip=192.0.2.1",
        (rep("sel1", "selector"),),
        free=2,
    ),
    "vendor exim ipv6 remote-ip": Want(
        "a.example;\r\n\tiprev=pass (...) smtp.remote-ip=2001:db8::1", (_a(),), free=1
    ),
    "vendor exim null sender": Want(
        "a.example;\r\n\tspf=none smtp.mailfrom=<>", (_a(),)
    ),
    "vendor exim ip-literal helo": Want(
        "a.example;\r\n\tspf=pass smtp.helo=[192.0.2.1]", (_a(),)
    ),
    "vendor postfix policyd-spf-perl localhost": Want(
        "a.example; none (...)", (_a(),), free=1
    ),
    "refused exim arc leading property": Want(SAME, arc=True),
    "refused microsoft domain between results": Want(
        "spf=none (...)\r\n  smtp.mailfrom=example.net; example.com; dkim=pass\r\n"
        "  (...) header.d=example.net;\r\n"
        "  example.com; dmarc=none action=none header.from=example.com;\r\n"
        "  compauth=fail reason=001",
        free=2,
    ),
    "refused opendkim authserv-id job id": Want(
        "a.example/job1;\r\n\tdkim=none", (_a(), rep("job1", "job-id"))
    ),
    "refused exim authserv-id only": Want("a.example", (_a(),)),
    "refused mimecast spf details as results": Want(
        "mimecast.com; spf=pass (...) client-ip=192.0.2.195;"
        " envelope-from=user1@example.com; helo=a.example;"
        " dkim=pass header.i=@example.com; dmarc=pass (...) header.from=example.com",
        (_user(), _a()),
        free=2,
    ),
    "refused zoho missing semicolon": Want(
        "mx.zoho.com;\r\n dkim=pass\r\n spf=pass (...)\r\n"
        " smtp.mailfrom=user1@example.net;",
        (_user(),),
        free=1,
    ),
}

# Reserved names become qx*.test, documentation addresses RFC 1918 or ULA.
_SUBSTITUTIONS: Final = (
    ("example.com", "qxc.test"),
    ("example.net", "qxn.test"),
    ("192.0.2.", "10.0.2."),
    ("198.51.100.", "10.51.100."),
    ("2001:db8::", "fd00::"),
)


def secret_variant(value: str) -> str:
    for old, new in _SUBSTITUTIONS:
        value = value.replace(old, new)
    return value


SECRET_SHAPES: Final = {
    "vendor microsoft both fail": Want(
        "spf=fail smtp.mailfrom=a.example;\r\n"
        " dkim=fail header.d=a.example; dmarc=fail action=quarantine;\r\n"
        " compauth=fail reason=000",
        (_a(2),),
    ),
    "vendor microsoft read results": Want(
        "spf=fail (...)\r\n smtp.mailfrom=a.example; dkim=pass (...)\r\n"
        " header.d=a.example; dmarc=fail action=quarantine\r\n"
        " header.from=a.example; compauth=fail reason=000",
        (_a(3),),
        free=2,
    ),
    "vendor microsoft via valimail": Want(
        "spf=pass (...)\r\n smtp.mailfrom=a.example; dkim=pass (...)\r\n"
        " header.d=a.example;dmarc=pass action=none\r\n"
        " header.from=a.example;compauth=pass reason=100",
        (_a(3),),
        free=2,
    ),
    "vendor gmail via valimail": Want(
        "mx.google.com;\r\n"
        "           dkim=pass header.i=@a.example header.s=sel1 header.b=b64-1;\r\n"
        "           spf=pass (...) smtp.mailfrom=user1@a.example;\r\n"
        "           dmarc=pass (...) header.from=a.example",
        (_a(3), rep("b64-1", "base64"), _user()),
        free=2,
    ),
    "vendor yahoo via valimail": Want(
        "atlas321.free.mail.ne1.yahoo.com;\r\n"
        " dkim=pass header.i=@a.example header.s=sel1;\r\n"
        " spf=pass smtp.mailfrom=a.example;\r\n"
        " dmarc=pass(...) header.from=a.example;",
        (_a(3),),
        free=1,
    ),
    "vendor gmail via postmark": Want(
        "mx.google.com;\r\n  spf=pass (...) smtp.mail=user1@a.example;\r\n"
        "  dkim=pass header.i=@b.example;\r\n"
        "  dmarc=pass (...) header.from=b.example",
        (_user(), _a(), _b(2)),
        free=2,
    ),
    "vendor microsoft dmarc oreject": Want(
        "spf=pass (...)\r\n  smtp.mailfrom=a.example; dkim=pass (...)\r\n"
        "  header.d=b.example; dmarc=fail action=oreject\r\n"
        "  header.from=c.example;compauth=fail reason=000",
        (_a(), _b(), _c()),
        free=2,
    ),
    "vendor gmail arc via postmark": Want(
        "i=1; mx.google.com;\r\n"
        "       dkim=pass header.i=@a.example header.s=sel1 header.b=b64-1;\r\n"
        "       dkim=pass header.i=@b.example header.s=sel2 header.b=b64-2;\r\n"
        "       spf=pass (...) smtp.mailfrom=user1@c.example;\r\n"
        "       dmarc=pass (...) header.from=a.example",
        (
            _a(2),
            rep("b64-1", "base64"),
            _b(),
            rep("b64-2", "base64"),
            _user(),
            _c(),
        ),
        free=2,
        arc=True,
    ),
    "vendor aol unknown results": Want(
        "atlas206.aol.mail.ne1.yahoo.com;\r\n dkim=unknown;\r\n"
        " spf=none smtp.mailfrom=a.example;\r\n"
        " dmarc=unknown header.from=a.example;",
        (_a(2),),
    ),
    "vendor fastmail blog": Want(
        "mx2.messagingengine.com;\r\n    dkim=pass (...) header.d=a.example"
        " header.i=@a.example header.b=b64-1/;\r\n"
        "    dmarc=pass header.from=a.example;\r\n"
        "    spf=pass smtp.mailfrom=user1@a.example smtp.helo=b.example",
        (_a(4), rep("b64-1/", "base64"), _user(), _b()),
        free=1,
    ),
    "vendor icloud dkim tab fold": Want(
        "dkim-verifier.icloud.com;\r\n\tdkim=pass (...) header.d=a.example"
        " header.i=@a.example header.b=b64-1",
        (_a(2), rep("b64-1", "base64")),
        free=1,
    ),
    "vendor zoho arc angle address": SHAPES["vendor zoho arc angle address"],
    "vendor zoho eu": Want(
        "mx.zohomail.eu;\r\n\tdkim=pass;\r\n"
        "\tspf=pass (...)  smtp.mailfrom=user1@a.example;\r\n"
        "\tdmarc=pass(...)  header.from=a.example",
        (_user(), _a(2)),
        free=2,
    ),
    "vendor proofpoint via guide": Want(
        "ppops.net;\r\n      spf=pass smtp.mailfrom=user1@a.example;\r\n"
        "      dkim=pass header.s=sel1 header.d=a.example;\r\n"
        "      dmarc=pass header.from=a.example",
        (_user(), _a(3)),
    ),
    "vendor cisco esa dmarc": SHAPES["vendor cisco esa dmarc"],
    "vendor opendkim header.b with slash": Want(
        "a.example;\r\n\tdkim=pass (...) header.d=b.example header.i=@b.example"
        " header.a=rsa-sha256 header.s=sel1 header.b=b64-1/",
        (_a(), _b(2), rep("b64-1/", "base64")),
        free=1,
    ),
    "vendor opendmarc dmarc pass": Want(
        "a.example; dmarc=pass (...) header.from=b.example", (_a(), _b()), free=1
    ),
    "vendor opendmarc spf tempfail": Want(
        "a.example; spf=tempfail smtp.mailfrom=b.example", (_a(), _b())
    ),
    "vendor rspamd quoted header.b": Want(
        'a.example; dkim=pass header.d=b.example header.s=sel1 header.b="b64-1/";'
        " spf=pass (...) smtp.mailfrom=user1@b.example",
        (_a(), _b(2), rep("b64-1/", "base64"), _user()),
        free=1,
    ),
    "vendor exim iprev and arc": Want(
        "a.example;\r\n\tiprev=pass (...) smtp.remote-ip=192.0.2.1;\r\n"
        "\tarc=pass (...) header.s=sel1 arc.oldest-pass=1 smtp.remote-ip=192.0.2.1",
        (_a(), rep("192.0.2.1", "ipv4", 2), rep("sel1", "selector")),
        free=2,
    ),
    "vendor exim ipv6 remote-ip": Want(
        "a.example;\r\n\tiprev=pass (...) smtp.remote-ip=2001:db8::1",
        (_a(), rep("2001:db8::1", "ipv6")),
        free=1,
    ),
    "vendor exim null sender": SHAPES["vendor exim null sender"],
    "vendor exim ip-literal helo": Want(
        "a.example;\r\n\tspf=pass smtp.helo=[192.0.2.1]",
        (_a(), rep("192.0.2.1", "ipv4")),
    ),
    "vendor postfix policyd-spf-perl localhost": SHAPES[
        "vendor postfix policyd-spf-perl localhost"
    ],
    "refused exim arc leading property": Want(
        "i=1; a.example; smtp.remote-ip=192.0.2.1;\r\n\tarc=none",
        (_a(), rep("192.0.2.1", "ipv4")),
        arc=True,
    ),
    "refused microsoft domain between results": Want(
        "spf=none (...)\r\n  smtp.mailfrom=a.example; b.example; dkim=pass\r\n"
        "  (...) header.d=a.example;\r\n"
        "  b.example; dmarc=none action=none header.from=b.example;\r\n"
        "  compauth=fail reason=001",
        (_a(2), _b(3)),
        free=2,
    ),
    "refused opendkim authserv-id job id": SHAPES[
        "refused opendkim authserv-id job id"
    ],
    "refused exim authserv-id only": SHAPES["refused exim authserv-id only"],
    "refused mimecast spf details as results": Want(
        "mimecast.com; spf=pass (...) client-ip=192.0.2.1;"
        " envelope-from=user1@a.example; helo=b.example;"
        " dkim=pass header.i=@a.example; dmarc=pass (...) header.from=a.example",
        (rep("192.0.2.1", "ipv4"), _user(), _a(3), _b()),
        free=2,
    ),
    "refused zoho missing semicolon": Want(
        "mx.zoho.com;\r\n dkim=pass\r\n spf=pass (...)\r\n"
        " smtp.mailfrom=user1@a.example;",
        (_user(), _a()),
        free=1,
    ),
}

# Doc layout artefacts with a full value in docs/refused-shapes.md.
_SECOPS: Final = (
    "i=1; mx.google.com;       dkim=pass header.i=@labilfrom=sender@example.com;"
    "       dara=pass header.i=@example.com"
)
_CISCO: Final = "example1.com header.from=From:user123@example.com; dkim=pass "
DOC_SHAPES: Final[dict[str, tuple[str, Call, Want, Want]]] = {
    "google secops": (
        _SECOPS,
        "parse_arc",
        Want(
            "i=1; mx.google.com;       dkim=pass header.i=@user1@example.com;"
            "       tok1=pass header.i=@example.com",
            (_user(), rep("tok1", "word")),
            arc=True,
        ),
        Want(
            "i=1; mx.google.com;       dkim=pass header.i=@user1@a.example;"
            "       tok1=pass header.i=@a.example",
            (_user(), _a(2), rep("tok1", "word")),
            arc=True,
        ),
    ),
    **{
        f"cisco {name}": (
            _CISCO + comment,
            "parse",
            Want(
                "a.example header.from=From:user123@example.com; dkim=pass (...)",
                (_a(),),
                free=1,
            ),
            Want(
                "a.example header.from=From:user123@b.example; dkim=pass (...)",
                (_a(), _b()),
                free=1,
            ),
        )
        for name, comment in (
            ("verified", "(signature verified)"),
            ("partially", "(partially verified [1000 bytes])"),
        )
    },
    "cisco permfail": (
        (
            "example1.com header.from=From:user123@example.com;"
            " dkim=permfail (body hash did not verify)"
        ),
        "parse",
        Want(
            "a.example header.from=From:user123@example.com; dkim=tok1 (...)",
            (_a(), rep("tok1", "word")),
            free=1,
        ),
        Want(
            "a.example header.from=From:user123@b.example; dkim=tok1 (...)",
            (_a(), _b(), rep("tok1", "word")),
            free=1,
        ),
    ),
}


Uses = list[tuple[Call, Options]]


def _uses(value: str) -> Uses:
    """Every (call, options) the case modules use with *value*."""
    return [(_call_of(c), c.kwargs) for c in _SHAPE_CASES if c.value == value]


def _assert_parse_kept(original: str, redacted: str, uses: Uses) -> None:
    assert uses
    for call, kwargs in uses:
        assert outcome(redacted, call, kwargs) == outcome(original, call, kwargs)


def test_every_shape_value_has_an_expected_output() -> None:
    expected = {_SHAPE_BY_ID[i].value for i in SHAPES}
    assert {c.value for c in _SHAPE_CASES} == expected
    assert set(SECRET_SHAPES) <= set(SHAPES)
    # Values with nothing to substitute have no variant.
    for case_id in set(SHAPES) - set(SECRET_SHAPES):
        value = _SHAPE_BY_ID[case_id].value
        assert isinstance(value, str)
        assert secret_variant(value) == value


def _doc_rewritten_values() -> set[str]:
    text = (ROOT / "docs" / "refused-shapes.md").read_text(encoding="utf-8")
    values = set()
    for line in text.splitlines():
        if "**Rewritten value" in line:
            spans = re.findall(r"`([^`]+)`", line)
            values.add(
                max(spans, key=len).replace("\\r\\n", "\r\n").replace("\\t", "\t")
            )
    return values


def test_every_documented_value_is_covered() -> None:
    documented = _doc_rewritten_values()
    assert len(documented) == 6  # noqa: PLR2004 - five refused shapes and Zoho
    covered = {_SHAPE_BY_ID[i].value for i in SHAPES} | {
        v[0] for v in DOC_SHAPES.values()
    }
    assert documented <= covered


@pytest.mark.parametrize(("case_id", "want"), SHAPES.items(), ids=SHAPES.keys())
def test_shape_case(case_id: str, want: Want) -> None:
    value = _SHAPE_BY_ID[case_id].value
    assert isinstance(value, str)
    result = check(value, want)
    _assert_parse_kept(value, result.text, _uses(value))


@pytest.mark.parametrize(
    ("case_id", "want"), SECRET_SHAPES.items(), ids=SECRET_SHAPES.keys()
)
def test_shape_case_with_secrets(case_id: str, want: Want) -> None:
    original = _SHAPE_BY_ID[case_id].value
    assert isinstance(original, str)
    value = secret_variant(original)
    assert value != original
    uses = _uses(original)
    # The substitution itself keeps the parse.
    _assert_parse_kept(original, value, uses)
    result = check(value, want)
    assert "qx" not in result.text.lower()
    _assert_parse_kept(value, result.text, uses)


@pytest.mark.parametrize(
    ("value", "call", "want", "secret_want"),
    DOC_SHAPES.values(),
    ids=DOC_SHAPES.keys(),
)
def test_doc_artefacts(value: str, call: Call, want: Want, secret_want: Want) -> None:
    uses: Uses = [(call, {}), (call, {"strict_syntax": True})]
    result = check(value, want)
    _assert_parse_kept(value, result.text, uses)
    variant = secret_variant(value)
    assert variant != value
    secret = check(variant, secret_want)
    assert "qx" not in secret.text.lower()
    _assert_parse_kept(variant, secret.text, uses)


# --- item 7: API hygiene -------------------------------------------------------------


class _Sneaky(str):
    __slots__ = ()

    def __str__(self) -> str:
        return "sneaky.qx.test; none"

    def __len__(self) -> int:
        return 0


def test_redact_str_subclass() -> None:
    plain = _redact.redact("qx.test; none")
    assert _redact.redact(_Sneaky("qx.test; none")) == plain
    assert plain.text == "a.example; none"


@pytest.mark.parametrize("value", [None, b"qx.test; none", 1, ["qx.test"]])
def test_redact_non_str(value: object) -> None:
    with pytest.raises(AuthResultsError) as info:
        _redact.redact(cast("str", value))
    assert info.value.reason is ErrorReason.INVALID_TYPE


def test_redact_internal_error_hides_input(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError(SECRET)

    monkeypatch.setattr(_redact, "_redact_value", boom)
    with pytest.raises(AuthResultsError) as info:
        _redact.redact(SECRET)
    assert info.value.reason is ErrorReason.INTERNAL
    text = "".join(traceback.format_exception(info.value))
    assert SECRET not in text
    assert "qxbank" not in text


def test_redaction_is_frozen_and_slotted() -> None:
    result = _redact.redact("qx.test; dkim=pass header.d=qx.test")
    for obj in (result, result.replacements[0]):
        assert dataclasses.is_dataclass(obj)
        assert not hasattr(obj, "__dict__")
        field = dataclasses.fields(obj)[0].name
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(obj, field, None)


def test_originals_out_of_repr_but_compared() -> None:
    fields = {f.name: f for f in dataclasses.fields(_redact.Redaction)}
    assert fields["originals"].repr is False
    assert fields["originals"].compare is True
    result = _redact.redact("qxsecret.test; dkim=pass header.i=qxbob@qxsecret.test")
    assert "qx" not in repr(result).lower()
    assert result == _redact.redact(
        "qxsecret.test; dkim=pass header.i=qxbob@qxsecret.test"
    )


def test_package_does_not_import_the_helper() -> None:
    tree = ast.parse((ROOT / "src" / "authresults" / "__init__.py").read_text("utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names.add(node.module or "")
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
    assert not names & {
        "redact",
        "_redact",
        "authresults.redact",
        "authresults._redact",
    }
    assert "redact" not in authresults.__all__
    assert "_redact" not in authresults.__all__


def test_no_console_script() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))["project"]
    assert not {"scripts", "gui-scripts", "entry-points"} & set(project)


# --- item 8: the CLI ----------------------------------------------------------------

HEAD: Final = b"authresults.redact: best effort; read the output before posting it\n"
HEAD_SHOWN: Final = (
    b"authresults.redact: best effort; ORIGINALS SHOWN BELOW: do not post this report\n"
)


def _lines(*lines: str) -> bytes:
    return "".join(line + "\n" for line in lines).encode("ascii")


CLI: Final = {
    "worked example 1": (
        UNITS["worked example 1"][0].encode(),
        UNITS["worked example 1"][1].text.encode() + b"\n",
        HEAD
        + _lines(
            "replaced (originals not shown):",
            "  a.example domain x1",
            "  b.example domain x2",
            "  user1 local-part x1",
            "  sel1 selector x1",
            "  b64-1/= base64 x1",
            "free text replaced with ...: 1",
            "parse (original): ok deviations: pvalue_tspecials",
            "parse (redacted): ok deviations: pvalue_tspecials",
        ),
    ),
    "worked example 2": (
        (
            b"mimecast.com; spf=pass (x) client-ip=10.1.2.3; envelope-from=bob@qx.test;"
            b" helo=mail.qx.test; dkim=pass header.i=@qx.test"
        ),
        (
            b"mimecast.com; spf=pass (...) client-ip=192.0.2.1;"
            b" envelope-from=user1@a.example; helo=b.example; dkim=pass"
            b" header.i=@a.example\n"
        ),
        HEAD
        + _lines(
            "replaced (originals not shown):",
            "  192.0.2.1 ipv4 x1",
            "  user1 local-part x1",
            "  a.example domain x2",
            "  b.example domain x1",
            "free text replaced with ...: 1",
            "parse (original): syntax at position 64 known shape"
            " spf_details_as_results",
            "parse (redacted): syntax at position 69 known shape"
            " spf_details_as_results",
        ),
    ),
    "worked example 3": (
        b"mail.qx.test/4ABCD1234;\r\n\tdkim=none",
        b"a.example/job1;\r\n\tdkim=none\n",
        HEAD
        + _lines(
            "replaced (originals not shown):",
            "  a.example domain x1",
            "  job1 job-id x1",
            "free text replaced with ...: 0",
            "line breaks: 1 CRLF, 0 LF, 0 CR",
            "parse (original): syntax at position 12 known shape authserv_id_job_id",
            "parse (redacted): syntax at position 9 known shape authserv_id_job_id",
        ),
    ),
    "worked example 4": (
        b"i=1; qx.test; smtp.remote-ip=10.0.0.1;\r\n\tarc=none",
        b"i=1; a.example; smtp.remote-ip=192.0.2.1;\r\n\tarc=none\n",
        HEAD
        + _lines(
            "replaced (originals not shown):",
            "  a.example domain x1",
            "  192.0.2.1 ipv4 x1",
            "free text replaced with ...: 0",
            "line breaks: 1 CRLF, 0 LF, 0 CR",
            "parse (original): syntax at position 18 known shape"
            " exim_arc_leading_property",
            "parse (redacted): syntax at position 20 known shape"
            " exim_arc_leading_property",
        ),
    ),
    "worked example 5": (
        str(_RFC_CASES["rfc8601 B.7"].value).encode(),
        RFC["rfc8601 B.7"].text.encode() + b"\n",
        HEAD
        + _lines(
            "replaced (originals not shown):",
            "  a.example domain x1",
            "  tok1 word x1",
            "  num1 number x1",
            "free text replaced with ...: 9",
            "line breaks: 3 CRLF, 0 LF, 0 CR",
            "parse (original): ok",
            "parse (redacted): ok",
        ),
    ),
    "worked example 6": (
        UNITS["worked example 6"][0].encode(),
        UNITS["worked example 6"][1].text.encode() + b"\n",
        HEAD
        + _lines(
            "replaced (originals not shown):",
            "  a.example domain x1",
            "  b.example domain x1",
            "  ptype1 ptype x1",
            "  prop1 property x1",
            "free text replaced with ...: 0",
            "parse (original): syntax at position 29",
            "parse (redacted): ok",
        ),
    ),
    "removed characters": (
        b"q|\x00\xe2\x80\x8b\xc3\xa9\xf0\x9f\x98\x80\xff.test; none",
        b"a.example; none\n",
        HEAD
        + _lines(
            "replaced (originals not shown):",
            "  a.example domain x1",
            "free text replaced with ...: 0",
            "removed: 2 non-ASCII, 3 control or format characters",
            "parse (original): control_char at position 2",
            "parse (redacted): ok",
        ),
    ),
    "nothing replaced": (
        b"example.com; none",
        b"example.com; none\n",
        HEAD
        + _lines(
            "replaced (originals not shown): none",
            "free text replaced with ...: 0",
            "parse (original): ok",
            "parse (redacted): ok",
        ),
    ),
    "empty": (
        b"",
        b"\n",
        HEAD
        + _lines(
            "replaced (originals not shown): none",
            "free text replaced with ...: 0",
            "parse (original): empty",
            "parse (redacted): empty",
        ),
    ),
    "over the parse default max_length": (
        b"qx.test;" + b" " * 9000 + b"none",
        b"a.example;" + b" " * 9000 + b"none\n",
        HEAD
        + _lines(
            "replaced (originals not shown):",
            "  a.example domain x1",
            "free text replaced with ...: 0",
            "parse (original): ok",
            "parse (redacted): ok",
        ),
    ),
    "14.3 removed: only non-ascii": (
        b"qx\xc3\xa9.test; none",
        b"a.example; none\n",
        HEAD
        + _lines(
            "replaced (originals not shown):",
            "  a.example domain x1",
            "free text replaced with ...: 0",
            "removed: 1 non-ASCII, 0 control or format characters",
            "parse (original): non_ascii at position 2",
            "parse (redacted): ok",
        ),
    ),
    "14.3 removed: only control": (
        b"qx\x00.test; none",
        b"a.example; none\n",
        HEAD
        + _lines(
            "replaced (originals not shown):",
            "  a.example domain x1",
            "free text replaced with ...: 0",
            "removed: 0 non-ASCII, 1 control or format characters",
            "parse (original): control_char at position 2",
            "parse (redacted): ok",
        ),
    ),
    "14.2 all three input notes": (
        b"\xef\xbb\xbfAuthentication-Results:qx.test; none\n",
        b"a.example; none\n",
        HEAD
        + _lines(
            "replaced (originals not shown):",
            "  a.example domain x1",
            "free text replaced with ...: 0",
            "input: removed byte order mark; field name; trailing line break",
            "parse (original): ok",
            "parse (redacted): ok",
        ),
    ),
    "14.4 line breaks after the strip": (
        b"qx.test;\r\n none\n",
        b"a.example;\r\n none\n",
        HEAD
        + _lines(
            "replaced (originals not shown):",
            "  a.example domain x1",
            "free text replaced with ...: 0",
            "line breaks: 1 CRLF, 0 LF, 0 CR",
            "input: removed trailing line break",
            "parse (original): ok",
            "parse (redacted): ok",
        ),
    ),
    "14.4 one newline left after the strip": (
        b"qx.test; none\n\n",
        b"a.example; none\n\n",
        HEAD
        + _lines(
            "replaced (originals not shown):",
            "  a.example domain x1",
            "free text replaced with ...: 0",
            "line breaks: 0 CRLF, 1 LF, 0 CR",
            "input: removed trailing line break",
            "parse (original): control_char at position 13",
            "parse (redacted): control_char at position 15",
        ),
    ),
    "14.4 mixed line breaks after a crlf strip": (
        b"qx.test;\r\n\tdkim=pass;\n spf=pass\r\n",
        b"a.example;\r\n\tdkim=pass;\n spf=pass\n",
        HEAD
        + _lines(
            "replaced (originals not shown):",
            "  a.example domain x1",
            "free text replaced with ...: 0",
            "line breaks: 1 CRLF, 1 LF, 0 CR",
            "input: removed trailing line break",
            "parse (original): ok deviations: lf_folding",
            "parse (redacted): ok deviations: lf_folding",
        ),
    ),
    "14.5 deviations in definition order": (
        b"spf=pass action=qx/a;",
        b"spf=pass action=tok1/a;\n",
        HEAD
        + _lines(
            "replaced (originals not shown):",
            "  tok1 word x1",
            "free text replaced with ...: 0",
            "parse (original): ok deviations: bare_property, pvalue_tspecials,"
            " trailing_semicolon, missing_authserv_id",
            "parse (redacted): ok deviations: bare_property, pvalue_tspecials,"
            " trailing_semicolon, missing_authserv_id",
        ),
    ),
    "14.10 wsp after the colon kept": (
        b"Authentication-Results: qx.test; none",
        b" a.example; none\n",
        HEAD
        + _lines(
            "replaced (originals not shown):",
            "  a.example domain x1",
            "free text replaced with ...: 0",
            "input: removed field name",
            "parse (original): ok",
            "parse (redacted): ok",
        ),
    ),
    "x- field name kept": (
        b"X-Authentication-Results: qx.test; none",
        b"tok1: a.example; none\n",
        HEAD
        + _lines(
            "replaced (originals not shown):",
            "  tok1 word x1",
            "  a.example domain x1",
            "free text replaced with ...: 0",
            "parse (original): syntax at position 24",
            "parse (redacted): syntax at position 4",
        ),
    ),
}


@pytest.mark.parametrize(("data", "stdout", "stderr"), CLI.values(), ids=CLI.keys())
def test_cli_exact(data: bytes, stdout: bytes, stderr: bytes) -> None:
    assert run_cli(data) == (0, stdout, stderr)


def test_cli_show_originals_exact() -> None:
    data, stdout, _ = CLI["worked example 1"]
    expected = HEAD_SHOWN + _lines(
        "replaced (originals shown):",
        "  a.example domain x1 <- mx.qx1.test",
        "  b.example domain x2 <- qx2.test",
        "  user1 local-part x1 <- bob",
        "  sel1 selector x1 <- qxsel",
        "  b64-1/= base64 x1 <- Ab+/cd=",
        "free text replaced with ...: 1",
        "parse (original): ok deviations: pvalue_tspecials",
        "parse (redacted): ok deviations: pvalue_tspecials",
    )
    assert run_cli(data, "--show-originals") == (0, stdout, expected)


def test_cli_show_originals_escapes() -> None:
    data, stdout, _ = CLI["removed characters"]
    expected = HEAD_SHOWN + (
        b"replaced (originals shown):\n"
        rb"  a.example domain x1 <- q\x7c\x00\u200b\xe9\U0001f600\udcff.test"
        b"\n"
        b"free text replaced with ...: 0\n"
        b"removed: 2 non-ASCII, 3 control or format characters\n"
        b"parse (original): control_char at position 2\n"
        b"parse (redacted): ok\n"
    )
    assert run_cli(data, "--show-originals") == (0, stdout, expected)


def test_cli_show_originals_lists_spellings() -> None:
    code, _, err = run_cli(b"QX.test; dkim=pass header.d=qx.TEST", "--show-originals")
    assert code == 0
    assert b"  a.example domain x2 <- QX.test | qx.TEST\n" in err


def _input_notes(stderr: bytes) -> list[str]:
    lines = [x for x in stderr.decode("ascii").splitlines() if x.startswith("input: ")]
    assert len(lines) == 1
    assert lines[0].startswith("input: removed ")
    return lines[0].removeprefix("input: removed ").split("; ")


_BOM = "byte order mark"
_NAME = "field name"
_BREAK = "trailing line break"

STRIPS: Final = {
    "bom": (b"\xef\xbb\xbfqx.test; none", b"a.example; none\n", [_BOM]),
    "field name": (
        b"Authentication-Results:qx.test; none",
        b"a.example; none\n",
        [_NAME],
    ),
    "field name any case and wsp": (
        b"aUTHENTICATION-results \t:qx.test; none",
        b"a.example; none\n",
        [_NAME],
    ),
    "arc field name": (
        b"ARC-Authentication-Results:i=1; qx.test; none",
        b"i=1; a.example; none\n",
        [_NAME],
    ),
    "lf": (b"qx.test; none\n", b"a.example; none\n", [_BREAK]),
    "crlf": (b"qx.test; none\r\n", b"a.example; none\n", [_BREAK]),
    "all three in order": (
        b"\xef\xbb\xbfARC-Authentication-Results:i=1; qx.test; none\r\n",
        b"i=1; a.example; none\n",
        [_BOM, _NAME, _BREAK],
    ),
    "bom and line break": (
        b"\xef\xbb\xbfqx.test; none\n",
        b"a.example; none\n",
        [_BOM, _BREAK],
    ),
}


@pytest.mark.parametrize(
    ("data", "stdout", "notes"), STRIPS.values(), ids=STRIPS.keys()
)
def test_cli_strips(data: bytes, stdout: bytes, notes: list[str]) -> None:
    code, out, err = run_cli(data)
    assert (code, out) == (0, stdout)
    assert _input_notes(err) == notes
    assert b"uthentication" not in err.lower()


ONLY_ONE: Final = {
    "two boms": (b"\xef\xbb\xbf\xef\xbb\xbfqx.test; none", b"a.example; none\n"),
    "two field names": (
        b"Authentication-Results:Authentication-Results:qx.test; none",
        b"tok1:a.example; none\n",
    ),
    "two newlines": (b"qx.test; none\n\n", b"a.example; none\n\n"),
    "field name after bom only": (
        b"Authentication-Results:\xef\xbb\xbfqx.test; none",
        b"a.example; none\n",
    ),
}


@pytest.mark.parametrize(("data", "stdout"), ONLY_ONE.values(), ids=ONLY_ONE.keys())
def test_cli_strips_only_one(data: bytes, stdout: bytes) -> None:
    code, out, _ = run_cli(data)
    assert (code, out) == (0, stdout)


def test_cli_invalid_utf8() -> None:
    code, out, err = run_cli(b"qx\xff\xc3\xa9.test; none")
    assert (code, out) == (0, b"a.example; none\n")
    assert b"removed: 1 non-ASCII, 1 control or format characters\n" in err


def test_cli_accepts_exactly_one_mib() -> None:
    data = b"qx.test;" + b" " * (MIB - 12) + b"none"
    assert len(data) == MIB
    code, out, _ = run_cli(data)
    assert code == 0
    assert out == b"a.example;" + b" " * (MIB - 12) + b"none\n"


def test_cli_refuses_one_mib_and_one() -> None:
    data = b"qx.test;" + b" " * (MIB - 11) + b"none"
    assert run_cli(data) == (
        1,
        b"",
        b"authresults.redact: input is longer than 1048576 bytes; nothing written\n",
    )


def test_cli_exhaustion() -> None:
    assert run_cli(_many_ipv4(763).encode()) == (
        1,
        b"",
        b"authresults.redact: too many distinct values to number; nothing written\n",
    )


def test_cli_help() -> None:
    for flag in ("--help", "-h"):
        code, out, err = run_cli(b"qx.test; none", flag)
        assert (code, err) == (0, b"")
        assert b"--show-originals" in out
        assert b"qx" not in out


@pytest.mark.parametrize(
    "args",
    [
        ("--bad",),
        ("-x",),
        ("file.txt",),
        ("--show-originals", "--show-originals"),
        ("--show-originals", "--help"),
        ("--help", "--show-originals"),
        ("-h", "--help"),
        ("--help", "extra"),
    ],
)
def test_cli_bad_arguments(args: tuple[str, ...]) -> None:
    _, usage, _ = run_cli(b"", "--help")
    assert run_cli(b"qx.test; none", *args) == (2, b"", usage)


def test_cli_internal_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError(SECRET)

    monkeypatch.setattr(_redact, "_redact_value", boom)
    for args in ((), ("--show-originals",)):
        assert run_cli(SECRET.encode(), *args) == (
            3,
            b"",
            b"authresults.redact: internal error; nothing written\n",
        )


class _Raises(io.BytesIO):
    def __init__(self, error: Exception) -> None:
        super().__init__()
        self.error = error

    def read(self, size: int | None = -1) -> bytes:  # noqa: ARG002
        raise self.error

    def write(self, data: object) -> int:  # noqa: ARG002
        raise self.error


def test_cli_read_error_is_internal() -> None:
    out = io.BytesIO()
    err = io.BytesIO()
    stdin = _Raises(RuntimeError(SECRET))
    assert redact_cli.main([], stdin, out, err) == 3  # noqa: PLR2004
    assert out.getvalue() == b""
    assert err.getvalue() == b"authresults.redact: internal error; nothing written\n"


def test_cli_broken_stdout() -> None:
    err = io.BytesIO()
    stdin = io.BytesIO(b"qxsecret.test; none")
    code = redact_cli.main([], stdin, _Raises(BrokenPipeError()), err)
    assert code == 3  # noqa: PLR2004
    # Section 14 item 15: stdout first; on failure stderr gets only this line.
    assert err.getvalue() == b"authresults.redact: could not write the output\n"


def test_cli_broken_stderr() -> None:
    # Section 16 item 3: stdout is complete, the report is missing: exit 3.
    out = io.BytesIO()
    stdin = io.BytesIO(b"qxsecret.test; none")
    code = redact_cli.main([], stdin, out, _Raises(OSError("closed")))
    assert code == 3  # noqa: PLR2004
    assert out.getvalue() == b"a.example; none\n"


WRITE_FAILED: Final = b"authresults.redact: could not write the output\n"


def test_cli_help_with_broken_stdout() -> None:
    # Section 16 item 3: not "internal error".
    err = io.BytesIO()
    stdin = io.BytesIO(b"")
    code = redact_cli.main(["--help"], stdin, _Raises(BrokenPipeError()), err)
    assert (code, err.getvalue()) == (3, WRITE_FAILED)


def test_cli_usage_error_with_broken_stderr() -> None:
    out = io.BytesIO()
    stdin = io.BytesIO(b"qx.test; none")
    code = redact_cli.main(["--bad"], stdin, out, _Raises(OSError("closed")))
    assert (code, out.getvalue()) == (2, b"")


class _FlushFails(io.BytesIO):
    def flush(self) -> None:
        raise BrokenPipeError


def test_cli_stdout_flush_failure() -> None:
    # Section 16 item 3: a failing flush is a failing stdout write.
    err = io.BytesIO()
    stdin = io.BytesIO(b"qxsecret.test; none")
    code = redact_cli.main([], stdin, _FlushFails(), err)
    assert (code, err.getvalue()) == (3, WRITE_FAILED)


def test_cli_messages_hold_no_input() -> None:
    for data in (b"qxsecret.test; none", b"qx\x00\xff.test; dkim=pass (qx) reason=qx"):
        _, out, err = run_cli(data)
        assert b"qx" not in out
        assert b"qx" not in err


def test_cli_main_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    stdin = io.BytesIO(b"qx.test; none")
    stdout = io.BytesIO()
    stderr = io.BytesIO()
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(stdin))
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(stdout))
    monkeypatch.setattr(sys, "stderr", io.TextIOWrapper(stderr))
    monkeypatch.setattr(sys, "argv", ["redact"])
    monkeypatch.delitem(sys.modules, "authresults.redact", raising=False)
    with pytest.raises(SystemExit) as info:
        runpy.run_module("authresults.redact", run_name="__main__")
    assert info.value.code == 0
    assert stdout.getvalue() == b"a.example; none\n"
    assert stderr.getvalue().startswith(HEAD)


@pytest.mark.parametrize("closed", ["stdin", "stdout"])
def test_cli_main_guard_closed_stream(
    monkeypatch: pytest.MonkeyPatch, closed: str
) -> None:
    # Section 17 item 7: a None stream exits 3 with no traceback.
    stderr = io.BytesIO()
    wrapper = io.TextIOWrapper(stderr)
    streams = {
        "stdin": io.TextIOWrapper(io.BytesIO(b"qx.test; none")),
        "stdout": io.TextIOWrapper(io.BytesIO()),
    }
    for name, stream in streams.items():
        monkeypatch.setattr(sys, name, None if name == closed else stream)
    monkeypatch.setattr(sys, "stderr", wrapper)
    monkeypatch.setattr(sys, "argv", ["redact"])
    monkeypatch.delitem(sys.modules, "authresults.redact", raising=False)
    with pytest.raises(SystemExit) as info:
        runpy.run_module("authresults.redact", run_name="__main__")
    assert info.value.code == 3  # noqa: PLR2004
    wrapper.flush()
    assert stderr.getvalue() == b"authresults.redact: internal error; nothing written\n"


# --- item 9: linear time --------------------------------------------------------------


def _repeat(unit: str, n: int) -> str:
    return (unit * (n // len(unit) + 1))[:n]


def _numbered(head: str, item: str, n: int) -> str:
    parts = [head]
    size = len(head)
    i = 1
    while size < n:
        text = item.format(i)
        parts.append(text)
        size += len(text)
        i += 1
    return "".join(parts)[:n]


PATTERNS: Final = {
    **{f"repeated {c!r}": c for c in '()"\\;@:='},
    **{f"repeated {p!r}": p for p in ("a@", "1:", "1.", "a.", "<[")},
    "repeated dkim=pass": "dkim=pass ",
    "repeated header.d=x": "header.d=x ",
    "repeated i=1;": "i=1;",
    "repeated fold": "\r\n ",
    "repeated e-acute": "\xe9",
    "repeated zero width space": "\u200b",
    "repeated nul": "\x00",
}
NUMBERED: Final = {
    "distinct domains": ("qx.test; dkim=pass", " d{}.qx"),
    "distinct ipv6": ("qx.test; iprev=pass", " policy.ip=fd00::{:x}"),
    "distinct local-parts": ("qx.test; spf=pass", " smtp.mailfrom=u{}@qx.test"),
}


@functools.cache
def _timing_values(n: int) -> dict[str, str]:
    values = {name: _repeat(unit, n) for name, unit in PATTERNS.items()}
    values["one long token"] = "a" * n
    values["parens open then close"] = "(" * (n // 2) + ")" * (n - n // 2)
    for name, (head, item) in NUMBERED.items():
        values[name] = _numbered(head, item, n)
    return values


_SMALL: Final = _timing_values(8_192)
_LARGE_NAMES: Final = sorted(_SMALL)


@pytest.mark.timeout(2)
@pytest.mark.parametrize("name", _LARGE_NAMES)
def test_linear_time_8k(name: str) -> None:
    result = _redact.redact(_SMALL[name])
    assert result.complete
    assert result.text.isascii()


@pytest.mark.timeout(15)
@pytest.mark.parametrize("name", _LARGE_NAMES)
def test_linear_time_1mib(name: str) -> None:
    result = _redact.redact(_timing_values(MIB)[name])
    assert result.complete
    assert result.text.isascii()


@pytest.mark.timeout(15)
def test_deep_parens_1mib() -> None:
    depth = (MIB - 20) // 2
    value = "qx.test; dkim=pass " + "(" * depth + "x" + ")" * depth
    text = "a.example; dkim=pass " + "(" * depth + "..." + ")" * depth
    check(value, Want(text, (_a(),), free=1))


@pytest.mark.timeout(15)
def test_cli_1mib() -> None:
    data = _repeat("qx.test; dkim=pass header.d=qx.test (c)\r\n ", MIB).encode()
    code, out, _ = run_cli(data)
    assert code == 0
    assert b"qx" not in out
