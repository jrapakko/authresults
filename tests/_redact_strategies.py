# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Shared helpers for the redaction tests (``docs/plans/al3d.md`` section 8).

- ``run_cli`` runs ``authresults.redact.main`` on bytes, in memory.
- ``structure`` and ``outcome`` give the parse outcome that redaction must
  keep (P3, P4): a ptype outside ``KEEP_PTYPES``, and its property name,
  compare as ``"<other>"`` (AU-Q60).
- ``case_sources`` lists every ``parse``/``parse_arc`` string case of the
  case modules, read through each module's ``CASES``.
- ``header_text``, ``secret_values``, ``model_values`` and ``edited`` are the
  Hypothesis strategies of P1 to P5.
- ``oracle_problems`` checks a redacted value from its text alone (P2).

The constants here are copied from the plan, not imported from
``authresults._redact``, so the oracle stays independent of the code under
test; ``tests/test_redact.py`` checks that both agree.
"""

import functools
import io
import ipaddress
import re
import string
from typing import Final, Literal

from hypothesis import strategies as st

from authresults import (
    ArcAuthenticationResults,
    AuthenticationResults,
    AuthResultsError,
    ErrorReason,
    KnownShape,
    Property,
    _redact,
    _registry,
    parse,
    parse_arc,
)
from authresults import redact as redact_cli

from . import (
    cases_grammar,
    cases_helpers,
    cases_limits,
    cases_redteam,
    cases_refused,
    cases_rfc8601,
    cases_rfc8617,
    cases_spike,
    cases_to_value,
    cases_vendor,
)
from ._case import Options
from ._strategies import Slot, cfws, join, layout_of, models, quote, slot_indexes

# --- constants from docs/plans/al3d.md section 3 ------------------------------

KEEP_PTYPES: Final = frozenset({"smtp", "header", "body", "policy", "dns", "arc"})
RESERVED_NAMES: Final = frozenset(
    {
        "example",
        "test",
        "invalid",
        "localhost",
        "example.com",
        "example.net",
        "example.org",
    }
)
DOC_NETWORKS: Final = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
DOC_IPV6: Final = ipaddress.ip_network("2001:db8::/32")
# The parse limit P3 and P4 use, so TOO_LONG never decides an outcome (AU-Q68).
BIG: Final = 2**21
# Case values longer than this are timing cases; P3 and P4 leave them out.
MAX_SOURCE: Final = 16_384
OTHER: Final = "<other>"

Call = Literal["parse", "parse_arc"]
Source = tuple[str, Call, Options]
Parsed = AuthenticationResults | ArcAuthenticationResults

# --- the CLI ------------------------------------------------------------------


def run_cli(data: bytes, *args: str) -> tuple[int, bytes, bytes]:
    """Run ``main`` on *data* with *args*; return (exit code, stdout, stderr)."""
    out = io.BytesIO()
    err = io.BytesIO()
    code = redact_cli.main(list(args), io.BytesIO(data), out, err)
    return code, out.getvalue(), err.getvalue()


def check_spans(value: str, result: _redact.Redaction) -> None:
    """Sorted, in bounds, non-overlapping; text outside them is copied."""
    previous = 0
    for start, end in result.spans:
        assert previous <= start < end <= len(value)
        previous = end
    cursor = 0
    previous = 0
    for start, end in (*result.spans, (len(value), len(value))):
        kept = value[previous:start]
        found = result.text.find(kept, cursor)
        assert found >= cursor
        if previous == 0:
            assert found == 0
        cursor = found + len(kept)
        previous = end
    tail = value[result.spans[-1][1] :] if result.spans else value
    assert result.text.endswith(tail)
    if not result.spans:
        assert result.text == value


# --- parse outcomes -------------------------------------------------------------


# --- AU-Q69: words kept in keyword positions ---------------------------------

SAFE_EXTRAS: Final = frozenset(
    {"rsa-sha1", "rsa-sha256", "ed25519-sha256", "quarantine", "reject"}
    | {"oreject", "yes", "no", "ipv6"}
)
RFC7208_KEYS: Final = frozenset(
    {"client-ip", "envelope-from", "helo", "receiver", "identity", "mechanism"}
    | {"problem"}
)


@functools.cache
def producer_words() -> frozenset[str]:
    """AU-Q69: the method, result and property names of the accepted
    ``cases_vendor`` and ``cases_refused`` models that are not registered,
    plus the RFC 7208 9.1 keys."""
    words: set[str] = set()
    for module in (cases_vendor, cases_refused):
        for case in module.CASES:
            expected = case.expected
            if isinstance(expected, ArcAuthenticationResults):
                expected = expected.payload
            if not isinstance(expected, AuthenticationResults):
                continue
            for result in expected.results:
                words |= {result.method.lower(), result.result.lower()}
                words |= {p.name.lower() for p in result.properties}
    return frozenset(words - _registry.REGISTERED_NAMES) | RFC7208_KEYS


@functools.cache
def kept_words() -> frozenset[str]:
    """``SAFE_WORDS`` and ``PRODUCER_WORDS``, computed from the plan."""
    return _registry.REGISTERED_NAMES | SAFE_EXTRAS | producer_words()


def _word(word: str) -> str:
    """A keyword as P3 compares it: renamed words (AU-Q69) are ``<other>``."""
    return word if word.lower() in kept_words() else OTHER


def _property(prop: Property) -> tuple[object, ...]:
    if prop.ptype is not None and prop.ptype.lower() not in KEEP_PTYPES:
        return (OTHER, OTHER, prop.quoted, prop.registered)
    return (prop.ptype, _word(prop.name), prop.quoted, prop.registered)


def structure(parsed: Parsed) -> tuple[object, ...]:
    """What P3 compares (``docs/plans/al3d.md`` section 8, P3)."""
    instance = None
    payload = parsed
    if isinstance(parsed, ArcAuthenticationResults):
        instance = parsed.instance
        payload = parsed.payload
    assert isinstance(payload, AuthenticationResults)
    return (
        instance,
        payload.authserv_id is None,
        payload.version_given,
        payload.none,
        payload.deviations,
        tuple(
            (
                _word(r.method),
                r.method_version,
                _word(r.result),
                r.registered,
                r.reason is None,
                tuple(_property(p) for p in r.properties),
            )
            for r in payload.results
        ),
    )


def parse_with(value: str, call: Call, kwargs: Options) -> Parsed:
    """Parse with the case's options, but with ``max_length`` raised to BIG."""
    options: Options = {**kwargs}
    options["max_length"] = BIG
    if call == "parse_arc":
        return parse_arc(value, **options)
    return parse(value, **options)


Outcome = (
    tuple[Literal["accepted"], tuple[object, ...]]
    | tuple[Literal["refused"], tuple[ErrorReason, KnownShape | None]]
)


def outcome(value: str, call: Call, kwargs: Options) -> Outcome:
    """The structure of an accepted value, or the reason and shape tag."""
    try:
        parsed = parse_with(value, call, kwargs)
    except AuthResultsError as err:
        return ("refused", (err.reason, err.known_shape))
    return ("accepted", structure(parsed))


def refusal(value: str, call: Call, kwargs: Options) -> AuthResultsError | None:
    try:
        parse_with(value, call, kwargs)
    except AuthResultsError as err:
        return err
    return None


def inside(position: int, spans: tuple[tuple[int, int], ...]) -> bool:
    """AU-Q68: a position is inside replaced text if a span holds it."""
    return any(start <= position < end for start, end in spans)


# --- case-table sources -----------------------------------------------------------

CASE_MODULES: Final = (
    cases_grammar,
    cases_helpers,
    cases_limits,
    cases_redteam,
    cases_refused,
    cases_rfc8601,
    cases_rfc8617,
    cases_spike,
    cases_to_value,
    cases_vendor,
)


@functools.cache
def case_sources() -> tuple[Source, ...]:
    """Every string case for ``parse`` or ``parse_arc``, with its options."""
    sources: list[Source] = []
    for module in CASE_MODULES:
        for case in module.CASES:
            value = case.value
            if not isinstance(value, str) or len(value) > MAX_SOURCE:
                continue
            if case.timeout is not None:
                continue
            if case.call == "parse":
                sources.append((str.__str__(value), "parse", case.kwargs))
            elif case.call == "parse_arc":
                sources.append((str.__str__(value), "parse_arc", case.kwargs))
    return tuple(sources)


# --- P1: any text -------------------------------------------------------------------

_FRAGMENTS: Final = (
    *("i=1;", "i", "=", "1", "01", ";", " ", "\t", "\r\n ", "\r", "\n", "(", ")"),
    *('"', "\\", "@", ".", "/", ":", "<", ">", "[", "]", ",", "?", "none"),
    *("dkim", "spf", "pass", "reason", "header", "smtp", "d", "s", "b", "bh"),
    *("qx.test", "mx.google.com", "example.com", "a.example", "user1", "tok_1"),
    *("10.0.0.1", "192.0.2.1", "fd00::1", "2001:db8::1", "::ffff:10.1.2.3"),
    *("QUJDREVGR0hJSktMTU5PUA1", "b64-1/=", "sel1", "...", "\ufeff", "\u200b"),
    *("\x00", "\x7f", "\x85", "\ud800", "\udcff", "\u212a", "\xe9", "\U0001f600"),
)


@functools.cache
def header_text() -> st.SearchStrategy[str]:
    """Full Unicode text, surrogates included, mixed with header fragments."""
    any_char = st.characters(exclude_categories=())
    piece = st.one_of(st.sampled_from(_FRAGMENTS), st.text(any_char, max_size=4))
    return st.lists(piece, max_size=40).map("".join)


# --- P2: values with planted secrets ----------------------------------------------

# Every planted secret holds "qx" (any case) or is an address outside the
# documentation ranges; the oracle checks the addresses.
_N = st.integers(1, 40)


@functools.cache
def _ipv4() -> st.SearchStrategy[str]:
    octet = st.integers(0, 255)
    return st.one_of(
        st.builds("10.{}.{}.{}".format, octet, octet, octet),
        st.builds("172.{}.{}.{}".format, st.integers(16, 31), octet, octet),
        st.builds("192.168.{}.{}".format, octet, octet),
    )


@functools.cache
def _ipv6() -> st.SearchStrategy[str]:
    group = st.integers(0, 0xFFFF)
    return st.one_of(
        st.builds("fd00::{:x}".format, group),
        st.builds("fd{:02x}:{:x}::{:x}".format, st.integers(0, 255), group, group),
        st.builds("::ffff:10.0.{}.{}".format, st.integers(0, 255), st.integers(0, 255)),
    )


@functools.cache
def _domain() -> st.SearchStrategy[str]:
    return st.one_of(
        st.builds("qx{}.test".format, _N),
        st.builds("mail.qx{}.test".format, _N),
        st.builds("QX{}.Test".format, _N),
        st.just("qx.example.com"),
    )


@functools.cache
def _address() -> st.SearchStrategy[str]:
    local = st.one_of(
        st.builds("qx{}".format, _N),
        st.builds("bob.qx{}".format, _N),
        st.builds("SRS0=hh=tt=qx{}.test=bob".format, _N),
        st.builds(quote, st.builds("qx bob {}".format, _N)),
        st.just(""),
    )
    domain = st.one_of(_domain(), st.builds("qxlabel{}".format, _N))
    plain = st.builds("{}@{}".format, local, domain)
    return st.one_of(plain, plain.map("<{}>".format))


@functools.cache
def _glued_ipv6() -> st.SearchStrategy[str]:
    """IPv6 with a zone ID or other characters glued on (section 16 item 1)."""
    group = st.integers(1, 0xFFFF)
    return st.one_of(
        st.builds("fd00::{:x}%eth0".format, group),
        st.builds("fd12:3456:{:x}::1%25en0".format, group),
        st.builds("2a00:1450::{:x}z".format, group),
        st.builds("fd00::{:x}qx".format, group),
        st.builds("fd00::{:x}zz/qx{:x}@qx.test".format, group, group),
        st.builds(
            "2001:db8::10.0.{}.{}".format, st.integers(0, 255), st.integers(0, 255)
        ),
        st.builds("2001:DB8:{:x}::1.cafe.de".format, group),
        st.builds("2001:db8:{}".format, st.integers(10**9, 10**10)),
        st.builds("2001:db8::{:x}::fd00:{:x}".format, group, group),
        st.builds("2001:db8:{:x}::1".format, st.integers(0x10000, 0xFFFFF)),
    )


@functools.cache
def _pvalue() -> st.SearchStrategy[str]:
    return st.one_of(
        st.builds("qxv{}".format, _N),
        _domain(),
        _address(),
        _ipv4(),
        _ipv4().map("[{}]".format),
        _ipv6(),
        _ipv6().map("[{}]".format),
        _glued_ipv6(),
        st.builds('"qx{}"'.format, _N),
        st.builds("QX{}abcdefghijklmnop+/=".format, _N),
    )


@functools.cache
def _reason() -> st.SearchStrategy[str]:
    """A reason the parser accepts (token or quoted)."""
    return st.one_of(
        st.builds("reason=qxr{}".format, _N),
        st.builds('reason="qx text {}"'.format, _N),
        st.builds("reason=qx{}.test".format, _N),
    )


_KNOWN_NAMES: Final = ("d", "i", "s", "b", "bh", "from", "mailfrom", "helo", "ip")


@functools.cache
def _item() -> st.SearchStrategy[str]:
    """A property the parser accepts, or a comment."""
    known = st.builds(
        "{}.{}={}".format,
        st.sampled_from(sorted(KEEP_PTYPES)),
        st.sampled_from(_KNOWN_NAMES),
        _pvalue(),
    )
    unknown = st.builds("qxp{}.qxq={}".format, _N, _pvalue())
    secret_name = st.builds(
        "{}.qxn{}={}".format, st.sampled_from(sorted(KEEP_PTYPES)), _N, _pvalue()
    )
    bare = st.builds("{}={}".format, st.sampled_from(("action", "qxbare")), _pvalue())
    comment = st.builds("(qx secret {})".format, _N)
    # Section 19: a non-canonical kept doc IPv6 next to a non-doc one.
    small = st.integers(1, 4)
    doc_pair = st.builds(
        "policy.ip={} policy.ip=fd00::{:x}".format,
        st.one_of(
            st.builds("2001:0db8:0:0:0:0:0:{:x}".format, small),
            st.builds("2001:DB8::{:X}".format, small),
            st.builds("2001:db8:0::{:x}".format, small),
        ),
        st.integers(1, 0xFFFF),
    )
    return st.one_of(known, unknown, secret_name, bare, comment, doc_pair)


_SEPARATOR: Final = Slot(" ", required=True)


@st.composite
def _gap(draw: st.DrawFn) -> str:
    if draw(st.booleans()):
        return " "
    return draw(cfws(_SEPARATOR, ascii_only=True)) + " "


@st.composite
def _result(draw: st.DrawFn) -> str:
    """``method[/1]=result [reason=...] properties``, all accepted."""
    methods = ("dkim", "spf", "dmarc", "arc", "iprev", "auth", "qxmethod", "QXM")
    method = draw(st.sampled_from(methods))
    version = draw(st.sampled_from(("", "", "/1")))
    result = draw(st.sampled_from(("pass", "fail", "none", "qxresult", "Qx-R")))
    parts = [f"{method}{version}={result}"]
    if draw(st.booleans()):
        parts += [" ", draw(_reason())]
    for item in draw(st.lists(_item(), max_size=5)):
        parts += [draw(_gap()), item]
    return "".join(parts)


@functools.cache
def _authserv_id() -> st.SearchStrategy[str]:
    return st.one_of(
        _domain(),
        st.builds("qxhost{}".format, _N),
        st.builds('"qx{}.test"'.format, _N),
        st.builds('"qx host {}"'.format, _N),
    )


# Refused shapes, appended or inserted in a minority of values so P4 still
# meets refusals: a job ID, a non-digit method version, junk after ";", a
# bare word among properties, junk glued to a result, a reason with "@".
_BREAKS: Final = ("job", "version", "stray", "word", "glued", "reason")


@st.composite
def _break(draw: st.DrawFn) -> tuple[str, str]:
    """(kind, text) of one refused shape."""
    kind = draw(st.sampled_from(_BREAKS))
    n = draw(_N)
    text = {
        "job": f"/QX{n}A",
        "version": f"; dkim/qx{n}=pass",
        "stray": f"; qxj{n}",
        "word": f" qxj{n}",
        "glued": f"@qx{n}.test",
        "reason": f" reason=qx{n}@qx.test",
    }[kind]
    return kind, text


@st.composite
def secret_values(draw: st.DrawFn) -> str:
    """A header value with secrets in every slot (P2), built inside a valid
    skeleton so most values parse (section 16 item 2); about one in five
    carries one refused shape."""
    # The simplest draws give a valid value with an authserv-id.
    missing_id = draw(st.integers(0, 5)) == 5  # noqa: PLR2004
    head = "" if missing_id else draw(st.sampled_from(("", "", "i=1; ")))
    authserv_id = "" if missing_id else draw(_authserv_id())
    version = "" if missing_id else draw(st.sampled_from(("", "", " 1")))
    results = draw(st.lists(_result(), min_size=1, max_size=3))
    body = results[0]
    for result in results[1:]:
        body += ";" + draw(_gap()) + result
    broken = draw(st.integers(0, 4)) == 4  # noqa: PLR2004
    kind, text = draw(_break()) if broken else ("", "")
    if kind == "job" and not missing_id:
        authserv_id += text
    elif kind in {"version", "stray", "word", "glued", "reason"}:
        body += text
    prefix = "" if missing_id else authserv_id + version + ";" + draw(_gap())
    return head + prefix + body


# --- P3: generated models ---------------------------------------------------------


@st.composite
def model_values(draw: st.DrawFn) -> Source:
    """A model written with a layout, comments and folds at random CFWS spots."""
    ascii_only = draw(st.booleans())
    missing_id = draw(st.booleans())
    model = draw(models(ascii_only=ascii_only, missing_id=missing_id))
    arc = None if missing_id else draw(st.one_of(st.none(), st.integers(1, 50)))
    layout = layout_of(
        model, pair_every=draw(st.sampled_from((0, 1, 3))), arc_instance=arc
    )
    fills = {}
    for index in draw(st.lists(st.sampled_from(slot_indexes(layout)), max_size=4)):
        slot = layout[index]
        assert isinstance(slot, Slot)
        fills[index] = draw(cfws(slot, ascii_only=ascii_only))
    kwargs: Options = {} if ascii_only else {"ascii_only": False}
    call: Call = "parse" if arc is None else "parse_arc"
    return join(layout, fills), call, kwargs


# --- P4: random edits ---------------------------------------------------------------

_EDIT_CHARS: Final = ' \t\r\n();"' + "()<>@,;:\\/[]?=" + "."


@st.composite
def edited(draw: st.DrawFn, value: str) -> str:
    """*value* with a few inserts, deletes or replacements of delimiter and
    tspecial characters."""
    text = list(value)
    for _ in range(draw(st.integers(1, 3))):
        kind = draw(st.sampled_from(("insert", "delete", "replace")))
        if kind == "insert" or not text:
            text.insert(
                draw(st.integers(0, len(text))), draw(st.sampled_from(_EDIT_CHARS))
            )
            continue
        index = draw(st.integers(0, len(text) - 1))
        if kind == "delete":
            del text[index]
        else:
            text[index] = draw(st.sampled_from(_EDIT_CHARS))
    return "".join(text)


# --- the P2 output oracle -----------------------------------------------------------

_QUAD: Final = re.compile(r"(?<![0-9A-Za-z.])\d+(?:\.\d+){3}(?![0-9A-Za-z.])")
_HEXRUN: Final = re.compile(r"[0-9A-Fa-f:.]+")
_IPV6_COLONS: Final = 2
_DOTTED: Final = re.compile(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+")
_PLACEHOLDER_DOMAIN: Final = re.compile(r"[a-z]{1,4}\.example")
# Section 17 item 11: trailing dots of a local-part are copied.
_USER: Final = re.compile(r"user[1-9][0-9]{0,5}\.*")
_KEYWORD: Final = re.compile(r"[A-Za-z0-9-]*[A-Za-z0-9]")
_LOCAL_STOP: Final = frozenset(' \t\r\n();"@<>[]:,\\=/?')
# Section 16 item 7(ii): before "@", a doc IPv6 piece with an optional glued
# placeholder tail is allowed too (R9 step 1 runs before the local-part check).
_DOC_IPV6_LOCAL: Final = re.compile(
    r"(?i:2001:0?db8:)[0-9A-Fa-f:.]*"
    r"(?:(?:user|tok|num|sel|job|ptype|prop)[1-9][0-9]{0,5}|tok_[1-9][0-9]{0,5})?"
)
_COMMENT_TEXT: Final = frozenset(". \t\r\n()\\")


def _quoted_and_comment_mask(text: str) -> tuple[list[bool], list[bool]]:
    """Per character: inside a quoted string, inside a comment."""
    quoted = [False] * len(text)
    comment = [False] * len(text)
    depth = 0
    in_quote = False
    escaped = False
    for i, c in enumerate(text):
        quoted[i] = in_quote
        comment[i] = depth > 0
        if escaped:
            escaped = False
        elif c == "\\" and (in_quote or depth):
            escaped = True
        elif in_quote:
            in_quote = c != '"'
        elif c == '"' and not depth:
            in_quote = True
        elif c == "(":
            depth += 1
            comment[i] = True
        elif c == ")" and depth:
            depth -= 1
    return quoted, comment


def _next_is_equals(text: str, end: int) -> bool:
    """True if the next character after *end*, skipping WSP, line breaks
    and comments, is ``=``."""
    depth = 0
    i = end
    while i < len(text):
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")" and depth:
            depth -= 1
        elif depth == 0 and c not in " \t\r\n":
            return c == "="
        i += 1
    return False


_MAX_GROUPS: Final = 8
_MAX_GROUP_DIGITS: Final = 4


def well_formed_ipv6(run: str) -> bool:
    """Section 18.2: no ".", groups of 1 to 4 hex digits, at most one "::",
    and 8 groups (fewer only with "::")."""
    if "." in run or run.count("::") > 1:
        return False
    head, double, tail = run.partition("::")
    groups = [g for part in (head, tail) if part for g in part.split(":")]
    if not all(
        0 < len(g) <= _MAX_GROUP_DIGITS and all(c in string.hexdigits for c in g)
        for g in groups
    ):
        return False
    if double:
        return len(groups) < _MAX_GROUPS
    return len(groups) == _MAX_GROUPS


def ipv6_value(run: str) -> tuple[int, ...]:
    """Section 19: the 8 16-bit numbers of a well-formed IPv6 run."""
    head, double, tail = run.partition("::")
    left = [int(g, 16) for g in head.split(":") if g]
    right = [int(g, 16) for g in tail.split(":") if g] if double else []
    middle = [0] * (_MAX_GROUPS - len(left) - len(right))
    return (*left, *middle, *right)


def doc_ipv6_runs(text: str) -> list[str]:
    """Well-formed doc-prefixed IPv6 runs in *text*, as written."""
    runs = []
    for match in _HEXRUN.finditer(text):
        run = match.group()
        if match.start() > 0 and text[match.start() - 1].isalnum():
            run = run.partition(":")[2]
        if run.lower().startswith(("2001:db8:", "2001:0db8:")) and well_formed_ipv6(
            run
        ):
            runs.append(run)
    return runs


def _ipv6_problems(text: str) -> list[str]:
    problems = []
    for match in _HEXRUN.finditer(text):
        run = match.group()
        if match.start() > 0 and text[match.start() - 1].isalnum():
            # The run starts inside a word (as in IPv6:...): skip that word.
            run = run.partition(":")[2]
        doc = run.lower().startswith(("2001:db8:", "2001:0db8:"))
        if run.count(":") >= _IPV6_COLONS and not doc:
            problems.append(f"IPv6 run outside 2001:db8::/32 at {match.start()}")
        elif doc and not well_formed_ipv6(run):
            # Sections 17.4 and 18.2: a doc-prefixed run is kept only when
            # it is a well-formed address.
            problems.append(f"malformed doc IPv6 run at {match.start()}")
    return problems


def _dotted_ok(name: str, text: str, end: int, keep_hosts: frozenset[str]) -> bool:
    lower = name.lower()
    if lower in RESERVED_NAMES or lower in keep_hosts:
        return True
    if _PLACEHOLDER_DOMAIN.fullmatch(lower):
        return True
    if all(part.isdigit() for part in name.split(".")):
        return True  # dotted quads are checked on their own
    head, _, tail = name.partition(".")
    return (
        "." not in tail
        and _KEYWORD.fullmatch(head) is not None
        and _KEYWORD.fullmatch(tail) is not None
        and _next_is_equals(text, end)
    )


def _doc_ipv6_local(text: str, at: int) -> bool:
    """True if the text right before the ``@`` at *at* is a doc IPv6 piece,
    with an optional glued placeholder tail."""
    start = at
    while start > 0 and (text[start - 1] == ":" or text[start - 1] not in _LOCAL_STOP):
        start -= 1
    return _DOC_IPV6_LOCAL.fullmatch(text, start, at) is not None


def _character_problems(
    text: str, quoted: list[bool], comment: list[bool]
) -> list[str]:
    """Comment interiors and unquoted local-parts."""
    problems = []
    for i, c in enumerate(text):
        if comment[i] and c not in _COMMENT_TEXT:
            problems.append(f"comment text at {i}")
        if c == "@" and not quoted[i] and not comment[i]:
            start = i
            while start > 0 and text[start - 1] not in _LOCAL_STOP:
                start -= 1
            local = text[start:i]
            if local and not _USER.fullmatch(local) and not _doc_ipv6_local(text, i):
                problems.append(f"local-part at {start}")
    return problems


def oracle_problems(text: str, keep_hosts: frozenset[str]) -> list[str]:
    """Check a redacted value from its text alone (P2)."""
    problems: list[str] = []
    quoted, comment = _quoted_and_comment_mask(text)
    for match in _QUAD.finditer(text):
        address = (
            ipaddress.ip_address(match.group()) if _is_ipv4(match.group()) else None
        )
        if address is None or not any(address in n for n in DOC_NETWORKS):
            problems.append(f"dotted quad outside the doc ranges at {match.start()}")
    problems += _ipv6_problems(text)
    problems += _character_problems(text, quoted, comment)
    for match in _DOTTED.finditer(text):
        if comment[match.start()]:
            continue
        if not _dotted_ok(match.group(), text, match.end(), keep_hosts):
            problems.append(f"dotted name at {match.start()}")
    return problems


def _is_ipv4(text: str) -> bool:
    parts = text.split(".")
    return all(p.isdigit() and len(p) <= 3 and int(p) <= 255 for p in parts)  # noqa: PLR2004
