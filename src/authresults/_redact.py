# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""The redaction scanner behind ``python -m authresults.redact`` (AL3d).

Not public API: not in ``__all__``, may change without notice. The rules R1
to R14 of ``docs/plans/al3d.md`` section 4 are the spec; the comments below
cite them.

Three passes, all linear and without recursion (R14):

- pass 0 maps every top-level comment and quoted-string to its end (R2);
- pass 1 is a state machine with one function per state (R4 to R8), which
  copies delimiters and kept text, rewrites values (R9, R10) and records a
  slot for every value to number;
- pass 2 numbers the slots in first-appearance order, skipping placeholders
  already in the input (R11), and joins the output.

The output is printable ASCII plus HTAB, CR and LF by construction (R12).
"""

import enum
from collections.abc import Callable
from dataclasses import dataclass, field

from ._checks import ascii_lower, exact_text
from ._errors import call_guarded
from ._lexical import DIGITS, KEYWORD, TOKEN, is_keyword
from ._registry import REGISTERED_NAMES
from ._tokenizer import control

# Vendor service hostnames, kept as written (equal to the test list, AU-Q66).
KEEP_HOSTNAMES = frozenset(
    {
        "mx.google.com",
        "google.com",
        "atlas321.free.mail.ne1.yahoo.com",
        "atlas206.aol.mail.ne1.yahoo.com",
        "bimi.icloud.com",
        "dkim-verifier.icloud.com",
        "mx2.messagingengine.com",
        "mx.zohomail360.com",
        "mx.zohomail.eu",
        "zohomail.eu",
        "mx.zoho.com",
        "zoho.com",
        "ppops.net",
        "mimecast.com",
    }
)
# RFC 2606 and RFC 6761 names, kept only when exact (AU-Q61).
RESERVED_NAMES = frozenset(
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
# Property types kept with their property names; "arc" for Exim (AU-Q60).
KEEP_PTYPES = frozenset({"smtp", "header", "body", "policy", "dns", "arc"})
# Producer words kept in values (AU-Q65).
SAFE_WORDS = REGISTERED_NAMES | frozenset(
    {
        "rsa-sha1",
        "rsa-sha256",
        "ed25519-sha256",
        "quarantine",
        "reject",
        "oreject",
        "yes",
        "no",
        "ipv6",
    }
)
# Unregistered method, result and property names of the vendor and refused
# cases, plus the RFC 7208 9.1 keys, kept in keyword positions (AU-Q69).
PRODUCER_WORDS = frozenset(
    {
        "action",
        "bimi",
        "compauth",
        "mail",
        "skipped",
        "tempfail",
        "client-ip",
        "envelope-from",
        "helo",
        "receiver",
        "identity",
        "mechanism",
        "problem",
    }
)
SELECTOR_PROPERTIES = frozenset({"s"})
BASE64_PROPERTIES = frozenset({"b", "bh"})
MAX_NUMBER = 999_999


class Kind(enum.StrEnum):
    """What a placeholder stands for."""

    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    LOCAL_PART = "local-part"
    SELECTOR = "selector"
    BASE64 = "base64"
    JOB_ID = "job-id"
    NUMBER = "number"
    WORD = "word"
    PTYPE = "ptype"
    PROPERTY = "property"


@dataclass(frozen=True, slots=True)
class Replacement:
    """One placeholder, the kind of value it replaced and how often."""

    placeholder: str
    kind: Kind
    count: int


@dataclass(frozen=True, slots=True)
class Redaction:
    """The redacted value and what was replaced.

    ``originals`` holds, aligned with ``replacements``, the distinct original
    spellings in first-appearance order; it is left out of ``repr`` so the
    repr never holds input text.
    """

    text: str
    complete: bool
    replacements: tuple[Replacement, ...]
    free_text: int
    non_ascii: int
    controls: int
    arc: bool
    spans: tuple[tuple[int, int], ...]
    originals: tuple[tuple[str, ...], ...] = field(repr=False)


# --- placeholders (R11) -----------------------------------------------------

_ALPHABET = "abcdefghijklmnopqrstuvwxyz"
_DOMAIN_LABELS = 475_253  # 1 to 4 letters, "none" skipped
_NONE_LABEL = 256_573  # the number "none" would have had
_IPV4_NETWORKS = ("192.0.2.", "198.51.100.", "203.0.113.")
_IPV4_HOSTS = 254
_IPV4_MAX = _IPV4_HOSTS * len(_IPV4_NETWORKS)
_IPV6_MAX = 2**32 - 1
_IPV6_GROUP = 0xFFFF
_IPV6_SHIFT = 16


def _check_cap(n: int, cap: int) -> None:
    if not 1 <= n <= cap:
        msg = "placeholder number out of range"
        raise ValueError(msg)


def domain_label(n: int) -> str:
    """Return label *n* in bijective base 26 (1 is ``a``, 27 is ``aa``).

    ``none`` is skipped; raises ``ValueError`` above 475,253.
    """
    _check_cap(n, _DOMAIN_LABELS)
    index = (n + 1 if n >= _NONE_LABEL else n) - 1
    length = 1
    size = len(_ALPHABET)
    while index >= size:
        index -= size
        length += 1
        size *= len(_ALPHABET)
    letters: list[str] = []
    for _ in range(length):
        index, letter = divmod(index, len(_ALPHABET))
        letters.append(_ALPHABET[letter])
    return "".join(reversed(letters))


def ipv4_placeholder(n: int) -> str:
    """Return host *n* of the three RFC 5737 networks; raises above 762."""
    _check_cap(n, _IPV4_MAX)
    network, host = divmod(n - 1, _IPV4_HOSTS)
    return f"{_IPV4_NETWORKS[network]}{host + 1}"


def ipv6_placeholder(n: int) -> str:
    """Return address *n* in 2001:db8::/32 (RFC 3849); raises above 2**32 - 1."""
    _check_cap(n, _IPV6_MAX)
    if n <= _IPV6_GROUP:
        return f"2001:db8::{n:x}"
    return f"2001:db8::{n >> _IPV6_SHIFT:x}:{n & _IPV6_GROUP:x}"


def _numbered(prefix: str, n: int) -> str:
    if prefix == "domain":
        return f"{domain_label(n)}.example"
    if prefix == "ipv4":
        return ipv4_placeholder(n)
    if prefix == "ipv6":
        return ipv6_placeholder(n)
    _check_cap(n, MAX_NUMBER)
    return f"{prefix}{n}"


_CAPS = {"domain": _DOMAIN_LABELS, "ipv4": _IPV4_MAX, "ipv6": _IPV6_MAX}

# (kind, placeholder prefix) of each family of values.
_Family = tuple[Kind, str]
_DOMAIN: _Family = (Kind.DOMAIN, "domain")
_IPV4: _Family = (Kind.IPV4, "ipv4")
_IPV6: _Family = (Kind.IPV6, "ipv6")
_USER: _Family = (Kind.LOCAL_PART, "user")
_SELECTOR: _Family = (Kind.SELECTOR, "sel")
_BASE64: _Family = (Kind.BASE64, "b64-")
_JOB: _Family = (Kind.JOB_ID, "job")
_NUMBER: _Family = (Kind.NUMBER, "num")
_TOKEN_WORD: _Family = (Kind.WORD, "tok")
_OTHER_WORD: _Family = (Kind.WORD, "tok_")
_PTYPE: _Family = (Kind.PTYPE, "ptype")
_PROPERTY: _Family = (Kind.PROPERTY, "prop")

# --- character classes ------------------------------------------------------

_DELIMITERS = frozenset(' \t\r\n();"')  # R1, the parser's RUN_STOP
_RUN_ENDS = _DELIMITERS | {""}
_FOLD = frozenset(" \t\r\n")
_WSP = frozenset(" \t")
_LINE = frozenset("\r\n")
_PARENS = frozenset("()")
_SEPARATORS = frozenset("@<>[]:,\\")  # R9, copied
_SPLIT = frozenset("/=?")  # R9, copied
_PIECE_ENDS = _SEPARATORS | _SPLIT
_TSPECIALS = frozenset('()<>@,;:\\"/[]?=')  # RFC 2045
_HEX = frozenset("0123456789abcdefABCDEF")
_HEX_RUN = _HEX | {":", "."}
_BASE64_CHARS = frozenset(_ALPHABET + _ALPHABET.upper() + "0123456789+/=_-")
_BASE64_HINTS = DIGITS | {"+", "/"}
_NOT_IN_CLEAN_QUOTE = frozenset(' \t\r\n\\"')
_METHOD_FOLLOW = frozenset("=/")
_NONE_FOLLOW = frozenset({";", ""})
_VERSION_ENDS = _RUN_ENDS | {"="}
_NONZERO = frozenset("123456789")
_FREE = "..."
_SHORT_NUMBER = 4
_ARC_DIGITS = 4  # 17.3
_LONG_BASE64 = 16
_IPV6_COLONS = 2
_IPV6_HALVES = 2
_IPV6_GROUPS = 8
_IPV6_GROUP_DIGITS = 4
_IPV4_DOTS = 3
_OCTET_DIGITS = 3
_OCTET_MAX = 255
_COUNTER_DIGITS = 6
_PLACEHOLDER_PREFIXES = ("user", "tok_", "tok", "num", "sel", "job", "ptype", "prop")
_DOC_IPV6 = ("2001:db8:", "2001:0db8:")
_EXAMPLE = ".example"
_EXAMPLE_LABEL = 4


# --- kept forms (R10) -------------------------------------------------------


def _counter(word: str, start: int) -> bool:
    """``word[start:]`` is ``[1-9][0-9]{0,5}``."""
    digits = len(word) - start
    return (
        1 <= digits <= _COUNTER_DIGITS
        and word[start] in _NONZERO
        and all(word[k] in DIGITS for k in range(start, len(word)))
    )


def _is_user(word: str) -> bool:
    return word.startswith("user") and _counter(word, len("user"))


def _placeholder_key(word: str) -> str | None:
    """Return the ``taken`` entry of a placeholder-shaped *word*, or None."""
    core = word.removesuffix("=").removesuffix("/")
    if core.startswith("b64-") and _counter(core, len("b64-")):
        return core
    for prefix in _PLACEHOLDER_PREFIXES:
        if word.startswith(prefix) and _counter(word, len(prefix)):
            return word
    return None


def _kept_name(lower: str) -> bool:
    if lower in RESERVED_NAMES or lower in KEEP_HOSTNAMES:
        return True
    head = lower.removesuffix(_EXAMPLE)
    return (
        head != lower
        and 1 <= len(head) <= _EXAMPLE_LABEL
        and all(c in _ALPHABET for c in head)
    )


def _ipv4_key(piece: str) -> str | None:
    """Four decimal groups 0 to 255, in canonical form, else ``None``."""
    if piece.count(".") != _IPV4_DOTS:
        return None
    groups: list[str] = []
    for group in piece.split("."):
        if not group or not all(c in DIGITS for c in group):
            return None
        canonical = group.lstrip("0") or "0"
        if len(canonical) > _OCTET_DIGITS or int(canonical) > _OCTET_MAX:
            return None
        groups.append(canonical)
    return ".".join(groups)


def _kept_form(piece: str) -> str | None:
    """Return the ``taken`` entry of a kept form (R10), or None."""
    lower = ascii_lower(piece)
    if _kept_name(lower):
        return lower
    key = _placeholder_key(piece)
    if key is not None:
        return key
    if piece and not piece.strip("."):
        return piece  # only dots, free text "..." included
    quad = _ipv4_key(piece)
    if quad is not None and quad.startswith(_IPV4_NETWORKS):
        return quad
    return None


def _short_number(word: str) -> bool:
    return 1 <= len(word) <= _SHORT_NUMBER and all(c in DIGITS for c in word)


# --- the scan state ---------------------------------------------------------


class _State(enum.Enum):
    START = "start"
    AFTER_ID = "after-id"
    METHOD = "method"
    VERSION = "version"
    RESULT = "result"
    ITEMS = "items"
    REASON = "reason"
    PVALUE = "pvalue"


@dataclass(slots=True)
class _Slot:
    """One distinct value to number: its family, count and spellings."""

    kind: Kind
    prefix: str
    suffix: str
    count: int
    spellings: dict[str, None]


@dataclass(slots=True)
class _Scan:
    """The input, its regions, and the output being built."""

    text: str
    size: int
    ends: dict[int, int]  # region start -> end (R2)
    open_region: int  # start of the unterminated region, or -1
    parts: list[str | int]  # output text, or an index into slots
    spans: list[tuple[int, int]]
    slots: list[_Slot]
    keys: dict[tuple[str, str], int]  # (prefix, normalised original) -> slot
    taken: set[str]  # kept forms seen anywhere (R10, R11)
    context: str  # the property name a pvalue belongs to
    free_text: int
    arc: bool
    started: bool  # the ARC prefix check ran
    no_ipv6_before: int  # hex runs before this offset are not IPv6
    reserved_ipv6: set[tuple[int, ...]]  # kept doc IPv6, by value (section 19)


# --- pass 0: regions (R2) ---------------------------------------------------


def _comment_close(text: str, start: int) -> int:
    """Return the offset after the comment opened at *start*, or -1."""
    depth = 0
    i = start
    size = len(text)
    while i < size:
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        elif c == "\\":
            i += 1
        i += 1
    return -1


def _quote_close(text: str, start: int) -> int:
    """Return the offset after the quoted-string opened at *start*, or -1."""
    i = start + 1
    quote = text.find('"', i)
    while quote >= 0:
        backslash = text.find("\\", i, quote)
        if backslash < 0:
            return quote + 1
        i = backslash + 2
        if quote < i:
            quote = text.find('"', i)
    return -1


def _regions(text: str) -> tuple[dict[int, int], int]:
    """Map each top-level comment and quoted-string to its end.

    Like ``_tokenizer.delimit`` but never raising and with no depth limit; an
    unterminated region ends at ``len(text)`` and is returned as the second
    item (-1 if there is none).
    """
    ends: dict[int, int] = {}
    open_region = -1
    size = len(text)
    paren = text.find("(")
    quote = text.find('"')
    while paren >= 0 or quote >= 0:
        start = paren if quote < 0 or 0 <= paren < quote else quote
        end = (
            _comment_close(text, start) if start == paren else _quote_close(text, start)
        )
        if end < 0:
            open_region = start
            end = size
        ends[start] = end
        if 0 <= paren < end:
            paren = text.find("(", end)
        if 0 <= quote < end:
            quote = text.find('"', end)
    return ends, open_region


# --- small readers ----------------------------------------------------------


def _char(scan: _Scan, i: int) -> str:
    return scan.text[i] if i < scan.size else ""


def _skip_cfws(scan: _Scan, i: int) -> int:
    """Skip WSP, line breaks and comments (lookahead, R4)."""
    text = scan.text
    while i < scan.size:
        c = text[i]
        if c in _FOLD:
            i += 1
        elif c == "(":
            i = scan.ends[i]
        else:
            break
    return i


def _end_of(scan: _Scan, i: int, chars: frozenset[str]) -> int:
    """Return the first offset from *i* whose character is not in *chars*."""
    text = scan.text
    while i < scan.size and text[i] in chars:
        i += 1
    return i


def _run_end(scan: _Scan, i: int) -> int:
    """Return the end of the run at *i*: the next delimiter (R1)."""
    text = scan.text
    while i < scan.size and text[i] not in _DELIMITERS:
        i += 1
    return i


# --- output -----------------------------------------------------------------


def _slot(scan: _Scan, family: _Family, key: str, start: int, end: int) -> None:
    """Emit a placeholder for ``text[start:end]``, keyed by *key* (R11)."""
    kind, prefix = family
    original = scan.text[start:end]
    index = scan.keys.get((prefix, key))
    if index is None:
        index = len(scan.slots)
        scan.keys[prefix, key] = index
        suffix = ""
        if kind is Kind.BASE64:
            suffix = ("/" if "/" in original else "") + ("=" if "=" in original else "")
        scan.slots.append(_Slot(kind, prefix, suffix, 0, {}))
    slot = scan.slots[index]
    slot.count += 1
    slot.spellings[original] = None
    scan.parts.append(index)
    scan.spans.append((start, end))


def _emit_cfws(scan: _Scan, start: int, end: int) -> None:
    """Copy CFWS found by ``_skip_cfws``, comments rewritten (R3)."""
    text = scan.text
    while start < end:
        if text[start] == "(":
            start = _free_region(scan, start)
        else:
            stop = start
            while stop < end and text[stop] in _FOLD:
                stop += 1
            scan.parts.append(text[start:stop])
            start = stop


def _free_run(scan: _Scan, start: int, end: int) -> None:
    """One text run of a region: WSP, then ``...`` for the core, then WSP."""
    if start >= end:
        return
    text = scan.text
    lead = _end_of(scan, start, _WSP)
    trail = end
    while trail > lead and text[trail - 1] in _WSP:
        trail -= 1
    core = trail - lead
    if core == 0 or (core == len(_FREE) and text.startswith(_FREE, lead)):
        scan.parts.append(text[start:end])
        return
    scan.parts.extend((text[start:lead], _FREE, text[trail:end]))
    scan.free_text += 1
    scan.spans.append((lead, trail))


def _free_region(scan: _Scan, start: int) -> int:
    """Rewrite the comment or quoted-string at *start* as free text (R3).

    Unescaped parens (comments only), CR, LF and the quotes are kept, as is a
    backslash before CR or LF; every text run between them is ``_free_run``.
    """
    text = scan.text
    end = scan.ends[start]
    closed = start != scan.open_region
    stop = end - 1 if closed else end
    comment = text[start] == "("
    scan.parts.append(text[start])
    run = i = start + 1
    while i < stop:
        c = text[i]
        if c == "\\" and i + 1 < stop and text[i + 1] in _LINE:
            _free_run(scan, run, i)
            scan.parts.append(c)
            run = i = i + 1
        elif c == "\\":
            i += 2
        elif c in _LINE or (comment and c in _PARENS):
            _free_run(scan, run, i)
            scan.parts.append(c)
            run = i = i + 1
        else:
            i += 1
    _free_run(scan, run, stop)
    if closed:
        scan.parts.append(text[stop])
    return end


# --- R9: value rewrite ------------------------------------------------------


def _keep_run(scan: _Scan, run: str) -> bool:
    """Step 0 of R9: a kept form, a safe word or 1 to 4 digits."""
    key = _kept_form(run)
    if key is not None:
        scan.taken.add(key)
        return True
    return ascii_lower(run) in SAFE_WORDS or _short_number(run)


def _whole_run_family(run: str, context: str) -> _Family | None:
    """Step 0 of R9: a selector or a base64 value as a whole."""
    if context in SELECTOR_PROPERTIES:
        return None if any(c in _TSPECIALS for c in run) else _SELECTOR
    base64 = all(c in _BASE64_CHARS for c in run)
    if context in BASE64_PROPERTIES:
        return _BASE64 if base64 else None
    long = len(run) >= _LONG_BASE64 and any(c in _BASE64_HINTS for c in run)
    return _BASE64 if base64 and long else None


def _all_pieces_kept(run: str) -> bool:
    """Return True for a base64-shaped run of kept pieces (``tok_1=tok2``).

    It is what R9 writes for a run with other characters, so keeping it
    keeps the rewrite idempotent (R13).
    """
    pieces = run.replace("/", "=").split("=")
    return all(
        not piece or _kept_form(piece) is not None or _family_of(piece) is None
        for piece in pieces
    )


def _rewrite(scan: _Scan, start: int, end: int, context: str) -> None:
    """Rewrite the value ``text[start:end]`` (R9) in *context*."""
    if start >= end:
        return
    run = scan.text[start:end]
    if _keep_run(scan, run):
        scan.parts.append(run)
        return
    family = _whole_run_family(run, context)
    if family is None or _all_pieces_kept(run):
        _pieces(scan, start, end)
    else:
        _slot(scan, family, run, start, end)


def _rewrite_run(scan: _Scan, start: int, context: str) -> int:
    end = _run_end(scan, start)
    _rewrite(scan, start, end, context)
    return end


def _pieces(scan: _Scan, start: int, end: int) -> None:
    """R9 steps 1 to 3 over ``text[start:end]``."""
    text = scan.text
    i = start
    while i < end:
        if text[i] in _SEPARATORS:
            # A "::" starts a piece only where a piece may start.
            starts = i == start or text[i - 1] in _PIECE_ENDS
            found = _ipv6_piece(scan, i, end) if starts else -1
            if found < 0:
                scan.parts.append(text[i])
                found = i + 1
            i = found
        else:
            i = _span(scan, i, end)


def _well_formed_ipv6(lower: str) -> bool:
    """Return True for a well-formed IPv6 address in hex groups (18.2).

    No ``.``, groups of 1 to 4 hex digits, at most one ``::``, and 8 groups
    (fewer only with ``::``).
    """
    halves = lower.split("::")
    if "." in lower or len(halves) > _IPV6_HALVES:
        return False
    groups = 0
    for half in halves:
        if not half:
            continue
        for group in half.split(":"):
            if not 1 <= len(group) <= _IPV6_GROUP_DIGITS or not all(
                c in _HEX for c in group
            ):
                return False
            groups += 1
    return (
        groups <= _IPV6_GROUPS - 1
        if len(halves) == _IPV6_HALVES
        else groups == _IPV6_GROUPS
    )


def _ipv6_value(lower: str) -> tuple[int, ...]:
    """Expand a run accepted by ``_well_formed_ipv6`` to its 8 numbers (sec. 19)."""
    halves = [
        [int(g, 16) for g in half.split(":")] if half else []
        for half in lower.split("::")
    ]
    head = halves[0]
    tail = halves[1] if len(halves) == _IPV6_HALVES else []
    return (*head, *([0] * (_IPV6_GROUPS - len(head) - len(tail))), *tail)


def _ipv6_piece(scan: _Scan, start: int, end: int) -> int:
    """R9 step 1: emit an IPv6 piece at *start* and return its end, or -1.

    The maximal run over hex digits, ``:`` and ``.`` from a hex digit or a
    ``::``, with 2 or more ``:``, wherever it ends; the characters after it,
    up to the next separator or split character, are a piece of their own
    (section 16 item 1). A failed run (fewer than 2 ``:``) fails from every
    later start inside it too, hence the memo.
    """
    text = scan.text
    if start < scan.no_ipv6_before:
        return -1
    if text[start] not in _HEX and not (
        text.startswith("::", start) and start + 1 < end
    ):
        return -1
    stop = start
    colons = 0
    while stop < end and text[stop] in _HEX_RUN:
        colons += text[stop] == ":"
        stop += 1
    if colons < _IPV6_COLONS:
        scan.no_ipv6_before = stop
        return -1
    lower = ascii_lower(text[start:stop])
    if lower.startswith(_DOC_IPV6) and _well_formed_ipv6(lower):  # 18.2
        scan.parts.append(text[start:stop])
        scan.taken.add(lower)
        scan.reserved_ipv6.add(_ipv6_value(lower))  # section 19
    else:
        _slot(scan, _IPV6, lower, start, stop)
    tail = stop
    while tail < end and text[tail] not in _PIECE_ENDS:
        tail += 1
    if tail > stop:
        _piece(scan, stop, tail, glued=True)
    if tail < end and text[tail] in _SPLIT:  # 17.5: the next span starts after
        scan.parts.append(text[tail])
        tail += 1
    return tail


def _local_part(scan: _Scan, start: int, stop: int) -> None:
    """Emit an unquoted local-part ``[start, stop)``, trailing dots copied.

    As for pieces (gap-fill a): ``a.@`` is refused at the ``@``, outside the
    replaced text, so ``user1.@`` keeps that refusal.
    """
    text = scan.text
    core = stop
    while core > start and text[core - 1] == ".":
        core -= 1
    word = text[start:core]
    if _is_user(word):
        scan.parts.append(word)
        scan.taken.add(word)
    elif word:
        _slot(scan, _USER, word, start, core)
    else:
        # Only dots (18.1): userN, then the dots, which keep the refusal.
        _slot(scan, _USER, text[start:stop], start, stop)
    if core < stop:
        scan.parts.append(text[core:stop])


def _span(scan: _Scan, start: int, end: int) -> int:
    """R9 step 2: a span of non-separators starting at *start*."""
    found = _ipv6_piece(scan, start, end)
    if found >= 0:
        return found
    text = scan.text
    stop = start
    while stop < end and text[stop] not in _SEPARATORS:
        stop += 1
    if stop < end and text[stop] == "@":
        _local_part(scan, start, stop)
        return stop
    return _split(scan, start, stop, end)


def _split(scan: _Scan, start: int, stop: int, end: int) -> int:
    """R9 step 3: split the span ``[start, stop)`` at ``/ = ?``."""
    text = scan.text
    i = start
    while i < stop:
        if text[i] in _SPLIT:
            scan.parts.append(text[i])
            i += 1
            found = _ipv6_piece(scan, i, end) if i < stop else -1
            if found >= 0:
                return found  # a new span starts there (17.5)
            continue
        piece_end = i
        while piece_end < stop and text[piece_end] not in _SPLIT:
            piece_end += 1
        _piece(scan, i, piece_end)
        i = piece_end
    return stop


def _family_of(piece: str) -> tuple[_Family, str] | None:
    """R9 step 3: the family and key of a piece that is not kept, else None."""
    quad = _ipv4_key(piece)
    if quad is not None:
        return _IPV4, quad
    if "." in piece:
        return _DOMAIN, ascii_lower(piece)
    if all(c in DIGITS for c in piece):
        return None if len(piece) <= _SHORT_NUMBER else (_NUMBER, piece)
    if ascii_lower(piece) in SAFE_WORDS:
        return None
    family = _TOKEN_WORD if is_keyword(piece) else _OTHER_WORD
    return family, ascii_lower(piece)  # 17.6: word keys ignore case


def _piece(scan: _Scan, start: int, end: int, *, glued: bool = False) -> None:
    """Emit one piece; trailing dots are copied, not replaced.

    A trailing dot is kept so that ``ptype.=`` stays a broken propspec and
    does not turn into a domain placeholder that reads as ``ptype.property``.
    A *glued* piece follows an IPv6 piece directly: a domain there becomes
    ``tok_N``, since a label such as ``a.example`` would extend the hex run
    on the next pass (R13).
    """
    text = scan.text
    stop = end
    while stop > start + 1 and text[stop - 1] == ".":
        stop -= 1
    piece = text[start:stop]
    key = _kept_form(piece)
    found = None if key is not None else _family_of(piece)
    if glued and found is not None and found[0] is _DOMAIN:
        found = _OTHER_WORD, ascii_lower(piece)
    if key is not None:
        scan.taken.add(key)
    if found is None:
        scan.parts.append(piece)
    else:
        _slot(scan, found[0], found[1], start, stop)
    if stop < end:
        scan.parts.append(text[stop:end])


# --- quoted values ----------------------------------------------------------


def _clean_quote(scan: _Scan, start: int) -> tuple[int, int, bool]:
    """(content end, region end, clean) of the quoted-string at *start*."""
    end = scan.ends[start]
    stop = end - 1 if start != scan.open_region else end
    text = scan.text
    clean = all(text[k] not in _NOT_IN_CLEAN_QUOTE for k in range(start + 1, stop))
    return stop, end, clean


def _quoted_value(scan: _Scan, start: int, context: str) -> int:
    """Rewrite a quoted value: its content (R9) if clean, else free text."""
    stop, end, clean = _clean_quote(scan, start)
    if not clean:
        return _free_region(scan, start)
    scan.parts.append('"')
    _rewrite(scan, start + 1, stop, context)
    if stop < end:
        scan.parts.append('"')
    return end


def _unquoted(content: str) -> str:
    """*content* with quoted-pairs resolved (the local-part key, 14.12)."""
    out: list[str] = []
    i = 0
    while i < len(content):
        if content[i] == "\\" and i + 1 < len(content):
            i += 1
        out.append(content[i])
        i += 1
    return "".join(out)


def _quoted_pvalue(scan: _Scan, start: int, context: str) -> int:
    """R8 ``PVALUE``: a quoted local-part before ``@``, or a quoted value."""
    end = scan.ends[start]
    if start == scan.open_region or _char(scan, end) != "@":
        return _quoted_value(scan, start, context)
    content = scan.text[start + 1 : end - 1]
    if "\r" in content or "\n" in content:
        # Folds stay in place (LF_FOLDING, CONTROL_CHAR): free text instead.
        _free_region(scan, start)
    else:
        scan.parts.append('"')
        if _is_user(content):
            scan.parts.append(content)
            scan.taken.add(content)
        elif content:
            _slot(scan, _USER, _unquoted(content), start + 1, end - 1)
        scan.parts.append('"')
    scan.parts.append("@")
    return _rewrite_run(scan, end + 1, "")


# --- pass 1: the states (R4 to R8) ------------------------------------------


def _is_word(scan: _Scan, start: int, end: int) -> bool:
    return end > start and scan.text[end - 1] != "-"


def _arc_prefix(scan: _Scan, start: int) -> int:
    """R5: emit ``i CFWS = CFWS digits CFWS ;`` at *start*; its end, or -1."""
    text = scan.text
    if text[start] != "i":
        return -1
    equals = _skip_cfws(scan, start + 1)
    if _char(scan, equals) != "=":
        return -1
    digits = _skip_cfws(scan, equals + 1)
    digits_end = _end_of(scan, digits, DIGITS)
    semicolon = _skip_cfws(scan, digits_end)
    if not 1 <= digits_end - digits <= _ARC_DIGITS or _char(scan, semicolon) != ";":
        return -1
    scan.arc = True
    scan.parts.append("i")
    _emit_cfws(scan, start + 1, equals)
    scan.parts.append("=")
    _emit_cfws(scan, equals + 1, digits)
    scan.parts.append(text[digits:digits_end])
    _emit_cfws(scan, digits_end, semicolon)
    scan.parts.append(";")
    return semicolon + 1


def _keyword_then(scan: _Scan, start: int, end: int, follow: int) -> int:
    """Emit a kept keyword, the CFWS after it and the character at *follow*.

    Returns the offset after that character.
    """
    scan.parts.append(scan.text[start:end])
    _emit_cfws(scan, end, follow)
    scan.parts.append(scan.text[follow])
    return follow + 1


def _keyword_word(scan: _Scan, start: int, end: int) -> None:
    """AU-Q69: a word in a keyword position, kept if known, else ``tokN``.

    Kept: registered and producer words (ASCII-lowercased) and
    placeholder-shaped words (R10); others are keyed ASCII-lowercase.
    """
    word = scan.text[start:end]
    lower = ascii_lower(word)
    key = _placeholder_key(word)
    if lower in SAFE_WORDS or lower in PRODUCER_WORDS:
        scan.parts.append(word)
    elif key is not None:
        scan.parts.append(word)
        scan.taken.add(key)
    else:
        _slot(scan, _TOKEN_WORD, lower, start, end)


def _word_then(scan: _Scan, start: int, end: int, follow: int) -> int:
    """``_keyword_then`` with the word checked under AU-Q69."""
    _keyword_word(scan, start, end)
    return _keyword_then(scan, end, end, follow)


def _method(scan: _Scan, start: int, end: int, follow: int) -> tuple[int, _State]:
    """R7: a method keyword, then ``=`` (a result) or ``/`` (a version)."""
    state = _State.RESULT if scan.text[follow] == "=" else _State.VERSION
    return _word_then(scan, start, end, follow), state


def _name_slot(scan: _Scan, start: int, end: int, family: _Family) -> None:
    """Rename a ptype or property name (AU-Q60), unless it is kept (R10)."""
    word = scan.text[start:end]
    key = _placeholder_key(word)
    if key is None:
        _slot(scan, family, ascii_lower(word), start, end)
    else:
        scan.parts.append(word)
        scan.taken.add(key)


def _propspec(scan: _Scan, start: int, end: int, dot: int) -> int:
    """R7, R8: ``ptype [CFWS] . [CFWS] property [CFWS] =`` from *start*.

    Emits it and returns the offset after ``=``, or returns -1 (and emits
    nothing) if the lookahead does not hold.
    """
    text = scan.text
    name = _skip_cfws(scan, dot + 1)
    name_end = _end_of(scan, name, KEYWORD)
    equals = _skip_cfws(scan, name_end)
    if not (_is_word(scan, name, name_end) and _char(scan, equals) == "="):
        return -1
    ptype = ascii_lower(text[start:end])
    prop = ascii_lower(text[name:name_end])
    dotted = f"{ptype}.{prop}"
    domain = _kept_name(dotted)
    known = ptype in KEEP_PTYPES
    if domain:
        scan.taken.add(dotted)
    if domain or known:
        scan.parts.append(text[start:end])
    else:
        _name_slot(scan, start, end, _PTYPE)
    _emit_cfws(scan, end, dot)
    scan.parts.append(".")
    _emit_cfws(scan, dot + 1, name)
    if domain:
        scan.parts.append(text[name:name_end])
    elif known:
        _keyword_word(scan, name, name_end)  # AU-Q69
    else:
        _name_slot(scan, name, name_end, _PROPERTY)
    _emit_cfws(scan, name_end, equals)
    scan.parts.append("=")
    scan.context = prop
    return equals + 1


def _authserv_id(scan: _Scan, start: int) -> int:
    """R5: the authserv-id run, split at its first ``/`` (job ID, 14.11)."""
    text = scan.text
    end = _run_end(scan, start)
    slash = text.find("/", start, end)
    if slash < 0:
        _rewrite(scan, start, end, "")
        return end
    _rewrite(scan, start, slash, "")
    scan.parts.append("/")
    tail = slash + 1
    if any(text[k] in _TSPECIALS for k in range(tail, end)):
        _rewrite(scan, tail, end, "")
    elif tail < end:
        key = _kept_form(text[tail:end])
        if key is None:
            _slot(scan, _JOB, text[tail:end], tail, end)
        else:
            scan.parts.append(text[tail:end])
            scan.taken.add(key)
    return end


def _version_end(scan: _Scan, digits: int) -> int:
    """Return the end of a method-version (``digits [CFWS] =``) at *digits*.

    -1 if there is none; only then are the digits kept (17.1).
    """
    end = _end_of(scan, digits, DIGITS)
    if (
        end > digits
        and _char(scan, end) in _VERSION_ENDS
        and _char(scan, _skip_cfws(scan, end)) == "="
    ):
        return end
    return -1


def _versioned(scan: _Scan, slash: int) -> bool:
    """Return True if a method-version follows the ``/`` at *slash*."""
    return _version_end(scan, _skip_cfws(scan, slash + 1)) >= 0


def _job_digits(scan: _Scan, end: int, slash: int) -> bool:
    """17.1: ``word/digits`` with nothing between is an authserv-id and job ID."""
    digits_end = _end_of(scan, slash + 1, DIGITS)
    return (
        end == slash and digits_end > slash + 1 and _char(scan, digits_end) in _RUN_ENDS
    )


def _at_start(scan: _Scan, i: int) -> tuple[int, _State]:
    """R5 ``START``."""
    if not scan.started:
        scan.started = True
        end = _arc_prefix(scan, i)
        if end >= 0:
            return end, _State.START
    if scan.text[i] == '"':
        return _quoted_value(scan, i, ""), _State.AFTER_ID
    end = _end_of(scan, i, KEYWORD)
    follow = _skip_cfws(scan, end)
    after = _char(scan, follow)
    if not _is_word(scan, i, end) or after not in _METHOD_FOLLOW:
        return _authserv_id(scan, i), _State.AFTER_ID
    # AU-Q35: no authserv-id, the first word is a method. Before a "/" that
    # no method-version follows (host/job), the parser refuses the value
    # anyway, and the word is rewritten (R9) rather than kept.
    if after == "/" and not _versioned(scan, follow):
        if _job_digits(scan, end, follow):
            return _authserv_id(scan, i), _State.AFTER_ID
        _rewrite(scan, i, end, "")
        return _keyword_then(scan, end, end, follow), _State.VERSION
    return _method(scan, i, end, follow)


def _at_after_id(scan: _Scan, i: int) -> tuple[int, _State]:
    """R6 ``AFTER_ID``: a digit-only run is the version."""
    end = _end_of(scan, i, DIGITS)
    if end > i and _char(scan, end) in _RUN_ENDS:
        scan.parts.append(scan.text[i:end])
        return end, _State.ITEMS  # one version only (17.2)
    return i, _State.ITEMS


def _at_method(scan: _Scan, i: int) -> tuple[int, _State]:
    """R7 ``METHOD``, after a ``;``."""
    text = scan.text
    if text[i] == '"':
        return _free_region(scan, i), _State.ITEMS
    end = _end_of(scan, i, KEYWORD)
    follow = _skip_cfws(scan, end)
    after = _char(scan, follow)
    word = _is_word(scan, i, end)
    if word and after in _METHOD_FOLLOW:
        return _method(scan, i, end, follow)
    if (
        ascii_lower(text[i:end]) == "none"
        and _char(scan, end) in _RUN_ENDS
        and after in _NONE_FOLLOW
    ):
        scan.parts.append(text[i:end])
        return end, _State.ITEMS
    if word and after == ".":
        found = _propspec(scan, i, end, follow)
        if found >= 0:
            return found, _State.PVALUE
    return _rewrite_run(scan, i, ""), _State.ITEMS


def _at_version(scan: _Scan, i: int) -> tuple[int, _State]:
    """R7: after the method's ``/``: digits kept, any other run rewritten."""
    if scan.text[i] == '"':
        return _free_region(scan, i), _State.ITEMS
    end = _version_end(scan, i)
    if end >= 0:
        scan.parts.append(scan.text[i:end])
    else:
        end = _rewrite_run(scan, i, "")
    follow = _skip_cfws(scan, end)
    if _char(scan, follow) == "=":
        return _keyword_then(scan, end, end, follow), _State.RESULT
    return end, _State.ITEMS


def _at_result(scan: _Scan, i: int) -> tuple[int, _State]:
    """R8 ``RESULT``: an all-LDH run is the result keyword."""
    if scan.text[i] == '"':
        return _free_region(scan, i), _State.ITEMS
    end = _run_end(scan, i)
    if _end_of(scan, i, KEYWORD) == end:
        _keyword_word(scan, i, end)  # AU-Q69
        return end, _State.ITEMS
    return _rewrite_run(scan, i, ""), _State.ITEMS


def _at_items(scan: _Scan, i: int) -> tuple[int, _State]:
    """R8 ``ITEMS``: a propspec, ``reason=``, a bare property, or a value."""
    text = scan.text
    if text[i] == '"':
        return _free_region(scan, i), _State.ITEMS
    end = _end_of(scan, i, KEYWORD)
    follow = _skip_cfws(scan, end)
    after = _char(scan, follow)
    word = _is_word(scan, i, end)
    if word and after == ".":
        found = _propspec(scan, i, end, follow)
        if found >= 0:
            return found, _State.PVALUE
    if word and after == "=":
        name = ascii_lower(text[i:end])
        if name == "reason":
            return _keyword_then(scan, i, end, follow), _State.REASON
        scan.context = name
        return _word_then(scan, i, end, follow), _State.PVALUE
    return _rewrite_run(scan, i, ""), _State.ITEMS


def _at_reason(scan: _Scan, i: int) -> tuple[int, _State]:
    """R8: the ``reason`` value; plain tokens become ``...`` (14.1)."""
    text = scan.text
    if text[i] == '"':
        return _free_region(scan, i), _State.ITEMS
    end = _run_end(scan, i)
    run = text[i:end]
    if _keep_run(scan, run):
        scan.parts.append(run)
    elif run.isascii() and all(c in TOKEN for c in run):
        scan.parts.append(_FREE)
        scan.free_text += 1
        scan.spans.append((i, end))
    else:
        _rewrite(scan, i, end, "")
    return end, _State.ITEMS


def _at_pvalue(scan: _Scan, i: int) -> tuple[int, _State]:
    """R8 ``PVALUE``, rewritten in the property's context."""
    if scan.text[i] == '"':
        return _quoted_pvalue(scan, i, scan.context), _State.ITEMS
    return _rewrite_run(scan, i, scan.context), _State.ITEMS


_Handler = Callable[[_Scan, int], tuple[int, _State]]
_HANDLERS: dict[_State, _Handler] = {
    _State.START: _at_start,
    _State.AFTER_ID: _at_after_id,
    _State.METHOD: _at_method,
    _State.VERSION: _at_version,
    _State.RESULT: _at_result,
    _State.ITEMS: _at_items,
    _State.REASON: _at_reason,
    _State.PVALUE: _at_pvalue,
}


def _walk(scan: _Scan) -> None:
    """Pass 1: copy CFWS, stray ``)`` and ``;`` (R1); a state handles the rest."""
    text = scan.text
    state = _State.START
    i = 0
    while i < scan.size:
        c = text[i]
        if c in _FOLD:
            end = _end_of(scan, i, _FOLD)
            scan.parts.append(text[i:end])
            i = end
        elif c == "(":
            i = _free_region(scan, i)
        elif c in {")", ";"}:
            scan.parts.append(c)
            i += 1
            if c == ";":
                state = _State.METHOD
        else:
            i, state = _HANDLERS[state](scan, i)


# --- pass 2 and the entry point ---------------------------------------------


def _reserved(scan: _Scan, prefix: str, n: int) -> bool:
    """Return True if placeholder *n* is in the input (spelling or IPv6 value)."""
    name = _numbered(prefix, n)
    if name in scan.taken:
        return True
    return prefix == "ipv6" and _ipv6_value(name) in scan.reserved_ipv6


def _allocate(scan: _Scan) -> list[str] | None:
    """Allocate placeholders per prefix, skipping ``taken``; None if a pool is out."""
    last: dict[str, int] = {}
    names: list[str] = []
    for slot in scan.slots:
        cap = _CAPS.get(slot.prefix, MAX_NUMBER)
        n = last.get(slot.prefix, 0) + 1
        while n <= cap and _reserved(scan, slot.prefix, n):
            n += 1
        if n > cap:
            return None
        last[slot.prefix] = n
        names.append(_numbered(slot.prefix, n) + slot.suffix)
    return names


def _removed(text: str) -> tuple[int, int]:
    """(non-ASCII, control) characters, CR, LF and HTAB excepted (R12)."""
    non_ascii = 0
    controls = 0
    seen: dict[str, bool] = {}
    for c in text:
        if " " <= c < "\x7f" or c in _FOLD:
            continue
        is_control = seen.get(c)
        if is_control is None:
            is_control = seen[c] = control(c)
        if is_control:
            controls += 1
        else:
            non_ascii += 1
    return non_ascii, controls


def _redact_value(value: object) -> Redaction:
    text = exact_text(value)
    ends, open_region = _regions(text)
    scan = _Scan(
        text=text,
        size=len(text),
        ends=ends,
        open_region=open_region,
        parts=[],
        spans=[],
        slots=[],
        keys={},
        taken=set(),
        context="",
        free_text=0,
        arc=False,
        started=False,
        no_ipv6_before=0,
        reserved_ipv6=set(),
    )
    _walk(scan)
    non_ascii, controls = _removed(text)
    names = _allocate(scan)
    if names is None:
        return Redaction(
            text="",
            complete=False,
            replacements=(),
            free_text=scan.free_text,
            non_ascii=non_ascii,
            controls=controls,
            arc=scan.arc,
            spans=(),
            originals=(),
        )
    output = "".join(names[p] if isinstance(p, int) else p for p in scan.parts)
    return Redaction(
        text=output,
        complete=True,
        replacements=tuple(
            Replacement(name, slot.kind, slot.count)
            for name, slot in zip(names, scan.slots, strict=True)
        ),
        free_text=scan.free_text,
        non_ascii=non_ascii,
        controls=controls,
        arc=scan.arc,
        spans=tuple(scan.spans),
        originals=tuple(tuple(slot.spellings) for slot in scan.slots),
    )


def redact(value: str) -> Redaction:
    """Redact one header value; never raises for a ``str``.

    A non-``str`` raises ``AuthResultsError(INVALID_TYPE)``; any internal
    failure becomes ``AuthResultsError(INTERNAL)`` with no input text.
    """
    return call_guarded(_redact_value, value)
