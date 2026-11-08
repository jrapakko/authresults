# authresults

`authresults` parses one RFC 8601 `Authentication-Results` header field value, and one
RFC 8617 `ARC-Authentication-Results` value, into immutable objects. It is pure Python with
zero runtime dependencies and fully typed. It does no DNS lookups, verifies nothing (no
DKIM, SPF, DMARC or ARC checks) and does not parse messages: you pass it one field's value.

**Status:** 0.1.0, the first release (alpha). The API may change in 0.x minor releases; see
[Versioning and stability](#versioning-and-stability).

## Install

`pip install authresults` or `uv add authresults`. Python 3.11 or later; no runtime
dependencies; the package ships `py.typed`.

## Quick start

```pycon
>>> from authresults import ascii_domain, parse, parse_arc
>>> ar = parse(
...     "mx.example.net; dkim=pass header.d=example.com header.s=sel1;"
...     " spf=pass smtp.mailfrom=example.com"
... )
>>> ar.authserv_id
'mx.example.net'
>>> [(r.method, r.result) for r in ar.results]
[('dkim', 'pass'), ('spf', 'pass')]
>>> ar.results_for("dkim")[0].get_unique("header", "d").value
'example.com'
>>> ascii_domain("Example.COM")
'example.com'
>>> parse_arc("i=1; mx.example.net; arc=none").instance
1
>>> parse("mx.example.net;  DKIM=pass (all good)  header.d=example.com").to_value()
'mx.example.net; dkim=pass header.d=example.com'
```

## What it does and does not do

In scope: parsing one value with `parse()` or one ARC value with `parse_arc()`; `registered`
flags from a frozen snapshot of the IANA Email Authentication Parameters registries; the
domain helpers `domain_of()` and `ascii_domain()`; a canonical serializer, `to_value()`.

Out of scope: DNS, DKIM/SPF/DMARC/ARC verification, message parsing, header field names,
comments as data, `Received` parsing, logging and warnings. The library never logs.

- **Comments are dropped**, never data: `(dmarc=pass)` in a comment never becomes a result.
- **RFC 8617 is Experimental.** `parse_arc()` reads the instance tag and the same payload
  grammar; nothing ARC-specific (chain validation, `ARC-Seal`) is in scope.
- **The registry snapshot** is dated 2026-05-22 (the IANA "last updated" date). A refresh
  is a patch release, with the new date in the
  [CHANGELOG](https://github.com/jrapakko/authresults/blob/main/CHANGELOG.md).
- `domainkeys=fail` is unregistered, because IANA lists no `fail` result for `domainkeys`.
- U-labels are not converted; use the `idna` package. `ascii_domain()` returns `None` for
  any non-ASCII name.

## Using it on received mail

Senders can add any `Authentication-Results` field they like, so trust only one your own
hosts wrote, and pick it by position:

- Read with `email.message_from_bytes(data, policy=email.policy.default)` and walk
  `msg.raw_items()` top-down.
- Only the fields above your receiving host's arrival `Received` were written by your
  hosts. Parse only those, and pick the one whose `authserv_id` equals your expected id.
  In the code below, `own_received` is the position, counted from the top, of the
  `Received` field your own receiving host adds on arrival. Never count too high:
  everything below that field was written by the sender.
- Never parse, or refuse on, fields further down: they are attacker-controlled. Check
  where your MTA puts its own field; some systems reorder headers.
- Strip a trailing CRLF or LF from the raw value (`raw_items()` may already have done it).
- Treat `AuthResultsError`, or any other exception, as "refuse".
- Match by token (`r.method == "dmarc" and r.result == "pass"`), never by substring.
- Use `get_unique()` for `header.from`, `header.d` and `header.i`, so a duplicate refuses,
  and compare domains only through `ascii_domain()`.
- The DKIM signing domain is `header.d`, or else `domain_of(header.i)`.
- Refuse a field whose `deviations` hold anything outside a set you have checked, or use
  `strict_syntax=True`.
- Refuse `authserv_id is None`. An ARC value passed to `parse()` is usually refused, and
  one without an authserv-id reads as a field with a missing id and an unregistered `i=1`
  result.
- Keep the defaults `max_length=8192` (counted in characters and checked first, so an
  oversized value costs O(1) to refuse) and `ascii_only=True` (which removes look-alike
  keywords and punctuation).

RFC 8601 sets rules for consumers too. §2.3: "Results reported using unknown ptypes MUST
NOT be used in making handling decisions." §4.1: "MUAs and downstream filters MUST ignore
any result reported using a "result" not specified in the IANA "Result Code" registry or a
"ptype" not listed in the "Email Authentication Property Types" registry". So test
`registered`. §2.7.6: "Any MTA, MUA, or downstream filter intended for production use
SHOULD ignore or delete any Authentication-Results header field that includes an
experimental (unknown) method identifier."

Selecting the trusted field:

```python
import email
import email.policy

from authresults import AuthenticationResults, parse


def trusted_results(
    data: bytes, authserv_id: str, *, own_received: int = 1
) -> AuthenticationResults | None:
    msg = email.message_from_bytes(data, policy=email.policy.default)
    matches: list[AuthenticationResults] = []
    received = 0
    for name, value in msg.raw_items():
        key = name.lower() if name.isascii() else ""
        if key == "received":
            received += 1
            if received == own_received:
                break  # everything below was not written by our hosts
        elif key == "authentication-results":
            if value.endswith("\r\n"):
                value = value[:-2]
            elif value.endswith("\n"):
                value = value[:-1]
            try:
                results = parse(value)
            except Exception:  # AuthResultsError or anything else: refuse
                return None
            if results.authserv_id == authserv_id:
                matches.append(results)
    else:
        return None  # fewer Received fields than expected
    return matches[0] if len(matches) == 1 else None
```

Deciding on it:

```python
from authresults import (
    AuthenticationResults,
    AuthResultsError,
    Deviation,
    ascii_domain,
    domain_of,
)

# Deviations you have checked and accept from your own host. If it writes
# header.b unquoted, you might add Deviation.PVALUE_TSPECIALS. On its own that
# would re-open the balanced-bracket field splitting described under
# "Characters in unquoted values", so deviations_ok() then also requires
# no_bracketed_values(); the functions below already do this. That check also
# refuses legitimate bracketed values, such as header.from=<noreply@...> or
# smtp.helo=[192.0.2.1], which is the safe direction.
EXPECTED_DEVIATIONS: frozenset[Deviation] = frozenset()
BRACKETS = frozenset("<>[]")


def no_bracketed_values(results: AuthenticationResults) -> bool:
    # True when no property has a bracket in its raw text. A DKIM signature
    # (header.b) is base64 and never holds one.
    return not any(
        BRACKETS.intersection(prop.raw)
        for result in results.results
        for prop in result.properties
    )


def deviations_ok(results: AuthenticationResults) -> bool:
    if not results.deviations <= EXPECTED_DEVIATIONS:
        return False
    if Deviation.PVALUE_TSPECIALS in EXPECTED_DEVIATIONS:
        return no_bracketed_values(results)
    return True


def dmarc_pass(results: AuthenticationResults, from_domain: str) -> bool:
    if not deviations_ok(results):
        return False
    dmarc = results.results_for("dmarc")
    if len(dmarc) != 1 or not dmarc[0].registered or dmarc[0].result != "pass":
        return False
    try:
        header_from = dmarc[0].get_unique("header", "from")  # refuses duplicates
        if header_from is None:
            return False
        ours = ascii_domain(from_domain)
        return ours is not None and ascii_domain(header_from.value) == ours
    except AuthResultsError:
        return False


def dkim_pass_domains(results: AuthenticationResults) -> frozenset[str]:
    if not deviations_ok(results):
        return frozenset()
    domains: set[str] = set()
    for dkim in results.results_for("dkim"):
        try:
            d = dkim.get_unique("header", "d")
            i = dkim.get_unique("header", "i")
        except AuthResultsError:  # a duplicate header.d or header.i
            return frozenset()
        if not dkim.registered or dkim.result != "pass":
            continue
        if d is not None:
            domain = ascii_domain(d.value)
        elif i is not None and (signer := domain_of(i.value)) is not None:
            domain = ascii_domain(signer)
        else:
            domain = None
        if domain is not None:
            domains.add(domain)
    return frozenset(domains)
```

## The result model

All four types are frozen, slotted dataclasses holding tuples, never lists.

| Type | Fields |
|---|---|
| `AuthenticationResults` | `authserv_id` (`str`, or `None` only with `missing_authserv_id`), `version` (1 when absent), `version_given`, `none`, `results`, `deviations` (a `frozenset`) |
| `ArcAuthenticationResults` | `instance` (1 to 50), `payload` (an `AuthenticationResults`) |
| `Result` | `method`, `method_version` (`int` or `None`), `result`, `reason`, `properties`, `registered` |
| `Property` | `ptype` (`None` only for a bare property), `name`, `value`, `raw`, `quoted`, `registered` |

- Method, result, ptype and property names are lowercased (A to Z only). The authserv-id,
  property values and `reason` are kept as written.
- `results_for()`, `Result.get()` and `Result.get_unique()` lowercase their arguments, so
  `results_for("DMARC")` equals `results_for("dmarc")`. `get()` returns every match in
  order; `get_unique()` returns one or `None`, and raises `duplicate_property` on two.
- The accessors reject `str` subclasses with `invalid_type` (they take your keywords, not
  header input), while `parse()` and the helpers accept one and read its underlying text.
- `Result.registered`: method, method version and result are all in the snapshot.
  `Property.registered`: the method, ptype and property row is.
- `Property.value` has quotes removed and quoted-pairs resolved (folds in an address are
  unfolded); `Property.raw` is the exact source text.
- `to_value(*, ascii_only=True)` writes one canonical line. It refuses CR, LF, other
  controls, Unicode space and format characters (`control_char`), and under
  `ascii_only=True` any non-ASCII (`non_ascii`), so its output can never inject a header.

## Strict and lenient parsing

By default five known real-world departures from the grammar are accepted and recorded in
`deviations`. With `strict_syntax=True`, the first one raises `deviation` at its position.

| `Deviation` | Example |
|---|---|
| `bare_property` | `mx.example.net; dkim=pass action=none` (no ptype) |
| `pvalue_tspecials` | `header.b=Ab+/cd=` (see below) |
| `trailing_semicolon` | `mx.example.net; dkim=pass;` |
| `lf_folding` | a fold written as LF and a tab instead of CRLF and a tab |
| `missing_authserv_id` | `dkim=pass header.d=example.com` (no id) |

Unregistered methods, results, ptypes and properties are kept with `registered=False`,
never dropped. With `require_registered=True`, they raise `unregistered` instead.

### Characters in unquoted values

`PVALUE_TSPECIALS` covers exactly `/`, `=`, `?`, `:`, `[`, `]`, `<` and `>` written
unquoted in a property value. `/ = ?` before an `@` are legal local-part characters and
are not flagged. Values keep these characters as written (IPv6 such as
`smtp.remote-ip=2001:db8::1`, IP-literal HELO `[192.0.2.1]`, `<>`, `<addr>`), so compare
domains only through `ascii_domain()`, which returns `None` for them.

`,` and `\` in an unquoted value are refused as `syntax`; widening the deviation to them
is the considered alternative, done only with a real-world value that needs it. A `"`
starts a quoted string and a `(` after a value starts a comment, so a value that goes on
after either is refused; `;` ends the value (it separates results). Brackets must pair up,
or the value is refused.

Caveat: balanced brackets do not stop field splitting by a producer that wraps attacker
text. The full value
`mx.example; spf=fail smtp.mailfrom=<x>; dkim=pass header.d=bank.example header.b=<>`
parses with an extra `dkim=pass`, so prefer `strict_syntax=True` or check the deviation. If
you accept `PVALUE_TSPECIALS`, also refuse values for which `no_bracketed_values()` is
False; the decision code above already does this in `deviations_ok()`. That check also
refuses legitimate bracketed values (`header.from=<noreply@...>`, `smtp.helo=[192.0.2.1]`),
which is the safe direction.

```pycon
>>> from authresults import AuthResultsError, Deviation
>>> parse("mx.example.net; dkim=pass header.b=Ab+/cd=").deviations
frozenset({<Deviation.PVALUE_TSPECIALS: 'pvalue_tspecials'>})
```

### A missing ";" between results

```pycon
>>> ar = parse("mx.example.net; dkim=pass spf=pass smtp.mailfrom=example.com")
>>> ar.results_for("spf")
()
>>> sorted(ar.deviations)
[<Deviation.BARE_PROPERTY: 'bare_property'>]
```

This is one dkim result with a bare property `spf=pass`. A bare property named like a
registered method signals a missing `;`: that result is not reported and never becomes a
pass, and `strict_syntax=True` refuses the value.

### X- fields such as X-TM-Authentication-Results

The library parses any value you pass it. Fields such as `X-TM-Authentication-Results` use
RFC 8601 syntax with no authserv-id, so they parse with `missing_authserv_id` and
`bare_property`.

### Non-ASCII input

With `ascii_only=False`, UTF-8 is allowed in values, never in keywords. Look-alike
punctuation (U+037E, U+FF1D) stays inside values, so never NFC-normalise values before
comparing. Unicode space and format characters are always `control_char`.

## Errors

`AuthResultsError` is a `ValueError` with `reason` (an `ErrorReason`), `position` (a
character offset, or `None`) and `known_shape` (a `KnownShape`, or `None`). The message is
exactly `"<reason>"` or `"<reason> at position <n>"`, never input text; `known_shape` is
not in it.

```pycon
>>> try:
...     parse("mx.example.net/4ABCD; dkim=none")
... except AuthResultsError as err:
...     print(err.reason, err.position, err.known_shape)
...     print(err)
syntax 14 authserv_id_job_id
syntax at position 14
```

| `ErrorReason` | Meaning |
|---|---|
| `invalid_type` | the value is not a `str` |
| `empty` | the value is empty or only whitespace |
| `too_long` | longer than `max_length` (checked first) |
| `non_ascii` | non-ASCII under `ascii_only=True` |
| `control_char` | a control, Unicode space or format character, or a lone surrogate |
| `unterminated_comment` | a comment is not closed |
| `unterminated_quoted_string` | a quoted string is not closed |
| `nesting_too_deep` | comments nested deeper than `max_comment_depth` |
| `syntax` | the value does not follow the grammar |
| `unsupported_version` | a header version other than 1 |
| `too_many_results` | more than `max_results` results |
| `too_many_properties` | more than `max_properties` properties in one result |
| `duplicate_reason` | two `reason=` in one result |
| `duplicate_property` | `get_unique()` found two matching properties |
| `deviation` | a deviation under `strict_syntax=True` |
| `unregistered` | an unregistered name under `require_registered=True` |
| `bad_arc_instance` | an ARC `i=` outside 1 to 50 |
| `internal` | an unexpected error inside the library |

- A limit that is not an `int` of at least 1, or a flag that is not a `bool`, raises a
  plain `ValueError`: a caller bug, the one documented exception to the closed set, raised
  before any input is read.
- `internal` covers any unexpected exception, including `MemoryError` and
  `RecursionError`, chained to a cause that carries only the original type name.
- Frame locals, as error trackers capture them, are out of the library's reach.

## Helpers

- `domain_of(value)`: the text after the last `@` (the whole value if there is none), or
  `None` if empty. It strips one enclosing `<...>` around a valid address and gives `None`
  for other values with `:`, `[`, `]`, `<` or `>`. It does no character validation: it can
  return C1 controls or non-ASCII spaces, and `<"a\x00"@good.example>` gives
  `good.example`. Always pass its result through `ascii_domain()` before comparing or
  looking it up.
- `ascii_domain(value)`: the value ASCII-lowercased if it is dot-separated LDH labels, else
  `None`. `xn--` labels pass unvalidated; there are no length checks.

```pycon
>>> from authresults import domain_of
>>> domain_of("<user@mail.example.com>")
'mail.example.com'
>>> domain_of("@sub.example.com")
'sub.example.com'
>>> print(ascii_domain("bad_label.example"))
None
```

## Shapes known from real software

When a refusal matches a shape known from real software, `known_shape` names it:

- `exim_arc_leading_property`: Exim's `ARC-Authentication-Results` opening element, a
  `ptype.property=value` where a result belongs.
- `stray_domain_between_results`: a bare domain between results.
- `authserv_id_job_id`: a job ID after the authserv-id (OpenDKIM and OpenDMARC's
  `AuthservIDWithJobID`; leave that option off).
- `authserv_id_only`: an authserv-id with no results and no `none`; refused for now,
  quick to change.
- `spf_details_as_results`: `Received-SPF` keys (`client-ip=`, `helo=`) written as results.

The library never logs. `known_shape` is set only on a refusal matching a shape in the log,
never on `internal` or `invalid_type`; it holds no input text and leaves `reason` and
`position` unchanged. Count or log it with your own logger to see which shapes your traffic
has. Sources and details:
[docs/refused-shapes.md](https://github.com/jrapakko/authresults/blob/main/docs/refused-shapes.md).

## Seeing a refusal on real mail?

```python
import logging

from authresults import AuthenticationResults, AuthResultsError, parse

logger = logging.getLogger(__name__)


def parse_or_log(value: str) -> AuthenticationResults | None:
    try:
        return parse(value)
    except AuthResultsError as err:
        # The three fields only: never the value, and no exc_info.
        logger.warning(
            "authresults refused a header: reason=%s position=%s known_shape=%s",
            err.reason,
            err.position,
            err.known_shape,
        )
        return None
```

Never log the header value or any part of it. To report a shape, run the redaction helper
(next section) and open the
[header shape form](https://github.com/jrapakko/authresults/issues/new?template=header-shape.yml).
A report of a known shape counts as a vote to re-enable it; an unknown one becomes a new
log entry through a question to the maintainer.

## Redacting a value for a report

```sh
python -m authresults.redact < value.txt
```

Write the value to a file with an editor, or run the command, paste and press Ctrl-D.
Avoid `echo`, which keeps the value in shell history; scrollback keeps it too.

- stdout is the redacted value; stderr is a report. Exit codes: 0, 1 (too long, or too
  many distinct values), 2 (usage), 3 (internal or write failure).
- Post the stdout value in a code block, plus the stderr lines `line breaks:`,
  `parse (original):` and `parse (redacted):`.
- `--show-originals` output is for your own check and must never be posted.
- It replaces domains, IP addresses, local-parts, selectors, signatures, job IDs, numbers
  longer than 4 digits, all comment and `reason` text, and unknown words in keyword
  positions. It keeps registered and producer words, vendor hostnames, short codes and the
  layout.
- It leaves in: authserv-id version and method-version digits at any length; any
  well-formed address in 2001:db8::/32; safe words, numbers of up to 4 digits,
  placeholder-shaped strings, and vendor hostnames (which reveal the provider); and, on
  purpose, structure: folds, whitespace, comment nesting, counts of results and
  properties, which values are equal, whether `/` or `=` appears in a signature. Together
  these can fingerprint the receiving system.

It is best effort: read the output before posting. Its Python module API is not public.

## Versioning and stability

- Semantic versioning: 0.x until the library has run in production, then 1.0.
- Public API: the names in `__all__`, the dataclass fields, the members of `ErrorReason`,
  `Deviation` and `KnownShape`, and the message format.
- Adding a member is a minor release (exhaustive `match` users notice). Removing or
  renaming anything is breaking: a major release, or a minor one while in 0.x. A retired
  `KnownShape` member stays, never set, until a minor release removes it.
- Accepting a previously refused shape, or changing an error position, is a minor release.
- Registry snapshot refreshes are patch releases, with the IANA date in the CHANGELOG.
- `authresults.redact`, `_`-prefixed modules and the redaction report format are not
  public API.
- Dropping a Python version happens only in a minor release.

The decisions behind all of this are recorded in
[docs/plan.md](https://github.com/jrapakko/authresults/blob/main/docs/plan.md).

## Security

Report vulnerabilities privately as described in
[SECURITY.md](https://github.com/jrapakko/authresults/blob/main/SECURITY.md), which also
lists what counts: an exception other than `AuthResultsError`, a mis-parse that creates or
hides a result, super-linear time, input text in an error message, serializer output that
could inject a header, and a redaction miss that leaks personal data.

## Contributing and licence

See [CONTRIBUTING.md](https://github.com/jrapakko/authresults/blob/main/CONTRIBUTING.md)
(commits are signed off under the DCO). Licensed under the
[Apache License 2.0](https://github.com/jrapakko/authresults/blob/main/LICENSE); see
[NOTICE](https://github.com/jrapakko/authresults/blob/main/NOTICE).
