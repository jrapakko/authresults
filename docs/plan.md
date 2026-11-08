# authresults: project plan

> **Citations of `PLAN.md` (AU-Q76).** Docstrings, tests and comments in this repository cite "PLAN.md" with section numbers. They refer to this document, which replaced that earlier private draft. Section map, PLAN.md to this file: sections 0 to 6 are the same; PLAN.md 7 (adoption by a downstream application) has no counterpart here; PLAN.md 8 (maintainer steps) is section 7; 9 (risks) is 8; 10 (sources) is 9; 11 (questions, AU-Q1 onward) is section 10. Subsection numbers inside sections 3 and 4 (for example 3.1 G1 to G16, the section 4 properties) are unchanged.

`authresults` is a zero-dependency, pure-Python, fully typed parser of one RFC 8601 `Authentication-Results` header value, and one RFC 8617 `ARC-Authentication-Results` value, into immutable objects. This document is the project's plan of record. It covers scope and API, the grammar decisions read from the RFCs, the frozen IANA registry snapshot, the test strategy, the project setup, the delivery slices with their acceptance criteria, risks, sources, and every design question with the maintainer's answer. The status section below records what is done.

Conventions: **VERIFIED** means read from a source (the date is given where it matters; the first reads were through a summarising fetch, and the grammar was then re-read verbatim at AL3a-R, section 3.1). **UNVERIFIED** means memory or inference. RFC grammar rules are cited by RFC, section and rule name and are not copied into this repository (G18, AU-Q19); short prose quotes from RFCs are attributed to their source.

**Decided by the maintainer (2026-11-05):** write a new parser in pure Python, no Rust, rather than adopt an existing one; Apache-2.0; its own public GitHub repository `authresults` under the maintainer's personal account; PyPI name `authresults`; creating the repository and every publish need the maintainer's OK each time; no other application names in the repository (README, metadata, examples, copyright, commit messages).

## Status (2026-11-07)

| Slice | Commit | State |
|---|---|---|
| AL1: skeleton, CI, supply-chain checks | `942d9ba` | done; pushed, CI green |
| AL2a: public API surface, error guard, stubs | `dfa357e` | done; pushed |
| AL2a amendment per AU-Q35 (`Deviation.MISSING_AUTHSERV_ID`, `authserv_id: str \| None`) | `0a68c06` | done; pushed |
| AL3a-R: verbatim RFC re-read (section 3.1) | none (plan only) | done |
| AL3a: case table, 606 cases | `841cb37` | done; written test-first by a fresh instance, red-teamed in 3 fix rounds; pushed, CI green on 3.11 to 3.15 |
| AL2b: parser, serializer, registry snapshot, Unicode table | `4e5f90e`; case amendment `608e139` | done; verified after 1 fix round; pushed, CI green |
| AL3b: properties, differential, mutation | `26a385f`; plan `86bcf35` | done; verified and red-teamed in 3 fix rounds; pushed |
| AL3c: vendor fixture sweep, refused-shapes log, `known_shape` | `1f4e1cc` (cases), `b80480a` (src) | done; verified and red-teamed in 3 fix rounds; pushed |
| AL3d: redaction helper for shape reports | `57c491c` (tests), `57c16c2` (helper) | done; verified and red-teamed in 3 fix rounds; pushed |
| AL4: release workflow, README, 0.1.0 | `d100d30`, `a57a86e`, `94d2ea9`; release `9a1f8d5`, tag `v0.1.0` | done; 0.1.0 published to PyPI 2026-11-08, attestations verified (record below) |

AL2b in detail:
- AU-Q41 (Unicode space and format characters refused) has its case amendment (`608e139`), made by a fresh test-writer per 6.4, and the matching parser change.
- A red-team review found no trust-relevant mis-parse. Fix round 1 closed M1 (per AU-Q42) and L1 to L3.
- 758 cases, 1,811 tests, 100% line and branch coverage on 3.11 to 3.15.

AL3b slice note (coverage audit): the audit command reports `scripts/check_lock_cooldown.py` lines 15 to 88 at 0%, because its test (`tests/test_lock_cooldown.py`) is outside the audit set; every `src/` module is at 100%. This is the listed omission the AL3b acceptance allows.

AL3c slice note (targets with no public example, 2026-11-07): **Proton**: proton.me blog posts (what-are-email-headers, whose header screenshot has no Authentication-Results field; what-is-email-spoofing, fragments only; dkim-replay-attack-breakdown; what-is-dmarc), /business/mail/email-authentication and /support/custom-domain; no Proton directory in the chatmail test fixtures; a forum `.eml` and a gist were excluded as private mail and a user script. **Barracuda**: campus.barracuda.com and documentation.campus.barracuda.com (Confluence CQL search for `"Authentication-Results"`, `"dkim=pass"`, `"spf=pass"`, `"dmarc=pass"`, `"spf=fail"`), Email Gateway Defense "Sender Authentication", Domain Fraud Protection pages, Impersonation Protection "Dashboard" (a screenshot only) and the release notes; no textual example. **SpamAssassin** 4.0.2: `Plugin/AuthRes.pm` reads the header and never writes one, so there is nothing to collect. Mimecast's only public value is refused and logged (AU-Q54).

AL3b in detail:
- Hypothesis properties 1 to 5 (`ci` 2,000 examples, `nightly` 100,000 in `fuzz.yml`), the authres 1.2.0 differential (11 differences and 5 normalisations, each with its own test), mutmut with its equivalents listed in `mutmut-equivalent.md`.
- The red-team found no parser bug. 1,870 tests, 100% line and branch coverage.

AL3c in detail:
- 865 cases plus helper cases (2,147 tests, 100% coverage). Vendor cases for 14 targets, re-checked against public sources on 2026-11-07; `docs/refused-shapes.md` logs five tagged refused shapes, one shape read differently (AU-Q49) and the doc artefacts.
- AU-Q45/53 accept `: [ ] < >` under `PVALUE_TSPECIALS`; the red-team's injection through an unclosed `<` led to AU-Q57 (brackets must pair up), and its `domain_of` findings to AU-Q58 and its clarification. `KnownShape` and `AuthResultsError.known_shape` per AU-Q52, AU-Q54 and AU-Q56. authres difference 12 added. No trust mis-parse in the final red-team pass.

AL3d in detail:
- `python -m authresults.redact`, planned in `docs/plans/al3d.md` (rules R1 to R14, answers AU-Q59 to AU-Q69, clarifications and fix rounds in sections 13 to 18). 3,166 tests, 100% coverage; written test-first by a separate test-writer.
- The red-team found leaks that were closed in three rounds (glued IPv6, digit runs after `/`, extra version runs, doc-prefixed IPv6, unknown keyword words under AU-Q69); its final pass got no undocumented personal data through. The last low item (L-c: a non-canonical kept doc IPv6 could share a spelling-equivalent placeholder) was fixed in a follow-up by reserving kept doc IPv6 by value (`docs/plans/al3d.md` section 19).

AL4 release record (AU-Q12, AU-Q75), 2026-11-08:
- Rehearsal: TestPyPI 0.1.0 from a manual Publish run on `main` (the release commit), environment `testpypi`. Exactly one wheel and one sdist; provenance publisher GitHub / `jrapakko/authresults` / `publish.yml` / `testpypi`; installed from TestPyPI into a scratch venv: `authresults.__version__ == "0.1.0"`, a parse and `python -m authresults.redact` (and `--help`) worked. The first attempt failed with `invalid-publisher` until the TestPyPI pending publisher was created.
- Release: tag `v0.1.0` (annotated, no signing key configured; AU-Q79 B) on commit `9a1f8d50399755d9f05823aa94545f7955032e95`. The first tag run was refused by the `pypi` environment (its deployment rule did not match the tag); after the rule was set to Tag `v*`, the failed job was re-run and published.
- PyPI 0.1.0 files (identical to the TestPyPI rehearsal):
  - `authresults-0.1.0-py3-none-any.whl` sha256 `7669910eac665dfb05e1a58afda82aa8f3ea76f6f3066bc5135fcb39138706ea`, transparency log index 3747819247;
  - `authresults-0.1.0.tar.gz` sha256 `dbda4f5fea5e3981e3eef75df473ec9a941d0a76c6206901162aedc12367ab88`, transparency log index 3747819245.
- Provenance (PyPI integrity API) for both files: publisher kind GitHub, repository `jrapakko/authresults`, workflow `publish.yml`, environment `pypi`.
- Verification: `uv tool run --from 'pypi-attestations==0.0.30' pypi-attestations verify pypi --repository https://github.com/jrapakko/authresults pypi:<file>` printed `OK` for both files. The repository and workflow are in the signed certificate; the environment is as recorded by PyPI's publisher (not checked from the signature).
- GitHub release `v0.1.0` exists with the same two files attached (AU-Q72).

Next: none planned in this plan; the library is released. Post-launch items (debug logging, AU-Q46/AU-Q51 revisits) are in section 8.

**Working method.** Each slice goes architect, then implementer, then verifier, then red-team, with a fix loop: red-team findings go back to the implementer as repros, and the verifier re-runs. The loop is capped at 3 rounds before it is escalated to the maintainer. Only the implementer edits source; the verifier and red-team are read-only. Tests come before the parser: the case table (AL3a) was written from the RFCs and this plan by a fresh instance before any parser code existed, and its expectations change only through answered questions (6.4). Every commit and every push happens only with the maintainer's OK.

## 0. Summary

- A zero-dependency, pure-Python, fully typed parser of one `Authentication-Results` value (and one `ARC-Authentication-Results` value) into immutable objects. No DNS, no verification, no message parsing.
- Safety contract: for any `str` input, `parse()` returns a result or raises `AuthResultsError` with a reason from a closed enum. Nothing else escapes. The tokeniser is one linear pass with a depth counter, so there is no recursion and no regex backtracking.
- Lenient by default on names and on known real-world grammar deviations, but **nothing is dropped**: unknown methods, ptypes and bare properties are kept and flagged, and every deviation is recorded so a strict caller can refuse.
- Library slices in this order: AL1, AL2a (API surface), AL3a-R (architect re-read of the RFCs), AL3a (case table, written before the parser), AL2b (parser), AL3b (properties, differential, mutation), AL3c (vendor fixture sweep), AL3d (redaction helper), AL4 (release).
- An earlier evaluation of existing parsers (authres, authheaders) produced 28 adversarial cases; they are now in `tests/cases_spike.py` under their original names and are cited below as "the earlier evaluation". That evaluation has no public write-up: every claim it makes about authres behaviour is backed in this repository by `tests/test_differential.py` (AL3b), which runs authres 1.2.0 and lists each known difference with its reason.

## 1. Scope

In:
- `parse(value)`: authserv-id, optional version, then either `none` or one or more results. Each result has method, optional method version, result, optional `reason`, and properties as `ptype.property=value`.
- `parse_arc(value)` (AU-Q2): RFC 8617 §4.1.1 (`arc-info` rule) puts an instance tag, then `;`, then the same payload grammar. The instance tag is defined in RFC 8617 §3.9 (`instance` and `position` rules): a case-sensitive `i` (the `%s` prefix, RFC 7405 §2.1), `=`, and a position of one or two digits in the range 1 to 50 (VERIFIED). It reuses the payload grammar, so it costs about 20 lines and its own tests. RFC 8617 is Experimental (VERIFIED). That goes in the README, and nothing ARC-specific (chain validation, `ARC-Seal`) is in scope.
- A frozen snapshot of the IANA registries (methods, ptypes, properties, results), dated, used only to set `registered` flags.
- Small helpers (section 2.5).
- A canonical serializer `to_value()` (AU-Q3). It drives the strongest Hypothesis property (model, then serialize, then parse, gives the same model). It must refuse CR, LF, other controls and, under `ascii_only`, non-ASCII, so it can never inject a header.

Out: DNS, DKIM/SPF/DMARC/ARC verification, message parsing, the header field name (callers pass the value), comments as data (dropped; the earlier evaluation showed comments carrying text like `dmarc=pass` that must never be trusted), `Received` parsing, logging and warnings.

**README pattern** (written generically):
- Use `email.message_from_bytes(data, policy=email.policy.default)`, walk `msg.raw_items()` top-down, and pick the trusted header **by position**: above the receiving host's arrival `Received`, with the authserv-id equal to the expected value. Parse **only that one**. Never parse, or refuse on, headers written further down by senders: they are attacker-controlled.
- Pass the raw value from `raw_items()`, with a trailing CRLF stripped (AU-Q29).
- Treat `AuthResultsError`, or any other exception, as "refuse".
- Match by token (`r.method == "dmarc" and r.result == "pass"`), never by substring.
- Use `get_unique()` for identity properties such as `header.from`, `header.d` and `header.i`, so a duplicate refuses; compare domains through `ascii_domain()`. For DKIM, the signing domain is `header.d` or, if absent, `domain_of(header.i)`.
- Refuse a trusted header that carries a `Deviation` outside the set the caller has checked and expects (for example `PVALUE_TSPECIALS` for Google's `header.b`), or use `strict_syntax`.
- The defaults `max_length=8192` and `ascii_only=True` are the recommended settings for this use: the length check runs before anything else, so an oversized or deeply nested value costs O(1) to refuse, and refusing non-ASCII removes the Unicode look-alike keywords and confusable punctuation described in G14 and section 10 (AL4 README items).

## 2. API

### 2.1 Entry points

```python
def parse(
    value: str,
    *,
    max_length: int = 8192,
    max_results: int = 64,
    max_properties: int = 64,
    max_comment_depth: int = 16,
    ascii_only: bool = True,
    strict_syntax: bool = False,
    require_registered: bool = False,
) -> AuthenticationResults: ...
def parse_arc(value: str, **same_keywords) -> ArcAuthenticationResults: ...
```

- Keyword-only limits. Each limit must be at least 1, or the call raises `ValueError` (a caller bug, not a parse error; the one documented exception to the closed set, and raised before any input is read). Exact rules in AU-Q15(c).
- Order of checks: type (`str`; anything else is `AuthResultsError(INVALID_TYPE)`), then length, then a character scan of the whole string, then tokenising. The length check runs first, so a 1 MB input costs O(1) before refusal.
- Defaults (AU-Q4): 8 KiB length, proposed by the earlier evaluation; comment depth 16 (real headers nest 0 to 2 levels, UNVERIFIED); 64 results and 64 properties per result.

### 2.2 Types (all `@dataclass(frozen=True, slots=True)`, tuples not lists, `py.typed` shipped)

- `AuthenticationResults`: `authserv_id: str | None` (as given; `None` only for `MISSING_AUTHSERV_ID`, AU-Q35), `version: int` (1 when absent), `version_given: bool`, `none: bool`, `results: tuple[Result, ...]` (empty if `none`), `deviations: frozenset[Deviation]`. Methods: `to_value() -> str`, `results_for(method) -> tuple[Result, ...]`.
- `ArcAuthenticationResults`: `instance: int`, `payload: AuthenticationResults`.
- `Result`: `method: str`, `method_version: int | None`, `result: str`, `reason: str | None`, `properties: tuple[Property, ...]`, `registered: bool` (method, method version and result all in the snapshot). Methods: `get(ptype, name) -> tuple[Property, ...]` (all matches, in order) and `get_unique(ptype, name) -> Property | None`, which raises `AuthResultsError(DUPLICATE_PROPERTY)` if there are two. Security callers must not pick "the first `header.from`".
- `Property`: `ptype: str | None` (`None` only for a bare `name=value` deviation), `name: str`, `value: str` (quotes removed, quoted-pairs resolved), `raw: str` (exact source text), `quoted: bool`, `registered: bool`.
- `ErrorReason(enum.StrEnum)`, closed: `INVALID_TYPE`, `EMPTY`, `TOO_LONG`, `NON_ASCII`, `CONTROL_CHAR` (includes bare CR, NUL, DEL and lone surrogates from `surrogateescape`), `UNTERMINATED_COMMENT`, `UNTERMINATED_QUOTED_STRING`, `NESTING_TOO_DEEP`, `SYNTAX`, `UNSUPPORTED_VERSION`, `TOO_MANY_RESULTS`, `TOO_MANY_PROPERTIES`, `DUPLICATE_REASON`, `DUPLICATE_PROPERTY`, `DEVIATION` (`strict_syntax`), `UNREGISTERED` (`require_registered`), `BAD_ARC_INSTANCE`, `INTERNAL`.
- `Deviation(enum.StrEnum)`, closed:
  - `BARE_PROPERTY` (Microsoft `action=none`, no ptype);
  - `PVALUE_TSPECIALS` (`/`, `=` or `?` inside an unquoted pvalue with no `@`, as in Google's `header.b=Ab+/cd=`; an RFC 2045 token excludes them, and authres accepts them, as observed in the earlier evaluation). `/ = ?` before an `@` are legal local-part atext and not a deviation (SRS `smtp.mailfrom`). The deviation set is exactly `/ = ?` (AU-Q22);
  - `TRAILING_SEMICOLON`;
  - `LF_FOLDING` (LF plus WSP instead of CRLF plus WSP);
  - `MISSING_AUTHSERV_ID` (AU-Q35, added by the AL2a amendment).

  The list is closed and grows only by a release, with a fixture that justifies it.

### 2.3 Errors

- One class: `class AuthResultsError(ValueError)` with `.reason: ErrorReason` and `.position: int | None` (character offset). Subclassing `ValueError` keeps it catchable by callers that already catch `ValueError`.
- **The message never contains input text**, only reason and offset. Headers hold addresses (PII), and callers log exceptions. A test asserts this for every reason.
- The public functions wrap the internals: any `Exception` not already an `AuthResultsError` becomes `AuthResultsError(INTERNAL)` chained with `from` to a sanitised surrogate that carries only the original exception's type name and traceback, never its message; an `AuthResultsError` passing through has its context suppressed. So no input text reaches a logged traceback either (AL2a red-team F2, 2026-11-06). Frame locals, as error trackers capture them, are out of reach; the README says so. `BaseException` (KeyboardInterrupt, SystemExit) passes through. Hypothesis asserts `INTERNAL` never occurs, so the wrapper is a guarantee, not a way to hide bugs.

### 2.4 Strict and lenient

- `strict_syntax=False` (default): the deviations above are accepted and recorded in `deviations`. With `True`, the first one raises `DEVIATION` with its position.
- `require_registered=False` (default): unregistered methods, ptypes, properties and results (`x-dmarc`, `compauth`, ptype `dns` if the snapshot lacks it, `policy.expired` from RFC 8601 B.7) are **kept** with `registered=False`. With `True`, they raise `UNREGISTERED`. Never drop silently, unlike authres (the earlier evaluation saw `action=none` vanish).
- README: RFC 8601 §4.1 and §2.3 say consumers ignore unregistered results and must not decide on unknown ptypes (VERIFIED), so callers should test `registered`. RFC 8601 §2.7.6 adds that a production consumer SHOULD ignore or delete the whole field if it includes an unknown method (G17).
- `version` other than 1: `UNSUPPORTED_VERSION` (RFC 8601 §2.6 lets a parser stop, VERIFIED). A method version other than the registered one is kept with `registered=False` (the RFC says SHOULD ignore it, VERIFIED).

### 2.5 Case and IDNA

- **Lowercased on output, A to Z only** (`_checks.ascii_lower`, never `str.lower`): method, result, ptype, property name, and the bare-property name.
  - The literals `none`, `reason`, `mailfrom` and `rcptto` match in any case. RFC 5234 §2.3: "ABNF strings are case insensitive and the character set for these strings is US-ASCII." (VERIFIED)
  - For `Keyword` (method, result, ptype, property) no imported text settles case. RFC 8601 says nothing except one rule for producers, in §2.2: an SMTP command is represented by converting it to lowercase and dropping any spaces (VERIFIED).
  - RFC 5321 §2.4 says SMTP verbs and argument values are not case sensitive, with the sole exception of a mailbox local-part (VERIFIED). That sentence is about SMTP's own syntax, so applying it to RFC 8601 keywords is a judgement call (AU-Q34; answered yes).
- **One exception is case-sensitive:** the ARC `i` (RFC 8617 §3.9 `instance` rule uses `%s`; RFC 7405 §2.1 defines `%s` as case-sensitive, VERIFIED). So `I=1` is `SYNTAX` (G12).
- **Kept exactly as given:**
  - authserv-id: the unquoted content (G6). RFC 8601 §2.5 says nothing about its case (VERIFIED, silent).
  - Property values and the `reason` value. RFC 2045 §5.1: "Parameter values are normally case sensitive" (VERIFIED).
- **Domain comparison is the caller's job, through `ascii_domain`.** RFC 5321 §2.4: "Mailbox domains follow normal DNS rules and are hence not case sensitive." (VERIFIED)
- **Keyword positions are ASCII only.**
  - RFC 5321 §4.1.2 defines `Keyword` as `Ldh-str`: letters, digits and `-`, ending in a letter or digit (`Ldh-str` and `Let-dig` rules, VERIFIED), with ALPHA and DIGIT ASCII-only (RFC 5234 Appendix B.1, VERIFIED).
  - With `ascii_only=True`, the character scan raises `NON_ASCII` first.
  - With `ascii_only=False`, a non-ASCII character where a keyword is being read is `SYNTAX` at that character. So the Kelvin-sign `dkim` and the long-s `spf` give `SYNTAX`, never a registered result.
- **Helpers** (zero-dependency; exact edge behaviour in AU-Q33 and AU-Q38):
  - `domain_of(value) -> str | None`: the text after the last `@`, or the whole value if there is no `@`; `None` if that text is empty.
  - `ascii_domain(value) -> str | None`: the value lowercased with `ascii_lower` if it is one or more dot-separated sub-domains by RFC 5321 §4.1.2 (`sub-domain` rule: starts with a letter or digit, then an optional `Ldh-str`; VERIFIED). Otherwise `None`, which covers an empty label, a trailing dot, `_`, `@`, and any non-ASCII character (so any U-label). A non-`str` argument raises `INVALID_TYPE` (AU-Q15b); a `str` subclass is normalised to an exact `str` from its underlying text, never via its own `__str__` or other overrides (AU-Q38(3)).
  - `xn--` A-labels pass because they are LDH strings. Punycode is not validated, and there are no label or total length checks (RFC 5321 §4.1.2 has none).
- **U-label conversion is left to the caller** with the `idna` package (AU-Q5). The claim that stdlib `str.encode("idna")` is IDNA 2003 and differs stays UNVERIFIED, not used by the case table.

---

## 3. Grammar coverage (RFC 8601 §2.2, VERIFIED rule by rule in 3.1, 2026-11-06)

Each bullet points to the 3.1 item (G1 to G19) that cites the source and records the decision.

- **Value boundaries (G1):**
  - The caller passes the value only: no field name, no final CRLF.
  - A trailing CRLF or LF is `CONTROL_CHAR` (AU-Q29).
  - `parse_arc` takes the instance tag, optional CFWS, `;`, then the payload (G12).
- **Lexing (G3):**
  - Two lexical classes. A **keyword** is `Ldh-str`, ASCII only, and cannot end in `-`. A **token** is RFC 2045: printable US-ASCII except SPACE, CTLs and tspecials. `.` is a token character, so it belongs inside a token.
  - The parser reads keywords only where the grammar has `Keyword` or a literal, and tokens only where it has `value` or `pvalue`.
  - `.` is a separator only between ptype and property.
  - Whether the scanner is driven by the parser or emits tokens with an "adjacent to the previous token" flag is AL2b's choice. It stays one linear pass, with constant lookahead and no backtracking.
  - CFWS is never allowed inside a keyword, a token, or an address-form pvalue (G10).
- **Comments (G4):**
  - Comments use a depth counter. `\` quoted-pairs work inside them.
  - Going over `max_comment_depth` gives `NESTING_TOO_DEEP` at the first `(` beyond the limit. End of input inside a comment gives `UNTERMINATED_COMMENT` at the outermost unclosed `(`. The first fault met by the single pass wins (AU-Q36).
  - A `"` inside a comment is ordinary comment text (RFC 5322 `ctext` includes it).
  - Comment content is discarded.
- **Quoted strings (G6):**
  - `"` ... `"`, with `qtext`, quoted-pairs and FWS inside, no nesting.
  - The value is the content between the quotes, with quoted-pairs resolved and fold line breaks removed (WSP kept).
  - A quoted-string brings no CFWS of its own; only the RFC 8601 rules put CFWS around it (AU-Q25).
  - End of input inside a quoted string gives `UNTERMINATED_QUOTED_STRING` at the opening `"`.
- **Folding (G5):**
  - CRLF followed by SP or HTAB is FWS. LF followed by WSP is accepted as `LF_FOLDING`.
  - Several folds in a row, and continuation lines made only of WSP (obs-FWS), are accepted with no deviation.
  - A bare CR, CRLF or LF not followed by WSP, NUL, other C0 controls except HTAB, DEL, lone surrogates, C1 controls U+0080 to U+009F, and Unicode space and format characters (AU-Q41) are all `CONTROL_CHAR`, whatever `ascii_only` says (AU-Q37).
  - `\` followed by CR or LF is `CONTROL_CHAR` at the CR or LF (AU-Q29).
- **CFWS spots (G4):** CFWS is allowed exactly where the grammar puts it. It is required in three places only:
  - between the authserv-id and the version;
  - before `reason`;
  - before the first property.

  It is optional between properties, so `header.s="a"header.d=b` is valid. This includes CFWS around `/`, `=` and `.`, as in RFC 8601 B.7.
- **Payload (G1, G11):**
  - Optional CFWS, the authserv-id, an optional version (after required CFWS), then either the `none` form or one or more resinfo, then optional CFWS (RFC 8601 §2.2, `authres-payload` rule).
  - The authserv-id is a `value`, either a token or a quoted-string. `authserv_id` holds the unquoted content, so `""` is accepted as the empty string (AU-Q30). A missing authserv-id is `MISSING_AUTHSERV_ID` (AU-Q35, AU-Q39).
  - The version is digits only, so `1.0` is `SYNTAX`.
  - Leading zeros are accepted (`01` is version 1).
  - Any value other than 1 is `UNSUPPORTED_VERSION` at its first digit. Digits are compared after stripping leading zeros, never with `int()` on an unbounded run (AU-Q24).
- **`none` (G7):**
  - Only as `; none` (any case, CFWS allowed around it) with nothing but CFWS after it.
  - `nonexistent=pass` is the method `nonexistent`: the keyword must match as a whole token.
  - `; none=pass` follows the grammar and is a result with the unregistered method `none` (AU-Q21).
  - `; none;` and `; none; dkim=pass` are `SYNTAX`.
- **resinfo (G8, G11):**
  - `;`, a method with an optional `/` and method version, `=`, a result, an optional `reason`, then optional properties (RFC 8601 §2.2, `resinfo` and `methodspec` rules).
  - `method_version` is kept as given, with leading zeros stripped. More than 9 significant digits is `SYNTAX` (AU-Q24). A version other than 1 is kept with `registered=False`.
  - `reason=` comes at most once, before the properties. A second `reason`, anywhere, is `DUPLICATE_REASON`. A first `reason` after a property is `SYNTAX` (AU-Q6, AU-Q26). The reason value is `value` only (token or quoted-string), never the address form.
- **propspec (G9):**
  - ptype, `.`, property, `=`, pvalue (RFC 8601 §2.2, `propspec` rule), with ptype and property as keywords.
  - Multiple and repeated properties are kept in order.
  - A bare `name=pvalue` in the property list is `BARE_PROPERTY` with `ptype=None` and `registered=False` (AU-Q27). The name `reason` is never treated as a bare property (AU-Q26).
- **pvalue (G10):** after optional CFWS, a pvalue is one of:
  - a quoted-string, which sets `quoted=True`, or `"local"@domain` when a `@` follows straight after it;
  - a token;
  - an address: an optional local-part, `@`, and a domain-name, for example `@example.com`, `a@example.com`, `"a b"@example.com` or `SRS0=x=y@fwd.example`.

  In detail:
  - The local-part is a dot-atom-text or a quoted-string. obs-local-part and CFWS inside or around the address are `SYNTAX` (AU-Q18).
  - The domain-name has two or more LDH labels and no trailing dot. Otherwise it is `SYNTAX` (AU-Q24 domain part; positions in AU-Q38(2)).
  - Address-form `value` is the source text of the address, quotes included, with folds unfolded, and `quoted=False` (AU-Q23, AU-Q42).
  - An unquoted run with no `@` that contains `/`, `=` or `?` is accepted as `PVALUE_TSPECIALS` at the first such character. Any other tspecial in an unquoted pvalue (`< > , : [ ] \ @`, except as above) is `SYNTAX` (AU-Q22).
  - `raw` is the exact source slice of the pvalue, without its surrounding CFWS.
- **Separators (G8, AU-Q28):**
  - `;;`, a `;` straight after the authserv-id or version with nothing after it (`example.com;`), and `; none;` are all `SYNTAX`.
  - A final `;` followed only by CFWS, after at least one resinfo, is `TRAILING_SEMICOLON` at that `;`.
- **Reject list:**
  - an empty value, or one made only of WSP or FWS (`EMPTY`);
  - a value that is only comments (`SYNTAX`);
  - the authserv-id alone (`SYNTAX` at `len(value)`);
  - `;;`, `=pass`, `dkim=`, `dkim pass`, `dkim=pass"x"`, `.from=x`, `header.=x`, `header.d=`, `header.d=example .com`, a ptype with no property;
  - a keyword ending in `-` (`SYNTAX` at the keyword's start), or containing `_` (`SYNTAX` at the `_`);
  - anything after `; none`;
  - under `strict_syntax`, each deviation (`DEVIATION`).
- **Non-ASCII (G14):** refused by default (`ascii_only=True`: `NON_ASCII` at the first non-ASCII character, found by the character scan). With `ascii_only=False`:
  - UTF-8 is allowed in comments, quoted-strings, token-form values (authserv-id, pvalue, reason), local-parts and domain-name labels (AU-Q18a).
  - It is never allowed in keywords, the ARC `i`, digits or specials (`SYNTAX`); C1 controls and Unicode space and format characters stay `CONTROL_CHAR` (AU-Q37, AU-Q41).
  - No IDNA validation is done.
- **ARC (G12):**
  - `i` is case-sensitive.
  - The position is one or two digits, between 1 and 50. `i=01` is instance 1 (AU-Q18d).
  - A digit run of 3 or more digits, or a value of 0 or of 51 and above, is `BAD_ARC_INSTANCE` at its first digit.
  - Any other fault in the instance part (missing `i`, `I`, no `=`, no digits, no `;`) is `SYNTAX`.
- **Registered flags (G16, AU-Q31):**
  - `Result.registered`: the method is in the snapshot, the version is absent or 1, and the result is listed for that method.
  - `Property.registered`: the (method, ptype, property) row exists. RFC 8601 §2.3: "Combinations of ptypes and properties are registered ... coupled with the authentication methods with which they are used" (VERIFIED).

---

### 3.1 Grammar decisions (AL3a-R, 2026-11-06)

Read through WebFetch from the rfc-editor.org plain text, with exact excerpts of at most 125 characters each. "VERIFIED" here means checked against an exact excerpt. Prose quotes that were read in pieces are joined by " / ". Grammar rules are cited by RFC, section and rule name, not copied (G18). The decisions bind AL3a and AL2b. Each judgement call points to an AU-Q in section 10.

**G1. Payload structure (RFC 8601 §2.2, VERIFIED)**

Sources: RFC 8601 §2.2, rules `authres-header-field`, `authres-payload`, `authserv-id` (a `value`), `authres-version` (digits, optional CFWS), `no-result`, `resinfo`, `methodspec`, `reasonspec`, `propspec`, `method` (a `Keyword`, optionally `/` and `method-version`), `method-version`, `result`, `ptype` and `property` (each a `Keyword`; `property` also allows the `special-smtp-verb` literals `mailfrom` and `rcptto`), and `pvalue` (a `value` or an address form, with optional CFWS around it).

Decisions:
- The value excludes the field name and the final CRLF. A trailing CRLF or LF is `CONTROL_CHAR` (AU-Q29).
- The payload needs at least one resinfo, so the authserv-id alone is `SYNTAX` at `len(value)`.
- `none` and the resinfo list exclude each other.

**G2. Imported rules (RFC 8601 §2.2 prose, VERIFIED)**

RFC 8601 §2.2 imports:
- `local-part` from RFC 5322 §3.4.1, as modified by RFC 6531;
- `CFWS` from RFC 5322 §3.2.2;
- `Keyword` from RFC 5321 §4.1.2, "further constrained by the necessity of being registered in the Internet Assigned Numbers Authority (IANA) registry" relevant to its context;
- `value` from RFC 2045 §5.1, with `quoted-string` updated by RFC 6532;
- `domain-name` from RFC 6376 §3.5.

It also says that a pvalue identifying an email identity "MUST use the right-hand portion of that ABNF definition" (the address form), and that "The "propspec" may be omitted if, for example, the method was unable to extract any properties".

Decisions:
- The "registered" constraint on Keyword is semantic. It is reported through `registered` flags, not as `SYNTAX` (section 2.4).
- The email-identity MUST binds producers only. A consumer accepts a quoted-string or token form as well.

**G3. Tokens and tspecials**

Sources:
- RFC 5321 §4.1.2 (VERIFIED): rules `Keyword`, `Ldh-str`, `Let-dig`, `sub-domain`.
- RFC 5234 Appendix B.1 (VERIFIED): core rules `ALPHA` (ASCII letters), `DIGIT` (ASCII digits), `CTL` (U+0000 to U+001F and U+007F), `CHAR`, `VCHAR` (U+0021 to U+007E), `WSP` (SP or HTAB).
- RFC 2045 §5.1 (VERIFIED): rules `value` (token or quoted-string), `token` (any US-ASCII CHAR except SPACE, CTLs or tspecials) and `tspecials` (the 15 characters `( ) < > @ , ; : \ " / [ ] ? =`, which must be in a quoted-string to be used within parameter values). The section notes that tspecials are RFC 822's specials plus `/`, `?` and `=`, minus `.`.

Decisions:
- **Keyword characters:** `[A-Za-z0-9-]`, not ending in `-`. A keyword may start with a digit or `-`. A run ending in `-` is `SYNTAX` at the run's first character. Any other character where a keyword continues (`_`, `.` outside ptype.property, non-ASCII) ends the keyword, and the parser then needs a legal next character or raises `SYNTAX` there.
- **Token characters (ASCII):** ``! # $ % & ' * + - . 0-9 A-Z ^ _ ` a-z { | } ~``. That is printable ASCII minus the 15 tspecials.
- **`atext`** (G10) equals the token characters minus `.` plus `/ = ?`. This identity drives AU-Q22.
- **Lexing is context-dependent:** `header.d` must split at `.`, while the value `example.com` keeps it. AL2b chooses the mechanism (section 3, Lexing).

**G4. CFWS and comments (RFC 5322, VERIFIED)**

Sources: RFC 5322 §3.2.2, rules `FWS`, `ctext` (printable US-ASCII except `(`, `)` and `\`, plus `obs-ctext`), `ccontent`, `comment` (nestable), `CFWS`; §3.2.1, rule `quoted-pair` (`\` followed by VCHAR or WSP, plus `obs-qp`); §4.2, `obs-FWS`; §4.1, `obs-qp` (`\` followed by NUL, an obsolete control, LF or CR) and `obs-ctext`. §3.2.2 also says: "Runs of FWS, comment, or CFWS that occur between lexical tokens in a structured header field" / "are semantically interpreted as a single space character."

CFWS spots read off G1. "Req" means at least one CFWS (FWS or a comment) is needed:

| # | Spot | Rule |
|---|---|---|
| 1 | before authserv-id | opt |
| 2 | authserv-id to version | **req** |
| 3 | after version | opt |
| 4 | before each `;` | opt |
| 5 | after `;` (before `none` or method) | opt |
| 6 | method to `/`, `/` to digits, after digits | opt |
| 7 | around methodspec `=` | opt |
| 8 | result (or result-plus-version) to `reason` | **req** |
| 9 | `reason` to `=` to value | opt |
| 10 | result or reason value to first propspec | **req** |
| 11 | around `.` in propspec, property to `=` | opt |
| 12 | `=` to pvalue, pvalue to next propspec or `;` | opt |
| 13 | after the last item | opt |
| 14 | inside keyword, token, digits, address form | none |

Decisions:
- `dkim=pass"x"` is `SYNTAX` at `"`, because spot 10 is required.
- `header.s="a"header.d=b` and `header.d=a.example(c)header.s=x` are valid (spot 12 is optional).
- A comment alone satisfies a required spot.
- Comment content is never data.

**G5. Folding (RFC 5322)**

Sources:
- RFC 5322 §3.2.2, `FWS` rule (VERIFIED).
- §2.2.3: "Unfolding is accomplished by simply removing any CRLF that is immediately followed by WSP." (VERIFIED, fragment)
- §4: obsolete forms "MUST be accepted and parsed by a conformant receiver." (VERIFIED, fragment)
- §3.2.2 producer rule: folding white space "MUST NOT be inserted in such a way that any line" / "of a folded header field is made up entirely of WSP characters and nothing else." (VERIFIED)

Decisions:
- CRLF followed by WSP is FWS. LF followed by WSP is FWS plus the `LF_FOLDING` deviation, at the LF.
- Several folds in a row and whitespace-only continuation lines are accepted with no deviation. This is obs-FWS, which a receiver MUST accept.
- A bare CR, or CRLF or LF not followed by WSP (including at the end of the value), is `CONTROL_CHAR`: at the CR for a CRLF, at the LF for a bare LF (AU-Q38(1)).
- obs-qp: `\` followed by CR or LF is `CONTROL_CHAR` at the CR or LF. `\` followed by another control is already `CONTROL_CHAR` from the character scan.
- All of this is AU-Q29.

**G6. Quoted strings**

Sources:
- RFC 5322 §3.2.4 (VERIFIED): rules `qtext` (printable US-ASCII except `"` and `\`, plus `obs-qtext`), `qcontent`, `quoted-string` (which has its own optional CFWS on each side).
- RFC 5322 §3.2.4 prose: "the quoted-string is what is contained between the two quote characters" and "the CRLF in any FWS/CFWS that appears within the quoted-string are semantically "invisible"" (VERIFIED, fragments).
- RFC 2045 §5.1: "Note that the value of a quoted string parameter does not include the" / "quotes." (VERIFIED)
- RFC 6532 §3.2 extends `qtext` with `UTF8-non-ascii` (VERIFIED).

Decisions:
- The value is the content with quoted-pairs resolved (`\x` becomes `x`, `\ ` becomes space) and fold line breaks removed (WSP kept).
- An empty `""` is allowed.
- The quoted-string's own CFWS from RFC 5322 is not used. Only the RFC 8601 spots apply (AU-Q25). So `reason="x"header.d=y` is `SYNTAX`.

**G7. `none` (RFC 8601 §2.2, VERIFIED)**

Sources: RFC 8601 §2.2, `no-result` rule (optional CFWS, `;`, optional CFWS, the literal `none`); its grammar comment says this special case indicates that no message authentication was performed. RFC 5234 §2.3: "ABNF strings are case insensitive" (VERIFIED).

Decisions:
- `; NONE (x)` is valid, with `none=True` and `results=()`.
- `; nonexistent=pass` is a result.
- `; none=pass` is a result with the method `none` and `registered=False`, because the grammar allows the Keyword `none` (AU-Q21).
- `; none;`, `; none; x=y` and `; none x` are `SYNTAX` at the first character after `none` and its CFWS.
- `none` counts as 0 results for `max_results`.

**G8. Reason order and separators**

Source: RFC 8601 §2.2, `resinfo` rule: the reasonspec is optional, comes once, and comes before the properties (VERIFIED).

Decisions:
- A second `reason` (any case, followed by optional CFWS and `=`) anywhere in the same resinfo is `DUPLICATE_REASON` at the second `reason`.
- A first `reason` after a property is `SYNTAX` at that `reason` (AU-Q6).
- `reason.x=y` is a propspec with ptype `reason` (unregistered).
- The reason value is `value` only. `reason=a@b` is `SYNTAX` at `@`, and `reason=a/b` is `SYNTAX` at `/`, with no `PVALUE_TSPECIALS`.
- Separators are AU-Q28. `;;` and `example.com;` are `SYNTAX`. A final `;` plus CFWS after at least one result is `TRAILING_SEMICOLON`.

**G9. propspec and bare properties**

Sources: RFC 8601 §2.2, `propspec` rule (VERIFIED), and the Appendix B.7 example, which puts comments and whitespace around the `.` and the `=` of `policy.expired` (VERIFIED; the example text is in G19).

Decisions:
- A ptype or property keyword followed by CFWS then `.` is valid.
- A bare keyword, optional CFWS, `=` and a pvalue at a property position is `BARE_PROPERTY` at the name (AU-Q27).
- `max_properties` counts propspecs and bare properties together. `TOO_MANY_PROPERTIES` is raised at the ptype or bare name of property N+1.

**G10. pvalue forms**

Sources:
- RFC 5322 §3.2.3 (VERIFIED): `atext` (ALPHA, DIGIT and ``! # $ % & ' * + - / = ? ^ _ ` { | } ~``), `dot-atom-text` (atext runs separated by single dots), `dot-atom` (dot-atom-text with optional CFWS on each side).
- RFC 5322 §3.4.1 (VERIFIED): `local-part` (dot-atom, quoted-string or obs-local-part).
- RFC 5322 §4.4 (VERIFIED): `obs-local-part` (words separated by dots), `word` (atom or quoted-string), `atom` (atext with optional CFWS on each side).
- RFC 6376 §3.5 (VERIFIED): `domain-name` (two or more sub-domains, from RFC 5321 Domain, excluding address-literal) and `sig-i-tag` (an optional local-part, `@`, domain-name).
- RFC 6531 §3.3 (VERIFIED): extends `atext` with `UTF8-non-ascii` and `sub-domain` with `U-label`.

Decisions:
- **Scan.** After the optional CFWS, read either a quoted-string, or a maximal run of token characters plus `/ = ? @`. In both cases a `@` straight after the quoted-string or inside the run continues into the address form. No CFWS is allowed inside, and the run stops at WSP, CR, LF, `(`, `)`, `;`, `"` or end of input.
- **Classify:**
  1. A run containing `@`: it must be an optional dot-atom-text, `@` and a domain-name, or a quoted-string, `@` and a domain-name. Otherwise `SYNTAX` at the first offending character. The result is address form with `quoted=False` (AU-Q23, AU-Q42). `/ = ?` in the local-part are legal atext and not a deviation, so SRS addresses are clean.
  2. A run with no `@` made only of token characters: a token.
  3. A run with no `@` containing `/`, `=` or `?`: `PVALUE_TSPECIALS` at the first of them, with value equal to the run (AU-Q22).
  4. Any other tspecial (`< > , : [ ] \`) is `SYNTAX` at that character.
- **Domain-name after `@`:** two or more labels, each a letter or digit followed by an optional `Ldh-str`, no trailing dot, no address-literal. Otherwise `SYNTAX` (AU-Q24; positions in AU-Q38(2)). With `ascii_only=False`, a label may also contain non-ASCII characters (AU-Q18a), with no IDNA check.
- **Narrowings of the imported grammar** (AU-Q18b): obs-local-part (`a . b@x.example`, `"a".b@x.example`) and CFWS between the local-part and `@` (allowed by `dot-atom`'s optional CFWS) are `SYNTAX`.
- **Quoted-string pvalue** not followed by `@`: `quoted=True`, value unquoted (G6).
- **`raw`** is the exact source slice of the pvalue without its surrounding CFWS. Folds inside a quoted-string are kept in `raw` and removed from `value` (AU-Q18c, AU-Q42).

**G11. Version (RFC 8601 §2.2 and §2.6, VERIFIED)**

Sources:
- RFC 8601 §2.2, rules `authres-version` and `method-version` (digits, optional CFWS). Their grammar comments say that this specification is version 1 and that an absent version means version 1, and that a method version is from the "Email Authentication Methods" registry, with 1 assumed when absent.
- §2.6: "That is, if a parser finds a version after an authserv-id that it does not explicitly know," / "it can immediately discontinue trying to parse, since what follows might not be in an expected format."
- §2.6: "For a method version, the parser SHOULD ignore a method result if the version is not supported".

Decisions:
- `1.0` is `SYNTAX` at the `.`.
- Leading zeros are accepted: `01` and `0001` mean 1.
- The authserv-id version is compared as digits with leading zeros stripped. Anything other than `1` is `UNSUPPORTED_VERSION` at the first digit, and never goes through `int()`. CPython's int and str conversions raise `ValueError` above 4,300 digits, which would surface as `INTERNAL`, and an 8 KiB value can hold more than that.
- `method_version` keeps the int. More than 9 significant digits is `SYNTAX` at its first digit (AU-Q24). A version other than 1 means `registered=False`. Under `require_registered` it is `UNREGISTERED` at the method keyword.
- `Result.method_version` is `None` when absent (AU-Q15e).

**G12. ARC instance (RFC 8617, VERIFIED)**

Sources:
- RFC 8617 §4.1.1: rules `arc-info` (instance, optional CFWS, `;`, payload) and `arc-authres-header`. (An earlier plan draft cited §4.1.1 for `instance`; it is in §3.9.)
- §3.9: rules `position` (one or two digits, commented as 1 to 50) and `instance` (optional CFWS, a case-sensitive `i` via `%s`, optional CFWS, `=`, optional CFWS, position).
- §4.2.1: "Instance tag values can range from 1-50 (inclusive)."
- RFC 7405 §2.1: `%s` marks a case-sensitive string (VERIFIED).
- Status line: "Category: Experimental".
- No text covers leading zeros (VERIFIED, silent).

Decisions:
- `i=01` to `i=09` mean instances 1 to 9, because the grammar allows two digits (AU-Q18d).
- A digit run of 3 or more, `0`, `00`, or 51 to 99 is `BAD_ARC_INSTANCE` at the first digit.
- A missing `i`, `I=` (case-sensitive), a missing `=`, no digits, a missing `;`, or `i=1x` is `SYNTAX` (AU-Q32).
- `max_length` counts the whole value. Section 4 property 4 (case changes) excludes `i`.

**G13. Keyword case**

Sources:
- RFC 5234 §2.3: "ABNF strings are case insensitive and the character set for these strings is US-ASCII." / "To specify a rule that is case sensitive, specify the characters individually." (VERIFIED)
- RFC 5321 §2.4 (VERIFIED): "Verbs and argument values (e.g., "TO:" or "to:" in the RCPT command and extension name keywords) are not case sensitive," / "with the sole exception in this specification of a mailbox local-part" / "(SMTP Extensions may explicitly specify case-sensitive elements)."
- RFC 2045 §5.1: "The type, subtype, and parameter names are not case sensitive." (VERIFIED)
- RFC 8601 §2.2: "represents that command by converting it to lowercase and dropping any spaces (e.g., "MAIL FROM" becomes "mailfrom"," (VERIFIED)

Decision:
- Literals are case-insensitive by RFC 5234.
- Keywords are matched and stored ASCII-lowercased. This is a judgement call (AU-Q34).
- `i` is the only case-sensitive literal.

**G14. Where UTF-8 is allowed (only with `ascii_only=False`)**

Sources:
- RFC 8601 §1.5.2 (VERIFIED): "Generally speaking, these documents allow UTF-8 in most places that free-form text can be found" / "and U-labels where domain names can be used, and this document extends Authentication-Results accordingly."
- RFC 8601 §2.5: "Note that in an EAI-formatted message, this identifier may be expressed in UTF-8." (VERIFIED)
- RFC 8601 §2.7.1: "Note that in an EAI-formatted message, the values of the "d" and "i" properties can be expressed in UTF-8." (VERIFIED)
- RFC 8601 §2.7.2: "Note that in an EAI-formatted message, the local-part of the "mailfrom" can be expressed in UTF-8" / "and the domain part can be expressed as a U-label." (VERIFIED). RFC 8601 §2.7.4 says the same for `auth` (VERIFIED).
- RFC 8601 §2.7.5: ""vbr.mv" and "vbr.md", which are already registered," / "can be expressed as U-labels." (VERIFIED)
- RFC 6532 §3.2 (VERIFIED) extends `VCHAR`, `ctext`, `atext` and `qtext` with `UTF8-non-ascii`, and notes: "Note that header field names are not on this list; these are still restricted to ASCII." RFC 6531 §3.3 extends `atext` too (G10).
- RFC 6532 §3.1: "normalization form NFC [UNF] SHOULD be used." (VERIFIED)
- RFC 2045's `token` is "(US-ASCII) CHAR" (VERIFIED), and RFC 6532 does not extend it.

| Position | UTF-8 | Basis |
|---|---|---|
| comment | yes | 6532 `ctext` |
| quoted-string (authserv-id, reason, pvalue, quoted local-part) | yes | 8601 §2.2 plus 6532 `qtext` |
| dot-atom local-part | yes | 6531 and 6532 `atext` |
| domain-name label after `@` | yes, no IDNA check | 6531 §3.3 extends `sub-domain` with U-label; 8601 §1.5.2 |
| unquoted token value (authserv-id, pvalue, reason, bare value) | yes, **judgement** | the grammar says no (2045 token is ASCII); 8601 §1.5.2, §2.5 and §2.7.1 say yes. AU-Q18a |
| keyword, `none`, `reason`, ptype, property, method, result, ARC `i`, digits, specials | never (`SYNTAX`) | `Ldh-str`, RFC 5234 ALPHA and DIGIT |
| C1 U+0080 to U+009F, lone surrogates, Unicode space and format characters | never (`CONTROL_CHAR`) | judgement, AU-Q29, AU-Q37, AU-Q41 (6532 permits C1) |

- No normalisation: values are returned as given (NFC is a producer SHOULD).
- Look-alike keywords (U+212A, U+017F) give `SYNTAX` at that character.

**G15. tspecials in values:** see G3 and G10. The accepted set for `PVALUE_TSPECIALS` is exactly `/ = ?` (AU-Q22).

**G16. IANA registry snapshot**

Source: <https://www.iana.org/assignments/email-auth/email-auth.xhtml> and `email-auth.xml`. **Last Updated 2026-05-22** (XML `<updated>2026-05-22</updated>`, VERIFIED). Three registries: Email Authentication Methods (Specification Required), Email Authentication Result Names (Specification Required), Email Authentication Property Types (Expert Review). All method versions are `1`. The registry now cites RFC 9989 for the dmarc method (it was RFC 7489) and cites "RFC-ietf-emailcore-rfc5322bis-12" in descriptions; neither changes parsing.

**Property types:** `body`, `dns`, `header`, `policy`, `smtp`.

**Methods (method / version / status: ptype.property, ...):**
- `arc` / 1 / active: `smtp.remote-ip`, `header.oldest-pass`
- `auth` / 1 / active: `smtp.auth`, `smtp.mailfrom`
- `dkim` / 1 / active: `header.d`, `header.i`, `header.b`, `header.a`, `header.s`
- `dkim-adsp` / 1 / deprecated: `header.from`
- `dkim-atps` / 1 / active: `header.from`
- `dmarc` / 1 / active (defined by RFC 9989 per the registry): `header.from`, `policy.dmarc`
- `dnswl` / 1 / active: `dns.zone`, `policy.ip`, `policy.txt`, `dns.sec`
- `domainkeys` / 1 / deprecated: `header.d`, `header.from`, `header.sender`
- `iprev` / 1 / active: `policy.iprev`
- `rrvs` / 1 / active: `smtp.rcptto`
- `sender-id` / 1 / deprecated: `header.<name of header field used by PRA>`, meaning any `header.*` (AU-Q31)
- `smime` / 1 / active: `body.smime-part`, `body.smime-identifer` (sic, as registered), `body.smime-serial`, `body.smime-issuer`
- `spf` / 1 / active: `smtp.mailfrom`, `smtp.helo`
- `vbr` / 1 / active: `header.md`, `header.mv`

**Results per method:**
- `arc`: fail, none, pass
- `auth`: fail, none, pass, permerror, temperror
- `dkim`: fail, neutral, none, pass, permerror, policy, temperror
- `dkim-adsp` (all deprecated): discard, fail, none, nxdomain, pass, permerror, temperror, unknown
- `dkim-atps`: fail, none, pass, permerror, temperror
- `dmarc`: fail, none, pass, permerror, temperror
- `dnswl`: none, pass, permerror, temperror
- `domainkeys` (deprecated): temperror, neutral, none, permerror, policy, pass, temperror. **IANA lists `temperror` twice and has no `fail`**, confirmed in the XML records (all `updated="2015-06-04"`).
- `iprev`: fail, pass, permerror, temperror
- `rrvs`: fail, none, pass, permerror, temperror, unknown
- `sender-id` (deprecated): fail, hardfail, neutral, none, pass, permerror, policy, softfail, temperror
- `smime`: fail, neutral, none, pass, permerror, policy, temperror
- `spf`: fail, hardfail (deprecated), neutral, none, pass, permerror, policy, softfail, temperror
- `vbr`: fail, none, pass, permerror, temperror

**Not registered (case-table relevant):** `x-dmarc`, `compauth`, `nonexistent`, `none` as a method, `dmarc=passed`, `dkim header.from`, `policy.expired`, `domainkeys=fail`.

**Semantics** (AU-Q31):
- `Result.registered` is true when the method is in the table, `method_version` is `None` or 1, and the result is listed for that method.
- `Property.registered` is true when the (method, ptype, property) row exists, with sender-id matching any `header.*`. A bare property is always false.
- Deprecated entries count as registered.
- The snapshot follows IANA literally, so `domainkeys=fail` has `registered=False`. `_registry.py` carries a comment on that.

**G17. What consumers must do (README only, not parser behaviour; VERIFIED)**
- RFC 8601 §2.3: "Results reported using unknown ptypes MUST NOT be used in making handling decisions."
- §4.1: "MUAs and downstream filters MUST ignore any result reported using a "result" not specified" / "in the IANA "Result Code" registry or a "ptype" not listed in the "Email Authentication Property Types" registry".
- §4.1: "Moreover, such agents MUST ignore a result indicated for any "method" they do not specifically support."
- §2.7.6: "Any MTA, MUA, or downstream filter intended for production use SHOULD ignore or delete any" / "Authentication-Results header field that includes an experimental (unknown) method identifier."

The §2.7.6 SHOULD covers the whole field; the README states it (section 2.4).

**G18. Reproducing RFC text (IETF Trust Legal Provisions, corrected TLP 5.0, effective March 25, 2015, VERIFIED)**
- §3.c.iii allows copying and distributing unmodified portions of IETF Documents, provided each portion "is clearly attributed to IETF and identifies the RFC or other IETF Document" from which it is taken.
- Legends are required where a substantial portion, and in any event more than one-fifth, of an RFC's text is reproduced.
- The code-components list includes "ABNF definitions" but not example header fields (VERIFIED).

Decisions (AU-Q19):
- The Appendix B values go in unmodified, with `cite="IETF RFC 8601, Appendix B.n (unmodified excerpt)"`.
- No ABNF is copied into tracked repository files, this plan included: cite section numbers and rule names instead. Copying ABNF would bring in the Revised BSD licence terms for Code Components.

**G19. RFC 8601 Appendix B as case data (VERIFIED line by line)**

The value is the text after `Authentication-Results:`, with the printed lines joined by CRLF and each continuation line's printed leading whitespace kept (it is valid FWS). The first line's leading space after the colon is dropped as the field separator, or kept: both are optional CFWS, and AL3a picks one and records it in `cite`. Fields (IETF RFC 8601, Appendix B, unmodified excerpts; " / " marks a line break):
- **B.2:** `example.org 1; none`
- **B.3:** `example.com;` / `spf=pass smtp.mailfrom=example.net`
- **B.4 (two fields):**
  - `example.com;` / `auth=pass (cram-md5) smtp.auth=sender@example.net;` / `spf=pass smtp.mailfrom=example.net`
  - `example.com; iprev=pass` / `policy.iprev=192.0.2.200`
- **B.5 (two fields):**
  - `example.com;` / `dkim=pass (good signature) header.d=example.com`
  - `example.com;` / `auth=pass (cram-md5) smtp.auth=sender@example.com;` / `spf=fail smtp.mailfrom=example.com`
- **B.6 (two fields):**
  - `example.com;` / `dkim=pass reason="good signature"` / `header.i=@mail-router.example.net;` / `dkim=fail reason="bad signature"` / `header.i=@newyork.example.com`
  - `example.net;` / `dkim=pass (good signature) header.i=@newyork.example.com`
- **B.7:** `foo.example.net (foobar) 1 (baz);` / `dkim (Because I like it) / 1 (One yay) = (wait for it) fail` / `policy (A dot can go here) . (like that) expired` / `(this surprised me) = (as I wasn't expecting it) 1362471462`

Expected B.7 parse:
- `authserv_id="foo.example.net"`, `version=1`, `version_given=True`.
- One `Result("dkim", 1, "fail", None, (Property("policy", "expired", "1362471462", "1362471462", False, False),), True)`.
- No deviations.

Also usable: the §2.7.6 example `example.com;` / `foo=pass bar.baz=blob (2 of 3 tests OK)`, which has the unregistered method `foo`.

**UNVERIFIED, not used by the case table:**
- The IDNA 2003 vs 2008 difference.
- That `email.policy`'s `header_source_parse` strips the final line ending from `raw_items()` values. It matters for the README's advice, and the README still says "strip a trailing CRLF".
- The RFC 6531 §1.2 statement "does not modify RFC 5322" (summary only).

---

#### Cases from the earlier evaluation (`tests/cases_spike.py`)

All 28 cases are present by name, and all 28 are definite. Two of them depended on AU-Q31 ("x-dmarc" and "from in other result": `header.from` under a method that does not register it); the answer (the (method, ptype, property) triple) makes that property `registered=False` in both. Every other property in the set has the same `registered` value under either reading.

Expected outcomes. Positions are 0-based; "ok" means it parses with no deviations unless one is named.

| # | Case | Expected |
|---|---|---|
| 1 | google-like good | ok. `header.b` value is `Ab+/cd=`; `header.i` is `@example.com` in address form, `quoted=False`; deviations `{PVALUE_TSPECIALS}` (AU-Q22). The spf comment is dropped. |
| 2 | header.d form | ok |
| 3 | upper case | ok. authserv_id `MX.Google.COM`; method, result, ptype and name lowercased; values `EXAMPLE.com` and `Example.COM` kept (AU-Q34) |
| 4 | version 1 | ok. `version=1`, `version_given=True` |
| 5 | version 2 | `UNSUPPORTED_VERSION` at 14 |
| 6 | pass in comment | ok. dkim fail |
| 7 | nested comment | ok. dkim fail |
| 8 | arc comment carrying dmarc=pass | ok. arc pass, registered, `properties=()` |
| 9 | x-dmarc | ok. `x-dmarc` unregistered; `header.from` unregistered (AU-Q31) |
| 10 | dmarc=passed | ok. `result="passed"`, `registered=False` |
| 11 | pass in quoted string | ok. `value="x; dmarc=pass"`, `quoted=True` |
| 12 | quoted value with ; and = | ok. `value="a;b=c"` |
| 13 | untrusted id | ok. authserv_id `evil.example` |
| 14 | from in other result | ok. `header.from` under `dkim` unregistered (AU-Q31) |
| 15 | lookalike from | ok |
| 16 | idna a-label | ok. Values as given |
| 17 | idna u-label | `NON_ASCII` at 39 |
| 18 | none | ok. `none=True`, `results=()` |
| 19 | nonexistent prefix | ok. Method `nonexistent`, `registered=False` |
| 20 | reason= | ok. `reason="looks ok; trust me"` |
| 21 | policy.* | ok. `policy.dmarc` is registered for dmarc |
| 22 | unknown ptype (microsoft style) | ok. `Property(None, "action", "none", "none", False, False)`; deviations `{BARE_PROPERTY}` |
| 23 | empty | `EMPTY`, position `None` |
| 24 | only id | `SYNTAX` at 13 |
| 25 | garbled | `CONTROL_CHAR` at 0 |
| 26 | unclosed comment | `UNTERMINATED_COMMENT` at 26 |
| 27 | deep nesting | `TOO_LONG` at 8192 (AU-Q14). The within-cap variant is `NESTING_TOO_DEEP` at 42 |
| 28 | folded | ok. CRLF SP and CRLF HTAB, no deviation |

## 4. Tests

Slice mapping (section 6): **AL3a**, written before the parser from the RFC and this plan: the case table, RFC and vendor fixtures, limit cases, the message-has-no-input check and the timing cases. **AL3b**, after the parser: the Hypothesis properties, the authres differential, the coverage audit and mutmut.

- **Case table** (parametrised, each with an expected parse or an expected `ErrorReason`, never just "raises"):
  - All 28 cases from the earlier evaluation, re-expressed at parse level. Notable: "unknown ptype (microsoft style)" parses with `BARE_PROPERTY`; "nonexistent prefix" parses with `registered=False`; "deep nesting" (5,000 levels, 10,026 characters) gives `TOO_LONG` under the default `max_length`, because length is checked first (2.1), and a within-cap variant (4,000 levels, 8,026 characters) gives `NESTING_TOO_DEEP` (AU-Q14); "idna u-label" gives `NON_ASCII`; "garbled" gives `CONTROL_CHAR`; "version 2" gives `UNSUPPORTED_VERSION`.
  - RFC 8601 Appendix B.2 to B.7 verbatim, B.7 especially (CFWS at every legal spot, `policy.expired`).
  - Real-world values from **public vendor documentation only** (Google, Microsoft Learn's anti-spam header page, Fastmail, Proton, Yahoo or whichever are found). Each fixture file records its source URL and read date. Domains are rewritten to RFC 2606 names and IPs to documentation ranges, so the fixture holds no personal data. Shapes are UNVERIFIED until collected.
  - Each limit at N and N+1; every `ErrorReason` reached at least once; the message-has-no-input check; non-`str` input.
- **Hypothesis properties:**
  1. Any text (full Unicode plus a header-specific alphabet) returns or raises `AuthResultsError`, never `INTERNAL`.
  2. Generated model, then `to_value()`, then `parse()`, gives an equal model (equality per AU-Q17). Then `to_value()` on that is a fixed point (idempotence).
  3. **Comment and quoted-string injection:** inserting a comment with arbitrary content at any CFWS position of a valid value leaves the parse unchanged. Placing `; dmarc=pass header.from=x` text inside any comment or quoted value never adds a result.
  4. Replacing any SP that does not already follow a fold (CRLF or LF) and is not the second character of a quoted-pair (`\ `) with CRLF SP leaves the parse unchanged (an SP after a fold would make an empty fold line, `CONTROL_CHAR`; corrected after the AL3b red-team, 2026-11-07); changing the case of any keyword, except the ARC `i`, leaves it unchanged. Replacing an SP inside a quoted-string also changes `Property.raw`, which is already outside AU-Q17's equality.
  5. Depth: `"(" * n` within `max_length` raises `NESTING_TOO_DEEP` or `UNTERMINATED_COMMENT`, never `RecursionError` or `INTERNAL`.

  Profiles: a CI profile (about 2,000 examples per property) and a nightly or manual one (100,000 or more).
- **Differential oracle:** authres 1.2.0 as a **dev-only** dependency (sdist-only, so it is built in the library's CI from a hash-pinned sdist; it never ships). On inputs both accept, compare the normalised tuple (authserv-id, version, method, result, reason, (ptype, name, value)). Known differences, each listed in the test with its reason: authres drops `action=none` (we keep it, flagged); authres raises on deep nesting with `RecursionError` (we raise our error); authres prefix-matches `none` and `reason`; authres silently drops a property whose ptype is outside smtp, header, body and policy and still parses the header (so `dns.zone`, registered by IANA, vanishes; VERIFIED at AL3b, 2026-11-07, correcting the earlier "rejects"). Each claimed difference must be shown by a test in `tests/test_differential.py`; one that the test cannot reproduce is removed from this list; quoted-pair handling (authres keeps escapes raw, we resolve them and keep `raw`); found at AL3b (VERIFIED, 2026-11-07): authres drops a quoted pvalue unless `;` or the end of the value follows it (only that property is lost), and authres stops reading CFWS after one FWS-comment pair, so in `(a) (b) reason=x` the reason is lost; authres also refuses some values we accept (a quoted authserv-id, which RFC 8601 allows, among others), each listed and tested in `tests/test_differential.py`.
- **Coverage:** 100% line and branch (`coverage.py`) for the package, enforced in CI from AL1 on. At AL3b it is also audited: the AL3a table plus the AL3b properties must reach 100% on their own, without the parser author's unit tests (section 6, AL3b).
- **Mutation testing:** `mutmut` over the tokeniser and parser modules. Target: zero surviving mutants, except ones listed in `mutmut-equivalent.md` with a reason. Run by hand or nightly, not on every push (one heavy job at a time on the maintainer's laptop).

## 5. Project setup

- **Python:** `requires-python = ">=3.11"`, CI on 3.11 to 3.15. 3.10 reached end of life on 2026-10-01, and 3.11 has security support to 2027-10 (devguide, VERIFIED). 3.11 brings `enum.StrEnum`, which the error API uses.
- **Build:** `pyproject.toml` (PEP 621), `license = "Apache-2.0"` plus `license-files`. Backend: **`flit_core`** (AU-Q7; PyPA, pure Python, no dependencies), with `uv_build` as the considered alternative. The build backend is pinned by hash through a build constraint in CI. Output: one `py3-none-any` wheel plus an sdist; `SOURCE_DATE_EPOCH` set from the tag commit.
- **Zero runtime dependencies**, enforced by a test that reads the built wheel's metadata.
- **Dev tooling:** `uv.lock` with hashes and a 7-day `exclude-newer` cooldown; Ruff (lint and format); mypy `--strict`; prek with a `.pre-commit-config.yaml`; `zizmor` on the workflows; `twine check` and `check-wheel-contents` on the build (tool choices UNVERIFIED as current; pinned at AL1).
- **CI (GitHub Actions):** `permissions: {}` at the top, `contents: read` per job; every action pinned by full commit SHA with a version comment; `actions/checkout` with `persist-credentials: false`; no `pull_request_target`; no secrets in CI at all. Matrix of 3.11 to 3.15 on `ubuntu-latest`; one job runs lint, mypy, coverage, the build and zizmor.
- **Release workflow (`publish.yml`):** on a push of tag `v*`:
  1. A `build` job (no `id-token`) checks that the tag equals the version, builds the sdist and wheel, checks them and uploads them as an artifact.
  2. A `publish` job with `environment: pypi` and `permissions: id-token: write` downloads the artifact and runs `pypa/gh-action-pypi-publish` (SHA-pinned). This is Trusted Publishing, with no API token. PyPI attestations are generated by default (PyPI docs, VERIFIED). Optional: `actions/attest-build-provenance` for GitHub-side attestations.
  3. A GitHub Release with the CHANGELOG section.

  The `pypi` environment has the maintainer as required reviewer and deployment limited to `v*` tags. A solo maintainer must not tick "prevent self-review" (UNVERIFIED option name).
- **Updates:** **Dependabot** (AU-Q8; built into GitHub, no third-party app grant) for `github-actions` and `uv`, weekly, with a 7-day cooldown if the `cooldown` option is available (UNVERIFIED).
- **Files:** `README.md` (scope, safety contract, the selection pattern, strict and lenient, the RFC 8601 warnings on unregistered results); `SECURITY.md` (GitHub private vulnerability reporting, supported versions = latest minor, what counts: any stray exception, mis-parse that creates a result, super-linear time, input text in an error message); `CONTRIBUTING.md` (setup, tests, no runtime dependencies, DCO sign-off, AU-Q9); `CHANGELOG.md` (Keep a Changelog); `LICENSE` (Apache-2.0 text); copyright line AU-Q1.
- **Semver:** 0.x until the library has run in production use. Then 1.0. Public API = the names in `__all__`, the dataclass fields, and the `ErrorReason` and `Deviation` members. Adding a member is a minor release (documented, since exhaustive `match` users notice). Removing or renaming one is a major release (breaking in 0.x minor). Registry snapshot refreshes are patch releases with the IANA "last updated" date in the CHANGELOG.
- **Repo `CLAUDE.md` (short):** the scope and out-of-scope list; non-negotiables (no runtime dependencies, no recursion, no regex over the whole input, no network, no logging, closed error set, no input text in messages, never drop data silently, no other application names in the repository); commands; the rule that publish, tag push, repo settings and any outward step need the maintainer's OK.
- **Repo settings:** a ruleset on `main` (no force push, required CI) and on `v*` tags (only the owner creates, no update or delete); Actions limited to selected, SHA-pinned actions where the setting exists (UNVERIFIED); private vulnerability reporting on.

## 6. Library slices

Order: AL1, AL2a, AL3a-R, AL3a, AL2b, AL3b, AL3c, AL3d, AL4 (AL3c, the vendor fixture sweep, and AL3d, the redaction helper, added by the maintainer on 2026-11-07) (re-split by the maintainer's decision, 2026-11-06: case-table tests before the parser). Each implementer slice goes through verifier and red-team before the next starts. AL3a is done by a fresh implementer instance that gets only this plan and the repo at the AL2a commit, not the AL2a implementer's notes; no parser code exists yet.

| Slice | Content | Acceptance (checkable) |
|---|---|---|
| AL1 (done, `942d9ba`) | Skeleton: `pyproject.toml`, empty package with `py.typed`, CI, zizmor, prek, LICENSE, SECURITY, CONTRIBUTING, CHANGELOG, CLAUDE.md, Dependabot. No release workflow yet | CI green on 3.11 to 3.15; zizmor reports nothing; every `uses:` is a 40-hex SHA; wheel tag `py3-none-any`; wheel metadata has no `Requires-Dist` |
| AL2a (done, `dfa357e`; amendment `0a68c06`) | Public API surface, no parsing logic (6.1). `_errors.py`: `ErrorReason`, `Deviation` (`StrEnum`, `auto()` values), `AuthResultsError(ValueError)` with `.reason`, `.position`, fixed message format (AU-Q15g), and the one INTERNAL guard. `_model.py`: the four frozen, slotted dataclasses with no field defaults; `results_for`, `get`, `get_unique` implemented; `to_value` stubbed. `_api.py`: `parse()` and `parse_arc()` with explicit keyword-only parameters (not `**kwargs`), keyword validation, the guard, and an internal `_parse_payload` stub. `_helpers.py`: `domain_of`, `ascii_domain` stubbed. `__init__.py`: re-exports and `__all__`. Tests: `tests/test_api.py` (survives AL2b), `tests/test_stubs.py` (deleted at AL2b), `tests/test_invariants.py` (stdlib `ast`: no direct or mutual recursion via a name-based call graph, no `import re` in the package, package imports only from an allowlist: `enum`, `dataclasses`, `typing`, `collections.abc`, `contextlib`, `functools`) | `__all__` is exactly {`parse`, `parse_arc`, `AuthenticationResults`, `ArcAuthenticationResults`, `Result`, `Property`, `ErrorReason`, `Deviation`, `AuthResultsError`, `domain_of`, `ascii_domain`} and each imports; `ErrorReason` has exactly the 18 members of 2.2 and `Deviation` the 4 (5 after the AU-Q35 amendment); `parse("x")`, `parse_arc("x")`, `to_value()`, `domain_of("x")`, `ascii_domain("x")` each raise `AuthResultsError` with `INTERNAL` and an `InternalCause` `__cause__` whose `type_name` is `"NotImplementedError"` (6.2); a monkeypatched `_parse_payload` raising `RuntimeError` gives `INTERNAL` chained with `from`, and `KeyboardInterrupt` passes through; `ValueError` for every limit at 0, -1, `True` and `"8"` and for a non-bool flag, even when `value` is not a `str`; for every `ErrorReason`, `str(err)` fullmatches `[a-z_]+( at position \d+)?`; `FrozenInstanceError` on assignment and no `__dict__`; `get_unique` raises `DUPLICATE_PROPERTY` on two matches; the invariants test passes and flags a planted recursive source string; `grep -rnE "pragma: no cover\|type: ignore" src/` is empty; coverage config unchanged and 100%; `mypy --strict` and ruff clean; `tests/test_packaging.py` unchanged and green; the verifier confirms from the diff that `_api.py` never inspects `value` |
| AL3a-R (done; architect, no code) | Verbatim re-read before AL3a: RFC 8601 §2.2 grammar and following prose, §1.5.2, §2.5, §2.7.1 to §2.7.6, §4.1, Appendix B; RFC 5322 §3.2.2 (CFWS) and §3.4.1 (local-part, dot-atom, obs-local-part); the parts of RFC 6531 and 6532 that 8601 imports; RFC 5321 §2.4 and §4.1.2 (`Keyword`, `Ldh-str`); RFC 2045 §5.1 (token, tspecials); RFC 6376 §3.5 (`domain-name`); RFC 8617 §3.9 and §4.1.1 (`instance`, `position`, including leading zeros such as `i=01`); the IANA registry (its "last updated" date and every entry the case table uses). Also the IETF Trust terms on reproducing RFC examples (AU-Q19). Output: subsection 3.1 "Grammar decisions" with a VERIFIED source per rule; each judgement call becomes an AU-Q (AU-Q18 holds the known ones) | Every grammar bullet in 2.5 and 3 that AL3a depends on is VERIFIED with a source or points to an answered AU-Q; 3.1 lists the IANA date and entries; no UNVERIFIED remains in 2.5 or 3 except items marked "not used by the case table"; the maintainer has answered AU-Q14 to AU-Q20 |
| AL3a (done, `841cb37`; fresh instance) | Case-table tests from the RFC and this plan, failing as intended until AL2b (6.2, 6.3). Case modules: `tests/cases_spike.py` (the 28 cases from the earlier evaluation, under their original names), `tests/cases_rfc8601.py` (B.2 to B.7 verbatim, cited), `tests/cases_rfc8617.py` (ARC examples, `i=` at 0, 1, 50, 51), `tests/cases_grammar.py` (section 3: reject list, `none`, reason order, CFWS spots, folding, each deviation lenient and strict, keyword case, `require_registered`, `ascii_only=False` rows per 3.1), `tests/cases_vendor.py` (public vendor docs only; URL, read date, rewrite note per case), `tests/cases_limits.py` (each limit at N and N+1, at the default and at 1 and 2, both entry points), `tests/cases_helpers.py`, `tests/cases_to_value.py` (only the forms AU-Q17 pins). Scaffolding: `tests/_case.py` (`Case`: `id`, `value`, `kwargs`, expected model or `ErrorReason`, `position`, `cite`), `tests/test_cases.py`, `tests/test_case_table_meta.py`, `tests/_pending.py`, `tests/conftest.py`. Timing cases: all-`(`, all-`\"`, all-`;` at 8192 characters with `pytest.mark.timeout`. The case helper compares a type fingerprint as well as `==` (`tuple`, `frozenset`, `bool`, `int` exactly, every deviation `type(d) is Deviation`), because `==` alone accepts a `set`, plain strings or `1` for `True`. Cases for non-ASCII look-alike keywords (Kelvin sign `K` in `dkim`, long s `ſ` in `spf`) under `ascii_only=False`, expecting no registered result to be created. Stopping rule: a case the plan cannot decide goes into the hand-off as a question and stays out of the table, never guessed. A needed new `Deviation` or API field also goes into the hand-off; it becomes an AU-Q, and if yes, a src-only AL2a amendment commit lands before AL2b | `uv run pytest` green on 3.11 to 3.15 with 0 failed, 0 xpassed, and xfailed equal to `len(PENDING_IDS)`; every parse-calling case id is in `PENDING_IDS` and every id there is collected (conftest raises a usage error otherwise); meta tests: ids unique, every `ErrorReason` except `INTERNAL` is the expected outcome of at least one case, every `Deviation` has a lenient case and a strict `DEVIATION` case, the 28 evaluation case names present exactly, every case has a non-empty `cite`, every vendor case has a URL and ISO date, vendor values use only RFC 2606 or RFC 6761 names (plus an explicit allowlist of the vendors' own service hostnames) and RFC 5737 or RFC 3849 addresses, every error case gives `position` as an int, the explicit `ANY_POSITION` marker, or `None` where AU-Q16 says the reason has no position (AU-Q16); `git diff --stat <AL2a>..<AL3a> -- src/` empty except src-only AL2a amendment commits; no new pytest marker or pyproject change; `tests/test_packaging.py` green (flat `tests/*.py`; any other file shape extends the sdist allowlist by an exact pattern in the same commit); `mypy --strict` and ruff clean (long values by implicit string concatenation, no new per-file ignores); the verifier checks at least 20 cases, including every vendor and every error-position case, against their `cite` |
| AL2b (done, `4e5f90e`; amendment `608e139`) | The `INVALID_TYPE` check (first step per 2.1, for `parse`, `parse_arc` and the helpers per AU-Q15b; until then a non-`str` gives `INTERNAL` from the stubs, and AL3a `INVALID_TYPE` cases stay pending). Normalise a `str` subclass to an exact `str` before any other step (a lying `__len__` must not bypass `TOO_LONG`). Check `isascii()` on keyword tokens before lowercasing, and lowercase with an ASCII-only table, never `str.lower()`/`casefold()` (AL2a red-team F6). Raise `AuthResultsError` from internal `except` blocks with `from None`. Known false positives of `tests/test_invariants.py` (methods are merged by name across classes): an internal method named `parse`, `get` or `next`, and any hand-written `__init__` that raises `AuthResultsError`, are flagged as recursion. Avoid them (dataclass `__post_init__` or factory functions), or, if that bends the design, the first AL2b commit may qualify method nodes by class in that one test file, touching nothing else. Uncaught shapes to avoid: `object.__getattribute__`, `functools.singledispatch`, a classmethod constructor called from `__post_init__`. Tokeniser (`_tokenizer.py`), parser (`_parser.py`), registry snapshot (`_registry.py`: Python literals, `LAST_UPDATED` equal to the AL3a-R date), helper logic, `to_value()`, `parse_arc()` (6.4). Remove the stubs and `tests/test_stubs.py`. Shrink `PENDING_IDS` as cases pass, then delete `tests/_pending.py` and the pending hook in `tests/conftest.py`. Own unit tests in new files only. Red-team repros go verbatim into `tests/cases_redteam.py` with expected outcome and cite. Disagreement with an AL3a case: stop on that case and follow 6.4 | Pytest shows 0 xfailed and 0 xpassed; `pytest tests/test_cases.py` reports exactly `len(ALL_CASES)` passed with 0 skipped and 0 deselected, and a meta check confirms the collected `test_case` ids equal the `ALL_CASES` ids; `tests/_pending.py` is gone; the AL2b diff of `tests/conftest.py` only deletes the pending hook (AL3a puts it in a clearly delimited block), and `pyproject.toml`'s pytest config (`addopts` and friends) is unchanged (AL3a red-team F4); the clean-environment CI step for the frozen case-table files is unchanged and green; `tests/conftest.py` matches the pinned post-AL2b hash (AL3a round 3); `git diff <AL3a>..HEAD -- tests/_case.py tests/test_cases.py tests/test_case_table_meta.py 'tests/cases_*.py' ':!tests/cases_redteam.py'` is empty apart from commits titled `amend case <id> per AU-Q<n>` touching only those files; no AL2b commit touches both `src/` and those files; `grep -rn NotImplementedError src/` is empty; `_registry.py` was diffed by hand against `email-auth.xml` (updated 2026-05-22) and matches 3.1 G16 entry for entry, and a test asserts `_registry.LAST_UPDATED` equals that date (the AL3a cases do not record it); no `int()` is applied to a digit run of unbounded length (a test with a 5,000-digit version, method version and ARC position, each within `max_length`, gives `UNSUPPORTED_VERSION`, `SYNTAX` and `BAD_ARC_INSTANCE`, not `INTERNAL`); `INTERNAL` is reached only by the monkeypatch test; `test_invariants.py` green; timing cases pass on every matrix version; coverage 100% with no `pragma: no cover`; `mypy --strict` and ruff clean; `tests/test_packaging.py` unchanged and green (package stays flat) |
| AL3b | The rest of section 4 (6.5). `tests/test_properties.py` (properties 1 to 5; property 2's equality per AU-Q17), Hypothesis profiles `ci` (about 2,000) and `nightly` (100,000) registered in a non-frozen module `tests/_hypothesis_profiles.py` that `tests/test_properties.py` imports (not in `tests/conftest.py`, which is pinned by hash since AL3a round 3), chosen by `HYPOTHESIS_PROFILE`. `tests/test_differential.py` against authres 1.2.0 as a dev-group dependency, known differences listed. Coverage audit: the case table and properties without the AL2b unit tests. mutmut over `_tokenizer.py` and `_parser.py` with `mutmut-equivalent.md`; `mutants/` in `.gitignore`. Optional `.github/workflows/fuzz.yml` (`schedule` plus `workflow_dispatch`) for the nightly profile. The mutmut command in CONTRIBUTING | Hypothesis `ci` profile green on 3.11 to 3.15, property 1 never sees `INTERNAL`; `coverage run -m pytest tests/test_cases.py tests/test_properties.py tests/test_api.py tests/test_invariants.py && coverage report` gives 100%, or each omitted line is listed in the slice notes with a reason; gaps closed only by new cited cases or by deleting unreachable code; existing case modules change by additions only; `mutmut results` shows zero survivors or each is listed with a reason; authres absent from wheel metadata, its sdist hash in `uv.lock`, `scripts/check_lock_cooldown.py` passes; `fuzz.yml`, if added, passes zizmor with SHA pins, `permissions: {}`, no secrets; the 28 evaluation cases present by name |
| AL3c (added by the maintainer, 2026-11-07) | Vendor fixture sweep, by a fresh instance after AL3b is committed. Collect real `Authentication-Results` and `ARC-Authentication-Results` values from **public documentation only** (AU-Q19 provenance: source URL, read date, rewrite note per case; RFC 2606/6761 names and RFC 5737/3849 addresses as in `tests/cases_vendor.py`). Targets: mailbox providers (Google, Microsoft, Yahoo, Fastmail, Proton, Apple iCloud, Zoho), gateways (Proofpoint, Mimecast, Barracuda, Cisco), and open-source software that writes the header, from its man pages or source (OpenDKIM, OpenDMARC, rspamd, SpamAssassin, Exim, the Postfix SPF policy daemon). Additions to `tests/cases_vendor.py` and the new `tests/cases_refused.py`, plus `docs/refused-shapes.md`; no src change except the AU-Q45 amendment and the src changes AU-Q52 to AU-Q54, AU-Q57 and AU-Q58 require (`KnownShape` and its detection, the AU-Q53 `@`-run rule, bracket pairing, `domain_of` angle stripping). A value the parser refuses, or parses only with a deviation the plan does not foresee, stays out of the table and goes to the maintainer as an AU-Q (as AU-Q35 did); an answer that changes behaviour becomes a src-only amendment before AL4. Settles the UNVERIFIED risk on unquoted `:` or `,` in vendor values (section 8; answered by AU-Q45). **Refused-shapes log (maintainer, 2026-11-07):** every real-world value the sweep found that the parser refuses, or reads differently from what the vendor meant, is logged in `docs/refused-shapes.md`, one entry per shape: the vendor or project and source (pinned URL or permalink, read date), the rewritten example value, today's outcome (reason and position, lenient and strict), the AU-Q that decided it, what would accept it (the deviation it would need and the parser branch to change, marked in src by a comment naming the entry), and the id of the case that pins today's outcome. Those pinning cases go in a new module `tests/cases_refused.py`, one per entry, each with the accepting expectation written beside it in a comment, so re-enabling a shape is: amend that case per 6.4, change the named branch, move the entry to a "re-enabled" section. Each entry also names its `KnownShape` member, set on the refusal at runtime (AU-Q52). Doc layout artefacts and doc typos (lines with no leading whitespace, spliced samples) are listed in a separate section of the same file with no case. | Each new case has a public URL and ISO read date and passes the vendor meta checks; at least one case per target found, and each target with no public example is listed in the slice notes with where it was looked for; every refused or unforeseen value is an AU-Q, and once answered is logged in `docs/refused-shapes.md` with its pinning case in `tests/cases_refused.py`; `git diff -- src/` limited to AU-Q45, AU-Q52 to AU-Q54, AU-Q57 and AU-Q58; full check set green |
| AL3d (added by the maintainer, 2026-11-07) | Redaction helper for shape reports, after AL3c, with an architect plan first. `python -m authresults.redact`: reads one header value on stdin, writes a rewritten value to stdout and a list of what it replaced to stderr. Not in `__all__` and not a parsing API. A forgiving character scan of its own (it must work on values the parser refuses): linear, no recursion, no regex, stdlib only, no `unicodedata`; keeps every delimiter, space, fold, comment boundary and keyword (method, ptype, property, result) where it is. Replaces consistently (same input, same placeholder): domains with `a.example`, `b.example`, ...; IPv4 with 192.0.2.x and IPv6 with 2001:db8::x; local-parts with `user1`, ...; long base64 runs, selectors and job IDs with placeholders; free text in comments and `reason` with `(...)`. Keeps the vendor service hostnames on the `VENDOR_HOSTNAMES` allowlist. Documented as best effort: the AL4 issue template tells the reporter to run it and still read the output before posting | Unit and Hypothesis property tests: the output contains none of the input's domains (outside the allowlist), IP addresses, local-parts or base64 runs; for every value the parser accepts, the redacted value parses to the same methods, results, ptypes, property names and deviations, and refused values keep their `reason` (and `known_shape`, AU-Q52) where the fault is not inside replaced text; idempotent on its own output; linear-time cases at 8 KiB and 1 MiB; never raises on any `str` input (exit code and a fixed message instead); invariants test (no recursion, no `re`) covers the new module; coverage 100%; wheel stays zero-dependency; verifier and red-team (the red-team tries to get personal data through it) |
| AL4 | `publish.yml`, README with the selection pattern and the AL4 README items (section 10), the header-shape issue template (pointing to `python -m authresults.redact`, AL3d), CHANGELOG 0.1.0 | Dry run on a fork or TestPyPI (AU-Q10); right after the first PyPI publish, its attestation is verified by hand against repo `jrapakko/authresults`, workflow `publish.yml`, environment `pypi`, and the result recorded (AU-Q12); the build job has no `id-token`; the publish job runs only in the `pypi` environment |

Threats (library): attacker-written input from any sender. DoS by length, nesting or quadratic scanning (length first, linear pass, limits). A crash that turns into "accept" or a stack trace (closed error set, `INTERNAL` wrapper). Mis-parse that creates a trusted-looking result (whole-token matching, comments dropped, injection properties). PII leakage through error text (no input in messages). Header injection through `to_value()` (controls refused). Supply chain: takeover of the GitHub or PyPI account (security keys, Trusted Publishing only, no long-lived token, an environment reviewer, tag rules), workflow injection (no `pull_request_target`, no untrusted context in `run:`, zizmor), a poisoned dev dependency (locked by hash, cooldown, no secrets in CI; the authres sdist build is covered in 6.5). Name squatting before the first upload, because a pending publisher does not reserve the name (PyPI docs, VERIFIED): AU-Q11.

### 6.1 AL2a stubs, coverage and types

- **Stub internals raise `NotImplementedError`; the real guard turns it into `AuthResultsError(INTERNAL)`, chained with `from`.** The guard is written in final form in AL2a and used by every public callable that reads input (`parse`, `parse_arc`, `to_value`, the helpers; AU-Q15b). Callers see exactly the closed error set at every commit, and no stub-only branch has to be removed later. Rejected: letting `NotImplementedError` escape, which breaks the CLAUDE.md contract on `main`.
- **Coverage stays 100% with no exclusions:** each stub body is one `raise` covered by `test_stubs.py`; the guard's `Exception` branch is covered by the stubs and by the monkeypatch test that outlives them; the `BaseException` pass-through by a `KeyboardInterrupt` monkeypatch; the accessors by tests that build models directly; the `ValueError` checks per keyword. `fail_under` and the coverage config are not touched.
- **mypy `--strict`:** the stubs carry the final signatures (`raise` satisfies any return type), and AL3a builds its expected objects from the real dataclasses, so mypy checks the case table against the API.
- **Type check:** AL2a has no `INVALID_TYPE` check; it is the first step of parsing and belongs to AL2b (maintainer, 2026-11-06).
- **Ruff:** `parse` has 8 parameters (`PLR0913`): a per-function `# noqa: PLR0913` with a one-line reason, no config change.
- **Recursion rule:** a stdlib `ast` test, rather than an Opengrep or Ruff rule. Ruff likely has no recursion rule (UNVERIFIED; checked with `ruff rule --all` at AL2a); Opengrep is not in the lock and Semgrep would add a large dev tree. About 50 lines of `ast` is the cheaper, lockable option.

### 6.2 Failing tests next to green CI (AL3a to AL2b)

- **`xfail(strict=True)`, applied by id from one tracking list, for one specific failure only.** `tests/_pending.py` defines `class Pending(Exception)` and `PENDING_IDS: frozenset[str]`. The case helper in `tests/test_cases.py` raises `Pending` only when it catches a stub error, detected exactly as `err.reason is ErrorReason.INTERNAL and isinstance(err.__cause__, authresults._errors.InternalCause) and err.__cause__.type_name == "NotImplementedError"` (the guard chains a sanitised `InternalCause` carrying only the original type name, per 2.3). `pytest_collection_modifyitems` in `tests/conftest.py` adds `pytest.mark.xfail(raises=Pending, strict=True, reason="AL2b")` to each item whose `callspec.id` is in `PENDING_IDS`, and raises a usage error if an id matches nothing. Each case test function has one `parametrize`, with ids from `Case.id`.
- **Why:** a case waiting on a stub xfails; a wrong answer, or an `INTERNAL` from a real bug, is a hard failure because `raises=Pending` does not match it; a case that starts passing is an XPASS, which strict mode fails, forcing its id off the list, so the list is an exact progress tracker. The case modules and `test_cases.py` stay byte-identical from AL3a to the end of AL2b, so "expectations not edited" is a one-line `git diff`. Nothing new to register (`xfail` built in, `timeout` from pytest-timeout, `xfail_strict = true` already set).
- **Rejected:** a directory left out of the default run (never runs in CI, no progress signal); a long-lived branch (`main` CI never sees the tests, extra push steps each needing an OK); a per-case marker (removing it edits the case modules and defeats the diff check).

### 6.3 Test-file layout and packaging

- Fixtures are Python modules, not data files: values need exact CR, LF, HTAB and trailing spaces, which the prek hooks `mixed-line-ending --fix=lf`, `trailing-whitespace` and `end-of-file-fixer` would rewrite; and expected values are typed objects mypy checks.
- All new files are flat `tests/*.py` and `src/authresults/*.py`, matching the existing allowlists in `tests/test_packaging.py`. Any non-`.py` file or subdirectory under `tests/`, or a subpackage, must extend the matching allowlist by an exact pattern in the same commit.
- `mutmut-equivalent.md` and `mutants/` sit at the root, outside flit's sdist `include`; `mutants/` goes in `.gitignore`.

### 6.4 Independence and disagreements

- The AL2b implementer may not edit AL3a's case modules, `tests/_case.py`, `tests/test_cases.py` or `tests/test_case_table_meta.py`.
- If it believes a case is wrong, it stops on that case; the hand-off gives the case id, the expectation, its proposed outcome, and the RFC or plan text for each side. The architect turns that into an AU-Q in section 10, and AL2b carries on with the other cases.
- After the maintainer answers, a fresh test-writer instance (not the AL2b implementer; AU-Q20) makes the change in a separate commit titled `amend case <id> per AU-Q<n>`, touching only test files. Gaps that AL3a itself reports take the same path.

### 6.5 What AL3b adds over AL2b

- The 100% gate already holds at AL2b. AL3b audits where it comes from: a branch covered only by the parser author's tests had its expected behaviour chosen by that author, so each gets a case cited to the RFC or plan, or is deleted.
- UNVERIFIED: authres 1.2.0 is sdist-only, so `uv sync` builds it, and its build backend may come from PyPI without a hash. Proposal: `tool.uv.no-build-isolation-package = ["authres"]` with `setuptools` in the dev group so the backend is hash-locked; if uv cannot order that install, raise an AU-Q rather than accept an unhashed build.
- UNVERIFIED: whether authres and mutmut run on 3.15. If authres does not, skip the differential there with the reason in the skip.
- mutmut is a heavy job: run it alone, after `free -h`, and stop if it grows past about 3 GB.

## 7. Steps for the maintainer, in order (each needs an explicit OK at the time)

1. **[OK]** Check that the PyPI account (to be created if needed) has security-key 2FA. Check GitHub too (already done).
2. **[OK] Create the GitHub repo** `authresults`: public, empty, Apache-2.0 chosen in the repo (or added by AL1). Turn on private vulnerability reporting. Set the Actions default token to read-only. Add the rulesets from section 5.
3. **[OK] Push each slice** as it passes review: AL1 (done, `942d9ba`, CI green on 2026-11-06), AL2a, AL3a (done), then AL2b and AL3b. Each push is outward-facing. AL3a went out with its cases marked expected-to-fail, and CI is green at every push.
4. **[OK] Register the PyPI pending publisher:** project `authresults`, owner `jrapakko`, repo `authresults`, workflow `publish.yml`, environment `pypi`. Optionally the same on TestPyPI (AU-Q10). Do this close to step 6 (AU-Q11).
5. **[OK] Create the GitHub environment `pypi`:** the maintainer as required reviewer, deployment tags `v*` only, no secrets.
6. **[OK] First release:** tag `v0.1.0` (signed tag recommended), push it, approve the `publish` deployment, then check the PyPI page shows the attestation and the files are exactly one wheel plus one sdist.

## 8. Risks and open points

- Real-world shapes (Microsoft `action=`, `compauth`, Fastmail and Proton formats, trailing `;`) are UNVERIFIED until fixtures are collected. The `Deviation` list may grow; each addition is an AU-Q, then a src-only AL2a amendment before AL2b (section 6). One has so far: `MISSING_AUTHSERV_ID` (AU-Q35).
- Writing tests first moves plan gaps to the front. Found so far: the deep-nesting contradiction (AU-Q14) and unpinned error positions, precedence and canonical form (AU-Q15 to AU-Q17), and the later AU-Q21 to AU-Q52. Each goes through 6.4 instead of being settled by whichever implementer hits it.
- An xfail could hide a regression. Mitigation: `raises=Pending` plus strict mode plus the stale-id check (6.2); AL2b ends with 0 xfailed.
- authres sdist build dependencies, and mutmut and authres support for 3.15, are UNVERIFIED (6.5).
- authres's acceptance of `dns` and its exact pvalue character class are UNVERIFIED (only the `header.b=Ab+/cd=` acceptance is observed).
- One maintainer: a bus factor of 1. Mitigation: small code, Apache-2.0, and a consumer can vendor a released version if needed.
- Name squatting between now and the first upload (section 6 threats).
- GitHub option names (SHA-pinning enforcement, self-review) and Dependabot `cooldown` are UNVERIFIED.
- AL3a-R: the quotes come from a tool limited to 125-character quotations. Whitespace inside grammar lines may be normalised, and the three RFC 5322 prose items (§2.2.3, §3.2.4, §4) are fragments.
- AL3a-R: **The IANA domainkeys anomaly** (duplicate `temperror`, no `fail`) is real in the XML. The literal snapshot marks `domainkeys=fail` unregistered.
- AL3a-R: **Unbounded digit runs** in version, method-version and ARC position would hit CPython's int and str conversion limit and surface as `INTERNAL`. This is covered by AU-Q24 and the AL2b acceptance item.
- AL3a-R: **Strictness:**
  - Narrowing obs-local-part (AU-Q18b) and the domain part (AU-Q24) will refuse some grammar-valid or real-world values. Vendor fixtures may push back; each pushback becomes an AU-Q.
  - With `PVALUE_TSPECIALS` limited to `/ = ?`, a vendor value containing `:` or `,` unquoted would be `SYNTAX`. VERIFIED by the AL3c sweep (2026-11-07): Exim writes unquoted IPv6 addresses, and `[ ]` and `< >` also appear in real output; `,` appeared only in doc mock-ups. Resolved by AU-Q45.
- Post-launch (maintainer, 2026-11-07): whether to add debug logging for troubleshooting. Deferred until after 0.1.0; any form must keep zero dependencies (stdlib `logging` only), stay silent by default, and never put header text in a record. Until then the no-logging non-negotiable stands.

## 9. Sources

Read 2026-11-05:
- RFC 8601, <https://www.rfc-editor.org/rfc/rfc8601.txt>: §2.2 grammar, §2.3, §2.5, §2.6, §2.7.4, §2.7.6, §4.1, §5, Appendix B and D.
- RFC 8617, <https://www.rfc-editor.org/rfc/rfc8617.txt>: §3.8, §3.9, §4.1.1, §4.2.1, status.
- IANA Email Authentication Parameters, <https://www.iana.org/assignments/email-auth/email-auth.xhtml> (last updated 2026-05-22): ptypes `body`, `dns`, `header`, `policy`, `smtp`; methods and result names. Re-read at AL3a-R; the date and entries recorded in 3.1 drive both the AL3a `registered` expectations and the AL2b snapshot (`_registry.LAST_UPDATED`).
- Python devguide versions, <https://devguide.python.org/versions/>.
- PyPI docs: <https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/> (a pending publisher does not reserve the name and is invalidated if someone registers it first) and <https://docs.pypi.org/attestations/producing-attestations/> (attestations by default with the PyPA action).
- An earlier evaluation of existing parsers (authres 1.2.0, authheaders), whose 28 adversarial cases are in `tests/cases_spike.py`; its observations of authres behaviour are re-checked by `tests/test_differential.py` (AL3b).
- RFC 7601 differences: taken from RFC 8601 Appendix D only. RFC 7601 itself was not fetched. The listed changes (DKIM `a` and `s` registered, EAI guidance, grammar token renames, errata 4671 and 5435) do not change the parsing scope, but the token renames are UNVERIFIED in detail.

Read 2026-11-06 (summarising fetch first, then the verbatim AL3a-R re-read):
- RFC 8601 §1.5.2, §2.2 (grammar and import prose), §2.5 and §2.7.1 to §2.7.5 (EAI notes); RFC 5321 §2.4 and §4.1.2.
- RFC 5234 §2.3 and Appendix B.1; RFC 7405 §2.1; RFC 5322 §2.2.3, §3.2.1 to §3.2.5, §3.4.1 and §4.x; RFC 2045 §5.1; RFC 6376 §3.5; RFC 6531 §3.3; RFC 6532 §3.1 and §3.2; RFC 8617 §3.9, §4.1.1 and §4.2.1.
- The IANA registry XHTML and XML (`email-auth.xml`).
- IETF Trust Legal Provisions 5.0, corrected (<https://trustee.ietf.org/documents/trust-legal-provisions/tlp-5>), and the IETF Trust code-components list.

## 10. Questions and answers

All questions are answered. Where a question's recommendation was refined during AL3a-R or later, the refined form is the one recorded; "consequence" items are coordinator notes that follow directly from an answer.

### Project and process (AU-Q1 to AU-Q13, answered 2026-11-05)

- **AU-Q1. Answered:** GitHub user `jrapakko` (repo `github.com/jrapakko/authresults`, the PyPI publisher's owner). Copyright line `Copyright 2026 Jess Rapakko`, in the `NOTICE` file and the licence header convention Apache-2.0 suggests; contributors keep their own copyright under the DCO (AU-Q9). Question: the GitHub username for the repo and the PyPI publisher, and the copyright line (own name, or "authresults contributors")?

AU-Q2 to AU-Q13 were all answered as recommended.

- **AU-Q2.** Include `parse_arc()` for `ARC-Authentication-Results` (`i=` plus the same payload)? Answered: yes, it is cheap and from the same grammar.
- **AU-Q3.** Include a canonical serializer `to_value()`? Answered: yes, for the round-trip property, with control characters refused.
- **AU-Q4.** Defaults: 8 KiB length, 16 comment depth, 64 results, 64 properties, ASCII only, lenient syntax and names (kept and flagged)? Answered: yes.
- **AU-Q5.** No IDNA conversion in the library (ASCII and A-label helper only; callers use `idna` for U-labels)? Answered: yes, it keeps zero dependencies.
- **AU-Q6.** `reason=` after properties: refuse as `SYNTAX` unless a public real-world sample shows it? Answered: yes.
- **AU-Q7.** Build backend: `flit_core` or `uv_build`? Answered: `flit_core`.
- **AU-Q8.** Dependabot on GitHub rather than a third-party update app? Answered: Dependabot.
- **AU-Q9.** Contributions: DCO sign-off, nothing, or a CLA? Answered: DCO sign-off.
- **AU-Q10.** Rehearse the first release on TestPyPI with its own pending publisher? Answered: yes, one extra OK.
- **AU-Q11.** Timing of the PyPI registration: a pending publisher does not reserve `authresults`. Do the first real upload soon after the repo is public, rather than a placeholder release, which PyPI discourages (UNVERIFIED policy wording)? Answered: yes, upload soon after the repo goes public.
- **AU-Q12.** As part of AL4, right after the first PyPI publish, verify its PyPI attestation against the repo, workflow and environment (publisher repo `jrapakko/authresults`, workflow `publish.yml`, environment `pypi`), and record it? Answered: yes, by hand for now. Re-timed by the maintainer on 2026-11-07: done in AL4, right after the first publish, rather than when a consumer first pins the wheel.
- **AU-Q13.** Confirm the three caller-side conventions from the earlier evaluation that the README pattern (section 1) relies on: DKIM aligned by `header.d` or, if absent, the domain of `header.i`; selection of the trusted header by position; the 8 KiB cap and ASCII only? Answered: yes to all three.

### Test-first details (AU-Q14 to AU-Q20, answered 2026-11-06)

- **AU-Q14. Answered: as recommended.** The "deep nesting" case versus length-first. The case value is 10,026 characters, so with the defaults it gives `TOO_LONG`, not `NESTING_TOO_DEEP`. Decision: keep the case name with the default call, expecting `TOO_LONG`; add "deep nesting (within cap)" with 4,000 levels and 8,026 characters, expecting `NESTING_TOO_DEEP` at offset 42 (the 17th `(`); keep property 5 as written.
- **AU-Q15. Answered: as recommended, (a) to (g).** API details AL2a pins:
  - (a) `to_value(*, ascii_only: bool = True) -> str`. It raises `AuthResultsError(CONTROL_CHAR | NON_ASCII)` with `position=None`.
  - (b) `to_value`, `domain_of` and `ascii_domain` go through the same INTERNAL guard; the helpers raise `INVALID_TYPE` for a non-`str`.
  - (c) A limit that is not an exact `int` (so no `bool`, `int` subclass or `IntEnum` member; AL2a red-team F1) or is below 1 raises `ValueError`, as does a non-`bool` flag. `parse_arc` spells out the same keywords explicitly, and `max_length` counts the whole ARC value including `i=`.
  - (d) `results_for`, `get` and `get_unique` lowercase their keyword arguments, so `results_for("DMARC")` equals `results_for("dmarc")`.
  - (e) A result with no method version counts as the registered version for `Result.registered`.
  - (f) Dataclass fields have no defaults, so every expectation is written out in full.
  - (g) `StrEnum` values are `auto()` (the lowercase name); the message is `"<reason>"` or `"<reason> at position <n>"`.
- **AU-Q16. Answered: as recommended, with the AL3a-R refinements.** Error positions and precedence.
  - Order: type, then length, then the character scan (`CONTROL_CHAR`, `NON_ASCII`, and `LF_FOLDING` under strict; leftmost wins), then a full tokeniser pass (`UNTERMINATED_*`, `NESTING_TOO_DEEP`; first detected, AU-Q36), then the parse (leftmost, with `UNREGISTERED` and `DEVIATION` raised at the token where found). `EMPTY` is a value that is only WSP or FWS after the scan; a comment-only value is `SYNTAX`.
  - Positions: `None` for `INVALID_TYPE`, `EMPTY`, `INTERNAL`, `DUPLICATE_PROPERTY` and `to_value` errors; `TOO_LONG` at `max_length`; `CONTROL_CHAR` and `NON_ASCII` at the character; `UNTERMINATED_COMMENT` at the outermost unclosed `(`; `UNTERMINATED_QUOTED_STRING` at its opening `"`; `NESTING_TOO_DEEP` at the first `(` over the limit; `SYNTAX` at the first token that cannot continue the grammar, or `len(value)` at end of input; `UNSUPPORTED_VERSION` at the version's first digit; `TOO_MANY_RESULTS` at the `;` of result N+1; `TOO_MANY_PROPERTIES` at the ptype of property N+1; `DUPLICATE_REASON` at the second `reason`; `DEVIATION` where it starts (the LF, the bare name, the first tspecial, the trailing `;`); `UNREGISTERED` at the keyword; `BAD_ARC_INSTANCE` at the position's first digit. Cases with several defects exist only to test this order.
  - AL3a-R refinements:
    1. Errors in the parse stage are raised in detection order. `UNREGISTERED` for a result is detected once its result keyword has been read, and placed at the method keyword; for a property, it is detected once its pvalue has been read, and placed at the ptype or bare name. `BARE_PROPERTY` is detected at the `=` and placed at the name. `PVALUE_TSPECIALS` is placed at the first `/ = ?`, `TRAILING_SEMICOLON` at the `;`, and `LF_FOLDING` (in the scan) at the LF.
    2. At the same position, `DEVIATION` comes before `UNREGISTERED`.
    3. A malformed keyword is `SYNTAX` at the keyword's first character.
    4. `TOO_MANY_PROPERTIES` counts bare properties too.
    5. ARC: `BAD_ARC_INSTANCE` only for a digit run that is present but out of range or too long; other instance faults are `SYNTAX`.
- **AU-Q17. Answered: as recommended, with the AL3a-R refinements.** Canonical form of `to_value()` and round-trip equality.
  - Form: the authserv-id, then ` <version>` only if `version_given`, then `; none` or `; method[/v]=result[ reason=V][ ptype.name=V]...` on one line, single spaces, no comments, no folding. `V` is bare if it is an RFC 2045 token or an address form, otherwise quoted with `\` before `"` and `\`; a bare property comes out as `name=value`.
  - Round-trip equality compares every field except `Property.raw` and `Property.quoted`, and compares `deviations` without `PVALUE_TSPECIALS`, `TRAILING_SEMICOLON` and `LF_FOLDING`. A second `to_value()` gives the same string. AL3a wrote `to_value` cases only after this answer.
  - AL3a-R refinements:
    1. "V is bare" uses the same token class as the parser, including UTF-8 under `ascii_only=False`. A reason value is never written in address form.
    2. An address-form value is written as is, because it already matches the grammar (AU-Q23).
    3. `to_value` gives `SYNTAX` with `position=None` for a model it cannot serialise (AU-Q33(b)).
- **AU-Q18. Answered, as adjusted at AL3a-R.** Grammar judgement calls:
  - (a) **Answered: as the adjustment recommends.** UTF-8 is allowed, with `ascii_only=False`, in comments, quoted-strings, token-form values (authserv-id, pvalue, reason), local-part and domain-name, never in keyword positions or specials. The unquoted-token item is a judgement call: the RFC 2045 `token` is US-ASCII and RFC 6532 does not extend it, while RFC 8601 §1.5.2, §2.5 and §2.7.1 intend UTF-8 there. C1 controls stay `CONTROL_CHAR`.
  - (b) **Answered: refuse as `SYNTAX`.** The original proposal (accept CFWS inside a dot-atom local-part) was contradicted by the re-read: dot-atom-text has no CFWS inside it (RFC 5322 §3.2.3); CFWS between atoms exists only in obs-local-part, and RFC 5322 §4 says obsolete forms "MUST be accepted and parsed by a conformant receiver." Decision: obs-local-part **and** any CFWS inside or around the address form are `SYNTAX`. This consciously narrows the grammar, because producers must not generate obs syntax and the narrowing removes the ambiguity `header.i=x (c) @example.com`. A new `OBS_LOCAL_PART` deviation only later, with a fixture that needs it.
  - (c) **Answered: as the adjustment recommends.** With (b) in place, no CFWS can sit inside a pvalue. `raw` is the exact pvalue slice without its surrounding CFWS, and folds inside a quoted-string stay in `raw`.
  - (d) **Answered: as the adjustment recommends.** The original proposal (`i=01` is `BAD_ARC_INSTANCE`) was contradicted: the RFC 8617 §3.9 `position` rule allows two digits, so `i=01` means 1. Three or more digits, 0, or above 50 is `BAD_ARC_INSTANCE`.
- **AU-Q19. Answered: as recommended, confirmed at AL3a-R.** Fixture provenance. RFC example text goes in verbatim, attributed. TLP §3.c.iii allows unmodified portions "clearly attributed to IETF" that identify the RFC; use the cite `IETF RFC 8601, Appendix B.n (unmodified excerpt)`. ABNF is a Code Component, so it is not copied into tracked files. Vendor documentation values go in only as rewritten shapes (names, addresses, selectors and signatures replaced) with the source URL and read date; vendor terms were not checked (UNVERIFIED, and the rewriting avoids the issue).
- **AU-Q20. Answered: as recommended, confirmed at AL3a-R.** Who edits an AL3a expectation after an answered dispute? A fresh test-writer instance, never the AL2b implementer, in a separate commit titled `amend case <id> per AU-Q<n>` touching only test files.

### Grammar and API decisions (AU-Q21 to AU-Q38, answered 2026-11-06)

- **AU-Q21. Answered: follow the grammar.** `none` as a method. The grammar allows `; none=pass` as a resinfo with the Keyword `none`. Decision: a Result with method `none` and `registered=False`. `; none` followed by anything except CFWS stays `SYNTAX`.
- **AU-Q22. Answered: exactly `/ = ?`; and document the wider option.** `PVALUE_TSPECIALS` set:
  - Exactly `/ = ?`, which are the tspecials that are also atext, in an unquoted pvalue (including a bare-property value) with no `@`.
  - `< > , : [ ] \` are `SYNTAX`.
  - Not applied to authserv-id or reason values.
  - `/ = ?` before `@` are a legal local-part, with no deviation.
  - The README and 3.1 record that the other tspecials that cannot break the structure (all except `;`, `(` and `"`: `< > , : [ ] \`; `@` is handled by the address form) are refused as `SYNTAX` in unquoted values, and that widening the deviation to them is the considered alternative, to be taken only with a vendor fixture that needs it.
- **AU-Q23. Answered: as recommended, amended by AU-Q42.** Address-form `Property.value`: the address's source text verbatim, with quotes and backslashes of a quoted local-part kept (`"a b"@example.com`), and `quoted=False`. Folds are unfolded in `value` (AU-Q42), so `value == raw` whenever there is no fold. The alternative, unquoting the local-part, produces strings that are not addresses.
- **AU-Q24. Answered: as recommended.** Numbers and the domain part:
  - Leading zeros are accepted for version, method-version and ARC position.
  - The version and position are compared as digit strings with leading zeros stripped, never through `int()` on unbounded input (CPython's 4,300-digit limit would raise `ValueError`, giving `INTERNAL`).
  - A `method_version` with more than 9 significant digits is `SYNTAX` at its first digit.
  - After `@`, the domain needs two or more LDH labels with no trailing dot, `_` or address-literal; otherwise `SYNTAX`. So `@localhost` and `a@[192.0.2.1]` are `SYNTAX`.
- **AU-Q25. Answered: as recommended, with the AL3a-R refinements.** Separators and the CFWS of a quoted-string:
  - CFWS is required only at the three grammar spots (G4).
  - A quoted-string used as `value` brings no CFWS of its own (the RFC 2045 lexical form), so `reason="x"header.d=y` is `SYNTAX`.
  - `header.s="a"header.d=b` is valid.
- **AU-Q26. Answered: as recommended, with the AL3a-R refinements.** `reason` collisions:
  - A second `reason=` anywhere in a resinfo is `DUPLICATE_REASON`.
  - A first `reason=` after a property is `SYNTAX` (AU-Q6).
  - `reason` is never a bare property.
  - `reason.x=y` is a propspec.
- **AU-Q26 consequence (coordinator, 2026-11-06):** `to_value()` raises `SYNTAX` (position `None`) for a bare property named `reason`, because AU-Q26 says `reason` is never a bare property and such output would parse back as a reason (AL3a red-team, theoretical finding).
- **AU-Q27. Answered: as recommended.** `BARE_PROPERTY` shape:
  - A keyword, optional CFWS, `=` and a pvalue at any property position, interleaved freely with propspecs.
  - The name is lowercased, with `ptype=None` and `registered=False`.
  - `dkim=pass spf=pass` (a missing `;`) therefore parses as dkim with a bare `spf` property, flagged. It never becomes an `spf` result.
- **AU-Q28. Answered: as recommended, with the AL3a-R refinements.** `;` placement:
  - `TRAILING_SEMICOLON` only for a final `;` followed by CFWS alone, after at least one resinfo.
  - `example.com;`, `; none;` and `;;` are `SYNTAX`.
  - Real-world evidence for any trailing `;` is still UNVERIFIED (section 8).
- **AU-Q29. Answered: as recommended.** Controls and folding edges:
  - obs-FWS (several folds, whitespace-only continuation lines) is accepted silently.
  - A trailing CRLF or LF is `CONTROL_CHAR` (the README says to strip it).
  - `\` followed by CR or LF is `CONTROL_CHAR` at the CR or LF.
  - C1 controls and lone surrogates are `CONTROL_CHAR` even with `ascii_only=False`.
  - Folds inside quoted-strings are removed from `value`.
- **AU-Q30. Answered: as recommended.** authserv-id form:
  - `authserv_id` is the unquoted, quoted-pair-resolved content, with case kept.
  - `""` is accepted (empty id), because the grammar allows it and a trust comparison fails anyway.
  - Tspecials in an unquoted id (`a/b`, `a@b`) are `SYNTAX`.
- **AU-Q31. Answered: the (method, ptype, property) triple, snapshot literal to IANA.** Registry semantics:
  - Property registration is by (method, ptype, property), as RFC 8601 §2.3 says.
  - Deprecated entries count as registered.
  - sender-id matches any `header.*`.
  - The snapshot follows IANA literally, including the missing `domainkeys` `fail`, with a comment in `_registry.py`. Reporting the duplicate to IANA is an outward step and needs the maintainer's OK.
- **AU-Q32. Answered: as recommended.** ARC instance errors:
  - `BAD_ARC_INSTANCE` for a present digit run that is out of range or 3+ digits long.
  - `SYNTAX` for every other fault in the instance part, including `I=1`.
- **AU-Q33. Answered: as recommended, with the AL3a-R refinements.** Helper edges and `to_value` of bad models:
  - (a) `domain_of` returns `None` only when the text after the last `@` is empty (`"a@"`, `""`). `ascii_domain` has no length limits, accepts single labels, lowercases ASCII only, and returns `None` for anything not made of LDH sub-domains (including `@`, a trailing dot, an empty label and non-ASCII). Neither helper strips CFWS or quotes.
  - (b) `to_value` raises `SYNTAX` with `position=None` when a field cannot be serialised: a keyword field that is not lowercase `Ldh-str`; `none=True` with results; `version != 1`; a negative `method_version` or one longer than 9 digits; `ptype=None` with a name that is not a keyword.
- **AU-Q34. Answered: as recommended, with the AL3a-R refinements.** Keyword case. RFC 8601 is silent, so lowercasing method, result, ptype and property rests on RFC 5321 §2.4 and RFC 2045 §5.1 by analogy (literals are case-insensitive by RFC 5234 itself). Decision: yes. The ARC `i` is exempt.
- **AU-Q35. Answered: a new deviation for a missing authserv-id.** Microsoft's documented headers (all 7 examples on Microsoft Learn "Troubleshoot email authentication", read 2026-11-06 at AL3a) start with `spf=...` and have no authserv-id. Decision: add `Deviation.MISSING_AUTHSERV_ID`; `AuthenticationResults.authserv_id` becomes `str | None` (`None` only when missing). Lenient: parsed and recorded; `strict_syntax=True`: `DEVIATION` at the offset of the first method keyword. Detection: the first token is followed (after CFWS) by `=` or `/`, so it is a method, not an id (narrowed by AU-Q39). This was a src-only AL2a amendment commit (types, enum, AL2a tests) before AL2b, per section 6 (`0a68c06`). Detail: `to_value()` on a model with `authserv_id=None` raises `SYNTAX` with `position=None`, so the serializer only ever writes RFC-conformant output.
- **AU-Q35 consequence (coordinator, 2026-11-06):** the AU-Q35 detection rule takes precedence over AU-Q30 for a first token followed by `/`: `a/b; none` reads as method `a` with a non-digit method version, so `SYNTAX` at 2 (not at 1). `a@b; none` stays `SYNTAX` at 1, because `@` does not trigger AU-Q35.
- **AU-Q36. Answered: first detected wins inside the tokeniser stage.** AU-Q16's "leftmost" means "first fault met by the single left-to-right pass": 8192 `(` at depth limit 16 gives `NESTING_TOO_DEEP` at 16, not `UNTERMINATED_COMMENT` at 0.
- **AU-Q37. Answered: a C1 control or lone surrogate is `CONTROL_CHAR` regardless of `ascii_only`** (the scan checks control before non-ASCII for each character).
- **AU-Q37 consequence (coordinator, 2026-11-06):** the same rule applies to `to_value()`: a C1 control or lone surrogate in any written field is `CONTROL_CHAR` (position `None`) regardless of `ascii_only`. Errors raised directly by `Result.get_unique` (outside the guard) have `__context__ is None`; the table asserts that instead of `__suppress_context__`. The AL3a conftest guards make `-k`/`--deselect` on the case table a usage error; partial runs during AL2b use node ids.
- **AU-Q38. Answered: four edge rules, as recommended.**
  1. A CRLF not followed by WSP (including a trailing CRLF) is `CONTROL_CHAR` at the CR; a bare LF at the LF.
  2. Domain faults after `@` are `SYNTAX` at the offending character where one exists (`x-.example` at the `-`, a trailing dot at the dot, `a@ x.example` at the space), otherwise at the domain's first character (`a@localhost` at `l`).
  3. `domain_of` and `ascii_domain` normalise a `str` subclass to an exact `str`, as `parse` does; non-`str` stays `INVALID_TYPE`.
  4. `to_value` writes the authserv-id with the AU-Q17 V rule: bare if a token, otherwise quoted with `\` escapes (`"mx example"`, `""`).

### Later decisions (AU-Q39 to AU-Q43, answered 2026-11-07)

- **AU-Q39. Answered: `mx.example=pass` is read as an id.** The AU-Q35 missing-id rule applies only when the first token is keyword-shaped (a `Keyword`, no dots, not quoted). Otherwise the first token is the authserv-id and an `=` (or `/`) after it is `SYNTAX` at that character: `mx.example=pass` at 10, `"dkim"=pass` at 6. Related, from the grammar: `dkim; none` has authserv-id `dkim`; `mx.example dmarc=pass` (no `;`) is `SYNTAX` at 11.
- **AU-Q40. Answered: `to_value` writes HTAB inside a quoted value.** HTAB is WSP and legal inside a quoted-string, so a value containing it is quoted and the tab written as is, keeping the round trip exact. Every other control stays `CONTROL_CHAR`.
- **AL3a round 3 scope (maintainer, 2026-11-07): everything red-team round 2 proposed.** Coverage gaps N3 to N6; harness hardening N1 and N2:
  - a clean-environment CI step running the frozen case-table files (no plugin autoload, `-I`, fixed `-o addopts`, `--confcutdir=tests`);
  - a meta test that AST-scans non-frozen `tests/*.py` and the repo root for `__kwdefaults__`, `__defaults__`, `__code__`, `__closure__`, imports of `test_cases` or `_case` internals, and any `conftest.py` other than `tests/conftest.py`;
  - `tests/conftest.py` refuses a non-empty `PYTEST_ADDOPTS` or `PYTEST_PLUGINS`, a non-`rewrite` assert mode and a missing timeout plugin;
  - `test_cases.py` asserts at import that the guard plugin is registered;
  - the shape test bans `obj`/`__kwdefaults__`/`__defaults__`/`__dict__`/`__code__` attribute loads and subscript stores;
  - a pinned hash of the post-AL2b `tests/conftest.py` form.

  `tests/cases_redteam.py` exists (empty) and is part of `ALL_CASES`, so AL2b only appends to it.
- **AU-Q41. Answered: refuse Unicode space separators and format characters everywhere.** Characters of general category `Zs`, `Zl`, `Zp` (other than ASCII SP) and `Cf` (bidi controls, zero-width characters, BOM, soft hyphen and the rest) are `CONTROL_CHAR` at their offset in every position (values, authserv-id, domains, comments, quoted-strings), even with `ascii_only=False`; under `ascii_only=True` they are `CONTROL_CHAR` too (they are checked before non-ASCII, as AU-Q37). `to_value()` refuses them in any written field with `CONTROL_CHAR`, position `None`. The set is a hard-coded table of code-point ranges taken from one stated Unicode version (not `unicodedata`, whose data differs between Python versions and which the import allowlist excludes), with the version recorded in the module and the test. Per 6.4, a fresh test-writer amends the affected AL3a cases (commits titled `amend case <id> per AU-Q41`, test files only), then the AL2b implementer changes the parser.
- **AU-Q42. Answered: unfold folds inside a quoted local-part.** AU-Q23 becomes: an address-form `Property.value` is the source text verbatim except that folds (CRLF or LF followed by WSP) are unfolded by removing the line break (RFC 5322 §2.2.3), so `smtp.mailfrom="a\r\n b"@x.example` gives value `"a b"@x.example`; `raw` keeps the fold; `value == raw` whenever there is no fold. (AL2b red-team M1.)
- **AU-Q43. Answered: accessors keep rejecting `str` subclasses** with `INVALID_TYPE` (they take caller keywords, not header input); `parse()` and the helpers keep normalising them (AU-Q38(3)). The README documents the difference.

### Vendor sweep decisions (AU-Q44 to AU-Q58, answered 2026-11-07, AL3c)

The AL3c research found real values from mailbox providers, gateways and open-source mail software (findings kept outside the repository until the AL3c cases land).

- **AU-Q44. Answered: vendor cases may also come from third-party guides and from open-source projects' public test fixtures**, each pinned to a URL or commit permalink with its read date. Still no private mail, no pastebins, nothing behind a login; values rewritten to RFC 2606/6761 names and RFC 5737/3849 addresses as before. Amends AU-Q19's "public vendor documentation only".
- **AU-Q45. Answered: accept `:`, `[`, `]`, `<` and `>` in unquoted property values under `PVALUE_TSPECIALS`** (lenient accepts and flags, `strict_syntax` refuses). Evidence: Exim writes IPv6 client addresses unquoted (`smtp.remote-ip=2001:db8::1`); Exim, Haraka and possibly OpenDMARC write IP-literal HELO (`smtp.helo=[192.0.2.1]`); Exim and Stalwart write the null sender `smtp.mailfrom=<>`; Zoho writes `header.from=<noreply@mail.example.com>`. The value keeps the characters as written, so `ascii_domain` on such a value returns `None`. `,` and `\` stay refused, as do `;`, `(` and `"`. Amends AU-Q22. Consequence: a behaviour change. The case-table expectations that refuse these characters are amended by a fresh test-writer (`amend case <id> per AU-Q45`, per 6.4), then a src-only amendment lands, both before AL4.
- **AU-Q46. Answered: refuse Exim's ARC-Authentication-Results opening element and document it.** Every ARC set Exim signs begins with a bare `ptype.property=value` where a `method=result` belongs (`i=1; example.com; smtp.remote-ip=192.0.2.1; arc=none`); `parse_arc` keeps refusing it as `SYNTAX`. Revisit after 0.1.0 if callers need it (it would need a model field for properties outside any result).
- **AU-Q47. Answered: values from other field names (Trend Micro's `X-TM-Authentication-Results`) stay out of the vendor table, but are documented**: the README says the library parses any value the caller passes, and that these X- fields use RFC 8601 syntax with no authserv-id, so they parse with `MISSING_AUTHSERV_ID` and `BARE_PROPERTY`.
- **AU-Q48. Answered: refuse a bare domain between results** (`...; example.com; dkim=pass ...`, seen only on one Microsoft Learn page) as `SYNTAX`, and document it.
- **AU-Q49. Answered: keep the current reading of a missing `;` between results, and document it.** `mx.zoho.com; dkim=pass spf=pass (...) smtp.mailfrom=...;` parses as one dkim result with a bare property `spf=pass` (`BARE_PROPERTY`), so `results_for("spf")` is empty; strict refuses it. It never creates a pass. The value becomes a case pinning this behaviour, and the README notes that a bare property named like a registered method signals a missing `;`.
- **AU-Q50. Answered: refuse a job ID appended to the authserv-id** (OpenDKIM/OpenDMARC's opt-in `AuthservIDWithJobID`, `mail.example.com/4ABCD1234`) as `SYNTAX`, document it (leave the option off), and revisit if needed.
- **AU-Q51. Answered: refuse an authserv-id with no results and no `none`** (inferred from Exim's and Stalwart's source, not seen in real output) as `SYNTAX` for now, and document it so it is quick to change: the README and a comment at the refusing branch name the case, and a cited case pins today's outcome so a later change is a one-line expectation amendment plus the src change.

- **AU-Q52. Answered (2026-11-07): refused shapes known from the wild are tagged on the error, not logged.** When a refusal matches an entry in `docs/refused-shapes.md`, `AuthResultsError` carries `known_shape`: a member of a new closed `KnownShape` enum (`StrEnum`, one member per entry, e.g. `EXIM_ARC_LEADING_PROPERTY`, `AUTHSERV_ID_JOB_ID`, `STRAY_DOMAIN_BETWEEN_RESULTS`, `AUTHSERV_ID_ONLY`); otherwise `known_shape is None`. The no-logging non-negotiable stands: the library emits nothing, and the caller logs or counts the tag with their own logger. The tag holds no input text, is never set on `INTERNAL` or `INVALID_TYPE`, does not appear in `str(err)` (the AU-Q15g message format is unchanged), and leaves `reason` and `position` exactly as today. Detection runs only on the error path, at the refusing branch the log entry names, in constant extra work per refusal (no second pass). AU-Q52b: refused shapes only; accepted shapes are already visible through `deviations`. Consequences: an API addition (`KnownShape` in `__all__`, the attribute, `test_api.py`'s `__all__` set), a frozen-file change to `tests/_case.py` so a case can expect `known_shape` (made by a fresh test-writer per 6.4, `amend case table per AU-Q52`), then the src change, all in AL3c before AL4; each `docs/refused-shapes.md` entry names its `KnownShape` member, and re-enabling a shape retires its member (removing a member is an API change, so it waits for a minor release; until then the member stays and is never set). The README documents the tag and how to log it.
- **AU-Q53. Answered (2026-11-07): an unquoted value with `@` that also contains any of `:`, `[`, `]`, `<` or `>` leaves the address check.** It is kept as written and flagged `PVALUE_TSPECIALS` (lenient); `strict_syntax` refuses it with `DEVIATION` at the first such character. So Zoho's `header.from=<noreply@mail.example.com>`, `smtp.mailfrom=a@[192.0.2.1]` and `user@[IPv6:2001:db8::1]` all parse in lenient mode. Amends AU-Q24's "no address-literal" for these runs (a run with `@` and none of these characters still goes through the address check). Consequence: the `address literal` case is amended by the AL3c test-writer (`amend case table per AU-Q45`), then the src change.
- **AU-Q54. Answered (2026-11-07): refuse, log and tag `Received-SPF` keys written as results.** Mimecast's support article ("Policies - DNS Authentication Overview", updated 2026-07-30, one illustrative example with a typo) shows `mimecast.com; spf=pass (...) client-ip=...; envelope-from=...; helo=...; dkim=...`: RFC 7208 9.1 `Received-SPF` keys split off by `;`, so each reads as a new resinfo. It stays refused (`SYNTAX`; strict refuses earlier at the first `BARE_PROPERTY`), gets an entry in `docs/refused-shapes.md` and a pinning case in `tests/cases_refused.py`, and is tagged `KnownShape.SPF_DETAILS_AS_RESULTS` (`"spf_details_as_results"`; neutral name, since other vendors may do the same). Detection, on the error path only: the token after a `;` and before `=` is one of the full RFC 7208 9.1 key list (`client-ip`, `envelope-from`, `helo`, `receiver`, `identity`, `mechanism`, `problem`), compared ASCII case-insensitively, one token of lookahead (AU-Q56). Accepting it (moving the keys onto the preceding result across `;`) was rejected on one doc example; whether it occurs in real mail is what the tag is for.
- **AU-Q55. Answered (2026-11-07): Cisco's AsyncOS 15.0 guide example (`example1.com header.from=From:user123@example.com; ...`) is a doc mock-up**, listed in the doc-artefact section of `docs/refused-shapes.md` with no case and no tag; Cisco's own PDF output is well formed.
- **AU-Q56. Answered (2026-11-07): `AUTHSERV_ID_ONLY` is tagged by syntax for any authserv-id-only value** (bare ids such as `X` or `none` included; six older cases expect the tag), **and detection may look ahead at most one token on the error path**, still in the one pass (needed to tell `example.com;` from `ptype.property=` for `STRAY_DOMAIN_BETWEEN_RESULTS` and `EXIM_ARC_LEADING_PROPERTY`). Amends AU-Q52's "constant extra work". Also confirmed: a shape read differently (AU-Q49) is logged in `docs/refused-shapes.md` with a pinning case but gets no `KnownShape` (AU-Q52b).
- **AU-Q57. Answered (2026-11-07, AL3c red-team M1): angle and square brackets in an unquoted value must pair up, or the value is refused.** Without this, `mx.example; spf=fail smtp.mailfrom=<x; dkim=pass header.d=bank.example header.b=>` parsed with an injected `dkim=pass`, flagged only `PVALUE_TSPECIALS`; before AU-Q45 the whole value was refused. Rule, within one unquoted pvalue: a `<` may appear only as the first character, and then its `>` must be the last character; at most one `[`, whose `]` is the last character or directly before that final `>`; no other `<`, `>`, `[` or `]`. `:` is unrestricted (IPv6). Otherwise `SYNTAX` at the first bracket that breaks the rule (an unclosed opener: at that opener), in lenient and strict mode alike (strict follows AU-Q16 precedence where both apply). Accepted: `<>`, `<user@example.com>`, `[192.0.2.1]`, `a@[192.0.2.1]`, `user@[IPv6:2001:db8::1]`, `<a@[192.0.2.1]>`. Refused: `<x`, `x>`, `<a>b`, `<evil@evil.example>@good.example`, `[a][b]`, `<<a>>`. Amends AU-Q45 and AU-Q53. Every real-world shape the sweep found is balanced. Positions (coordinator clarification of the wording above, 2026-11-07): the value is scanned left to right and the fault is the first bracket at which the rule is broken: a closer that is not where the rule allows it (`<a>b`, `<evil@evil.example>@good.example`: the `>`; `[a][b]`: the first `]`), a second or misplaced opener (`<<a>>`: the second `<`), or an opener left unclosed at the end of the run (`<x`: the `<`). In strict mode the leftmost refusal wins (AU-Q16): an earlier `PVALUE_TSPECIALS` deviation in the same run gives `DEVIATION` there (`<a>b`: `DEVIATION` at the `<`; `a:b>`: `DEVIATION` at the `:`), and at the same position `SYNTAX` wins over `DEVIATION` (`<x`: `SYNTAX` at the `<`).
- **AU-Q58. Answered (2026-11-07, AL3c red-team L1): `domain_of` strips one enclosing `<...>` and refuses everything else with the AU-Q45 characters.** If the whole value is exactly `<` + local-part + `@` + domain + `>`, `domain_of` returns the domain (so Zoho's `header.from=<noreply@mail.example.com>` gives `mail.example.com`); any other value containing `:`, `[`, `]`, `<` or `>` gives `None` (so `<evil@evil.example>@good.example`, `<user@example.com`, `a@[192.0.2.1]`, `<a@[192.0.2.1]>` and `<>` give `None`). `ascii_domain` is unchanged. Amends the AU-Q45 sentence on `ascii_domain`. Clarification (coordinator, 2026-11-07, AL3c red-team round 2 M1): "local-part + `@` + domain" means the text inside the brackets is exactly what the parser's address check accepts for an unbracketed value (AU-Q24, G10: one `@`, a local-part the unbracketed path accepts, a domain of two or more LDH labels), so `<evil@evil.example@good.example>`, `<a@@good.example>`, `<a..b@good.example>` and `<a@b>` give `None` (unbracketed, each is refused by the address check).

### Release decisions (AU-Q70 to AU-Q81, answered 2026-11-08, AL4)

The AL4 architect plan is `docs/plans/al4.md`. The maintainer asked that every decision below be stated here in full, so the README, workflows, issue forms and later notes can cite `docs/plan.md` for it.

- **AU-Q70. Answered: one `publish.yml`.** A manual "Run workflow" (`workflow_dispatch`) on `main` builds and publishes to TestPyPI in the GitHub environment `testpypi`; a pushed `v*` tag builds and publishes to PyPI in the environment `pypi`. The rehearsal runs the same build job and workflow as the real release.
- **AU-Q71. Answered: the rehearsal uses the release commit itself** (`release 0.1.0`), so PyPI gets the same bytes TestPyPI got. TestPyPI refuses a second upload of 0.1.0; a further rehearsal after an upload needs a new version on TestPyPI only.
- **AU-Q72. Answered: a `github-release` job** runs after the PyPI publish, with `contents: write` in that job only, creates the GitHub release for the tag with the CHANGELOG section as notes, and attaches the same wheel and sdist.
- **AU-Q73. Answered: PyPI's PEP 740 attestations only** (made by the publish action under Trusted Publishing); no separate GitHub build-provenance job, so `id-token: write` exists only in the two publish jobs.
- **AU-Q74. Answered: classifier `Development Status :: 3 - Alpha`** for 0.1.0.
- **AU-Q75. Answered: the AU-Q12 attestation check is recorded in this file** (status row and a slice note): date, tool and version, both file names with sha256, the tag commit, the publisher fields, the transparency-log indexes, and the result.
- **AU-Q76. Answered: citations of `PLAN.md` in tracked files refer to this document.** A note at the top of this file says so and maps the sections (for example, AU-Qs are section 11 in `PLAN.md` and section 10 here). Only the `pyproject.toml` `[tool.mutmut]` comment is rewritten; frozen and hash-pinned files keep their citations.
- **AU-Q77. Answered: a redaction miss that leaks personal data is reported privately** (GitHub private vulnerability reporting, per `SECURITY.md`), because the repro contains the data; `SECURITY.md` and the header-shape issue form say so.
- **AU-Q78. Answered: blank issues stay enabled**, and `.github/ISSUE_TEMPLATE/config.yml` adds a contact link for security reports.
- **AU-Q79. Answered: the release tag is a signed annotated tag** (`git tag -s`) if the maintainer has a signing key set up, otherwise an annotated tag (`git tag -a`).
- **AU-Q80. Answered: the `testpypi` environment has the maintainer as required reviewer**, like `pypi`, so the rehearsal also exercises the approval step.
- **AU-Q81. Answered: one README of about 400 lines**, which is also the PyPI page; every link in it is an absolute `https://github.com/jrapakko/authresults/blob/main/...` URL, because `docs/` does not ship and relative links break on PyPI. Where the README states a decision, it links to this file.

### Redaction helper decisions (AU-Q59 to AU-Q68, answered 2026-11-07, AL3d)

The AL3d architect plan is `docs/plans/al3d.md`; its rules R1 to R14 and section 13 are the spec for the test-writer and the implementer.

- **AU-Q59. Answered: the stderr report lists placeholder, kind and count only; a `--show-originals` flag adds the originals** (escaped, never raw control or format characters, with a "do not post this report" first line). stdout is identical either way. Reads the AL3d row's "a list of what it replaced" as kinds by default.
- **AU-Q60. Answered: a property whose ptype is outside `smtp`, `header`, `body`, `policy`, `dns`, `arc` is renamed `ptypeN.propN`**, so a domain in that position (`bank.example=1`) cannot pass through; the AL3d structure property compares such ptypes and their property names as `<other>`.
- **AU-Q61. Answered: only exact reserved names are kept** (`example`, `test`, `invalid`, `localhost`, `example.com/net/org`), plus the tool's own `[a-z]{1,4}.example` placeholders and the vendor hosts; subdomains such as `mail.example.com` are replaced.
- **AU-Q62 to AU-Q68. Answered as recommended:** the CLI strips one pasted `Authentication-Results:` or `ARC-Authentication-Results:` field name (Q62); invalid UTF-8 is decoded with `surrogateescape`, redacted and counted (Q63); the report shows the parse outcome of the original and the redacted value (Q64); producer words (`SAFE_WORDS`) and numbers of up to 4 digits are kept (Q65); the runtime vendor host list equals `tests/cases_vendor.VENDOR_HOSTNAMES` exactly (Q66); IPv4 placeholders use the three RFC 5737 ranges (762 addresses), then the tool fails closed with exit 1 (Q67); a refusal counts as "inside replaced text" when its position falls in a replaced span (Q68).
- **AU-Q69. Answered (2026-11-07): unknown words in keyword positions are renamed.** A method name, result word or property name is kept only if it is a registered name, a producer word seen in the vendor and refused cases, or an RFC 7208 9.1 key (`_redact.PRODUCER_WORDS`, tested equal to the set derived from `tests/cases_vendor.py` and `tests/cases_refused.py`); anything else becomes `tokN`. Found by the AL3d leak property (`qx.test; reason=qxsecret` kept `qxsecret` as a result word). The structure property compares renamed words as `<other>`. Details in `docs/plans/al3d.md` section 15.

### README items for AL4 (from the AL2b red-team and the AL3c sweep)

- The redaction helper (AL3d) keeps keyword positions only for registered and producer words (AU-Q69), keeps the authserv-id version and method-version digits at any length, numbers of up to 4 digits, vendor hostnames and the whole layout (folds, whitespace, comment nesting, counts of results and properties, which values are equal). Read its output before posting; run it on a file, not with `echo` (shell history).
- `domain_of` does no character validation (AU-Q33(a)): it can return text with non-ASCII spaces or C1 controls that the parser would refuse, and it accepts a bracketed address whose quoted local-part holds characters the parser would refuse (`<"a\x00"@good.example>` gives `good.example`; the domain is still the one named). Compare and look up domains only through `ascii_domain`, which refuses them (AL3c verifier V11).

- Brackets do not stop field splitting by a producer that wraps attacker-controlled text: `smtp.mailfrom=<x>; dkim=pass header.d=bank.example header.b=<>` is balanced and parses (AU-Q57 catches only unbalanced brackets), the same exposure as unbracketed text. `PVALUE_TSPECIALS` marks such values; callers that trust one producer's header should still prefer `strict_syntax=True` or check the deviation (AL3c red-team round 2).

- Callers must refuse `authserv_id is None` (or use `strict_syntax`), since an ARC value passed to `parse()` is usually refused, and one without an authserv-id reads as a missing-id header with an unregistered `i=1` result (corrected after the AL4 review).
- Under `ascii_only=False`, look-alike punctuation (U+037E, U+FF1D) stays inside values, so never NFC-normalise values before comparing.
- The `INTERNAL` reason, and that `MemoryError` and `RecursionError` map to it.
- Shapes known from real software and refused (AU-Q46, AU-Q48, AU-Q50, AU-Q51): Exim's ARC-Authentication-Results opening element, a bare domain between results, a job ID appended to the authserv-id (leave OpenDKIM/OpenDMARC's `AuthservIDWithJobID` off), and an authserv-id with no results and no `none`.
- A bare property named like a registered method (`spf=pass` under a dkim result) signals a missing `;` between results; that result is not reported (AU-Q49).
- `X-TM-Authentication-Results` and similar X- fields can be passed in; they parse with `MISSING_AUTHSERV_ID` and `BARE_PROPERTY` (AU-Q47).
- Under `PVALUE_TSPECIALS`, values may hold `:`, `[ ]` and `< >` as written (IPv6 addresses, IP-literal HELO, `<>`, `<addr>`); compare domains only through `ascii_domain` (AU-Q45).
- `AuthResultsError.known_shape` (AU-Q52): set to a `KnownShape` member when a refusal matches a shape known from real software, else `None`; log or count it with your own logger to see which shapes your traffic contains. The library never logs.
- Reporting real-world shapes (maintainer, 2026-11-07; the no-logging rule stands): a GitHub issue template "Report a header shape" (`.github/ISSUE_TEMPLATE/header-shape.yml`) asking for the vendor or software, the value rewritten to RFC 2606/6761 names and RFC 5737/3849 addresses (with a short checklist for removing personal details), and the `reason`, `position` and `known_shape` the caller got; and a README section "Seeing a refusal on real mail?" with a few lines of caller-side code that log those three fields (`reason`, `position`, `known_shape`) with the caller's own logger, never the header value or any part of it, and a link to the template. A report of a known shape counts as a vote to re-enable it; an unknown one becomes a new `docs/refused-shapes.md` entry through an AU-Q.
