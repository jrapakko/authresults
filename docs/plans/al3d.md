# AL3d plan: redaction helper (`python -m authresults.redact`)

Architect plan for HEAD `891f17b` (2026-11-07). Spec: the AL3d row in `docs/plan.md` section 6. Open questions are AU-Q59 to AU-Q68 (section 10 here; answers recorded in `docs/plan.md` section 10).

## 0. Findings that shape the design

- `tests/test_invariants.py` scans every `src/authresults/*.py` (`_package_sources()` globs the folder), and `test_module_imports` allows only `enum, dataclasses, typing, collections.abc, contextlib, functools`. A CLI needs `sys`, so it needs a narrow, explicit exemption; nothing else in the package gets one.
- `tests/test_packaging.py` accepts any flat module matching `[a-z_][a-z0-9_]*\.py`, so `redact.py` and `_redact.py` need no allowlist change. `entry_points.txt` is already refused by the exact `WHEEL_DIST_INFO` set, so "no console script" is enforced implicitly; the plan adds explicit assertions anyway.
- The non-frozen scan in `tests/test_case_table_meta.py` (`_tree_problems`) forbids, in any new test file, importing `test_cases` / `ALL_CASES` or `_case` internals, and attribute stores on imported modules. The redact tests read the case modules directly (`from . import cases_vendor, cases_refused, ...`, each has `CASES`) and use `monkeypatch.setattr`. New files must not be named `cases_*.py` (that scan skips them, and the name implies case-table membership).
- `VENDOR_HOSTNAMES` lives only in `tests/cases_vendor.py`, which does not ship; `src/` needs its own copy.
- The recursion check merges function names across modules: a `_redact.py` helper named like a parser helper (`_value`, `_peek`, `_cfws`, `_keyword`, `scan`) can create a false cycle, so use distinct names.
- Reuse: `_tokenizer.control(c)` (C0 except HTAB, DEL, C1, surrogates, the AU-Q41 table); `_lexical.KEYWORD`, `TOKEN`, `LET_DIG`, `DIGITS`, `is_keyword`; `_checks.exact_text`; `_errors.call_guarded`. `_registry` names are private (`_RESULTS`, `_PROPERTIES`), so add a package-internal constant (section 3).

## 1. Scope and non-goals

In scope: `src/authresults/_redact.py` (scanner and placeholder allocator), `src/authresults/redact.py` (CLI), one constant in `src/authresults/_registry.py`, one CHANGELOG "Unreleased" line, new tests, and narrow edits to `tests/test_invariants.py` and `tests/test_packaging.py`.

Non-goals: the README section and issue template (AL4; items in section 11); a console script, `[project.scripts]` or any `pyproject.toml` change; a public Python API (not in `__all__`, may change without semver); file or argument input, or options other than `--help`; whole messages or other header fields; finding names inside free text (all free text is dropped instead); IDNA, NFC or IPv6 normalisation; mutmut over `_redact.py` (could be added to `[tool.mutmut]` later); keeping the parse unchanged where the fault is inside replaced text.

## 2. Placement and packaging

1. Two modules. `_redact.py` is pure (no I/O, no `sys`, full invariants). `redact.py` is the CLI shell with `main()` and an `if __name__ == "__main__":` guard. The split keeps the `sys` exemption to one small file. Rejected: one module (puts the scanner under the exemption); avoiding `sys` with `open(0)` (hides I/O, harder to test).
2. Only entry point: `python -m authresults.redact`. No console script.
3. Out of `__all__`: `__init__.py` is unchanged and imports neither module; tests import `authresults._redact` and `authresults.redact` directly; `tests/test_api.py` stays unchanged; a new test checks by AST that `__init__.py` imports neither module.
4. `tests/test_invariants.py`:
   - `EXTRA_IMPORTS = {"redact.py": frozenset({"sys"})}`; `test_module_imports` asserts `imports <= ALLOWED_IMPORTS | EXTRA_IMPORTS.get(module, frozenset())`.
   - New check: in `redact.py`, every `Name` node `sys` lies inside the module-level `if __name__ == "__main__":` block (the top-level `import sys` is allowed), and every `sys.<attr>` is in `{"argv", "stdin", "stdout", "stderr"}`.
   - Planted self-tests: `import sys` in another module fails; `sys.modules` in `redact.py` fails.
   - `assert {"_redact.py", "redact.py"} <= set(_package_sources())`, so a rename cannot drop coverage silently.
5. `tests/test_packaging.py`: the wheel contains `authresults/redact.py` and `authresults/_redact.py`; no `entry_points.txt` and no `Requires-Dist` (existing check stays); the sdist contains both files under `src/authresults/`.
6. Runtime hostname list: `_redact.KEEP_HOSTNAMES: frozenset[str]` with the same 14 names; `tests/test_redact.py` asserts `_redact.KEEP_HOSTNAMES == cases_vendor.VENDOR_HOSTNAMES` (equal, not superset; AU-Q66).

## 3. Interfaces and data flow

```python
# src/authresults/_redact.py  (imports: enum, dataclasses, typing; ._checks, ._errors, ._lexical, ._tokenizer, ._registry)
KEEP_HOSTNAMES: frozenset[str]
RESERVED_NAMES = frozenset({"example", "test", "invalid", "localhost", "example.com", "example.net", "example.org"})
KEEP_PTYPES = frozenset({"smtp", "header", "body", "policy", "dns", "arc"})   # arc: Exim's arc.oldest-pass
SAFE_WORDS: frozenset[str]   # _registry.REGISTERED_NAMES | {"rsa-sha1","rsa-sha256","ed25519-sha256","quarantine","reject","oreject","yes","no","ipv6"}
SELECTOR_PROPERTIES = frozenset({"s"}); BASE64_PROPERTIES = frozenset({"b", "bh"})
MAX_NUMBER = 999_999

class Kind(enum.StrEnum):  # explicit values
    DOMAIN="domain"; IPV4="ipv4"; IPV6="ipv6"; LOCAL_PART="local-part"; SELECTOR="selector"
    BASE64="base64"; JOB_ID="job-id"; NUMBER="number"; WORD="word"; PTYPE="ptype"; PROPERTY="property"

@dataclass(frozen=True, slots=True)
class Replacement: placeholder: str; kind: Kind; count: int

@dataclass(frozen=True, slots=True)
class Redaction:
    text: str                                # "" when not complete
    complete: bool                           # False only when a placeholder pool ran out
    replacements: tuple[Replacement, ...]    # first-appearance order; never original text
    free_text: int                           # free-text cores replaced by "..."
    non_ascii: int                           # non-ASCII, non-control characters removed
    controls: int                            # control()/AU-Q41 characters removed (CR, LF, HTAB excluded)
    arc: bool                                # an ARC "i=N;" prefix was read
    spans: tuple[tuple[int, int], ...]       # sorted, non-overlapping half-open original offsets replaced

def redact(value: str) -> Redaction          # = call_guarded(_redact_value, value); exact_text() first;
                                             # never raises on any str; non-str -> AuthResultsError(INVALID_TYPE)
def domain_label(n: int) -> str              # bijective base-26: 1->a, 26->z, 27->aa, ...; skips "none"; n <= cap
def ipv4_placeholder(n: int) -> str          # 1..254 -> 192.0.2.n, 255..508 -> 198.51.100.x, ...; cap 762
def ipv6_placeholder(n: int) -> str          # n<=0xffff: 2001:db8::{n:x}; else 2001:db8::{n>>16:x}:{n&0xffff:x}

# src/authresults/redact.py  (imports: sys, typing/collections.abc; ._redact, ._api, ._errors)
MAX_INPUT_BYTES = 1_048_576
EXIT_OK, EXIT_REFUSED, EXIT_USAGE, EXIT_INTERNAL = 0, 1, 2, 3
def main(argv: Sequence[str], stdin: BinaryIO, stdout: BinaryIO, stderr: BinaryIO) -> int
if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:], sys.stdin.buffer, sys.stdout.buffer, sys.stderr.buffer))
```

Add `REGISTERED_NAMES: frozenset[str]` to `_registry.py`: every method, result, ptype and property name, computed from the existing tables.

Data flow: bytes from stdin; CLI pre-processing (section 6); `redact(str)` in three passes (pass 0 maps comment and quoted-string regions; pass 1 is the state machine, emitting parts and collecting the `taken` placeholders; pass 2 allocates placeholders and joins); `Redaction`; the CLI writes ASCII to stdout and the fixed-format report to stderr.

## 4. Scanner rules (R1 to R14)

Both roles cite these rules. A test-writer who cannot decide a case asks; it never guesses.

**R1. Delimiters.** SP, HTAB, CR, LF, `(`, `)`, `;`, `"` (the parser's `RUN_STOP`). Always copied verbatim, including a stray `)` and bare CR or LF, so `CONTROL_CHAR` at a line break survives. A *run* is a maximal sequence of non-delimiters.

**R2. Pass 0 (regions).** Map each top-level `(` and `"` to the offset where it ends, mirroring `_tokenizer.delimit` (`\` quotes the next character, `"` inside a comment is text, `(` inside quotes is text), but with an unbounded depth counter, never raising, and an unterminated region ending at `len(text)`. Custom because `delimit` raises and enforces limits.

**R3. Comments and quoted free text.** Inside a region, structural characters are kept: unescaped `(` and `)` (comments only), CR, LF, and the opening and closing `"`. Between them, each text run becomes leading WSP, then `...` if the core is non-empty, then trailing WSP. A core already equal to `...` is kept and not counted. A `\` directly before CR or LF is kept after the `...`. Nesting, depth, unterminated regions and folds all survive: `(a (b\) c) d)` becomes `(... (...) ...)`, and `(a\r\n b)` becomes `(...\r\n ...)`.

**R4. States.** `START`, `AFTER_ID`, `METHOD`, `RESULT`, `ITEMS`, `PVALUE`. CFWS (delimiters and comments) is emitted as met. Lookahead skips CFWS using pass 0's region ends and looks at most one keyword ahead; CFWS is scanned at most twice.

**R5. `START`.**
- ARC prefix: if the value begins `i` CFWS `=` CFWS digits CFWS `;` (case-sensitive `i`), keep it verbatim, set `arc`, re-enter `START`.
- Quoted id: a quoted string is the authserv-id (R11), then `AFTER_ID`.
- Missing id (AU-Q35): if the first run's LDH prefix W is keyword-shaped, ends at a delimiter, `=` or `/`, and the next non-CFWS character is `=` or `/`, handle W as a method (`METHOD` logic).
- Otherwise the run is the authserv-id: rewrite it with R9 in id context, splitting at the first `/`; the part after it is a `JOB_ID` when it has no tspecials. Then `AFTER_ID`.

**R6. `AFTER_ID`.** A digit-only run is the version, kept verbatim whatever its length. Then `;` goes to `METHOD`. Anything else goes to `ITEMS` (recovery).

**R7. `METHOD`, after `;`.** A `;` stays in `METHOD`. A quoted string is free text and goes to `ITEMS`. Otherwise W is the run's LDH prefix:
- W ends at a delimiter, `=`, `/` or `.`, and the next non-CFWS character is `=`: a method, kept; go to `RESULT`.
- That character is `/`: keep `/`; a digit-only run after it is kept, any other run is rewritten with R9; if `=` follows go to `RESULT`, else `ITEMS`.
- W ASCII-lowercased is `none` and `;` or the end follows: keep it, go to `ITEMS`.
- `ptype.property=` lookahead (W, `.`, an LDH keyword P ending at a delimiter or `=`, then `=`, CFWS allowed between): handle as a propspec (R8). This is the Exim leading property.
- W directly followed by `.` and not a propspec (a stray domain): rewrite the whole run with R9, go to `ITEMS`.
- Anything else: rewrite the whole run with R9, go to `ITEMS`.

**R8. `RESULT`, `ITEMS`, `PVALUE`.**
- `RESULT`: a run that is entirely LDH is kept as the result keyword; any other run is rewritten with R9 (Mimecast's `envelope-from=sender@...` becomes `user1@...`); a quoted string is free text. Then `ITEMS`.
- `ITEMS`:
  - Propspec (the R7 lookahead holds): keep W and P when W ASCII-lowercased is in `KEEP_PTYPES`, or when `W.P` is a kept domain under R10 (needed for idempotence). Otherwise W becomes `ptypeN` and P becomes `propN` (AU-Q60). Emit `=` and enter `PVALUE` with context P.
  - `reason`: W is `reason` (any case) followed by `=`; keep it. A quoted value becomes free text (`"..."`). An unquoted run of only ASCII token characters is kept if it is in `SAFE_WORDS` or is a number of 4 digits or fewer, otherwise it becomes `...`. Any other unquoted run is rewritten with R9.
  - Bare property: W followed by `=`; keep W, enter `PVALUE` with context W.
  - Otherwise: rewrite the run with R9.
  - `;` goes to `METHOD`. A stray quoted string is free text.
- `PVALUE`: a quoted string followed directly by `@` becomes `"userN"`, then `@`, then the run after `@` rewritten with R9. Any other quoted string: if its content has no WSP, CR, LF, `\` or `"`, rewrite the content with R9 inside the quotes using the context; otherwise it is free text. An unquoted run is rewritten with R9 using the context. Then `ITEMS`.

**R9. Value rewrite** of the run `[s, e)` with a context.
- Step 0, whole run: kept (R10), or in `SAFE_WORDS` (ASCII case-insensitive), or 1 to 4 digits: verbatim. Selector context and no tspecials: `SELECTOR`. Base64 context and only `[A-Za-z0-9+/=_-]`: `BASE64`. Outside those contexts, a run of 16 or more characters, only base64 alphabet, no `.`, containing a digit or `+` or `/`: `BASE64`.
- Otherwise scan left to right. Separators `@ < > [ ] : , \` are copied verbatim.
  1. At the start of every piece (a hex digit, or `::`), take the maximal run over `[0-9A-Fa-f:.]`; if it holds 2 or more `:`, it is one `IPV6` piece. This check may run past `:` separators.
  2. A span is a maximal run of non-separators. A span that ends at `@` is one `LOCAL_PART` piece (so SRS local-parts are a single piece).
  3. Any other span is split at `/ = ?` (copied). Each piece is classified, in order: kept (R10); IPv4 (4 decimal groups 0 to 255, keyed canonically); only dots: kept; contains `.`: `DOMAIN`, keyed ASCII-lowercase; digits only: kept if 4 digits or fewer, else `NUMBER`; `SAFE_WORDS`: kept; keyword-shaped (`is_keyword`): `WORD` as `tokN`; anything else, including non-ASCII or control characters: `WORD` as `tok_N`.
- Base64 placeholder: `b64-N`, then `/` if the original contains `/`, then `=` if it contains `=` (keeps whether `PVALUE_TSPECIALS` fires).
- `tokN` and `tok_N` keep keyword-shapedness, which the parser's AU-Q35, AU-Q39 and keyword checks act on at a distance.

**R10. Kept forms.** Never replaced; each is added to `taken` wherever it appears, keyword positions included.
- Names, compared after ASCII lowercasing: exact `RESERVED_NAMES`, exact `KEEP_HOSTNAMES`, and `[a-z]{1,4}.example`. Subdomains of reserved names (`mail.example.com`) are replaced (AU-Q61).
- IPv4 in 192.0.2.0/24, 198.51.100.0/24 or 203.0.113.0/24.
- IPv6: a run starting `2001:db8:` or `2001:0db8:` (any case).
- Placeholders, with N = `[1-9][0-9]{0,5}`: `userN`, `tokN`, `tok_N`, `numN`, `selN`, `jobN`, `ptypeN`, `propN`; `b64-N` optionally followed by `/`, then optionally `=`.
- Free text: `...`.

**R11. Consistency and allocation (pass 2).** The key is (kind family, normalised original); the same key always gives the same placeholder. Numbers are allocated in first-appearance order per prefix, skipping `taken`. Pools: domain labels up to 4 letters (475,253 after skipping `none`); IPv4 762 (three /24s, hosts 1 to 254); IPv6 2^32 − 1; every other prefix 999,999. When a pool runs out, return `complete=False`, `text=""`, empty `replacements` and `spans`. Only IPv4 can run out within 1 MiB.

**R12. Characters.** Output is printable ASCII plus HTAB, CR and LF, by construction. Non-ASCII and `control()` characters are never delimiters; they sit inside a run or a free-text core and are always replaced, counted (`non_ascii` or `controls`) and never echoed, AU-Q41 characters included.

**R13. Idempotence.** Every output substring is a delimiter, a kept keyword, a kept form or a placeholder, and placeholders keep the R9 class the state machine branches on. So `redact(r.text)` gives the same text with `replacements == ()`, `free_text == 0`, `non_ascii == controls == 0`.

**R14. Linearity.** Each character is examined a bounded number of times (at most 3: pass 0, the state machine, the IPv6 and local-part lookaheads, the re-scan of skipped CFWS). Output is built with a list and `"".join`, with no slicing of the rest of the input. No recursion, no `re`. One function per state, so ruff's complexity rules pass without new ignores.

## 5. Worked examples

Synthetic secrets under `.test` and RFC 1918 or ULA addresses, so the repository stays free of real data.

1. `mx.qx1.test; dkim=pass (good signature) header.d=qx2.test header.i=bob@qx2.test header.s=qxsel header.b=Ab+/cd=` becomes `a.example; dkim=pass (...) header.d=b.example header.i=user1@b.example header.s=sel1 header.b=b64-1/=`.
2. `mimecast.com; spf=pass (x) client-ip=10.1.2.3; envelope-from=bob@qx.test; helo=mail.qx.test; dkim=pass header.i=@qx.test` becomes `mimecast.com; spf=pass (...) client-ip=192.0.2.1; envelope-from=user1@a.example; helo=b.example; dkim=pass header.i=@a.example`. Still `SYNTAX` with `SPF_DETAILS_AS_RESULTS`.
3. `mail.qx.test/4ABCD1234;\r\n\tdkim=none` becomes `a.example/job1;\r\n\tdkim=none`. Still `AUTHSERV_ID_JOB_ID`.
4. `parse_arc` on `i=1; qx.test; smtp.remote-ip=10.0.0.1;\r\n\tarc=none` becomes `i=1; a.example; smtp.remote-ip=192.0.2.1;\r\n\tarc=none`. Still `EXIM_ARC_LEADING_PROPERTY`.
5. RFC 8601 B.7: `foo.example.net` becomes `a.example`, every comment becomes `(...)`, `1362471462` becomes `num1`, and all keywords, CFWS and folds stay in place.
6. `bank.qx.test=1` in a property list goes through the R8 propspec check, then the direct-`.` value path, and becomes `a.example=1`. `qxcorp.test=1` becomes `ptype1.prop1=1` (under AU-Q60 B).

## 6. CLI behaviour (`redact.py: main`)

1. Arguments: none is normal. `--help` or `-h` prints the usage to stdout, exit 0. Anything else prints the usage to stderr, exit 2.
2. Read `stdin.read(MAX_INPUT_BYTES + 1)`. Longer than the limit: exit 1 with `authresults.redact: input is longer than 1048576 bytes; nothing written`.
3. Decode with `decode("utf-8", "surrogateescape")`; invalid bytes become lone surrogates and are redacted and counted under R12 (AU-Q63).
4. Strip, in this order, each reported as a note: one leading U+FEFF; an `Authentication-Results` or `ARC-Authentication-Results` field name, ASCII case-insensitive, optional WSP, and the `:` (AU-Q62); one trailing `\r\n` or `\n`.
5. Redact. If `complete` is False, exit 1 with `authresults.redact: too many distinct values to number; nothing written`.
6. Parse outcome (AU-Q64): `parse_arc` if `arc`, else `parse`, with defaults plus `max_length=MAX_INPUT_BYTES`, on both the original and the redacted value.
7. Output: stdout gets `text.encode("ascii")` (strict, a last net against leaks) plus `b"\n"`, written once; stderr gets the report.

`main` catches `Exception` (never `BaseException`) and exits 3 with `authresults.redact: internal error; nothing written`. Nothing reaches stdout before step 7. An `OSError` while writing gives exit 3 and `authresults.redact: could not write the output`; that stderr write is wrapped in `contextlib.suppress(OSError)`. No message ever contains input text.

stderr on success (exact, ASCII, each line ending `\n`; bracketed lines only when they apply):

```
authresults.redact: best effort; read the output before posting it
replaced (originals not shown):            <- or "replaced (originals not shown): none"
  <placeholder> <kind> x<count>            <- one per Replacement, first-appearance order
free text replaced with ...: <n>
[removed: <a> non-ASCII, <b> control or format characters]
[line breaks: <n> CRLF, <m> LF, <k> CR]
[input: removed <notes joined by "; ">]
parse (original): <ok [deviations: d1, d2] | <reason> [at position <p>] [known shape <k>]>
parse (redacted): <same format>
```

Kinds and not originals: the report exists to be shared, and printing originals beside placeholders would put the personal data in the same paste as the redacted value. The reporter has the original to check the mapping (AU-Q59).

## 7. Reuse and custom code

Reused: `_tokenizer.control` (with the AU-Q41 table), `_lexical` character sets and `is_keyword`, `_checks.exact_text`, `_errors.call_guarded`, `_registry` names, `_api.parse` and `parse_arc` (for the report). Tests reuse `tests/_strategies.py` (`models`, `layout_of`, `cfws`, `comments`, `join`), `tests/_hypothesis_profiles.py`, the case modules' `CASES`, and stdlib `ipaddress` and `re` (tests only).

Custom: the scanner must accept values the parser refuses, so the parser and `delimit` (which raise) cannot be reused; no stdlib module redacts header values; `ipaddress` is outside the import allowlist and a doc-range check is about 20 lines; no runtime dependencies by rule.

## 8. Tests (mapped to the AL3d acceptance)

**`tests/test_redact.py`: unit, CLI and timing**

1. Placeholders and numbering: domains; IPv4 (canonical key, `010.000.000.001` equals `10.0.0.1`); IPv6 (`fd00::1`, `::ffff:10.0.0.1`, `[IPv6:fd00::2]`); local-parts (plain, quoted, SRS as one piece); selector; base64 with each suffix; long base64 outside `b`/`bh`; job ID; number; `tokN` and `tok_N`; `ptypeN.propN`; consistency of repeated values; first-appearance order; skipping kept placeholders already in the input (`a.example`, `user1`, `192.0.2.1`, `tok1`, `2001:db8::1`); caps (`user1234567` and `abcde.example` are replaced); `domain_label` (1, 26, 27, 702, 703, 475,253, `none` skipped); `ipv4_placeholder` (1, 254, 255, 762); `ipv6_placeholder` (0xffff, 0x10000); exhaustion at 763 distinct IPv4.
2. Kept forms: every `KEEP_HOSTNAMES` entry in any case; a subdomain of a vendor host is replaced; `RESERVED_NAMES` exact; `mail.example.com` replaced; doc IPs; `SAFE_WORDS`; 1 to 4 digits; `KEEP_HOSTNAMES == cases_vendor.VENDOR_HOSTNAMES`.
3. Structure: RFC 8601 B.2 to B.7 (every keyword, CFWS, fold and version kept); the ARC prefix (`i=1;`, `i = 01 ;`); AU-Q35 and AU-Q39 shapes; `;;`, a trailing `;`, a stray `)`; the empty string and whitespace-only values unchanged; uppercase keywords kept.
4. Free text: nested comments, `\)`, a fold inside a comment, `\` before CR, unterminated comments and quotes, `()`, `( a )`, quoted reason, plain-token reason, compauth `reason=000`, tspecial reason `a@b.test`, a 1 MiB depth of parens.
5. Characters: each AU-Q41 range (one code point each, in every position), C0, DEL, C1, surrogates, Kelvin `dkim`, non-ASCII domains. Output always ASCII, counts exact. A bare CR or LF is kept.
6. Shape cases: every `docs/refused-shapes.md` value (doc artefacts included) and every `cases_vendor` / `cases_refused` value gets an exact expected output, with the parse reason and `known_shape` preserved. Each also has a secret-substituted variant (reserved names to `qx*.test`, doc IPs to `10.x`, `fd00::x`): preserved, and no `qx` in the output.
7. API hygiene: `redact` on a `str` subclass; a non-`str` gives `INVALID_TYPE`; a monkeypatched internal `RuntimeError` gives `INTERNAL` with no input in the traceback; `Redaction` frozen and slotted; `"qx"` never in `repr(redaction)`; spans sorted, in bounds, non-overlapping; `__init__.py` does not import `redact`/`_redact` (AST); `"redact"` not in `authresults.__all__`.
8. CLI: exact stdout and stderr bytes for the worked examples; each strip (BOM, field name, `\n`, `\r\n`, only one); `X-Authentication-Results:` not stripped; invalid UTF-8; exactly 1 MiB accepted, 1 MiB + 1 gives exit 1; exhaustion gives exit 1; `--help` exits 0; a bad argument exits 2; an internal error (monkeypatched, with a secret in the exception message) gives exit 3, empty stdout, no secret in stderr; stdout raising `BrokenPipeError` gives exit 3; stderr raising still returns a code; every fixed message and parse-report line exact; the `__main__` guard covered with `runpy.run_module("authresults.redact", run_name="__main__")` after `monkeypatch.delitem(sys.modules, "authresults.redact", raising=False)`, with `sys.stdin`/`stdout`/`stderr`/`argv` set through `monkeypatch.setattr` (TextIOWrapper over BytesIO), expecting `SystemExit(0)`.
9. Linear time, `pytest.mark.timeout(2)` at 8,192 characters and `pytest.mark.timeout(15)` at 2^20: repeated single characters (all `(`, `)`, `"`, `\`, `;`, `@`, `:`, `=`); repeated pairs (`a@`, `1:`, `1.`, `a.`, `<[`); one long token; many distinct domains, IPv6, local-parts; `dkim=pass `, `header.d=x `, `i=1;` repeated; `(`×n/2 + `)`×n/2; `\r\n ` repeated; `é`×n, U+200B×n, `\x00`×n; plus a CLI run at 1 MiB. Laptop budget: the whole file under about 60 s.

**`tests/test_redact_properties.py`: Hypothesis (`ci` and `nightly` profiles)**

- P1 never raises: full-Unicode text (surrogates included) plus a header alphabet; `redact` returns; output is ASCII with no controls except HTAB, CR and LF; `complete` is True unless there are more than 762 distinct IPv4.
- P2 no leak: structured values with planted secrets (marker `qx`) in every value slot (authserv-id, job ID, pvalues as token, address, quoted local, `<...>`, `[...]`; bare values; reasons; comments; junk next to keywords; single labels after `@`; IPv4 outside the doc ranges; IPv6 outside 2001:db8::/32), interleaved with `_strategies.cfws`. Assert `"qx" not in out.lower()`. An output-only oracle checks: every dotted quad is a doc address; every IPv6 run is in 2001:db8::/32; every unquoted local-part is `userN` or empty; every dotted name is a kept form or `kw.kw=`; comment interiors hold only `.`, WSP, CR, LF, parens and `\`. The stderr of `main` on the same input holds no secret either.
- P3 same structure: sources are every parse/parse_arc string case in the case modules (with their kwargs), `models()` then `to_value()` with layouts (comments, folds, quoted-pairs), and the P2 values. If the original is accepted (with `max_length=2**21`), the redacted value is accepted, and `structure()` is equal: `authserv_id is None`, `version_given`, `none`, `deviations`, the ARC instance, and per result method, `method_version`, result, `registered`, `reason is None`, and per property ptype, name, `quoted`, `registered`. A ptype outside `KEEP_PTYPES` compares as `"<other>"`, and so does its property name (AU-Q60).
- P4 refusals kept: the same sources plus random edits (insert, delete or replace with delimiter and tspecial characters). If the original is refused with reason r (not `TOO_LONG`) at position p, and p is `None` or not inside any span, the redacted value is refused with the same reason and `known_shape`. "Inside replaced text" means `start <= p < end` for some span (AU-Q68).
- P5 idempotent: on P1 and P2 inputs, `redact(out)` gives the same text and reports nothing replaced (R13).

Other gates: `tests/test_invariants.py` covers both modules (section 2); `tests/test_packaging.py` (section 2); coverage 100% with no pragmas; `mypy --strict` and ruff clean.

New test files: no imports from `test_cases` / `_case` internals, no attribute stores on modules, no `cases_*.py` names. One shared strategies module: `tests/_redact_strategies.py`.

## 9. Tests-first split and ownership

- Test-writer (fresh instance, gets this plan only): `tests/test_redact.py`, `tests/test_redact_properties.py`, `tests/_redact_strategies.py`, and the edits to `tests/test_invariants.py` and `tests/test_packaging.py`. Writes exact outputs by hand from R1 to R14; an undecidable case goes into its hand-off and becomes an AU-Q, never a guess.
- Implementer: `src/authresults/_redact.py`, `src/authresults/redact.py`, `src/authresults/_registry.py` (`REGISTERED_NAMES` only), `CHANGELOG.md` (one Unreleased line), and its own extra unit tests in `tests/test_redact_units.py` only. May not edit the test-writer's files; a dispute follows plan 6.4.
- Commits: `add redaction tests` (test files only), then `add redaction helper` (src plus CHANGELOG), pushed together.
- Coordinator: `docs/plan.md` and `PLAN.md` (status, AU-Q59 onward, AL4 README items).

## 10. Open questions (recommendation first)

- AU-Q59, stderr list: **answered (c)**: kinds only by default, plus a `--show-originals` flag. See section 13.
- AU-Q60 **answered (B)**, unknown ptypes (`x.y=` with x outside `smtp, header, body, policy, dns, arc`): (B) rename to `ptypeN.propN` (recommended; `bank.com=` would otherwise pass through); (A) keep verbatim.
- AU-Q61 **answered strict**, reserved names: strict, keep only exact RFC 2606/6761 names, the tool's `[a-z]{1,4}.example` and vendor hosts (recommended); lenient, keep every reserved suffix.
- AU-Q62, strip a leading `Authentication-Results:` / `ARC-Authentication-Results:` in the CLI: yes, exact names, case-insensitive, with a note (recommended); no.
- AU-Q63, invalid UTF-8: `surrogateescape`, redacted and counted (recommended); refuse with exit 1.
- AU-Q64, print the parse outcome of original and redacted: yes (recommended); no.
- AU-Q65, keep `SAFE_WORDS` and numbers of 4 digits or fewer in values: yes (recommended); redact every value.
- AU-Q66, vendor hostnames in src: exactly equal to the test list (recommended); a superset with a containment test.
- AU-Q67, IPv4 pool: three doc /24s (762), then fail closed with exit 1 (recommended); only 192.0.2.x (254).
- AU-Q68, "fault inside replaced text": the error position lies in a replaced span, `TOO_LONG` excluded by raising `max_length` in P3 and P4 (recommended); any fault at or after the first replaced span.

## 11. Risks, residual leaks, AL4 text

Still leaks, by design or as residue (document all):
- The authserv-id version (R6) and method-version digits are kept verbatim at any length (added in fix round 1, V4).
- A kept doc IPv6 written non-canonically (`2001:0db8:0:0:0:0:0:1`) is not reserved under its canonical spelling, so a placeholder can be the same address spelled differently (`2001:db8::1`), which a reader could misread as equal values (final red-team L-c; no data revealed; open after the 3-round cap).
- Any well-formed address in 2001:db8::/32 is kept (R10), so up to 96 bits after the prefix pass through when the input already uses the doc prefix.
- Word placeholders ignore ASCII case only; `QxÄb` and `qxäb` get different `tok_N` (fix round 3, L-b; cosmetic).
- Keyword positions are kept verbatim: method names, results, bare property names, method-version digits, property names under known ptypes (`header.<anything>`). A producer that puts personal words there passes them through.
- Kept values: `SAFE_WORDS`, numbers of 4 digits or fewer, kept forms and placeholder-shaped strings (`user12`, `tok3`, `sel5`), vendor hostnames (which reveal the provider).
- Structure is kept on purpose: layout (folds, indentation, whitespace counts, comment count and nesting), counts of results and properties, equality relations between values (alignment of `header.from` and `smtp.mailfrom`), and whether `/` or `=` appears in signatures. Together these can fingerprint the receiving system.
- Display names, `policy.*` and `X-` free text are replaced only because every non-safe word is replaced; a missed classification in a keyword position is the main residual risk and the red-team's target.
- Outside the tool: the original stays in shell history (`echo '...' |`) and terminal scrollback.

Engineering risks: the state machine diverging from the parser on accepted input (mitigation: P3 over the whole case table and generated layouts); false recursion cycles from merged names (distinct names, run `tests/test_invariants.py` early); 1 MiB runtime in pure Python (`str.find` where possible, measure, 15 s timeout); ruff complexity limits (one function per state); different placeholders for IPv6 spellings of one address (minor); CRLF lost when pasted into GitHub (the stderr line-break counts).

README and issue-template items for AL4:
- Run `python -m authresults.redact < value.txt`, or paste and press Ctrl-D; avoid `echo` (shell history).
- Best effort: read the output before posting it.
- It keeps keywords, vendor hostnames, short codes and the layout; it replaces domains, IPs, local-parts, selectors, signatures, job IDs, numbers longer than 4 digits, and all comment and reason text.
- Post the output in a code block, with the stderr lines `line breaks:` and `parse (original)` / `parse (redacted)`.
- The Python module API is not public.

## 12. Acceptance criteria

1. `python -m authresults.redact` works; `tests/test_packaging.py` asserts the wheel and sdist contain `redact.py` and `_redact.py`, there is no `entry_points.txt` and no `Requires-Dist`, and `pyproject.toml` is unchanged.
2. `authresults.__all__` and `tests/test_api.py` are unchanged; the AST test shows `__init__.py` imports neither module.
3. `tests/test_invariants.py` covers both modules (explicit assertion); `sys` only in `redact.py`, only inside the `__main__` guard, only `argv`, `stdin`, `stdout`, `stderr`; planted self-tests fail as expected; no recursion, no `re`, no banned constructs.
4. `_redact.KEEP_HOSTNAMES == cases_vendor.VENDOR_HOSTNAMES`.
5. Every unit case in section 8 items 1 to 7 matches its exact expected output and counts, including every `docs/refused-shapes.md`, `cases_vendor` and `cases_refused` value and their secret-substituted variants (reason and `known_shape` preserved, no `qx`).
6. P1 to P5 pass under the `ci` profile on 3.11 to 3.15.
7. The 8 KiB and 1 MiB timing cases and the CLI 1 MiB case pass within their timeouts.
8. CLI tests: exact bytes and exit codes 0, 1, 2 and 3 for every path in section 6; stdout empty on every failure; no input text in any stderr output; the runpy guard test exits 0.
9. `uv run coverage run -m pytest && uv run coverage report` gives 100%; `grep -rnE "pragma: no cover|type: ignore" src/` is empty.
10. `uv run mypy`, `uv run ruff check && uv run ruff format --check` clean, with no new per-file ignores.
11. The full check set from `CLAUDE.md` is green, including `prek run --all-files` and the forbidden-name check.
12. The verifier confirms the section 9 file ownership from the diff. The red-team's personal-data bypass attempts are fixed or, if they fall into a documented section 11 category, recorded there.

## 13. Answers (maintainer, 2026-11-07) and the `--show-originals` design

AU-Q59 (c); AU-Q60 (B); AU-Q61 strict; AU-Q62 to AU-Q68 as recommended. Sections 1 to 12 stand, amended by this section for AU-Q59 (c):

- **Arguments.** Accepted: none, `--show-originals`, or `-h`/`--help` alone. Anything else (including `--show-originals` twice or with `--help`) prints the usage to stderr and exits 2. The usage text names the flag and says its report is not for posting.
- **Data.** `Redaction` gains `originals: tuple[tuple[str, ...], ...]`, aligned with `replacements`: for each placeholder, the distinct original spellings in first-appearance order (so `Bob.Example` and `bob.example` both show for one domain placeholder). Declared with `field(repr=False)`, so `repr(redaction)` still never contains input text, and excluded from equality only if that is needed for the frozen-dataclass tests (decide in the tests; keep it compared by default). Free-text cores and removed characters are not listed.
- **Without the flag** the report is exactly section 6; nothing about originals is computed into the output.
- **With the flag** the report changes in three places: the first line becomes `authresults.redact: best effort; ORIGINALS SHOWN BELOW: do not post this report`; the header line becomes `replaced (originals shown):`; each replacement line becomes `  <placeholder> <kind> x<count> <- <o1> | <o2> ...`, where each original is written with `ascii()`-style escaping (printable ASCII except `\` and `|` as is; `\`, `|`, controls, non-ASCII, surrogates as `\\`, `\x7c`, `\xNN`, `\uNNNN`, `\UNNNNNNNN`), so the terminal never receives control or format characters. stdout is identical with and without the flag.
- **Acceptance changes.** Criterion 8's "no input text in any stderr output" holds for every run without the flag; with the flag, only the escaped originals appear, only on replacement lines, and an internal error or failure exit still prints only its fixed message. P2's stderr check runs without the flag; a separate property checks that with the flag every stderr line other than replacement lines is identical to the run without it, and that stdout bytes are identical.

## 14. Clarifications from the test-writer's questions (coordinator, 2026-11-07)

These fill gaps in sections 3 to 6 and 13. They are spec; both roles follow them.

1. A plain-token `reason` value replaced by `...` counts in `free_text`, like any other free-text core.
2. The `input:` notes are, in strip order: `byte order mark`, `field name`, `trailing line break`. Example: `input: removed byte order mark; field name; trailing line break`.
3. The `removed:` line appears when either count is non-zero, and always shows both numbers.
4. `line breaks:` counts CR, LF and CRLF in the value that is redacted, after the step-4 strips.
5. Parse lines: `ok`, or `ok deviations: d1, d2` with the `Deviation` values in the enum's definition order; on refusal `<reason value>`, then ` at position <p>` if the position is not `None`, then ` known shape <value>` if set. Example: `parse (original): syntax at position 12 known shape authserv_id_job_id`.
6. `Replacement.placeholder` for base64 includes its suffix (`b64-1/=`).
7. Every non-empty unquoted local-part becomes `userN`, unless it already is a `userN` placeholder (kept, R10). So `sender@`, `tok1@` and `a.example@` all become `userN@`; `user123@` stays.
8. R5's "(R11)" for a quoted authserv-id means R9: a quoted id whose content has no WSP, CR, LF, `\` or `"` has its content rewritten with R9 in id context inside the quotes; otherwise it is free text (`"..."`).
9. The ARC prefix may follow leading CFWS, which is copied as usual (R3 for comments): `" (a) i (b) = (c) 7 ;"` keeps its structure and sets `arc`.
10. Only the field name, the WSP before the colon, and the colon are stripped; WSP after the colon is kept as part of the value.
11. If the part after the authserv-id's `/` contains tspecials, it is not a `JOB_ID`; it is rewritten with R9 like any other run (the job-ID kind is not used).
12. Keys: a quoted and an unquoted local-part with the same content share a key (content after resolving quoted-pairs); local-parts are case-sensitive; domains, IPv6 and ptype/property keys are ASCII-lowercased; IPv4 is keyed canonically; `NUMBER` is keyed by the digits as written (`0123` and `123` differ).
13. The "only base64 alphabet" test outside `b`/`bh` uses the same alphabet as inside, `[A-Za-z0-9+/=_-]`, plus the length, no-`.` and digit-or-`+`-or-`/` conditions.
14. In R3, WSP between a core and a `\` before CR or LF is trailing WSP: `(a \` CR LF ` b)` becomes `(... \` CR LF ` ...)`.
15. stdout is written before stderr. If writing stdout fails, stderr gets only `authresults.redact: could not write the output` (no report), exit 3.
16. Section 13's "every stderr line other than replacement lines is identical" excludes the first line and the `replaced (...)` header line, which change by design.
17. `redact` looks up `_redact_value` as a module global at call time, so it can be monkeypatched. `domain_label`, `ipv4_placeholder` and `ipv6_placeholder` raise `ValueError` above their caps (internal; the allocator never calls them there). Free-text cores are included in `spans`.
18. Runtime: if the 1 MiB timing cases push the redact test files past about 60 s on this laptop once src exists, the coordinator decides how to trim them (fewer 1 MiB inputs, keep all 8 KiB ones); do not trim before measuring.

## 15. AU-Q69 and the implementer's disputes (coordinator, 2026-11-07)

**AU-Q69 (maintainer): rename unknown words in keyword positions.** A method name, a result word, a property name (bare, or under a kept ptype), and a ptype under AU-Q60 are kept only if, ASCII-lowercased, they are in `SAFE_WORDS` or in a new frozen constant `_redact.PRODUCER_WORDS`; otherwise they become `tokN` (keyword-shaped, so the parser reads the same structure), keyed ASCII-lowercase. Placeholder-shaped words stay kept (R10).
- `PRODUCER_WORDS` = every method, result and property name that appears in the parsed models of `tests/cases_vendor.py` and `tests/cases_refused.py` (accepted cases) and is not in `_registry.REGISTERED_NAMES`, plus the RFC 7208 9.1 keys (`client-ip`, `envelope-from`, `helo`, `receiver`, `identity`, `mechanism`, `problem`). A test asserts the constant equals that set exactly, as for `KEEP_HOSTNAMES` (AU-Q66).
- P3: a method, result or property name that is renamed compares as `"<other>"`, like AU-Q60's ptypes. Registered and producer words compare exactly.
- This supersedes R7's "a method, kept", R8's "a run that is entirely LDH is kept as the result keyword", and R8's "keep W" for bare properties and kept-ptype property names. Section 11's "keyword positions are kept verbatim" leak is closed except for registered and producer words.

**Rulings on the disputes.**
1. `kelvin dkim`: the implementer is right (R11 counts occurrences; R12 counts U+212A as non-ASCII). Expect `a.example x2` and `non_ascii=1`.
2. `non-ascii domain`: `non_ascii=1` (R12).
3. P2: with AU-Q69 a secret in a method, result or property position is renamed, so the generator keeps generating those positions and the oracle stays strict; nothing is filtered out.
4. `test_p3_case_table`: the bound becomes `>= 700` (the table yields 707 sources).

**Implementer's gap-fills (section 3a of its report), accepted as spec pending the verifier:** (a) trailing dots in an R9 run are copied, not replaced; (b) a quoted local-part containing CR or LF is free text, not `"userN"`; (c) `::` starts an IPv6 piece only where a piece may start, and the hex run must end at a separator, a split character or the end of the run; (d) base64 does not fire when every `/`- or `=`-separated piece is already kept; (e) before a `/` not followed by `digits [CFWS] =`, the first word of the authserv-id is rewritten with R9; (f) a kept form after `reason=` (including `...`) is kept; (g) method, bare-property and propspec keywords are non-empty and do not end in `-`; a placeholder-shaped ptype or property is kept; the long-base64 rule applies only outside the selector and base64 contexts; a job ID that is already a kept form stays; the domain after a quoted local-part's `@` is rewritten without the property's context.

AU-Q69 details (coordinator, after the test-writer's re-derivation): `PRODUCER_WORDS` is exactly the derived set (today `action`, `bimi`, `compauth`, `mail`, `skipped`, `tempfail` plus the seven RFC 7208 keys); `permfail` is not in it, so `dkim=permfail` becomes `dkim=tok1`. A renamed keyword has `Kind.WORD`. A renamed property keeps its original name as the PVALUE context (`header.bh=Ef+gh` becomes `header.tok1=b64-N`). A digits-only result outside an ARC prefix becomes `tokN`.

## 16. Fix round 1 (coordinator, 2026-11-08, from the verifier's V1 to V5)

1. **V1, IPv6 glued to other characters (leak).** Gap-fill (c) is split: keep "`::` starts a piece only where a piece may start"; drop "the hex run must end at a separator, a split character or the end of the run". A hex run over `[0-9A-Fa-f:.]` with 2 or more `:` is one `IPV6` piece wherever it ends (R9 step 1 as written). The characters after it, up to the next separator or split character, form their own piece and are classified by R9 step 3 as usual. So `fd12:3456:7890::1%eth0` becomes `2001:db8::1` followed by `%eth0` classified as a piece (`tok_1`), and `2a00:1450:4001:815::200ez` becomes `2001:db8::N` followed by `ez` classified (`tokN`). Idempotence must still hold.
2. **V2, test strength.** P3 and P4 over the P2 values must mostly run on values the parser accepts: the P2 generator builds each value inside a valid skeleton (an authserv-id, `;`, at least one `method=result`, and properties) so that a clear majority of generated values parse, and a test asserts that share (for example at least half of a fixed sample). P2 also gains the four missing slots: a quoted authserv-id, a method-version (`dkim/qx=`), a missing authserv-id (AU-Q35), and IPv6 glued to other characters or with a zone ID (`%eth0`).
3. **V3, CLI stream failures.** A failing stdout while printing `--help` gives `authresults.redact: could not write the output` and exit 3 (not "internal error"). A usage error exits 2 even if writing the usage to stderr fails. If stdout was written and the stderr report fails, exit 3 (stdout is complete; the report is missing). A failing `flush()` of stdout counts as a stdout write failure (`could not write the output`, exit 3), even if some bytes went out.
4. **V4, residual leak.** Section 11 adds: the authserv-id version (R6) is kept verbatim at any length, like method-version digits. Same for the AL4 README items.
5. **V5, test indirection.** `test_module_imports` calls the same `imports_allowed` helper that the planted self-test exercises.
6. **Readings confirmed after the test-writer's questions.** In R9 step 1 the hex run takes every `[0-9A-Fa-f:.]` character, so in `...::200ez` the `e` belongs to the IPv6 piece and the tail is `z`. R10's "IPv6: a run starting `2001:db8:`" means the IPv6 hex piece, not the whole R9 run: `2001:db8::1%eth0` keeps `2001:db8::1` and classifies `%eth0` as its own piece. The redact test files may take up to about 75 s (the reworked P2 values now mostly parse, so P3 and P4 do real work).
7. **After the src fix (coordinator).** (i) Accepted gap-fill: a tail glued to an IPv6 piece that R9 would class as a domain becomes `tok_N`, because a domain placeholder starting with a hex letter would extend the hex run on a second pass (R13). (ii) The P2 oracle accepts, right before `@`, an IPv6 piece in 2001:db8::/32 (with an optional glued placeholder tail) as well as `userN` or empty: R9 step 1 finds the IPv6 before the local-part check, and `user1@...` would lose the original's `PVALUE_TSPECIALS` (P3). The generator keeps producing that shape.

## 17. Fix round 2 (coordinator, 2026-11-08, from verifier V6/V7 and red-team M1, L1 to L6)

1. **M1, digits after `/`.** Digits after a `/` are kept only when they are a method version: digits, optional CFWS, then `=`. Otherwise the run is rewritten with R9: after the authserv-id it is a `JOB_ID` (`jobN`) when it has no tspecials (R5, so `mailhost/3456789012` gives `tok1/job1`); elsewhere digits of more than 4 characters become `numN`. This applies on the AU-Q35 path, in `METHOD`, and wherever the `VERSION` state is entered.
2. **L1, one version.** `AFTER_ID` keeps at most one digit-only run as the version. A further run goes to `ITEMS` recovery and is rewritten with R9.
3. **L2, ARC instance.** The ARC prefix (R5) requires 1 to 4 digits. With more digits the value is not read as an ARC prefix, and the run is rewritten by the normal rules (so long digit runs become `numN`).
4. **V6/L3, doc IPv6 with dots.** A hex run that starts `2001:db8:` or `2001:0db8:` is kept only if it contains no `.`. A doc-prefixed run with a `.` is replaced like any other IPv6 piece (it gets a placeholder). Placeholders never contain `.`, so idempotence holds.
5. **L4, split character after a glued tail.** After an IPv6 piece and its glued tail, a split character (`/ = ?`) is copied verbatim, and the next span starts after it (so `x=fd00::1zz/bob@qx.test` gives `tok1=2001:db8::1tok2/user1@a.example`, stable on a second pass).
6. **L5, word keys.** Every `WORD` piece (`tokN` and `tok_N`) is keyed ASCII-lowercase, in keyword and value positions alike, so placeholders do not reveal letter case. Local-parts stay case-sensitive (their own `userN` namespace, 14.12).
7. **L6, closed streams.** In the `__main__` guard, if `sys.stdin`, `sys.stdout` or `sys.stderr` is `None`, exit 3 without a traceback (write `authresults.redact: internal error; nothing written` to stderr if stderr exists). `sys` use stays inside the guard.
8. **V7, runtime.** `test_p5_idempotent_secret_values` is folded into `test_p2_no_leak` (same strategy: P2 calls `redact(result.text)` once more and adds the P5 assertions). Other P5 sources (P1's `header_text`) keep their own test. Target: the redact files under about 75 s.
9. Section 11 adds nothing new from this round: M1, L1 to L3 are closed by the rules above.
10. **Readings after the round-2 tests.** `qxhost /5551234567; dkim=pass` gives `tok1 /num1` (a `/` separated from the authserv-id by CFWS is not a job ID). A digits-only word in the result position follows AU-Q69 like any other result word: it becomes `tokN` whatever its length, so 17.3's `i=987654321; mx.qx.test; arc=pass` gives `i=tok1; a.example; arc=pass`.
11. **After the round-2 src fix.** The implementer's dispute is upheld: in `mx.qx.test; dkim/5551234567 header.d=qx.test` the two domains differ, so the second is `b.example` (R11). New gap-fill accepted: trailing dots of an unquoted local-part are copied (like gap-fill (a)), so `a.@b.c` gives `user1.@b.example` and the parser's refusal at `@` is kept; the P2 oracle accepts `userN` followed by dots. Runtime: the redact files take 63 s on a quiet machine and 83 to 98 s under load, almost all in the Hypothesis properties; accepted as is (CI runners are not this laptop), with no cut to example counts.

## 18. Fix round 3 (coordinator, 2026-11-08; last round)

1. **V8, dots-only local-part.** A non-empty unquoted local-part made only of dots becomes `userN` followed by those dots (`...@qx.test` gives `user1...@b.example`), in line with 14.7; the dots are kept so the parser's refusal stays where it was.
2. **L-a, doc IPv6 kept only when well formed.** A doc-prefixed hex run (`2001:db8:` / `2001:0db8:`, any case) is kept only if it is a well-formed IPv6 address: no `.`, groups of 1 to 4 hex digits, at most one `::`, and 8 groups at most (fewer than 8 only with `::`). Anything else gets an IPv6 placeholder like a non-doc run (so `2001:db8:5551234567` and `2001:db8::2a00:1450:4001:815::200e` are replaced). Placeholders are well formed, so idempotence holds.
3. **L-b, non-ASCII case.** Word keys stay ASCII-lowercased (no `str.lower()`, which the package avoids); a case difference in non-ASCII letters gives two `tok_N` placeholders. Recorded in section 11 as cosmetic (no data revealed).
