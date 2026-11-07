# Equivalent mutants

Surviving `mutmut` mutants of `src/authresults/_tokenizer.py` and
`src/authresults/_parser.py` that no test can kill, each with the reason the
mutated code behaves the same for every input (PLAN.md 4, mutation testing).
Any survivor not listed here is a test gap. Names are from `mutmut results`
(mutmut 3.8.1, AL3b, 2026-11-07); a source change can renumber them.

## Offsets that are never 0

The parser and tokeniser work on absolute offsets. Where an offset comes from
a search that starts at 1 or later, `>= 0` and `> 0` (or `>= 1`), and `< 0`
and `<= 0` (or `< 1`), mean the same thing.

| Mutant | Change | Why equivalent |
|---|---|---|
| `_tokenizer.x__quoted_end__mutmut_11`, `_12` | `quote >= 0` to `> 0`, `>= 1` | `quote` is found from `start + 1 >= 1` |
| `_tokenizer.x__quoted_end__mutmut_22`, `_23` | `backslash < 0` to `<= 0`, `< 1` | `backslash` is found from `i >= 1` |
| `_tokenizer.x__find__mutmut_11`, `_12` | `found < 0` to `<= 0`, `< 1` | every caller passes `start >= 1` (inside a quoted-string) |
| `_parser.x__pvalue__mutmut_66`, `_67` | `at >= 0` to `> 0`, `>= 1` | a pvalue starts after `=`, so `at >= 1` |
| `_parser.x__raise_at__mutmut_1`, `_2` | `fault >= 0` to `> 0`, `>= 1` | faults are offsets inside a pvalue or domain, so at least 1 |

## Boundaries that cannot meet

| Mutant | Change | Why equivalent |
|---|---|---|
| `_tokenizer.x__quoted_end__mutmut_33` | `quote < i` to `quote <= i` | when `quote == i`, searching again from `i` finds the same `quote` |
| `_tokenizer.x_delimit__mutmut_20` | `paren < quote` to `paren <= quote` | a `(` and a `"` cannot share an offset |
| `_tokenizer.x_delimit__mutmut_38` | `paren < end` to `paren <= end` | when `paren == end`, searching again from `end` finds the same `paren` |
| `_tokenizer.x_delimit__mutmut_48` | `quote < end` to `quote <= end` | as above, for `quote` |
| `_tokenizer.x_unquote__mutmut_53` | `lf < stop` to `lf <= stop` | `lf == stop` is "not found"; the mutant appends the rest with `removesuffix("\r")`, and the character before the closing `"` is never a CR (the scan allows CR only in CRLF followed by WSP) |

## Characters the scan has already refused

The character scan (`scan`) refuses C0, DEL, C1 (U+0080 to U+009F), lone
surrogates and the Zs, Zl, Zp and Cf characters before any later stage
reads the value.

| Mutant | Change | Why equivalent |
|---|---|---|
| `_tokenizer.x_control__mutmut_15` | `c > "\x9f"` to `c >= "\x9f"` | U+009F is caught by the C1 clause before it; it is not in the space and format table either |
| `_tokenizer.x_control__mutmut_16` | `c > "\x9f"` to `c > "XX\x9fXX"` | the guard only skips the table lookup; the table holds nothing below U+00A0, so the result is the same for every character |
| `_parser.x__start__mutmut_17` | `strip(" \t\r\n")` to `strip(None)` | the only other characters `str.strip()` removes are C0, C1, Zs, Zl and Zp, all refused by the scan |
| `_parser.x__token_end__mutmut_6` | `>= "\x80"` to `> "\x80"` | U+0080 is a C1 control |
| `_parser.x__check_token__mutmut_11` | `>= "\x80"` to `> "\x80"` | as above |
| `_parser.x__version__mutmut_8` | `lstrip("0")` to `lstrip("XX0XX")` | the slice holds only digits |
| `_parser.x__method_version__mutmut_9` | `lstrip("0")` to `lstrip("XX0XX")` | as above |

## Flags read only for truth

| Mutant | Change | Why equivalent |
|---|---|---|
| `_tokenizer.x_scan__mutmut_3` | `lf_fold = False` to `None` | the one caller tests the result with `if` |
| `_parser.x__items__mutmut_113` | `need_cfws = False` to `None` | read only as `if need_cfws and ...` |
| `_parser.x__check_token__mutmut_2` | `flagged = False` to `None` | read only as `if not flagged` |
| `_parser.x__check_token__mutmut_23`, `_24` | `flagged = True` to `None`, `False` | `_deviate` again adds the same deviation to a set (lenient), or never returns from the first call (strict) |

## Initial `need_cfws` in `_items`

| Mutant | Change | Why equivalent |
|---|---|---|
| `_parser.x__items__mutmut_3`, `_4` | `need_cfws = True` to `None`, `False` | on the first pass the item starts at the end of the result keyword. If there is no CFWS there, the next character cannot continue a keyword (the keyword run would have taken it), so `_keyword_end` raises `SYNTAX` at the same offset that the `need_cfws` check would. After a reason, `need_cfws` is set to `True` again |

## Detected, not counted as killed

| Mutant | Status | Note |
|---|---|---|
| `_tokenizer.x_unquote__mutmut_41` | segfault | `i = backslash - 2` loops and grows memory until the run's memory cap (`ulimit -v`) stops it |
| `_parser.x__address_end__mutmut_5` | timeout | the mutant loops; mutmut's timeout stops it |
