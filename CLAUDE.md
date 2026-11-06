# CLAUDE.md

`authresults`: a zero-dependency, pure-Python, fully typed parser of one RFC 8601
`Authentication-Results` value (and one RFC 8617 `ARC-Authentication-Results`
value) into immutable objects.

## Scope

In: parsing one header value, a frozen IANA registry snapshot used for
`registered` flags, small domain helpers, a canonical serializer `to_value()`.

Out: DNS, DKIM/SPF/DMARC/ARC verification, message parsing, header field names,
comments as data, `Received` parsing, logging and warnings.

## Non-negotiables

- No runtime dependencies.
- No recursion; no regex over the whole input; one linear pass.
- No network access and no logging.
- A closed error set: only `AuthResultsError` with an `ErrorReason` escapes.
- Error messages never contain input text.
- Never drop data silently; keep and flag what is unknown or deviant.
- No downstream application names anywhere in the repository: not in files,
  paths or commit messages. CI checks tracked contents and paths; the prek
  hooks also check commit messages once `prek install` has been run.

## Commands

```sh
uv sync
uv run ruff check && uv run ruff format --check
uv run mypy
uv run coverage run -m pytest && uv run coverage report
uv build --build-constraints build-constraints.txt --require-hashes
uv run python scripts/check_lock_cooldown.py
prek run --all-files
```

## Outward steps

Publishing, pushing tags, changing repository or PyPI settings, and any other
outward-facing step need the user's explicit OK each time. Do not commit or
push unless asked.
