# AL4 plan: release workflow, README, issue template, 0.1.0

Architect plan for HEAD `2fb4b38` (2026-11-07). Spec: the AL4 row in `docs/plan.md` section 6, sections 1, 5, 7 and 8, AU-Q10 to AU-Q13, every "README items for AL4" entry, and `docs/plans/al3d.md` section 11. New questions start at AU-Q70 (section 9). I did not read `PLAN.md`.

## 0. Findings that shape the design

1. **Version.** `src/authresults/__init__.py` has `__version__ = "0.1.0.dev0"`. `pyproject.toml` has `dynamic = ["version"]`, so flit reads the version from `__init__.py`. `tests/test_packaging.py` derives the expected file names and the `Version` metadata from `authresults.__version__`, so changing that one line is the whole version change.
2. **ruff formats the README's code blocks.** Ruff 0.17.3 is locked, and since 0.16 `ruff format` formats fenced `python`/`py`/`pycon` blocks inside Markdown by default. The prek hook passes markdown files to `ruff format` explicitly. So every Python block in `README.md` must survive `uv run ruff format --check` (88 columns, double quotes). Whether CI's plain `ruff format --check` also picks up `README.md` without an explicit path is UNVERIFIED; the implementer runs both.
3. **What ships.** The sdist ships `README.md`. flit's sdist `include` list does not cover `.github/` or `docs/`, and `exclude` drops `**/.*`. So the issue template and `publish.yml` never ship, and **`tests/test_packaging.py` needs no allowlist change for them**. `README.md` is already in `SDIST_TOP_LEVEL`.
4. **PyPI renders the README as the long description.** Relative links (`docs/refused-shapes.md`, `SECURITY.md`) break on PyPI, so every README link must be an absolute `https://github.com/jrapakko/authresults/blob/main/...` URL.
5. **New test files are scanned.** `tests/test_case_table_meta.py::_tree_problems` scans every non-frozen `tests/*.py`. It bans imports of `test_cases`, `_case` internals and `conftest`, attribute stores on imported modules, and the names `__defaults__`, `__kwdefaults__`, `__code__` and `__closure__`. New files must not be named `cases_*.py`. `exec` would trip ruff `S102`, so the README's script blocks run through stdlib `runpy.run_path` and the REPL blocks through stdlib `doctest`. No new dependency.
6. **No YAML parser in the dev group.** pyyaml is only in the `mutation` group. Workflow and issue-template checks are therefore line-based text tests, and the YAML must follow the skeleton's 2-space layout. YAML syntax is checked by prek's `check-yaml` (locally only; CI does not run prek) and by GitHub when it renders the form.
7. **`PLAN.md` is cited in tracked files.** About 100 citations, in `src/` docstrings, `pyproject.toml` (the `[tool.mutmut]` comment), `.gitignore`, `mutmut-equivalent.md`, `docs/plans/al3d.md` and many test files. Some of those test files are frozen (`tests/cases_*.py`, `tests/_case.py`, `tests/test_cases.py`, `tests/test_case_table_meta.py`), and `tests/conftest.py`, whose docstring cites it, is pinned by hash (`test_conftest_post_al2b_hash`). Retiring `PLAN.md` leaves these citations dangling in the public repo (AU-Q76). `git log --all -- PLAN.md` is empty: it was never committed. It is ignored through `.git/info/exclude`.
8. **Existing pins to reuse:** `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1`, `astral-sh/setup-uv@68559e99cc807c1eb7e9238fd43a15bba460eec2 # v10.3.3`, `UV_VERSION: "0.13.5"`, `enable-cache: false`, `persist-credentials: false`. zizmor 1.31.1 is locked; CI runs it over the whole `.github/workflows` folder with `GH_TOKEN` for the online audits, so `publish.yml` is covered without a CI change. Dependabot's `github-actions` ecosystem picks up the new workflow on its own, so `dependabot.yml` needs no change.
9. **New actions** (latest releases, all at least 7 days old today, so the cooldown is met):
   - `actions/upload-artifact` v7.0.2 (7 Oct);
   - `actions/download-artifact` v8.0.2 (7 Oct; since v8 a hash mismatch fails by default);
   - `pypa/gh-action-pypi-publish` v1.14.3 (20 Oct; makes PEP 740 attestations by default under Trusted Publishing).

   The release pages omit the year; 2026 is inferred. For the AU-Q12 check: `pypi-attestations` 0.0.31 came out on 2026-11-02, inside the 7-day cooldown, so use 0.0.30 (2026-07-28) unless 0.0.31 is older than 7 days on release day.

## 1. Scope and non-goals

**In scope:**
- `.github/workflows/publish.yml`;
- a rewritten `README.md`;
- `.github/ISSUE_TEMPLATE/header-shape.yml` and `.github/ISSUE_TEMPLATE/config.yml`;
- the `CHANGELOG.md` 0.1.0 section;
- a short "Releasing" section in `CONTRIBUTING.md`;
- one line in `SECURITY.md` (AU-Q77);
- `pyproject.toml`: the classifier (AU-Q74) and the `[tool.mutmut]` comment that cites `PLAN.md`;
- `__version__` set to `0.1.0`;
- new tests `tests/test_readme.py` and `tests/test_release_files.py`, plus additions to `tests/test_packaging.py`;
- the maintainer's outward steps (section 7) and the AU-Q12 record.

**Non-goals:**
- any change to parser, serializer, helper or redaction behaviour (no `src/` logic change; `git diff -- src/` touches only the `__version__` line);
- new `ErrorReason`, `Deviation` or `KnownShape` members;
- a docs site or a separate usage document;
- debug logging (deferred, section 8);
- actionlint or any other new dev dependency;
- GitHub-side build provenance (AU-Q73);
- a console script;
- rewriting the frozen test files' citations (AU-Q76).

## 2. Versioning

- The version lives in `src/authresults/__init__.py` as `__version__ = "0.1.0.dev0"`. It stays `.dev0` through commit 2 and becomes `"0.1.0"` in commit 3 (`release 0.1.0`), together with the CHANGELOG date and the classifier.
- Tags are `v<version>`, so `v0.1.0`. Annotated, and signed if a signing key is set up (AU-Q79). The tag goes on the commit 3 SHA, which must already be on `main` with CI green.
- The workflow refuses a tag that is not `v` + `__version__`, and a tag whose commit is not an ancestor of `origin/main`.
- Next development version: none. The project goes straight to the next release number later, with `## [Unreleased]` kept in the CHANGELOG. `tests/test_release_files.py` accepts both forms (section 6).

## 3. `publish.yml`

**Decision (AU-Q70):** one workflow with two triggers.
- A push of a `v*` tag publishes to PyPI in environment `pypi`.
- `workflow_dispatch` on `main` publishes to TestPyPI in environment `testpypi`. This is the AU-Q10 rehearsal.

The two publish jobs are separate, each with a fixed environment and a fixed `if:`, rather than one job with a computed environment: clearer for zizmor, for reviewers and for the structural test.

Skeleton (SHAs as placeholders; the comment after each SHA is the exact version tag):

```yaml
name: Publish

# A v* tag: build, publish to PyPI (environment pypi), then a GitHub release.
# A manual run on main: build, publish to TestPyPI (environment testpypi);
# the release rehearsal (docs/plan.md AU-Q10). Trusted Publishing only: no
# API tokens, no secrets. Only the publish jobs get id-token: write.

on:
  push:
    tags: ["v*"]
  workflow_dispatch:

permissions: {}

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: false

env:
  UV_LOCKED: "1"
  UV_VERSION: "0.13.5"

jobs:
  build:
    name: build and check distributions
    runs-on: ubuntu-latest
    permissions:
      contents: read
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
          fetch-depth: 0  # origin/main is needed for the ancestor check
      - uses: astral-sh/setup-uv@68559e99cc807c1eb7e9238fd43a15bba460eec2 # v10.3.3
        with:
          version: ${{ env.UV_VERSION }}
          python-version: "3.15"
          enable-cache: false
      - name: check the trigger
        env:
          EVENT: ${{ github.event_name }}
          REF: ${{ github.ref }}
        run: |
          commit="$(git rev-parse "$GITHUB_SHA^{commit}")"
          case "$EVENT" in
            push)
              case "$REF" in refs/tags/v*) ;; *) echo "::error::not a v* tag"; exit 1 ;; esac
              git merge-base --is-ancestor "$commit" origin/main \
                || { echo "::error::the tagged commit is not on main"; exit 1; } ;;
            workflow_dispatch)
              [ "$REF" = refs/heads/main ] || { echo "::error::run the rehearsal from main"; exit 1; } ;;
            *) echo "::error::unexpected trigger"; exit 1 ;;
          esac
      - run: uv sync
      - name: build
        run: |
          SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
            uv build --build-constraints build-constraints.txt --require-hashes
      - name: exactly one wheel and one sdist, named for the version
        env:
          EVENT: ${{ github.event_name }}
          REF_NAME: ${{ github.ref_name }}
        run: |
          version="$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' src/authresults/__init__.py)"
          [ -n "$version" ] || { echo "::error::no __version__"; exit 1; }
          expected="$(printf '%s\n' "authresults-$version-py3-none-any.whl" "authresults-$version.tar.gz" | sort)"
          actual="$(find dist -maxdepth 1 -type f ! -name .gitignore -printf '%f\n' | sort)"
          [ "$actual" = "$expected" ] || { echo "::error::dist/ does not hold exactly one wheel and one sdist"; exit 1; }
          if [ "$EVENT" = push ] && [ "$REF_NAME" != "v$version" ]; then
            echo "::error::the tag does not match the package version"; exit 1
          fi
      - name: check distributions
        run: |
          uv run twine check --strict dist/*.whl dist/*.tar.gz
          uv run check-wheel-contents dist/*.whl
          AUTHRESULTS_WHEEL="$(ls dist/*.whl)" AUTHRESULTS_SDIST="$(ls dist/*.tar.gz)" \
            uv run pytest tests/test_packaging.py
      - name: hashes
        run: sha256sum dist/*.whl dist/*.tar.gz | tee -a "$GITHUB_STEP_SUMMARY"
      - uses: actions/upload-artifact@<SHA> # v7.0.2
        with:
          name: dist
          path: |
            dist/*.whl
            dist/*.tar.gz
          if-no-files-found: error
          retention-days: 7

  publish-testpypi:
    name: publish to TestPyPI (rehearsal)
    if: github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'
    needs: build
    runs-on: ubuntu-latest
    timeout-minutes: 15
    environment:
      name: testpypi
      url: https://test.pypi.org/p/authresults
    permissions:
      id-token: write  # Trusted Publishing and PEP 740 attestations
    steps:
      - uses: actions/download-artifact@<SHA> # v8.0.2
        with:
          name: dist
          path: dist
      - name: exactly one wheel and one sdist
        run: |
          [ "$(ls -A dist | wc -l)" -eq 2 ] && ls dist/*.whl dist/*.tar.gz \
            || { echo "::error::unexpected artifact contents"; exit 1; }
      - uses: pypa/gh-action-pypi-publish@<SHA> # v1.14.3
        with:
          repository-url: https://test.pypi.org/legacy/
          attestations: true

  publish-pypi:
    name: publish to PyPI
    if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')
    needs: build
    runs-on: ubuntu-latest
    timeout-minutes: 15
    environment:
      name: pypi
      url: https://pypi.org/p/authresults
    permissions:
      id-token: write  # Trusted Publishing and PEP 740 attestations
    steps:
      - uses: actions/download-artifact@<SHA> # v8.0.2
        with:
          name: dist
          path: dist
      - name: exactly one wheel and one sdist
        run: |
          [ "$(ls -A dist | wc -l)" -eq 2 ] && ls dist/*.whl dist/*.tar.gz \
            || { echo "::error::unexpected artifact contents"; exit 1; }
      - uses: pypa/gh-action-pypi-publish@<SHA> # v1.14.3
        with:
          attestations: true

  github-release:                     # AU-Q72 option A; delete the job under B or C
    name: GitHub release
    needs: [build, publish-pypi]
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: write  # create the release
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/download-artifact@<SHA> # v8.0.2
        with:
          name: dist
          path: dist
      - name: create the release from the CHANGELOG section
        env:
          GH_TOKEN: ${{ github.token }}
          GH_REPO: ${{ github.repository }}
          TAG: ${{ github.ref_name }}
        run: |
          version="${TAG#v}"
          awk -v h="## [$version]" 'index($0, h) == 1 {f=1; next} /^## \[/ {f=0} f' CHANGELOG.md > "$RUNNER_TEMP/notes.md"
          [ -s "$RUNNER_TEMP/notes.md" ] || { echo "::error::no CHANGELOG section for $version"; exit 1; }
          gh release create "$TAG" dist/*.whl dist/*.tar.gz --verify-tag \
            --title "authresults $version" --notes-file "$RUNNER_TEMP/notes.md"
```

Rules the skeleton encodes, each checked by `tests/test_release_files.py`:
- `permissions: {}` at top level.
- `contents: read` in `build`, and no `id-token` there.
- `id-token: write` only in `publish-testpypi` and `publish-pypi`.
- The publish jobs only download: no `actions/checkout`, no `uv`.
- No `secrets.`, no `pull_request_target`, no `pull_request`.
- Every `${{ }}` used in a `run:` goes through `env:` (zizmor `template-injection`).
- No caching (`enable-cache: false`; zizmor `cache-poisoning` treats tag workflows as release workflows).
- `SOURCE_DATE_EPOCH` is set inline, not through `$GITHUB_ENV` (zizmor `github-env`).

UNVERIFIED and handled defensively:
- Whether `uv build` writes `dist/.gitignore`: the check ignores exactly that name, and the artifact uploads only `*.whl` and `*.tar.gz`.
- Whether `GITHUB_SHA` for an annotated tag is the tag object: hence `^{commit}`.
- That the SHA-pinned pypa action builds its Docker image at run time: slower, still fine.

**Getting the SHAs without `gh`** (coordinator, read-only network):

```sh
git ls-remote --tags https://github.com/actions/upload-artifact 'refs/tags/v7.0.2*'
git ls-remote --tags https://github.com/actions/download-artifact 'refs/tags/v8.0.2*'
git ls-remote --tags https://github.com/pypa/gh-action-pypi-publish 'refs/tags/v1.14.3*'
```

- If the output has a `refs/tags/vX^{}` line, the tag is annotated: use that line's SHA, which is the commit. Otherwise use the single line's SHA.
- Cross-check each SHA one way: the commit shown on the release page, or `curl -s https://api.github.com/repos/<owner>/<repo>/commits/<tag>` (unauthenticated) and its first `"sha"`.
- CI's zizmor run (online audits with `GH_TOKEN`) then flags any SHA that does not match its version comment (`ref-version-mismatch`).

## 4. README

One file, about **400 lines** (hard ceiling 500). It is the PyPI page. Headings below are exact (the test checks them in order). **M** = mandatory, **O** = optional.

1. `# authresults` (M). One paragraph: what it parses, zero dependencies, fully typed, immutable results; no DNS, no verification, no message parsing. Status line: "0.1.0, the first release (alpha). The API may change in 0.x minor releases; see Versioning and stability."
2. `## Install` (M). `pip install authresults` or `uv add authresults`; Python 3.11 or later; no runtime dependencies; ships `py.typed`.
3. `## Quick start` (M). `pycon` blocks (doctested), using RFC 2606 names only:
   - parse a two-result value;
   - `authserv_id`;
   - `[(r.method, r.result) for r in ar.results]`;
   - `results_for("dkim")[0].get_unique("header", "d").value`;
   - `ascii_domain("Example.COM")`;
   - `parse_arc("i=1; mx.example.net; arc=none").instance`;
   - one `to_value()`.
4. `## What it does and does not do` (M):
   - the scope and out-of-scope lists (CLAUDE.md, plan section 1);
   - comments are dropped, never data;
   - RFC 8617 is Experimental, and nothing ARC-specific (chain validation, `ARC-Seal`) is in scope;
   - the `registered` flags come from a frozen IANA snapshot dated **2026-05-22** (must equal `_registry.LAST_UPDATED`), and a snapshot refresh is a patch release;
   - `domainkeys=fail` is unregistered because IANA lists no `fail` for it (AU-Q31);
   - U-labels are left to the caller's `idna` package (AU-Q5).
5. `## Using it on received mail` (M, the plan section 1 pattern). Bullets:
   - read with `email.message_from_bytes(data, policy=email.policy.default)`;
   - walk `msg.raw_items()` top-down;
   - only headers above your receiving host's arrival `Received` were written by your hosts, so parse only those, and pick the one whose `authserv_id` equals your expected id;
   - never parse, or refuse on, headers further down (attacker-controlled); check where your MTA puts its headers;
   - strip a trailing CRLF or LF from the raw value (AU-Q29; `raw_items()` may already have stripped it, UNVERIFIED);
   - treat `AuthResultsError` or any exception as "refuse";
   - match by token, never by substring;
   - `get_unique()` for `header.from`, `header.d` and `header.i`; compare domains only through `ascii_domain()`;
   - DKIM domain is `header.d`, or else `domain_of(header.i)` (AU-Q13);
   - refuse a header whose `deviations` are outside a set you have checked, or use `strict_syntax=True`;
   - refuse `authserv_id is None` (an ARC value passed to `parse()` reads as a missing id with an unregistered `i=1` result);
   - keep the defaults `max_length=8192` (counted in characters; checked first, so oversize costs O(1)) and `ascii_only=True` (removes look-alike keywords and punctuation);
   - RFC 8601 consumer rules, quoted with attribution (G17): ignore unregistered results and ptypes (test `registered`), and §2.7.6's SHOULD ignore a field with an unknown method.

   Two `python` blocks (run by the test, section 6):
   - **Selection block:** imports plus `def trusted_results(data: bytes, authserv_id: str, *, own_received: int = 1) -> AuthenticationResults | None`. It:
     - walks `raw_items()` top-down, comparing names ASCII case-insensitively;
     - looks only at `Authentication-Results` fields seen before the `own_received`-th `Received`, and returns `None` if there are fewer `Received` fields than that;
     - strips a trailing CRLF or LF, then calls `parse()` with defaults;
     - returns `None` if any candidate raises;
     - returns `None` if no candidate, or more than one, has `authserv_id == authserv_id`; otherwise the one match.
   - **Decision block:** `EXPECTED_DEVIATIONS: frozenset[Deviation] = frozenset()`, plus two functions:
     - `def dmarc_pass(results: AuthenticationResults, from_domain: str) -> bool`. True only if `deviations <= EXPECTED_DEVIATIONS`, there is exactly one dmarc result, it is `registered` and `result == "pass"`, `get_unique("header", "from")` is present, and `ascii_domain(value) == ascii_domain(from_domain)` with neither side `None`. `AuthResultsError` gives `False`.
     - `def dkim_pass_domains(results: AuthenticationResults) -> frozenset[str]`. The `ascii_domain` of `header.d`, or else of `domain_of(header.i)`, for each registered dkim pass, skipping `None`. Empty if `deviations` is not a subset of `EXPECTED_DEVIATIONS`, and empty if any dkim result raises `DUPLICATE_PROPERTY`.
6. `## The result model` (M):
   - a short table of the four dataclasses and their fields (plan 2.2);
   - accessors: `results_for`, `get`, `get_unique` lowercase their arguments (AU-Q15d);
   - accessors reject `str` subclasses with `INVALID_TYPE`, while `parse()` and the helpers normalise them (AU-Q43);
   - `to_value()`: one canonical line; refuses CR, LF, other controls, Unicode space and format characters, and non-ASCII under `ascii_only=True`;
   - `Property.raw` versus `value`.
7. `## Strict and lenient parsing` (M):
   - a table of all 5 `Deviation` values with one example each;
   - `strict_syntax`;
   - `require_registered` (unregistered names are kept, never dropped).

   Subsections:
   - `### Characters in unquoted values` (M). `PVALUE_TSPECIALS` covers exactly `/ = ? : [ ] < >`, unquoted, in a property value; `/ = ?` before an `@` are legal local-part characters and not flagged. Values keep these characters as written (IPv6 such as `smtp.remote-ip=2001:db8::1`, IP-literal HELO `[192.0.2.1]`, `<>`, `<addr>`), so compare domains only through `ascii_domain` (AU-Q45). `,` and `\` are refused as `SYNTAX`, and so are `;`, `(` and `"`; widening the deviation to them is the considered alternative, only with a fixture that needs it (AU-Q22). Brackets must pair up (AU-Q57). Caveat: balanced brackets do not stop field splitting by a producer that wraps attacker text (`smtp.mailfrom=<x>; dkim=pass header.d=bank.example header.b=<>` parses), so prefer `strict_syntax=True` or check the deviation. One `pycon` example: `header.b=Ab+/cd=` gives `{PVALUE_TSPECIALS}`.
   - `### A missing ";" between results` (M, AU-Q49). A `pycon` example where `mx.example.net; dkim=pass spf=pass smtp.mailfrom=example.com` gives `results_for("spf") == ()` and `BARE_PROPERTY`. A bare property named like a registered method signals a missing `;`; that result is not reported and never becomes a pass; strict refuses it.
   - `### X- fields such as X-TM-Authentication-Results` (M, AU-Q47). The library parses any value it is given. These fields use RFC 8601 syntax with no authserv-id, so they parse with `MISSING_AUTHSERV_ID` and `BARE_PROPERTY`. Prose only, no invented vendor value.
   - `### Non-ASCII input` (M). With `ascii_only=False`, UTF-8 is allowed in values, never in keywords. Look-alike punctuation (U+037E, U+FF1D) stays inside values, so never NFC-normalise values before comparing. Unicode space and format characters are always `CONTROL_CHAR`.
8. `## Errors` (M):
   - `AuthResultsError` is a `ValueError` with `reason`, `position` (character offset or `None`) and `known_shape`;
   - the message is exactly `"<reason>"` or `"<reason> at position <n>"`, never input text, and `known_shape` is not in it;
   - a table of all 18 `ErrorReason` values with one line each;
   - `ValueError` for bad limits or flags is the one documented exception, raised before any input is read;
   - `INTERNAL`: any unexpected exception, including `MemoryError` and `RecursionError`, chained to a cause that carries only the type name;
   - frame locals, as error trackers capture them, are out of the library's reach (plan 2.3);
   - `DUPLICATE_PROPERTY` comes from `get_unique()`;
   - one `pycon` example printing `err.reason, err.position, err.known_shape` for `mx.example.net/4ABCD; dkim=none` (`syntax 14 authserv_id_job_id`, which the implementer confirms by running it).
9. `## Helpers` (M):
   - `domain_of`: the text after the last `@`; strips one enclosing `<...>` around a valid address; `None` for other bracketed or AU-Q45-character values (AU-Q58). It does no character validation (it can return C1 controls or non-ASCII spaces, and `<"a\x00"@good.example>` gives `good.example`), so always pass its result through `ascii_domain` before comparing or looking up.
   - `ascii_domain`: LDH labels only, ASCII-lowercased; `xn--` passes unvalidated; no length checks (AU-Q33a).
10. `## Shapes known from real software` (M):
    - the 5 `KnownShape` values, one line each: Exim's ARC opening element (AU-Q46); a bare domain between results (AU-Q48); a job ID after the authserv-id (AU-Q50; leave OpenDKIM/OpenDMARC `AuthservIDWithJobID` off); an authserv-id with no results and no `none` (AU-Q51; refused for now, quick to change); `Received-SPF` keys written as results (AU-Q54);
    - the AU-Q52 rule: the library never logs; `known_shape` is set only on a refusal matching a shape in the log, never on `INTERNAL` or `INVALID_TYPE`, holds no input text, and leaves `reason` and `position` unchanged; count or log it with your own logger to see which shapes your traffic has;
    - an absolute link to `docs/refused-shapes.md`.
11. `## Seeing a refusal on real mail?` (M; exact heading from plan section 10). A `python` block defining `def parse_or_log(value: str) -> AuthenticationResults | None`:
    - `logger = logging.getLogger(__name__)`;
    - on `AuthResultsError as err`, call `logger.warning("authresults refused a header: reason=%s position=%s known_shape=%s", err.reason, err.position, err.known_shape)` and return `None`;
    - no `exc_info`; the value is never logged.

    Then the prose: never log the header value or any part of it; to report a shape, run the redaction helper and open the issue form at `https://github.com/jrapakko/authresults/issues/new?template=header-shape.yml`. A report of a known shape counts as a vote to re-enable it; an unknown one becomes a new log entry through a question.
12. `## Redacting a value for a report` (M; al3d section 11 and the plan's AL4 item):
    - `python -m authresults.redact < value.txt` (write the value to a file with an editor), or run it, paste, and press Ctrl-D; avoid `echo`, which keeps the value in shell history; scrollback keeps it too;
    - stdout is the redacted value; stderr is a report; exit codes 0, 1 (too long, or too many distinct values), 2 (usage), 3 (internal or write failure);
    - post the stdout value in a code block, plus the stderr lines `line breaks:`, `parse (original):` and `parse (redacted):`;
    - `--show-originals` output is for your own check and must never be posted;
    - it replaces domains, IP addresses, local-parts, selectors, signatures, job IDs, numbers longer than 4 digits, all comment and `reason` text, and unknown words in keyword positions (AU-Q69); it keeps registered and producer words, vendor hostnames, short codes and the layout;
    - residuals (al3d section 11 as amended through section 19; the L-c entry is gone):
      - authserv-id version and method-version digits kept at any length;
      - any well-formed address in 2001:db8::/32 kept;
      - kept values: safe words, numbers of up to 4 digits, placeholder-shaped strings, and vendor hostnames, which reveal the provider;
      - structure kept on purpose: folds, whitespace, comment nesting, counts of results and properties, which values are equal, whether `/` or `=` appears in a signature; together these can fingerprint the receiving system;
    - best effort: read the output before posting;
    - the Python module API is not public.
13. `## Versioning and stability` (M; plan section 5):
    - semantic versioning, 0.x until the library has run in production, then 1.0;
    - public API = the names in `__all__`, the dataclass fields, the members of `ErrorReason`, `Deviation` and `KnownShape`, and the message format;
    - adding a member is a minor release (exhaustive `match` users notice);
    - removing or renaming anything is breaking: a major release, or a minor one while in 0.x;
    - a retired `KnownShape` member stays (never set) until a minor release removes it;
    - accepting a previously refused shape, or changing an error position, is a minor release;
    - registry snapshot refreshes are patch releases, with the IANA date in the CHANGELOG;
    - `authresults.redact`, `_`-prefixed modules and the redaction report format are not public API;
    - dropping a Python version happens only in a minor release.
14. `## Security` (M). Absolute link to `SECURITY.md`: private vulnerability reporting, and the scope list.
15. `## Contributing and licence` (M). Links to `CONTRIBUTING.md` (DCO), `LICENSE` (Apache-2.0) and `NOTICE`.

Optional within the ceiling: a one-paragraph "Design" note (one linear pass, no recursion, no regex); a pointer to the CHANGELOG.

Formatting rules:
- `pycon` fences only for doctested REPL examples, `python` fences only for runnable scripts, never `>>>` inside a `python` fence;
- `sh` for shell;
- only RFC 2606/6761 names and RFC 5737/3849 addresses;
- no images or badges;
- all links absolute `https://`, or `#anchors`.

## 5. Issue template, config and CHANGELOG

**`.github/ISSUE_TEMPLATE/header-shape.yml`** (an issue form):
- `name: Report a header shape`.
- `description:` a real-world value that authresults refuses or reads differently.
- `title: "[shape] "`.
- `labels: ["header-shape"]`. The maintainer creates the label in the UI; GitHub ignores a missing label.
- `body`:
  1. `markdown`: never paste an original value. Write it to a file and run `python -m authresults.redact < value.txt`, read the output, and paste the stdout value. Never post `--show-originals` output. A mis-parse that creates or hides a result, or a redaction miss that leaks personal data, is a security report: use private reporting (link to `https://github.com/jrapakko/authresults/security/advisories/new`) (AU-Q77).
  2. `input` `producer` (required): vendor or software, and its version if known.
  3. `dropdown` `field` (required): `Authentication-Results`, `ARC-Authentication-Results`, other (an X- field).
  4. `input` `call` (required): the call and keywords, for example `parse(value)` or `parse_arc(value, strict_syntax=True)`.
  5. `textarea` `value` (required, `render: text`): the redacted value, rewritten to RFC 2606/6761 names and RFC 5737/3849 addresses.
  6. `textarea` `report` (`render: text`): the stderr lines `line breaks:`, `parse (original):` and `parse (redacted):`.
  7. `input` fields `reason` (required), `position` and `known_shape` (the text `None` if unset).
  8. `input` `version` (required): the authresults version.
  9. `checkboxes` `checks`, all required:
     - domains replaced with RFC 2606/6761 names;
     - IP addresses replaced with RFC 5737/3849 addresses;
     - local-parts, display names, selectors, signatures, message and job IDs removed;
     - I read the output before posting;
     - this is not a security issue.

**`.github/ISSUE_TEMPLATE/config.yml`** (AU-Q78 A): `blank_issues_enabled: true`, plus `contact_links` with one entry, "Security vulnerability", pointing to the private advisory URL above.

Neither file ships. `tests/test_packaging.py` needs no change for them; `tests/test_release_files.py` checks them (section 6).

**CHANGELOG** (Keep a Changelog). Commit 2 rewrites `## [Unreleased]` to the list below. Commit 3 moves it under `## [0.1.0] - 2026-11-DD` (the tag date), leaves an empty `## [Unreleased]`, and adds link references.

```
## [Unreleased]

## [0.1.0] - 2026-11-DD

First release.

### Added

- `parse()` for one RFC 8601 `Authentication-Results` value and `parse_arc()`
  for one RFC 8617 `ARC-Authentication-Results` value (RFC 8617 is
  Experimental), returning frozen, slotted dataclasses: `AuthenticationResults`,
  `ArcAuthenticationResults`, `Result` and `Property`.
- Keyword-only limits and flags; defaults `max_length=8192`, `max_results=64`,
  `max_properties=64`, `max_comment_depth=16`, `ascii_only=True`,
  `strict_syntax=False`, `require_registered=False`.
- A closed error set: `AuthResultsError` (a `ValueError`) with `reason`
  (`ErrorReason`, 18 members), `position` and `known_shape` (`KnownShape`,
  5 members, for refused shapes known from real software). Messages never
  contain input text.
- `Deviation` (5 members) for accepted real-world departures from the grammar,
  recorded on the result and refused under `strict_syntax=True`.
- `registered` flags from a frozen snapshot of the IANA Email Authentication
  Parameters registries (last updated 2026-05-22).
- `AuthenticationResults.to_value()`, a canonical serializer that refuses CR,
  LF and other control characters.
- Accessors `results_for()`, `Result.get()` and `Result.get_unique()`; helpers
  `domain_of()` and `ascii_domain()`.
- `python -m authresults.redact`: a best-effort helper that replaces personal
  data in one header value before it is posted in a bug report.
- `py.typed`: the package is fully typed.

[Unreleased]: https://github.com/jrapakko/authresults/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jrapakko/authresults/releases/tag/v0.1.0
```

The "Project skeleton ... No parser yet." line is dropped.

**CONTRIBUTING.md:** a new section `## Releasing (maintainer)`, about 10 lines. It names `publish.yml`, the two environments, the rehearsal by manual run on `main`, the tag `vX.Y.Z` on a commit already on `main`, approving the deployment, the AU-Q12 check, and that every step needs the maintainer.

## 6. Tests and checks (tests first)

The test-writer is a fresh instance with this plan only. Its tests are red until commit 2. Both commits are pushed together, so CI on `main` is never red.

**`tests/test_readme.py`** (new):
1. `README.md` has the H2 headings of section 4 items 2 to 15, in that order, plus the three M subsections under item 7. The H1 is `# authresults`.
2. **Doctest:** the whole README goes through `doctest.DocTestParser().get_doctest(text, {}, "README.md", path, 0)` and a `DocTestRunner(optionflags=doctest.ELLIPSIS)`: 0 failed, at least 12 attempted, one shared namespace in file order. No `>>>` inside a `python` fence; every `pycon` fence holds at least one `>>>`.
3. **Script blocks:** each `python` fence is written to `tmp_path` and run with `runpy.run_path(..., run_name="readme_block")`. None raises. The blocks defining `trusted_results`, `dmarc_pass`, `dkim_pass_domains`, `EXPECTED_DEVIATIONS` and `parse_or_log` exist; the test finds them by name, not by index.
4. **`trusted_results`:** synthetic CRLF messages built in the test with RFC 2606 names:
   - our header above the first `Received`, with the expected id, gives a model;
   - the same header below the `Received` gives `None`;
   - a different authserv-id gives `None`;
   - two headers with our id give `None`;
   - no `Received` gives `None`;
   - a candidate that fails to parse (non-ASCII, or over 8192 characters) gives `None`;
   - a missing authserv-id gives `None`;
   - a folded value parses (fold kept, trailing line break handled).
5. **`dmarc_pass`:**
   - true for `dmarc=pass header.from=example.com` against `Example.COM`;
   - false for `dmarc=pass` only inside a comment;
   - false for duplicate `header.from` (no exception);
   - false for a different domain;
   - false for `dmarc=passed` (unregistered);
   - false for two dmarc results;
   - false when a deviation outside `EXPECTED_DEVIATIONS` is present (the AU-Q49 missing-`;` value).
6. **`dkim_pass_domains`:**
   - `header.d` is used;
   - `header.i=@sub.example.com` is used when `header.d` is absent;
   - a `fail` is ignored;
   - a duplicate `header.d` gives an empty set.
7. **`parse_or_log`,** with `caplog` at WARNING:
   - a refused value carrying the marker `qxsecret` (`qxsecret.test/4ABCD; dkim=none`) returns `None` and gives exactly one record, with `record.args == (err.reason, err.position, err.known_shape)` (the expected `err` from calling `parse` in the test), `known_shape is KnownShape.AUTHSERV_ID_JOB_ID`, `exc_info is None`, and `"qxsecret"` absent from `record.getMessage()` and from `repr(record.args)`;
   - an untagged refusal logs `known_shape=None`;
   - an accepted value returns a model with no record.
8. **Closed sets covered:** every value of `ErrorReason`, `Deviation` and `KnownShape` appears in the README.
9. The README contains `_registry.LAST_UPDATED`, `python -m authresults.redact`, `--show-originals`, `X-TM-Authentication-Results`, `MemoryError`, `RecursionError`, `Experimental`, and each of `/ = ? : [ ] < >` inside the `PVALUE_TSPECIALS` subsection.
10. **Links:** every Markdown link and autolink is `https://` or `#...`; none is relative. The issue-form URL `https://github.com/jrapakko/authresults/issues/new?template=header-shape.yml` is present, and `.github/ISSUE_TEMPLATE/header-shape.yml` exists. Every `https://github.com/jrapakko/authresults/blob/main/<path>` link names a tracked file that exists in the working tree.
11. **No secrets in examples:** every domain-looking token in `pycon`/`python` blocks ends in `.example`, `.test`, `.invalid`, `example.com`, `example.net` or `example.org`; every dotted quad is in RFC 5737 ranges.

**`tests/test_release_files.py`** (new), line-based:
1. **Every workflow:**
   - every `uses:` line in `.github/workflows/*.yml` matches `uses: [\w.-]+/[\w./-]+@[0-9a-f]{40} # v\d+(\.\d+)*$`;
   - a top-level `permissions: {}` line;
   - no `pull_request_target`, no `secrets.`;
   - the count of `actions/checkout` equals the count of `persist-credentials: false`;
   - every `setup-uv` step has `enable-cache: false`.
2. **`publish.yml`:**
   - triggers are exactly `push` tags `["v*"]` and `workflow_dispatch`;
   - jobs are exactly `build`, `publish-testpypi`, `publish-pypi`, `github-release`, split at `^  (\S+):$` under `jobs:`;
   - `build` has `contents: read`, no `id-token`, and the exact build command `uv build --build-constraints build-constraints.txt --require-hashes`;
   - `id-token: write` appears only in the two publish jobs;
   - `publish-pypi` has `name: pypi` and an `if:` containing `refs/tags/v`;
   - `publish-testpypi` has `name: testpypi`, an `if:` containing `workflow_dispatch`, and `repository-url: https://test.pypi.org/legacy/`;
   - neither publish job contains `actions/checkout` or `uv `; each uses `pypa/gh-action-pypi-publish` and `actions/download-artifact`;
   - `github-release` has `contents: write` and `needs:` including `publish-pypi`;
   - no `${{` inside a `run:` block. A line-state check: lines after `run: |` at deeper indent.
3. **Issue template:** `header-shape.yml` contains `python -m authresults.redact`, `RFC 2606`, `RFC 5737`, `reason`, `position`, `known_shape`, `--show-originals` and `security/advisories/new`. `config.yml` contains `security/advisories/new`.
4. **Version and CHANGELOG:**
   - `authresults.__version__` fullmatches `\d+\.\d+\.\d+(\.dev\d+)?`;
   - `## [Unreleased]` always present;
   - if not a dev version: a heading `## [<v>] - \d{4}-\d{2}-\d{2}`, a link line `[<v>]: https://github.com/jrapakko/authresults/releases/tag/v<v>`, and a non-empty section body;
   - if a dev version: no heading for the base version yet.

**`tests/test_packaging.py`** (additions only):
- `test_long_description_is_the_readme`: wheel `METADATA` has `Description-Content-Type: text/markdown` and `get_payload().strip() == README.md text .strip()`. Same for the sdist `PKG-INFO`.
- `test_project_urls`: `Project-URL` values include the three in `pyproject.toml`.
- Under AU-Q74 A, the `Classifier` list holds `Development Status :: 3 - Alpha`. This is the only release-dependent assertion; it belongs in commit 3 and is written by the test-writer as a separate small commit (or included in commit 1 if the maintainer answers AU-Q74 before the slice starts).

**Checks run by the implementer and the verifier** (light; run the full suite once at the end, after `free -h`):
- `uv run ruff check && uv run ruff format --check`, plus `uv run ruff format --check README.md` explicitly;
- `uv run mypy`;
- `uv run coverage run -m pytest && uv run coverage report` (100%; `src/` and `scripts/` unchanged);
- `uv build --build-constraints build-constraints.txt --require-hashes`, then `twine check --strict` and `check-wheel-contents`;
- `uv run zizmor .github/workflows .github/dependabot.yml` clean, plus `uv run zizmor --persona=pedantic .github/workflows/publish.yml`, with each pedantic finding fixed or listed in the hand-off;
- `prek run --all-files` (includes `check-yaml` on the issue template and the forbidden-name hooks);
- the `git ls-remote` SHA check from section 3.

Considered and rejected:
- actionlint: a new Go binary or wheel; zizmor, the structural test and the rehearsal cover the risk.
- `pytest --doctest-glob`: changes the pytest config that earlier slices kept fixed.

## 7. Outward steps (maintainer; each marked [OK] needs an explicit OK at the time)

`gh` is not installed. The maintainer does every GitHub and PyPI UI step.

1. **[OK] Push commits 1 and 2** after verifier and red-team. Confirm CI is green. Then check that the issue form renders under Issues, New issue.
2. **Check the name** (read-only): `curl -s -o /dev/null -w '%{http_code}\n' https://pypi.org/pypi/authresults/json` and the same for `https://test.pypi.org/pypi/authresults/json`. Both should be `404`. If TestPyPI is taken by someone else, stop and decide (risk R3).
3. **[OK] Repo settings, if not already done** (plan section 7 step 2):
   - private vulnerability reporting on;
   - Actions default token read-only;
   - "require actions pinned to a full-length commit SHA" if offered (UNVERIFIED name);
   - ruleset on `main`: no force push, no deletion, required CI;
   - ruleset on `v*` tags: only the owner creates; updates, deletions and force pushes blocked;
   - optionally the label `header-shape`;
   - optionally "immutable releases" (UNVERIFIED name).
4. **[OK] GitHub environments** (Settings, Environments):
   - `pypi`: required reviewer `jrapakko`; "prevent self-review" unticked (solo maintainer); deployment branches and tags limited to the tag rule `v*` with no branches; no secrets.
   - `testpypi`: required reviewer `jrapakko` (AU-Q80 A); deployment limited to branch `main`; no secrets.
5. **[OK] TestPyPI pending publisher** (test.pypi.org, its own account with security-key 2FA): project `authresults`, owner `jrapakko`, repository `authresults`, workflow `publish.yml`, environment `testpypi`.
6. **[OK] PyPI pending publisher** (pypi.org, security-key 2FA): project `authresults`, owner `jrapakko`, repository `authresults`, workflow `publish.yml`, environment `pypi`. Do it the same day as step 9 (AU-Q11; a pending publisher does not reserve the name).
7. **[OK] Push commit 3** (`release 0.1.0`). Confirm CI is green.
8. **[OK] TestPyPI rehearsal** (AU-Q71 A, the exact release commit):
   - Actions, Publish, "Run workflow" on `main`; approve the `testpypi` deployment.
   - Check that `https://test.pypi.org/project/authresults/0.1.0/` lists exactly one wheel and one sdist.
   - Check the publisher: `curl -sS https://test.pypi.org/integrity/authresults/0.1.0/authresults-0.1.0-py3-none-any.whl/provenance | python3 -m json.tool` shows `publisher` = `{kind: GitHub, repository: jrapakko/authresults, workflow: publish.yml, environment: testpypi}`.
   - Smoke test in a scratch directory outside the repo: `uv venv /tmp/ar-smoke && uv pip install --python /tmp/ar-smoke --index-url https://test.pypi.org/simple/ --no-deps authresults==0.1.0`, then `/tmp/ar-smoke/bin/python -c "import authresults; print(authresults.__version__)"` and `/tmp/ar-smoke/bin/python -m authresults.redact --help` (exit 0). Delete the scratch venv afterwards.
   - If the rehearsal fails before the upload, fix and re-run. If it fails after (0.1.0 is now taken on TestPyPI), fix and go on to PyPI. A further rehearsal needs a new version number on TestPyPI only.
9. **[OK] Tag and first publish:**
   - `git tag -s v0.1.0 -m "authresults 0.1.0" <commit-3-sha>` (or `-a` under AU-Q79 B);
   - `git push origin v0.1.0`;
   - approve the `pypi` deployment;
   - after `publish-pypi`, `github-release` runs.
   - Check that `https://pypi.org/project/authresults/0.1.0/` shows exactly two files, each with a "Provenance" or attestation section.
10. **[OK] AU-Q12 attestation check**, right after step 9:

    ```sh
    curl -sS https://pypi.org/integrity/authresults/0.1.0/authresults-0.1.0-py3-none-any.whl/provenance | python3 -m json.tool
    curl -sS https://pypi.org/integrity/authresults/0.1.0/authresults-0.1.0.tar.gz/provenance | python3 -m json.tool
    uv tool run --from 'pypi-attestations==0.0.30' pypi-attestations verify pypi \
      --repository https://github.com/jrapakko/authresults pypi:authresults-0.1.0-py3-none-any.whl
    uv tool run --from 'pypi-attestations==0.0.30' pypi-attestations verify pypi \
      --repository https://github.com/jrapakko/authresults pypi:authresults-0.1.0.tar.gz
    curl -sS https://pypi.org/pypi/authresults/0.1.0/json | python3 -m json.tool | grep -A2 '"digests"'
    ```

    Pass criteria:
    - both `verify pypi` runs succeed;
    - each `publisher` is `{kind: GitHub, repository: jrapakko/authresults, workflow: publish.yml, environment: pypi}`;
    - the sha256 values equal the build job's "hashes" step summary and the GitHub release assets.

    Record in `docs/plan.md` (AU-Q75 A): date; tool and version; both file names with sha256; tag commit SHA; publisher fields; each bundle's `transparency_entries[0].logIndex`; the result. The workflow and repository are in the signed certificate. The environment comes from PyPI's publisher record, not, as far as I know, from the signature (UNVERIFIED; `-v` output shows what was checked). Record it as such.
11. **[OK] Commit and push the record** (coordinator: `record 0.1.0 release`), together with the `docs/plan.md` status row.
12. **[OK] Retire `PLAN.md`:**
    - the coordinator first confirms `docs/plan.md` holds every answer and status (it does through AU-Q69; AL4's answers are added);
    - `git log --all -- PLAN.md` is still empty;
    - the AU-Q76 note is committed;
    - then the maintainer moves `PLAN.md` to private storage outside the repo, or deletes it, and removes `/PLAN.md` from `.git/info/exclude`;
    - the coordinator updates its memory notes to stop dual updates.

## 8. File ownership and commits

- **Test-writer** (fresh instance, launched as `implementer`, given this plan only): `tests/test_readme.py`, `tests/test_release_files.py`, additions to `tests/test_packaging.py`. It writes no README text. An undecidable case goes into its hand-off as a question, never a guess.
- **Implementer:**
  - `README.md`;
  - `.github/workflows/publish.yml`, using the SHAs the coordinator supplies, which it re-checks with `git ls-remote`;
  - `.github/ISSUE_TEMPLATE/header-shape.yml` and `.github/ISSUE_TEMPLATE/config.yml`;
  - `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md` (AU-Q77);
  - `pyproject.toml`: the `[tool.mutmut]` comment `PLAN.md 4` becomes `docs/plan.md section 4`, and the classifier in commit 3;
  - `src/authresults/__init__.py`: the `__version__` line only, in commit 3.

  It may not edit the test-writer's files; a dispute follows plan 6.4.
- **Coordinator:** `docs/plan.md` (status, AU-Q70 onward, AU-Q76 note, the AU-Q12 record), saving this plan as `docs/plans/al4.md`, the SHA lookup, and `PLAN.md` until it is retired.
- **Commits** (each with the maintainer's OK, `git commit -s`, files added by name):
  1. `add release tests` (test files only).
  2. `add publish workflow, readme and issue template`. Pushed together with commit 1.
  3. `release 0.1.0`: version, CHANGELOG date and links, classifier, and the classifier assertion in `tests/test_packaging.py`. Pushed alone, before the rehearsal.
  4. `update plan for al4` (coordinator, plan and answers), which may go with commit 2.
  5. `record 0.1.0 release` (coordinator, after step 10).

## 9. Open questions (recommendation first)

- **AU-Q70, rehearsal mechanism.** (A) Same `publish.yml`, `workflow_dispatch` on `main` goes to TestPyPI in env `testpypi`. Recommended: one workflow is rehearsed, same build job. (B) A separate `testpypi.yml`. (C) A `test-v*` tag pattern.
- **AU-Q71, rehearsal version.** (A) The release commit itself (0.1.0, exact bytes). Recommended. (B) A `0.1.0rc1` commit first, then a bump commit. This allows repeated rehearsals but adds a commit and push, and the bytes differ. (C) The current `0.1.0.dev0`, before the release commit.
- **AU-Q72, GitHub Release.** (A) A `github-release` job with `contents: write` after the PyPI publish, notes from the CHANGELOG section, assets attached. Recommended; plan section 5 item 3. (B) By hand in the UI. (C) None.
- **AU-Q73, GitHub-side build provenance** (`actions/attest-build-provenance`). (A) No: PyPI PEP 740 attestations only, keeping `id-token` out of every job but the publish ones. Recommended. (B) Yes, in a separate `attest` job with `id-token: write` and `attestations: write`.
- **AU-Q74, classifier for 0.1.0.** (A) `Development Status :: 3 - Alpha`. Recommended. (B) Keep `2 - Pre-Alpha`. (C) `4 - Beta`.
- **AU-Q75, where to record the AU-Q12 check.** (A) `docs/plan.md` status row and a slice note. Recommended. (B) A new `docs/releases.md`. (C) The GitHub release notes.
- **AU-Q76, the `PLAN.md` citations in tracked files.** (A) Add a note at the top of `docs/plan.md` that citations of `PLAN.md` in source and tests refer to this document, with a section map built by the coordinator (for example, AU-Qs are section 11 there and section 10 here). Fix only the `pyproject.toml` comment, and leave frozen and hash-pinned files untouched. Recommended. (B) Also rewrite the citations in non-frozen files (`src/` docstrings, `.gitignore`, `mutmut-equivalent.md`, non-frozen tests). (C) Rewrite everything, including frozen files through 6.4 amend commits and a new pinned `conftest.py` hash.
- **AU-Q77, redaction leaks.** (A) `SECURITY.md` and the issue form say a redaction miss that leaks personal data is reported privately, because the repro contains the data. Recommended. (B) Public issues.
- **AU-Q78, blank issues.** (A) A `config.yml` with blank issues enabled and a security contact link. Recommended. (B) Disable blank issues. (C) No `config.yml`.
- **AU-Q79, the tag.** (A) A signed annotated tag (`git tag -s`) if a signing key is set up, else an annotated one. Recommended. (B) Annotated, unsigned.
- **AU-Q80, reviewer on `testpypi`.** (A) Required reviewer, same as `pypi`. Recommended: the rehearsal also tests the approval step. (B) None.
- **AU-Q81, README form.** (A) One README of about 400 lines, which is the PyPI page. Recommended: `docs/` does not ship and relative links break on PyPI. (B) A short README plus `docs/usage.md`.

## 10. Risks

- **R1.** Ruff formats README code blocks. A reformat could break a doctest's expected output or the line-based checks. Mitigation: the implementer runs `ruff format` on `README.md` before running the tests, and CI runs both.
- **R2.** Name squatting before step 9. Mitigation: steps 5 to 9 on one day (AU-Q11), and the name check in step 2.
- **R3.** `authresults` already taken on TestPyPI. Mitigation: escalate. The options are skipping the rehearsal or rehearsing on a fork with a different project name; neither is planned.
- **R4.** TestPyPI forbids re-uploading 0.1.0, so a second rehearsal after an upload needs a new version there (AU-Q71).
- **R5.** UNVERIFIED runner behaviours: `dist/.gitignore` from `uv build`, `GITHUB_SHA` for annotated tags, the pypa action's SHA-pinned Docker build, the environment "tag rule" UI wording. All are handled defensively or caught by the rehearsal.
- **R6.** The environment field in PyPI provenance comes from PyPI's publisher record, not, as far as I know, from the Sigstore certificate (UNVERIFIED). The AU-Q12 record says which fields were checked how.
- **R7.** The line-based workflow tests depend on the skeleton's layout. A reformatted YAML fails loudly rather than passing silently, which is the safe direction.
- **R8.** The README recipe assumes your hosts prepend headers above their own `Received`. The README says to check the MTA's layout. Some systems reorder headers.
- **R9.** CHANGELOG date versus the actual tag day: if the tag slips, the date is off by a day or two. This is tolerated; an amend after push is not allowed.
- **R10.** `uv tool run` for `pypi-attestations`: the newest version is inside the 7-day cooldown today, so pin 0.0.30. A user-level uv `exclude-newer` setting could also hide a fresh PyPI release in the smoke test; use `--exclude-newer` explicitly if needed.
- **R11.** The `PLAN.md` citations stay in frozen files (AU-Q76). Mitigated by the note in `docs/plan.md`.
- **R12.** Laptop load. All new tests are light. Run the full suite once, after `free -h`. No containers.

## 11. Acceptance criteria (each testable)

1. `uv run pytest tests/test_readme.py tests/test_release_files.py tests/test_packaging.py` passes. The full suite passes with 100% line and branch coverage; `git diff 2fb4b38 -- src/` shows only the `__version__` line after commit 3.
2. Every README `pycon` example passes under doctest (0 failed, at least 12 attempted). Every `python` block runs. `trusted_results`, `dmarc_pass`, `dkim_pass_domains` and `parse_or_log` pass the section 6 behaviours, including no `qxsecret` in any log record.
3. The README has the section 4 headings in order. It names every `ErrorReason`, `Deviation` and `KnownShape` value, `_registry.LAST_UPDATED` and the `PVALUE_TSPECIALS` characters. It has no relative links, and every `blob/main` link names an existing tracked file.
4. `uv run ruff check`, `uv run ruff format --check` and `uv run ruff format --check README.md` are clean; so is `uv run mypy`.
5. `uv build ...`, `twine check --strict` and `check-wheel-contents` pass. The wheel `METADATA` and sdist `PKG-INFO` long description equals `README.md`, with content type `text/markdown`.
6. `uv run zizmor .github/workflows .github/dependabot.yml` reports nothing, in CI too with the online audits. Pedantic findings on `publish.yml` are fixed or listed.
7. Every `uses:` in every workflow is a 40-hex SHA with a `# vX.Y.Z` comment, and each new SHA equals the `git ls-remote` commit for that tag.
8. In `publish.yml`:
   - top-level `permissions: {}`;
   - `build` has `contents: read` and no `id-token`;
   - `id-token: write` only in `publish-testpypi` (env `testpypi`, dispatch on `main`) and `publish-pypi` (env `pypi`, `v*` tags);
   - the publish jobs have no checkout and no `uv`;
   - the build checks tag == `v` + `__version__` and that the tag commit is on `main`, and checks for exactly one wheel and one sdist in both the build and publish jobs.

   All asserted by `tests/test_release_files.py`.
9. The issue form and `config.yml` exist with the required strings. `prek run --all-files` passes. The forbidden-name check passes.
10. The CHANGELOG matches `__version__` under the section 6 rule. After commit 3, `__version__ == "0.1.0"` and the section is dated.
11. Rehearsal: TestPyPI 0.1.0 has exactly 2 files; its provenance publisher is (GitHub, `jrapakko/authresults`, `publish.yml`, `testpypi`); the TestPyPI install prints `0.1.0` and `python -m authresults.redact --help` exits 0.
12. Release: PyPI 0.1.0 has exactly 2 files, whose sha256 equal the build summary. `pypi-attestations verify pypi --repository https://github.com/jrapakko/authresults` passes for both files. The provenance publisher is (GitHub, `jrapakko/authresults`, `publish.yml`, `pypi`). The record is committed in `docs/plan.md`.
13. Under AU-Q72 A, the GitHub release `v0.1.0` exists with the CHANGELOG section as notes and the same two files.
14. The verifier confirms the section 8 file ownership from the diff.

## Files

- To create: `/home/jrpko/projects/authresults/.github/workflows/publish.yml`, `/home/jrpko/projects/authresults/.github/ISSUE_TEMPLATE/header-shape.yml`, `/home/jrpko/projects/authresults/.github/ISSUE_TEMPLATE/config.yml`, `/home/jrpko/projects/authresults/tests/test_readme.py`, `/home/jrpko/projects/authresults/tests/test_release_files.py`.
- To change: `/home/jrpko/projects/authresults/README.md`, `/home/jrpko/projects/authresults/CHANGELOG.md`, `/home/jrpko/projects/authresults/CONTRIBUTING.md`, `/home/jrpko/projects/authresults/SECURITY.md`, `/home/jrpko/projects/authresults/pyproject.toml`, `/home/jrpko/projects/authresults/src/authresults/__init__.py`, `/home/jrpko/projects/authresults/tests/test_packaging.py`, `/home/jrpko/projects/authresults/docs/plan.md`.
- Read for context: `/home/jrpko/projects/authresults/docs/plans/al3d.md`, `/home/jrpko/projects/authresults/docs/refused-shapes.md`, `/home/jrpko/projects/authresults/.github/workflows/ci.yml`, `/home/jrpko/projects/authresults/tests/test_case_table_meta.py` (`_tree_problems`), `/home/jrpko/projects/authresults/src/authresults/redact.py` (usage text), `/home/jrpko/projects/authresults/src/authresults/_errors.py`.

Sources:
- [pypa/gh-action-pypi-publish releases](https://github.com/pypa/gh-action-pypi-publish/releases)
- [actions/upload-artifact releases](https://github.com/actions/upload-artifact/releases)
- [actions/download-artifact releases](https://github.com/actions/download-artifact/releases)
- [pypi-attestations (CLI usage)](https://github.com/trailofbits/pypi-attestations)
- [pypi-attestations on PyPI](https://pypi.org/project/pypi-attestations/)
- [PyPI Integrity API](https://docs.pypi.org/api/integrity/)
- [PyPI: adding a trusted publisher](https://docs.pypi.org/trusted-publishers/adding-a-publisher/)
- [Ruff v0.16.0 release (Markdown formatting)](https://github.com/astral-sh/ruff/releases/tag/0.16.0)
- [Ruff v0.16.0 blog post](https://astral.sh/blog/ruff-v0.16.0)
- [Ruff formatter docs](https://docs.astral.sh/ruff/formatter/)
## 12. Answers (maintainer, 2026-11-08)

AU-Q70 A, AU-Q71 A, AU-Q76 A; AU-Q72 to AU-Q75 and AU-Q77 to AU-Q81 as recommended. Each decision is stated in full in `docs/plan.md` section 10, "Release decisions (AU-Q70 to AU-Q81)", which is the place to cite (the maintainer asked that these points can be referenced there).

## 13. Coordinator rulings on the test-writer's questions (2026-11-08)

1. Doctest: feed only the bodies of the `pycon` fences, in file order, as one doctest with a shared namespace (not the whole README), so a closing fence is never read as expected output and no blank-line convention is needed.
2. Full-line YAML comments are skipped in the substring checks: accepted.
3. The job-header pattern allows a trailing comment: accepted.
4. The `Development Status :: 3 - Alpha` classifier assertion goes in now, active only when `__version__` is not a dev version (mirrors the CHANGELOG rule), so commit 3 turns it on.
5. The README names each closed-set value in backticks as its lowercase value (`` `syntax` ``); a bare word in prose does not count.
6. AU-Q81: at least one `blob/main/docs/plan.md` link is enough.
7. The extra checks drawn from other plan sections stay.
8. Running the tests from an unpacked sdist: `test_release_files.py` skips as a module when `.github/workflows` is absent; in `test_readme.py` only the checks that need git or `.github/`/`docs/` (tracked-file links, the issue-form file) skip when those are absent, with a stated reason. Everything that needs only `README.md` and the package still runs.

## 14. Fix round 1 (coordinator, 2026-11-08, from the verifier's V1 to V5 and the red-team's M1, L1 to L4)

1. **M1 (trust).** Where the README suggests adding `PVALUE_TSPECIALS` to `EXPECTED_DEVIATIONS` for producers that write `header.b` unquoted, it must say that this re-opens the balanced-bracket splitting described under "Characters in unquoted values", and give the safer alternative as code: accept the deviation only when no property other than `header.b` has `<`, `>`, `[` or `]` in its `raw`. The suggested check is a small function in the decision block, exercised by a test (red-team repro: `mx.example.net; spf=fail smtp.mailfrom=<x>; dkim=pass header.d=bank.example header.b=<>; ...` must not yield `bank.example` / `dmarc_pass` true with the safer check).
2. **L1 (release).** (a) The build job, on a tag run, refuses a version that is not a final release (any `dev`, `a`, `b`, `rc` or local part), so an old `v0.1.0.dev0`-style tag cannot publish to PyPI; the dispatch (TestPyPI) path keeps accepting the release commit only (unchanged). (b) `CONTRIBUTING.md`'s release section says the protections are the GitHub settings (tag ruleset, environments with reviewer and tag/branch limits, created before the first run) and the pending publishers, and that the workflow checks are a backstop.
3. **L2.** The README defines `own_received`: the position, counted from the top, of the `Received` field your own receiving host adds on arrival; never count too high, since everything below it was written by the sender.
4. **L3 / V1.** README line on ARC: "an ARC value passed to `parse()` is usually refused, and one without an authserv-id reads as a field with a missing id and an unregistered `i=1` result". The characters line says `(` is refused as `syntax` only in the middle of a value (a `(` after a value starts a comment), and that `;` ends the value (separator), rather than listing them as refused characters.
5. **V2.** The balanced-bracket example is shown as a full value (`mx.example; spf=fail smtp.mailfrom=<x>; dkim=pass header.d=bank.example header.b=<>`).
6. **V3.** The README's security summary adds the serializer header-injection item from `SECURITY.md`, or says the list is a selection.
7. **L4.** The issue-form checkbox reads that domains and addresses are replaced (vendor service hostnames that the redaction helper keeps may stay).
8. **V4** is handled by the coordinator in `docs/plan.md` (the AU-Q76 note and section map are added at the top; the ARC wording in section 10 is corrected).
9. **Coordinator ruling on 14.1 (after the implementer's note):** the guard is wired into the recipe's deviation check, not left as a separate step the caller must remember: when `PVALUE_TSPECIALS` is in `EXPECTED_DEVIATIONS`, a result passes the deviation check only if `tspecials_only_in_signature` is also True. A reader who copies the recipe and adds the deviation keeps the protection. The test that showed the repro working through `dkim_pass_domains` / `dmarc_pass` with the deviation accepted is changed (per 6.4, by the test-writer) to show the repro through the bare deviation comparison, and that the recipe functions refuse it.
10. **Fix round 2 (coordinator, from the verifier's V6 and V7).** The guard no longer exempts `header.b`: a DKIM signature is base64 and never holds `<`, `>`, `[` or `]`, so the check covers every property and is renamed `no_bracketed_values(results)` (same place, still called from `deviations_ok()`). The README says the check also refuses legitimate bracketed values (for example `header.from=<noreply@...>` or `smtp.helo=[192.0.2.1]`), which is the safe direction. New case: `mx.example.net; dkim=fail header.b=<x>; dkim=pass header.d=bank.example header.b=<>; dmarc=pass header.from=bank.example` gives no pass with the deviation accepted.
