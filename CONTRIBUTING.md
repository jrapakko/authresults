# Contributing

Thanks for your interest in `authresults`.

## Setup

You need [uv](https://docs.astral.sh/uv/). Then:

```sh
uv sync                 # create .venv with the locked dev tools
prek install            # optional: run the hooks on each commit and commit message
```

The hooks need [prek](https://github.com/j178/prek); the config uses prek's
built-in hooks, so upstream pre-commit cannot run it. Ruff and zizmor run
through `uv run --locked`, so the hooks install nothing outside `uv.lock`.

## Checks

```sh
uv run ruff check
uv run ruff format --check
uv run mypy
uv run coverage run -m pytest && uv run coverage report   # 100% line and branch
uv build --build-constraints build-constraints.txt --require-hashes
uv run twine check --strict dist/*
uv run check-wheel-contents dist/*.whl
uv run zizmor .github/workflows .github/dependabot.yml
uv run python scripts/check_lock_cooldown.py
prek run --all-files
```

CI runs the tests on Python 3.11 to 3.15 and all other checks once. CI does
not run prek; it runs ruff, zizmor and the forbidden-name check directly.

## Rules

- No runtime dependencies. The wheel must stay pure Python (`py3-none-any`).
- Every change keeps line and branch coverage at 100%.
- GitHub Actions are pinned by full commit SHA with a version comment. Hooks
  are either prek built-ins or `uv run --locked` commands; do not add remote
  hook repositories.
- Dev dependencies are locked in `uv.lock` with a 7-day `exclude-newer`
  cooldown; update them with `uv lock --upgrade`. CI re-checks every upload
  time in the lock against the cooldown (`scripts/check_lock_cooldown.py`).
- The project itself is not installed into `.venv` (`tool.uv.package = false`);
  tests and mypy import it from `src/`. Only `uv build` runs the build backend,
  and it is pinned by hash in `build-constraints.txt`.
- `flit-core` is pinned twice: in `uv.lock` (dev group, used by the packaging
  tests) and in `build-constraints.txt` (with hashes, used by `uv build`).
  Dependabot ignores it; bump both together by hand and regenerate the hashes
  with `echo flit-core==X.Y.Z | uv pip compile - --generate-hashes`.

## Sign-off (DCO)

Please sign off every commit to certify the
[Developer Certificate of Origin](https://developercertificate.org/):

```sh
git commit -s
```

This adds a `Signed-off-by: Your Name <you@example.com>` line. You keep the
copyright to your contribution, which is licensed under Apache-2.0.
