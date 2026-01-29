# Agent Instructions

This project uses **bd** (beads) for issue tracking. Run `bd onboard` to get started.

## Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --status in_progress  # Claim work
bd close <id>         # Complete work
bd sync               # Sync with git
```

## Project Overview (quick discovery)

- This is a **Python package with a Rust extension** built via **maturin**/**pyo3**.
- Python package: `johnnycanencrypt/`
- Rust crate: `src/` (builds a `cdylib`)
- Tests: `tests/` (pytest)
- Docs: `docs/` (Sphinx)

## Where to look first

- `README.md` – high-level build instructions
- `pyproject.toml` – Python metadata + maturin build backend
- `Cargo.toml` – Rust crate metadata + dependencies
- `.github/workflows/ci_pr.yml` – authoritative CI commands (tests/build)

## Common local commands

```bash
# Create venv + install dev deps
uv sync
source .venv/bin/activate
maturin develop

# Run Python tests
pytest -q

# Release build (wheel)
maturin build --release
```

## Notes on tooling

- Type checking: `mypy.ini` is present.
- This repo uses `uv` in CI (`.github/workflows/ci_pr.yml`), and includes `uv.lock`.
- No `ruff.toml`/`.ruff.toml`, `pytest.ini`, `tox.ini`, `.editorconfig`, or `.pre-commit-config.yaml` were found at the repo root during discovery.

## Quality gates (tests / typecheck / build)

```bash
# Tests (unit + integration; CI also runs Postgres-backed integration)
pytest -q

# Type-checking
mypy johnnycanencrypt

# Build/install local dev extension (Rust -> Python)
maturin develop

# Build release artifacts (wheel/sdist)
maturin build --release
```

CI reference: `.github/workflows/ci_pr.yml` (uses `uv` to create venv and run `pytest`).

## Suggestions (optional)

- Add a `pyproject.toml` `[tool.mypy]` section (or keep `mypy.ini`, but document one source of truth).
- Consider adding a linter + formatter setup (e.g. Ruff) and wiring it into CI.
- Consider a simple task runner (`Makefile` at repo root, `justfile`, or `python -m ...`) so contributors have a single entrypoint for `fmt/lint/test/build`.

## Repo patterns and practices (observed)

- **Folder layout**
  - Python package code lives in `johnnycanencrypt/`.
  - Rust crate code lives in `src/` and is built as a `cdylib` for Python.
  - Tests are `pytest`-style in `tests/` and frequently import helpers from `tests/utils.py`.

- **Schema versioning approach**
  - DB schema is defined as SQL strings (e.g. `johnnycanencrypt/utils.py: createdb`).
  - A single schema “version” value is tracked via `DB_UPGRADE_DATE`.
  - SQLite upgrades are implemented as a **file-swap + data copy** procedure (`SqliteBackend.upgrade_if_required_with`).
  - Postgres async backend currently validates the schema version and errors if it mismatches (no auto-migrations).

- **Error handling style**
  - Domain exceptions are minimal and live in `johnnycanencrypt/exceptions.py`.
  - Many code paths raise standard exceptions with explicit messages (e.g. `ValueError`, `NotImplementedError`, `RuntimeError`).

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
