# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

nasdirstat is a WinDirStat-style disk usage treemap for NAS systems. It scans a mapped `/data` directory using native Python (`os.scandir`), caches results as gzip JSON, and serves an interactive D3 v7 treemap via a FastAPI/Uvicorn web server. Designed to run as a small Docker container and ship via Unraid Community Apps.

## Commands

```bash
# Build and run locally (requires Docker)
docker compose up --build

# Run dev stack (NOAUTH=true, mounts /tmp/nasdirstat-testdata as /data)
DEV_DATA_PATH=/tmp/nasdirstat-testdata docker compose -f docker-compose.dev.yml up --build

# Run tests only (spins up dev stack, runs pytest, exits)
DEV_DATA_PATH=/tmp/nasdirstat-testdata docker compose -f docker-compose.dev.yml up --abort-on-container-exit --exit-code-from tests

# Run a single test
DEV_DATA_PATH=/tmp/nasdirstat-testdata docker compose -f docker-compose.dev.yml run --rm tests pytest tests/test_api.py::test_status_ok -v
```

## Architecture

```
app/
  main.py           FastAPI app: auth, scanner, cache, API endpoints
  static/
    index.html      Single-file SPA: D3 treemap, toolbar, tooltip, settings panel

tests/
  conftest.py       Session-scoped httpx.Client fixture; waits for server readiness
  test_api.py       Integration tests against a live server

Dockerfile          python:3.13-slim, no system deps needed (pure Python scanner)
Dockerfile.dev      Includes dev dependencies for the test container
templates/
  nasdirstat.xml    Unraid Community Apps template
```

**Data flow:**
1. `scheduler_loop` (background asyncio task) triggers `run_scan` on the configured interval.
2. `run_scan` calls `_scan_sync` in a thread executor (non-blocking).
3. `_scan_sync` walks `/data` with `os.scandir`, building a nested dict tree. Keeps top-N files per directory by size; aggregates the rest into a `[N other files]` leaf.
4. The result is saved as gzip JSON to `/index/scan_cache.json.gz` and an in-memory `_dir_index` dict (path → node) is built for O(1) lookup.
5. `GET /api/data?path=X&depth=N` looks up the node in `_dir_index`, trims to depth N (largest children first), and returns JSON.
6. The frontend polls `/api/status`, renders the D3 treemap from `/api/data`, and navigates via breadcrumb or cell click.

## Security model

Identical to nasearch:
- Session cookies with 24h TTL (configurable `SESSION_HOURS`); stored in-memory.
- CSRF token per session, validated on all POST requests via `X-CSRF-Token` header.
- Timing-safe credential comparison via `secrets.compare_digest`.
- Rate limiting: 5 failed logins per IP per 15-minute window → 429.
- Dual-layer path validation on every `/api/data` request: `os.path.normpath` + `startswith(data_root)` AND `os.path.realpath` + `startswith` to block `../` and symlink escapes.
- Security headers on all responses: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`.
- Auth is skipped entirely when `NOAUTH=true`.

## Key env vars

| Variable | Default | Purpose |
|---|---|---|
| `DATA_PATH` | `/data` | Root to scan and serve |
| `PRUNE_PATHS` | `/data/appdata /data/system /data/domains /data/isos` | Space-separated dirs to skip |
| `MAX_FILES_PER_DIR` | `200` | Top-N files kept per dir (by size); rest aggregated |
| `AUTH_USER` / `AUTH_PASS` | `""` | Credentials; both must be set for auth to activate |
| `NOAUTH` | `false` | Disable auth entirely |
| `SESSION_HOURS` | `24` | Session TTL |

## CI/CD

GitHub Actions (`.github/workflows/docker-publish.yml`):
1. **test** job: creates test data, runs `docker compose -f docker-compose.dev.yml up --abort-on-container-exit`
2. **build-and-push** job: on test success, builds and pushes to `ghcr.io/dewgenenny/nasdirstat`
