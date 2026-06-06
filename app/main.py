"""nasdirstat – disk-usage treemap for NAS-style /data mounts."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import sqlite3
import sys
import threading
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
_DATA_ROOT = os.environ.get("DATA_PATH", "/data").rstrip("/") or "/data"
_DATA_ROOT_REAL = os.path.realpath(_DATA_ROOT)
_DATA_ROOT_SEP = _DATA_ROOT_REAL.rstrip("/") + "/"
_INDEX_DIR = os.environ.get("INDEX_DIR", "/index")
_DB_FILE = os.path.join(_INDEX_DIR, "scan.db")
_SETTINGS_FILE = os.path.join(_INDEX_DIR, "settings.json")

_PRUNE_PATHS_RAW = os.environ.get(
    "PRUNE_PATHS",
    f"{_DATA_ROOT}/appdata {_DATA_ROOT}/system {_DATA_ROOT}/domains {_DATA_ROOT}/isos {_DATA_ROOT}/docker",
)
_PRUNE_PATHS: set[str] = {p.strip() for p in _PRUNE_PATHS_RAW.split() if p.strip()}
_MAX_FILES_PER_DIR = int(os.environ.get("MAX_FILES_PER_DIR", "200"))

_AUTH_USER = os.environ.get("AUTH_USER", "")
_AUTH_PASS = os.environ.get("AUTH_PASS", "")
_NOAUTH = os.environ.get("NOAUTH", "false").lower() in ("true", "1", "yes")
_SESSION_HOURS = max(1, int(os.environ.get("SESSION_HOURS", "24")))

_VALID_INTERVALS = {0, 1, 6, 12, 24, 48, 168}

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

os.makedirs(_INDEX_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------
_sessions: dict[str, dict[str, Any]] = {}
_login_attempts: dict[str, list[float]] = {}

_scanner_state: dict[str, Any] = {
    "running": False,
    "progress": "",
    "error": None,
}
_scanner_lock = asyncio.Lock()

_db: sqlite3.Connection | None = None
_db_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def load_settings() -> dict[str, Any]:
    try:
        with open(_SETTINGS_FILE) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"interval_hours": 24}


def save_settings(data: dict[str, Any]) -> None:
    tmp = _SETTINGS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, _SETTINGS_FILE)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def _open_db() -> bool:
    """Open the SQLite scan DB. Returns True if data is available."""
    global _db
    if not os.path.exists(_DB_FILE):
        return False
    try:
        conn = sqlite3.connect(_DB_FILE, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA cache_size=-65536")  # 64 MB page cache
        count = conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
        if count == 0:
            conn.close()
            return False
        with _db_lock:
            if _db is not None:
                _db.close()
            _db = conn
        log.info("Opened scan DB: %d nodes", count)
        return True
    except Exception as exc:
        log.warning("Failed to open scan DB: %s", exc)
        return False


def _has_data() -> bool:
    with _db_lock:
        return _db is not None


def _fetch_subtree(path: str, depth: int) -> dict[str, Any] | None:
    """
    Fetch a depth-limited subtree from the DB using a recursive CTE.
    Rows are returned ordered by (depth, size DESC) so parent nodes always
    appear before their children, and children are already size-sorted.
    """
    with _db_lock:
        if _db is None:
            return None
        try:
            rows = _db.execute("""
                WITH RECURSIVE tree(path, name, parent, size, is_dir, d) AS (
                    SELECT path, name, parent, size, is_dir, 0
                    FROM nodes WHERE path = ?
                    UNION ALL
                    SELECT n.path, n.name, n.parent, n.size, n.is_dir, t.d + 1
                    FROM nodes n JOIN tree t ON n.parent = t.path
                    WHERE t.d < ?
                )
                SELECT path, name, parent, size, is_dir, d
                FROM tree
                ORDER BY d, size DESC
            """, (path, depth)).fetchall()
        except Exception as exc:
            log.warning("DB query error for %s: %s", path, exc)
            return None

    if not rows:
        return None

    by_path: dict[str, dict[str, Any]] = {}
    root_node: dict[str, Any] | None = None

    for row_path, name, parent, size, is_dir, d in rows:
        node: dict[str, Any] = {"name": name, "path": row_path, "size": size}
        if is_dir:
            node["children"] = []
        by_path[row_path] = node
        if d == 0:
            root_node = node
        elif parent in by_path:
            par = by_path[parent]
            if "children" in par:
                par["children"].append(node)

    return root_node


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def _scan_sync(root: str, prune: set[str], max_files: int) -> None:
    """
    Streaming scanner that writes directly to SQLite during the recursive walk.

    Peak Python memory is O(tree depth): only the current call stack exists at
    any moment — no intermediate Python tree is built.  The previous approach
    materialised the entire tree as nested Python dicts (20× overhead vs the
    raw data), causing multi-GB RAM usage on large NAS collections.

    SQLite write strategy: single transaction, periodic commits every 50 K items
    for durability.  The parent index is created after the bulk insert (much
    faster than maintaining it during writes).  The finished DB is atomically
    renamed over the previous one so readers always see a consistent snapshot.
    """
    nodes_seen = 0
    visited_dirs: set[tuple[int, int]] = set()  # (st_dev, st_ino) — detect bind-mount loops
    old_limit = sys.getrecursionlimit()
    sys.setrecursionlimit(10_000)

    db_new = _DB_FILE + ".new"
    try:
        os.unlink(db_new)
    except FileNotFoundError:
        pass

    conn = sqlite3.connect(db_new, check_same_thread=True)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=-65536")
        conn.execute("""
            CREATE TABLE nodes (
                path   TEXT PRIMARY KEY,
                name   TEXT NOT NULL,
                parent TEXT,
                size   INTEGER NOT NULL DEFAULT 0,
                is_dir INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.execute("BEGIN")

        def walk(path: str, parent: str | None) -> int:
            nonlocal nodes_seen
            name = os.path.basename(path) or path
            dirs: list[str] = []
            files: list[tuple[str, str, int]] = []

            # Detect cycles caused by bind mounts or hard-linked directories.
            # A bind mount exposes the same inode at a second path — its (dev, ino)
            # pair will already be in visited_dirs, so we stop before recursing.
            try:
                st = os.stat(path, follow_symlinks=False)
                inode_key = (st.st_dev, st.st_ino)
                if inode_key in visited_dirs:
                    log.warning("Skipping already-visited inode at %s (bind mount?)", path)
                    return 0
                visited_dirs.add(inode_key)
            except OSError:
                return 0

            try:
                with os.scandir(path) as it:
                    for entry in it:
                        if entry.path in prune or entry.is_symlink():
                            continue
                        nodes_seen += 1
                        if nodes_seen % 50_000 == 0:
                            _scanner_state["progress"] = f"Scanned {nodes_seen:,} items…"
                            log.info(_scanner_state["progress"])
                            conn.commit()
                            conn.execute("BEGIN")
                        if entry.is_dir(follow_symlinks=False):
                            dirs.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            try:
                                files.append((
                                    entry.name, entry.path,
                                    entry.stat(follow_symlinks=False).st_size,
                                ))
                            except OSError:
                                pass
            except PermissionError:
                pass
            except OSError as exc:
                log.warning("Scan error at %s: %s", path, exc)

            # Recurse first so child sizes are known before inserting this dir
            size = 0
            for d in dirs:
                size += walk(d, path)

            # Keep top-N files by size; aggregate the rest into one leaf
            files.sort(key=lambda f: f[2], reverse=True)
            kept, rest = files[:max_files], files[max_files:]
            for fname, fpath, fsize in kept:
                size += fsize
                conn.execute(
                    "INSERT OR REPLACE INTO nodes VALUES (?,?,?,?,0)",
                    (fpath, fname, path, fsize),
                )
            if rest:
                other_size = sum(f[2] for f in rest)
                size += other_size
                conn.execute(
                    "INSERT OR REPLACE INTO nodes VALUES (?,?,?,?,0)",
                    (path + "/[other]", f"[{len(rest):,} other files]", path, other_size),
                )

            # Insert this directory with its fully-computed size
            conn.execute(
                "INSERT OR REPLACE INTO nodes VALUES (?,?,?,?,1)",
                (path, name, parent, size),
            )
            return size

        log.info("Scan starting: %s (prune: %s)", root, prune)
        walk(root, None)

        conn.commit()
        # Build index after bulk insert — orders of magnitude faster than during
        conn.execute("CREATE INDEX idx_parent ON nodes(parent)")
        conn.commit()
        conn.close()
        conn = None

        os.replace(db_new, _DB_FILE)
        log.info("Scan complete: %d items written to DB", nodes_seen)

    except Exception as exc:
        log.error("Scan failed: %s", exc, exc_info=True)
        if conn:
            conn.close()
        try:
            os.unlink(db_new)
        except OSError:
            pass
        raise
    finally:
        sys.setrecursionlimit(old_limit)


async def run_scan() -> None:
    async with _scanner_lock:
        if _scanner_state["running"]:
            return
        _scanner_state.update({"running": True, "progress": "Starting scan…", "error": None})

    t0 = time.monotonic()
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(
            None, _scan_sync, _DATA_ROOT, _PRUNE_PATHS, _MAX_FILES_PER_DIR
        )
        elapsed = time.monotonic() - t0
        _open_db()
        settings = load_settings()
        settings["last_scanned"] = time.time()
        settings["last_duration_seconds"] = round(elapsed, 1)
        save_settings(settings)
        _scanner_state.update({
            "running": False,
            "progress": f"Done in {elapsed:.0f}s",
            "error": None,
        })
        log.info("Scan complete in %.1fs", elapsed)
    except Exception as exc:
        log.exception("Scan failed: %s", exc)
        _scanner_state.update({"running": False, "progress": "", "error": str(exc)})


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

async def scheduler_loop() -> None:
    await asyncio.sleep(3)
    while True:
        settings = load_settings()
        interval = settings.get("interval_hours", 24)
        if interval <= 0:
            await asyncio.sleep(3600)
            continue
        last_scanned = settings.get("last_scanned", 0)
        elapsed_h = (time.time() - last_scanned) / 3600
        wait_s = max(0.0, (interval - elapsed_h) * 3600)
        await asyncio.sleep(wait_s)
        if not _scanner_state["running"]:
            await run_scan()


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    _open_db()
    task = asyncio.create_task(scheduler_loop())
    try:
        yield
    finally:
        task.cancel()
        with _db_lock:
            if _db is not None:
                _db.close()


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)


# ---------------------------------------------------------------------------
# Middleware – security headers (outermost; wraps all responses)
# ---------------------------------------------------------------------------
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


# ---------------------------------------------------------------------------
# Middleware – auth guard
# ---------------------------------------------------------------------------
@app.middleware("http")
async def auth_guard(request: Request, call_next):
    path = request.url.path
    if _NOAUTH or path.startswith("/api/login"):
        return await call_next(request)
    if path.startswith("/api/") or path in ("/", ""):
        if not _get_session(request):
            return RedirectResponse("/api/login", status_code=303)
    return await call_next(request)


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _get_session(request: Request) -> dict[str, Any] | None:
    if _NOAUTH:
        return {"user": "noauth", "csrf": "noauth"}
    token = request.cookies.get("session")
    if not token:
        return None
    sess = _sessions.get(token)
    if not sess:
        return None
    if time.time() - sess["created"] > _SESSION_HOURS * 3600:
        _sessions.pop(token, None)
        return None
    return sess


def _require_session(request: Request) -> dict[str, Any]:
    sess = _get_session(request)
    if sess is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return sess


def _check_csrf(request: Request, sess: dict[str, Any]) -> None:
    if _NOAUTH:
        return
    token = request.headers.get("X-CSRF-Token", "")
    if not secrets.compare_digest(token, sess.get("csrf", "")):
        raise HTTPException(status_code=403, detail="CSRF token mismatch")


def _rate_limit(ip: str) -> bool:
    now = time.time()
    attempts = [t for t in _login_attempts.get(ip, []) if now - t < 900]
    _login_attempts[ip] = attempts
    return len(attempts) >= 5


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
_LOGIN_HTML = """<!doctype html><html><head><title>nasdirstat login</title>
<meta charset="utf-8">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#c9d1d9;font-family:'Consolas','Monaco',monospace;
  display:flex;align-items:center;justify-content:center;min-height:100vh}
form{background:#161b22;padding:2rem;border:1px solid #30363d;border-radius:8px;min-width:300px}
h2{margin-bottom:1.5rem;color:#58a6ff;letter-spacing:.05em}
label{display:block;font-size:.8rem;color:#8b949e;margin-bottom:.25rem}
input{width:100%;padding:.5rem .75rem;margin-bottom:1rem;background:#0d1117;
  border:1px solid #30363d;color:#c9d1d9;border-radius:4px;font-family:inherit}
input:focus{outline:none;border-color:#58a6ff}
button{width:100%;padding:.6rem;background:#238636;color:#fff;border:none;
  border-radius:4px;cursor:pointer;font-family:inherit;font-size:.95rem}
button:hover{background:#2ea043}
.err{color:#f85149;font-size:.85rem;margin-bottom:.75rem}
</style></head>
<body><form method="post" action="/api/login">
<h2>nasdirstat</h2>
{err}
<label>Username</label>
<input name="username" autocomplete="username" required autofocus>
<label>Password</label>
<input name="password" type="password" autocomplete="current-password" required>
<button type="submit">Sign in</button>
</form></body></html>"""


@app.get("/api/login")
async def login_form(err: str = ""):
    body = _LOGIN_HTML.replace("{err}", '<p class="err">Invalid credentials</p>' if err else "")
    return HTMLResponse(body)


@app.post("/api/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    ip = request.client.host if request.client else "unknown"
    if _rate_limit(ip):
        raise HTTPException(status_code=429, detail="Too many attempts – try again later")
    valid = (
        bool(_AUTH_USER)
        and secrets.compare_digest(username, _AUTH_USER)
        and secrets.compare_digest(password, _AUTH_PASS)
    )
    if not valid:
        _login_attempts.setdefault(ip, []).append(time.time())
        return RedirectResponse("/api/login?err=1", status_code=303)
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    _sessions[token] = {"user": username, "csrf": csrf, "created": time.time()}
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie("session", token, httponly=True, samesite="strict")
    return resp


@app.post("/api/logout")
async def logout(request: Request):
    token = request.cookies.get("session")
    if token:
        _sessions.pop(token, None)
    resp = RedirectResponse("/api/login", status_code=303)
    resp.delete_cookie("session")
    return resp


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@app.get("/api/status")
async def api_status(request: Request):
    sess = _require_session(request)
    settings = load_settings()
    return {
        "running": _scanner_state["running"],
        "progress": _scanner_state["progress"],
        "error": _scanner_state["error"],
        "last_scanned": settings.get("last_scanned", 0),
        "last_duration_seconds": settings.get("last_duration_seconds", 0),
        "has_data": _has_data(),
        "interval_hours": settings.get("interval_hours", 24),
        "data_root": _DATA_ROOT,
        "csrf": sess.get("csrf"),
    }


@app.post("/api/rescan")
async def api_rescan(request: Request):
    sess = _require_session(request)
    _check_csrf(request, sess)
    if _scanner_state["running"]:
        raise HTTPException(status_code=409, detail="Scan already running")
    asyncio.create_task(run_scan())
    return {"status": "started"}


@app.post("/api/settings")
async def api_settings(request: Request):
    sess = _require_session(request)
    _check_csrf(request, sess)
    body = await request.json()
    interval = body.get("interval_hours")
    if interval not in _VALID_INTERVALS:
        raise HTTPException(
            status_code=400,
            detail=f"interval_hours must be one of {sorted(_VALID_INTERVALS)}",
        )
    settings = load_settings()
    settings["interval_hours"] = interval
    save_settings(settings)
    return {"interval_hours": interval}


def _validate_path(path: str) -> str:
    """Validate that path is within data root (guards path traversal + symlink escapes)."""
    norm = os.path.normpath(path)
    if norm != _DATA_ROOT_REAL and not norm.startswith(_DATA_ROOT_SEP):
        raise HTTPException(status_code=403, detail="Path outside data root")
    real = os.path.realpath(norm)
    if real != _DATA_ROOT_REAL and not real.startswith(_DATA_ROOT_SEP):
        raise HTTPException(status_code=403, detail="Path outside data root (symlink)")
    return norm


@app.get("/api/data")
async def api_data(request: Request, path: str = "", depth: int = 3):
    _require_session(request)
    if not _has_data():
        raise HTTPException(status_code=503, detail="No scan data yet – trigger a rescan")
    depth = min(max(1, depth), 6)
    target = _validate_path(path.strip() or _DATA_ROOT)
    node = _fetch_subtree(target, depth)
    if node is None:
        raise HTTPException(status_code=404, detail="Path not found in scan data")
    return node


# ---------------------------------------------------------------------------
# Static files
# ---------------------------------------------------------------------------
app.mount("/", StaticFiles(directory="/app/static", html=True), name="static")
