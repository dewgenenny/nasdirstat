"""nasdirstat – disk-usage treemap for NAS-style /data mounts."""

from __future__ import annotations

import asyncio
import gzip
import json
import logging
import os
import secrets
import sys
import threading
import time
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor, as_completed
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
_CACHE_FILE = os.path.join(_INDEX_DIR, "scan_cache.json.gz")
_SETTINGS_FILE = os.path.join(_INDEX_DIR, "settings.json")

_PRUNE_PATHS_RAW = os.environ.get(
    "PRUNE_PATHS",
    f"{_DATA_ROOT}/appdata {_DATA_ROOT}/system {_DATA_ROOT}/domains {_DATA_ROOT}/isos",
)
_PRUNE_PATHS: set[str] = {p.strip() for p in _PRUNE_PATHS_RAW.split() if p.strip()}
_MAX_FILES_PER_DIR = int(os.environ.get("MAX_FILES_PER_DIR", "200"))

_AUTH_USER = os.environ.get("AUTH_USER", "")
_AUTH_PASS = os.environ.get("AUTH_PASS", "")
_NOAUTH = os.environ.get("NOAUTH", "false").lower() in ("true", "1", "yes")
_SESSION_HOURS = max(1, int(os.environ.get("SESSION_HOURS", "24")))

_VALID_INTERVALS = {0, 1, 6, 12, 24, 48, 168}
# One thread per top-level directory (≈ one per Unraid share / physical drive).
# Capped at 16 — more than enough for any NAS, and avoids thrashing a shared spindle.
_SCAN_WORKERS = min(16, os.cpu_count() or 4)

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

_cached_tree: dict[str, Any] | None = None
# Maps each directory path → node (only directory nodes, not file leaves)
_dir_index: dict[str, dict[str, Any]] = {}

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
# Cache
# ---------------------------------------------------------------------------

def _build_dir_index(node: dict[str, Any]) -> None:
    if "children" in node:
        _dir_index[node["path"]] = node
        for child in node["children"]:
            _build_dir_index(child)


def load_cache() -> dict[str, Any] | None:
    global _cached_tree
    if not os.path.exists(_CACHE_FILE):
        return None
    try:
        with gzip.open(_CACHE_FILE, "rt", encoding="utf-8") as f:
            _cached_tree = json.load(f)
        _dir_index.clear()
        _build_dir_index(_cached_tree)
        return _cached_tree
    except Exception as exc:
        log.warning("Cache load failed: %s", exc)
        return None


def save_cache(tree: dict[str, Any]) -> None:
    global _cached_tree
    tmp = _CACHE_FILE + ".tmp"
    with gzip.open(tmp, "wt", encoding="utf-8", compresslevel=6) as f:
        json.dump(tree, f, separators=(",", ":"))
    os.replace(tmp, _CACHE_FILE)
    _cached_tree = tree
    _dir_index.clear()
    _build_dir_index(tree)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def _scan_sync(root: str, prune: set[str], max_files: int) -> dict[str, Any]:
    """
    Share-level parallel scanner.

    Each top-level subdirectory of root is scanned by a dedicated thread,
    sequentially within its own subtree.  On Unraid each top-level entry
    (Movies, Music, TV, etc.) typically lives on a different physical drive,
    so threads do genuinely parallel I/O with no head-seeking contention.

    Within each thread the walk is the original bottom-up recursive approach:
    the completed subtree is returned as a finished dict, so peak memory is
    proportional to the final tree size, not the raw file count across all dirs
    simultaneously.
    """
    nodes_seen = 0
    nodes_lock = threading.Lock()
    old_limit = sys.getrecursionlimit()
    sys.setrecursionlimit(10_000)

    try:
        def walk(path: str) -> dict[str, Any]:
            nonlocal nodes_seen
            node: dict[str, Any] = {
                "name": os.path.basename(path) or path,
                "path": path,
                "size": 0,
                "children": [],
            }
            dirs: list[str] = []
            files: list[tuple[str, str, int]] = []
            try:
                with os.scandir(path) as it:
                    for entry in it:
                        if entry.path in prune or entry.is_symlink():
                            continue
                        with nodes_lock:
                            nodes_seen += 1
                            if nodes_seen % 50_000 == 0:
                                _scanner_state["progress"] = f"Scanned {nodes_seen:,} items…"
                                log.info(_scanner_state["progress"])
                        if entry.is_dir(follow_symlinks=False):
                            dirs.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            try:
                                size = entry.stat(follow_symlinks=False).st_size
                                files.append((entry.name, entry.path, size))
                            except OSError:
                                pass
            except PermissionError:
                pass
            except OSError as exc:
                log.warning("Scan error at %s: %s", path, exc)

            for d in dirs:
                child = walk(d)
                node["size"] += child["size"]
                node["children"].append(child)

            files.sort(key=lambda f: f[2], reverse=True)
            kept, rest = files[:max_files], files[max_files:]
            for name, fpath, size in kept:
                node["size"] += size
                node["children"].append({"name": name, "path": fpath, "size": size})
            if rest:
                other_size = sum(f[2] for f in rest)
                node["size"] += other_size
                node["children"].append({
                    "name": f"[{len(rest):,} other files]",
                    "path": path + "/[other]",
                    "size": other_size,
                })
            return node

        # Enumerate root's immediate children
        top_dirs: list[str] = []
        top_files: list[tuple[str, str, int]] = []
        try:
            with os.scandir(root) as it:
                for entry in it:
                    if entry.path in prune or entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        top_dirs.append(entry.path)
                    elif entry.is_file(follow_symlinks=False):
                        try:
                            top_files.append((entry.name, entry.path,
                                              entry.stat(follow_symlinks=False).st_size))
                        except OSError:
                            pass
        except (PermissionError, OSError) as exc:
            log.warning("Scan error at root %s: %s", root, exc)

        log.info("Scan starting: %s  top-level dirs: %d  workers: %d",
                 root, len(top_dirs), min(_SCAN_WORKERS, len(top_dirs) or 1))

        # Each top-level dir gets its own thread (one thread ≈ one share ≈ one drive)
        workers = min(_SCAN_WORKERS, len(top_dirs)) if top_dirs else 1
        children: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for child in as_completed(pool.submit(walk, d) for d in top_dirs):
                children.append(child.result())

        # Assemble root node
        root_size = sum(c["size"] for c in children)
        top_files.sort(key=lambda f: f[2], reverse=True)
        kept, rest = top_files[:max_files], top_files[max_files:]
        for name, fpath, size in kept:
            root_size += size
            children.append({"name": name, "path": fpath, "size": size})
        if rest:
            other_size = sum(f[2] for f in rest)
            root_size += other_size
            children.append({
                "name": f"[{len(rest):,} other files]",
                "path": root + "/[other]",
                "size": other_size,
            })

        return {
            "name": os.path.basename(root) or root,
            "path": root,
            "size": root_size,
            "children": children,
        }

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
        tree = await loop.run_in_executor(
            None, _scan_sync, _DATA_ROOT, _PRUNE_PATHS, _MAX_FILES_PER_DIR
        )
        elapsed = time.monotonic() - t0
        save_cache(tree)
        settings = load_settings()
        settings["last_scanned"] = time.time()
        settings["last_duration_seconds"] = round(elapsed, 1)
        save_settings(settings)
        _scanner_state.update({
            "running": False,
            "progress": f"Done in {elapsed:.0f}s",
            "error": None,
        })
        log.info("Scan complete in %.1fs, %d dirs indexed", elapsed, len(_dir_index))
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
    load_cache()
    task = asyncio.create_task(scheduler_loop())
    try:
        yield
    finally:
        task.cancel()


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
        "has_data": _cached_tree is not None,
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


def _trim_depth(node: dict[str, Any], depth: int) -> dict[str, Any]:
    """Return node trimmed to `depth` levels, largest children first."""
    if depth <= 0 or "children" not in node:
        return {"name": node["name"], "path": node["path"], "size": node["size"]}
    children = [
        _trim_depth(c, depth - 1)
        for c in sorted(node["children"], key=lambda c: c["size"], reverse=True)
    ]
    return {"name": node["name"], "path": node["path"], "size": node["size"], "children": children}


@app.get("/api/data")
async def api_data(request: Request, path: str = "", depth: int = 3):
    _require_session(request)
    if _cached_tree is None:
        raise HTTPException(status_code=503, detail="No scan data yet – trigger a rescan")
    depth = min(max(1, depth), 6)
    target = _validate_path(path.strip() or _DATA_ROOT)
    # Look up in directory index (O(1))
    node = _dir_index.get(target)
    if node is None:
        # Might be the root itself if it wasn't indexed as a dir (edge case)
        if target == _DATA_ROOT_REAL and _cached_tree:
            node = _cached_tree
        else:
            raise HTTPException(status_code=404, detail="Path not found in scan data")
    return _trim_depth(node, depth)


# ---------------------------------------------------------------------------
# Static files
# ---------------------------------------------------------------------------
app.mount("/", StaticFiles(directory="/app/static", html=True), name="static")
