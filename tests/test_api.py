"""Integration tests for nasdirstat API (run against a live server with NOAUTH=true)."""
import time

import httpx
import pytest


# ── /api/status ───────────────────────────────────────────────────────────────

def test_status_ok(client: httpx.Client):
    r = client.get("/api/status")
    assert r.status_code == 200
    body = r.json()
    assert "running" in body
    assert "has_data" in body
    assert "data_root" in body
    assert "interval_hours" in body


def test_status_fields_types(client: httpx.Client):
    body = client.get("/api/status").json()
    assert isinstance(body["running"], bool)
    assert isinstance(body["has_data"], bool)
    assert isinstance(body["interval_hours"], int)
    assert isinstance(body["last_scanned"], (int, float))
    assert isinstance(body["last_duration_seconds"], (int, float))


# ── /api/rescan ───────────────────────────────────────────────────────────────

def test_rescan_starts(client: httpx.Client, csrf: str):
    # If a scan is already running, this returns 409 — that's also valid
    r = client.post("/api/rescan", headers={"X-CSRF-Token": csrf})
    assert r.status_code in (200, 409)


def test_rescan_and_wait(client: httpx.Client, csrf: str):
    """Trigger a scan and poll until it finishes (max 120s)."""
    # May already be running from previous test
    client.post("/api/rescan", headers={"X-CSRF-Token": csrf})

    deadline = time.time() + 120
    while time.time() < deadline:
        s = client.get("/api/status").json()
        if not s["running"]:
            assert s["has_data"], "Scan finished but has_data is False"
            return
        time.sleep(2)
    pytest.fail("Scan did not complete within 120 seconds")


def test_rescan_409_when_running(client: httpx.Client, csrf: str):
    """If we POST rescan while one is running, expect 409."""
    # Kick off a scan; if it's already running we'll get 409, which is fine.
    r1 = client.post("/api/rescan", headers={"X-CSRF-Token": csrf})
    if r1.status_code == 200:
        # Now a second request should return 409
        r2 = client.post("/api/rescan", headers={"X-CSRF-Token": csrf})
        assert r2.status_code == 409
        # Wait for it to finish before continuing
        deadline = time.time() + 120
        while time.time() < deadline:
            if not client.get("/api/status").json()["running"]:
                break
            time.sleep(2)


# ── /api/data ─────────────────────────────────────────────────────────────────

def test_data_root(client: httpx.Client):
    r = client.get("/api/data")
    assert r.status_code == 200
    body = r.json()
    assert "name" in body
    assert "size" in body
    assert isinstance(body["size"], int)


def test_data_has_children(client: httpx.Client):
    body = client.get("/api/data").json()
    # Root must have at least one child (our test data)
    assert "children" in body
    assert len(body["children"]) >= 1


def test_data_depth_respected(client: httpx.Client):
    """At depth=1 the children should have no nested children."""
    body = client.get("/api/data?depth=1").json()
    for child in body.get("children", []):
        assert "children" not in child or len(child["children"]) == 0


def test_data_path_param(client: httpx.Client):
    """Fetch data for a specific sub-path."""
    root = client.get("/api/data").json()
    if not root.get("children"):
        pytest.skip("No children in root — empty test data")
    first_child = root["children"][0]
    if "children" not in first_child:
        pytest.skip("First child is a file, not a directory")
    r = client.get(f"/api/data?path={first_child['path']}")
    assert r.status_code == 200
    body = r.json()
    assert body["path"] == first_child["path"]


def test_data_size_consistency(client: httpx.Client):
    """Parent size should equal or exceed sum of children sizes."""
    body = client.get("/api/data").json()
    if "children" in body:
        children_sum = sum(c["size"] for c in body["children"])
        # Allow small rounding differences
        assert body["size"] >= children_sum * 0.99


# ── /api/data path traversal ─────────────────────────────────────────────────

@pytest.mark.parametrize("bad_path", [
    "../etc",
    "../../etc/passwd",
    "/etc/passwd",
    "/proc/1",
    "//etc",
])
def test_path_traversal_rejected(client: httpx.Client, bad_path: str):
    r = client.get(f"/api/data?path={bad_path}")
    assert r.status_code in (403, 404), f"Expected 403/404 for {bad_path!r}, got {r.status_code}"


# ── /api/settings ─────────────────────────────────────────────────────────────

def test_settings_update(client: httpx.Client, csrf: str):
    r = client.post(
        "/api/settings",
        json={"interval_hours": 12},
        headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
    )
    assert r.status_code == 200
    assert r.json()["interval_hours"] == 12


def test_settings_invalid_interval(client: httpx.Client, csrf: str):
    r = client.post(
        "/api/settings",
        json={"interval_hours": 99},
        headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
    )
    assert r.status_code == 400


def test_settings_interval_reflected_in_status(client: httpx.Client, csrf: str):
    client.post(
        "/api/settings",
        json={"interval_hours": 6},
        headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
    )
    body = client.get("/api/status").json()
    assert body["interval_hours"] == 6
    # Restore default
    client.post(
        "/api/settings",
        json={"interval_hours": 24},
        headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
    )


# ── Static / HTML ─────────────────────────────────────────────────────────────

def test_index_served(client: httpx.Client):
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")
    assert "nasdirstat" in r.text.lower()


def test_security_headers(client: httpx.Client):
    r = client.get("/api/status")
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "SAMEORIGIN"
    assert r.headers.get("referrer-policy") == "same-origin"
