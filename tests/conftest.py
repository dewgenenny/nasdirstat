"""Pytest fixtures — waits for the server to be ready before running tests."""
import os
import time

import httpx
import pytest

BASE_URL = os.environ.get("TEST_URL", "http://localhost:8000")


def _wait_for_server(url: str, timeout: int = 60) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = httpx.get(f"{url}/api/status", timeout=3)
            if r.status_code in (200, 401, 403):
                return
        except (httpx.ConnectError, httpx.TimeoutException):
            pass
        time.sleep(1)
    raise RuntimeError(f"Server at {url} did not become ready within {timeout}s")


@pytest.fixture(scope="session")
def client() -> httpx.Client:
    _wait_for_server(BASE_URL)
    with httpx.Client(base_url=BASE_URL, timeout=30) as c:
        yield c


@pytest.fixture(scope="session")
def csrf(client: httpx.Client) -> str:
    """Return the CSRF token from /api/status (works when NOAUTH=true)."""
    r = client.get("/api/status")
    assert r.status_code == 200, f"Status check failed: {r.text}"
    return r.json().get("csrf", "noauth")
