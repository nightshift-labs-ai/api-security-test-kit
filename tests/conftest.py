"""Shared fixtures + a tiny JSON result writer (no plugins beyond pytest itself).

Set APISEC_RESULTS_JSON=/path/out.json to get per-test outcome, markers, docstring
and the real HTTP exchanges each test made (used by tools/report.py as evidence).
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from demo_api.app import create_app  # noqa: E402

TOKENS = {"alice": "alice-token", "bob": "bob-token", "admin": "admin-token", "anonymous": None}
_RESULTS: dict[str, dict] = {}
_T0 = time.time()


class RecordingClient:
    """Wraps TestClient; records every request/response so the report can show real evidence."""

    def __init__(self, client: TestClient, log: list):
        self._c, self._log = client, log

    def request(self, method: str, url: str, as_user: str | None = None, **kw):
        headers = dict(kw.pop("headers", {}) or {})
        if as_user and TOKENS.get(as_user):
            headers["Authorization"] = f"Bearer {TOKENS[as_user]}"
        resp = self._c.request(method, url, headers=headers, **kw)
        full_url = str(resp.request.url).replace("http://testserver", "")
        self._log.append({
            "method": method.upper(), "url": full_url,
            "auth": headers.get("Authorization"), "json": kw.get("json"),
            "status": resp.status_code, "body": resp.text[:700],
        })
        return resp

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)

    def patch(self, url, **kw):
        return self.request("PATCH", url, **kw)

    def delete(self, url, **kw):
        return self.request("DELETE", url, **kw)


@pytest.fixture
def api(request):
    """Fresh app + fresh in-memory DB per test, so tests never affect each other."""
    log: list = []
    request.node._exchanges = log
    with TestClient(create_app()) as c:
        yield RecordingClient(c, log)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    if rep.when == "setup" and rep.outcome != "passed" or rep.when == "call":
        fm = item.get_closest_marker("finding")
        msg = ""
        if rep.failed and call.excinfo is not None:
            msg = str(call.excinfo.value).split("\n")[0][:300]
        _RESULTS[item.nodeid] = {
            "nodeid": item.nodeid, "name": item.name, "outcome": rep.outcome,
            "duration": round(rep.duration, 4),
            "finding": dict(fm.kwargs) if fm else None,
            "kind": "finding" if fm else ("matrix" if item.get_closest_marker("matrix") else "functional"),
            "params": {k: v for k, v in getattr(item, "callspec", None).params.items()} if hasattr(item, "callspec") else {},
            "doc": (item.function.__doc__ or "").strip(),
            "message": msg,
            "exchanges": getattr(item, "_exchanges", []),
        }


def pytest_sessionfinish(session, exitstatus):
    out = os.environ.get("APISEC_RESULTS_JSON")
    if not out:
        return
    data = {
        "mode": "fixed" if os.environ.get("DEMO_FIXED") == "1" else "vulnerable",
        "duration_s": round(time.time() - _T0, 2),
        "tests": list(_RESULTS.values()),
    }
    Path(out).write_text(json.dumps(data, indent=1, default=str))
