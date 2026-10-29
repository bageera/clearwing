"""Regression tests for the vuln-fixes branch (vuln-fixes round 1)."""

import json

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from nightwing.data.memory.session_store import SessionStore, _safe_session_id
from nightwing.ui.web.app import create_app


class TestSessionIdTraversalGuard:
    def test_rejects_traversal(self):
        for sid in ("../evil", "..\\evil", "a/b", "a\\b", "", ".", "..", "x y"):
            with pytest.raises(ValueError):
                _safe_session_id(sid)

    def test_accepts_valid_ids(self):
        assert _safe_session_id("abc123") == "abc123"
        assert _safe_session_id("Ab_2-Z") == "Ab_2-Z"

    def test_load_traversal_raises_not_escapes_basedir(self, tmp_path, monkeypatch):
        store = SessionStore.__new__(SessionStore)
        store.BASE_DIR = tmp_path / "sessions"
        store.BASE_DIR.mkdir(parents=True)
        # plant a victim file OUTSIDE the base dir
        victim = tmp_path / "evil.json"
        victim.write_text(json.dumps({"session_id": "x", "target": "t", "model": "m", "status": "s", "start_time": "2025-01-01T00:00:00"}))
        with pytest.raises(ValueError):
            store.load("../evil")

    def test_delete_traversal_raises(self, tmp_path):
        store = SessionStore.__new__(SessionStore)
        store.BASE_DIR = tmp_path / "sessions"
        store.BASE_DIR.mkdir(parents=True)
        with pytest.raises(ValueError):
            store.delete("../../other")


class TestCorsLocked:
    def test_foreign_origin_not_reflected(self):
        app = create_app()
        client = TestClient(app)
        r = client.get("/api/health", headers={"Origin": "http://evil.example"})
        assert r.headers.get("access-control-allow-origin") != "http://evil.example"

    def test_local_origin_allowed(self):
        app = create_app()
        client = TestClient(app)
        r = client.get("/api/health", headers={"Origin": "http://localhost:8899"})
        assert r.headers.get("access-control-allow-origin") == "http://localhost:8899"

    def test_wildcard_gone(self):
        app = create_app()
        cors = [m for m in app.user_middleware if hasattr(m, "kwargs") and "allow_origins" in m.kwargs]
        assert cors and cors[0].kwargs["allow_origins"] != ["*"]