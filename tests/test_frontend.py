from starlette.testclient import TestClient
from sdg.frontend.app import app


def test_dashboard_renders():
    client = TestClient(app)
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Secure Deploy Guard" in resp.text


def test_health_endpoint():
    client = TestClient(app)
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_api_config():
    client = TestClient(app)
    resp = client.get("/api/config")
    assert resp.status_code == 200
    data = resp.json()
    assert "developer" in data["roles"]
    assert "local" in data["environments"]


def test_scan_endpoint_auto_approve(tmp_path, monkeypatch):
    from sdg.frontend import app as frontend_app
    monkeypatch.setattr(frontend_app, "ALLOWED_SCAN_ROOT", tmp_path)
    (tmp_path / "main.py").write_text("print('hello')\n")
    client = TestClient(frontend_app.app)
    resp = client.post("/api/scan", data={"path": ".", "role": "developer", "env": "local", "auto_approve": "true"})
    assert resp.status_code == 200
    data = resp.json()
    assert "session_id" in data
    assert "trust_score" in data



def test_scan_endpoint_rejects_outside_path():
    client = TestClient(app)
    resp = client.post("/api/scan", data={"path": "/etc", "role": "developer", "env": "local", "auto_approve": "true"})
    assert resp.status_code == 400


def test_red_team_endpoint():
    client = TestClient(app)
    resp = client.post("/api/scan/red-team", data={"path": "."})
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("agent") == "red_team"


def test_dashboard_uses_local_assets():
    client = TestClient(app)
    resp = client.get("/")
    assert resp.status_code == 200
    assert "cdn.replit" not in resp.text
    assert "/static/bootstrap.min.css" in resp.text
    assert "/static/sdg-dashboard.js" in resp.text
