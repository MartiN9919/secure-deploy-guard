"""SDG Web Dashboard — FastAPI frontend."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
import anyio
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from sdg.config import load_config
from sdg.models import ScanTarget, Finding, Severity, ScanCategory
from sdg.adk.orchestrator import OrchestratorAgent
from sdg.red_blue_green.red_team import RedTeam
from sdg.red_blue_green.green_team import GreenTeam

app = FastAPI(title="Secure Deploy Guard", version="0.2.0")
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")

ALLOWED_SCAN_ROOT = Path.cwd().resolve()


def _validate_scan_path(path: str) -> Path:
    target = (ALLOWED_SCAN_ROOT / path).resolve()
    try:
        target.relative_to(ALLOWED_SCAN_ROOT)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Path outside allowed root") from exc
    return target


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(request, "dashboard.html", {"request": request})


@app.get("/api/config")
async def api_config():
    config = load_config()
    return {
        "roles": list(config.get("roles", {}).keys()),
        "environments": list(config.get("environments", {}).keys()),
    }


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "0.2.0"}


@app.post("/api/scan")
async def run_scan(
    path: str = Form("."),
    role: str = Form("developer"),
    env: str = Form("local"),
    auto_approve: bool = Form(False),
):
    target_path = _validate_scan_path(path)
    config = load_config()
    config["auto_approve"] = auto_approve
    orchestrator = OrchestratorAgent(config)
    target = ScanTarget(path=str(target_path))
    result = await anyio.to_thread.run_sync(orchestrator.run, target, role, env)
    return JSONResponse(result)


@app.post("/api/scan/red-team")
async def red_team_scan(path: str = Form(".")):
    target_path = _validate_scan_path(path)
    config = load_config()
    rt = RedTeam(config)
    result = await anyio.to_thread.run_sync(rt.run, str(target_path))
    return JSONResponse(result)


@app.post("/api/scan/green-team")
async def green_team_scan(findings_json: str = Form("")):
    config = load_config()
    gt = GreenTeam(config)
    raw_findings = json.loads(findings_json) if findings_json else []
    findings = []
    for f in raw_findings:
        findings.append(
            Finding(
                severity=Severity(f.get("severity", "low")),
                category=ScanCategory(f.get("category", "code_quality")),
                message=f.get("message", ""),
                file_path=f.get("file_path", f.get("file", "")),
                line_number=f.get("line_number", f.get("line")),
                recommendation=f.get("recommendation"),
            )
        )
    result = await anyio.to_thread.run_sync(gt.auto_fix, findings)
    return JSONResponse(result)
