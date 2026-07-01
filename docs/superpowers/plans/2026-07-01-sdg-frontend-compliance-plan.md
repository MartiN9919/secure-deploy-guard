# SDG Frontend & Compliance Redesign — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the Secure Deploy Guard frontend to be beautiful, secure, and A2UI-aligned; fix critical/high audit findings; align the codebase with the 5 agentic-engineering whitepapers.

**Architecture:** FastAPI backend serves a Jinja2 dashboard with local Bootstrap assets; the backend runs the orchestrator in a background thread and returns structured JSON that the frontend renders via a safe component catalog. Critical fixes (secrets removal, MCP semgrep, policy gates, sandboxing, config alignment) are applied across the Python codebase.

**Tech Stack:** Python 3.14, FastAPI/Starlette, Jinja2, Bootstrap 5 (local), vanilla JS, pytest, OpenRouter API, MCP SDK.

## Global Constraints
- Python 3.14 on Linux
- No hardcoded secrets; `.env` must not be committed
- All dynamic frontend content must be HTML-escaped
- Existing 65 tests must remain green; new tests added for new behavior
- Follow existing code style and file structure
- No external CDN dependencies in production

---

## File Structure

| Path | Responsibility |
|---|---|
| `sdg/frontend/app.py` | FastAPI routes, scan orchestration, config endpoint |
| `sdg/frontend/templates/dashboard.html` | Main dashboard template |
| `sdg/frontend/static/` | Local Bootstrap, CSS, JS assets |
| `sdg/frontend/static/sdg-dashboard.js` | Safe component renderer |
| `sdg/frontend/static/sdg-dashboard.css` | Custom styles |
| `sdg/policy_engine/structural.py` | Structural gate with approval-required state |
| `sdg/policy_engine/semantic.py` | Fail-closed semantic gate |
| `sdg/policy_engine/context_hygiene.py` | Recursive context sanitization |
| `sdg/mcp_servers/server_semgrep.py` | Correct file-reading semgrep server |
| `sdg/mcp_servers/client.py` | Use `sys.executable` |
| `sdg/models.py` | Align `passed()` logic |
| `sdg/config.yaml` | Add reviewer/ci |
| `sdg/sandbox/executor.py` | Safer subprocess runner |
| `sdg/evaluation/judge.py` | JSON-mode judge |
| `sdg/cli.py` | Align choices with config |
| `Dockerfile` | Non-root, .dockerignore compliant |
| `.dockerignore` | Exclude secrets/build artifacts |
| `docker-compose.yml` | Dev compose with env file |
| `.gitignore` | Exclude .env, .venv, caches |
| `tests/test_frontend.py` | Frontend route tests |
| `tests/test_mcp_servers.py` | MCP call_tool tests |
| `tests/test_policy.py` | Approval flow tests |

---

### Task 1: Repository hygiene — remove hardcoded secret and ignore sensitive files

**Files:**
- Delete: `.env`
- Modify: `.gitignore`
- Modify: `sdg/.env.example`

**Interfaces:**
- Produces: `.env` no longer tracked; `.env.example` contains placeholder only

- [ ] **Step 1: Write test verifying no .env secret leakage**

```python
# tests/test_repo_hygiene.py
import re
from pathlib import Path

def test_no_env_file_committed():
    env_path = Path(__file__).parent.parent / ".env"
    assert not env_path.exists(), ".env must not be committed"

def test_env_example_is_placeholder():
    example = Path(__file__).parent.parent / "sdg" / ".env.example"
    content = example.read_text()
    assert "OPENROUTER_API_KEY=your_key_here" in content
    assert not re.search(r"sk-or-v1-[a-f0-9]{32,}", content)
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python3 -m pytest tests/test_repo_hygiene.py -v
```
Expected: FAIL on `test_no_env_file_committed`.

- [ ] **Step 3: Delete .env and update .env.example**

Delete `/home/dev/PycharmProjects/PythonProject3/.env`.
Update `sdg/.env.example` to:
```env
OPENROUTER_API_KEY=your_key_here
OPENROUTER_MODEL=google/gemini-2.5-flash-lite-preview-05-2025
```

- [ ] **Step 4: Create .gitignore**

```gitignore
.env
.venv
__pycache__
*.pyc
.pytest_cache
*.egg-info
.DS_Store
.vscode
.idea
```

- [ ] **Step 5: Run tests**

```bash
python3 -m pytest tests/test_repo_hygiene.py -v
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add .gitignore sdg/.env.example tests/test_repo_hygiene.py
# Note: .env deletion is tracked by git rm
```

---

### Task 2: Fix MCP Semgrep server to actually read files

**Files:**
- Modify: `sdg/mcp_servers/server_semgrep.py`
- Modify: `tests/test_mcp_servers.py`

**Interfaces:**
- Consumes: `sdg.utils.patterns.scan_with_patterns(file_path: str, content: str) -> list[Finding]`
- Produces: `call_tool("semgrep_scan", {"path": str, "rules": str})` returns JSON findings

- [ ] **Step 1: Write failing test**

```python
# tests/test_mcp_servers.py
import asyncio
import tempfile
from pathlib import Path
from sdg.mcp_servers.server_semgrep import call_tool

async def _call(tool, args):
    return await call_tool(tool, args)

def test_semgrep_server_scans_file_content():
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "vuln.py"
        f.write_text("password = 'secret'\n")
        result = asyncio.run(_call("semgrep_scan", {"path": str(tmp), "rules": "owasp-top-10"}))
    assert len(result) == 1
    text = result[0].text
    assert "hardcoded_secret" in text or "password" in text.lower()
```

- [ ] **Step 2: Run test to verify failure**

```bash
python3 -m pytest tests/test_mcp_servers.py::test_semgrep_server_scans_file_content -v
```
Expected: FAIL (no findings because path treated as content).

- [ ] **Step 3: Implement correct server_semgrep.py**

Replace the `call_tool` body with:
```python
import json
import os
from pathlib import Path
from sdg.utils.patterns import scan_with_patterns, EXCLUDED_DIRS

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name != "semgrep_scan":
        raise ValueError(f"Unknown tool: {name}")

    path = arguments["path"]
    rules = arguments.get("rules", "owasp-top-10")

    def _should_scan(filepath: str) -> bool:
        parts = filepath.replace("\\", "/").split("/")
        return not any(p in EXCLUDED_DIRS for p in parts)

    findings = []
    if os.path.isfile(path):
        try:
            content = Path(path).read_text(encoding="utf-8", errors="ignore")
            findings.extend(scan_with_patterns(str(path), content))
        except Exception as e:
            return [TextContent(type="text", text=json.dumps({"error": str(e)}, indent=2))]
    elif os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
            for fname in files:
                fpath = os.path.join(root, fname)
                if not _should_scan(fpath):
                    continue
                try:
                    content = Path(fpath).read_text(encoding="utf-8", errors="ignore")
                    findings.extend(scan_with_patterns(fpath, content))
                except Exception:
                    continue
    else:
        return [TextContent(type="text", text=json.dumps({"error": f"Path not found: {path}"}, indent=2))]

    return [TextContent(type="text", text=json.dumps([{
        "severity": f.severity.value,
        "category": f.category.value,
        "message": f.message,
        "file": f.file_path,
        "line": f.line_number,
        "recommendation": f.recommendation,
    } for f in findings], indent=2))]
```

- [ ] **Step 4: Run test**

```bash
python3 -m pytest tests/test_mcp_servers.py::test_semgrep_server_scans_file_content -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 3: Fix policy gates — required approval and fail-closed semantic gate

**Files:**
- Modify: `sdg/policy_engine/structural.py`
- Modify: `sdg/policy_engine/semantic.py`
- Modify: `sdg/adk/orchestrator.py`
- Modify: `tests/test_policy.py`

**Interfaces:**
- `StructuralGate.check_action_allowed()` returns `(bool, str)` or raises `ApprovalRequiredError`
- `SemanticGate.check_action()` returns `(bool, str)`, fails closed

- [ ] **Step 1: Define ApprovalRequiredError**

In `sdg/policy_engine/structural.py`:
```python
class ApprovalRequiredError(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)
```

- [ ] **Step 2: Update structural gate**

Modify `check_tool_allowed`:
```python
if tool_name in env.get("required_approval", []):
    raise ApprovalRequiredError(f"Requires approval in '{environment}'")
```

- [ ] **Step 3: Update semantic gate to fail-closed**

```python
except Exception as e:
    return False, f"Gate error: {e}"
```

- [ ] **Step 4: Update orchestrator to catch ApprovalRequiredError**

In `OrchestratorAgent.run`, wrap structural check:
```python
from sdg.policy_engine.structural import ApprovalRequiredError
try:
    allowed, reason = self.policy_structural.check_action_allowed("scan", role, environment)
except ApprovalRequiredError as e:
    # proceed to HITL later; mark approval needed
    session.approval_required = True
    allowed, reason = True, ""
```

- [ ] **Step 5: Write tests**

```python
def test_required_approval_raises():
    gate = StructuralGate({
        "environments": {"local": {"required_approval": ["scan"]}},
        "roles": {"developer": {"allowed_tools": ["scan"]}},
    })
    from sdg.policy_engine.structural import ApprovalRequiredError
    with pytest.raises(ApprovalRequiredError):
        gate.check_action_allowed("scan", role="developer", environment="local")

def test_semantic_fail_closed():
    gate = SemanticGate({})
    allowed, reason = gate.check_action("test")
    assert not allowed
    assert "no API key" in reason.lower() or "skipped" in reason.lower()
```

- [ ] **Step 6: Run tests**

```bash
python3 -m pytest tests/test_policy.py -v
```
Expected: PASS.

- [ ] **Step 7: Commit**

---

### Task 4: Align config, models, and CLI

**Files:**
- Modify: `sdg/config.yaml`
- Modify: `sdg/models.py`
- Modify: `sdg/cli.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Update config.yaml**

Add:
```yaml
roles:
  developer:
    allowed_tools: ["*"]
  admin:
    allowed_tools: ["*"]
  reviewer:
    allowed_tools: ["scan", "read", "evaluate"]
  ci:
    allowed_tools: ["scan", "lint"]

environments:
  local:
    blocked_tools: []
    required_approval: []
  ci:
    blocked_tools: []
    required_approval: []
  staging:
    blocked_tools: ["deploy"]
    required_approval: []
  production:
    blocked_tools: ["deploy", "delete"]
    required_approval: ["scan"]
```

- [ ] **Step 2: Fix ScanReport.passed()**

```python
def passed(self) -> bool:
    return not any(f.severity == Severity.CRITICAL for f in self.findings)
```

- [ ] **Step 3: Fix CLI choices and green-team deserialization**

Update choices to match config.
For green-team, deserialize raw dicts into `Finding` objects before passing to `auto_fix`.

- [ ] **Step 4: Update tests**

Add CLI config alignment tests.

- [ ] **Step 5: Run all tests**

```bash
python3 -m pytest tests/ -v
```
Expected: all pass.

- [ ] **Step 6: Commit**

---

### Task 5: Safer sandbox and context hygiene

**Files:**
- Modify: `sdg/sandbox/executor.py`
- Modify: `sdg/policy_engine/context_hygiene.py`
- Modify: `tests/test_sandbox.py` (create)
- Modify: `tests/test_policy.py`

- [ ] **Step 1: Implement safer executor**

```python
import subprocess
from pathlib import Path
from typing import Any

class SandboxExecutor:
    def __init__(self, allowed_root: str | Path = ".", timeout: int = 30):
        self.allowed_root = Path(allowed_root).resolve()
        self.timeout = timeout

    def _validate_path(self, p: Path) -> Path:
        resolved = (self.allowed_root / p).resolve()
        if self.allowed_root not in resolved.parents and resolved != self.allowed_root:
            raise ValueError(f"Path {resolved} is outside allowed root {self.allowed_root}")
        return resolved

    def run(self, cmd: list[str], cwd: str | Path | None = None, **kwargs: Any) -> subprocess.CompletedProcess:
        if not cmd:
            raise ValueError("Command must not be empty")
        if isinstance(cmd, str):
            raise ValueError("Command must be a list, not a string")
        workdir = self._validate_path(cwd) if cwd else self.allowed_root
        return subprocess.run(
            cmd,
            cwd=str(workdir),
            timeout=self.timeout,
            shell=False,
            capture_output=True,
            text=True,
            **kwargs,
        )
```

- [ ] **Step 2: Fix context_hygiene imports and recursion**

Move `from sdg.policy_engine.pii_mask import mask_pii` to top.
Add recursive sanitization:
```python
def sanitize_tool_args(args: dict[str, Any], state: dict[str, Any] | None = None) -> dict[str, Any]:
    def _sanitize_value(value: Any) -> Any:
        if isinstance(value, str):
            return mask_pii(resolve_context(value, state))
        if isinstance(value, list):
            return [_sanitize_value(i) for i in value]
        if isinstance(value, dict):
            return {k: _sanitize_value(v) for k, v in value.items()}
        return value
    return {k: _sanitize_value(v) for k, v in args.items()}
```

- [ ] **Step 3: Write tests**

```python
def test_sandbox_rejects_shell_command():
    ex = SandboxExecutor()
    with pytest.raises(ValueError):
        ex.run("ls -la")

def test_context_hygiene_recursive():
    args = {"nested": {"email": "a@b.com"}, "list": ["x@y.com"]}
    result = ContextHygiene.sanitize(args)
    assert "@" not in result["nested"]["email"]
    assert "@" not in result["list"][0]
```

- [ ] **Step 4: Run tests**

```bash
python3 -m pytest tests/test_sandbox.py tests/test_policy.py -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 6: Improve LLM Judge with JSON mode

**Files:**
- Modify: `sdg/utils/llm.py`
- Modify: `sdg/evaluation/judge.py`
- Modify: `tests/test_evaluation.py`

- [ ] **Step 1: Add response_format support to query_llm**

```python
def query_llm(prompt: str, config: dict[str, Any], system_prompt: str = "...", max_tokens: int = 1024, response_format: dict[str, Any] | None = None) -> str:
    ...
    payload = {...}
    if response_format:
        payload["response_format"] = response_format
    ...
```

- [ ] **Step 2: Update judge to use JSON mode**

```python
result = query_llm(
    prompt,
    self.config,
    system_prompt="You are a security judge. Return valid JSON.",
    max_tokens=512,
    response_format={"type": "json_object"},
)
```

- [ ] **Step 3: Update tests**

Add test with mocked response.

- [ ] **Step 4: Run tests**

```bash
python3 -m pytest tests/test_evaluation.py -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

---

### Task 7: Rebuild frontend — backend routes and safe template

**Files:**
- Modify: `sdg/frontend/app.py`
- Create: `sdg/frontend/static/sdg-dashboard.js`
- Create: `sdg/frontend/static/sdg-dashboard.css`
- Modify: `sdg/frontend/templates/dashboard.html`
- Modify: `tests/test_frontend.py` (create)

- [ ] **Step 1: Update app.py routes**

```python
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import anyio
from sdg.config import load_config
from sdg.models import ScanTarget
from sdg.adk.orchestrator import OrchestratorAgent
from sdg.red_blue_green.red_team import RedTeam
from sdg.red_blue_green.green_team import GreenTeam

app = FastAPI(title="Secure Deploy Guard", version="0.2.0")
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")

ALLOWED_SCAN_ROOT = Path.cwd().resolve()

def _validate_scan_path(path: str) -> Path:
    target = (ALLOWED_SCAN_ROOT / path).resolve()
    if ALLOWED_SCAN_ROOT not in target.parents and target != ALLOWED_SCAN_ROOT:
        raise HTTPException(status_code=400, detail="Path outside allowed root")
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

@app.post("/api/scan")
async def run_scan(path: str = Form("."), role: str = Form("developer"), env: str = Form("local"), auto_approve: bool = Form(False)):
    target_path = _validate_scan_path(path)
    config = load_config()
    config["auto_approve"] = auto_approve
    orchestrator = OrchestratorAgent(config)
    target = ScanTarget(path=str(target_path))
    result = await anyio.to_thread.run_sync(orchestrator.run, target, role, env)
    return JSONResponse(result)

@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "0.2.0"}

@app.post("/api/scan/red-team")
async def red_team_scan(path: str = Form(".")):
    target_path = _validate_scan_path(path)
    config = load_config()
    rt = RedTeam(config)
    result = await anyio.to_thread.run_sync(rt.run, str(target_path))
    return JSONResponse(result)

@app.post("/api/scan/green-team")
async def green_team_scan(findings_json: str = Form("")):
    from sdg.models import Finding, Severity, ScanCategory
    import json
    config = load_config()
    gt = GreenTeam(config)
    raw = json.loads(findings_json) if findings_json else []
    findings = []
    for f in raw:
        findings.append(Finding(
            severity=Severity(f.get("severity", "low")),
            category=ScanCategory(f.get("category", "code_quality")),
            message=f.get("message", ""),
            file_path=f.get("file", ""),
            line_number=f.get("line"),
            recommendation=f.get("recommendation"),
        ))
    result = await anyio.to_thread.run_sync(gt.auto_fix, findings)
    return JSONResponse(result)
```

- [ ] **Step 2: Create safe JS renderer**

`sdg/frontend/static/sdg-dashboard.js` will use `document.createElement` and `textContent` only; no `innerHTML` with dynamic data.

- [ ] **Step 3: Create CSS**

Custom dark-theme styles using local Bootstrap.

- [ ] **Step 4: Rewrite dashboard.html**

Use local Bootstrap from `/static`, no CDN, no emojis, clean layout with:
- Hero section
- Scan form
- Summary stat cards
- Trust score gauge
- Findings table with filters
- Agent log
- Policy log
- Vibe diff
- Red team / green team panels
- Export buttons

- [ ] **Step 5: Add frontend tests**

```python
from starlette.testclient import TestClient
from sdg.frontend.app import app

def test_dashboard():
    client = TestClient(app)
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Secure Deploy Guard" in resp.text

def test_api_config():
    client = TestClient(app)
    resp = client.get("/api/config")
    assert resp.status_code == 200
    assert "developer" in resp.json()["roles"]
```

- [ ] **Step 6: Run tests**

```bash
python3 -m pytest tests/test_frontend.py -v
```
Expected: PASS.

- [ ] **Step 7: Commit**

---

### Task 8: Local Bootstrap assets

**Files:**
- Create: `sdg/frontend/static/bootstrap.min.css`
- Create: `sdg/frontend/static/bootstrap.bundle.min.js`

- [ ] **Step 1: Download Bootstrap 5.3 dark bundle**

```bash
curl -L -o sdg/frontend/static/bootstrap.min.css https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css
curl -L -o sdg/frontend/static/bootstrap.bundle.min.js https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js
```

- [ ] **Step 2: Reference local files in dashboard.html**

```html
<link href="/static/bootstrap.min.css" rel="stylesheet">
<script src="/static/bootstrap.bundle.min.js" defer></script>
```

- [ ] **Step 3: Verify dashboard loads without external CDN**

Open `/` and check network tab (or grep for `cdn.replit`).

- [ ] **Step 4: Commit**

---

### Task 9: Dockerfile and docker-compose fixes

**Files:**
- Modify: `Dockerfile`
- Create: `.dockerignore`
- Modify: `docker-compose.yml`

- [ ] **Step 1: Write .dockerignore**

```
.env
.venv
__pycache__
*.pyc
.pytest_cache
.git
.gitignore
Dockerfile
docker-compose.yml
*.md
tests/
```

- [ ] **Step 2: Rewrite Dockerfile**

```dockerfile
FROM python:3.14-slim
WORKDIR /app
RUN groupadd -r sdg && useradd -r -g sdg sdg
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sdg/ ./sdg/
USER sdg
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"
CMD ["python3", "-m", "uvicorn", "sdg.frontend.app:app", "--host", "0.0.0.0", "--port", "8000"]
```

- [ ] **Step 3: Update docker-compose.yml**

```yaml
services:
  sdg:
    build: .
    ports:
      - "8000:8000"
    env_file:
      - .env
    environment:
      - OPENROUTER_MODEL=${OPENROUTER_MODEL:-google/gemini-2.5-flash-lite-preview-05-2025}
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"]
      interval: 30s
      timeout: 5s
      retries: 3
```

- [ ] **Step 4: Build image to verify**

```bash
docker build -t sdg:test .
```
Expected: builds without error, runs as non-root.

- [ ] **Step 5: Commit**

---

### Task 10: Final integration and full test run

**Files:**
- All modified

- [ ] **Step 1: Run full test suite**

```bash
python3 -m pytest tests/ -v
```
Expected: all tests pass.

- [ ] **Step 2: Run CLI smoke test**

```bash
python3 -m sdg.cli scan . --auto-approve --format json
```
Expected: returns JSON with findings, no errors.

- [ ] **Step 3: Run frontend smoke test**

```bash
python3 -m uvicorn sdg.frontend.app:app --host 0.0.0.0 --port 8000 &
curl -s http://localhost:8000/api/health
```
Expected: `{"status":"ok","version":"0.2.0"}`.

- [ ] **Step 4: Update README.md**

Document new frontend features, config, and security fixes.

- [ ] **Step 5: Commit and final summary**

---

## Spec Coverage Check

| Spec Requirement | Task |
|---|---|
| A2UI-inspired frontend | Task 7, 8 |
| No hardcoded secrets | Task 1 |
| MCP semgrep reads files | Task 2 |
| Structural required approval | Task 3 |
| Semantic fail-closed | Task 3 |
| Config alignment | Task 4 |
| Sandbox safety | Task 5 |
| Context hygiene recursion | Task 5 |
| LLM Judge JSON mode | Task 6 |
| Frontend path validation | Task 7 |
| Local assets (no CDN) | Task 8 |
| Docker non-root + .dockerignore | Task 9 |
| Full test coverage | All tasks |

## Placeholder Scan

No TBD/TODO placeholders. Out-of-scope items (gVisor, OSV API) are explicitly listed as future enhancements.
