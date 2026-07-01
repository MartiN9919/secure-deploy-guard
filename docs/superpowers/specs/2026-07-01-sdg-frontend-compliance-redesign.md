# Secure Deploy Guard (SDG) — Frontend & Compliance Redesign

**Date:** 2026-07-01  
**Status:** Approved by user ("СДЕЛАЙ НА СВОЙ ВКУС КАК ПРОФЕССИОНАЛЬНО")  
**Goal:** Rebuild the frontend to be beautiful, functional, and aligned with the 5 agentic-engineering whitepapers; fix all critical/high audit findings; ensure every documented concept has a working, correct implementation.

---

## 1. Context & Constraints

### Source documents
1. **Day 1** — The New SDLC with Vibe Coding (harness, conductor/orchestrator, factory model)
2. **Day 2** — Agent Tools & Interoperability (MCP, A2A, A2UI, protocols)
3. **Day 3** — Agent Skills (SKILL.md format, progressive disclosure, eval)
4. **Day 4** — Vibe Coding Agent Security and Evaluation (7 pillars, Red/Blue/Green, Trust Score, Vibe Diff, HITL, evaluation)
5. **Day 5** — Spec-Driven Production Grade Development (SDD, BDD/Gherkin, guardrails, sandboxing, policy server, context hygiene)

### Hard constraints
- Python 3.14, Linux, project root `/home/dev/PycharmProjects/PythonProject3`
- LLM: OpenRouter + Gemini 2.5 Flash Lite
- No hardcoded secrets; secrets via `.env`
- All changes must keep existing tests green and add new tests for new behavior
- Follow existing code style; avoid speculative abstractions

---

## 2. What We Are Building

### 2.1 New frontend (A2UI-inspired secure dashboard)
A single-page FastAPI/Jinja2 dashboard that turns raw scan JSON into safe, interactive, declarative UI components:

- **Hero / summary surface** — Trust Score gauge, severity cards, pass/fail banner
- **Scan launcher** — path, role, environment, auto-approve toggle with HITL warning
- **Findings explorer** — filterable table with severity/category/file, detail drawer
- **Agent trajectory panel** — which agents ran, what they found, execution time
- **Policy gate log** — structural + semantic gate decisions with reasoning
- **Vibe Diff card** — plain-English summary before HITL approval
- **Red Team surface** — adversarial findings with pattern/type badges
- **Green Team surface** — auto-fix suggestions with diff preview
- **Report export** — Markdown/JSON download

Design principles from A2UI:
- Server emits **data + component descriptors**, never raw HTML/JS strings
- Client renders via a trusted local component catalog
- All dynamic text is HTML-escaped; no `innerHTML` with user content
- Assets served locally (no external CDN dependency)

### 2.2 Critical fixes
| # | Issue | Fix |
|---|---|---|
| 1 | Hardcoded `OPENROUTER_API_KEY` in `.env` | Remove from repo, rotate, use `.env.example` only, add `.gitignore` |
| 2 | `server_semgrep.py` never reads files | Read file contents and pass to `scan_with_patterns()`; iterate directories |
| 3 | Dockerfile copies `.env`/`.venv` | Add `.dockerignore`, non-root `USER`, `HEALTHCHECK`, multi-stage copy |
| 4 | Frontend hardcodes `auto_approve=True` | Make it a form toggle with HITL warning; default False |
| 5 | Frontend runs sync orchestrator in async endpoint | Run scan in `anyio.to_thread.run_sync` |
| 6 | Semantic gate fail-open | Change to fail-closed (`return False` on exception) |
| 7 | Structural `required_approval` blocks instead of requesting approval | Return approval-required state; orchestrator routes to HITL |
| 8 | `ScanReport.passed()` treats HIGH as failure | Align with orchestrator/README: fail only on CRITICAL |
| 9 | `context_hygiene.py` fragile import order | Move imports to top; add recursive sanitization |
| 10 | Frontend XSS via unescaped findings | Escape every dynamic value in JS; render via safe DOM APIs |
| 11 | `Dockerfile` runs as root | Add non-root user |
| 12 | `docker-compose.yml` mounts host volume in prod | Separate dev/prod compose or remove mount |
| 13 | MCP client uses `python` command | Use `sys.executable` |
| 14 | CLI choices don't match `config.yaml` | Add `reviewer` role and `ci` environment to config |

### 2.3 Alignment improvements
- **Agent Skills:** ensure all 6 SKILL.md files follow canonical format (YAML frontmatter, When to use / When NOT to use / Workflow / Examples / Output format)
- **7 Pillars mapping:** add a `docs/security/7-pillars-mapping.md` explaining how SDG maps to each pillar
- **Policy Server:** structural+semantic gates already exist; make required-approval route correctly
- **Context Hygiene:** apply PII masking to all LLM prompts and tool arguments
- **Evaluation:** LLM Judge uses JSON-mode response_format; add trajectory tracking
- **Red/Blue/Green:** make thresholds configurable; Red Team emits typed findings; Green Team shows diff preview

---

## 3. Frontend Architecture

```
┌─────────────────────────────────────────────┐
│  Browser                                    │
│  ┌──────────────┐  ┌─────────────────────┐ │
│  │ Dashboard    │  │ Component Catalog   │ │
│  │ (Jinja2 +    │  │ (safe renderers)    │ │
│  │  vanilla JS) │  │                     │ │
│  └──────┬───────┘  └─────────────────────┘ │
└─────────┼───────────────────────────────────┘
          │ HTTP / FormData / JSON
┌─────────┼───────────────────────────────────┐
│  FastAPI│                                   │
│  ┌──────┴───────┐  ┌─────────────────────┐ │
│  │ app.py        │  │ OrchestratorAgent   │ │
│  │ routes        │──│ (threaded runner)   │ │
│  └───────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────┘
```

### Routes
| Route | Method | Purpose |
|---|---|---|
| `/` | GET | Dashboard HTML |
| `/api/health` | GET | Health check |
| `/api/scan` | POST | Run full scan (returns JSON) |
| `/api/scan/red-team` | POST | Run Red Team scan |
| `/api/scan/green-team` | POST | Generate fixes for findings |
| `/api/config` | GET | Roles/environments for UI |

### Component catalog (server-safe)
- `StatCard`, `SeverityBadge`, `FindingRow`, `DetailDrawer`, `TrustGauge`, `AgentLog`, `PolicyLog`, `VibeDiffCard`, `FixPreview`

---

## 4. Backend Changes

### 4.1 `sdg/frontend/app.py`
- Remove `sys.path.insert`
- Add `/api/config` route
- `/api/scan` validates path (must be subdirectory of allowed root), runs orchestrator in thread, returns JSON
- Auto-approve comes from form toggle, not hardcoded
- Add background-task support for long scans

### 4.2 `sdg/policy_engine/semantic.py`
- Fail-closed: `except Exception` returns `(False, f"Gate error: {e}")`
- Use JSON-mode / structured output when possible

### 4.3 `sdg/policy_engine/structural.py`
- `required_approval` returns `("approval_required", reason)` instead of `(False, ...)`
- Orchestrator interprets this state and routes to HITL

### 4.4 `sdg/mcp_servers/server_semgrep.py`
- Read files recursively (excluding skip dirs)
- Pass file content to `scan_with_patterns(file_path, content)`
- Return structured findings list

### 4.5 `sdg/mcp_servers/client.py`
- Use `sys.executable` instead of `"python"`

### 4.6 `sdg/models.py`
- `ScanReport.passed()` fails only on CRITICAL

### 4.7 `sdg/sandbox/executor.py`
- Add explicit timeout, cwd restriction, no-shell enforcement
- Rename class or add warnings that it is subprocess isolation, not kernel-level sandbox

### 4.8 `sdg/cli.py`
- Align role/environment choices with config.yaml
- Deserialize findings for green-team properly

### 4.9 `sdg/evaluation/judge.py`
- Use OpenRouter JSON mode / response_format
- Robust parsing with fallback

### 4.10 Configuration
- Add `reviewer` role and `ci` environment to `config.yaml`
- Add `.gitignore` with `.env`, `.venv`, `__pycache__`, etc.

---

## 5. Deployment & Security

### Dockerfile
```dockerfile
FROM python:3.14-slim
WORKDIR /app
RUN groupadd -r sdg && useradd -r -g sdg sdg
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sdg/ ./sdg/
USER sdg
EXPOSE 8000
HEALTHCHECK CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"
CMD ["python3", "-m", "uvicorn", "sdg.frontend.app:app", "--host", "0.0.0.0", "--port", "8000"]
```

### `.dockerignore`
```
.env
.venv
__pycache__
.pytest_cache
.git
.gitignore
Dockerfile
docker-compose.yml
*.md
tests/
```

### docker-compose.yml
- Use `.env` file injection
- No host volume mount for production
- Healthcheck

---

## 6. Testing

- Add frontend route tests (`/`, `/api/health`, `/api/scan`, `/api/scan/red-team`)
- Add MCP server `call_tool` integration tests
- Add policy engine tests for approval-required flow
- Add semantic gate fail-closed test
- Add context hygiene recursive sanitization test
- Keep all existing 65 tests green

---

## 7. Out of Scope (YAGNI)

- Real kernel-level sandbox (gVisor) — document as future enhancement
- Full OSV/Safety API integration — keep hardcoded CVE list but improve parsing
- A2A agent card / registry
- AP2/UCP payment protocols
- Online evaluation pipeline

---

## 8. Success Criteria

1. Dashboard renders correctly, no XSS, works without internet CDN
2. Full scan from UI returns correct JSON and displays findings
3. HITL gate works when auto-approve is off
4. All 65+ tests pass (including new tests)
5. No hardcoded secrets in repo
6. Docker image builds and runs without root
7. MCP semgrep server actually scans files
8. Code aligns with documented Agent Skills, MCP, 7-pillar, evaluation, and A2UI concepts
