# Secure Deploy Guard (SDG)

**Secure Deploy Guard (SDG)** is an AI-agent-powered, pre-deployment security scanner built around the Model Context Protocol (MCP).

SDG automatically inspects source code, dependencies, and infrastructure configurations for security vulnerabilities before they reach production. An orchestrator dispatches specialized agents; each agent invokes dedicated MCP servers. Findings flow through a policy engine, Human-in-the-Loop (HITL) approval, and an LLM judge. The result is a deterministic deploy/no-deploy signal with actionable reports.

---

## Table of Contents

1. [Project Purpose](#1-project-purpose)
2. [What SDG Scans](#2-what-sdg-scans)
3. [Technology Stack](#3-technology-stack)
4. [Architecture](#4-architecture)
5. [How the AI Agents Work](#5-how-the-ai-agents-work)
6. [MCP Servers](#6-mcp-servers)
7. [Policy Engine](#7-policy-engine)
8. [Trust Score, Judge, and Reports](#8-trust-score-judge-and-reports)
9. [Installation and Configuration](#9-installation-and-configuration)
10. [Usage](#10-usage)
11. [Docker Deployment](#11-docker-deployment)
12. [PyCharm Setup](#12-pycharm-setup)
13. [Project Structure](#13-project-structure)
14. [Configuration Reference](#14-configuration-reference)
15. [Troubleshooting](#15-troubleshooting)
16. [License](#16-license)

---

## 1. Project Purpose

Modern development—especially vibe coding and AI-assisted code generation—produces code very quickly. SDG exists to make sure that speed does not come at the cost of security. It acts as an automated gatekeeper that evaluates a project before deployment and returns a clear verdict.

### Key Goals

- Detect common vulnerabilities in source code before they are deployed.
- Identify vulnerable dependencies through CVE intelligence.
- Flag insecure Docker, docker-compose, and Kubernetes configurations.
- Block or require approval for high-risk actions based on role and environment.
- Provide LLM-based semantic analysis of critical findings.
- Offer adversarial scanning (Red Team), anomaly detection (Blue Team), and suggested fixes (Green Team).
- Generate human-readable Markdown, JSON, and web dashboard reports.

### Target Audience

- Developers checking code before a commit or pull request.
- DevOps engineers integrating security gates into CI/CD.
- Security engineers who need a lightweight pre-deployment scanner.
- Teams practicing agentic engineering and vibe coding who need guardrails.

---

## 2. What SDG Scans

| Scan Type | Files / Inputs | Examples of Detected Issues |
|---|---|---|
| **SAST** | `.py`, `.js`, `.c`, `.cpp`, `.cs`, `.java`, `.go`, `.rb` | SQL injection, XSS, command injection, hardcoded secrets, path traversal, SSRF, insecure deserialization, buffer overflow |
| **SCA** | `requirements.txt` | Known CVEs in pinned dependencies; enriched with NVD, MITRE, and OSV data |
| **Config** | `Dockerfile*`, `docker-compose*.yml`, `*.yaml`/`*.yml` (K8s) | Missing `USER`, missing `HEALTHCHECK`, `:latest` tag, secrets in `ENV`, privileged containers, missing resource limits, `runAsNonRoot` missing |
| **Secrets** | All text files | Hardcoded AWS keys, API keys, passwords, tokens, SSH private keys, JWTs |
| **Red Team** | `.py`, `.js`, `.html`, `.md`, `.txt`, `.yaml`, `.yml` | Instruction injection, hidden commands, zero-width characters |
| **Blue Team** | Session-level metrics | Anomaly spikes, unexpected agent counts, unusual critical finding ratios |
| **Green Team** | Critical / high findings | Auto-fix suggestions for SQLi, command injection, hardcoded secrets |

Additional outputs:

| Output | Description |
|---|---|
| **SBOM** | CycloneDX 1.5 JSON generated from `requirements.txt` |
| **Exit codes** | `0` = passed, `1` = severity threshold exceeded, `2` = error |
| **Ignore list** | Inline `# sdg-ignore: rule-id` comments or `.sdg-ignore` baseline file |

---

## 3. Technology Stack

| Component | Implementation |
|---|---|
| **Agent framework** | Custom ADK-style (`OrchestratorAgent`, `LlmAgent`, `BaseAgent`) |
| **LLM provider** | OpenRouter (Gemini 2.5 Flash Lite) |
| **SAST engines** | Bandit + built-in regex patterns |
| **SCA engine** | `requirements.txt` parser + CVE Intelligence Gathering |
| **Config scanner** | MCP Docker Scanner |
| **Secrets scanner** | MCP Secret Detector |
| **MCP transport** | MCP Python SDK 1.28+ over stdio |
| **Policy engine** | YAML configuration + Python (`StructuralGate`, `SemanticGate`) |
| **HITL** | CLI approval gate with UTF-8 / Cyrillic support |
| **Reports** | JSON, Markdown, CycloneDX SBOM, CLI table, web dashboard |
| **Web UI** | FastAPI 0.138 + Starlette 1.3 + Jinja2 + Uvicorn 0.49 |
| **HTTP client** | httpx |
| **Testing** | pytest 9.1 |
| **Python version** | 3.14+ |

---

## 4. Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  User / CI / Web UI / Python API / External MCP client              │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  OrchestratorAgent                                                  │
│  Central controller: runs agents, applies policies, HITL, judge,    │
│  and report generation                                              │
└──────┬────────┬────────┬────────┬────────┬────────┬─────────────────┘
       │        │        │        │        │        │
       ▼        ▼        ▼        ▼        ▼        ▼
   ┌──────┐ ┌──────┐ ┌──────┐ ┌───────┐ ┌───────┐ ┌─────────┐
    │ SAST │ │ SCA  │ │Config│ │Secrets│ │Structural│ │Semantic│ │ Blue   │
    │Agent │ │Agent │ │Agent │ │Agent │ │ Gate   │ │ Gate   │ │ Team   │
    └──┬───┘ └──┬───┘ └──┬───┘ └───┬───┘ └────┬────┘ └────┬────┘ └───┬────┘
       │        │        │         │          │           │          │
       ▼        ▼        ▼         ▼          │           │          ▼
   Bandit    CVE      Docker   Secret      roles +      LLM      anomaly
   MCP       API      MCP      MCP         env rules   check     detection
   Semgrep
   MCP
       │        │        │         │          │           │
       └────────┴────────┴─────────┴──────────┴───────────┘

                              │
                              ▼
                    ┌─────────────────────┐
                    │  HITL Approval      │
                    │  (human approval)   │
                    └──────────┬──────────┘
                               ▼
                    ┌─────────────────────┐
                    │  LLM Judge          │
                    │  (OpenRouter/Gemini)│
                    └──────────┬──────────┘
                               ▼
                    ┌─────────────────────┐
                    │  Report Generator   │
                    │  Markdown / JSON    │
                    └─────────────────────┘
```

### Execution Flow

1. `OrchestratorAgent.run(target, role, environment)` receives a target path, role, and environment.
2. `StructuralGate` evaluates whether the scan action is allowed for the role/environment combination. If approval is required, it routes to HITL. If forbidden, it blocks immediately.
3. `SASTAgent` asynchronously calls the MCP Bandit server and the MCP Semgrep server.
4. `SCAAgent` parses `requirements.txt`, compares versions against a known-vulnerability database, and enriches findings via `CVEIntelligenceGatherer`.
5. `ConfigAgent` calls the MCP Docker Scanner for Dockerfile and docker-compose checks.
6. `SecretsAgent` calls the MCP Secret Detector for hardcoded credentials.
7. Ignore filtering is applied via inline `# sdg-ignore:` comments or a `.sdg-ignore` baseline file.
8. `SemanticGate` sends critical findings to the LLM for semantic policy evaluation.
9. `TrustScoreCalculator` computes a score from the collected findings.
10. `BlueTeam` checks the session for anomalies.
11. `ApprovalGate` requests human approval if the trust score is low, critical findings exist, or the policy requires it.
12. `LLMJudge` evaluates scan quality on a 1-5 scale.
13. `ReportGenerator` produces Markdown, JSON, and CycloneDX SBOM reports.

---

## 5. How the AI Agents Work

SDG uses a hybrid agent model: deterministic scanning agents perform the bulk of the work, while LLM-based agents handle evaluation and semantic reasoning.

### 5.1 OrchestratorAgent

**File:** `sdg/adk/orchestrator.py`

The central agent. It owns the scan lifecycle, manages the shared `Session`, dispatches sub-agents, applies gates, handles HITL, invokes the LLM judge, and produces the final report.

### 5.2 SASTAgent

**File:** `sdg/agents/sast_agent.py`

Performs static application security testing by invoking two MCP servers:
- `MCPClient("sdg/mcp_servers/server_bandit.py")` for Bandit-based Python scanning.
- `MCPClient("sdg/mcp_servers/server_semgrep.py")` for regex-based pattern scanning.

Both results are parsed into a unified `Finding` model and added to the report.

### 5.3 SCAAgent

**File:** `sdg/agents/sca_agent.py`

Performs software composition analysis:
- Reads `requirements.txt`.
- Matches package versions against a built-in vulnerability database.
- Enriches CVE data via NVD, MITRE, and OSV using `CVEIntelligenceGatherer`.

### 5.4 ConfigAgent

**File:** `sdg/agents/config_agent.py`

Checks infrastructure configurations by calling:
- `MCPClient("sdg/mcp_servers/server_docker.py")` for Dockerfile and docker-compose scanning.

### 5.5 SecretsAgent

**File:** `sdg/agents/secrets_agent.py`

Detects hardcoded secrets and credentials by calling:
- `MCPClient("sdg/mcp_servers/server_secrets.py")` for secret pattern scanning.

This agent is enabled by default in `config.yaml`.

### 5.6 LlmAgent

**File:** `sdg/adk/llm_agent.py`

A reusable LLM agent wrapper. It builds prompts from instructions, available tools, and user input, then calls the OpenRouter API through `sdg/utils/llm.py`.

### 5.6 LLMJudge

**File:** `sdg/evaluation/judge.py`

Sends a summary of findings to the LLM and asks for a structured evaluation:
- `score` (1-5)
- `quality` (e.g., "very poor", "good")
- `recommendation`

### 5.7 SemanticGate

**File:** `sdg/policy_engine/semantic.py`

Sends descriptions of critical findings to the LLM and asks whether they violate security policies (PII, destructive operations, etc.). Operates fail-closed: if the LLM call fails, the action is blocked. Uses batching to reduce the number of LLM calls when multiple critical findings exist.

### 5.8 Red, Blue, and Green Teams

| Team | File | Purpose |
|---|---|---|
| **Red Team** | `sdg/red_blue_green/red_team.py` | Adversarial pattern scanning (instruction injection, hidden commands, zero-width characters) |
| **Blue Team** | `sdg/red_blue_green/blue_team.py` | Anomaly and spike detection over the scan session |
| **Green Team** | `sdg/red_blue_green/green_team.py` | Template-based auto-fix suggestions for common vulnerabilities |

---

## 6. MCP Servers

**Directory:** `sdg/mcp_servers/`

MCP servers are standalone processes that expose tools via the Model Context Protocol over stdio. This makes them reusable by any MCP-compatible orchestrator, not just SDG.

| Server | Tool | Description |
|---|---|---|
| `server_bandit.py` | `bandit_scan` | Runs Bandit CLI and returns JSON results |
| `server_semgrep.py` | `semgrep_scan` | Runs regex-based SAST using `sdg/utils/patterns` |
| `server_docker.py` | `scan_dockerfile` | Scans Dockerfiles and docker-compose files |
| `server_secrets.py` | `scan_secrets` | Detects secrets via regex patterns |
| `client.py` | — | `MCPClient` wrapper for stdio MCP connections |

### MCPClient

**File:** `sdg/mcp_servers/client.py`

Features:
- Uses `sys.executable` instead of a hardcoded `python` binary.
- Adds the project root to `PYTHONPATH` so servers can import `sdg` modules.
- Adds `.venv/bin` to `PATH` so tools like `bandit` are discoverable.

---

## 7. Policy Engine

**Directory:** `sdg/policy_engine/`

Policies are defined in `sdg/config.yaml`.

### StructuralGate

**File:** `sdg/policy_engine/structural.py`

Fast binary checks based on role and environment:
- Is the tool allowed for this role?
- Is the tool blocked in this environment?
- Does this action require approval?

### SemanticGate

**File:** `sdg/policy_engine/semantic.py`

LLM-based check that evaluates the intent and content of critical findings for PII, destructive operations, or policy violations. Uses `batch_query_llm` from `sdg/utils/llm.py` to group multiple findings into one LLM call.

### Supporting Modules

| Module | Purpose |
|---|---|
| `pii_mask.py` | Masks emails, API keys, IPs, SSNs in text |
| `context_hygiene.py` | Resolves `[[VAR]]` placeholders and sanitizes tool arguments recursively |

---

## 8. Trust Score, Judge, Reports, and SBOM

### Trust Score

**File:** `sdg/evaluation/trust_score.py`

The trust score starts at 1.0 and decreases based on finding severity:

| Severity | Deduction |
|---|---|
| CRITICAL | -0.30 |
| HIGH | -0.15 |
| MEDIUM | -0.05 |
| LOW | -0.01 |

A scan passes only if `trust_score >= 0.5` and there are no critical findings.

### LLM Judge

See [LLMJudge](#56-llmjudge).

### Reports

**File:** `sdg/evaluation/report.py`

Generated outputs:
- CLI table
- JSON (`--format json`)
- Markdown (`sdg-report.md` or `--output path`)
- CycloneDX 1.5 SBOM JSON (`--sbom`)
- Web dashboard rendered in `sdg/frontend/`

### SBOM Generation

SDG can generate a CycloneDX 1.5 JSON SBOM from `requirements.txt`:

```bash
.venv/bin/python -m sdg.cli scan . --sbom
.venv/bin/python -m sdg.cli scan . --sbom --sbom-output bom.json
```

The SBOM is saved to `sdg-sbom.json` by default or to the path specified by `--sbom-output`.

---

## 9. Installation and Configuration

### 9.1 Requirements

- Python 3.14 or newer
- Linux, macOS, or WSL
- Internet connection (only required for LLM calls and CVE enrichment)

### 9.2 Local Installation

```bash
# Clone or navigate to the project directory
cd /path/to/secure-deploy-guard

# Create a virtual environment
python3 -m venv .venv

# Activate it
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 9.3 Environment Variables

Copy the example file and add your OpenRouter API key:

```bash
cp .env.example .env
```

Edit `.env`:

```env
OPENROUTER_API_KEY=sk-or-v1-your-key-here
OPENROUTER_MODEL=google/gemini-2.5-flash-lite-preview-09-2025
```

`OPENROUTER_API_KEY` is required only for LLM Judge and SemanticGate. All other scanners work without it.

### 9.4 Verify Installation

```bash
# Run the test suite
.venv/bin/python -m pytest tests/ -v

# Run a quick scan
.venv/bin/python -m sdg.cli scan . --auto-approve
```

---

## 10. Usage

### 10.1 CLI

```bash
# Basic scan: SAST + SCA + Config + Secrets
.venv/bin/python -m sdg.cli scan ./my-project --auto-approve

# Full pipeline: scan + Red Team + Green Team fixes
.venv/bin/python -m sdg.cli scan ./my-project --auto-approve --full

# Scan with role and environment
.venv/bin/python -m sdg.cli scan ./my-project --role admin --environment production

# JSON output
.venv/bin/python -m sdg.cli scan . --format json

# Save Markdown report
.venv/bin/python -m sdg.cli scan . --output report.md

# Generate CycloneDX SBOM
.venv/bin/python -m sdg.cli scan . --sbom --sbom-output bom.json

# CI/CD gating: fail on critical or high findings
.venv/bin/python -m sdg.cli scan . --auto-approve --fail-on critical
.venv/bin/python -m sdg.cli scan . --auto-approve --fail-on high

# Red Team scan only
.venv/bin/python -m sdg.cli red-team ./my-project

# Green Team fixes from findings JSON
.venv/bin/python -m sdg.cli green-team findings.json

# CVE lookup
.venv/bin/python -m sdg.cve_intelligence.cli CVE-2023-46695
```

### Exit Codes

| Exit Code | Meaning |
|---|---|
| `0` | Scan passed (no findings at or above `--fail-on` severity) |
| `1` | Findings at or above `--fail-on` severity were detected |
| `2` | Scan error (blocked by policy, anomaly, HITL denied, etc.) |

### Suppressing False Positives

#### Inline suppression

Add a comment on the same line as the finding:

```python
password = "test123"  # sdg-ignore: hardcoded_secret
api_key = "abc"       # sdg-ignore: hardcoded_secret,api_key
```

Use `# sdg-ignore: *` to suppress all rules on that line.

#### Baseline file

Create `.sdg-ignore` in the project root with a JSON list of finding fingerprints:

```json
[
  "a1b2c3d4e5f67890",
  "0987654321fedcba"
]
```

Fingerprints are generated from file path, line number, category, and snippet. The path is configurable via `ignore_baseline_path` in `config.yaml`.

### 10.2 Web Dashboard

```bash
.venv/bin/python -m uvicorn sdg.frontend.app:app --host 0.0.0.0 --port 8000
```

Open http://localhost:8000 in a browser.

Dashboard features:
- Path, role, and environment selection.
- Auto-approve checkbox to skip HITL.
- Full pipeline checkbox to include Red Team + Green Team.
- Trust Score gauge with pass/fail badge.
- Severity cards (Critical / High / Medium / Low).
- Filterable findings table.
- Agent trajectory and policy log.
- Green Team suggested fixes panel.
- Export to JSON and Markdown.

---

## 11. Docker Deployment

### 11.1 Why Use Docker

Docker provides a clean, reproducible runtime for SDG. It is useful for:
- CI/CD pipelines where you do not want to install Python dependencies on the runner.
- Shared development environments.
- Running the web dashboard without polluting the host system.

### 11.2 Creating the Docker Files

Because Docker files were removed from the repository, recreate them in the project root.

**`Dockerfile`**

```dockerfile
FROM python:3.14-slim

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc git \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m -u 1000 sdg

# Set working directory
WORKDIR /app

# Copy dependency manifest and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY sdg/ ./sdg/
COPY tests/ ./tests/

# Change ownership
RUN chown -R sdg:sdg /app

# Switch to non-root user
USER sdg

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD .venv/bin/python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1

# Default command: web dashboard
CMD ["python", "-m", "uvicorn", "sdg.frontend.app:app", "--host", "0.0.0.0", "--port", "8000"]
```

**`docker-compose.yml`**

```yaml
services:
  sdg:
    build: .
    container_name: secure-deploy-guard
    ports:
      - "8000:8000"
    env_file:
      - .env
    volumes:
      - ./:/app/workspace:ro
    working_dir: /app
    command: ["python", "-m", "uvicorn", "sdg.frontend.app:app", "--host", "0.0.0.0", "--port", "8000"]
```

**`.dockerignore`**

```text
.env
.venv
.git
.pytest_cache
__pycache__
*.pyc
*.pyo
*.pyd
sdg-report.md
report.md
sdg-sbom.json
```

### 11.3 Building and Running

```bash
# Build the image
docker build -t secure-deploy-guard .

# Run the web dashboard
 docker run -d \
  --name sdg \
  -p 8000:8000 \
  --env-file .env \
  secure-deploy-guard

# Or use docker-compose
docker-compose up --build -d
```

Access the dashboard at http://localhost:8000.

### 11.4 Running a Scan Inside Docker

```bash
# Run a one-off scan inside the container
docker run --rm \
  --env-file .env \
  -v "$(pwd)/my-project:/workspace:ro" \
  secure-deploy-guard \
  python -m sdg.cli scan /workspace --auto-approve --full
```

### 11.5 Docker in CI/CD

```yaml
# Example GitHub Actions workflow
name: SDG Security Scan
on: [push, pull_request]
jobs:
  sdg-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build SDG image
        run: docker build -t sdg .
      - name: Run SDG scan
        run: |
           docker run --rm \
             -e OPENROUTER_API_KEY=${{ secrets.OPENROUTER_API_KEY }} \
             -v "$(pwd):/workspace:ro" \
             sdg \
             python -m sdg.cli scan /workspace --auto-approve --full --fail-on critical

```

---

## 12. PyCharm Setup

### 12.1 Open the Project

1. Open PyCharm.
2. `File → Open` and select the project folder.
3. PyCharm will detect Python 3.14 and the project structure.

### 12.2 Configure Interpreter

1. `File → Settings → Project → Python Interpreter`.
2. Select `.venv/bin/python`.
3. Install dependencies if needed:

```bash
pip install -r requirements.txt
```

### 12.3 Run CLI from PyCharm

1. `Run → Edit Configurations → + → Python`.
2. **Module name:** `sdg.cli`
3. **Parameters:** `scan . --auto-approve --full`
4. **Working directory:** project root

### 12.4 Run Web Dashboard from PyCharm

1. `Run → Edit Configurations → + → Python`.
2. **Module name:** `uvicorn`
3. **Parameters:** `sdg.frontend.app:app --host 0.0.0.0 --port 8000 --reload`
4. **Working directory:** project root

---

## 13. Project Structure

```
.
├── sdg/                                # Main application package
│   ├── adk/                            # ADK-style agents
│   │   ├── orchestrator.py             # OrchestratorAgent
│   │   ├── llm_agent.py                # LlmAgent wrapper
│   │   └── parallel_agent.py           # Parallel execution helper
│   ├── agents/                         # Scanning agents
│   │   ├── base.py                     # BaseAgent abstract class
│   │   ├── sast_agent.py               # SAST via MCP Bandit + Semgrep
│   │   ├── sca_agent.py                # SCA + CVE intelligence
│   │   ├── config_agent.py             # Config via MCP Docker
│   │   └── secrets_agent.py            # Secrets via MCP Secret Detector
│   ├── cve_intelligence/               # CVE enrichment (NVD, MITRE, OSV)
│   │   ├── models.py
│   │   ├── sources.py
│   │   ├── gatherer.py
│   │   └── cli.py
│   ├── evaluation/                     # Scoring and reporting
│   │   ├── judge.py                    # LLM Judge
│   │   ├── trust_score.py              # Trust Score calculator
│   │   └── report.py                   # Report generator
│   ├── frontend/                       # FastAPI web dashboard
│   │   ├── app.py
│   │   ├── templates/
│   │   │   └── dashboard.html
│   │   └── static/
│   │       ├── bootstrap.min.css
│   │       ├── bootstrap.bundle.min.js
│   │       ├── sdg-dashboard.css
│   │       └── sdg-dashboard.js
│   ├── hitl/                           # Human-in-the-Loop
│   │   ├── approval.py                 # Approval gate
│   │   └── vibe_diff.py                # Plain-English summary
│   ├── mcp_servers/                    # MCP servers and client
│   │   ├── client.py                   # MCPClient
│   │   ├── server_bandit.py
│   │   ├── server_semgrep.py
│   │   ├── server_docker.py
│   │   └── server_secrets.py
│   ├── orchestrator/
│   │   └── session.py                  # Session / Memory Bank
│   ├── policy_engine/                  # Policy enforcement
│   │   ├── structural.py               # Role × environment gate
│   │   ├── semantic.py                 # LLM semantic gate
│   │   ├── pii_mask.py                 # PII masker
│   │   └── context_hygiene.py          # Argument sanitizer
│   ├── red_blue_green/                 # Security teams
│   │   ├── red_team.py                 # Adversarial scan
│   │   ├── blue_team.py                # Anomaly detection
│   │   └── green_team.py               # Auto-fix suggestions
│   ├── sandbox/
│   │   └── executor.py                 # Subprocess sandbox
│   ├── utils/
│   │   ├── llm.py                      # OpenRouter LLM client + rate limiter
│   │   ├── ignore_manager.py           # False positive suppression
│   │   └── patterns.py                 # Regex SAST patterns
│   ├── config.py                       # Configuration loader
│   ├── config.yaml                     # Default policies and settings
│   └── models.py                       # Finding, ScanTarget, ScanReport
├── tests/                              # pytest test suite
├── .env.example                        # Environment variable template
├── .gitignore
├── requirements.txt                    # Python dependencies
└── README.md                           # This file
```

---

## 14. Configuration Reference

`sdg/config.yaml` contains the default configuration:

```yaml
environments:
  local:
    blocked_tools: []
    required_approval: []
  ci:
    blocked_tools: []
    required_approval: []
  staging:
    blocked_tools:
      - deploy
      - send_email
    required_approval: []
  production:
    blocked_tools:
      - write_file
      - delete_file
      - deploy
    required_approval:
      - deploy
      - database_migration
      - scan

roles:
  viewer:
    allowed_tools:
      - scan
      - read
  developer:
    allowed_tools:
      - "*"
    except:
      - deploy
      - send_email
  reviewer:
    allowed_tools:
      - scan
      - read
      - evaluate
  admin:
    allowed_tools:
      - "*"
    requires_mfa: true

scanning:
  enabled_agents:
    - sast
    - sca
    - config
    - secrets
  severity_threshold: medium
  fail_on: critical
  excluded_dirs:
    - .venv
    - __pycache__
    - .git
    - .pytest_cache
    - node_modules
    - .superpowers
    - .worktrees
    - tests
  excluded_file_patterns:
    - "*.min.js"
    - "*.min.css"

llm_rate_limit_calls_per_minute: 30
llm_rate_limit_calls_per_scan: 10
ignore_baseline_path: .sdg-ignore
```

You can override settings by editing `sdg/config.yaml` or by passing a custom path to `load_config()`.

### LLM Rate Limiting and Cost Controls

SDG includes a token-bucket rate limiter and a per-scan budget for LLM calls. Configure in `config.yaml`:

```yaml
llm_rate_limit_calls_per_minute: 30
llm_rate_limit_calls_per_scan: 10
```

- `llm_rate_limit_calls_per_minute` limits calls to the OpenRouter API within a 60-second window.
- `llm_rate_limit_calls_per_scan` caps the total number of LLM calls for a single scan.

If the limit is exceeded, the SemanticGate and LLMJudge gracefully skip with a message instead of crashing the scan.

---

## 15. Troubleshooting

### `ModuleNotFoundError: No module named 'sdg'`

Run commands from the project root. If using a virtual environment, activate it:

```bash
source .venv/bin/activate
```

### `Judge Score: 3 / judge skipped: no API key`

Create `.env` with a valid `OPENROUTER_API_KEY`.

### `LLM query skipped: rate limit or scan budget exceeded`

Increase the limits in `config.yaml` or reduce the number of findings by fixing critical/high issues.

### Bandit not found inside MCP server

Make sure Bandit is installed in the same environment:

```bash
.venv/bin/bandit --version
```

`MCPClient` automatically adds `.venv/bin` to `PATH`.

### Docker container cannot find `sdg` module

Ensure the Docker image copies the project root into `/app` and that `PYTHONPATH` includes `/app` if needed.

### CVE Intelligence Gathering is slow

Adjust timeout in `config.yaml`:

```yaml
enable_cve_intelligence: true
cve_intelligence_timeout: 5.0
```

Or disable it:

```yaml
enable_cve_intelligence: false
```

---

## 16. License

MIT
