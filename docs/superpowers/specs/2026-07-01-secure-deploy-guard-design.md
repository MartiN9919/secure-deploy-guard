# Secure Deploy Guard (SDG) — Design Document

## Vision
Agent-based security system that checks all code before production deploy or GitHub publish.
"Zero Trust for AI-generated code" — no code trusted without full verification.

## Architecture
```
DEVELOPER/CI/CD → ORCHESTRATOR AGENT → parallel sub-agents → POLICY SERVER → SANDBOX → EVALUATION → HITL → REPORT → DECISION
```

## Components

### 1. Orchestrator Agent
- Routes tasks to sub-agents
- Manages DAG orchestration via file message bus
- Session/Memory Bank for state

### 2. Sub-Agents
- **SAST Agent**: Bandit + regex patterns for SQLi, XSS, path traversal, hardcoded secrets, command injection, SSRF
- **SCA Agent**: Dependency vulnerability analysis (requirements.txt parsing, version pinning, known vulnerability DB)
- **Config Agent**: Dockerfile, docker-compose, YAML/K8s security checks

### 3. MCP Servers
- mcp_bandit.py — wraps Bandit scanner
- mcp_semgrep.py — wraps Semgrep (simulated)
- mcp_docker.py — Docker config analyzer

### 4. Policy Engine (Hybrid)
- Structural: Role × Environment gating (YAML-based)
- Semantic: LLM-as-Referee via OpenRouter (Gemini 2.5 Flash Lite)

### 5. Sandbox
- Subprocess isolation (subprocess with restricted permissions)
- Resource limits: CPU, RAM, time, filesystem allowlist

### 6. Evaluation Engine
- LLM-as-Judge: intent satisfaction, code quality
- Trust Score: dynamic scoring based on findings
- Report Generator: CLI output + JSON + Markdown

### 7. HITL (Human-in-the-Loop)
- Vibe Diff: translate code to plain-English summary
- Approval gate for critical operations

### 8. Red/Blue/Green Teams
- Red: adversarial testing patterns (simulated)
- Blue: anomaly detection (tool trajectory, token spend)
- Green: auto-fix via patch generation

## Technology Stack
| Layer | Technology |
|-------|-----------|
| Language | Python 3.14 |
| Agent Framework | Custom ADK-style (OpenRouter LLM) |
| LLM | Gemini 2.5 Flash Lite via OpenRouter |
| SAST | Bandit + custom regex patterns |
| MCP | MCP Python SDK (stdio) |
| Policy | YAML + Python |
| CLI | argparse |
| Reporting | JSON + Markdown + CLI table |

## Implementation Order
1. Project scaffold + CLI entry point
2. SAST Agent (Bandit + regex patterns)
3. MCP Servers (Bandit, Semgrep, Docker)
4. Orchestrator Agent
5. SCA Agent
6. Config Agent
7. Policy Engine
8. Evaluation Engine + Report
9. HITL
10. Red/Blue/Green Teams
11. Tests and integration
