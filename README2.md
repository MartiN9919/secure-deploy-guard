# Secure Deploy Guard (SDG)

AI-agent-powered pre-deployment security scanner using MCP.

## Purpose

Automated security gatekeeper for code, dependencies, and infrastructure configs before production deployment.

## Features

- **SAST**: SQLi, XSS, command injection, secrets, path traversal, SSRF, deserialization, buffer overflow
- **SCA**: CVE detection in `requirements.txt` with NVD/MITRE/OSV enrichment
- **Config**: Dockerfile, docker-compose, Kubernetes checks
- **Secrets**: AWS keys, API keys, passwords, tokens, SSH keys, JWTs
- **Red Team**: adversarial pattern scanning
- **Blue Team**: anomaly detection
- **Green Team**: auto-fix suggestions
- **Policy Engine**: structural role/environment gates + LLM semantic checks
- **HITL**: human approval for high-risk scans
- **Trust Score**: 1.0-0.0 risk metric
- **LLM Judge**: OpenRouter/Gemini evaluation
- **SBOM**: CycloneDX 1.5 JSON output
- **CI Gating**: `--fail-on severity` with exit codes 0/1/2
- **False Positives**: `# sdg-ignore: rule-id` + `.sdg-ignore` baseline

## Architecture

OrchestratorAgent runs SAST, SCA, Config, Secrets agents via MCP servers. Results pass through StructuralGate, SemanticGate, TrustScoreCalculator, BlueTeam, HITL, LLMJudge, and ReportGenerator.

## Stack

Python 3.14, OpenRouter/Gemini 2.5 Flash Lite, MCP SDK, FastAPI, Bandit, httpx, pytest.

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # Add OPENROUTER_API_KEY
```

## Usage

```bash
python -m sdg.cli scan . --auto-approve
python -m sdg.cli scan . --auto-approve --full
python -m sdg.cli scan . --fail-on critical
python -m sdg.cli scan . --sbom --sbom-output bom.json
python -m sdg.cli red-team .
python -m sdg.cve_intelligence.cli CVE-2023-46695
```

## Docker

```bash
docker build -t secure-deploy-guard .
docker run --rm -e OPENROUTER_API_KEY=$KEY -v "$(pwd):/workspace:ro" secure-deploy-guard python -m sdg.cli scan /workspace --auto-approve --fail-on critical
```

Exit codes: `0` passed, `1` threshold exceeded, `2` error.

MIT
