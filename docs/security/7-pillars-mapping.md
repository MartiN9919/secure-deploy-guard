# Secure Deploy Guard — Mapping to 7-Pillar Agent Security Architecture

This document maps the Secure Deploy Guard project to the 7-pillar security architecture described in *Vibe Coding Agent Security and Evaluation* (Day 4 whitepaper).

## Pillar 1 — Infrastructure & Networking

| Requirement | SDG Implementation |
|---|---|
| Ephemeral sandboxes | `sdg/sandbox/executor.py` provides subprocess isolation with path validation and timeout. Kernel-level sandboxing (gVisor) is out of scope for this prototype. |
| Egress governance | Docker image runs without outbound network requirement; no auto-update calls. |
| Non-root execution | Dockerfile creates `sdg` user and runs container as non-root. |

## Pillar 2 — Data

| Requirement | SDG Implementation |
|---|---|
| Secrets management | `.env` is excluded from git via `.gitignore`; only `.env.example` is committed. |
| PII protection | `sdg/policy_engine/pii_mask.py` masks emails, API keys, IPs, etc. |
| Context hygiene | `sdg/policy_engine/context_hygiene.py` resolves `[[VAR]]` placeholders and sanitizes tool args recursively. |

## Pillar 3 — Model

| Requirement | SDG Implementation |
|---|---|
| System prompt as artifact | Agent skills (`SKILL.md`) and orchestrator instructions are version-controlled markdown files. |
| Semantic attacks | `sdg/policy_engine/semantic.py` evaluates critical findings for PII/policy violations via LLM. |

## Pillar 4 — Application & Runtime

| Requirement | SDG Implementation |
|---|---|
| Lifecycle hooks | Policy gates run before scan execution and after critical findings are collected. |
| Agent Gateway | `StructuralGate` + `SemanticGate` act as policy server for scanner actions. |
| Tool validation | MCP servers validate paths and return structured results. |

## Pillar 5 — Identity & Access Management

| Requirement | SDG Implementation |
|---|---|
| Role-based access | `config.yaml` defines roles (`viewer`, `developer`, `reviewer`, `admin`) and allowed tools per environment. |
| Approval workflows | `ApprovalRequiredError` triggers HITL approval gate instead of silently blocking. |

## Pillar 6 — Observability & Security Ops

| Requirement | SDG Implementation |
|---|---|
| Red Team | `sdg/red_blue_green/red_team.py` scans for adversarial patterns. |
| Blue Team | `sdg/red_blue_green/blue_team.py` detects anomaly spikes. |
| Green Team | `sdg/red_blue_green/green_team.py` suggests auto-fixes. |
| Audit trail | Scan sessions carry UUIDs; reports include timestamps and agent trajectory. |

## Pillar 7 — Governance

| Requirement | SDG Implementation |
|---|---|
| Risk-stratified attestation | Trust Score provides quantitative pass/fail signal per scan. |
| Human review | HITL gate requires explicit approval for high-risk scans. |
| Spec-driven | Design documents live in `docs/superpowers/specs/`; agent skills follow canonical format. |

## Gaps & Future Work

- True kernel-level sandboxing via gVisor or containers.
- SPIFFE/SPIRE agent identities and JIT tokens.
- Immutable signed audit log.
- EU AI Act compliance documentation.
