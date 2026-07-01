"""Orchestrator Agent — ADK Custom Agent pattern."""
from __future__ import annotations
import asyncio
import json
from typing import Any
from sdg.models import ScanTarget
from sdg.adk.llm_agent import LlmAgent
from sdg.adk.parallel_agent import ParallelAgent
from sdg.policy_engine.structural import ApprovalRequiredError


class OrchestratorAgent:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        from sdg.agents.sast_agent import SASTAgent
        from sdg.agents.sca_agent import SCAAgent
        from sdg.agents.config_agent import ConfigAgent
        from sdg.policy_engine.structural import StructuralGate
        from sdg.policy_engine.semantic import SemanticGate
        from sdg.evaluation.trust_score import TrustScoreCalculator
        from sdg.evaluation.report import ReportGenerator
        from sdg.evaluation.judge import LLMJudge
        from sdg.hitl.approval import ApprovalGate
        from sdg.red_blue_green.blue_team import BlueTeam

        self.sast = SASTAgent(config)
        self.sca = SCAAgent(config)
        self.config_agent = ConfigAgent(config)
        self.policy_structural = StructuralGate(config)
        self.policy_semantic = SemanticGate(config)
        self.trust_calc = TrustScoreCalculator()
        self.reporter = ReportGenerator()
        self.judge = LLMJudge(config)
        self.approval = ApprovalGate(config)
        self.blue_team = BlueTeam()

        # ADK-style LLM agent for orchestration reasoning
        self.llm_agent = LlmAgent(
            name="orchestrator",
            config=config,
            instructions="You are a security orchestration agent. Route requests to security scanning sub-agents."
        )

    def run(self, target: ScanTarget, role: str = "developer", environment: str = "local", run_red_team: bool = False, run_green_team: bool = False) -> dict:
        from sdg.red_blue_green.red_team import RedTeam
        from sdg.red_blue_green.green_team import GreenTeam
        from sdg.orchestrator.session import Session
        session = Session(target, self.config)

        # Structural policy check
        approval_required = False
        try:
            allowed, reason = self.policy_structural.check_action_allowed("scan", role, environment)
        except ApprovalRequiredError as exc:
            allowed, reason, approval_required = True, "", True
        if not allowed:
            return {"error": f"Scan blocked: {reason}", "session_id": session.session_id}

        # Run agents sequentially (simulated parallel)
        agents = {"sast": self.sast, "sca": self.sca, "config_agent": self.config_agent}
        for name, agent in agents.items():
            try:
                report = agent.execute(target)
                session.add_result(name, report)
            except Exception as e:
                session.add_result(name, type('obj', (object,), {'findings': []})())

        # Semantic policy check on critical findings
        critical_findings = [f for f in session.get_all_findings() if hasattr(f, 'severity') and f.severity.value == "critical"]
        if critical_findings:
            action_desc = f"Found {len(critical_findings)} critical vulnerabilities in {target.path}"
            allowed, reason = self.policy_semantic.check_action(action_desc)
            if not allowed:
                return {"error": f"Semantic policy violation: {reason}", "session_id": session.session_id}

        # Trust score
        session.trust_score = self.trust_calc.calculate(session.get_all_findings())

        # Blue Team anomaly check
        anomaly = self.blue_team.check(session)
        if anomaly:
            return {"error": f"Anomaly detected: {anomaly}", "session_id": session.session_id}

        # HITL approval if needed
        needs_approval = approval_required or session.trust_score < 0.7 or bool(critical_findings)
        if needs_approval:
            session.approved = self.approval.request(session)
            if not session.approved:
                return {"error": "Human approval denied", "session_id": session.session_id}

        # Red Team adversarial scan (optional full pipeline)
        red_team_findings: list[dict] = []
        if run_red_team:
            try:
                rt = RedTeam(self.config)
                rt_result = rt.run(target.path)
                red_team_findings = rt_result.get("findings", [])
            except Exception:
                red_team_findings = []

        # Green Team auto-fix suggestions (optional full pipeline)
        green_team_fixes: list[dict] = []
        if run_green_team:
            try:
                gt = GreenTeam(self.config)
                fixable = [f for f in session.get_all_findings() if f.severity.value in ("critical", "high")]
                green_team_fixes = gt.auto_fix(fixable)
            except Exception:
                green_team_fixes = []

        # LLM Judge evaluation
        eval_result = self.judge.evaluate(target, session)

        # Report
        report_data = self.reporter.generate(session)
        report_markdown = self.reporter.to_markdown(session)

        result = {
            "session_id": session.session_id,
            "trust_score": session.trust_score,
            "summary": session.summary(),
            "evaluation": eval_result,
            "report": report_data,
            "report_markdown": report_markdown,
            "passed": session.trust_score >= 0.5 and not critical_findings,
            "red_team_findings": red_team_findings,
            "green_team_fixes": green_team_fixes,
        }
        return result
