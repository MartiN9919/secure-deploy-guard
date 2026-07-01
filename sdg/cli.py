from __future__ import annotations
import argparse
import sys
import json
from pathlib import Path
from sdg.config import load_config
from sdg.models import ScanTarget
from sdg.adk.orchestrator import OrchestratorAgent
from sdg.red_blue_green.red_team import RedTeam
from sdg.red_blue_green.green_team import GreenTeam


def cmd_scan(args: argparse.Namespace) -> None:
    config = load_config()
    cfg = config.copy()
    if args.auto_approve:
        cfg["auto_approve"] = True
    orchestrator = OrchestratorAgent(cfg)
    target = ScanTarget(path=args.path)
    result = orchestrator.run(
        target,
        role=args.role,
        environment=args.environment,
        run_red_team=args.full,
        run_green_team=args.full,
    )
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"Session: {result.get('session_id', 'N/A')}")
        print(f"Trust Score: {result.get('trust_score', 'N/A')}")
        print(f"Passed: {result.get('passed', False)}")
        if "error" in result:
            print(f"ERROR: {result['error']}", file=sys.stderr)
        summary = result.get("summary", {})
        print(f"Findings: {summary.get('total_findings', 0)}")
        for agent, report in result.get("agent_results", {}).items():
            if hasattr(report, "findings"):
                print(f"  {agent}: {len(report.findings)} findings")
        if result.get("red_team_findings"):
            print(f"  red_team: {len(result['red_team_findings'])} findings")
        if result.get("green_team_fixes"):
            print(f"  green_team: {len(result['green_team_fixes'])} suggestions")
        eval_result = result.get("evaluation", {})
        if eval_result:
            print(f"Judge Score: {eval_result.get('score', 'N/A')}")
            print(f"Quality: {eval_result.get('quality', 'N/A')}")
    if result.get("report_markdown"):
        report_path = Path(args.output) if args.output else Path.cwd() / "sdg-report.md"
        report_path.write_text(result["report_markdown"])
        print(f"Report saved: {report_path}", file=sys.stderr)


def cmd_red_team(args: argparse.Namespace) -> None:
    config = load_config()
    rt = RedTeam(config)
    result = rt.run(args.path)
    print(json.dumps(result, indent=2))


def cmd_green_team(args: argparse.Namespace) -> None:
    from sdg.models import Finding, Severity, ScanCategory
    config = load_config()
    gt = GreenTeam(config)
    if args.findings_file:
        import json as _json
        with open(args.findings_file) as f:
            raw_findings = _json.load(f)
        findings = []
        for f in raw_findings:
            findings.append(Finding(
                severity=Severity(f.get("severity", "low")),
                category=ScanCategory(f.get("category", "code_quality")),
                message=f.get("message", ""),
                file_path=f.get("file_path", f.get("file", "")),
                line_number=f.get("line_number", f.get("line")),
                recommendation=f.get("recommendation"),
            ))
        fixes = gt.auto_fix(findings)
    else:
        print("No findings file provided; run a scan first and pass findings JSON.")
        return
    print(json.dumps(fixes, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure Deploy Guard — pre-deployment security scanner")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Run full security scan pipeline")
    scan_p.add_argument("path", nargs="?", default=".", help="Target path to scan")
    scan_p.add_argument("--role", default="developer", choices=["developer", "admin", "reviewer", "viewer"])
    scan_p.add_argument("--environment", "-e", default="local", choices=["local", "ci", "staging", "production"])
    scan_p.add_argument("--format", "-f", default="text", choices=["text", "json"])
    scan_p.add_argument("--output", "-o", default=None, help="Report output path")
    scan_p.add_argument("--auto-approve", action="store_true", help="Skip human approval")
    scan_p.add_argument("--full", action="store_true", help="Run full pipeline: scan + red-team + green-team fixes automatically")
    scan_p.set_defaults(func=cmd_scan)

    rt_p = sub.add_parser("red-team", help="Run Red Team adversarial scan")
    rt_p.add_argument("path", nargs="?", default=".", help="Target path")
    rt_p.set_defaults(func=cmd_red_team)

    gt_p = sub.add_parser("green-team", help="Auto-fix suggestions from findings")
    gt_p.add_argument("findings_file", help="JSON file with findings")
    gt_p.set_defaults(func=cmd_green_team)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
