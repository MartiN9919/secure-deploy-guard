import json
import os
import re
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent


server = Server("secret-detector")


SECRET_PATTERNS: list[dict[str, str]] = [
    {"type": "AWS Access Key", "pattern": r"(?i)AKIA[0-9A-Z]{16}", "severity": "critical"},
    {"type": "AWS Secret Key", "pattern": r"(?i)(?:(?:aws|amazon)[_-]?)?(?:secret|access)[_-]?key\s*[=:]\s*['\"][a-zA-Z0-9/+=]{40}['\"]", "severity": "critical"},
    {"type": "API Key (generic)", "pattern": r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{16,64}['\"]", "severity": "high"},
    {"type": "Password", "pattern": r"(?i)password\s*[=:]\s*['\"][^'\"]{8,}['\"]", "severity": "critical"},
    {"type": "Token (generic)", "pattern": r"(?i)(?:token|bearer|jwt)\s*[=:]\s*['\"][a-zA-Z0-9_\-\.]{20,}['\"]", "severity": "high"},
    {"type": "SSH Private Key", "pattern": r"-----BEGIN\s*(?:RSA|DSA|EC|OPENSSH)\s*PRIVATE\s*KEY-----", "severity": "critical"},
    {"type": "JWT Token", "pattern": r"(?i)eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+", "severity": "high"},
    {"type": "GitHub Token", "pattern": r"(?i)(?:gh[ps]_[a-zA-Z0-9]{36,}|github[_-]?token\s*[=:]\s*['\"][a-zA-Z0-9_\-]+['\"])", "severity": "critical"},
    {"type": "Slack Token", "pattern": r"(?i)xox[abprs]-[a-zA-Z0-9_-]{10,}", "severity": "high"},
    {"type": "Google API Key", "pattern": r"(?i)AIza[0-9A-Za-z_\-]{35}", "severity": "high"},
    {"type": "Heroku API Key", "pattern": r"(?i)heroku[a-z0-9_\-]{20,}", "severity": "high"},
    {"type": "Generic Secret", "pattern": r"(?i)(?:secret|secret_key|api_secret|app_secret|consumer_secret)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]", "severity": "high"},
]


def should_skip_path(filepath: str) -> bool:
    skip_dirs = {
        ".git", "__pycache__", "node_modules", ".venv", "venv", "env",
        ".tox", "dist", "build", ".egg-info", ".mypy_cache", ".pytest_cache",
    }
    parts = filepath.replace(os.sep, "/").split("/")
    return any(part in skip_dirs for part in parts)


def scan_file(filepath: str) -> list[dict]:
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return findings

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("<!--"):
            continue

        for secret_def in SECRET_PATTERNS:
            if re.search(secret_def["pattern"], line):
                findings.append({
                    "file_path": filepath,
                    "line_number": lineno,
                    "secret_type": secret_def["type"],
                    "severity": secret_def["severity"],
                    "line": stripped[:120],
                })
                break

    return findings


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="scan_secrets",
            description="Scan codebase for hardcoded secrets and credentials",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to file or directory to scan",
                    },
                },
                "required": ["path"],
            },
        )
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name != "scan_secrets":
        raise ValueError(f"Unknown tool: {name}")

    path = arguments["path"]

    if not os.path.exists(path):
        return [TextContent(type="text", text=json.dumps({"error": f"Path not found: {path}"}, indent=2))]

    all_findings = []

    if os.path.isfile(path):
        if not should_skip_path(path):
            all_findings.extend(scan_file(path))
    else:
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if not should_skip_path(os.path.join(root, d))]
            for f in files:
                filepath = os.path.join(root, f)
                if should_skip_path(filepath):
                    continue
                all_findings.extend(scan_file(filepath))

    return [TextContent(type="text", text=json.dumps(all_findings, indent=2))]


async def main():
    async with stdio_server() as (read, write):
        init_options = server.create_initialization_options()
        await server.run(read, write, init_options)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
