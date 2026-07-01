import json
import os
from pathlib import Path
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
from sdg.utils.patterns import scan_with_patterns, EXCLUDED_DIRS


server = Server("semgrep-scanner")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="semgrep_scan",
            description="Scan source code for security vulnerabilities using regex patterns",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to file or directory to scan",
                    },
                    "rules": {
                        "type": "string",
                        "enum": ["owasp-top-10", "cwe-top-25", "custom"],
                        "description": "Ruleset to use for scanning",
                    },
                },
                "required": ["path", "rules"],
            },
        )
    ]


def _should_scan(filepath: str) -> bool:
    parts = filepath.replace("\\", "/").split("/")
    return not any(p in EXCLUDED_DIRS for p in parts)


def _find_files(path: str) -> list[str]:
    files = []
    if os.path.isfile(path):
        return [path]
    for root, dirs, filenames in os.walk(path):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for fname in filenames:
            fpath = os.path.join(root, fname)
            if _should_scan(fpath):
                files.append(fpath)
    return files


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name != "semgrep_scan":
        raise ValueError(f"Unknown tool: {name}")

    path = arguments["path"]
    rules = arguments.get("rules", "owasp-top-10")

    if not os.path.exists(path):
        return [TextContent(type="text", text=json.dumps({"error": f"Path not found: {path}"}, indent=2))]

    findings = []
    for fpath in _find_files(path):
        try:
            content = Path(fpath).read_text(encoding="utf-8", errors="ignore")
            findings.extend(scan_with_patterns(fpath, content))
        except Exception:
            continue

    output = [
        {
            "severity": f.severity.value,
            "category": f.category.value,
            "message": f.message,
            "file": f.file_path,
            "line": f.line_number,
            "recommendation": f.recommendation,
        }
        for f in findings
    ]
    return [TextContent(type="text", text=json.dumps(output, indent=2))]


async def main():
    async with stdio_server() as (read, write):
        init_options = server.create_initialization_options()
        await server.run(read, write, init_options)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
