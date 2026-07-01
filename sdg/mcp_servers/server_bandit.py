import json
import subprocess
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent


server = Server("bandit-scanner")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="bandit_scan",
            description="Run Bandit security scanner on a Python file or directory",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to Python file or directory to scan",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["low", "medium", "high"],
                        "description": "Minimum severity level to report",
                    },
                },
                "required": ["path"],
            },
        )
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name != "bandit_scan":
        raise ValueError(f"Unknown tool: {name}")

    path = arguments["path"]
    severity = arguments.get("severity", "low")

    try:
        cmd = ["bandit", "-f", "json", "-q", path]
        if severity != "low":
            cmd.extend(["--severity-level", severity.upper()])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if result.returncode in (0, 1):
            try:
                output = json.loads(result.stdout)
                return [TextContent(type="text", text=json.dumps(output, indent=2))]
            except json.JSONDecodeError:
                return [TextContent(type="text", text=result.stdout or result.stderr)]
        else:
            return [TextContent(type="text", text=json.dumps({
                "error": "Bandit scan failed",
                "stderr": result.stderr,
                "stdout": result.stdout,
            }, indent=2))]

    except FileNotFoundError:
        return [TextContent(type="text", text=json.dumps({
            "error": "Bandit is not installed. Install it with: pip install bandit",
        }, indent=2))]
    except subprocess.TimeoutExpired:
        return [TextContent(type="text", text=json.dumps({
            "error": "Bandit scan timed out",
        }, indent=2))]


async def main():
    async with stdio_server() as (read, write):
        init_options = server.create_initialization_options()
        await server.run(read, write, init_options)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
