import json
import os
import re
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent


server = Server("docker-scanner")


DOCKERFILE_RULES = [
    {
        "id": "DOCKER-001",
        "title": "Missing USER directive",
        "description": "Dockerfile does not specify a USER. Container will run as root.",
        "severity": "high",
        "check": lambda lines: not any(re.match(r"^\s*USER\s", line) for line in lines),
    },
    {
        "id": "DOCKER-002",
        "title": "Missing HEALTHCHECK",
        "description": "Dockerfile does not include a HEALTHCHECK instruction.",
        "severity": "medium",
        "check": lambda lines: not any(re.match(r"^\s*HEALTHCHECK\s", line) for line in lines),
    },
    {
        "id": "DOCKER-003",
        "title": "Use of :latest tag",
        "description": "Using the :latest tag for a base image can lead to unpredictable builds.",
        "severity": "medium",
        "check": lambda lines: any(re.match(r"^\s*FROM\s+\S+:\s*latest\s*$", line) for line in lines),
    },
    {
        "id": "DOCKER-004",
        "title": "Secrets in ENV",
        "description": "ENV instruction may contain sensitive information like passwords or tokens.",
        "severity": "critical",
        "check": lambda lines: any(
            re.match(r"^\s*ENV\s+.*(?:password|passwd|secret|token|api[_-]?key|aws[_-]?access)", line, re.IGNORECASE)
            for line in lines
        ),
    },
    {
        "id": "DOCKER-005",
        "title": "Privileged mode",
        "description": "Container running in privileged mode has elevated host access.",
        "severity": "critical",
        "check": lambda lines: any(
            re.match(r"^\s*(?:--privileged|privileged\s*:\s*true)", line, re.IGNORECASE)
            for line in lines
        ),
    },
    {
        "id": "DOCKER-006",
        "title": "Use of ADD instead of COPY",
        "description": "ADD has extra features like auto-extraction. Prefer COPY for clarity.",
        "severity": "low",
        "check": lambda lines: any(re.match(r"^\s*ADD\s", line) for line in lines),
    },
    {
        "id": "DOCKER-007",
        "title": "Exposed port without EXPOSE",
        "description": "Port mapping in docker-compose without EXPOSE in Dockerfile.",
        "severity": "low",
        "check": lambda lines: False,
    },
]

COMPOSE_RULES = [
    {
        "id": "COMPOSE-001",
        "title": "Privileged mode in docker-compose",
        "description": "Service runs in privileged mode.",
        "severity": "critical",
        "pattern": r"privileged\s*:\s*true",
    },
    {
        "id": "COMPOSE-002",
        "title": "Port binding to all interfaces",
        "description": "Port exposed to 0.0.0.0 (default). Consider restricting to specific interfaces.",
        "severity": "medium",
        "pattern": r'ports\s*:\s*[\s\S]*?(?:\d+:\d+|"\d+:\d+")',
    },
    {
        "id": "COMPOSE-003",
        "title": "Missing restart policy",
        "description": "Service does not specify a restart policy.",
        "severity": "low",
        "pattern": None,
    },
]


def scan_dockerfile(path: str) -> list[dict]:
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.splitlines()
    except Exception as e:
        return [{"id": "ERROR", "severity": "high", "title": "Read error", "file": path, "detail": str(e)}]

    for rule in DOCKERFILE_RULES:
        if rule["check"](lines):
            findings.append({
                "id": rule["id"],
                "severity": rule["severity"],
                "title": rule["title"],
                "description": rule["description"],
                "file": path,
            })

    return findings


def scan_compose(path: str) -> list[dict]:
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        return [{"id": "ERROR", "severity": "high", "title": "Read error", "file": path, "detail": str(e)}]

    for rule in COMPOSE_RULES:
        if rule["pattern"]:
            if re.search(rule["pattern"], content, re.IGNORECASE):
                findings.append({
                    "id": rule["id"],
                    "severity": rule["severity"],
                    "title": rule["title"],
                    "description": rule.get("description", ""),
                    "file": path,
                })
        else:
            findings.append({
                "id": rule["id"],
                "severity": rule["severity"],
                "title": rule["title"],
                "description": rule.get("description", ""),
                "file": path,
            })

    return findings


def find_docker_files(path: str) -> list[tuple[str, str]]:
    docker_files = []

    if os.path.isfile(path):
        basename = os.path.basename(path).lower()
        if basename == "dockerfile":
            docker_files.append(("dockerfile", path))
        elif basename in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            docker_files.append(("compose", path))
        return docker_files

    for root, _, files in os.walk(path):
        for f in files:
            fl = f.lower()
            full = os.path.join(root, f)
            if fl == "dockerfile":
                docker_files.append(("dockerfile", full))
            elif fl in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
                docker_files.append(("compose", full))

    return docker_files


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="scan_dockerfile",
            description="Scan Dockerfiles and docker-compose files for security issues",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to Dockerfile, docker-compose file, or directory to scan",
                    },
                },
                "required": ["path"],
            },
        )
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name != "scan_dockerfile":
        raise ValueError(f"Unknown tool: {name}")

    path = arguments["path"]

    if not os.path.exists(path):
        return [TextContent(type="text", text=json.dumps({"error": f"Path not found: {path}"}, indent=2))]

    docker_files = find_docker_files(path)
    all_findings = []

    for filetype, filepath in docker_files:
        if filetype == "dockerfile":
            findings = scan_dockerfile(filepath)
        else:
            findings = scan_compose(filepath)

        for f in findings:
            f["file_type"] = filetype
        all_findings.extend(findings)

    if not all_findings:
        all_findings.append({"message": "No issues found"})

    return [TextContent(type="text", text=json.dumps(all_findings, indent=2))]


async def main():
    async with stdio_server() as (read, write):
        init_options = server.create_initialization_options()
        await server.run(read, write, init_options)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
