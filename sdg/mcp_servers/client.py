from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
import os
import sys


class MCPClient:
    def __init__(self, server_script: str, server_args: list[str] | None = None):
        self.server_script = server_script
        cwd = os.getcwd()
        env = os.environ.copy()
        python_path = env.get("PYTHONPATH", "")
        if cwd not in python_path.split(os.pathsep):
            env["PYTHONPATH"] = cwd + (os.pathsep + python_path if python_path else "")
        # Ensure PATH includes the virtual environment so spawned tools like bandit are found.
        venv_bin = os.path.join(cwd, ".venv", "bin")
        if os.path.isdir(venv_bin):
            env["PATH"] = venv_bin + os.pathsep + env.get("PATH", "")
        self.server_params = StdioServerParameters(
            command=sys.executable,
            args=[server_script] + (server_args or []),
            env=env,
        )

    async def list_tools(self) -> list[tuple[str, str]]:
        try:
            async with stdio_client(self.server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    return [(t.name, t.description) for t in tools.tools]
        except Exception as e:
            return [("error", f"Failed to connect or list tools: {e}")]

    async def call_tool(self, tool_name: str, arguments: dict) -> str:
        try:
            async with stdio_client(self.server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool(tool_name, arguments)
                    return result.content[0].text
        except Exception as e:
            return f"Error calling tool '{tool_name}': {e}"
