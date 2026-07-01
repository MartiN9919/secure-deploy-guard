from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class MCPClient:
    def __init__(self, server_script: str, server_args: list[str] | None = None):
        self.server_params = StdioServerParameters(
            command="python",
            args=[server_script] + (server_args or []),
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
