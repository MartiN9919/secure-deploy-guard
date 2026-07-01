from sdg.mcp_servers.server_bandit import server as bandit_server
from sdg.mcp_servers.server_semgrep import server as semgrep_server
from sdg.mcp_servers.server_docker import server as docker_server
from sdg.mcp_servers.server_secrets import server as secrets_server
from sdg.mcp_servers.client import MCPClient


class TestMCPServers:
    def test_bandit_server_name(self):
        assert bandit_server.name == "bandit-scanner"

    def test_semgrep_server_name(self):
        assert semgrep_server.name == "semgrep-scanner"

    def test_docker_server_name(self):
        assert docker_server.name == "docker-scanner"

    def test_secrets_server_name(self):
        assert secrets_server.name == "secret-detector"


class TestMCPClient:
    def test_client_creation(self):
        client = MCPClient("sdg/mcp_servers/server_secrets.py")
        assert client.server_params.command == "python"
        assert "server_secrets.py" in str(client.server_params.args[0])


class TestSemgrepServer:
    def test_semgrep_server_scans_file_content(self):
        import asyncio
        import tempfile
        from pathlib import Path
        from sdg.mcp_servers.server_semgrep import call_tool

        async def _call(tool, args):
            return await call_tool(tool, args)

        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "vuln.py"
            f.write_text("password = 'secret'\n")
            result = asyncio.run(_call("semgrep_scan", {"path": str(tmp), "rules": "owasp-top-10"}))
        assert len(result) == 1
        text = result[0].text
        assert "hardcoded_secret" in text.lower() or "password" in text.lower()


