from __future__ import annotations
from typing import Any


class ApprovalRequiredError(Exception):
    """Raised when an action requires human approval before proceeding."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class StructuralGate:
    def __init__(self, config: dict[str, Any]):
        self.config = config

    def check_tool_allowed(self, tool_name: str, role: str = "developer", environment: str = "local") -> tuple[bool, str]:
        env = self.config.get("environments", {}).get(environment, {})
        rl = self.config.get("roles", {}).get(role, {})
        if tool_name in env.get("blocked_tools", []):
            return False, f"Blocked in '{environment}'"
        if tool_name in env.get("required_approval", []):
            raise ApprovalRequiredError(f"Requires approval in '{environment}'")
        allowed = rl.get("allowed_tools", [])
        if tool_name in rl.get("except", []):
            return False, f"Excepted for role '{role}'"
        if "*" in allowed or tool_name in allowed:
            return True, ""
        return False, f"Not allowed for role '{role}'"

    def check_action_allowed(self, action: str, role: str = "developer", environment: str = "local") -> tuple[bool, str]:
        return self.check_tool_allowed(action, role, environment)

