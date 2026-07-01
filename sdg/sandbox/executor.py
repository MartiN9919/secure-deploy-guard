from __future__ import annotations
import subprocess
from pathlib import Path
from typing import Any


class SandboxExecutor:
    """Ephemeral subprocess isolation with path and command restrictions.

    This is **subprocess isolation**, not a kernel-level sandbox. For true
    kernel-level isolation (gVisor, containers) see docs/security/7-pillars-mapping.md.
    """

    def __init__(self, allowed_root: str | Path = ".", timeout: int = 120):
        self.allowed_root = Path(allowed_root).resolve()
        self.timeout = timeout

    def _validate_path(self, p: str | Path) -> Path:
        target = (self.allowed_root / Path(p)).resolve()
        # Check target is inside allowed_root (or is allowed_root itself)
        try:
            target.relative_to(self.allowed_root)
        except ValueError as exc:
            raise PermissionError(f"Path not allowed: {p}") from exc
        return target

    def run(self, cmd: list[str], cwd: str | Path | None = None, env: dict[str, str] | None = None, **kwargs: Any) -> subprocess.CompletedProcess:
        if not isinstance(cmd, list):
            raise ValueError("Command must be a list, not a string")
        if not cmd:
            raise ValueError("Command must not be empty")

        workdir = self._validate_path(cwd) if cwd else self.allowed_root

        safe_env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(self.allowed_root)}
        if env:
            safe_env.update({k: v for k, v in env.items() if not any(secret in k.upper() for secret in ("SECRET", "TOKEN", "KEY", "PASSWORD"))})

        return subprocess.run(
            cmd,
            cwd=str(workdir),
            env=safe_env,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            shell=False,
            **kwargs,
        )
