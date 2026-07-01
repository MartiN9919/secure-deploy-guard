#!/usr/bin/env python3
"""Run Bandit security scan and output JSON results."""
import subprocess
import json
import sys

def run_bandit(path: str, severity: str = "medium"):
    try:
        result = subprocess.run(
            ["bandit", "-r", path, "-f", "json"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode in (0, 1):
            return json.loads(result.stdout)
        return {"error": result.stderr}
    except FileNotFoundError:
        return {"error": "Bandit not installed"}
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    print(json.dumps(run_bandit(path)))
