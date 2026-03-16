"""
Thin Python wrapper that starts the Node.js MCP server.

Resolves the built JS entry point from the bundled npm package and
executes it via Node.js, forwarding stdio so the MCP transport works
transparently.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


def _find_node() -> str:
    """Locate a Node.js >= 20 binary on the system."""
    node = shutil.which("node")
    if node is None:
        print(
            "Error: Node.js is required but not found on PATH.\n"
            "Install Node.js 20+ from https://nodejs.org or via your package manager.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Quick version check
    try:
        result = subprocess.run(
            [node, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        version = result.stdout.strip().lstrip("v")
        major = int(version.split(".")[0])
        if major < 20:
            print(
                f"Error: Node.js >= 20 is required (found v{version}).\n"
                "Upgrade at https://nodejs.org",
                file=sys.stderr,
            )
            sys.exit(1)
    except (subprocess.TimeoutExpired, ValueError, IndexError):
        pass  # best-effort — let it fail later if node is truly broken

    return node


def _find_server_js() -> str:
    """Locate the compiled index.js entry point.

    Search order:
      1. Bundled alongside this Python package  (pip install from sdist/wheel)
      2. Relative to repo root                  (development / editable install)
      3. npx fallback                           (global npm package)
    """
    # 1) Bundled: python/multicloud_security_mcp/../../dist/index.js
    pkg_dir = Path(__file__).resolve().parent
    bundled = pkg_dir / "dist" / "index.js"
    if bundled.is_file():
        return str(bundled)

    # 2) Repo-relative: <repo>/dist/index.js
    repo_dist = pkg_dir.parent.parent / "dist" / "index.js"
    if repo_dist.is_file():
        return str(repo_dist)

    # 3) Let npx resolve it
    return ""


def serve() -> None:
    """Start the Multi-Cloud Security MCP server.

    This function never returns — it replaces the current process with the
    Node.js server (via exec on Unix, subprocess on Windows).
    """
    node = _find_node()
    server_js = _find_server_js()

    # Forward all env vars (cloud credentials, config, etc.)
    env = os.environ.copy()

    if server_js:
        # Direct invocation — fastest path
        args = [node, server_js]
    else:
        # Fallback: use npx to resolve the npm package
        npx = shutil.which("npx")
        if npx is None:
            print(
                "Error: Could not find the MCP server JS bundle or npx.\n"
                "Either install the npm package:\n"
                "    npm install -g multicloud-security-mcp\n"
                "Or rebuild from source:\n"
                "    npm run build",
                file=sys.stderr,
            )
            sys.exit(1)
        args = [npx, "multicloud-security-mcp"]

    try:
        # On Unix, exec replaces the process so signals propagate cleanly
        if sys.platform != "win32":
            os.execvpe(args[0], args, env)
        else:
            # On Windows, use subprocess and proxy the exit code
            result = subprocess.run(args, env=env)
            sys.exit(result.returncode)
    except FileNotFoundError:
        print(f"Error: Failed to execute {args[0]}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)
