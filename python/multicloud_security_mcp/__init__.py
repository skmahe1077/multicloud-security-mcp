"""
Multi-Cloud Security MCP Server

Unified security visibility across AWS, Azure, and GCP for AI agents and Claude Desktop.

Usage:
    # CLI
    multicloud-security-mcp

    # Python module
    python -m multicloud_security_mcp

    # Programmatic
    from multicloud_security_mcp import serve
    serve()
"""

__version__ = "1.0.0"

from .server import serve  # noqa: F401
