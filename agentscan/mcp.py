"""agentscan-mcp — expose the deterministic skill scanner over MCP.

A minimal Model Context Protocol (stdio) server that exposes the
scanaskill scanner as a tool. Lets any MCP client (Claude, Cursor,
editors, agents) scan a skill directory without leaving the chat.

Stdlib only, matching the project's zero-dependency rule. Implements
the small MCP surface: initialize, ping, tools/list, tools/call.
The scan itself is deterministic, local, and never executes anything.

Run:
    python3 -m agentscan.mcp

Or with the console-script entry point (see pyproject.toml):
    agentscan-mcp

Register in a client (Claude Desktop example):

    "mcpServers": {
      "agentscan": {
        "command": "agentscan-mcp",
        "args": []
      }
    }
"""

from __future__ import annotations

import json
import sys
from typing import Any

PROTOCOL_VERSION = "2024-11-05"

TOOLS = [
    {
        "name": "scan",
        "description": (
            "Deterministic security scan of an AI agent skill directory. "
            "Reports shell commands, network calls, secrets, licenses, "
            "supply-chain patterns, and obfuscation with file:line evidence. "
            "Never executes the skill. Never uploads data."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to a skill directory to scan (local filesystem).",
                },
                "severity": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"],
                    "description": "Only report findings at or above this severity (default: low).",
                },
            },
            "required": ["path"],
        },
    }
]


def _scan(path: str, severity: str) -> dict[str, Any]:
    """Run scan_directory and return a portable JSON report."""
    from scanaskill.scanner import scan_directory

    res = scan_directory(path)
    sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    threshold = sev_order.get(severity, 1)
    findings = [
        {
            "severity": f["severity"],
            "check": f["check"],
            "title": f["title"],
            "file": f["path"],
            "line": f.get("line"),
            "confidence": f.get("confidence"),
        }
        for f in res["findings"]
        if sev_order.get(f["severity"], 0) >= threshold
    ]
    return {
        "target": res["target"],
        "artifacts": len(res["skills"]),
        "findings": findings,
        "summary": res["summary"],
        "review_queue": [
            {"severity": f["severity"], "title": f["title"]}
            for f in res.get("review_queue", [])
        ],
    }


def _handle(msg: dict[str, Any]) -> dict[str, Any] | None:
    """Handle one JSON-RPC message. Returns a response, or None for notifications."""
    method = msg.get("method")
    ident = msg.get("id")
    params = msg.get("params") or {}

    # Notifications carry no id — no response.
    if method == "notifications/initialized":
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": ident,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "agentscan-mcp", "version": "1.0.0"},
            },
        }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": ident, "result": {}}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": ident, "result": {"tools": TOOLS}}

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        if name != "scan":
            return {
                "jsonrpc": "2.0",
                "id": ident,
                "error": {"code": -32601, "message": f"unknown tool: {name}"},
            }
        path = args.get("path", "").strip()
        if not path:
            return {
                "jsonrpc": "2.0",
                "id": ident,
                "error": {"code": -32602, "message": "missing required argument: path"},
            }
        try:
            report = _scan(path, str(args.get("severity", "low")))
        except Exception as exc:  # noqa: BLE001 — report any scan error to the client
            return {
                "jsonrpc": "2.0",
                "id": ident,
                "error": {"code": -32000, "message": f"scan failed: {exc}"},
            }
        return {
            "jsonrpc": "2.0",
            "id": ident,
            "result": {
                "content": [{"type": "text", "text": json.dumps(report, indent=2)}],
                "isError": False,
            },
        }

    return {
        "jsonrpc": "2.0",
        "id": ident,
        "error": {"code": -32601, "message": f"method not found: {method}"},
    }


def main() -> int:
    """stdio transport: newline-delimited JSON-RPC 2.0 on stdin/stdout."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = _handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
