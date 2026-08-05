"""Check: agent configuration entry points and tamper signals.

The "AI execution artifacts" generalization: skills are not the only thing
that executes. MCP server configs, agent hooks, npm lifecycle scripts,
Dockerfiles, and CI workflows all run code when an agent project is used.
This check scans those files for dangerous entries. Format detection lives
in the scanner; this module reports the dangerous content.

Everything here is deterministic: a remote MCP server URL is a fact, a hook
command is a fact, a postinstall script is a fact.
"""

import json
import os
import re

from ..common import read_lines

NAME = "config_tamper"
TITLE = "Agent configuration entry points"

# config files that are code-execution surfaces
CONFIG_FILES = {
    ".mcp.json": "MCP server config",
    "mcp.json": "MCP server config",
    ".claude/settings.json": "Claude Code settings",
    ".cursor/mcp.json": "Cursor MCP config",
    "package.json": "npm package",
    "Dockerfile": "Dockerfile",
    "Makefile": "Makefile",
    ".pre-commit-config.yaml": "pre-commit config",
    ".github/workflows": "GitHub Actions",
}

REMOTE_MCP_URL = re.compile(r'"(?:url|transport_url)"\s*:\s*"https?://')
MCP_COMMAND = re.compile(r'"(?:command|cmd)"\s*:\s*"[^\"]+"')
HOOK_COMMAND = re.compile(r'"(?:command|script)"\s*:\s*"[^\"]+"')
DENY_EMPTY = re.compile(r'"deny"\s*:\s*\[\s*\]')
LIFECYCLE_KEY = re.compile(r'"(?:preinstall|postinstall|prepare|prepublishOnly)"\s*:\s*"([^\"]+)"')
PIPE_SHELL = re.compile(r"\b(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b")
WORKFLOW_RUN = re.compile(r"^\s*run\s*:\s*(.+)$")


def run(path, findings):
    rel = os.path.normpath(str(path))
    name = os.path.basename(rel)
    parent = os.path.basename(os.path.dirname(rel))

    is_workflow = ".github" in rel.replace("\\", "/") and name.endswith((".yml", ".yaml"))
    is_mcp = name == ".mcp.json" or name == "mcp.json"
    is_settings = name == "settings.json" and ".claude" in rel.replace("\\", "/")
    is_pkg = name == "package.json"
    is_docker = name == "Dockerfile"

    if not (is_mcp or is_settings or is_pkg or is_docker or is_workflow):
        return

    lines = read_lines(path)
    joined = "\n".join(lines)

    if is_mcp:
        if REMOTE_MCP_URL.search(joined):
            findings.append({
                "severity": "medium",
                "check": NAME,
                "title": "Remote MCP server",
                "path": str(path),
                "line": _first_line(lines, REMOTE_MCP_URL),
                "detail": "MCP server fetched over the network — server code is third-party.",
            })
        if MCP_COMMAND.search(joined):
            findings.append({
                "severity": "medium",
                "check": NAME,
                "title": "MCP server launches command",
                "path": str(path),
                "line": _first_line(lines, MCP_COMMAND),
                "detail": "MCP config executes a local command on agent start.",
            })
    elif is_settings:
        if HOOK_COMMAND.search(joined):
            findings.append({
                "severity": "medium",
                "check": NAME,
                "title": "Agent hook executes command",
                "path": str(path),
                "line": _first_line(lines, HOOK_COMMAND),
                "detail": "Hook commands run on every matching agent event — review before enabling.",
            })
        if DENY_EMPTY.search(joined):
            findings.append({
                "severity": "low",
                "check": NAME,
                "title": "Empty deny list in permissions",
                "path": str(path),
                "line": _first_line(lines, DENY_EMPTY),
                "detail": "An explicit empty deny list permits all tools.",
            })
    elif is_pkg:
        for m in LIFECYCLE_KEY.finditer(joined):
            script = m.group(1)
            key = m.group(0).split('"')[1]
            sev = "high" if PIPE_SHELL.search(script) else "medium"
            findings.append({
                "severity": sev,
                "check": NAME,
                "title": "npm lifecycle script ({})".format(key),
                "path": str(path),
                "line": _line_of(joined, m.start()),
                "detail": script[:160],
            })
    elif is_docker:
        for lineno, line in enumerate(lines, 1):
            if re.match(r"^\s*RUN\b", line):
                findings.append({
                    "severity": "medium",
                    "check": NAME,
                    "title": "Dockerfile RUN executes",
                    "path": str(path),
                    "line": lineno,
                    "detail": line.strip()[:160],
                })
    elif is_workflow:
        for lineno, line in enumerate(lines, 1):
            m = WORKFLOW_RUN.match(line)
            if m and PIPE_SHELL.search(m.group(1)):
                findings.append({
                    "severity": "high",
                    "check": NAME,
                    "title": "Workflow fetches and executes remote code",
                    "path": str(path),
                    "line": lineno,
                    "detail": m.group(1).strip()[:160],
                })


def _first_line(lines, rx):
    for i, line in enumerate(lines, 1):
        if rx.search(line):
            return i
    return 1


def _line_of(joined, pos):
    return joined.count("\n", 0, pos) + 1
