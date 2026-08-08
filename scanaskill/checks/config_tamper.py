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

from ..common import PIPE_SHELL_RX, read_lines

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
MCP_COMMAND = re.compile(r'"(?:command|cmd)"\s*:\s*"[^\\"]+"')
HOOK_COMMAND = re.compile(r'"(?:command|script)"\s*:\s*"[^\\"]+"')
DENY_EMPTY = re.compile(r'"deny"\s*:\s*\[\s*\]')
LIFECYCLE_KEY = re.compile(r'"(?:preinstall|postinstall|prepare|prepublishOnly)"\s*:\s*"([^\\"]+)"')
PIPE_SHELL = PIPE_SHELL_RX
WORKFLOW_RUN = re.compile(r"^\s*run\s*:\s*(.+)$")

# v3 (FN9): lifecycle-script content analysis — network primitives and
# sensitive reads inside npm lifecycle script strings.
_LIFECYCLE_NET = re.compile(
    r"\b(?:fetch\s*\(|https?\.(?:get|post|request)\b|require\(['\"](?:https?|http|net|child_process|axios)"
    r"|axios\.|got\s*\(|node-fetch|XMLHttpRequest|WebSocket)",
    re.IGNORECASE,
)
_LIFECYCLE_READ = re.compile(
    r"\b(?:readFileSync|readFile)\s*\(|process\.env"
    r"|['\"](?:[^'\"]*\.env|/home/[^'\"]*|~?/\.ssh|~?/\.aws|~?/\.git-credentials|~?/\.netrc)['\"]",
    re.IGNORECASE,
)

# v2: MCP tool-description poisoning (CVE-2025-54136 shape).
# A tool description that pairs file/credential reads with send/upload
# verbs is instruction content that will land in the model's context —
# the MSRC/ghostprobe "lethal trifecta": execution + exfiltration +
# credential-adjacent paths inside a description.
_POISON_READ = re.compile(
    r"\b(?:read|open|cat|get|fetch|load|access|collect|copy|exfiltrat\w*)\b"
    r"[^\n]{0,40}?(?:~/?\.ssh|\.env\b|credentials?|id_rsa|id_ed25519|"
    r"\.aws|\.git-credentials|\.netrc|/etc/(?:passwd|shadow)|secret|token|key)",
    re.IGNORECASE,
)
_POISON_SEND = re.compile(
    r"\b(?:send|upload|post|pass|forward|transmit|deliver|exfiltrat\w*)\b"
    r"[^\n]{0,40}?(?:to|as|via|using|through|in)",
    re.IGNORECASE,
)
_POISON_APPEND = re.compile(
    r"\b(?:as the|as a|in the|in a|to the|to a|parameter|argument|note|"
    r"field|body|request|endpoint|url|server)\b",
    re.IGNORECASE,
)

# v3 (FN10): generic user-file reads paired with transfer — lower
# confidence, review queue (credentials stay at 0.7).
_POISON_READ_GENERIC = re.compile(
    r"\b(?:read|open|cat|get|fetch|load|access|collect|copy|exfiltrat\w*)\b"
    r"[^\n]{0,40}?(?:~?/\.(?:bashrc|zshrc|profile|bash_history|zsh_history|config)|"
    r"/home/[^\s]+|documents|notes|vault|clipboard|browser data|history|database|"
    r"chat logs|conversation)",
    re.IGNORECASE,
)


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
        # v2/v3: tool-description poisoning — credential reads paired with
        # send/upload verbs inside a description or command string.
        for m in _STRINGS.finditer(joined):
            val = m.group(1)
            if not (len(val) > 20):
                continue
            if _POISON_READ.search(val) and (_POISON_SEND.search(val)
                                             or _POISON_APPEND.search(val)):
                findings.append({
                    "severity": "high",
                    "check": NAME,
                    "title": "Tool description pairs credential access with data transfer",
                    "path": str(path),
                    "line": _line_of(joined, m.start()),
                    "detail": val[:160],
                    "confidence": 0.7,
                    "origin": "deterministic",
                    "capability": "secret.access->network.upload",
                })
                break
            # v3 (FN10): generic user-file reads — lower confidence, review
            if _POISON_READ_GENERIC.search(val) and (_POISON_SEND.search(val)
                                                     or _POISON_APPEND.search(val)):
                findings.append({
                    "severity": "medium",
                    "check": NAME,
                    "title": "Tool description pairs user-file access with data transfer",
                    "path": str(path),
                    "line": _line_of(joined, m.start()),
                    "detail": val[:160],
                    "confidence": 0.5,
                    "review": True,
                    "origin": "deterministic",
                    "capability": "filesystem.read->network.upload",
                })
                break
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
        # v3: parse package.json properly (the regex truncates scripts at
        # escaped quotes, e.g. `node -e "fetch(...)"`).
        try:
            pkg = json.loads(joined)
        except (ValueError, json.JSONDecodeError):
            pkg = {}
        scripts = pkg.get("scripts") or {}
        lifecycle = {k: v for k, v in scripts.items()
                     if k in ("preinstall", "postinstall", "prepare", "prepublishOnly")}
        for key, script in lifecycle.items():
            sev = "high" if PIPE_SHELL.search(script) else "medium"
            findings.append({
                "severity": sev,
                "check": NAME,
                "title": "npm lifecycle script ({})".format(key),
                "path": str(path),
                "line": _line_of(joined, joined.find(f'"{key}"')) if f'"{key}"' in joined else 1,
                "detail": script[:160],
            })
            # v3 (FN9): lifecycle script content — network + sensitive read
            if _LIFECYCLE_NET.search(script):
                if _LIFECYCLE_READ.search(script):
                    findings.append({
                        "severity": "high",
                        "check": NAME,
                        "title": "Lifecycle script reads secrets and performs network transfer",
                        "path": str(path),
                        "line": _line_of(joined, joined.find(f'"{key}"')) if f'"{key}"' in joined else 1,
                        "detail": script[:160],
                        "confidence": 0.75,
                        "capability": "secret.access->network.upload",
                    })
                else:
                    findings.append({
                        "severity": "medium",
                        "check": NAME,
                        "title": "Lifecycle script performs network access",
                        "path": str(path),
                        "line": _line_of(joined, joined.find(f'"{key}"')) if f'"{key}"' in joined else 1,
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


# string values in JSON configs (poisoning scan)
_STRINGS = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')


def _line_of(joined, pos):
    return joined.count("\n", 0, pos) + 1
