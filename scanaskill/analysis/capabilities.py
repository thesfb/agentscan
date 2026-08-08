"""Capability extraction (v2 layer 5).

Maps observed code/instructions to a small capability vocabulary so the
report can answer "what can this artifact do?" with evidence, and later
layers can detect declared-vs-observed drift and build attack paths.

Capabilities are facts (file:line evidence), never verdicts.
"""

from __future__ import annotations

import os
import re

from .python_ast import parse_python_source
from .shell_parser import parse_shell_line

# capability -> evidence records
CAPABILITIES = (
    "filesystem.read", "filesystem.write", "filesystem.delete",
    "env.read", "secret.access", "process.exec", "network.connect",
    "network.upload", "persistence", "privilege.change",
    "package.install", "code.exec", "tool.invoke", "secret.write",
)

NETWORK_VERBS = {"curl", "wget", "nc", "netcat", "telnet", "ftp"}
INSTALL_VERBS = {"pip", "pip3", "npm", "pnpm", "yarn", "brew", "apt",
                 "apt-get", "pacman", "dnf", "yum", "cargo", "go", "gem",
                 "composer", "uv"}
EXEC_VERBS = {"bash", "sh", "zsh", "python", "python3", "node", "perl",
              "ruby", "php", "lua", "pwsh", "powershell"}
PERSIST_VERBS = {"cron", "at", "systemctl", "launchctl", "logind"}
PRIV_VERBS = {"sudo", "su", "chmod", "chown", "setuid", "runas"}


def capabilities_from_shell(line):
    """Capabilities from one shell line. Returns list of (cap, detail)."""
    caps = []
    for cmd in parse_shell_line(line):
        verb = cmd.verb
        if verb in NETWORK_VERBS:
            caps.append(("network.connect", f"{verb} {line.strip()[:60]}"))
            # upload shapes: -d, -F, --data, -X POST with a body source
            if verb in ("curl", "wget") and any(
                    a in cmd.args for a in ("-d", "-F", "--data", "--data-binary",
                                            "--data-urlencode", "-X", "--request",
                                            "-T", "--upload-file")):
                caps.append(("network.upload", f"{verb} with body {line.strip()[:60]}"))
        elif verb in INSTALL_VERBS:
            caps.append(("package.install", f"{verb} {line.strip()[:60]}"))
        elif verb in EXEC_VERBS or verb.endswith((".sh", ".py", ".js")):
            caps.append(("process.exec", f"{verb} {line.strip()[:60]}"))
        elif verb in PERSIST_VERBS:
            caps.append(("persistence", f"{verb} {line.strip()[:60]}"))
        elif verb in PRIV_VERBS:
            caps.append(("privilege.change", f"{verb} {line.strip()[:60]}"))
        if cmd.has_redirect:
            caps.append(("filesystem.write", f"redirect to {cmd.redirect_target}"))
        if cmd.has_cmd_subst:
            caps.append(("process.exec", f"command substitution {line.strip()[:60]}"))
    return caps


def capabilities_from_python(module):
    """Capabilities from a parsed Python module. Returns (cap, detail) list."""
    caps = []
    for c in module.calls:
        if c.kind == "env_read":
            caps.append(("env.read", f"{c.func} at line {c.lineno}"))
        elif c.kind == "file_read":
            caps.append(("filesystem.read", f"{c.func} at line {c.lineno}"))
        elif c.kind == "network":
            caps.append(("network.connect", f"{c.func} at line {c.lineno}"))
            caps.append(("network.upload", f"{c.func} at line {c.lineno}"))
        elif c.kind == "exec":
            caps.append(("process.exec", f"{c.func} at line {c.lineno}"))
            caps.append(("code.exec", f"{c.func} at line {c.lineno}"))
        elif c.kind == "base64":
            caps.append(("code.exec", f"{c.func} at line {c.lineno}"))
        elif c.kind == "write":
            caps.append(("filesystem.write", f"{c.func} at line {c.lineno}"))
        elif c.kind == "delete":
            caps.append(("filesystem.delete", f"{c.func} at line {c.lineno}"))
    return caps


def capabilities_from_markdown_line(line):
    """Capabilities from an instruction-ish markdown line (heuristic)."""
    caps = []
    low = line.lower()
    if re.search(r"\bcat\s+~?/?(?:\.ssh|\.aws|\.env|\.git-credentials|\.netrc)", low) \
            or re.search(r"\b(?:read|open)\s+[\"']?(?:~?/?(?:\.ssh|\.aws|\.env))", low):
        caps.append(("secret.access", line.strip()[:60]))
    if re.search(r"\b(?:curl|wget|nc|netcat)\b", low):
        caps.append(("network.connect", line.strip()[:60]))
    if re.search(r"\b(?:curl|wget)\b[^\n]*\b(?:-d|-F|--data|--upload-file|-T)\b", low):
        caps.append(("network.upload", line.strip()[:60]))
    if re.search(r"\b(?:os\.environ|os\.getenv|process\.env|getenv|environ)\b", line):
        caps.append(("env.read", line.strip()[:60]))
    if re.search(r"\b(?:eval|exec|os\.system|subprocess|child_process)\b", low):
        caps.append(("code.exec", line.strip()[:60]))
    if re.search(r"\bchmod\s+777|\bchown\b|\bsudo\b", low):
        caps.append(("privilege.change", line.strip()[:60]))
    return caps


def dedupe_caps(caps):
    """Collapse (cap, detail) to {cap: [details]} preserving order."""
    out = {}
    for cap, detail in caps:
        out.setdefault(cap, []).append(detail)
    return out
