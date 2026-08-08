"""Check: deep analysis — taint chains, cross-file references,
capability extraction, and evidence correlation (v2 layers 5-8).

Runs LAST in the check order so it can read the other checks' findings
for the same file and emit correlated compound findings.

- taint: secret-shaped data flows to network/exec sinks, with per-hop
  attack paths (python files, python fences, shell scripts, shell
  fences).
- cross-file: SKILL.md references to bundled scripts are resolved one
  hop; dangerous content in the referenced script becomes a chain.
- capabilities: per-file capability evidence at info severity,
  aggregated by the scanner into the report.
- correlation: a curl|bash line that fired shell + supply_chain
  findings collapses into one explained "fetch remote code and
  execute" finding (the components stay as evidence).
"""

import os
import re

from ..common import PIPE_SHELL_DEST, read_lines
from ..analysis.python_ast import parse_python, parse_python_source
from ..analysis.shell_parser import (apply_var_resolution, join_continuations,
                                     resolve_var_verbs)
from ..analysis.taint import taint_python, taint_shell_lines
from ..analysis.capabilities import (capabilities_from_python,
                                     capabilities_from_shell,
                                     capabilities_from_markdown_line)

NAME = "analysis"
TITLE = "Deep analysis (taint / capabilities / correlation)"

_PY_FENCE = re.compile(r"^```(?:python|py|python3)\s*$", re.IGNORECASE)
_SHELL_FENCE = re.compile(r"^```(?:sh|bash|zsh|shell|fish)\s*$", re.IGNORECASE)
_FENCE_END = re.compile(r"^```\s*$")

# cross-file script references in SKILL.md
_SCRIPT_REF = re.compile(
    r"(?:^|[\s;\"'`(])(?:\./)?(?:scripts|tools|bin|lib|helpers?)/"
    r"[\w./-]+\.(?:sh|bash|py|js|pl|rb)\b"
)

_DANGEROUS_SCRIPT = re.compile(
    r"\b(?:curl|wget)\b[^\n]*\|\s*" + PIPE_SHELL_DEST + r"|"
    r"base64[^\n]*\|\s*" + PIPE_SHELL_DEST + r"|rm\s+-rf?\s+(?:/|\$HOME|~)|"
    r"chmod\s+(?:-\w+\s+)*777|/etc/(?:passwd|shadow)"
)

# v3 (FN9): JS structural analysis — network primitives and sensitive
# reads in .js files and js fences (regex-level, no JS parser).
_JS_NET = re.compile(
    r"\b(?:fetch\s*\(|https?\.(?:get|post|request)\b|"
    r"require\(['\"](?:https?|http|net|axios)|axios\.|got\s*\(|"
    r"XMLHttpRequest|WebSocket|node-fetch|child_process)",
    re.IGNORECASE,
)
_JS_READ = re.compile(
    r"\b(?:readFileSync|readFile)\s*\([^)]*(?:\.env|\.ssh|\.aws|credentials?|id_rsa)|"
    r"process\.env\.[A-Z_]+|['\"](?:[^'\"]*\.env|~?/\.ssh|~?/\.aws|~?/\.git-credentials)['\"]",
    re.IGNORECASE,
)


def _finding(sev, title, path, line, detail, **extra):
    f = {
        "severity": sev, "check": NAME, "title": title,
        "path": str(path), "line": line, "detail": detail,
    }
    f.update(extra)
    return f


def _fences(lines):
    """Yield (lang, start_line, content_lines) for python/shell fences."""
    i = 0
    n = len(lines)
    while i < n:
        if _PY_FENCE.match(lines[i].strip()):
            lang = "python"
        elif _SHELL_FENCE.match(lines[i].strip()):
            lang = "shell"
        else:
            i += 1
            continue
        start = i + 1
        content = []
        j = i + 1
        while j < n and not _FENCE_END.match(lines[j].strip()):
            content.append(lines[j])
            j += 1
        yield lang, start, content
        i = j + 1


def _capability_findings(path, caps_by_line, out):
    """Emit one info finding per capability per file, with the evidence
    lines in the detail (per-line findings were too granular)."""
    per_cap = {}
    for line, caps in sorted(caps_by_line.items()):
        for cap, detail in caps:
            per_cap.setdefault(cap, []).append((line, detail))
    for cap, evs in sorted(per_cap.items()):
        first_line = evs[0][0]
        lines_list = ", ".join(str(l) for l, _d in evs[:12])
        if len(evs) > 12:
            lines_list += ", …"
        out.append(_finding(
            "info", f"Capability: {cap}", path, first_line,
            f"observed at line(s) {lines_list}",
            capability=cap,
        ))


# v3: fetch + execute in two steps (`curl -o /tmp/x.sh && bash /tmp/x.sh`)
_FETCH_THEN_EXEC = re.compile(
    r"\b(?:curl|wget)\b[^\n]*\s+-o\s+[^\s]+\.(?:sh|bash|zsh|py|js|bin|exe)"
    r"[^\n]{0,80}?(?:&&|;|then)\s*(?:sudo\s+)?(?:ba|z|fi|k|da)?sh\b[^\n]*\s+\S+\.(?:sh|bash|zsh)",
    re.IGNORECASE,
)
# a fetch that writes to a script path (for the windowed two-step check)
_FETCH_OUTPUT = re.compile(
    r"\b(?:curl|wget)\b[^\n]*\s+-o\s+([^\s]+\.(?:sh|bash|zsh|py|js|bin|exe))",
    re.IGNORECASE,
)
_EXECUTE_SCRIPT = re.compile(
    r"(?:^|[\s;])(?:sudo\s+)?(?:ba|z|fi|k|da)?sh\b[^\n]*\s+([^\s;]+\.(?:sh|bash|zsh))\b",
    re.IGNORECASE,
)


def run(path, findings, file_start=0):
    p = str(path)
    ext = os.path.splitext(p)[1].lower()
    name = os.path.basename(p)
    try:
        lines = read_lines(path)
    except OSError:
        return

    cap_by_line = {}

    # ---- v3: fetch-then-execute across two steps (FN2) ----
    joined, line_of = join_continuations(lines)
    var_map = resolve_var_verbs(lines)
    # windowed: `curl -o /tmp/x.sh` then `bash /tmp/x.sh` on a later line
    fetched_paths = {}  # path -> first line it was fetched to
    for j, jline in enumerate(joined):
        resolved = apply_var_resolution(jline, var_map)
        if _FETCH_THEN_EXEC.search(resolved):
            findings.append(_finding(
                "high",
                "Remote code fetched then executed",
                p, line_of[j],
                resolved.strip()[:160],
                confidence=0.7,
                attack_path=[
                    {"line": line_of[j], "desc": "fetch remote script"},
                    {"line": line_of[j], "desc": "execute downloaded script"},
                ],
                capability="network.connect->process.exec",
                origin="deterministic",
            ))
        # record downloaded script paths
        fm = _FETCH_OUTPUT.match(resolved)
        if fm:
            fetched_paths.setdefault(fm.group(1), line_of[j])
        # execute a previously fetched path?
        em = _EXECUTE_SCRIPT.match(resolved)
        if em:
            target = em.group(1)
            if target in fetched_paths:
                findings.append(_finding(
                    "high",
                    "Remote code fetched then executed",
                    p, line_of[j],
                    resolved.strip()[:160],
                    confidence=0.7,
                    attack_path=[
                        {"line": fetched_paths[target], "desc": "fetch remote script"},
                        {"line": line_of[j], "desc": "execute downloaded script"},
                    ],
                    capability="network.connect->process.exec",
                    origin="deterministic",
                ))

    # ---- python files: AST + taint ----
    if ext in (".py", ".pyw"):
        module = parse_python(p)
        if module:
            for cap in _caps_with_lines(module):
                cap_by_line.setdefault(cap[1], []).append((cap[0], cap[2]))
            for chain in taint_python(module):
                findings.append(_chain_finding(p, chain, module.path))

    # ---- python fences in markdown ----
    if ext in (".md", ".markdown", ".mdown"):
        for lang, start, content in _fences(lines):
            if lang == "python":
                module = parse_python_source("\n".join(content))
                if module:
                    for cap in _caps_with_lines(module):
                        cap_by_line.setdefault(start + cap[1] - 1, []).append((cap[0], cap[2]))
                    for chain in taint_python(module, line_offset=start - 1):
                        findings.append(_chain_finding(p, chain, p))
            elif lang == "shell":
                for chain in taint_shell_lines(content, start=start):
                    findings.append(_chain_finding(p, chain, p))
                _shell_caps(content, start, cap_by_line)
            elif lang in ("js", "javascript", "node", "ts", "typescript", "mjs", "cjs"):
                _js_structural(p, content, findings, cap_by_line, offset=start - 1)

    # ---- shell scripts ----
    if ext in (".sh", ".bash", ".zsh", ".fish", ".ksh"):
        for chain in taint_shell_lines(lines, start=1):
            findings.append(_chain_finding(p, chain, p))
        _shell_caps(lines, 1, cap_by_line)

    # ---- JS/TS files: structural analysis (FN9) ----
    if ext in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"):
        _js_structural(p, lines, findings, cap_by_line, offset=0)

    # ---- markdown instruction-level capabilities (any markdown file) ----
    if ext in (".md", ".markdown", ".mdown"):
        for i, line in enumerate(lines, 1):
            for cap in capabilities_from_markdown_line(line):
                cap_by_line.setdefault(i, []).append(cap)

    if cap_by_line:
        _capability_findings(path, cap_by_line, findings)

    # ---- cross-file: SKILL.md references bundled scripts ----
    if name == "SKILL.md":
        _cross_file(path, lines, findings)

    # ---- correlation: same-line remote-code fetch-and-execute ----
    if file_start >= 0:
        _correlate(path, findings[file_start:], findings)


def _caps_with_lines(module):
    """Capabilities with their line numbers from a python module."""
    out = []
    for c in module.calls:
        cap = {
            "env_read": "env.read", "file_read": "filesystem.read",
            "network": "network.connect", "exec": "process.exec",
            "base64": "code.exec", "write": "filesystem.write",
            "delete": "filesystem.delete",
        }.get(c.kind)
        if cap:
            out.append((cap, c.lineno, f"{c.func} at line {c.lineno}"))
    return out


def _shell_caps(content, start, cap_by_line):
    for i, line in enumerate(content, 1):
        for cap in capabilities_from_shell(line):
            cap_by_line.setdefault(start + i - 1, []).append(cap)


def _js_structural(path, lines, findings, cap_by_line, offset=0):
    """FN9: structural JS analysis — sensitive reads + network transfers.

    Regex-level (no JS parser). Emits a chain when a file both reads
    sensitive data and performs a network transfer.
    """
    net_lines = []
    read_lines_ = []
    for i, line in enumerate(lines, 1):
        if _JS_NET.search(line):
            net_lines.append(i)
            cap_by_line.setdefault(offset + i, []).append(
                ("network.connect", "js network primitive"))
        if _JS_READ.search(line):
            read_lines_.append(i)
            cap_by_line.setdefault(offset + i, []).append(
                ("secret.access", "js sensitive read"))
    if read_lines_ and net_lines:
        findings.append(_finding(
            "high",
            "JS file reads sensitive data and performs network transfer",
            path, offset + read_lines_[0],
            f"read at line {offset + read_lines_[0]}, "
            f"network at line {offset + net_lines[0]}",
            confidence=0.7,
            attack_path=[
                {"line": offset + read_lines_[0], "desc": "sensitive read"},
                {"line": offset + net_lines[0], "desc": "network transfer"},
            ],
            capability="secret.access->network.upload",
            origin="deterministic",
        ))


def _chain_finding(path, chain, evidence_path):
    hops = [
        {"line": h.line, "desc": h.desc}
        for h in chain.hops()
    ]
    title = ("Secret data flows to external endpoint"
             if chain.kind == "exfil" else
             "Tainted data reaches code execution")
    return _finding(
        chain.severity, title, path, chain.sink.line,
        f"attack path: {' -> '.join(h['desc'] for h in hops)[:160]}",
        confidence=chain.confidence,
        attack_path=hops,
        capability="secret.access->network.upload" if chain.kind == "exfil"
        else "secret.access->process.exec",
        origin="deterministic",
    )


def _cross_file(path, lines, findings):
    """One-hop: SKILL.md tells the agent to run a bundled script that is
    dangerous. Emit a chain finding citing both locations."""
    root = os.path.dirname(os.path.abspath(path))
    for i, line in enumerate(lines, 1):
        m = _SCRIPT_REF.search(line)
        if not m:
            continue
        rel = m.group(0).strip().strip("\"'`();,")
        rel = re.sub(r"^\./", "", rel)
        target = os.path.normpath(os.path.join(root, rel))
        if not os.path.isfile(target):
            continue
        try:
            tlines = read_lines(target)
        except OSError:
            continue
        for j, tline in enumerate(tlines, 1):
            if _DANGEROUS_SCRIPT.search(tline):
                findings.append(_finding(
                    "high",
                    "Skill instruction runs bundled script with dangerous content",
                    path, i,
                    f"SKILL.md:{i} references {rel}; {rel}:{j} contains: "
                    f"{tline.strip()[:100]}",
                    confidence=0.8,
                    attack_path=[
                        {"line": i, "desc": f"instruction references {rel}"},
                        {"line": j, "desc": f"{rel} contains dangerous command"},
                    ],
                    capability="process.exec",
                    origin="deterministic",
                ))
                break


def _correlate(path, file_findings, out):
    """Layer 8: when the same line fired curl + bash + pipe findings, one
    compound 'fetch remote code and execute' finding explains the chain.
    Component findings remain as evidence."""
    by_line = {}
    for f in file_findings:
        if f["check"] == NAME:
            continue
        by_line.setdefault((f["check"], f["line"]), []).append(f["title"])
    # lines with a fetch primitive + a shell execution primitive
    for (check, line), titles in by_line.items():
        joined = " ".join(t for t in titles)
        if check != "shell":
            continue
        has_fetch = any("curl" in t.lower() or "wget" in t.lower() for t in titles)
        has_exec = any("bash" in t.lower() or "zsh" in t.lower() or "fish" in t.lower()
                       or "sh -c" in t.lower() for t in titles)
        if has_fetch and has_exec:
            out.append(_finding(
                "high",
                "Remote code fetch-and-execute chain",
                path, line,
                "line fetches remote content and executes it with a shell",
                confidence=0.9,
                attack_path=[
                    {"line": line, "desc": "fetch primitive"},
                    {"line": line, "desc": "shell execution"},
                ],
                capability="network.connect->process.exec",
                origin="deterministic",
            ))
