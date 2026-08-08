"""Check: supply chain behavior.

Deterministic observation of patterns that pull code from elsewhere:
curl|bash installs, git clone, unpinned dependency installs, binary
downloads. Unpinned installs are flagged as facts with a suggested
severity — a doc example in a README is not the same as a setup script
the skill tells the agent to run.
"""

import re

from ..common import PIPE_SHELL_DEST, read_lines

NAME = "supply_chain"
TITLE = "Supply-chain behavior"

PATTERNS = [
    (r"\bcurl\b[^\n]*\|\s*" + PIPE_SHELL_DEST, "curl|bash (remote code pipe)", "high"),
    (r"\bwget\b[^\n]*\|\s*" + PIPE_SHELL_DEST, "wget|sh (remote code pipe)", "high"),
    (r"\bgit\s+clone\b", "git clone (pulls external repo)", "medium"),
    (r"\bdocker\s+(?:pull|run)\b", "docker pull/run (external image)", "medium"),
    (r"\bpip(?:3)?\s+install\b(?!.*[=~<>])", "pip install (unpinned)", "medium"),
    (r"\bnpm\s+(?:i|install)\b(?!.*@\d)", "npm install (unpinned)", "medium"),
    (r"\bcurl\b[^\n]*\s+-o\s+[^\s]+\.(?:sh|py|js|bin|exe)\b", "curl -o script/binary", "medium"),
    (r"\bwget\b[^\n]*\s+-O\s+[^\s]+\.(?:sh|py|js|bin|exe)\b", "wget -O script/binary", "medium"),
    (r"\bbrew\s+install\b|\bapt(-get)?\s+install\b|\bpacman\s+-S\b",
     "system package install", "low"),
    (r"\bgo\s+(?:get|install)\b|\bcargo\s+install\b", "language toolchain install", "low"),
]

# pip/npm install with an explicit version pin is fine — match and exclude
PINNED_PIP = re.compile(r"pip(?:3)?\s+install\b.*[=~<>]\s*\d")
PINNED_NPM = re.compile(r"npm\s+(?:i|install)\b.*@\d")


# cheap gate: only run pattern list on lines with a relevant keyword
_PREFILTER = re.compile(
    r"curl|wget|git\s+clone|docker|pip|npm|brew|apt|pacman|go\s+get|cargo|install",
    re.IGNORECASE,
)
_HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*$")

# single-pass compiled alternation
_COMBINED = re.compile("|".join(rx for rx, _, _ in PATTERNS))


def _label_for(group):
    for rx, lbl, sev in PATTERNS:
        if re.search(rx, group):
            return lbl, sev
    return "unknown", "medium"


def run(path, findings):
    from ..analysis.instructions import is_user_install
    from ..analysis.shell_parser import (apply_var_resolution,
                                         join_continuations, resolve_var_verbs)

    lines = read_lines(path)
    # v3: join backslash continuations and resolve verb indirection so
    # multi-line pipes and `x=curl; $x ... | bash` shapes are detected.
    joined, line_of = join_continuations(lines)
    var_map = resolve_var_verbs(lines)
    section = ""
    prev_section_line = 0
    for j, jline in enumerate(joined):
        lineno = line_of[j]
        if lineno != prev_section_line:
            # re-scan headings only when the original line is new
            hm = _HEADING.match(jline.strip())
            if hm:
                section = hm.group(1)
        prev_section_line = lineno
        resolved = apply_var_resolution(jline, var_map)
        if not _PREFILTER.search(resolved):
            continue
        for mm in _COMBINED.finditer(resolved):
            label, sev = _label_for(mm.group(0))
            if "unpinned" in label and ("pip" in label and PINNED_PIP.search(resolved)
                                        or "npm" in label and PINNED_NPM.search(resolved)):
                continue
            # v3: install instructions aimed at the user (their terminal,
            # their machine) are documentation, not the skill's behavior —
            # downgrade one level and mark for the inventory channel.
            # curl|bash pipes and script downloads keep severity.
            user_install = False
            if sev == "medium" and is_user_install(resolved, section):
                sev = "low"
                user_install = True
            findings.append({
                "severity": sev,
                "check": NAME,
                "title": label,
                "path": str(path),
                "line": lineno,
                "detail": jline.strip()[:160],
                "user_install": user_install,
            })
