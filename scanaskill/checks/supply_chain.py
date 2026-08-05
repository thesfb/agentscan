"""Check: supply chain behavior.

Deterministic observation of patterns that pull code from elsewhere:
curl|bash installs, git clone, unpinned dependency installs, binary
downloads. Unpinned installs are flagged as facts with a suggested
severity — a doc example in a README is not the same as a setup script
the skill tells the agent to run.
"""

import re

from ..common import read_lines

NAME = "supply_chain"
TITLE = "Supply-chain behavior"

PATTERNS = [
    (r"\bcurl\b[^\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b", "curl|bash (remote code pipe)", "high"),
    (r"\bwget\b[^\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b", "wget|sh (remote code pipe)", "high"),
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

# single-pass compiled alternation
_COMBINED = re.compile("|".join(rx for rx, _, _ in PATTERNS))


def _label_for(line, group):
    for rx, lbl, sev in PATTERNS:
        if re.match(rx, group) or re.search(rx, line):
            return lbl, sev
    return "unknown", "medium"


def run(path, findings):
    lines = read_lines(path)
    for lineno, line in enumerate(lines, 1):
        if not _PREFILTER.search(line):
            continue
        for m in _COMBINED.finditer(line):
            label, sev = _label_for(line, m.group(0))
            if "unpinned" in label and ("pip" in label and PINNED_PIP.search(line)
                                        or "npm" in label and PINNED_NPM.search(line)):
                continue
            findings.append({
                "severity": sev,
                "check": NAME,
                "title": label,
                "path": str(path),
                "line": lineno,
                "detail": line.strip()[:160],
            })
