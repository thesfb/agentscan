"""Check: shell / interpreter invocation.

Deterministic observation: which interpreters and exec primitives a skill
(and its bundled files) invoke. Presence is a FACT; whether it's justified
is the human's verdict. Skills legitimately reference bash — the report
surfaces where, with what, and lets the reader judge.
"""

import re

from ..common import read_lines

NAME = "shell"
TITLE = "Shell / interpreter invocation"

# (regex, label)
PATTERNS = [
    (r"\bcurl\b", "curl"),
    (r"\bwget\b", "wget"),
    (r"\bbash\b", "bash"),
    (r"\bsh\s+-c\b", "sh -c"),
    (r"\bzsh\b", "zsh"),
    (r"\bpython3?\s+-c\b", "python -c"),
    (r"\bnode\s+-e\b|\bnode\s+--eval\b", "node -e"),
    (r"\bos\.system\s*\(", "os.system"),
    (r"\bsubprocess\s*\.\s*(run|call|Popen|check_output)\s*\(", "subprocess"),
    (r"\bchild_process\s*\.\s*(exec|execSync|spawn|spawnSync)\s*\(", "child_process"),
    (r"\bexec\s*\(|\beval\s*\(", "exec/eval"),
    (r"\b`[^`]{3,}`", "shell backticks"),
]

# cheap gate: only run the full pattern list on lines that mention a keyword
_PREFILTER = re.compile(
    r"curl|wget|bash|\bsh\b|zsh|python|node|\bos\.|\bsubprocess\b|child_process|\bexec\b|\beval\b|`",
    re.IGNORECASE,
)

# single-pass compiled alternation (5-10x faster than N per-line searches).
# Label lookup must be robust: alternation can match a branch whose re.match
# on the group fails, so fall back to searching the line.
_COMBINED = re.compile("|".join(rx for rx, _ in PATTERNS))


def _label_for(line, group):
    for rx, lbl in PATTERNS:
        if re.match(rx, group) or re.search(rx, line):
            return lbl
    return "command"


def run(path, findings):
    lines = read_lines(path)
    for lineno, line in enumerate(lines, 1):
        if not _PREFILTER.search(line):
            continue
        for m in _COMBINED.finditer(line):
            label = _label_for(line, m.group(0))
            findings.append({
                "severity": "medium",
                "check": NAME,
                "title": f"Invokes {label}",
                "path": str(path),
                "line": lineno,
                "detail": line.strip()[:160],
            })
