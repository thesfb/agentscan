"""Check: destructive filesystem operations.

Deterministic observation of operations that can modify git state, delete
directories, or overwrite files. Every pattern is an exact match on a
well-known destructive primitive.
"""

import re

from ..common import read_lines

NAME = "filesystem"
TITLE = "Destructive filesystem / git operations"

PATTERNS = [
    (r"\brm\s+-[a-z]*r", "rm -r (recursive delete)", "high"),
    (r"\brm\s+-[a-z]*f", "rm -f (forced delete)", "medium"),
    (r"\bshutil\.rmtree\s*\(", "shutil.rmtree (recursive delete)", "high"),
    (r"\bfs\.rm\s*\(|\bfs\.rmSync\s*\(", "fs.rm / fs.rmSync", "high"),
    (r"\bos\.remove\s*\(|\bos\.unlink\s*\(", "os.remove / os.unlink", "medium"),
    (r"\bgit\s+reset\s+--hard\b", "git reset --hard (discards work)", "high"),
    (r"\bgit\s+clean\s+-[a-z]*f", "git clean -f (deletes untracked)", "high"),
    (r"\bgit\s+push\s+--force\b|\bgit\s+push\s+-f\b", "git push --force", "medium"),
    (r"\bgit\s+checkout\s+--\s+\.\b", "git checkout -- . (reverts all)", "medium"),
    (r">\s*/[^\s]*\.(log|json|db|sqlite|txt)", "truncating overwrite of file in root path", "medium"),
    (r"\bchmod\s+777\b|\bchown\b", "permission escalation (chmod 777 / chown)", "medium"),
]


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
        for m in _COMBINED.finditer(line):
            label, sev = _label_for(line, m.group(0))
            findings.append({
                "severity": sev,
                "check": NAME,
                "title": label,
                "path": str(path),
                "line": lineno,
                "detail": line.strip()[:160],
            })
