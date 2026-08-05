"""Check: high-risk prompt-manipulation patterns.

NOT "injection detection". Static pattern matching can observe that a
skill contains phrases commonly used to manipulate an agent's behavior
("ignore previous instructions", embedded override blocks, opaque encoded
blobs). Whether that is actually an attack is a manual-review question.
The finding says: "this pattern appears here — look at it", and nothing
stronger. Security reviewers can bypass any claim stronger than that, so
we deliberately do not make one.
"""

import re

from ..common import read_lines

NAME = "prompt_patterns"
TITLE = "High-risk prompt-manipulation patterns"

# patterns that are suspicious in an agent-instruction context
PATTERNS = [
    (r"\bignore\s+(?:all\s+)?(?:previous|prior|earlier)\s+(?:instructions|commands|prompts|messages)\b",
     "Ignore-previous-instructions phrasing", "medium"),
    (r"\bdisregard\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions|prompts)\b",
     "Disregard-previous phrasing", "medium"),
    (r"\bdo\s+not\s+(?:tell|reveal|mention|disclose|inform)\b[^.\n]{0,40}?\b(?:the\s+)?(?:user|human)\b",
     "Conceal-from-user phrasing", "medium"),
    (r"\bnever\s+(?:tell|reveal|mention)\b[^.\n]{0,40}?\b(?:the\s+)?(?:user|human)\b",
     "Never-tell-user phrasing", "medium"),
    (r"<\s*(?:system|input)\s*>",
     "Embedded override tag", "medium"),
    # note: deliberately NOT "always ... start" — benign design-doc phrasing
    (r"\b(?:always|secretly)\s+(?:run|execute)\b",
     "Always-run directive", "medium"),
]

# opaque base64-ish blobs (>= 60 chars of base64 alphabet) — encoded payload hint
BASE64_BLOB = re.compile(r"[A-Za-z0-9+/=]{60,}")
BASE64_PREFIX = re.compile(r"\b(?:base64|b64|from64)\b", re.IGNORECASE)

# cheap gate — must cover every PATTERN keyword (perf-only, never semantic)
_PREFILTER = re.compile(
    r"ignore|disregard|never\s+tell|do\s+not\s+(?:tell|reveal|mention|disclose|inform)|"
    r"<system|<input|always|secretly|base64",
    re.IGNORECASE,
)


def run(path, findings):
    lines = read_lines(path)
    for lineno, line in enumerate(lines, 1):
        if not _PREFILTER.search(line):
            continue
        for rx, label, sev in PATTERNS:
            if re.search(rx, line, re.IGNORECASE):
                findings.append({
                    "severity": sev,
                    "check": NAME,
                    "title": label,
                    "path": str(path),
                    "line": lineno,
                    "detail": line.strip()[:160],
                })
        if BASE64_PREFIX.search(line) and BASE64_BLOB.search(line):
            blob = BASE64_BLOB.search(line).group(0)
            findings.append({
                "severity": "medium",
                "check": NAME,
                "title": "Base64-decoded payload present",
                "path": str(path),
                "line": lineno,
                "detail": f"base64 blob ({len(blob)} chars) — decode and review before running",
            })
