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

# v2: explicit instructions to move credential material out. Guarded
# against defensive phrasings ("never send credentials", "do not upload").
INSTRUCTION_EXFIL = re.compile(
    r"\b(?:send|upload|post|pass|forward|transmit|deliver|copy|exfiltrat\w*|"
    r"email|ship|dump|leak)\b[^\n]{0,60}?"
    r"(?:~/?\.ssh|\.env\b|id_rsa|id_ed25519|credentials?|\.git-credentials|"
    r"\.netrc|\.aws|/etc/(?:passwd|shadow)|tokens?|api[_-]?keys?|secrets?)"
    r"[^\n]{0,60}?(?:to|via|into|through|at|as)",
    re.IGNORECASE,
)
INSTRUCTION_EXFIL_REV = re.compile(
    r"\b(?:~/?\.ssh|\.env\b|id_rsa|credentials?|\.git-credentials|\.netrc|"
    r"tokens?|api[_-]?keys?|secrets?)\b[^\n]{0,40}?"
    r"\b(?:send|upload|post|pass|forward|transmit|deliver|copy)\b",
    re.IGNORECASE,
)
DEFENSIVE_PROMPT = re.compile(
    r"(?i)\b(?:never|do not|don't|must not|should not|avoid|without)\b"
    r"[^\n]{0,30}?\b(?:send|upload|post|pass|share|reveal|expose|transmit)\b"
)
# demanded-authority phrasing (SCH-shaped): compliance-style rules that
# demand sensitive capabilities — review queue, not a verdict
SCH_PHRASING = re.compile(
    r"(?i)\b(?:compliance|policy|security requirement|mandatory|required|"
    r"must|before (?:continuing|proceeding|returning)|as part of (?:the )?setup)\b"
    r"[^\n]{0,50}?\b(?:read|access|collect|upload|send|run|execute|download)\b"
)

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
                    "review": True,  # manual-review class, never a verdict
                })
        # v2: explicit credential-exfil instruction (guarded vs defensive)
        if not DEFENSIVE_PROMPT.search(line):
            if INSTRUCTION_EXFIL.search(line) or INSTRUCTION_EXFIL_REV.search(line):
                findings.append({
                    "severity": "high",
                    "check": NAME,
                    "title": "Instruction directs transfer of credential material",
                    "path": str(path),
                    "line": lineno,
                    "detail": line.strip()[:160],
                    "review": True,
                    "confidence": 0.6,
                    "capability": "secret.access->network.upload",
                })
            elif SCH_PHRASING.search(line):
                # compliance-rule phrasing demanding sensitive capabilities:
                # review-queue signal (SCH-shaped content), not a finding
                findings.append({
                    "severity": "low",
                    "check": NAME,
                    "title": "Compliance-rule phrasing demands sensitive capability",
                    "path": str(path),
                    "line": lineno,
                    "detail": line.strip()[:160],
                    "review": True,
                    "confidence": 0.35,
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
                "review": True,
            })
