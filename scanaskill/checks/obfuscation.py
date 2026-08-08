"""Check: obfuscated payload indicators.

Deterministic observation of encoding/decoding chains that hide executable
content: base64-to-shell, hex/xxd/openssl decodes, character-code arrays,
and nested eval/exec. The finding reports that a decode-and-execute chain
is present — what it decodes to is the human's problem, not a scanner claim.
"""

import re

from ..common import PIPE_SHELL_DEST, read_lines

NAME = "obfuscation"
TITLE = "Obfuscated payload indicators"

# decode-to-execute chains (base64/hex/rot into a shell or interpreter)
DECODE_EXEC = [
    (r"(?:base64|b64)\s*-d[^\n]*\|\s*" + PIPE_SHELL_DEST,
     "base64 decode piped to shell", "critical"),
    (r"(?:base64|b64)\s*-d[^\n]*\|\s*(?:python3?|node|perl|ruby)\b",
     "base64 decode piped to interpreter", "critical"),
    (r"\b(?:echo|printf|cat)\b[^\n]*(?:base64|b64)[^\n]*\|\s*" + PIPE_SHELL_DEST,
     "encoded blob decoded to shell", "critical"),
    (r"\b(?:xxd|hexdump)\s*-r\b|\bopenssl\s+enc\s+-d\b|\brot13\b|\btr\s+[^\n]*A-Za-z",
     "binary/rot decode", "medium"),
    (r"\b(?:base64\.b64decode|b64decode\()\s*[^\n]*(?:exec|eval|os\.system|subprocess)",
     "base64 decode then execute (python)", "critical"),
    (r"\b(?:atob|Buffer\.from)\s*\([^\n]*(?:eval|Function|exec|child_process)",
     "base64 decode then execute (node)", "critical"),
]

# nested eval/exec — the classic payload wrapper
NESTED_EVAL = re.compile(r"\b(?:eval|exec)\s*\(\s*(?:eval|exec|Function|compile)\s*\(")

# long hex-escape runs and char-code arrays
HEX_RUN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
CHARCODE = re.compile(r"\b(?:String\.fromCharCode|charCodeAt|chr\()\s*\(")
BYTEARRAY = re.compile(r"\bbytearray\s*\(\s*\[[^\]]{20,}\]")


# cheap gate
_PREFILTER = re.compile(
    r"base64|b64|xxd|hexdump|openssl|rot13|fromCharCode|charCodeAt|bytearray|eval|exec|\\x",
    re.IGNORECASE,
)


def run(path, findings):
    lines = read_lines(path)
    for lineno, line in enumerate(lines, 1):
        if not _PREFILTER.search(line):
            continue
        for rx, label, sev in DECODE_EXEC:
            if re.search(rx, line):
                findings.append({
                    "severity": sev,
                    "check": NAME,
                    "title": label,
                    "path": str(path),
                    "line": lineno,
                    "detail": line.strip()[:160],
                })
        if NESTED_EVAL.search(line):
            findings.append({
                "severity": "critical",
                "check": NAME,
                "title": "Nested eval/exec",
                "path": str(path),
                "line": lineno,
                "detail": line.strip()[:160],
            })
        if HEX_RUN.search(line):
            findings.append({
                "severity": "medium",
                "check": NAME,
                "title": "Hex-escape payload run",
                "path": str(path),
                "line": lineno,
                "detail": line.strip()[:160],
            })
        if CHARCODE.search(line) and (BYTEARRAY.search(line) or re.search(r"[\d,]{12,}", line)):
            findings.append({
                "severity": "medium",
                "check": NAME,
                "title": "Character-code array",
                "path": str(path),
                "line": lineno,
                "detail": line.strip()[:160],
            })
