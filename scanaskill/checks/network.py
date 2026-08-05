"""Check: network egress.

Deterministic observation of outbound network primitives and URLs. A skill
that makes network calls is not inherently bad — but an agent skill that
sends data somewhere is exactly the class of thing a reviewer must know
about. Token-in-URL patterns are escalated.
"""

import re

from ..common import read_lines

NAME = "network"
TITLE = "Network egress"

# egress primitives
PRIMITIVES = [
    (r"\bcurl\b", "curl"),
    (r"\bwget\b", "wget"),
    (r"\bfetch\s*\(", "fetch()"),
    (r"\brequests\.(get|post|put|patch|delete|head)\s*\(", "requests.*"),
    (r"\burllib\.request\b", "urllib.request"),
    (r"\baxios\.(get|post|put|patch|delete)\s*\(", "axios.*"),
    (r"\bhttpx\.(get|post|put|patch|delete)\s*\(", "httpx.*"),
    (r"\bXMLHttpRequest\b|\bWebSocket\b", "XHR / WebSocket"),
    (r"\bnet\.(connect|request)\b", "node net"),
    (r"\bsocket\.(socket|create_connection)\b", "python socket"),
    (r"\bInvoke-WebRequest\b|\bInvoke-RestMethod\b", "PowerShell web request"),
]

# URL matching: bounded at real terminators (space, quotes, brackets, backtick).
# URLs legitimately contain $ ( ) ? = & — do NOT cut at those.
URL = re.compile(r"https?://[^\s\"'`<>]+")
TOKEN_IN_URL = re.compile(
    r"https?://[^\s\"'`\)\]]*(token|key|secret|auth|password|api[_-]?key)=[^\s&\"'`\)\]]+",
    re.IGNORECASE,
)
# non-https URLs are a stronger signal (cleartext)
HTTP_URL = re.compile(r"http://[^\s\"'`\)\]]+")

# risky URL structures (facts: IP literal, userinfo, internal host, shortener, hosted content)
IP_LITERAL = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?[/\s\"'`\)\]]")
USERINFO = re.compile(r"https?://[^/\s:@]+:[^/\s@]+@")
INTERNAL_HOST = re.compile(
    r"https?://(?:localhost|127\.0\.0\.1|169\.254\.169\.254|metadata\.google\.internal|"
    r"instance-data|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)",
    re.IGNORECASE,
)
SHORTENER = re.compile(r"https?://(?:bit\.ly|t\.co|tinyurl\.com|goo\.gl|is\.gd|rb\.gy|cutt\.ly)/")
RAW_HOST = re.compile(r"https?://(?:raw\.githubusercontent\.com|gist\.githubusercontent\.com)")

# well-known documentation/license hosts — boilerplate, not findings
DOC_ALLOWLIST = re.compile(
    r"https?://(?:opensource\.org|www\.apache\.org|apache\.org|www\.gnu\.org|gnu\.org|"
    r"creativecommons\.org|unlicense\.org|wtfpl\.net|www\.python\.org|docs\.python\.org|"
    r"pypi\.org|www\.w3\.org|developer\.mozilla\.org|en\.wikipedia\.org|www\.npmjs\.com|"
    r"rubygems\.org|example\.com|example\.org|localhost(?::\d+)?)",
    re.IGNORECASE,
)


# cheap gate: only run URL/primitive patterns on lines that mention network
_PREFILTER = re.compile(
    r"http|curl|wget|fetch|requests|axios|httpx|urllib|socket|XHR|WebSocket|Invoke-",
    re.IGNORECASE,
)


# single-pass compiled alternation
_COMBINED = re.compile("|".join(rx for rx, _ in PRIMITIVES))


def _label_for(line, group):
    for rx, lbl in PRIMITIVES:
        if re.match(rx, group) or re.search(rx, line):
            return lbl
    return "unknown"


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
                "title": f"Network primitive: {label}",
                "path": str(path),
                "line": lineno,
                "detail": line.strip()[:160],
            })
        # skip lines with no URL-ish content entirely (fast path)
        if "://" not in line and not line.lower().startswith("http"):
            continue
        for m in URL.finditer(line):
            url = m.group(0)
            if DOC_ALLOWLIST.search(url):
                continue  # license/docs boilerplate, not a finding
            if TOKEN_IN_URL.search(url):
                findings.append({
                    "severity": "high",
                    "check": NAME,
                    "title": "Credential in URL",
                    "path": str(path),
                    "line": lineno,
                    "detail": url[:160],
                })
            elif IP_LITERAL.search(url):
                findings.append({
                    "severity": "high",
                    "check": NAME,
                    "title": "IP-literal URL",
                    "path": str(path),
                    "line": lineno,
                    "detail": url[:160],
                })
            elif INTERNAL_HOST.search(url):
                findings.append({
                    "severity": "high",
                    "check": NAME,
                    "title": "Internal/metadata host URL",
                    "path": str(path),
                    "line": lineno,
                    "detail": url[:160],
                })
            elif USERINFO.search(url):
                findings.append({
                    "severity": "high",
                    "check": NAME,
                    "title": "Credentials embedded in URL",
                    "path": str(path),
                    "line": lineno,
                    "detail": url[:160],
                })
            elif SHORTENER.search(url):
                findings.append({
                    "severity": "medium",
                    "check": NAME,
                    "title": "URL shortener",
                    "path": str(path),
                    "line": lineno,
                    "detail": url[:160],
                })
            elif RAW_HOST.search(url):
                findings.append({
                    "severity": "medium",
                    "check": NAME,
                    "title": "Hosted raw content URL",
                    "path": str(path),
                    "line": lineno,
                    "detail": url[:160],
                })
            else:
                findings.append({
                    "severity": "info",
                    "check": NAME,
                    "title": "URL in skill",
                    "path": str(path),
                    "line": lineno,
                    "detail": url[:160],
                })
        if HTTP_URL.search(line) and not DOC_ALLOWLIST.search(line):
            findings.append({
                "severity": "high",
                "check": NAME,
                "title": "Cleartext http:// URL",
                "path": str(path),
                "line": lineno,
                "detail": HTTP_URL.search(line).group(0)[:160],
            })
