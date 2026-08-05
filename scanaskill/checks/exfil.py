"""Check: data exfiltration indicators.

Deterministic observation of patterns that move data OUT: credentialed
webhook sinks, local-secret reads piped to network, environment variables
interpolated into URLs, and paste-style upload services. A webhook URL is
not proof of theft (notifications exist) — the finding names the sink and
lets the human judge. Local-secret-read + network on the same line is
escalated because that combination has no benign reading.
"""

import re

from ..common import read_lines

NAME = "exfil"
TITLE = "Data exfiltration indicators"

# credentialed sinks commonly used to ship stolen data
WEBHOOK_SINKS = [
    (r"discord\.com/api/webhooks", "Discord webhook"),
    (r"hooks\.slack\.com", "Slack webhook"),
    (r"api\.telegram\.org/bot", "Telegram bot API"),
    (r"webhook\.site|requestbin\.com", "Request bin"),
    (r"pipedream\.com|make\.com/webhooks|zapier\.com/hooks|n8n\.cloud/webhook", "Automation webhook"),
]

# upload / paste services
UPLOAD_SINKS = [
    (r"pastebin\.com", "Pastebin"),
    (r"gist\.githubusercontent\.com", "GitHub Gist"),
    (r"transfer\.sh|0x0\.st|file\.io|termbin\.com|dpaste\.org", "File drop"),
]

# reading local secrets, then sending them somewhere
LOCAL_SECRET_READ = re.compile(
    r"(?:cat|curl|type|more|less|head|tail)\s+"
    r"(?:~?/?(?:\.ssh|\.aws|\.env|\.git-credentials|\.netrc|\.npmrc|\.pypirc)"
    r"|/etc/(?:passwd|shadow|hosts|secrets?)|[\"']?\$?(?:AWS_|GITHUB_|GH_|OPENAI_|ANTHROPIC_|STRIPE_)[A-Z_]*[\"']?)",
    re.IGNORECASE,
)

# environment / command interpolation inside a URL = dynamic exfiltration
ENV_IN_URL = re.compile(r"https?://[^\s\"'`\)\]]*(?:\$\([^)]*\)|\$\{[^}]*\})")

NETWORK_WORD = re.compile(r"\b(?:curl|wget|nc|netcat|fetch|requests\.(?:post|get)|httpx|Invoke-WebRequest)\b")

# cheap gate
_PREFILTER = re.compile(
    r"curl|wget|http|webhook|pastebin|gist|transfer\.sh|0x0|file\.io|termbin|dpaste|"
    r"\.ssh|\.aws|\.env|\.netrc|\.npmrc|\.pypirc|git-credentials|/etc/|\$\(",
    re.IGNORECASE,
)


def run(path, findings):
    lines = read_lines(path)
    for lineno, line in enumerate(lines, 1):
        if not _PREFILTER.search(line):
            continue
        line_lower = line.lower()
        has_network = bool(NETWORK_WORD.search(line))

        # credentialed webhook sinks
        for rx, label in WEBHOOK_SINKS:
            if re.search(rx, line_lower):
                findings.append({
                    "severity": "high",
                    "check": NAME,
                    "title": f"Exfiltration sink: {label}",
                    "path": str(path),
                    "line": lineno,
                    "detail": line.strip()[:160],
                })

        # paste/upload services
        for rx, label in UPLOAD_SINKS:
            if re.search(rx, line_lower) and has_network:
                findings.append({
                    "severity": "medium",
                    "check": NAME,
                    "title": f"Upload sink: {label}",
                    "path": str(path),
                    "line": lineno,
                    "detail": line.strip()[:160],
                })

        # env/command interpolation in URLs
        if ENV_IN_URL.search(line):
            findings.append({
                "severity": "high",
                "check": NAME,
                "title": "Environment/command interpolation in URL",
                "path": str(path),
                "line": lineno,
                "detail": line.strip()[:160],
            })

        # local secret read + network on the same line: no benign reading
        if LOCAL_SECRET_READ.search(line) and has_network:
            findings.append({
                "severity": "critical",
                "check": NAME,
                "title": "Local secret read piped to network",
                "path": str(path),
                "line": lineno,
                "detail": line.strip()[:160],
            })
        elif LOCAL_SECRET_READ.search(line) and not has_network:
            findings.append({
                "severity": "medium",
                "check": NAME,
                "title": "Reads local secret file",
                "path": str(path),
                "line": lineno,
                "detail": line.strip()[:160],
            })
