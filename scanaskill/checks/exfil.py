"""Check: data exfiltration indicators (v2 — destination-aware).

Deterministic observation of patterns that move data OUT: credentialed
webhook sinks, local-secret reads piped to network, environment
variables interpolated into URLs, and paste-style upload services.

v2 changes:
- Official API hosts (api.telegram.org, tenor.googleapis.com, ...) are
  trusted destinations when the credential is env/config-shaped: a bot
  calling its own official API with a configured token is the skill
  working as designed, downgraded to info. Command substitution
  ($(cat ~/.env)) and local-secret reads keep full severity on ANY
  host — the exfiltration shape.
- Environment-variable interpolation in URLs is split from command
  substitution: env vars on non-official hosts are medium; command
  substitution is high; secret-read + network stays critical.

A webhook URL is not proof of theft (notifications exist) — the finding
names the sink and lets the human judge.
"""

import re

from ..common import read_lines
from ..context import LineContext, code_region
from .network import _host_of

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

# official API hosts: the credential's own service, not an exfil target
OFFICIAL_API_HOSTS = frozenset({
    "api.telegram.org", "tenor.googleapis.com", "api.openai.com",
    "api.anthropic.com", "api.github.com", "api.stripe.com",
    "api.slack.com", "api.discord.com", "api.google.com",
    "oauth2.googleapis.com", "api.together.ai", "api.groq.com",
    "api.mistral.ai", "api.cohere.com", "api.gemini.google.com",
    "api.giphy.com", "api.cloudflare.com", "api.vercel.com",
})

# v3: reading local secrets, then sending them somewhere. Reader verbs
# expanded: openssl -in, gpg -d, base64 -d, strings, xxd, tar/unzip,
# scp/rsync/sftp (which both read and transmit).
LOCAL_SECRET_READ = re.compile(
    r"(?:cat|curl|type|more|less|head|tail|strings|xxd|base64\s+-d|scp|rsync|sftp|zipinfo|unzip|"
    r"openssl\s+(?:enc\s+)?(?:-[A-Za-z0-9]+\s+)*-in|gpg\s+(?:-d|--decrypt)|"
    r"tar\s+[^|\n]*\s+-x)\s+"
    r"(?:~?/?(?:\.ssh|\.aws|\.env|\.git-credentials|\.netrc|\.npmrc|\.pypirc)"
    r"|/etc/(?:passwd|shadow|hosts|secrets?)|[\"']?\$?(?:AWS_|GITHUB_|GH_|OPENAI_|ANTHROPIC_|STRIPE_)[A-Z_]*[\"']?)",
    re.IGNORECASE,
)

# environment variable / f-string interpolation inside a URL
ENV_VAR_IN_URL = re.compile(
    r"https?://[^\s\"'`\)\]]*(?:\$\{[^}]*\}|\$[A-Z_][A-Z0-9_]*|\{[A-Z_][A-Z0-9_]*\})"
)
# command substitution inside a URL — dynamic exfiltration shape
CMD_IN_URL = re.compile(r"https?://[^\s\"'`\)\]]*\$\(")

NETWORK_WORD = re.compile(r"\b(?:curl|wget|nc|netcat|fetch|requests\.(?:post|get)|httpx|scp|rsync|sftp|Invoke-WebRequest)\b")

# cheap gate
_PREFILTER = re.compile(
    r"curl|wget|http|webhook|pastebin|gist|transfer\.sh|0x0|file\.io|termbin|dpaste|"
    r"\.ssh|\.aws|\.env|\.netrc|\.npmrc|\.pypirc|git-credentials|/etc/|\$\(",
    re.IGNORECASE,
)


def _host_of_url_in_line(line):
    m = re.search(r"https?://[^\s\"'`<>]+", line)
    if not m:
        return ""
    return _host_of(m.group(0))


def _official_ok(line, host):
    """True when the line targets an official API host with an env-shaped
    credential and no secret read — the skill working as designed."""
    if host not in OFFICIAL_API_HOSTS:
        return False
    if CMD_IN_URL.search(line):
        return False
    if LOCAL_SECRET_READ.search(line):
        return False
    if "://" not in line:
        return False
    # require some credential-shaped interpolation to justify the trust:
    # bare official API call without credentials is still informational
    return bool(ENV_VAR_IN_URL.search(line) or re.search(r"\$[A-Z_][A-Z0-9_]*", line))


def run(path, findings):
    lines = read_lines(path)
    ctx = LineContext(lines, path)
    for lineno, line in enumerate(lines, 1):
        if not _PREFILTER.search(line):
            continue
        line_lower = line.lower()
        has_network = bool(NETWORK_WORD.search(line))
        region = code_region(ctx, lineno - 1)

        # credentialed webhook sinks
        for rx, label in WEBHOOK_SINKS:
            if re.search(rx, line_lower):
                host = _host_of_url_in_line(line)
                if _official_ok(line, host):
                    findings.append({
                        "severity": "info",
                        "check": NAME,
                        "title": f"Exfiltration sink: {label} (official API, env-configured)",
                        "path": str(path),
                        "line": lineno,
                        "detail": line.strip()[:160],
                        "region_class": region,
                    })
                else:
                    findings.append({
                        "severity": "high",
                        "check": NAME,
                        "title": f"Exfiltration sink: {label}",
                        "path": str(path),
                        "line": lineno,
                        "detail": line.strip()[:160],
                        "region_class": region,
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
                    "region_class": region,
                })

        # interpolation in URLs: env var vs command substitution
        host = _host_of_url_in_line(line)
        if ENV_VAR_IN_URL.search(line):
            sev = "info" if host in OFFICIAL_API_HOSTS else "medium"
            title = "Environment variable in URL"
            if sev == "info":
                title += " (official API, env-configured)"
            findings.append({
                "severity": sev,
                "check": NAME,
                "title": title,
                "path": str(path),
                "line": lineno,
                "detail": line.strip()[:160],
                "region_class": region,
            })
        if CMD_IN_URL.search(line):
            findings.append({
                "severity": "high",
                "check": NAME,
                "title": "Environment/command interpolation in URL",
                "path": str(path),
                "line": lineno,
                "detail": line.strip()[:160],
                "region_class": region,
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
                "region_class": region,
            })
        elif LOCAL_SECRET_READ.search(line) and not has_network:
            findings.append({
                "severity": "medium",
                "check": NAME,
                "title": "Reads local secret file",
                "path": str(path),
                "line": lineno,
                "detail": line.strip()[:160],
                "region_class": region,
            })
