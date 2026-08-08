"""Check: network egress (v2 — destination-trust tiered).

Deterministic observation of outbound network primitives and URLs. v2
change: destinations are classified into trust tiers (loopback,
private, metadata, official-API/doc allowlist, public-unknown) and
severity follows the tier. A URL to 127.0.0.1 is the machine itself —
informational, not an exfiltration signal. A cleartext URL to a public
host stays high. One finding per URL, at the highest applicable class,
instead of one finding per pattern class.

A skill that makes network calls is not inherently bad — but an agent
skill that sends data somewhere is exactly the class of thing a
reviewer must know about. Token-in-URL patterns are escalated.
"""

import ipaddress
import re

from ..common import read_lines
from ..context import LineContext, code_region

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

URL = re.compile(r"https?://[^\s\"'`<>]+")
TOKEN_IN_URL = re.compile(
    r"https?://[^\s\"'`\)\]]*(token|key|secret|auth|password|api[_-]?key)=[^\s&\"'`\)\]]+",
    re.IGNORECASE,
)
HTTP_URL = re.compile(r"http://[^\s\"'`\)\]]+")

# risky URL structures (facts, not verdicts)
USERINFO = re.compile(r"https?://[^/\s:@]+:[^/\s@]+@")
METADATA_HOST = re.compile(
    r"https?://(?:169\.254\.169\.254|metadata\.google\.internal|instance-data|"
    r"metadata\.azure\.internal|169\.254\.170\.2)",
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

# placeholder hosts that stand in for a real host in examples/docs.
# v3: brace-wrapped ({host}, {args.host}), dotted, and $VAR (incl.
# ${VAR:-default} parameter expansion) forms are placeholders too —
# the old regex let them fall through to "public" and produced
# cleartext HIGH findings on legitimately templated hosts.
PLACEHOLDER_HOST = re.compile(
    r"^[A-Z_][A-Z0-9_]*$|^<[^>]+>$|^\$[A-Za-z_][A-Za-z0-9_]*$"
    r"|^\{[A-Za-z_][A-Za-z0-9_.]*\}$"
    r"|^\$\{[A-Za-z_][A-Za-z0-9_]*:?[-]?[^}]*\}$",
    re.IGNORECASE,
)

_PREFILTER = re.compile(
    r"http|curl|wget|fetch|requests|axios|httpx|urllib|socket|XHR|WebSocket|Invoke-",
    re.IGNORECASE,
)

_COMBINED = re.compile("|".join(rx for rx, _ in PRIMITIVES))


def _label_for(group):
    for rx, lbl in PRIMITIVES:
        if re.search(rx, group):
            return lbl
    return "unknown"


def _host_of(url):
    """Host portion of a URL (after scheme, before path/port), lowercased."""
    rest = url.split("://", 1)[1] if "://" in url else url
    rest = rest.split("/", 1)[0]
    rest = rest.split("@")[-1]  # strip userinfo
    if ":" in rest and not rest.endswith("]") and not rest.startswith("["):
        # strip a numeric port, or a ${VAR:-default} port form. The
        # parameter expansion itself contains ':' (${VAR:-9222}), so
        # handle it as one token before splitting on the last ':'.
        if "${" in rest:
            # host:${VAR:-default} — take everything before the port colon
            head = rest.split(":", 1)[0]
            rest = head
        else:
            tail = rest.rsplit(":", 1)[1]
            if tail.rstrip(".").isdigit():
                rest = rest.rsplit(":", 1)[0]
    return rest.strip().lower().rstrip(".")


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def host_tier(host):
    """Classify a host into a trust tier.

    Returns one of: metadata, loopback, private, placeholder, public.
    """
    if not host:
        return "placeholder"
    if _is_ip(host):
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return "public"
        if ip.is_loopback:
            return "loopback"
        if ip.is_link_local:
            return "metadata" if host.startswith("169.254.169.254") else "private"
        if ip.is_private or ip.is_reserved:
            return "private"
        return "public"
    if host == "localhost" or host.endswith(".localhost"):
        return "loopback"
    if PLACEHOLDER_HOST.match(host):
        return "placeholder"
    return "public"


def _tier_detail(tier):
    return {
        "loopback": "loopback host (the machine itself)",
        "private": "private/network-local host",
        "metadata": "cloud metadata service",
        "placeholder": "placeholder host",
    }.get(tier, "")


def run(path, findings):
    lines = read_lines(path)
    ctx = LineContext(lines, path)
    for lineno, line in enumerate(lines, 1):
        if not _PREFILTER.search(line):
            continue
        lang_ctx = ctx.fence_lang[lineno - 1] or ctx.script
        for m in _COMBINED.finditer(line):
            if not lang_ctx:
                continue  # prose mention, not an invocation (docs vs code)
            label = _label_for(m.group(0))
            findings.append({
                "severity": "medium",
                "check": NAME,
                "title": f"Network primitive: {label}",
                "path": str(path),
                "line": lineno,
                "detail": line.strip()[:160],
                "region_class": code_region(ctx, lineno - 1),
            })
        if "://" not in line and not line.lower().startswith("http"):
            continue
        # one finding per URL, at the highest applicable class
        for m in URL.finditer(line):
            url = m.group(0)
            if DOC_ALLOWLIST.search(url):
                continue
            host = _host_of(url)
            tier = host_tier(host)
            detail = url[:160]
            if TOKEN_IN_URL.search(url):
                findings.append({
                    "severity": "high", "check": NAME,
                    "title": "Credential in URL", "path": str(path),
                    "line": lineno, "detail": detail,
                    "region_class": code_region(ctx, lineno - 1),
                })
            elif USERINFO.search(url):
                findings.append({
                    "severity": "high", "check": NAME,
                    "title": "Credentials embedded in URL", "path": str(path),
                    "line": lineno, "detail": detail,
                    "region_class": code_region(ctx, lineno - 1),
                })
            elif METADATA_HOST.search(url) or tier == "metadata":
                findings.append({
                    "severity": "high", "check": NAME,
                    "title": "Internal/metadata host URL", "path": str(path),
                    "line": lineno, "detail": detail,
                    "region_class": code_region(ctx, lineno - 1),
                })
            elif tier == "loopback" or tier == "private":
                hostlabel = "IP-literal" if _is_ip(host) else "Internal"
                findings.append({
                    "severity": "info", "check": NAME,
                    "title": f"{hostlabel} URL ({tier} host)",
                    "path": str(path), "line": lineno, "detail": detail,
                    "region_class": code_region(ctx, lineno - 1),
                })
            elif SHORTENER.search(url):
                findings.append({
                    "severity": "medium", "check": NAME,
                    "title": "URL shortener", "path": str(path),
                    "line": lineno, "detail": detail,
                    "region_class": code_region(ctx, lineno - 1),
                })
            elif RAW_HOST.search(url):
                findings.append({
                    "severity": "medium", "check": NAME,
                    "title": "Hosted raw content URL", "path": str(path),
                    "line": lineno, "detail": detail,
                    "region_class": code_region(ctx, lineno - 1),
                })
            else:
                # plain https URL: informational
                sev = "info"
                title = "URL in skill"
                if url.startswith("http://"):
                    if tier == "public":
                        sev, title = "high", "Cleartext http:// URL"
                    elif tier == "placeholder":
                        sev, title = "info", "Cleartext http:// URL (placeholder host)"
                    else:
                        sev, title = "info", "Cleartext http:// URL (local host)"
                findings.append({
                    "severity": sev, "check": NAME,
                    "title": title, "path": str(path),
                    "line": lineno, "detail": detail,
                    "region_class": code_region(ctx, lineno - 1),
                })
