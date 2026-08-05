"""Check: secrets — known token formats + high-entropy candidates.

Deterministic: regexes for well-known credential formats (gitleaks-style)
plus a Shannon-entropy heuristic for opaque tokens. A match is a FACT
("this string matches AWS key format"), never a claim of compromise.
"""

import os
import re

from ..common import read_lines, shannon_entropy

NAME = "secrets"
TITLE = "Secrets / credentials"

# (regex, label, severity)
PATTERNS = [
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS Access Key", "critical"),
    (r"\bghp_[0-9A-Za-z]{36}\b", "GitHub personal access token", "critical"),
    (r"\bgithub_pat_[0-9A-Za-z_]{22,}\b", "GitHub fine-grained PAT", "critical"),
    (r"\bglpat-[0-9A-Za-z_-]{20,}\b", "GitLab personal access token", "critical"),
    (r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", "Slack token", "critical"),
    (r"\bAIza[0-9A-Za-z\-_]{35}\b", "Google API key", "critical"),
    (r"\bsk_live_[0-9a-zA-Z]{24,}\b", "Stripe live secret key", "critical"),
    (r"\brk_live_[0-9a-zA-Z]{16,}\b", "Stripe restricted key", "high"),
    (r"\bwhsec_[0-9A-Za-z+/=]{20,}\b", "Webhook signing secret", "high"),
    (r"\bsk-proj-[A-Za-z0-9_-]{20,}\b", "OpenAI project API key", "critical"),
    (r"\bsk-ant-[A-Za-z0-9_-]{20,}\b", "Anthropic API key", "critical"),
    (r"\bsk-[A-Za-z0-9]{20,}\b", "OpenAI/Anthropic-style API key", "critical"),
    (r"\bnpm_[A-Za-z0-9]{36}\b", "npm access token", "critical"),
    (r"\bhf_[A-Za-z0-9]{20,}\b", "Hugging Face token", "critical"),
    (r"\bSG\.[A-Za-z0-9_\-\.]{20,}\b", "SendGrid API key", "critical"),
    (r"\bAC[0-9a-f]{32}\b", "Twilio Account SID", "high"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "Private key material", "critical"),
    (r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "JWT", "high"),
    (r"\botpauth://", "TOTP/2FA secret URI", "medium"),
    (r"[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s@]+@", "Credentials in URI (db/queue)", "high"),
]

# explicit secret-like assignments, regardless of value shape.
# NOTE: 'auth' and 'credential' are intentionally NOT included — they appear
# in too many benign contexts (type annotations, SDK objects, headers).
ASSIGN = re.compile(
    r"""^\s*(?:export\s+)?(?:api[_-]?key|apikey|token|secret|password|passwd)s?\s*[:=]\s*['"]?([^\s'"]{8,})""",
    re.IGNORECASE,
)

# entropy gate: high-entropy scanning is meaningful on assignment-like lines
# (x = "...", x: "...") and in code/config files; on prose lines it only
# produces noise (the alphabet, example blobs, word lists). Deterministic.
CODEISH_EXT = {".py", ".js", ".ts", ".sh", ".bash", ".zsh", ".json", ".yaml",
               ".yml", ".toml", ".env", ".ini", ".cfg", ".rb", ".go", ".rs",
               ".php", ".ps1", ".env"}
_ASSIGNISH = re.compile(r"[:=]")
ENTROPY_THRESHOLD = 4.2
ENTROPY_MIN_LEN = 14
# token candidates: alnum clusters with mixed case and/or digits
TOKEN_RX = re.compile(r"[A-Za-z0-9+/=_\-]{14,}")

# placeholder / example markers — not credentials, never flag
PLACEHOLDER = re.compile(
    r"^(?:(?:sk|ghp|hf|npm|glpat|sk-proj-|sk-ant-|xox[baprs]|AKIA|AIza|sk_live|rk_live|whsec|SG\.[A-Za-z0-9]*)[-_.]*(?:\.\.\.|xxx+|your[-_]?(?:key|token)|example|placeholder|here|redacted|<[^>]*>|[A-Z0-9_]{0,6}))$",
    re.IGNORECASE,
)

# cheap gate: secret patterns all start with a distinctive prefix.
# NOTE: this gate must never exclude a line a PATTERN could match — it is
# purely a performance optimization. Entropy has its own gate above.
_PREFILTER = re.compile(
    r"AKIA|ghp_|github_pat|glpat|xox|AIza|sk_|sk-|rk_live|whsec|npm_|hf_|SG\.|"
    r"AC[0-9a-f]|BEGIN|eyJ|otpauth|://|token|secret|key|password|passwd|auth|credential",
    re.IGNORECASE,
)


# single-pass compiled alternation over PATTERNS (fast path)
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
            if PLACEHOLDER.match(m.group(0)):
                continue  # "sk-...", "AKIAXXXX", etc. — examples, not secrets
            label, sev = _label_for(line, m.group(0))
            findings.append({
                "severity": sev,
                "check": NAME,
                "title": label,
                "path": str(path),
                "line": lineno,
                "detail": f"{label}: {m.group(0)[:24]}…",
            })
        m = ASSIGN.search(line)
        if m and m.group(1):
            value = m.group(1)
            # reading from env vars is the RECOMMENDED pattern, not a leak
            if re.search(r"(?i)getenv|environ|GetEnvironmentVariable|process\.env|os\.environ", line):
                continue
            # example/placeholder values ("YOUR_API_KEY", "xxx", "<token>") are
            # documentation, not credentials
            if re.search(r"(?i)your[_\-]?|xxx+|example|placeholder|^<|>$|\.\.\.|redacted", value):
                continue
            findings.append({
                "severity": "high",
                "check": NAME,
                "title": "Secret-like assignment",
                "path": str(path),
                "line": lineno,
                "detail": line.strip()[:120],
            })
        # entropy heuristic on opaque tokens — only when the line LOOKS like
        # an assignment/config (deterministic gate, tested). Avoids flagging
        # prose, and avoids the 36k-findings noise on arbitrary long tokens.
        suffix = os.path.splitext(str(path))[1].lower()
        if _ASSIGNISH.search(line) or suffix in CODEISH_EXT:
            for tok in TOKEN_RX.findall(line):
                if tok.lower() in {"localhost", "authentication", "configuration",
                                   "implementation", "documentation"}:
                    continue
                # a real secret-like token is bounded and dense: 14-64 chars,
                # and NOT a substring of a longer prose run (e.g. a URL path
                # or base64 blob would already be flagged elsewhere).
                if not (ENTROPY_MIN_LEN <= len(tok) <= 64):
                    continue
                if shannon_entropy(tok) >= ENTROPY_THRESHOLD:
                    findings.append({
                        "severity": "low",
                        "check": NAME,
                        "title": "High-entropy token (manual review)",
                        "path": str(path),
                        "line": lineno,
                        "detail": tok[:24] + "…",
                    })
