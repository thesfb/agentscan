"""Channel separation (v3).

Every finding is assigned to exactly one channel so the report can
separate security signal from inventory, review queues, and compliance.

Channels:
- signal:     security-relevant finding with evidence (the findings list)
- review:     low-confidence signal needing a human (prompt phrasings,
              drift, entropy candidates, SCH shapes)
- inventory:  observations that are useful data but not findings
              (URLs, capabilities, dependencies, loopback notes)
- compliance: license / packaging declarations (not security)
- info:       unclassified low-severity notes (legacy fallback)

A finding's channel is computed from its check, severity, and explicit
markers set by the checks (review: True, user_install: True). The
fingerprint is stable per (check, title, path, line) so baselines and
dedup work across runs.
"""

# checks whose output is inventory by nature (useful data, not findings)
INVENTORY_CHECKS = frozenset({
    "dependencies",          # SBOM seed
    "license",               # compliance, not security
})

# findings marked review: True are review-queue signals, never verdicts
def channel_of(f):
    """The channel for a single finding dict."""
    sev = f.get("severity", "info")
    check = f.get("check", "")
    if f.get("review") or check in ("prompt_patterns", "drift"):
        return "review"
    if check == "license":
        return "compliance"
    if check in INVENTORY_CHECKS:
        return "inventory"
    if f.get("user_install") or sev == "info":
        # user-facing install instructions and info notes are inventory:
        # useful data about the artifact, not security findings.
        return "inventory"
    if sev in ("critical", "high", "medium", "low"):
        return "signal"
    return "info"


def split_channels(findings):
    """Split a finding list into {channel: [findings]} preserving order."""
    out = {}
    for f in findings:
        out.setdefault(channel_of(f), []).append(f)
    return out
