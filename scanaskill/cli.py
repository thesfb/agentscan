"""scanaskill CLI.

Usage:
  python3 -m scanaskill [--json|--sarif] [--severity low|medium|high|critical]
                       [--max-findings N] <path>

Exit codes:
  0  no findings at or above the threshold severity
  1  findings at or above the threshold severity
  2  usage / scan error

Default threshold: medium. Facts below the threshold are still reported
in the human output but do not fail the scan.
"""

import argparse
import json
import os
import sys

from . import __version__
from .scanner import scan_directory

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

COLORS = {
    "critical": "\033[31;1m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[2m",
}
RESET = "\033[0m"


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="scanaskill",
        description="Deterministic security scanner for AI agent artifacts "
                    "(skills, MCP servers, agent configs). Reports observed "
                    "facts; the human owns the verdict.",
    )
    parser.add_argument("path", nargs="?", default=".", help="skill dir or collection to scan")
    parser.add_argument("--json", action="store_true", help="emit JSON only")
    parser.add_argument("--sarif", action="store_true",
                        help="emit SARIF 2.1.0 (GitHub code-scanning compatible)")
    parser.add_argument("--sbom", action="store_true",
                        help="emit a CycloneDX 1.5 SBOM of extracted dependencies")
    parser.add_argument("--osv", action="store_true",
                        help="look up extracted dependencies against the OSV "
                             "vulnerability database (online, opt-in)")
    parser.add_argument("--severity", default="medium",
                        choices=["info", "low", "medium", "high", "critical"],
                        help="minimum severity that fails the scan (default: medium)")
    parser.add_argument("--max-findings", type=int, default=100,
                        help="findings shown in the human report (default: 100; "
                             "0 = all; --json/--sarif always include everything)")
    parser.add_argument("--channels", action="store_true",
                        help="v3: report findings by channel (signal/inventory/"
                             "review/compliance) instead of one flat list")
    parser.add_argument("--profile", choices=["registry", "enterprise", "cli"],
                        default="cli",
                        help="v3: threshold profile. registry = very low FPR "
                             "(high/critical only fail the scan); enterprise = "
                             "medium and above fails; cli = default medium")
    parser.add_argument("--baseline", metavar="FILE",
                        help="v3: compare findings against a baseline "
                             "fingerprint file; exit 1 when new fingerprints "
                             "appear or known ones drift")
    parser.add_argument("--baseline-write", metavar="FILE",
                        help="v3: write the current findings' fingerprints to "
                             "FILE (creates a baseline for --baseline)")
    args = parser.parse_args(argv)

    if not os.path.isdir(args.path):
        print(f"scanaskill: not a directory: {args.path}", file=sys.stderr)
        return 2

    res = scan_directory(args.path)

    # v2: optional OSV lookup — adds findings, never removes them
    if args.osv:
        from .sbom import query_osv
        vulns, errors = query_osv(res.get("dependencies", []))
        osv_findings = []
        for v in vulns:
            osv_findings.append({
                "severity": v["severity"],
                "check": "osv",
                "title": f"Known vulnerability: {v['id']}",
                "path": os.path.join(args.path, v["package"]),
                "line": 0,
                "detail": f"{v['package']} ({v['ecosystem']}): {v['summary']}",
                "confidence": 0.95,
                "origin": "external",
            })
        for e in errors:
            osv_findings.append({
                "severity": "info", "check": "osv",
                "title": "OSV lookup incomplete", "path": args.path, "line": 0,
                "detail": e,
            })
        res["findings"].extend(osv_findings)
        for f in osv_findings:
            res["summary"][f["severity"]] = res["summary"].get(f["severity"], 0) + 1
            res["summary_by_check"][f["check"]] = res["summary_by_check"].get(f["check"], 0) + 1

    if args.sbom:
        from .sbom import cyclonedx
        print(json.dumps(cyclonedx(
            os.path.basename(os.path.abspath(args.path)),
            res.get("dependencies", []),
            tool_version=__version__,
        ), indent=2))
        return 0

    # v3: baseline write/check — fingerprints are stable per finding
    if args.baseline_write:
        _write_baseline(args.baseline_write, res["findings"])

    if args.sarif:
        print(json.dumps(_sarif(res), indent=2))
    elif args.json:
        print(json.dumps(res, indent=2))
    else:
        _human_report(res, args.max_findings, channels=args.channels)

    # v3: threshold profile — registry profile fails only on high/critical,
    # enterprise on medium+, cli keeps the --severity default.
    threshold = SEV_ORDER[args.severity]
    if args.profile == "registry":
        threshold = SEV_ORDER["high"]
    elif args.profile == "enterprise":
        threshold = SEV_ORDER["medium"]

    if args.baseline:
        new, drifted = _check_baseline(args.baseline, res["findings"])
        for f in new:
            print(f"  NEW fingerprint: [{f['check']}] {f['title']} "
                  f"{os.path.relpath(f['path'], res['target'])}:{f['line']}")
        for f in drifted:
            print(f"  DRIFTED fingerprint: [{f['check']}] {f['title']} "
                  f"{os.path.relpath(f['path'], res['target'])}:{f['line']}")
        return 1 if (new or drifted) else 0

    worst = max((SEV_ORDER[f["severity"]] for f in res["findings"]), default=0)
    return 1 if worst >= threshold else 0


def _write_baseline(path, findings):
    """Write {fingerprint: {check, title, path, line}} to a JSON baseline."""
    with open(path, "w") as fh:
        json.dump({f["fingerprint"]: {
            "check": f["check"], "title": f["title"],
            "path": f["path"], "line": f["line"],
        } for f in findings}, fh, indent=2, sort_keys=True)
    print(f"wrote baseline: {path} ({len(findings)} fingerprints)")


def _check_baseline(path, findings):
    """Compare findings against a baseline. Returns (new, drifted)."""
    try:
        with open(path) as fh:
            base = json.load(fh)
    except (OSError, ValueError):
        print(f"scanaskill: cannot read baseline {path}", file=sys.stderr)
        return [], []
    current = {f["fingerprint"]: f for f in findings}
    new = [f for fp, f in current.items() if fp not in base]
    drifted = []
    for fp, b in base.items():
        if fp not in current:
            continue  # gone — not a failure (baselines accept removals)
        c = current[fp]
        if c["line"] != b.get("line") or c["path"] != b.get("path"):
            drifted.append(c)
    return new, drifted


def _human_report(res, max_findings, channels=False):
    print(f"scanaskill {__version__} — {res['target']}")
    print(f"scanned {len(res['skills'])} artifact(s), {len(res['findings'])} finding(s)\n")

    for skill in res["skills"]:
        name = skill["name"]
        fmt = skill.get("format", "generic")
        desc = f" — {skill['description'][:70]}" if skill.get("description") else ""
        print(f"  ARTIFACT  [{fmt}] {name}{desc}")

    if not res["findings"]:
        print("\n  no findings. clean.")
        return

    if channels:
        _human_report_by_channel(res, max_findings)
        return

    print()
    shown = res["findings"] if max_findings == 0 else res["findings"][:max_findings]
    for f in shown:
        color = COLORS.get(f["severity"], "")
        rel = os.path.relpath(f["path"], res["target"])
        loc = f"{rel}:{f['line']}" if f["line"] else rel
        print(f"  {color}{f['severity'].upper():8s}{RESET} [{f['check']}] {f['title']}")
        print(f"           {loc}")
        if f.get("detail"):
            print(f"           {f['detail']}")
    if max_findings and len(res["findings"]) > max_findings:
        print(f"\n  … {len(res['findings']) - max_findings} more finding(s) "
              f"(use --max-findings 0 or --json for all)")

    s = res["summary"]
    print(f"\n  summary: critical={s['critical']} high={s['high']} "
          f"medium={s['medium']} low={s['low']} info={s['info']}")
    print("  per check: " + ", ".join(
        f"{k}={v}" for k, v in sorted(res["summary_by_check"].items())))

    caps = res.get("capabilities") or {}
    if caps:
        print("\n  capabilities:")
        for cap, locs in caps.items():
            print(f"    {cap:24s} {', '.join(locs[:4])}"
                  + (" …" if len(locs) > 4 else ""))

    review = res.get("review_queue") or []
    if review:
        print("\n  review queue (manual review — never a verdict):")
        for f in review[:10]:
            rel = os.path.relpath(f["path"], res["target"])
            print(f"    {f['severity'].upper():8s} [{f['check']}] "
                  f"{f['title'][:70]} — {rel}:{f['line']}")
        if len(review) > 10:
            print(f"    … {len(review) - 10} more")

    print("  note: findings are observed patterns, not verdicts. "
          "Review each before acting.\n")


def _human_report_by_channel(res, max_findings):
    """v3: render signal / review / inventory / compliance separately."""
    ch = res.get("channels") or {}
    order = ["signal", "review", "inventory", "compliance", "info"]
    for chan in order:
        items = ch.get(chan) or []
        if not items:
            continue
        label = {
            "signal": "SECURITY FINDINGS (signal)",
            "review": "REVIEW QUEUE (low confidence — human decides)",
            "inventory": "INVENTORY (observed facts, not findings)",
            "compliance": "COMPLIANCE (license/packaging)",
            "info": "INFO",
        }[chan]
        print(f"\n  {label} — {len(items)}")
        shown = items if max_findings == 0 else items[:max_findings]
        for f in shown:
            color = COLORS.get(f["severity"], "")
            rel = os.path.relpath(f["path"], res["target"])
            loc = f"{rel}:{f['line']}" if f["line"] else rel
            print(f"    {color}{f['severity'].upper():8s}{RESET} [{f['check']}] {f['title']}")
            if f.get("detail"):
                print(f"             {f['detail'][:100]}")
        if max_findings and len(items) > max_findings:
            print(f"    … {len(items) - max_findings} more")

    print("\n  note: signal = security facts with evidence; inventory = "
          "observations (URLs, capabilities, dependencies); review = "
          "low-confidence signals. Findings are observed patterns, not "
          "verdicts.\n")


def _sarif(res):
    """SARIF 2.1.0 — level mapping: critical/high→error, medium→warning, low/info→note."""
    rules = []
    rule_ids = {}
    for name, count in sorted(res["summary_by_check"].items()):
        rules.append({
            "id": name,
            "name": name,
            "shortDescription": {"text": f"scanaskill check: {name} ({count} hit(s))"},
            "properties": {"tags": ["scanaskill", name]},
        })
        rule_ids[name] = len(rule_ids)

    results = []
    for f in res["findings"]:
        level = "error" if f["severity"] in ("critical", "high") else \
                "warning" if f["severity"] == "medium" else "note"
        uri = os.path.relpath(f["path"], res["target"])
        r = {
            "ruleId": f["check"],
            "level": level,
            "message": {"text": f"{f['title']} — {f.get('detail', '')}"[:300]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": f["line"]} if f["line"] else {},
                }
            }],
            "properties": {"severity": f["severity"], "check": f["check"]},
        }
        results.append(r)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "scanaskill",
                    "version": __version__,
                    "informationUri": "https://github.com/baldbee/scanaskill",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }


def run() -> None:
    """Console-script entry point (pyproject: scanaskill = scanaskill.cli:run)."""
    sys.exit(main())


if __name__ == "__main__":
    run()
