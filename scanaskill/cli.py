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
    parser.add_argument("--severity", default="medium",
                        choices=["info", "low", "medium", "high", "critical"],
                        help="minimum severity that fails the scan (default: medium)")
    parser.add_argument("--max-findings", type=int, default=100,
                        help="findings shown in the human report (default: 100; "
                             "0 = all; --json/--sarif always include everything)")
    args = parser.parse_args(argv)

    if not os.path.isdir(args.path):
        print(f"scanaskill: not a directory: {args.path}", file=sys.stderr)
        return 2

    res = scan_directory(args.path)

    if args.sarif:
        print(json.dumps(_sarif(res), indent=2))
    elif args.json:
        print(json.dumps(res, indent=2))
    else:
        _human_report(res, args.max_findings)

    threshold = SEV_ORDER[args.severity]
    worst = max((SEV_ORDER[f["severity"]] for f in res["findings"]), default=0)
    return 1 if worst >= threshold else 0


def _human_report(res, max_findings):
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
    print("  note: findings are observed patterns, not verdicts. "
          "Review each before acting.\n")


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


if __name__ == "__main__":
    sys.exit(main())
