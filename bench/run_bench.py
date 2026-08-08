"""AgentScan v2 benchmark harness.

Runs the scanner over the bench/corpus (benign + malicious skills),
computes precision/recall/FPR/severity-accuracy/scan-time, and fails
the run when the contract is violated. The contract prevents the
scanner from being "improved" by going quiet.

Usage:
    python3 bench/run_bench.py [--json] [--exit]

Exit code 1 when any contract check fails.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from scanaskill.scanner import scan_batch  # noqa: E402

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Minimum recall per behavior class: the scanner must fire at least one
# finding from each expected check on each malicious skill.
MIN_CLASS_RECALL = 1.0
# Malicious skills must produce at least one high/critical finding.
MIN_MALICIOUS_HIGH = 1.0


def load_labels():
    with open(os.path.join(HERE, "labels.json")) as fh:
        return json.load(fh)


def scan_skill(root, skill):
    """Scan one skill dir; returns its findings."""
    target = os.path.join(root, skill)
    res = scan_batch([target])[0]
    return res["findings"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--exit", action="store_true", help="exit 1 on contract violation")
    args = ap.parse_args()

    labels = load_labels()
    corpus = os.path.join(HERE, "corpus")
    t0 = time.time()

    results = {"benign": {}, "malicious": {}}
    failures = []

    # -- malicious: per-skill recall over expected checks -------------
    for skill, expected_checks in labels["malicious"].items():
        finds = scan_skill(os.path.join(corpus, "malicious"), skill)
        checks_hit = {f["check"] for f in finds}
        missing = [c for c in expected_checks if c not in checks_hit]
        worst = max((SEV_ORDER.get(f["severity"], 0) for f in finds), default=0)
        has_high = worst >= SEV_ORDER["high"]
        results["malicious"][skill] = {
            "findings": len(finds),
            "checks_hit": sorted(checks_hit),
            "missing": missing,
            "worst": [s for s, o in sorted(SEV_ORDER.items(), key=lambda kv: kv[1]) if o == worst][-1],
            "has_high": has_high,
        }
        if missing:
            failures.append(f"malicious/{skill}: missing expected check(s) {missing}")
        if not has_high:
            failures.append(f"malicious/{skill}: no high/critical finding")

    # -- benign: per-skill caps (info findings — capability notes — are
    # by design and do not count against the noise cap) --------------
    for skill, limits in labels["benign"].items():
        finds = scan_skill(os.path.join(corpus, "benign"), skill)
        countable = [f for f in finds if f["severity"] != "info"]
        worst = max((SEV_ORDER.get(f["severity"], 0) for f in finds), default=0)
        has_high = worst >= SEV_ORDER["high"]
        results["benign"][skill] = {
            "findings": len(finds),
            "countable": len(countable),
            "checks": sorted({f["check"] for f in finds}),
            "max_total": limits["max_total"],
            "max_high_critical": limits["max_high_critical"],
        }
        if len(countable) > limits["max_total"]:
            failures.append(
                f"benign/{skill}: {len(countable)} findings > cap {limits['max_total']}")
        if has_high and limits["max_high_critical"] == 0:
            failures.append(f"benign/{skill}: high/critical finding on benign skill")

    elapsed = time.time() - t0
    results["scan_time_s"] = round(elapsed, 2)

    # -- aggregate metrics ---------------------------------------------
    m_finds = [v["findings"] for v in results["malicious"].values()]
    b_finds = [v["findings"] for v in results["benign"].values()]
    tp = sum(1 for v in results["malicious"].values() if v["has_high"])
    total_m = len(results["malicious"])
    fp_skills = sum(1 for v in results["benign"].values() if v["max_high_critical"] == 0 and v["findings"] > 0)
    total_b = len(results["benign"])
    metrics = {
        "malicious_skills": total_m,
        "benign_skills": total_b,
        "malicious_high_findings": tp,
        "malicious_recall_at_high": round(tp / total_m, 3) if total_m else 1.0,
        "benign_with_any_finding": fp_skills,
        "benign_clean_rate": round(1 - fp_skills / total_b, 3) if total_b else 1.0,
        "total_findings_malicious": sum(m_finds),
        "total_findings_benign": sum(b_finds),
        "scan_time_s": results["scan_time_s"],
    }

    if args.json:
        print(json.dumps({"results": results, "metrics": metrics,
                          "failures": failures}, indent=2))
    else:
        print("== AgentScan v2 benchmark ==")
        print(f"malicious skills: {total_m}, benign skills: {total_b}")
        print(f"malicious skills with high/critical finding: {tp}/{total_m}")
        print(f"benign skills with zero findings: {total_b - fp_skills}/{total_b}")
        print(f"total findings: malicious={sum(m_finds)} benign={sum(b_finds)}")
        print(f"scan time: {elapsed:.2f}s")
        print()
        for skill, r in sorted(results["malicious"].items()):
            flag = "OK " if not r["missing"] and r["has_high"] else "FAIL"
            print(f"  [{flag}] malicious/{skill}: {r['findings']} findings, "
                  f"worst={r['worst']}, missing={r['missing'] or '-'}")
        for skill, r in sorted(results["benign"].items()):
            flag = "OK " if r["countable"] <= r["max_total"] else "FAIL"
            print(f"  [{flag}] benign/{skill}: {r['countable']} findings "
                  f"(cap {r['max_total']}), checks={r['checks'] or '-'}")
        if failures:
            print()
            for f in failures:
                print(f"  CONTRACT FAIL: {f}")
        print()
        print("metrics:", json.dumps(metrics))

    if args.exit and failures:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
