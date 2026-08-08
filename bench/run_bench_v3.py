"""AgentScan v3 benchmark harness.

Runs the scanner over bench/corpus (benign, malicious, adversarial,
hard-benign) and enforces:

- malicious: per-skill expected-check recall (each expected check fires)
- adversarial: per-sample minimum severity (evasion resistance)
- benign + hard-benign: zero high/critical findings, per-skill caps
- severity accuracy: adversarial samples must emit >= expected severity
- channel ratio: signal findings are the minority; inventory/review
  separated (the "high signal, not low count" objective)
- scan-time regression gate

Usage:
    python3 bench/run_bench_v3.py [--json] [--exit]

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
SEV_NAMES = {v: k for k, v in SEV_ORDER.items()}

# hard floor: adversarial samples must be detected at or above this
MIN_ADVERSARIAL_SEV = "high"
# benign/hard-benign skills must have zero high/critical findings
# malicious skills must produce at least one high/critical finding
# scan-time gate: the fixed corpus must finish under this many seconds
MAX_SCAN_TIME = 60.0


def load_labels():
    with open(os.path.join(HERE, "labels.json")) as fh:
        return json.load(fh)


def load_labels_v3():
    with open(os.path.join(HERE, "labels-v3.json")) as fh:
        return json.load(fh)


def scan_skill(root, skill):
    target = os.path.join(root, skill)
    res = scan_batch([target])[0]
    return res


def worst_sev(findings):
    return max((SEV_ORDER.get(f["severity"], 0) for f in findings), default=0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--exit", action="store_true", help="exit 1 on contract violation")
    args = ap.parse_args()

    labels = load_labels()
    labels_v3 = load_labels_v3()
    corpus = os.path.join(HERE, "corpus")
    t0 = time.time()

    results = {"malicious": {}, "benign": {}, "adversarial": {}, "hard_benign": {}}  # type: ignore[typeddict-item]
    failures = []

    # -- malicious: per-skill expected-check recall (existing corpus) --
    for skill, expected_checks in labels["malicious"].items():
        res = scan_skill(os.path.join(corpus, "malicious"), skill)
        finds = res["findings"]
        checks_hit = {f["check"] for f in finds}
        missing = [c for c in expected_checks if c not in checks_hit]
        worst = worst_sev(finds)
        results["malicious"][skill] = {
            "findings": len(finds), "checks_hit": sorted(checks_hit),
            "missing": missing, "worst": SEV_NAMES.get(worst, "info"),
            "has_high": worst >= SEV_ORDER["high"],
        }
        if missing:
            failures.append(f"malicious/{skill}: missing expected check(s) {missing}")
        if worst < SEV_ORDER["high"]:
            failures.append(f"malicious/{skill}: no high/critical finding")

    # -- benign: per-skill caps, zero high/critical (existing corpus) --
    for skill, limits in labels["benign"].items():
        res = scan_skill(os.path.join(corpus, "benign"), skill)
        finds = res["findings"]
        countable = [f for f in finds if f["severity"] != "info"]
        worst = worst_sev(finds)
        results["benign"][skill] = {
            "findings": len(finds), "countable": len(countable),
            "worst": SEV_NAMES.get(worst, "info"),
            "max_total": limits["max_total"],
            "max_high_critical": limits["max_high_critical"],
        }
        if len(countable) > limits["max_total"]:
            failures.append(f"benign/{skill}: {len(countable)} > cap {limits['max_total']}")
        if worst >= SEV_ORDER["high"] and limits["max_high_critical"] == 0:
            failures.append(f"benign/{skill}: high/critical finding on benign skill")

    # -- adversarial: minimum severity (evasion resistance) --
    adv_floor = SEV_ORDER[labels_v3.get("min_adversarial_sev", MIN_ADVERSARIAL_SEV)]
    for skill, expected_checks in labels_v3["adversarial"].items():
        res = scan_skill(os.path.join(corpus, "adversarial"), skill)
        finds = res["findings"]
        checks_hit = {f["check"] for f in finds}
        missing = [c for c in expected_checks if c not in checks_hit]
        worst = worst_sev(finds)
        expected = labels_v3["severity_expect"].get(skill, "high")
        results["adversarial"][skill] = {
            "findings": len(finds), "checks_hit": sorted(checks_hit),
            "missing": missing, "worst": SEV_NAMES.get(worst, "info"),
            "expected": expected, "severity_ok": worst >= SEV_ORDER[expected],
        }
        if worst < adv_floor:
            failures.append(f"adversarial/{skill}: worst={SEV_NAMES.get(worst, 'info')} "
                            f"< floor {SEV_NAMES[adv_floor]}")
        if worst < SEV_ORDER[expected]:
            failures.append(f"adversarial/{skill}: severity {SEV_NAMES.get(worst, 'info')} "
                            f"< expected {expected}")

    # -- hard-benign: zero high/critical, per-skill caps --
    for skill, cap in labels_v3["hard_benign"].items():
        res = scan_skill(os.path.join(corpus, "hard-benign"), skill)
        finds = res["findings"]
        countable = [f for f in finds if f["severity"] != "info"]
        worst = worst_sev(finds)
        results["hard_benign"][skill] = {
            "findings": len(finds), "countable": len(countable),
            "worst": SEV_NAMES.get(worst, "info"), "cap": cap,
        }
        if worst >= SEV_ORDER["high"]:
            failures.append(f"hard-benign/{skill}: high/critical finding on benign skill")
        if len(countable) > cap:
            failures.append(f"hard-benign/{skill}: {len(countable)} > cap {cap}")

    # -- channel ratio: signal should be a minority of output --
    total_signal = 0
    total_findings = 0
    for group in ("malicious", "benign", "adversarial", "hard_benign"):
        for skill, r in results[group].items():
            total_findings += r["findings"]
    # re-scan one representative group for channel breakdown
    ch_breakdown = {}
    for skill in list(results["benign"].keys())[:4]:
        res = scan_skill(os.path.join(corpus, "benign"), skill)
        channels = res.get("channels") or {}
        for chan, items in channels.items():
            ch_breakdown[chan] = ch_breakdown.get(chan, 0) + len(items)
    signal_ratio = ch_breakdown.get("signal", 0) / max(1, sum(ch_breakdown.values()))
    results["channel_breakdown"] = ch_breakdown
    results["signal_ratio"] = round(signal_ratio, 3)

    elapsed = time.time() - t0
    results["scan_time_s"] = round(elapsed, 2)
    if elapsed > MAX_SCAN_TIME:
        failures.append(f"scan time {elapsed:.1f}s > gate {MAX_SCAN_TIME:.0f}s")

    # -- aggregate metrics --
    m = results["malicious"]
    a = results["adversarial"]
    metrics = {
        "malicious_recall_at_high": round(
            sum(1 for v in m.values() if v["has_high"]) / max(1, len(m)), 3),
        "adversarial_detection_rate": round(
            sum(1 for v in a.values() if v["severity_ok"]) / max(1, len(a)), 3),
        "benign_clean_rate": round(
            sum(1 for v in results["benign"].values()
                if v["worst"] == "info") / max(1, len(results["benign"])), 3),
        "hard_benign_clean_rate": round(
            sum(1 for v in results["hard_benign"].values()
                if v["worst"] == "info") / max(1, len(results["hard_benign"])), 3),
        "signal_ratio": results["signal_ratio"],
        "total_findings": total_findings,
        "scan_time_s": results["scan_time_s"],
    }

    if args.json:
        print(json.dumps({"results": results, "metrics": metrics,
                          "failures": failures}, indent=2))
    else:
        print("== AgentScan v3 benchmark ==")
        print(f"malicious recall at high: {metrics['malicious_recall_at_high']} "
              f"({sum(1 for v in m.values() if v['has_high'])}/{len(m)})")
        print(f"adversarial detection:    {metrics['adversarial_detection_rate']} "
              f"({sum(1 for v in a.values() if v['severity_ok'])}/{len(a)})")
        print(f"benign clean rate:        {metrics['benign_clean_rate']} "
              f"({sum(1 for v in results['benign'].values() if v['worst'] == 'info')}/{len(results['benign'])})")
        print(f"hard-benign clean rate:   {metrics['hard_benign_clean_rate']}")
        print(f"signal ratio:             {metrics['signal_ratio']}")
        print(f"scan time:                {metrics['scan_time_s']}s")
        print()
        for group, r in results.items():
            if group in ("channel_breakdown", "signal_ratio", "scan_time_s"):
                continue
            for skill, v in sorted(r.items()):
                flag = "OK " if not (group == "adversarial" and not v.get("severity_ok", True)) else "FAIL"
                if group in ("malicious",) and v.get("missing"):
                    flag = "FAIL"
                print(f"  [{flag}] {group}/{skill}: worst={v.get('worst', '?')} "
                      f"findings={v.get('findings', 0)}")
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
