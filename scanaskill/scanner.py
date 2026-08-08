"""Scanner orchestrator: walk a directory, run all checks, aggregate.

The scanner reports OBSERVED FACTS with suggested severities. It never
labels a skill "malicious" — that verdict belongs to the human. Findings
carry file + line so every claim is checkable by hand.
"""

import os
import re
from concurrent.futures import ProcessPoolExecutor
from math import ceil
import multiprocessing

from . import checks
from .checks import (  # noqa: F401 — importing registers the modules
    analysis,
    config_tamper,
    dependencies,
    exfil,
    filesystem,
    license as license_check,
    network,
    obfuscation,
    prompt_patterns,
    secrets,
    shell,
    supply_chain,
)
from .common import SEVERITIES, SEV_ORDER, IGNORED_FILES, _PathLike, is_text_file

CHECK_MODULES = [
    shell,
    filesystem,
    network,
    secrets,
    license_check,
    supply_chain,
    prompt_patterns,
    exfil,
    obfuscation,
    config_tamper,
    dependencies,
    analysis,  # v2: runs last — reads sibling findings for correlation
]

# v2: capability -> evidence aggregation for the report
CAPABILITY_ORDER = (
    "secret.access", "network.upload", "network.connect", "process.exec",
    "code.exec", "persistence", "privilege.change", "filesystem.delete",
    "filesystem.write", "filesystem.read", "env.read", "package.install",
    "tool.invoke", "secret.write",
)

# sanity caps: pathological files should not stall a scan
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_FILE_LINES = 100_000
# per-file finding cap: one pathological file (e.g. a 15k-URL prompt JSON)
# must not dominate a scan or inflate corpus stats.
MAX_FINDINGS_PER_FILE = 200


def _detect_format(root, target):
    """Classify a scanned directory into an agent-artifact format.

    Deterministic, filename-based. SKILL.md → claude-skill; mcp configs →
    mcp-server; .cursor rules → cursor-rules; root AGENTS.md/CLAUDE.md →
    context-file; workflows → github-actions; package.json → npm-package.
    """
    root = os.path.abspath(root)
    names = set(os.listdir(root)) if os.path.isdir(root) else set()
    if "SKILL.md" in names:
        return "claude-skill"
    if ".mcp.json" in names or "mcp.json" in names:
        return "mcp-server"
    if ".cursor" in names and os.path.isdir(os.path.join(root, ".cursor")):
        return "cursor-rules"
    if "AGENTS.md" in names or "CLAUDE.md" in names:
        return "context-file"
    if ".github" in names:
        return "github-actions"
    if "package.json" in names:
        return "npm-package"
    return "generic"


def _parse_frontmatter(path):
    """Return (name, description) from SKILL.md frontmatter, best-effort."""
    name = os.path.basename(path)
    description = ""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        if lines and lines[0].strip() == "---":
            for line in lines[1:]:
                if line.strip() == "---":
                    break
                low = line.lower()
                if low.startswith("name:"):
                    name = line.split(":", 1)[1].strip().strip('"\'')
                elif low.startswith("description:"):
                    description = line.split(":", 1)[1].strip().strip('"\'')
    except OSError:
        pass
    return name, description


def _scan_batch(files):
    """Scan a batch of files (one process worker); returns the findings list."""
    out = []
    for fp in files:
        try:
            if os.path.getsize(fp) > MAX_FILE_BYTES:
                continue
            before = len(out)
            for mod in CHECK_MODULES:
                try:
                    if mod.NAME == "analysis":
                        # correlation reads the same-file findings so far
                        mod.run(fp, out, before)
                    else:
                        mod.run(fp, out)
                except Exception as e:  # a broken check must not kill the scan
                    out.append({
                        "severity": "info",
                        "check": mod.NAME,
                        "title": "check error: {}".format(e),
                        "path": fp,
                        "line": 0,
                        "detail": "internal error in scanner check — report this",
                    })
            # v2: per-file dedup — identical (check, title, line) findings
            # collapse to one (same pattern matching the same line twice,
            # or two patterns labeling the same event). The first finding
            # wins; correlation (Phase 3) re-derives merged evidence.
            out = _dedup_file(out, before)
            # v2: enrich every finding with confidence/evidence/fingerprint
            for f in out[before:]:
                _enrich(f)
            # cap findings per file so pathological files can't dominate
            if len(out) - before > MAX_FINDINGS_PER_FILE:
                del out[before + MAX_FINDINGS_PER_FILE:]
                out.append({
                    "severity": "info",
                    "check": "cap",
                    "title": "finding cap reached for file",
                    "path": fp,
                    "line": 0,
                    "detail": "file exceeded {} findings — results truncated".format(MAX_FINDINGS_PER_FILE),
                })
        except OSError:
            continue
    return out


def _dedup_file(findings, start):
    """Collapse findings within one file that share (check, title, line).

    The first occurrence is kept; identical repeats are dropped. This
    removes the same-title-twice-on-one-line noise class without losing
    distinct behaviors (different checks/titles/lines survive).
    """
    if len(findings) - start < 2:
        return findings
    seen = set()
    kept = []
    for f in findings[start:]:
        key = (f["check"], f["title"], f["line"])
        if key in seen:
            continue
        seen.add(key)
        kept.append(f)
    return findings[:start] + kept


# default confidence per check (calibrated in the benchmark)
_BASE_CONFIDENCE = {
    "secrets": 0.9, "exfil": 0.9, "obfuscation": 0.9, "filesystem": 0.85,
    "supply_chain": 0.85, "network": 0.8, "config_tamper": 0.8,
    "prompt_patterns": 0.5, "shell": 0.8, "analysis": 0.85,
    "cap": 1.0, "license": 0.95,
}


def _enrich(f):
    """v2 finding model: every finding carries confidence, evidence,
    fingerprint, origin, and (where known) capability and region_class."""
    if "confidence" not in f:
        f["confidence"] = _BASE_CONFIDENCE.get(f["check"], 0.8)
        if f.get("severity") == "info":
            f["confidence"] = min(f["confidence"], 0.7)
    if "evidence" not in f:
        f["evidence"] = [{
            "file": f["path"], "line": f["line"], "snippet": f.get("detail", ""),
        }]
    if "origin" not in f:
        f["origin"] = "deterministic"
    if "fingerprint" not in f:
        import hashlib
        key = "{}|{}|{}|{}".format(f["check"], f["title"], f["path"], f["line"])
        f["fingerprint"] = hashlib.sha1(key.encode()).hexdigest()[:16]
    return f


def _aggregate_capabilities(findings):
    """{capability: [file:line ...]} for a target's findings."""
    caps = {}
    for f in findings:
        cap = f.get("capability")
        if not cap:
            continue
        loc = "{}:{}".format(os.path.basename(f["path"]), f["line"])
        caps.setdefault(cap, []).append(loc)
    return {c: caps[c] for c in CAPABILITY_ORDER if c in caps}


def _sbom_components(findings):
    """Deduplicated dependency list for the SBOM, from dependency fields."""
    comps = {}
    for f in findings:
        dep = f.get("dependency")
        if not dep:
            continue
        key = (dep.get("ecosystem", ""), dep.get("name", ""))
        if key in comps:
            continue
        comps[key] = dep
    return list(comps.values())


# v2: drift detection — declared behavior contradicts observed capabilities
_OFFLINE_DECLARATION = re.compile(
    r"(?i)\b(?:no network|no internet|never (?:sends?|uploads?|contacts|calls|"
    r"leaves|exfiltrates)|offline|local only|read-?only|never (?:reads|touches|"
    r"accesses) (?:credentials?|secrets?|\.ssh|\.env)|does not (?:send|upload|"
    r"contact|call)|without network|fully local|stays local)\b"
)


def _drift_findings(skills, capabilities, target):
    """Findings for declared-vs-observed contradictions. Review-queue class."""
    out = []
    net_upload = capabilities.get("network.upload") or capabilities.get("network.connect")
    secret = capabilities.get("secret.access")
    for skill in skills:
        desc = (skill.get("description") or "").strip()
        if not desc:
            continue
        if not _OFFLINE_DECLARATION.search(desc):
            continue
        if net_upload or secret:
            out.append({
                "severity": "medium",
                "check": "drift",
                "title": "Declared offline/read-only behavior contradicts observed capabilities",
                "path": skill["root"],
                "line": 1,
                "detail": "description claims {} but scan observed {}".format(
                    desc[:80], "network.upload" if net_upload else "secret.access"),
                "confidence": 0.5,
                "review": True,
                "origin": "deterministic",
                "capability": "secret.access->network.upload",
            })
    return out


def scan_directory(target):
    """Scan a directory (skill, or a collection of skills) deterministically.

    Returns a dict: {target, skills, findings, summary, summary_by_check}.
    Uses a process pool for parallelism; falls back to sequential if the
    pool cannot start (forkserver/auth issues on some platforms).
    """
    target = os.path.abspath(target)
    return scan_batch([target])[0]


def scan_batch(targets):
    """Scan many directories through ONE process pool.

    The right way to scan a corpus: one pool, one walk, N targets. Avoids
    the per-directory pool-spawn cost that makes scanning thousands of
    small skill dirs pathological.
    """
    targets = [os.path.abspath(t) for t in targets]
    # gather all files up front (single walk)
    all_files = []
    file_owner = {}
    for t in targets:
        for rel in _rel_files(t):
            fp = os.path.join(t, rel)
            all_files.append(fp)
            file_owner[fp] = t

    # parallel per-file scan (CPU-bound regex → processes, chunked).
    # Use fork context explicitly: Python 3.14 defaults to spawn, which
    # re-imports __main__ and breaks under stdin/notebooks; fork copies the
    # parent and just works. Falls back to sequential if unavailable.
    workers = max(1, min(4, os.cpu_count() or 1))
    findings = []
    if all_files:
        chunk = max(1, ceil(len(all_files) / workers))
        batches = [all_files[i:i + chunk] for i in range(0, len(all_files), chunk)]
        try:
            ctx = multiprocessing.get_context("fork")
            with ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as pool:
                per_batch = list(pool.map(_scan_batch, batches))
            findings = [f for batch in per_batch for f in batch]
        except (OSError, RuntimeError, ValueError):
            findings = []
            for batch in batches:
                findings.extend(_scan_batch(batch))

    # group findings per target
    results = []
    for t in targets:
        tf = [f for f in findings if file_owner.get(f["path"]) == t]
        skills = _skills_for(t, tf)
        caps = _aggregate_capabilities(tf)
        # v2: drift detection adds review-queue findings per skill
        tf = tf + _drift_findings(skills, caps, t)
        for f in tf:
            _enrich(f)
        # v3: merge duplicate representations of one behavior (the same
        # line firing "Invokes curl" in shell and "Network primitive: curl"
        # in network) into a single finding with multiple evidence records.
        tf = _merge_duplicates(tf)
        tf.sort(key=lambda f: (-SEV_ORDER.get(f["severity"], 0), f["path"], f["line"]))
        summary = {s: 0 for s in SEVERITIES}
        summary_by_check = {}
        for f in tf:
            summary[f["severity"]] = summary.get(f["severity"], 0) + 1
            summary_by_check[f["check"]] = summary_by_check.get(f["check"], 0) + 1
        from .channels import split_channels
        channels = split_channels(tf)
        results.append({
            "target": t,
            "skills": skills,
            "findings": tf,
            "channels": channels,
            "summary": summary,
            "summary_by_check": summary_by_check,
            "capabilities": caps,
            "dependencies": _sbom_components(tf),
            "review_queue": [f for f in tf if f.get("review")],
        })
    return results


# v3: same-behavior duplicate merge. A line like
#   curl -s https://x.example/install.sh | bash
# fires "Invokes curl" (shell) and "Network primitive: curl" (network)
# and the correlation chain (analysis). The two primitive observations
# are one behavior; merge them so the reviewer reads one finding with
# two evidence records. Correlation chains (attack paths) are kept
# separately — they are the higher-value representation.
_MERGE_TITLE = {
    ("shell", "network"): "Shell invokes network primitive",
}


def _merge_duplicates(findings):
    """Merge same-line (shell fetch, network primitive) duplicates.

    Only the GENERIC "Network primitive: X" observation merges into the
    shell invocation — specific URL-risk findings (IP-literal, credentials
    in URL, cleartext) are distinct security facts and stay separate.
    """
    merged = []
    keyed = {}  # (path, line) -> list of indices
    for i, f in enumerate(findings):
        if f["check"] in ("shell", "network"):
            keyed.setdefault((f["path"], f["line"]), []).append(i)
    skip = set()
    for (path, line), idxs in keyed.items():
        shell_idx = [i for i in idxs if findings[i]["check"] == "shell"]
        net_idxs = [i for i in idxs if findings[i]["check"] == "network"]
        if not shell_idx or not net_idxs:
            continue
        s = findings[shell_idx[0]]
        # only merge the GENERIC primitive observation, same-verb
        generic = [i for i in net_idxs
                   if findings[i]["title"].startswith("Network primitive:")]
        if not generic:
            continue
        n = findings[generic[0]]
        if _verb_of_title(s["title"]).lower() != _verb_of_title(n["title"]).lower():
            continue
        verb = _verb_of_title(s["title"]) or _verb_of_title(n["title"])
        if not verb:
            continue
        merged.append({
            "severity": max(s["severity"], n["severity"], key=lambda x: SEV_ORDER[x]),
            "check": "shell+network",
            "title": f"Shell invokes {verb} (network primitive)",
            "path": path,
            "line": line,
            "detail": (s.get("detail", "") or "")[:160],
            "confidence": min(s.get("confidence", 0.8), n.get("confidence", 0.8)),
            "evidence": s.get("evidence", []) + n.get("evidence", []),
            "origin": "deterministic",
            "region_class": s.get("region_class", n.get("region_class", "")),
        })
        # skip ONLY the merged pair — specific URL-risk findings on the
        # same line (IP-literal, credentials, cleartext) stay separate.
        skip.add(shell_idx[0])
        skip.add(generic[0])
    for i, f in enumerate(findings):
        if i in skip:
            continue
        merged.append(f)
    # enrich merged findings (fingerprint, evidence, origin)
    for f in merged:
        _enrich(f)
    return merged


def _verb_of_title(title):
    """The network verb named in a shell/network title, e.g. 'curl'."""
    m = re.search(r"\b(curl|wget|nc|netcat|fetch|scp|rsync|sftp)\b", title, re.IGNORECASE)
    return m.group(1) if m else ""


def _skills_for(target, findings):
    """Build the skills list for a target from its findings (files walked)."""
    skills = []
    roots = set()
    for f in findings:
        root = _skill_root(target, f["path"])
        if root in roots:
            continue
        roots.add(root)
        smd = os.path.join(root, "SKILL.md")
        if os.path.isfile(smd):
            nm, desc = _parse_frontmatter(smd)
        else:
            nm, desc = os.path.basename(root), ""
        skills.append({
            "root": root,
            "name": nm,
            "description": desc,
            "format": _detect_format(root, target),
        })
    # include skill dirs that produced zero findings (walk again for completeness)
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in {"node_modules", ".git",
                                                        ".venv", "venv", "dist",
                                                        "build", "__pycache__"}]
        if "SKILL.md" in filenames and dirpath not in roots:
            roots.add(dirpath)
            nm, desc = _parse_frontmatter(os.path.join(dirpath, "SKILL.md"))
            skills.append({
                "root": dirpath,
                "name": nm,
                "description": desc,
                "format": _detect_format(dirpath, target),
            })
    return skills


def _rel_files(target):
    """All scannable files under target, relative paths, sorted."""
    out = []
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in {"node_modules", ".git",
                                                        ".venv", "venv", "dist",
                                                        "build", "__pycache__"}]
        for fn in filenames:
            if fn in IGNORED_FILES:
                continue  # lockfiles/generated data — parsed, not scanned
            full = os.path.join(dirpath, fn)
            if is_text_file(_PathLike(full)):
                out.append(os.path.relpath(full, target))
    return sorted(out)


def _skill_root(target, path):
    """The skill directory owning a file: the dir containing SKILL.md, else the file's dir."""
    d = os.path.dirname(path)
    while True:
        if os.path.isfile(os.path.join(d, "SKILL.md")):
            return d
        parent = os.path.dirname(d)
        if parent == d or not d.startswith(target):
            return os.path.dirname(path)
        d = parent
