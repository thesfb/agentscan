"""Scanner orchestrator: walk a directory, run all checks, aggregate.

The scanner reports OBSERVED FACTS with suggested severities. It never
labels a skill "malicious" — that verdict belongs to the human. Findings
carry file + line so every claim is checkable by hand.
"""

import os
from concurrent.futures import ProcessPoolExecutor
from math import ceil
import multiprocessing

from . import checks
from .checks import (  # noqa: F401 — importing registers the modules
    config_tamper,
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
from .common import SEVERITIES, SEV_ORDER, _PathLike, is_text_file

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
]

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
        tf.sort(key=lambda f: (-SEV_ORDER.get(f["severity"], 0), f["path"], f["line"]))
        summary = {s: 0 for s in SEVERITIES}
        summary_by_check = {}
        for f in tf:
            summary[f["severity"]] = summary.get(f["severity"], 0) + 1
            summary_by_check[f["check"]] = summary_by_check.get(f["check"], 0) + 1
        results.append({
            "target": t,
            "skills": skills,
            "findings": tf,
            "summary": summary,
            "summary_by_check": summary_by_check,
        })
    return results


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
