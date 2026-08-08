"""Check: dependencies — pin detection, typosquat heuristics, SBOM seed
(v2 layer 14).

Extracts the dependencies an artifact introduces (package.json,
requirements.txt, pyproject.toml, SKILL.md install instructions,
bundled Python imports), flags unpinned installs and typosquat
candidates, and attaches a `dependency` field so the scanner can
aggregate an SBOM and the CLI can run OSV lookups.

Facts only: a dependency name is a fact; whether the name is a
typosquat is a heuristic with a score.
"""

import os

from ..common import read_lines
from ..analysis.dependencies import extract_dependencies, typosquat_score

NAME = "dependencies"
TITLE = "Dependencies"


def _skill_root(path):
    d = os.path.dirname(os.path.abspath(str(path)))
    while True:
        if os.path.isfile(os.path.join(d, "SKILL.md")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return os.path.dirname(os.path.abspath(str(path)))
        d = parent


def _eligible(path, root):
    """Only artifact-root files and bundled scripts contribute deps."""
    rel = os.path.relpath(os.path.abspath(str(path)), root)
    parts = rel.split(os.sep)
    base = os.path.basename(rel)
    if len(parts) == 1 and base in ("SKILL.md", "package.json", "requirements.txt",
                                    "pyproject.toml", "Pipfile"):
        return True
    if len(parts) == 2 and parts[0] in ("scripts", "tools", "bin", "lib") and base.endswith(".py"):
        return True
    return False


def run(path, findings):
    p = str(path)
    root = _skill_root(path)
    if not _eligible(p, root):
        return
    try:
        lines = read_lines(path)
    except OSError:
        return

    deps = extract_dependencies({os.path.relpath(p, root): lines})

    for dep in deps:
        # SBOM seed: every dependency is an info finding carrying the
        # structured dependency field (pinned/unpinned visible in version).
        findings.append({
            "severity": "info",
            "check": NAME,
            "title": f"Dependency: {dep.name} ({dep.ecosystem})",
            "path": p,
            "line": dep.line or 1,
            "detail": f"{dep.name} from {dep.source}"
                      + ("" if dep.pinned else " — unpinned"),
            "dependency": {"ecosystem": dep.ecosystem, "name": dep.name,
                           "version": dep.version or "",
                           "pinned": dep.pinned},
        })
        score = typosquat_score(dep.name)
        if score >= 2:
            findings.append({
                "severity": "medium",
                "check": NAME,
                "title": f"Possible typosquat dependency: {dep.name}",
                "path": p,
                "line": dep.line or 1,
                "detail": f"{dep.name} from {dep.source} — name is one edit "
                          f"from a popular package",
                "confidence": 0.5,
                "dependency": {"ecosystem": dep.ecosystem, "name": dep.name,
                               "version": dep.version or ""},
            })
        elif score == 1:
            findings.append({
                "severity": "low",
                "check": NAME,
                "title": f"Name similar to popular package: {dep.name}",
                "path": p,
                "line": dep.line or 1,
                "detail": f"{dep.name} from {dep.source}",
                "confidence": 0.35,
                "dependency": {"ecosystem": dep.ecosystem, "name": dep.name,
                               "version": dep.version or ""},
            })
