"""Check: license presence (v2 — skill granularity).

Deterministic and cheap: does the skill declare a license? v2 change:
the license contract is per-skill, not per-file. Only the skill's
SKILL.md is evaluated (plus a sibling LICENSE file). Ancillary docs
(DESCRIPTION.md, references/*.md, README.md, knowledge/) are covered
by the skill-level declaration and no longer produce individual
findings — one finding per skill at most.

Presence is a fact; legal advice it is not.
"""

import os
import re

from ..common import read_lines

NAME = "license"
TITLE = "License"

KNOWN = {
    "mit": "MIT",
    "apache": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "apache2": "Apache-2.0",
    "bsd": "BSD",
    "bsd-3-clause": "BSD-3-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "gpl": "GPL",
    "gpl-3.0": "GPL-3.0",
    "gpl-2.0": "GPL-2.0",
    "lgpl": "LGPL",
    "mpl": "MPL",
    "mpl-2.0": "MPL-2.0",
    "cc0": "CC0",
    "cc-by": "CC-BY",
    "unlicense": "Unlicense",
    "isc": "ISC",
    "proprietary": "Proprietary",
    "source-available": "Source-available",
    "cc-by-sa": "CC-BY-SA",
}

FRONTMATTER_LICENSE = re.compile(r"^\s*license\s*:\s*(.+?)\s*$", re.IGNORECASE)

_LICENSE_FILES = {"license", "license.md", "license.txt", "copying",
                  "copying.txt", "copying.md", "unlicense", "unlicense.txt"}


def _sibling_license(dirpath):
    try:
        for name in os.listdir(dirpath):
            if name.lower() in _LICENSE_FILES:
                return True
    except OSError:
        pass
    return False


def run(path, findings):
    # Only the skill definition file carries the license contract.
    name = os.path.basename(str(path))
    if name != "SKILL.md":
        return

    lines = read_lines(path)
    declared = None
    for line in lines[:40]:  # frontmatter only
        m = FRONTMATTER_LICENSE.match(line)
        if m:
            declared = m.group(1).strip().strip('"\'')
            break

    if declared:
        key = declared.lower().split()[0].rstrip(".")
        if key in KNOWN:
            # recognized license = no finding
            return
        findings.append({
            "severity": "low",
            "check": NAME,
            "title": f"Unrecognized license declaration: {declared}",
            "path": str(path),
            "line": 1,
            "detail": "License string does not match a known license name — "
                      "verify before redistributing.",
        })
        return

    # No frontmatter license: a sibling LICENSE file satisfies the contract.
    if _sibling_license(os.path.dirname(str(path))):
        return

    findings.append({
        "severity": "low",
        "check": NAME,
        "title": "No license declared",
        "path": str(path),
        "line": 1,
        "detail": "Skill declares no license (frontmatter `license:` or "
                  "LICENSE file). Redistribution rights unclear.",
    })
