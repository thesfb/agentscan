"""Check: license presence.

Deterministic and cheap: does the skill declare a license (frontmatter
`license:` or a LICENSE file) and is it a recognizable permissive/known
license? Missing or unrecognized licenses matter for anyone redistributing
skills (the exact thing the repackagers ignore). Presence is a fact; legal
advice it is not.
"""

import re

from ..common import read_lines

NAME = "license"
TITLE = "License"

KNOWN = {
    "mit": "MIT",
    "apache": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "bsd": "BSD",
    "gpl": "GPL",
    "lgpl": "LGPL",
    "mpl": "MPL",
    "cc0": "CC0",
    "cc-by": "CC-BY",
    "unlicense": "Unlicense",
    "isc": "ISC",
    "proprietary": "Proprietary",
    "source-available": "Source-available",
}

FRONTMATTER_LICENSE = re.compile(r"^\s*license\s*:\s*(.+?)\s*$", re.IGNORECASE)


def run(path, findings):
    # Only evaluate the SKILL.md (or a top-level LICENSE). Bundled scripts
    # don't carry their own licenses — the skill-level license governs.
    import os as _os
    name = _os.path.basename(path)
    if name.lower() == "license" or name.lower() in ("copying", "copying.txt", "license.txt"):
        return
    if not name.lower().endswith((".md", ".markdown")):
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
    else:
        findings.append({
            "severity": "low",
            "check": NAME,
            "title": "No license declared",
            "path": str(path),
            "line": 1,
            "detail": "Skill declares no license (frontmatter `license:` or "
                      "LICENSE file). Redistribution rights unclear.",
        })
