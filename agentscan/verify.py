"""Package verifier.

Checks are deliberately shallow today and structured so real cryptographic
signatures can be dropped in later without changing the command surface:

    ✓ Signature Valid   — placeholder: checks for audit.json + signature.sig
    ✓ Latest Version    — installed version vs the live catalog
    ✓ Audit Passed      — audit.json exists and reports status: passed
    ✓ Package Intact    — local tarball checksum matches the manifest

Each check returns (label, ok, detail). Nothing here executes package code.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional, Tuple

from .api import Client
from .config import CACHE_DIR
from .installer import installed_dir
from .models import Package

Check = Tuple[str, bool, str]

MOCK_SIGNATURE_MARKER = "signature.sig"


def _audit_ok(pkg_dir: Path) -> Tuple[bool, str]:
    audit = pkg_dir / "audit.json"
    if not audit.exists():
        return False, "audit.json missing"
    try:
        data = json.loads(audit.read_text())
    except ValueError:
        return False, "audit.json is not valid JSON"
    if data.get("status") != "passed":
        return False, f"audit status is '{data.get('status')}'"
    return True, "audit passed"


def verify_package(pkg: Package, installed_version: str, client: Client) -> List[Check]:
    checks: List[Check] = []
    pkg_dir = installed_dir(pkg.id)

    # Signature — placeholder for real cryptographic verification.
    if pkg_dir is not None and (pkg_dir / MOCK_SIGNATURE_MARKER).exists():
        checks.append(("Signature Valid", True, "signature present (verification pending)"))
    elif pkg_dir is not None:
        checks.append(("Signature Valid", False, "signature.sig missing"))
    else:
        checks.append(("Signature Valid", False, "package not installed"))

    # Latest version against the live catalog.
    try:
        catalog = client.search()
        latest = catalog.find(pkg.id)
    except Exception:
        latest = None
    if latest is None:
        checks.append(("Latest Version", False, "package not found in catalog"))
    elif latest.version == installed_version:
        checks.append(("Latest Version", True, f"{installed_version} is current"))
    else:
        checks.append(
            ("Latest Version", False, f"{installed_version} installed, {latest.version} available")
        )

    # Audit.
    if pkg_dir is not None:
        ok, detail = _audit_ok(pkg_dir)
        checks.append(("Audit Passed", ok, detail))
    else:
        checks.append(("Audit Passed", False, "package not installed"))

    # Package intact — local tarball checksum vs manifest.
    if pkg.sha256:
        tarball = CACHE_DIR / pkg.asset
        if not tarball.exists():
            checks.append(("Package Intact", False, "cached tarball missing"))
        else:
            from .installer import _sha256

            actual = _sha256(tarball)
            if actual == pkg.sha256:
                checks.append(("Package Intact", True, "checksum verified"))
            else:
                checks.append(("Package Intact", False, "checksum mismatch"))
    else:
        checks.append(("Package Intact", True, "no checksum in manifest"))

    return checks
