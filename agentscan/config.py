"""Local state for the Trusted Distribution.

Everything lives under ~/.agentscan/:

    license         the activated license (JSON, one line)
    installed.json  {package-id: version} — the only state the CLI keeps
    config.json     {api_url: ...} — optional overrides
    cache/          downloaded tarballs, reused across install/update

Nothing else is ever written. No lockfiles, no session dirs, no telemetry.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Optional

from .models import License

AGENTSCAN_DIR = Path.home() / ".agentscan"
LICENSE_FILE = AGENTSCAN_DIR / "license"
INSTALLED_FILE = AGENTSCAN_DIR / "installed.json"
CONFIG_FILE = AGENTSCAN_DIR / "config.json"
CACHE_DIR = AGENTSCAN_DIR / "cache"

DEFAULT_API_URL = "https://agentscan.baldbee.me"


def ensure_dirs() -> None:
    AGENTSCAN_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def api_url() -> str:
    """API base URL. Priority: AGENTSCAN_API_URL env → config.json → default."""
    env = os.environ.get("AGENTSCAN_API_URL")
    if env:
        return env.rstrip("/")
    try:
        cfg = json.loads(CONFIG_FILE.read_text())
        url = cfg.get("api_url")
        if url:
            return url.rstrip("/")
    except (OSError, ValueError):
        pass
    return DEFAULT_API_URL


def set_api_url(url: str) -> None:
    ensure_dirs()
    cfg = {"api_url": url}
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2) + "\n")


# --------------------------------------------------------------------------
# License
# --------------------------------------------------------------------------


def load_license() -> Optional[License]:
    try:
        return License.from_dict(json.loads(LICENSE_FILE.read_text()))
    except (OSError, ValueError, KeyError):
        return None


def save_license(lic: License) -> None:
    ensure_dirs()
    LICENSE_FILE.write_text(json.dumps(lic.to_dict()) + "\n")


def clear_license() -> None:
    try:
        LICENSE_FILE.unlink()
    except FileNotFoundError:
        pass


# --------------------------------------------------------------------------
# installed.json — {package-id: version}
# --------------------------------------------------------------------------


def load_installed() -> Dict[str, str]:
    try:
        data = json.loads(INSTALLED_FILE.read_text())
        return {k: str(v) for k, v in data.items()}
    except (OSError, ValueError):
        return {}


def save_installed(installed: Dict[str, str]) -> None:
    ensure_dirs()
    INSTALLED_FILE.write_text(json.dumps(installed, indent=2, sort_keys=True) + "\n")
