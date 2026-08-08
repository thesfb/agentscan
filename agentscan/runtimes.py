"""Runtime detection for the Trusted Distribution installer.

Detects which agent runtimes are installed on this machine, using official
install locations (verified against runtime docs 2026-08) and PATH binaries.
Never guesses; a runtime is reported installed only when a documented path
exists or its CLI binary is on PATH.

    claude   → ~/.claude/skills  (or `claude` on PATH)
    opencode → ~/.config/opencode (or `opencode` on PATH)
    codex    → ~/.codex or ~/.agents (or `codex` on PATH)
    hermes   → $HERMES_HOME or ~/.hermes (or `hermes` on PATH)

Hermes note: the skills directory is $HERMES_HOME/skills when HERMES_HOME
is set (profiles included), else ~/.hermes/skills. Detection treats
HERMES_HOME as authoritative when present (verified against the Hermes
docs: hermes-agent.nousresearch.com/docs).
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Dict, List, Optional

# Official per-runtime config/state dirs (presence ⇒ installed).


def hermes_home_dir() -> Path:
    """The Hermes home directory: $HERMES_HOME when set, else ~/.hermes.

    HERMES_HOME is the official override (docs: hermes-agent.nousresearch
    .com/docs) and also covers named profiles, which use
    $HERMES_HOME/profiles/<name>/ with the same layout.
    """
    env = os.environ.get("HERMES_HOME", "").strip()
    return Path(env) if env else Path.home() / ".hermes"


_DETECT_DIRS: Dict[str, List[Path]] = {
    "claude": [Path.home() / ".claude"],
    "opencode": [
        Path.home() / ".config" / "opencode",
        Path.home() / ".local" / "share" / "opencode",
    ],
    "codex": [Path.home() / ".codex", Path.home() / ".agents"],
    "hermes": [hermes_home_dir()],
}

_DETECT_BINS: Dict[str, List[str]] = {
    "claude": ["claude"],
    "opencode": ["opencode"],
    "codex": ["codex"],
    "hermes": ["hermes"],
}

RUNTIMES = ("claude", "opencode", "codex", "hermes")


def detect_runtimes() -> Dict[str, bool]:
    """{runtime: installed?} for every supported runtime."""
    found: Dict[str, bool] = {}
    for runtime in RUNTIMES:
        dirs_hit = any(d.is_dir() for d in _DETECT_DIRS[runtime])
        bin_hit = any(shutil.which(b) for b in _DETECT_BINS[runtime])
        found[runtime] = dirs_hit or bin_hit
    return found


def detect_installed() -> List[str]:
    """Runtimes actually present, in canonical order."""
    found = detect_runtimes()
    return [r for r in RUNTIMES if found[r]]


def resolve_runtimes(flag: Optional[str], detected: Optional[List[str]] = None) -> List[str]:
    """Turn a --runtime flag value into a concrete runtime list.

    - None or "auto" → detected runtimes.
    - "all" → every supported runtime.
    - A single runtime name → that runtime.
    Returns [] when nothing can be determined (caller should prompt).
    """
    if detected is None:
        detected = detect_installed()
    if flag in (None, "", "auto"):
        return detected
    if flag == "all":
        return list(RUNTIMES)
    if flag in RUNTIMES:
        # Explicit request wins even if detection missed it; the installer
        # will create the dir if needed. If detection says it's absent,
        # still honor the explicit flag (user knows their setup).
        return [flag]
    return []


def prompt_for_runtime() -> List[str]:
    """Ask the user which runtime(s) to install into. Returns selection."""
    from .ui import prompt

    print("Which runtime should packages install into?")
    for i, r in enumerate(RUNTIMES, 1):
        print(f"  {i}) {r}")
    print("  a) all")
    choice = prompt("choice").strip().lower()
    if choice == "a" or choice == "all":
        return list(RUNTIMES)
    if choice in RUNTIMES:
        return [choice]
    try:
        idx = int(choice)
        if 1 <= idx <= len(RUNTIMES):
            return [RUNTIMES[idx - 1]]
    except ValueError:
        pass
    return []
