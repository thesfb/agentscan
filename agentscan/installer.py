"""Package installer: download → checksum → extract → install into Claude Code.

The package is a tarball of a package directory (manifest.json + agents/,
skills/, commands/, templates/, knowledge/, audit.json). It is extracted
into ~/.claude/skills/<package-id>/ so the skills inside become available
to Claude Code, and the installed version is recorded in installed.json.

The exact Claude Code layout can evolve; everything is local and visible.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tarfile
from pathlib import Path
from typing import Dict, Optional

from .api import ApiError, Client
from .config import CACHE_DIR, ensure_dirs
from .models import Package

CLAUDE_SKILLS_DIR = Path.home() / ".claude" / "skills"


class InstallError(Exception):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _extract(tarball: Path, dest: Path) -> None:
    """Extract a package tarball into dest.

    Tarballs are expected to contain a single top-level directory (the
    package dir, e.g. security-engineer/). It is stripped so contents land
    directly in dest.
    """
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball, "r:gz") as tf:
        members = tf.getmembers()
        top_dirs = {m.name.split("/")[0] for m in members if "/" in m.name} | {
            m.name for m in members if m.isdir()
        }
        prefix = None
        for candidate in sorted(top_dirs):
            if "/" not in candidate:
                prefix = candidate
                break
        if prefix is None:
            raise InstallError("package tarball has no top-level directory")
        for member in members:
            name = member.name
            if name == prefix or name.startswith(prefix + "/"):
                member.name = name[len(prefix):].lstrip("/")
                if member.name:
                    tf.extract(member, dest)


def _install_dir_for(package_id: str) -> Path:
    return CLAUDE_SKILLS_DIR / package_id


def install_package(client: Client, pkg: Package) -> Path:
    """Download, verify, extract and install one package. Returns its dir."""
    ensure_dirs()
    cache_file = CACHE_DIR / pkg.asset
    if not cache_file.exists():
        print(f"  ↓ downloading {pkg.asset} ({pkg.version})")
        client.download(pkg.id, cache_file)
    actual = _sha256(cache_file)
    if pkg.sha256 and actual != pkg.sha256:
        cache_file.unlink(missing_ok=True)
        raise InstallError(
            f"checksum mismatch for {pkg.id}: expected {pkg.sha256[:12]}…, got {actual[:12]}…"
        )

    dest = _install_dir_for(pkg.id)
    tmp = dest.with_name(dest.name + ".tmp")
    if tmp.exists():
        shutil.rmtree(tmp)
    _extract(cache_file, tmp)

    # Validate the manifest before swapping into place.
    manifest_path = tmp / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, ValueError) as e:
        shutil.rmtree(tmp)
        raise InstallError(f"{pkg.id}: missing or invalid manifest.json ({e})") from None
    if manifest.get("id") != pkg.id:
        shutil.rmtree(tmp)
        raise InstallError(
            f"{pkg.id}: manifest id '{manifest.get('id')}' does not match package name"
        )

    if dest.exists():
        shutil.rmtree(dest)
    tmp.rename(dest)
    print(f"  ✓ installed {pkg.id} {pkg.version} → {dest}")
    return dest


def latest_installed_versions() -> Dict[str, str]:
    """{package-id: version} currently on disk, from installed.json."""
    from .config import load_installed

    return load_installed()


def installed_dir(package_id: str) -> Optional[Path]:
    d = _install_dir_for(package_id)
    return d if d.exists() else None
