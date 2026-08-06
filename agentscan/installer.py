"""Package installer: download → checksum → extract → install into Claude Code.

The package is a tarball of a package directory (manifest.json + agents/,
skills/, commands/, templates/, knowledge/, audit.json). It is extracted
into ~/.claude/skills/<package-id>/ so the skills inside become available
to Claude Code, and the installed version is recorded in installed.json.

The flow is split into stages so the CLI can show progress per stage:

    cache_path()      → where the downloaded tarball lives
    verify_checksum() → sha256 against the catalog
    extract_to_temp() → unpack + validate the manifest
    commit_install()  → swap the temp dir into place
    count_package()   → skills/commands/knowledge/readme stats

install_package() is the combined convenience form.

The exact Claude Code layout can evolve; everything is local and visible.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

from .api import ApiError, Client
from . import config
from .models import Package

CLAUDE_SKILLS_DIR = Path.home() / ".claude" / "skills"


class InstallError(Exception):
    pass


@dataclass
class InstallResult:
    """What an install produced — used for the post-install summary."""

    pkg: Package
    dest: Path
    skills: int
    commands: int
    knowledge: int
    has_readme: bool


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


def cache_path(pkg: Package) -> Path:
    """Where the downloaded tarball is cached (~/.agentscan/cache/<asset>)."""
    return config.CACHE_DIR / pkg.asset


def verify_checksum(tarball: Path, pkg: Package) -> None:
    """Verify the tarball's sha256 against the catalog. Raises InstallError."""
    actual = _sha256(tarball)
    if pkg.sha256 and actual != pkg.sha256:
        tarball.unlink(missing_ok=True)
        raise InstallError(
            f"checksum mismatch for {pkg.id}: expected {pkg.sha256[:12]}…, got {actual[:12]}…"
        )


def extract_to_temp(tarball: Path, pkg: Package) -> Path:
    """Extract a downloaded tarball into a temp dir and validate its
    manifest. Returns the temp dir (not yet in its final place)."""
    dest = _install_dir_for(pkg.id)
    tmp = dest.with_name(dest.name + ".tmp")
    if tmp.exists():
        shutil.rmtree(tmp)
    _extract(tarball, tmp)

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
    return tmp


def commit_install(tmp: Path, pkg: Package) -> Path:
    """Move the validated temp dir into its final location."""
    dest = _install_dir_for(pkg.id)
    if dest.exists():
        shutil.rmtree(dest)
    tmp.rename(dest)
    return dest


def count_package(pkg_dir: Path):
    """(skills, commands, knowledge, has_readme) from an installed package."""
    skills_dir = pkg_dir / "skills"
    commands_dir = pkg_dir / "commands"
    knowledge_dir = pkg_dir / "knowledge"
    skills = (
        sum(1 for d in skills_dir.iterdir() if (d / "SKILL.md").exists())
        if skills_dir.is_dir()
        else 0
    )
    commands = (
        sum(1 for d in commands_dir.iterdir() if d.is_dir())
        if commands_dir.is_dir()
        else 0
    )
    knowledge = (
        len(list(knowledge_dir.glob("*.md"))) if knowledge_dir.is_dir() else 0
    )
    has_readme = (pkg_dir / "README.md").is_file()
    return skills, commands, knowledge, has_readme


def install_package(client: Client, pkg: Package, progress=None) -> InstallResult:
    """Download, verify, extract and install one package. Returns the result.

    This is the combined form; the CLI drives the stages individually so it
    can render progress between them.
    """
    config.ensure_dirs()
    cf = cache_path(pkg)
    if not cf.exists():
        client.download(pkg.id, cf, progress=progress)
    verify_checksum(cf, pkg)
    tmp = extract_to_temp(cf, pkg)
    dest = commit_install(tmp, pkg)
    skills, commands, knowledge, has_readme = count_package(dest)
    return InstallResult(pkg=pkg, dest=dest, skills=skills, commands=commands,
                         knowledge=knowledge, has_readme=has_readme)


def latest_installed_versions() -> Dict[str, str]:
    """{package-id: version} currently on disk, from installed.json."""
    from .config import load_installed

    return load_installed()


def installed_dir(package_id: str) -> Optional[Path]:
    d = _install_dir_for(package_id)
    return d if d.exists() else None
