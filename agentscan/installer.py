"""Package installer: download → checksum → extract → install into runtimes.

The package tarball contains canonical `skills/<id>/SKILL.md` plus generated
per-runtime layouts (`claude/`, `opencode/`, `codex/`, `hermes/`, `grok/`)
and an `AGENTS.md` for the agents.md convention. The installer copies each
skill into the selected runtime's skills directory, flattened one level:

    claude   → ~/.claude/skills/<skill-id>/
    opencode → ~/.config/opencode/skills/<skill-id>/
    codex    → ~/.agents/skills/<skill-id>/   (+ AGENTS.md to repo root)
    hermes   → $HERMES_HOME/skills/<skill-id>/  (default ~/.hermes/skills)
    grok     → $GROK_HOME/skills/<skill-id>/    (default ~/.grok/skills)

Hermes discovery is recursive under its skills root and follows the
agentskills.io open standard, so the same flat one-level layout that the
other runtimes use is also the correct Hermes layout — no nested package
directory (nested installs were invisible to every runtime).

Grok Build (xAI) reads the same agentskills.io SKILL.md standard and
discovers skills recursively under skills/ dirs (cwd/.grok/skills,
~/.grok/skills, ~/.agents/skills, ~/.claude/skills); $GROK_HOME overrides
the home. The flat one-level layout is the native install shape.

The flow is split into stages so the CLI can show progress per stage:

    cache_path()      → where the downloaded tarball lives
    verify_checksum() → sha256 against the catalog
    extract_to_temp() → unpack + validate the manifest
    install_layouts() → copy per-runtime layouts into place
    count_package()   → skills/commands/knowledge/readme stats
    remove_package()  → remove an installed package's layouts

install_package() is the combined convenience form.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .api import ApiError, Client
from . import config
from .models import Package

# Official runtime discovery roots (verified against runtime docs 2026-08).


def _hermes_skills_dir() -> Path:
    """$HERMES_HOME/skills when HERMES_HOME is set, else ~/.hermes/skills.

    Hermes skills root honors $HERMES_HOME (official override; covers
    named profiles too), falling back to ~/.hermes/skills.
    """
    from .runtimes import hermes_home_dir

    return hermes_home_dir() / "skills"


def _grok_skills_dir() -> Path:
    """$GROK_HOME/skills when GROK_HOME is set, else ~/.grok/skills.

    Grok Build's native user-level skills directory (verified in the
    grok-build source: skills are discovered under <grok-home>/skills,
    and GROK_HOME overrides the home like HERMES_HOME does for Hermes).
    """
    from .runtimes import grok_home_dir

    return grok_home_dir() / "skills"


RUNTIME_DIRS: Dict[str, Path] = {
    "claude": Path.home() / ".claude" / "skills",
    "opencode": Path.home() / ".config" / "opencode" / "skills",
    "codex": Path.home() / ".agents" / "skills",
    "hermes": _hermes_skills_dir(),
    "grok": _grok_skills_dir(),
}


def _grok_agents_dir() -> Path:
    """$GROK_HOME/agents when GROK_HOME is set, else ~/.grok/agents.

    Verified in the grok-build source (xai-org/grok-build,
    crates/codegen/xai-grok-agent/src/discovery.rs): agent files are
    .md + YAML frontmatter discovered under <grok-home>/agents (user
    scope), and GROK_HOME overrides the home like HERMES_HOME does.
    """
    from .runtimes import grok_home_dir

    return grok_home_dir() / "agents"


# Native agent definition directories per runtime (verified 2026-08-10
# against each harness's official docs / source):
#   claude   ~/.claude/agents/            (markdown + YAML frontmatter)
#   opencode ~/.config/opencode/agents/   (markdown, file name = agent)
#   codex    ~/.codex/agents/             (TOML, name/description/
#                                         developer_instructions)
#   grok     ~/.grok/agents/              (markdown; GROK_HOME-aware,
#                                         also reads ~/.claude/agents/)
#   hermes   (none — Hermes has no file-based agents; delegation is the
#             native mechanism, documented in hermes/agents/README.md)
RUNTIME_AGENT_DIRS: Dict[str, Optional[Path]] = {
    "claude": Path.home() / ".claude" / "agents",
    "opencode": Path.home() / ".config" / "opencode" / "agents",
    "codex": Path.home() / ".codex" / "agents",
    "grok": _grok_agents_dir(),
    "hermes": None,
}

# Layout subdir inside the package tarball per runtime.
RUNTIME_LAYOUT = {
    "claude": "claude",
    "opencode": "opencode",
    "codex": "codex",
    "hermes": "hermes",
    "grok": "grok",
}

RUNTIME_NAMES = {
    "claude": "Claude Code",
    "opencode": "OpenCode",
    "codex": "OpenAI Codex",
    "hermes": "Hermes",
    "grok": "Grok Build",
}


class InstallError(Exception):
    pass


@dataclass
class InstallResult:
    """What an install produced — used for the post-install summary."""

    pkg: Package
    runtimes: List[str] = field(default_factory=list)
    dests: Dict[str, Path] = field(default_factory=dict)
    skills: int = 0
    commands: int = 0
    knowledge: int = 0
    has_readme: bool = False
    agents_written: List[str] = field(default_factory=list)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _extract(tarball: Path, dest: Path) -> None:
    """Extract a package tarball into dest, stripping the top-level dir."""
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


def extract_to_temp(tarball: Path, pkg: Package, tmp: Optional[Path] = None) -> Path:
    """Extract a downloaded tarball into a temp dir and validate its
    manifest. Returns the temp dir (not yet in its final place)."""
    if tmp is None:
        tmp = Path(config.AGENTSCAN_DIR) / f"{pkg.id}.tmp"
    if tmp.exists():
        shutil.rmtree(tmp)
    _extract(tarball, tmp)

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


def _layout_dir(tmp: Path, runtime: str) -> Path:
    """The per-runtime layout dir inside an extracted package."""
    layout = tmp / RUNTIME_LAYOUT[runtime]
    if not layout.is_dir():
        # Fall back to canonical skills/ if the runtime layout is absent
        # (older packages). Claude's canonical layout is skills/<id>/.
        layout = tmp / "skills"
    return layout


def _find_agents_root() -> Optional[Path]:
    """The repository root when inside a git work tree, else None."""
    try:
        import subprocess

        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode == 0 and out.stdout.strip():
            return Path(out.stdout.strip())
    except Exception:
        pass
    return None


def _write_agents_md(tmp: Path, pkg: Package) -> List[str]:
    """Install AGENTS.md per the agents.md convention. Returns paths written.

    Priority: repo-root AGENTS.md when inside a git work tree (append a
    clearly delimited AgentScan section; never destroy existing content).
    Otherwise no write — the caller prints where the file lives.
    """
    src = tmp / "AGENTS.md"
    if not src.is_file():
        return []
    root = _find_agents_root()
    if root is None:
        return []
    target = root / "AGENTS.md"
    marker = f"<!-- agentscan:{pkg.id} -->"
    try:
        existing = target.read_text() if target.exists() else ""
    except OSError:
        return []
    if marker in existing:
        # Replace the previous section for this package.
        start = existing.index(marker)
        end = existing.index("<!-- /agentscan -->", start)
        if end == -1:
            end = len(existing)
        else:
            end += len("<!-- /agentscan -->")
        new_section = f"{marker}\n\n{src.read_text()}\n\n<!-- /agentscan -->"
        target.write_text(existing[:start].rstrip() + "\n\n" + new_section + "\n")
    else:
        section = f"\n{marker}\n\n{src.read_text()}\n\n<!-- /agentscan -->\n"
        target.write_text(existing.rstrip() + "\n" + section)
    return [str(target)]


def install_layouts(tmp: Path, pkg: Package, runtimes: List[str]) -> InstallResult:
    """Copy each requested runtime's skill layouts into place.

    Returns an InstallResult with per-runtime destinations. Does not touch
    installed.json — the CLI owns that bookkeeping.
    """
    result = InstallResult(pkg=pkg, runtimes=list(runtimes))
    for runtime in runtimes:
        dest_root = RUNTIME_DIRS[runtime]
        layout = _layout_dir(tmp, runtime)
        skills = [d for d in layout.iterdir() if (d / "SKILL.md").is_file()] if layout.is_dir() else []
        if not skills:
            raise InstallError(f"{pkg.id}: no skills found for runtime '{runtime}'")
        for skill_dir in skills:
            target = dest_root / skill_dir.name
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(skill_dir, target)
        result.dests[runtime] = dest_root
        _install_agents(tmp, runtime, dest_root)
    # AGENTS.md (agents.md convention) — repo root only.
    result.agents_written = _write_agents_md(tmp, pkg)
    return result


def _install_agents(tmp: Path, runtime: str, dest_root: Path) -> List[str]:
    """Copy a runtime's agent definition files into its native agents dir.

    The package tarball carries per-runtime agent adapters under
    <runtime>/agents/ (claude/*.md, codex/*.toml, opencode/*.md,
    grok/*.md, hermes/README.md). Each file-based runtime discovers
    agents in its own native directory; Hermes has no file-based agents
    so its delegation guide is copied next to the skills instead.

    Returns the paths written (empty when the runtime has no agent dir).
    """
    layout = tmp / RUNTIME_LAYOUT[runtime] / "agents"
    dest = RUNTIME_AGENT_DIRS.get(runtime)
    if dest is None or not layout.is_dir():
        return []
    dest.mkdir(parents=True, exist_ok=True)
    written: List[str] = []
    for f in sorted(layout.iterdir()):
        if not f.is_file():
            continue
        target = dest / f.name
        target.write_bytes(f.read_bytes())
        written.append(str(target))
    return written


def count_package(pkg_dir: Path):
    """(skills, commands, knowledge, has_readme) from an extracted package dir.

    Works on the canonical layout (skills/<id>/SKILL.md, commands/, knowledge/).
    """
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


def remove_package(pkg: Package, runtimes: List[str]) -> List[str]:
    """Remove installed skill dirs for pkg across runtimes. Returns removed paths.

    Only removes the flattened per-runtime dirs (RUNTIME_DIRS[r] / <skill-id>).
    Legacy nested installs (~/.claude/skills/<pkg>/skills/...) are left in
    place — the CLI reports them and never deletes.
    """
    removed: List[str] = []
    tmp = Path(config.AGENTSCAN_DIR) / f"{pkg.id}.tmp"
    if not tmp.exists():
        # Need the skill list; reconstruct from the cache tarball if present.
        cf = cache_path(pkg)
        if cf.exists():
            try:
                tmp = extract_to_temp(cf, pkg)
            except InstallError:
                return removed
        else:
            return removed
    try:
        for runtime in runtimes:
            layout = _layout_dir(tmp, runtime)
            root = RUNTIME_DIRS[runtime]
            for skill_dir in layout.iterdir() if layout.is_dir() else []:
                if not (skill_dir / "SKILL.md").is_file():
                    continue
                target = root / skill_dir.name
                if target.exists():
                    shutil.rmtree(target)
                    removed.append(str(target))
            # Remove this package's agent definitions from the runtime's
            # native agents dir (only files whose name matches a package
            # agent; never delete the whole dir).
            agent_layout = tmp / RUNTIME_LAYOUT[runtime] / "agents"
            agent_dest = RUNTIME_AGENT_DIRS.get(runtime)
            if agent_dest is not None and agent_layout.is_dir() and agent_dest.is_dir():
                for f in agent_layout.iterdir():
                    if not f.is_file():
                        continue
                    target = agent_dest / f.name
                    if target.exists():
                        target.unlink()
                        removed.append(str(target))
    finally:
        if tmp.exists() and tmp.name.endswith(".tmp"):
            shutil.rmtree(tmp)
    return removed


def install_package(client: Client, pkg: Package, runtimes: List[str], progress=None) -> InstallResult:
    """Download, verify, extract and install one package into runtimes."""
    config.ensure_dirs()
    cf = cache_path(pkg)
    if not cf.exists():
        client.download(pkg.id, cf, progress=progress)
    verify_checksum(cf, pkg)
    tmp = extract_to_temp(cf, pkg)
    try:
        result = install_layouts(tmp, pkg, runtimes)
        skills, commands, knowledge, has_readme = count_package(tmp)
        result.skills = skills
        result.commands = commands
        result.knowledge = knowledge
        result.has_readme = has_readme
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return result


def latest_installed_versions() -> Dict[str, str]:
    """{package-id: version} currently on disk, from installed.json."""
    from .config import load_installed

    return load_installed()


def installed_dir(package_id: str) -> Optional[Path]:
    """Legacy helper: the old nested install dir, if present."""
    d = Path.home() / ".claude" / "skills" / package_id
    return d if d.exists() else None
