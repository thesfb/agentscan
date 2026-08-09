"""agentscan — command-line interface for the AgentScan Trusted Distribution.

Commands:

    agentscan scan .                 scan a directory of agent skills (free)
    agentscan activate               activate a Trusted Distribution license
    agentscan logout                 remove the local license
    agentscan whoami                 show the active license
    agentscan search                 browse the catalog
    agentscan install <package>      install a package (auto-detect runtime)
    agentscan install <p> --runtime codex   install into a specific runtime
    agentscan install <p> --runtime grok    install into Grok Build
    agentscan update                 update installed packages
    agentscan verify                 verify installed packages

Every command follows the same shape: start → progress → result → next
step. Pass --quiet to suppress progress lines for automation.

The scanner is free and local. Everything distribution-related talks to the
website API through agentscan.api.Client — swap the base URL and the whole
CLI points at a different backend.
"""

from __future__ import annotations

import argparse
import difflib
import os
import sys
import textwrap
from pathlib import Path
from typing import Optional

from . import __version__
from .api import ApiError, Client
from .config import (
    DEFAULT_POLAR_ORGANIZATION_ID,
    api_url,
    clear_license,
    ensure_dirs,
    load_installed,
    load_license,
    save_installed,
    save_license,
)
from . import installer
from .installer import InstallError, RUNTIME_AGENT_DIRS, RUNTIME_DIRS, RUNTIME_NAMES
from .models import Catalog, Package, normalize_name
from . import runtimes
from .runtimes import detect_installed, prompt_for_runtime, resolve_runtimes
from . import ui
from .ui import banner, bold, dim, done, err, hint, info, ok, prompt, rule, step, warn
from .verify import verify_package

EXAMPLES = """\
examples:
  agentscan scan .
  agentscan activate
  agentscan search
  agentscan install trust-pack
  agentscan update
  agentscan verify

Use 'agentscan <command> --help' for details on a command.
"""


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _client() -> Client:
    lic = load_license()
    return Client(api_url(), license_key=lic.key if lic else None)


def _require_license():
    lic = load_license()
    if lic is None:
        err("not activated — run 'agentscan activate' first")
        hint("agentscan activate")
        raise SystemExit(1)
    return lic


def _wrap(text: str, width: int = 62) -> list:
    """Wrap to at most two lines, with an ellipsis when truncated."""
    lines = textwrap.wrap(text, width=width)
    if len(lines) > 2:
        lines = lines[:2]
        lines[-1] = lines[-1].rstrip(".") + "…"
    return lines


def _network_error(e: ApiError) -> None:
    err("unable to reach the AgentScan registry")
    print()
    print("  Check your internet connection.")
    print(f"  API: {api_url()}")
    if str(e):
        print(f"  details: {e}")


def _license_error(e: ApiError) -> None:
    err("license validation failed")
    print()
    print("  Possible reasons:")
    print("    • invalid key")
    print("    • revoked license")
    print("    • expired license")
    print()
    if str(e):
        info(f"details: {e}")
    hint("agentscan activate")


def _unknown_package(query: str, catalog: Catalog) -> None:
    err(f"unknown package: {query}")
    # best guess for "did you mean"
    pool: dict[str, str] = {}
    for p in catalog.packages:
        pool.setdefault(normalize_name(p.id), p.id)
        pool.setdefault(normalize_name(p.title), p.id)
    guess = difflib.get_close_matches(normalize_name(query), list(pool), n=1, cutoff=0.4)
    if guess:
        print()
        print("  Did you mean:")
        print(f"    {pool[guess[0]]}")
        print()
    hint("agentscan search")


def _validate_license(lic) -> bool:
    """Re-validate the stored license against Polar. True when valid."""
    step("validating license…")
    try:
        Client(api_url()).activate(lic.key, DEFAULT_POLAR_ORGANIZATION_ID)
    except ApiError as e:
        ui.progress_end()
        _license_error(e)
        return False
    ok("license valid")
    return True


def _install_flow(client: Client, pkg: Package, lic, runtimes_: List[str]) -> int:
    """Install one package with full progress UI. Returns exit code."""
    if not _validate_license(lic):
        return 1

    ensure_dirs()
    cf = installer.cache_path(pkg)
    if cf.exists():
        info("package already downloaded")
        ok("download complete")
    else:
        step(f"downloading {pkg.asset}…")
        try:
            client.download(pkg.id, cf, progress=ui.progress)
        except ApiError as e:
            ui.progress_end()
            _network_error(e)
            return 1
        ui.progress_end()
        ok("download complete")

    step("verifying checksum…")
    try:
        installer.verify_checksum(cf, pkg)
    except InstallError as e:
        err(str(e))
        return 1
    ok("SHA256 verified")

    step("extracting package…")
    try:
        tmp = installer.extract_to_temp(cf, pkg)
    except InstallError as e:
        err(str(e))
        return 1

    step("installing skills…")
    counts = (0, 0, 0, False)
    try:
        result = installer.install_layouts(tmp, pkg, runtimes_)
        counts = installer.count_package(tmp)
    except InstallError as e:
        err(str(e))
        return 1
    finally:
        import shutil as _shutil

        _shutil.rmtree(tmp, ignore_errors=True)

    # Bookkeeping: record version + per-runtime skill lists.
    installed = load_installed()
    record = installed.get(pkg.id, {"version": pkg.version, "runtimes": {}})
    record["version"] = pkg.version
    for runtime in runtimes_:
        root = RUNTIME_DIRS[runtime]
        skills = sorted(
            d.name for d in root.iterdir() if d.is_dir() and (d / "SKILL.md").is_file()
        ) if root.is_dir() else []
        record["runtimes"][runtime] = {"skills": skills}
    installed[pkg.id] = record
    save_installed(installed)
    done(f"installed {pkg.title} v{pkg.version}")
    print()
    _install_summary(pkg, counts, record["runtimes"], result.agents_written)
    hint("agentscan search")
    return 0


def _install_summary(pkg: Package, counts, runtimes_: dict, agents_written) -> None:
    skills, commands, knowledge, has_readme = counts
    rule()
    print(f"  Installed")
    print(f"    {bold(pkg.title)}")
    print("  Version")
    print(f"    {pkg.version}")
    for runtime, record in runtimes_.items():
        print(f"  {RUNTIME_NAMES.get(runtime, runtime)}")
        print(f"    {RUNTIME_DIRS[runtime]}")
        n = len(record.get("skills", []))
        print(f"    {n} skill(s)")
        agent_dir = RUNTIME_AGENT_DIRS.get(runtime)
        if agent_dir is not None:
            agent_files = sorted(
                p.name for p in agent_dir.iterdir() if p.is_file()
            ) if agent_dir.is_dir() else []
            print(f"    {len(agent_files)} agent(s)")
            if agent_files:
                print(f"    {agent_dir}")
    if skills or commands or knowledge or has_readme:
        print("  Package contents")
        if skills:
            print(f"    skills:      {skills}")
        if commands:
            print(f"    commands:    {commands}")
        if knowledge:
            print(f"    knowledge:   {knowledge}")
        if has_readme:
            print(f"    README:      included")
    if agents_written:
        print("  AGENTS.md")
        for path in agents_written:
            print(f"    {path}")
    rule()
    done("ready to use")


def _package_card(pkg: Package) -> None:
    rule()
    print(f"  {bold(pkg.title)}")
    print(f"  id:      {pkg.id}")
    print(f"  version: {pkg.version}")
    for line in _wrap(pkg.description):
        print(f"  {line}")
    print()
    print(f"  install: agentscan install {pkg.id}")
    rule()


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


def cmd_scan(path: str, severity: str) -> int:
    """Free scanner: delegate to the scanaskill core and render compactly."""
    try:
        from scanaskill.scanner import scan_directory
    except ImportError:
        err("scanner core unavailable (install scanaskill)")
        return 2
    if not Path(path).is_dir():
        err(f"not a directory: {path}")
        return 2

    step(f"scanning {path}…")
    res = scan_directory(path)
    banner(f"agentscan {__version__} — {res['target']}")
    print(f"scanned {len(res['skills'])} artifact(s), {len(res['findings'])} finding(s)")

    for skill in res["skills"]:
        name = skill["name"]
        fmt = skill.get("format", "generic")
        desc = f" — {skill['description'][:70]}" if skill.get("description") else ""
        print(f"  ARTIFACT  [{fmt}] {name}{desc}")

    for f in res["findings"]:
        rel = os.path.relpath(f["path"], res["target"])
        loc = f"{rel}:{f['line']}" if f.get("line") else rel
        color = {
            "critical": ui.red, "high": ui.red, "medium": ui.yellow, "low": None, "info": ui.dim,
        }.get(f["severity"])
        sev = f["severity"].upper()
        line = f"  {sev:8s} [{f['check']}] {f['title']}"
        print(color(line) if color else line)
        print(f"           {loc}")
        if f.get("detail"):
            print(f"           {ui.dim(f['detail'])}")

    s = res["summary"]
    print(f"\n  summary: critical={s['critical']} high={s['high']} "
          f"medium={s['medium']} low={s['low']} info={s['info']}")
    print(ui.dim("  note: findings are observed patterns, not verdicts. Review each before acting."))

    from scanaskill.common import SEV_ORDER

    threshold = SEV_ORDER.get(severity, 2)
    worst = max((SEV_ORDER.get(f["severity"], 0) for f in res["findings"]), default=0)
    return 1 if worst >= threshold else 0


def cmd_activate() -> int:
    lic = load_license()
    if lic is not None:
        done(f"already activated as {lic.customer} ({lic.plan})")
        hint("agentscan search")
        return 0
    key = prompt("Enter your AgentScan license:")
    if not key:
        err("no license key provided")
        return 1
    step("contacting Polar…")
    try:
        result = Client(api_url()).activate(key, DEFAULT_POLAR_ORGANIZATION_ID)
    except ApiError as e:
        _license_error(e)
        return 1
    ok("license validated")
    step("saving license…")
    save_license(result)
    done("activation successful")
    print(f"  {bold(result.customer)} ({result.plan})")
    info(f"expires: {result.expires_at or 'never'}")
    hint("agentscan search")
    return 0


def cmd_logout() -> int:
    if load_license() is None:
        warn("not activated")
        return 0
    step("removing local license…")
    clear_license()
    done("logged out")
    hint("agentscan activate")
    return 0


def cmd_whoami() -> int:
    lic = load_license()
    if lic is None:
        warn("not activated — run 'agentscan activate'")
        return 1
    rule()
    print(f"  {bold(lic.customer)}")
    print(f"  plan:     {lic.plan}")
    print(f"  license:  {lic.key}")
    print(f"  expires:  {lic.expires_at or 'never'}")
    print(f"  api:      {api_url()}")
    rule()
    hint("agentscan logout")
    return 0


def cmd_search() -> int:
    client = _client()
    step("fetching catalog…")
    try:
        catalog = client.search()
    except ApiError as e:
        _network_error(e)
        return 1
    if not catalog.packages:
        warn("catalog is empty")
        return 0
    ok(f"{len(catalog.packages)} package(s) available")
    print()
    for i, pkg in enumerate(catalog.packages):
        _package_card(pkg)
        if i < len(catalog.packages) - 1:
            print()
    hint("agentscan install <name>")
    return 0


def _resolve(catalog: Catalog, query: str) -> Optional[Package]:
    pkg, note, candidates, suggestion = catalog.resolve(query)
    if candidates:
        err(f"ambiguous package: {query}")
        print()
        print("  Did you mean one of:")
        for c in candidates:
            print(f"    {c}")
        print()
        hint("agentscan search")
        return None
    if pkg is None:
        _unknown_package(query, catalog)
        return None
    if note:
        info(note)
    return pkg


def cmd_install(query: str, runtime_flag: Optional[str] = None) -> int:
    _require_license()
    client = _client()
    step("fetching catalog…")
    try:
        catalog = client.search()
    except ApiError as e:
        _network_error(e)
        return 1
    ok("catalog received")

    pkg = _resolve(catalog, query)
    if pkg is None:
        return 1

    runtimes_ = resolve_runtimes(runtime_flag)
    if not runtimes_:
        detected = detect_installed()
        if not detected:
            warn("no supported agent runtime detected on this machine")
            info("pass --runtime claude|opencode|codex|hermes|grok to choose one")
            return 1
        runtimes_ = prompt_for_runtime()
        if not runtimes_:
            err("no runtime selected")
            return 1
    if runtime_flag in (None, "", "auto") and len(runtimes_) > 1:
        names = ", ".join(RUNTIME_NAMES.get(r, r) for r in runtimes_)
        info(f"detected runtime(s): {names}")
    return _install_flow(client, pkg, load_license(), runtimes_)


def cmd_update() -> int:
    _require_license()
    client = _client()
    installed = load_installed()
    if not installed:
        warn("nothing installed yet")
        hint("agentscan search")
        return 0
    step("checking for updates…")
    try:
        catalog = client.search()
    except ApiError as e:
        _network_error(e)
        return 1
    ok("catalog received")

    updated = 0
    failed = 0
    for package_id, record in sorted(installed.items()):
        version = record.get("version", "")
        runtimes_ = list(record.get("runtimes", {}).keys()) or detect_installed()
        pkg = catalog.find(package_id)
        if pkg is None:
            warn(f"{package_id}: no longer in catalog")
            continue
        print(f"  {bold(pkg.title)}")
        print(f"    current: {version}")
        print(f"    latest:  {pkg.version}")
        if pkg.version == version:
            ok("up to date")
            print()
            continue
        if _install_flow(client, pkg, load_license(), runtimes_) != 0:
            failed += 1
            print()
            continue
        updated += 1
        print()
    save_installed(installed)
    if updated:
        done(f"updated {updated} package(s)")
    if failed:
        err(f"{failed} update(s) failed")
    if not updated and not failed:
        ok("everything is up to date")
    return 1 if failed else 0


def cmd_verify() -> int:
    _require_license()
    client = _client()
    installed = load_installed()
    if not installed:
        warn("nothing installed — 'agentscan install <name>' first")
        return 1
    step("fetching catalog…")
    try:
        catalog = client.search()
    except ApiError as e:
        _network_error(e)
        return 1

    all_ok = True
    for package_id, record in sorted(installed.items()):
        version = record.get("version", "")
        runtimes_ = list(record.get("runtimes", {}).keys()) or detect_installed()
        pkg = catalog.find(package_id)
        if pkg is None:
            err(f"{package_id}: not found in catalog")
            all_ok = False
            continue
        rule()
        print(f"  {bold(pkg.title)}  {dim(version)}")
        checks = verify_package(pkg, version, client)
        for label, passed, detail in checks:
            if passed:
                ok(f"{label} — {detail}")
            else:
                err(f"{label} — {detail}")
                all_ok = False
        # Per-runtime layout check: each recorded skill dir must exist.
        for runtime, rrec in record.get("runtimes", {}).items():
            root = RUNTIME_DIRS[runtime]
            missing = [s for s in rrec.get("skills", []) if not (root / s / "SKILL.md").exists()]
            if missing:
                err(f"{runtime} — {len(missing)} skill(s) missing: {', '.join(missing[:3])}")
                all_ok = False
            else:
                ok(f"{runtime} — {len(rrec.get('skills', []))} skill(s) present")
        # Legacy nested install warning.
        legacy = Path.home() / ".claude" / "skills" / package_id
        if legacy.is_dir():
            warn("legacy nested layout detected at ~/.claude/skills/"
                 f"{package_id} — reinstall to make it discoverable")
        rule()
        print()
    return 0 if all_ok else 1


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    # Shared flags: --quiet works before OR after the subcommand.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-q", "--quiet", action="store_true", default=argparse.SUPPRESS,
                        help="suppress progress output (results and errors still print)")

    p = argparse.ArgumentParser(
        prog="agentscan",
        description="The trust layer for AI agent skills. Free scanner + Trusted Distribution.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[common],
    )
    p.add_argument("--version", action="version", version=f"agentscan {__version__}")
    sub = p.add_subparsers(dest="command", metavar="<command>")

    sp = sub.add_parser("scan", help="scan a directory of agent skills (free, local)", parents=[common])
    sp.add_argument("path", nargs="?", default=".")
    sp.add_argument("--severity", default="medium",
                    choices=["info", "low", "medium", "high", "critical"])

    sub.add_parser("activate", help="activate a Trusted Distribution license", parents=[common])
    sub.add_parser("logout", help="remove the local license", parents=[common])
    sub.add_parser("whoami", help="show the active license", parents=[common])
    sub.add_parser("search", help="browse the Trusted Distribution catalog", parents=[common])

    sp = sub.add_parser(
        "install",
        help="install a package into Claude Code, OpenCode, Codex, Hermes, or Grok Build",
        parents=[common],
    )
    sp.add_argument("package", nargs="+", metavar="<package>",
                    help="package id, title, or any unambiguous prefix")
    sp.add_argument(
        "--runtime", default=None, metavar="claude|opencode|codex|hermes|grok|all",
        help="target runtime (default: auto-detect installed runtimes)",
    )

    sub.add_parser("update", help="update installed packages to the latest version", parents=[common])
    sub.add_parser("verify", help="verify installed packages", parents=[common])
    return p


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
    ui.QUIET = bool(getattr(args, "quiet", False))
    if args.command == "scan":
        return cmd_scan(args.path, args.severity)
    if args.command == "activate":
        return cmd_activate()
    if args.command == "logout":
        return cmd_logout()
    if args.command == "whoami":
        return cmd_whoami()
    if args.command == "search":
        return cmd_search()
    if args.command == "install":
        return cmd_install(" ".join(args.package), getattr(args, "runtime", None))
    if args.command == "update":
        return cmd_update()
    if args.command == "verify":
        return cmd_verify()
    build_parser().print_help()
    return 0


def run() -> None:
    sys.exit(main())


if __name__ == "__main__":
    run()
