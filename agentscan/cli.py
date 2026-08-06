"""agentscan — command-line interface for the AgentScan Trusted Distribution.

Commands:

    agentscan scan .                 scan a directory of agent skills (free)
    agentscan activate               activate a Trusted Distribution license
    agentscan logout                 remove the local license
    agentscan whoami                 show the active license
    agentscan search                 list available packages
    agentscan install <package>      install a package into Claude Code
    agentscan update                 update installed packages to the latest
    agentscan verify                 verify installed packages

The scanner is free and local. Everything distribution-related talks to the
website API through agentscan.api.Client — swap the base URL and the whole
CLI points at a different backend.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Optional

from . import __version__
from .api import ApiError, Client
from .config import (
    DEFAULT_POLAR_ORGANIZATION_ID,
    api_url,
    clear_license,
    load_installed,
    load_license,
    save_installed,
    save_license,
)
from .installer import InstallError, install_package
from .models import Package
from .ui import banner, bold, dim, err, green, ok, prompt, red, step, warn, yellow
from .verify import verify_package


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _client() -> Client:
    lic = load_license()
    return Client(api_url(), license_key=lic.key if lic else None)


def _require_license() -> None:
    lic = load_license()
    if lic is None:
        err("not activated — run 'agentscan activate' first")
        raise SystemExit(1)
    return lic  # type: ignore[return-value]


def _print_package(pkg: Package, width: int = 18) -> None:
    print(f"  {bold(pkg.title):<{width}}  {green(pkg.version):<10} {dim(pkg.description)}")


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
            "critical": red, "high": red, "medium": yellow, "low": None, "info": dim,
        }.get(f["severity"])
        sev = f["severity"].upper()
        line = f"  {sev:8s} [{f['check']}] {f['title']}"
        print(color(line) if color else line)
        print(f"           {loc}")
        if f.get("detail"):
            print(f"           {dim(f['detail'])}")

    s = res["summary"]
    print(f"\n  summary: critical={s['critical']} high={s['high']} "
          f"medium={s['medium']} low={s['low']} info={s['info']}")
    print(dim("  note: findings are observed patterns, not verdicts. Review each before acting."))

    from scanaskill.common import SEV_ORDER

    threshold = SEV_ORDER.get(severity, 2)
    worst = max((SEV_ORDER.get(f["severity"], 0) for f in res["findings"]), default=0)
    return 1 if worst >= threshold else 0


def cmd_activate() -> int:
    lic = load_license()
    if lic is not None:
        ok(f"already activated as {lic.customer} ({lic.plan})")
        return 0
    key = prompt("Enter your AgentScan license:")
    if not key:
        err("no license key provided")
        return 1
    client = Client(api_url())
    step("verifying license…")
    try:
        result = client.activate(key, DEFAULT_POLAR_ORGANIZATION_ID)
    except ApiError as e:
        err(f"activation failed: {e}")
        return 1
    save_license(result)
    ok(f"activated — welcome, {result.customer} ({result.plan})")
    if result.expires_at:
        print(dim(f"  expires {result.expires_at}"))
    else:
        print(dim("  no expiry"))
    return 0


def cmd_logout() -> int:
    if load_license() is None:
        warn("not activated")
        return 0
    clear_license()
    ok("logged out")
    return 0


def cmd_whoami() -> int:
    lic = load_license()
    if lic is None:
        warn("not activated — run 'agentscan activate'")
        return 1
    print(f"  {bold(lic.customer)}")
    print(f"  plan:      {lic.plan}")
    print(f"  license:   {lic.key}")
    print(f"  expires:   {lic.expires_at or 'never'}")
    print(dim(f"  api:       {api_url()}"))
    return 0


def cmd_search() -> int:
    client = _client()
    step("fetching catalog…")
    try:
        catalog = client.search()
    except ApiError as e:
        err(str(e))
        return 1
    if not catalog.packages:
        warn("catalog is empty")
        return 0
    banner("Trusted Distribution")
    for pkg in catalog.packages:
        _print_package(pkg)
    print(dim(f"\n  {len(catalog.packages)} package(s) — 'agentscan install <name>' to install"))
    return 0


def _resolve_package(client: Client, package_id: str) -> Optional[Package]:
    try:
        catalog = client.search()
    except ApiError as e:
        err(str(e))
        return None
    pkg = catalog.find(package_id)
    if pkg is None:
        err(f"unknown package: {package_id} — run 'agentscan search'")
    return pkg


def cmd_install(package_id: str) -> int:
    _require_license()
    client = _client()
    pkg = _resolve_package(client, package_id)
    if pkg is None:
        return 1
    try:
        install_package(client, pkg)
    except (ApiError, InstallError) as e:
        err(str(e))
        return 1
    installed = load_installed()
    installed[pkg.id] = pkg.version
    save_installed(installed)
    ok(f"{pkg.id} {pkg.version} installed")
    return 0


def cmd_update() -> int:
    _require_license()
    client = _client()
    installed = load_installed()
    if not installed:
        warn("nothing installed yet — 'agentscan search' then 'agentscan install <name>'")
        return 0
    step("fetching catalog…")
    try:
        catalog = client.search()
    except ApiError as e:
        err(str(e))
        return 1

    updated = 0
    for package_id, current in sorted(installed.items()):
        pkg = catalog.find(package_id)
        if pkg is None:
            warn(f"{package_id}: no longer in catalog")
            continue
        if pkg.version == current:
            print(f"  {bold(pkg.title)} {green(pkg.version)} — up to date")
            continue
        print(f"  {bold(pkg.title)} {dim(current)} → {green(pkg.version)}")
        try:
            install_package(client, pkg)
        except (ApiError, InstallError) as e:
            err(f"{package_id}: {e}")
            continue
        installed[package_id] = pkg.version
        updated += 1
    save_installed(installed)
    if updated:
        ok(f"updated {updated} package(s)")
    else:
        ok("everything is up to date")
    return 0


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
        err(str(e))
        return 1

    all_ok = True
    for package_id, version in sorted(installed.items()):
        pkg = catalog.find(package_id)
        if pkg is None:
            err(f"{package_id}: not found in catalog")
            all_ok = False
            continue
        banner(pkg.title)
        checks = verify_package(pkg, version, client)
        for label, passed, detail in checks:
            if passed:
                ok(f"{label} — {detail}")
            else:
                err(f"{label} — {detail}")
                all_ok = False
        print()
    return 0 if all_ok else 1


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agentscan",
        description="The trust layer for AI agent skills. Free scanner + Trusted Distribution.",
    )
    p.add_argument("--version", action="version", version=f"agentscan {__version__}")
    sub = p.add_subparsers(dest="command", metavar="<command>")

    sp = sub.add_parser("scan", help="scan a directory of agent skills (free, local)")
    sp.add_argument("path", nargs="?", default=".")
    sp.add_argument("--severity", default="medium",
                    choices=["info", "low", "medium", "high", "critical"])

    sub.add_parser("activate", help="activate a Trusted Distribution license")
    sub.add_parser("logout", help="remove the local license")
    sub.add_parser("whoami", help="show the active license")
    sub.add_parser("search", help="list packages in the Trusted Distribution")

    sp = sub.add_parser("install", help="install a package into Claude Code")
    sp.add_argument("package", metavar="<package>")

    sub.add_parser("update", help="update installed packages to the latest version")
    sub.add_parser("verify", help="verify installed packages")
    return p


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
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
        return cmd_install(args.package)
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
