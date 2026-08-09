"""Tests for the agentscan Trusted Distribution layer.

Coverage: typed models, local config/state, installer checksum+manifest
guards, and verifier checks. Network and real installs are exercised
end-to-end in the docs; here we stay offline and deterministic.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

from agentscan import config
from agentscan.installer import InstallError, _extract, _sha256
from agentscan.models import Catalog, License, Package, normalize_name
from agentscan.verify import verify_package

# Repo root (tests/..): used to put the package on sys.path in subprocess
# probes so a fresh interpreter imports the same source tree.
ROOT_SRC = str(Path(__file__).resolve().parent.parent)


def make_pkg(**overrides) -> Package:
    base = dict(
        id="trust-pack",
        title="Trust Pack",
        version="1.0.0",
        description="The core professional skill bundle.",
        sha256="",
        release="v1.0.0",
        asset="trust-pack-1.0.0.tar.gz",
    )
    base.update(overrides)
    return Package.from_dict(base)


def make_tarball(dest: Path, pkg_id: str, manifest_ok: bool = True) -> Path:
    """Build a valid package tarball with a top-level dir, like the registry."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        payload = {
            "manifest.json": json.dumps(
                {"id": pkg_id, "version": "1.0.0"} if manifest_ok else {"id": "wrong"}
            ),
            "README.md": "# " + pkg_id,
            "audit.json": json.dumps({"status": "passed"}),
            "skills/SKILL.md": "---\nname: " + pkg_id + "\n---\nDo things.",
        }
        for name, content in payload.items():
            info = tarfile.TarInfo(f"{pkg_id}/{name}")
            data = content.encode()
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    dest.write_bytes(buf.getvalue())
    return dest


class ModelsTest(unittest.TestCase):
    def test_package_from_dict(self):
        p = make_pkg()
        self.assertEqual(p.id, "trust-pack")
        self.assertEqual(p.version, "1.0.0")

    def test_catalog_find(self):
        p = make_pkg()
        c = Catalog.from_dict({"packages": [p.__dict__]})
        self.assertIsNotNone(c.find("trust-pack"))
        self.assertIsNone(c.find("nope"))


class ResolveTest(unittest.TestCase):
    """Package-name matching: normalize + resolve."""

    def setUp(self):
        pkgs = [
            {"id": "security-engineer", "title": "Security Engineer", "version": "2.0.0",
             "description": "Threat modeling.", "sha256": "", "release": "v2.0.0", "asset": "a.tar.gz"},
            {"id": "backend-engineer", "title": "Backend Engineer", "version": "2.0.0",
             "description": "APIs.", "sha256": "", "release": "v2.0.0", "asset": "b.tar.gz"},
            {"id": "devops-engineer", "title": "DevOps Engineer", "version": "2.0.0",
             "description": "CI/CD.", "sha256": "", "release": "v2.0.0", "asset": "c.tar.gz"},
            {"id": "ai-engineer", "title": "AI Engineer", "version": "2.0.0",
             "description": "LLMs.", "sha256": "", "release": "v2.0.0", "asset": "d.tar.gz"},
        ]
        self.catalog = Catalog.from_dict({"packages": pkgs})

    def test_normalize_name(self):
        self.assertEqual(normalize_name("DevOps Engineer"), "devops engineer")
        self.assertEqual(normalize_name("devops-engineer"), "devops engineer")
        self.assertEqual(normalize_name("DEVOPS_ENGINEER"), "devops engineer")
        self.assertEqual(normalize_name("  devops   engineer "), "devops engineer")

    def test_exact_id(self):
        pkg, note, cands, sugg = self.catalog.resolve("devops-engineer")
        self.assertEqual(pkg.id, "devops-engineer")
        self.assertEqual(note, "")
        self.assertEqual(cands, [])
        self.assertIsNone(sugg)

    def test_exact_title_with_spaces(self):
        pkg, note, cands, _ = self.catalog.resolve("DevOps Engineer")
        self.assertEqual(pkg.id, "devops-engineer")
        self.assertEqual(note, "")

    def test_uppercase_and_spaces(self):
        pkg, _, _, _ = self.catalog.resolve("DEVOPS ENGINEER")
        self.assertEqual(pkg.id, "devops-engineer")

    def test_prefix_resolves(self):
        pkg, note, _, _ = self.catalog.resolve("devops")
        self.assertEqual(pkg.id, "devops-engineer")
        self.assertIn("matched", note)

    def test_fuzzy_typo(self):
        pkg, note, _, _ = self.catalog.resolve("secuirty")
        self.assertEqual(pkg.id, "security-engineer")
        self.assertIn("matched", note)

    def test_ambiguous_prefix_returns_candidates(self):
        # "engineer" is a prefix of every title/id — must be ambiguous.
        pkg, note, cands, sugg = self.catalog.resolve("engineer")
        self.assertIsNone(pkg)
        self.assertTrue(len(cands) >= 2)
        self.assertIn("security-engineer", cands)
        self.assertIsNone(sugg)

    def test_unknown_returns_suggestion(self):
        pkg, note, cands, sugg = self.catalog.resolve("database")
        self.assertIsNone(pkg)
        self.assertEqual(cands, [])
        # no close match at cutoff — suggestion may be None (fine)
        self.assertIn(sugg, (None, "backend-engineer", "security-engineer", "devops-engineer", "ai-engineer"))

    def test_license_roundtrip(self):
        lic = License.from_dict({"license_key": "ABCD-EFGH-1234", "customer": "Ada", "plan": "trusted-distribution", "expires_at": None})
        self.assertEqual(lic.key, "ABCD-EFGH-1234")
        self.assertIsNone(lic.expires_at)

    def test_license_from_polar_response(self):
        # The customer-portal validate endpoint returns customer as an object.
        lic = License.from_dict({
            "key": "POLAR_ABCDEF",
            "status": "granted",
            "customer": {"email": "ada@example.com", "name": "Ada Lovelace"},
            "expires_at": None,
        })
        self.assertEqual(lic.key, "POLAR_ABCDEF")
        self.assertEqual(lic.customer, "Ada Lovelace")

    def test_license_customer_object_falls_back_to_email(self):
        lic = License.from_dict({
            "key": "POLAR_ABCDEF",
            "customer": {"email": "ada@example.com"},
            "expires_at": None,
        })
        self.assertEqual(lic.customer, "ada@example.com")


class ConfigTest(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        base = Path(self._dir.name)
        # The path constants are module globals — patch them all.
        for name in ("AGENTSCAN_DIR", "LICENSE_FILE", "INSTALLED_FILE", "CONFIG_FILE", "CACHE_DIR"):
            setattr(config, name, base / name.lower())
        config.ensure_dirs()

    def tearDown(self):
        self._dir.cleanup()

    def test_installed_roundtrip(self):
        self.assertEqual(config.load_installed(), {})
        config.save_installed({"security-engineer": {"version": "1.0.0", "runtimes": {}}})
        self.assertEqual(
            config.load_installed(),
            {"security-engineer": {"version": "1.0.0", "runtimes": {}}},
        )

    def test_installed_v1_backward_compat(self):
        """A bare {pkg: version} file (v1) loads as the v2 shape."""
        config.INSTALLED_FILE.write_text('{"security-engineer": "1.0.0"}\n')
        self.assertEqual(
            config.load_installed(),
            {"security-engineer": {"version": "1.0.0", "runtimes": {}}},
        )

    def test_license_roundtrip(self):
        lic = License.from_dict({"license_key": "A", "customer": "B", "plan": "p", "expires_at": None})
        config.save_license(lic)
        loaded = config.load_license()
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.key, "A")
        config.clear_license()
        self.assertIsNone(config.load_license())

    def test_api_url_default_and_override(self):
        self.assertEqual(config.api_url(), config.DEFAULT_API_URL)
        config.set_api_url("http://localhost:9999")
        self.assertEqual(config.api_url(), "http://localhost:9999")

    def test_polar_org_id_is_embedded_constant(self):
        # The org id is public metadata, baked into the CLI — never read
        # from the environment, never a user-configuration step.
        self.assertEqual(
            config.DEFAULT_POLAR_ORGANIZATION_ID,
            "75ee754e-8e6c-4808-b082-f4384819459c",
        )


class InstallerTest(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)
        self.cache = self.root / "cache"
        self.cache.mkdir()

    def tearDown(self):
        self._dir.cleanup()

    def test_extract_strips_top_level(self):
        tarball = make_tarball(self.root / "pkg.tar.gz", "security-engineer")
        dest = self.root / "out"
        _extract(tarball, dest)
        self.assertTrue((dest / "manifest.json").exists())
        self.assertTrue((dest / "skills" / "SKILL.md").exists())
        self.assertFalse((dest / "security-engineer").exists())

    def test_sha256(self):
        f = self.root / "blob"
        f.write_bytes(b"hello")
        self.assertEqual(_sha256(f), hashlib.sha256(b"hello").hexdigest())

    def test_extract_rejects_no_top_level(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            data = b"flat file"
            info = tarfile.TarInfo("flat.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        tarball = self.root / "flat.tar.gz"
        tarball.write_bytes(buf.getvalue())
        with self.assertRaises(InstallError):
            _extract(tarball, self.root / "out2")


class VerifyTest(unittest.TestCase):
    def test_signature_placeholder_missing(self):
        pkg = make_pkg(sha256="a" * 64)
        checks = verify_package(pkg, "1.0.0", client=None)  # type: ignore[arg-type]
        labels = {c[0]: c[1] for c in checks}
        self.assertIn("Signature Valid", labels)
        # not installed → signature and audit fail
        self.assertFalse(labels["Signature Valid"])
        self.assertFalse(labels["Audit Passed"])
        # checksum provided but no cached tarball → not intact
        self.assertFalse(labels["Package Intact"])


class RuntimeTest(unittest.TestCase):
    """Runtime resolution + per-runtime layout installs."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)

    def tearDown(self):
        self._dir.cleanup()

    def test_resolve_auto_uses_detected(self):
        from agentscan.runtimes import resolve_runtimes

        self.assertEqual(resolve_runtimes(None, detected=["claude"]), ["claude"])
        self.assertEqual(resolve_runtimes("auto", detected=["opencode"]), ["opencode"])
        self.assertEqual(
            resolve_runtimes("all", detected=[]),
            ["claude", "opencode", "codex", "hermes", "grok"],
        )

    def test_resolve_explicit_flag_wins(self):
        from agentscan.runtimes import resolve_runtimes

        # Explicit --runtime wins even if detection says absent.
        self.assertEqual(resolve_runtimes("codex", detected=["claude"]), ["codex"])
        self.assertEqual(resolve_runtimes("opencode", detected=[]), ["opencode"])
        self.assertEqual(resolve_runtimes("hermes", detected=["claude"]), ["hermes"])
        self.assertEqual(resolve_runtimes("grok", detected=["claude"]), ["grok"])

    def test_resolve_unknown_flag_empty(self):
        from agentscan.runtimes import resolve_runtimes

        self.assertEqual(resolve_runtimes("bogus", detected=["claude"]), [])

    def test_hermes_home_override_and_detection(self):
        """HERMES_HOME is the official skills-root override; detection
        must honor it (Hermes docs: hermes-agent.nousresearch.com/docs).

        RUNTIME_DIRS is resolved at import time (the CLI is a fresh process
        per run), so the env-var coupling is asserted in a subprocess with
        HERMES_HOME set — the same conditions a real install runs under.
        """
        import agentscan.runtimes as rt
        from agentscan.installer import RUNTIME_DIRS

        # Default (no override): ~/.hermes, and the skills root derives from it.
        self.assertEqual(rt.hermes_home_dir(), Path.home() / ".hermes")
        self.assertEqual(RUNTIME_DIRS["hermes"], Path.home() / ".hermes" / "skills")

        # Detection reports hermes when the dir exists.
        found = rt.detect_runtimes()
        self.assertIn("hermes", found)

        # Env override at process start drives the import-time resolution.
        probe = (
            "import sys; sys.path.insert(0, %r); "
            "from agentscan.installer import RUNTIME_DIRS; "
            "print(RUNTIME_DIRS['hermes'])" % str(ROOT_SRC)
        )
        env = dict(os.environ, HERMES_HOME="/tmp/hermes-custom")
        r = subprocess.run(
            [sys.executable, "-c", probe], capture_output=True, text=True,
            env=env, timeout=60,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "/tmp/hermes-custom/skills")

    def test_grok_home_override_and_detection(self):
        """GROK_HOME is the official Grok Build home override; detection
        and the installer must honor it.

        Verified in the grok-build source (xai_grok_config::user_grok_home)
        and the @xai-official/grok npm launcher. RUNTIME_DIRS resolves at
        import time (fresh process per CLI run), so the env coupling is
        asserted in a subprocess, same as the Hermes probe.
        """
        import agentscan.runtimes as rt
        from agentscan.installer import RUNTIME_DIRS

        # Default (no override): ~/.grok.
        self.assertEqual(rt.grok_home_dir(), Path.home() / ".grok")
        self.assertEqual(RUNTIME_DIRS["grok"], Path.home() / ".grok" / "skills")

        # Detection reports grok when the dir exists or binary is on PATH.
        found = rt.detect_runtimes()
        self.assertIn("grok", found)

        # Env override at process start drives the import-time resolution.
        probe = (
            "import sys; sys.path.insert(0, %r); "
            "from agentscan.installer import RUNTIME_DIRS; "
            "print(RUNTIME_DIRS['grok'])" % str(ROOT_SRC)
        )
        env = dict(os.environ, GROK_HOME="/tmp/grok-custom")
        r = subprocess.run(
            [sys.executable, "-c", probe], capture_output=True, text=True,
            env=env, timeout=60,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "/tmp/grok-custom/skills")

    def test_install_layouts_flattens_skills(self):
        """Each runtime root gets <skill-id>/SKILL.md one level deep."""
        import agentscan.installer as inst
        from agentscan.runtimes import RUNTIMES

        # Build a fake extracted package with per-runtime layouts.
        pkg = make_pkg()
        tmp = self.root / "pkg"
        for runtime in ("claude", "opencode", "codex", "hermes", "grok"):
            layout = tmp / runtime / "skill-a"
            layout.mkdir(parents=True)
            (layout / "SKILL.md").write_text(
                "---\nname: skill-a\ndescription: x\nlicense: MIT\n---\nbody\n"
            )
        (tmp / "AGENTS.md").write_text("---\nlicense: MIT\n---\n# setup\n")

        # Point the installer at sandbox roots AND sandbox CWD so the
        # AGENTS.md write cannot touch the real repository.
        orig = inst.RUNTIME_DIRS
        orig_cwd = Path.cwd()
        inst.RUNTIME_DIRS = {
            "claude": self.root / "claude-skills",
            "opencode": self.root / "opencode-skills",
            "codex": self.root / "agents-skills",
            "hermes": self.root / "hermes-skills",
            "grok": self.root / "grok-skills",
        }
        try:
            fake_repo = self.root / "repo"
            fake_repo.mkdir()
            subprocess.run(["git", "init", "-q", str(fake_repo)], check=True)
            os.chdir(fake_repo)
            result = inst.install_layouts(tmp, pkg, list(RUNTIMES))
            for runtime, root in inst.RUNTIME_DIRS.items():
                self.assertTrue((root / "skill-a" / "SKILL.md").is_file(),
                                f"{runtime} skill not flattened")
            self.assertEqual(
                sorted(result.dests),
                ["claude", "codex", "grok", "hermes", "opencode"],
            )
            self.assertTrue((fake_repo / "AGENTS.md").is_file())
        finally:
            os.chdir(orig_cwd)
            inst.RUNTIME_DIRS = orig

    def test_install_layouts_requires_skills(self):
        import agentscan.installer as inst

        pkg = make_pkg()
        tmp = self.root / "pkg"
        (tmp / "claude").mkdir(parents=True)
        with self.assertRaises(InstallError):
            inst.install_layouts(tmp, pkg, ["claude"])

    def test_remove_package_only_flattened(self):
        import agentscan.installer as inst

        pkg = make_pkg()
        tmp = self.root / "pkg"
        layout = tmp / "claude" / "skill-a"
        layout.mkdir(parents=True)
        (layout / "SKILL.md").write_text(
            "---\nname: skill-a\ndescription: x\nlicense: MIT\n---\nbody\n"
        )
        (tmp / "AGENTS.md").write_text("---\nlicense: MIT\n---\n# setup\n")

        orig = inst.RUNTIME_DIRS
        orig_cache = inst.cache_path
        orig_cwd = Path.cwd()
        inst.RUNTIME_DIRS = {
            "claude": self.root / "claude-skills",
            "opencode": self.root / "o",
            "codex": self.root / "c",
            "hermes": self.root / "h",
            "grok": self.root / "g",
        }
        inst.cache_path = lambda pkg: self.root / "pkg.tar.gz"
        try:
            # Sandbox CWD inside a fake git repo so _write_agents_md /
            # _find_agents_root cannot touch the real repository.
            fake_repo = self.root / "repo"
            fake_repo.mkdir()
            subprocess.run(["git", "init", "-q", str(fake_repo)], check=True)
            os.chdir(fake_repo)

            # Seed the cache with a tarball so remove can reconstruct skills.
            import io as _io, tarfile as _tf

            buf = _io.BytesIO()
            with _tf.open(fileobj=buf, mode="w:gz") as tf:
                for name, content in {
                    "pkg/manifest.json": json.dumps({"id": "trust-pack", "version": "1.0.0"}),
                    "pkg/claude/skill-a/SKILL.md": "---\nname: skill-a\ndescription: x\nlicense: MIT\n---\nbody\n",
                    "pkg/AGENTS.md": "---\nlicense: MIT\n---\n# setup\n",
                }.items():
                    info = _tf.TarInfo(name)
                    data = content.encode()
                    info.size = len(data)
                    tf.addfile(info, _io.BytesIO(data))
            (self.root / "pkg.tar.gz").write_bytes(buf.getvalue())

            # Install into claude, then remove only claude's flattened dir.
            inst.install_layouts(tmp, pkg, ["claude"])
            root = inst.RUNTIME_DIRS["claude"]
            self.assertTrue((root / "skill-a").exists())
            removed = inst.remove_package(pkg, ["claude"])
            self.assertFalse((root / "skill-a").exists())
            self.assertEqual(len(removed), 1)
            # AGENTS.md must land in the fake repo, not the real one.
            self.assertTrue((fake_repo / "AGENTS.md").is_file())
        finally:
            os.chdir(orig_cwd)
            inst.RUNTIME_DIRS = orig
            inst.cache_path = orig_cache


if __name__ == "__main__":
    unittest.main()
