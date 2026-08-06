"""Tests for the agentscan Trusted Distribution layer.

Coverage: typed models, local config/state, installer checksum+manifest
guards, and verifier checks. Network and real installs are exercised
end-to-end in the docs; here we stay offline and deterministic.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from agentscan import config
from agentscan.installer import InstallError, _extract, _sha256
from agentscan.models import Catalog, License, Package, normalize_name
from agentscan.verify import verify_package


def make_pkg(**overrides) -> Package:
    base = dict(
        id="security-engineer",
        title="Security Engineer",
        version="1.0.0",
        description="Threat modeling and secure code auditing.",
        sha256="",
        release="v1.0.0",
        asset="security-engineer-1.0.0.tar.gz",
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
        self.assertEqual(p.id, "security-engineer")
        self.assertEqual(p.version, "1.0.0")

    def test_catalog_find(self):
        p = make_pkg()
        c = Catalog.from_dict({"packages": [p.__dict__]})
        self.assertIsNotNone(c.find("security-engineer"))
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
        config.save_installed({"security-engineer": "1.0.0"})
        self.assertEqual(config.load_installed(), {"security-engineer": "1.0.0"})

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


if __name__ == "__main__":
    unittest.main()
