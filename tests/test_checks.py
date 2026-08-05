"""Tests for scanaskill v1 — deterministic checks only.

Run: python3 -m unittest discover -s tests -v
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanaskill.scanner import scan_directory  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
GOOD = os.path.join(FIXTURES, "good_skill")
EVIL = os.path.join(FIXTURES, "evil_skill")

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def by_check(findings, check):
    return [f for f in findings if f["check"] == check]


def worst(findings):
    if not findings:
        return "info"
    return max((f["severity"] for f in findings), key=lambda s: SEV_ORDER[s])


class TestShellCheck(unittest.TestCase):
    def test_evil_skill_flags_shell_invocations(self):
        res = scan_directory(EVIL)
        shell = by_check(res["findings"], "shell")
        # curl|bash, node -e, and the scripts/sync.sh bundled file
        self.assertGreaterEqual(len(shell), 3)
        titles = " ".join(f["title"].lower() for f in shell)
        self.assertIn("bash", titles)
        self.assertIn("node", titles)
        self.assertIn("curl", titles)

    def test_good_skill_no_shell_invocations(self):
        res = scan_directory(GOOD)
        self.assertEqual(by_check(res["findings"], "shell"), [])


class TestFilesystemCheck(unittest.TestCase):
    def test_evil_skill_flags_destructive_ops(self):
        res = scan_directory(EVIL)
        fs = by_check(res["findings"], "filesystem")
        titles = " ".join(f["title"].lower() for f in fs)
        self.assertGreaterEqual(len(fs), 2)
        self.assertIn("recursive delete", titles)  # rm -rf / rm -r
        self.assertIn("force", titles)

    def test_good_skill_clean(self):
        res = scan_directory(GOOD)
        self.assertEqual(by_check(res["findings"], "filesystem"), [])


class TestNetworkCheck(unittest.TestCase):
    def test_evil_skill_flags_egress(self):
        res = scan_directory(EVIL)
        net = by_check(res["findings"], "network")
        self.assertGreaterEqual(len(net), 3)  # curl, wget, https urls
        # the token-in-URL variant should be high severity
        sevs = [f["severity"] for f in net]
        self.assertIn("high", sevs)

    def test_good_skill_no_egress(self):
        res = scan_directory(GOOD)
        self.assertEqual(by_check(res["findings"], "network"), [])


class TestSecretsCheck(unittest.TestCase):
    def test_evil_skill_flags_credentials(self):
        res = scan_directory(EVIL)
        sec = by_check(res["findings"], "secrets")
        self.assertGreaterEqual(len(sec), 3)  # AWS, Slack, ghp_, sk_live_
        titles = " ".join(f["title"].lower() for f in sec)
        self.assertIn("aws", titles)
        self.assertIn("slack", titles)
        self.assertIn("github", titles)
        self.assertIn("stripe", titles)
        self.assertEqual(worst(sec), "critical")

    def test_good_skill_no_secrets(self):
        res = scan_directory(GOOD)
        self.assertEqual(by_check(res["findings"], "secrets"), [])

    def test_placeholders_are_not_flagged(self):
        """sk-... / AKIAXXXX / ghp_xxx are documentation examples, not creds."""
        import tempfile
        from scanaskill.checks import secrets as secrets_check

        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "SKILL.md")
            with open(p, "w") as f:
                f.write("---\nname: doc-example\n---\n# Doc\n"
                        'Use "Authorization: Bearer sk-..." in requests.\n'
                        "Never hardcode AKIAXXXX in code.\n"
                        "Example token: ghp_xxx\n")
            findings = []
            secrets_check.run(p, findings)
            self.assertEqual(findings, [])


class TestLicenseCheck(unittest.TestCase):
    def test_good_skill_has_license(self):
        res = scan_directory(GOOD)
        lic = by_check(res["findings"], "license")
        # a present license should NOT produce a missing-license finding
        self.assertEqual(lic, [])

    def test_evil_skill_missing_license(self):
        res = scan_directory(EVIL)
        lic = by_check(res["findings"], "license")
        self.assertTrue(any("license" in f["title"].lower() for f in lic))


class TestSupplyChainCheck(unittest.TestCase):
    def test_evil_skill_flags_unpinned_and_pipe_install(self):
        res = scan_directory(EVIL)
        sc = by_check(res["findings"], "supply_chain")
        titles = " ".join(f["title"].lower() for f in sc)
        self.assertIn("pipe", titles)          # curl | bash
        self.assertIn("unpinned", titles)      # pip install / npm install
        self.assertIn("npm", titles)


class TestPromptPatternsCheck(unittest.TestCase):
    def test_evil_skill_flags_manipulation_pattern(self):
        res = scan_directory(EVIL)
        pp = by_check(res["findings"], "prompt_patterns")
        self.assertTrue(any("instruction" in f["title"].lower() for f in pp))
        # never claim "injection" in output
        blob = json.dumps(res)
        self.assertNotIn("injection", blob.lower())


class TestReportShape(unittest.TestCase):
    def test_json_shape_and_exit_semantics(self):
        res = scan_directory(EVIL)
        self.assertIn("target", res)
        self.assertIn("skills", res)
        self.assertIn("findings", res)
        self.assertIn("summary", res)
        self.assertIsInstance(res["summary"]["critical"], int)
        self.assertGreater(res["summary"]["critical"], 0)

    def test_good_skill_summary_clean(self):
        res = scan_directory(GOOD)
        self.assertEqual(res["summary"]["critical"], 0)
        self.assertEqual(res["summary"]["high"], 0)

    def test_every_finding_has_location(self):
        res = scan_directory(EVIL)
        for f in res["findings"]:
            self.assertIn("evil_skill", f["path"]), f
            self.assertIsInstance(f["line"], int)
            self.assertGreaterEqual(f["line"], 1)
            self.assertIn(f["severity"], SEV_ORDER)


if __name__ == "__main__":
    unittest.main()
