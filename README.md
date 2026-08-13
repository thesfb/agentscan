# agentscan

[![PyPI version](https://img.shields.io/pypi/v/agentscan-cli)](https://pypi.org/project/agentscan-cli/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PyPI downloads](https://img.shields.io/pypi/dm/agentscan-cli)](https://pypi.org/project/agentscan-cli/)

**The trust layer for AI agent skills.**

A deterministic, local security scanner for AI agent skills — plus the
Trusted Distribution: a curated, continuously audited package registry.

**Website:** [agentscan.baldbee.me](https://agentscan.baldbee.me) — docs,
scan examples, and the Trust Pack storefront.

```bash
pip install agentscan-cli

agentscan scan ~/.claude/skills     # free, local, deterministic
agentscan activate                  # Trusted Distribution license
agentscan search                    # what's available
agentscan install trust-pack # one command, verified
agentscan update                    # like brew upgrade
```

---

## The scanner (free, open source, MIT)

Scan any skill, MCP server, or agent config for what it actually *does* —
shell, exfiltration, secrets, supply-chain, obfuscation — before you run it
in your agent. v2 adds structural and semantic analysis: the scanner now
understands what a skill is (instructions vs docs vs code), tracks
secret-shaped data flows with attack paths, extracts capabilities, and
correlates evidence instead of reporting raw pattern matches.

- **Facts, not verdicts.** Every finding is a checkable fact with
  `file:line`. The scanner never calls anything "malicious" — that verdict
  is yours. Every finding carries a confidence score separate from its
  severity, and an evidence list.
- **Deterministic, not ML.** Regex, entropy, AST, taint, structure. Same
  input, same report, every time. No model, no hallucination.
- **Zero dependency, zero execution.** Pure Python stdlib. Never runs a
  skill, never calls out (OSV lookup is opt-in with `--osv`), works
  offline.

```bash
$ agentscan scan ~/Downloads/suspicious-skill

agentscan 1.1.0 — /home/you/Downloads/suspicious-skill
scanned 1 artifact(s), 8 finding(s)

  ARTIFACT  [claude-skill] auto-updater
  CRITICAL [exfil] Local secret read piped to network
           SKILL.md:41
  CRITICAL [analysis] Secret data flows to external endpoint
           SKILL.md:17
           attack path: reads sensitive file (open.read) -> urllib.request.urlopen receives tainted data (...)
  ...
  summary: critical=3 high=2 medium=5 low=2 info=2
  capabilities:
    secret.access      SKILL.md:24
    network.upload     SKILL.md:41
  review queue (manual review — never a verdict):
    HIGH [prompt_patterns] Instruction directs transfer of credential material — SKILL.md:30
```

Exit codes: `0` clean · `1` findings at/above threshold · `2` usage error.
##Motivation

### What it checks

| Check | Observes |
|---|---|
| `shell` | bash/sh/python -c/node -e/exec/eval/subprocess invocations — fence- and context-aware (markdown inline code is not shell) |
| `filesystem` | rm -r/-f, shutil.rmtree, git reset --hard/clean/push --force, chmod 777 — defensive contexts excluded, path scope graded (TMPDIR vs $HOME) |
| `network` | curl/wget/fetch/requests, URLs, credential-in-URL, IP literals, cleartext http — destination-trust tiered (loopback/private/metadata/public) |
| `secrets` | 20+ token formats (AWS, GitHub, Slack, Stripe, OpenAI, Anthropic, JWT, PEM…) — config/env reads exempt, documentation-context examples downgraded |
| `license` | declared license at skill granularity (one finding per skill) |
| `supply_chain` | curl\|bash pipes, git clone, unpinned pip/npm, script downloads — user-install docs downgraded |
| `prompt_patterns` | high-risk prompt-manipulation phrasing + explicit credential-transfer instructions + SCH-shaped compliance-rule phrasings (review queue) — flagged, never "detected" |
| `exfil` | credentialed webhooks, env-in-URL, secret-read → network — official-API destinations with env-configured credentials are informational |
| `obfuscation` | decode-to-execute chains, nested eval/exec, hex escapes |
| `config_tamper` | remote MCP servers, hook commands, npm lifecycle scripts, poisoned MCP tool descriptions (credential read + data transfer in one description) |
| `dependencies` | dependency extraction, pin status, typosquat candidates, SBOM seed |
| `analysis` | taint chains with attack paths (Python AST + shell parser), cross-file script references, capability extraction, evidence correlation |

**Artifacts detected:** `claude-skill`, `mcp-server`, `cursor-rules`,
`context-file`, `github-actions`, `npm-package`, `generic`.

### Usage

```bash
python3 -m agentscan <dir>                  # human report
python3 -m agentscan <dir> --json           # machine-readable
python3 -m agentscan <dir> --sarif          # SARIF 2.1.0 (GitHub code scanning)
python3 -m agentscan <dir> --sbom           # CycloneDX 1.5 SBOM of dependencies
python3 -m agentscan <dir> --osv            # OSV vulnerability lookup (online, opt-in)
python3 -m agentscan <dir> --severity high  # only high+ fails exit code
```

### v2 finding model

Every finding carries:

- `severity` (impact if true) and `confidence` (how likely it is true) —
  separate axes, reported separately
- `evidence`: file:line + snippet for every claim
- `attack_path`: per-hop citations for correlated/taint findings
- `capability`: the capability the evidence contributes to
- `fingerprint`: stable per (rule, location) — baseline support
- `origin`: `deterministic` (or `model-assisted` in a future optional tier)

The report also includes a `capabilities` map (what the artifact can do,
with evidence) and a `review_queue` (low-confidence semantic signals that
are review items, never verdicts).

### Benchmark

`python3 bench/run_bench.py --exit` runs a 22-skill corpus (10 malicious
attack classes, 12 benign FP classes) and fails on contract violations:
malicious skills must produce high/critical findings, benign skills must
not. Malicious recall at high: **10/10** on the shipped corpus. This is
the guardrail that prevents the scanner from being "improved" by going
quiet.

---

## The Trusted Distribution (paid)

Access to curated, security-reviewed packages. Buy once (`$59`), receive a
license key, activate, install. No dashboard, no browser login, no accounts —
it's a developer tool.

```
Buy ($59, Polar checkout)
  ↓
License key (shown on your Polar purchases page)
  ↓
pip install agentscan-cli
  ↓
agentscan activate            → Polar /v1/customer-portal/license-keys/validate (direct)
  ↓
agentscan search              → GET  /api/packages
  ↓
agentscan install <package>   → GET /api/download/<id> (license-gated) → sha256 → extract → install
  ↓
agentscan update              → like brew upgrade
```

### Architecture

```
PyPI (agentscan CLI, MIT)
   ↓
Polar (payment + license keys — source of truth, no users table)
   ↑ direct validation (public endpoint, no server in the middle)
   |
agentscan.baldbee.me (Next.js site + API route handlers)
   ├── /api/packages       public catalog
   └── /api/download/[id]  license-gated tarball proxy
   ↓
agentscan-registry (private GitHub repo)
   ├── packages/        source of truth
   ├── packages.json    generated catalog (sha256 per package)
   └── GitHub Releases  tarball distribution
   ↓
~/.agentscan/  license · installed.json · config.json · cache/
~/.claude/skills/<skill-id>/            Claude Code install
~/.config/opencode/skills/<skill-id>/   OpenCode install
~/.agents/skills/<skill-id>/            Codex install (+ AGENTS.md at repo root)
~/.hermes/skills/<skill-id>/            Hermes install ($HERMES_HOME honored)
~/.grok/skills/<skill-id>/              Grok Build install ($GROK_HOME honored)
```

The website and API are the same Next.js application. No separate backend,
no database, no object storage. Git is the source of truth; GitHub Releases
are the CDN. License validation is on-demand against Polar — nothing is
stored server-side, no webhooks, no subscriptions.

The Polar organization id is public metadata and is baked into the CLI as a
constant (`DEFAULT_POLAR_ORGANIZATION_ID` in `agentscan/config.py`). Users
never configure it — install, activate, done.

### Commands

```bash
agentscan scan .                    # scan a directory of agent skills (free)
agentscan activate                  # prompt for license → verify → store
agentscan logout                    # remove local license
agentscan whoami                    # show active license
agentscan search                    # browse the catalog (package cards)
agentscan install <package>         # verified install, runtime auto-detected
agentscan install <p> --runtime codex   # install into a specific runtime
agentscan update                    # upgrade installed packages
agentscan verify                    # signature · latest · audit · intact
```

Package names are matched flexibly — any of these work:

```bash
agentscan install trust-pack
agentscan install "Trust Pack"
agentscan install Trust Pack
agentscan install trust
agentscan install trustpac        # typos are suggested, not silent
```

### Integrations (ecosystem distribution)

The scanner ships as visible artifacts, not just a CLI. Each one is a
searchable distribution channel:

| Artifact | What it gives you | Where
|---|---|---|
| **GitHub Action** | Scan skills on push/PR, fail the build on risky skills | `uses: thesfb/agentscan-action@v1` (marketplace) — or copy `.github/workflows/scan-skills.yml` for SARIF code-scanning |
| **pre-commit hook** | Fail the commit when a scan finds issues at/above your threshold | `.pre-commit-hooks.yaml` (add the repo to your pre-commit config) |
| **MCP server** | Scan a skill directory from any MCP client (Claude, Cursor, agents) | `python3 -m agentscan.mcp` or `agentscan-mcp` |
| **PyPI package** | `pip install agentscan-cli` — scanner + distribution CLI | pypi.org/project/agentscan-cli |

**GitHub Action** — add one step to any workflow (published action,
[thesfb/agentscan-action](https://github.com/thesfb/agentscan-action)):

```yaml
- uses: thesfb/agentscan-action@v1
  with:
    path: .          # directory of skills to scan (default: repo root)
    severity: high   # fail when a finding is at/above this (default: high)
```

The action runs the scan in a container, fails the job when a finding
reaches the severity threshold, and is fully local. For SARIF upload to
GitHub code scanning, copy `.github/workflows/scan-skills.yml` into your
repo instead — it installs the CLI, scans every push/PR, and uploads the
report to the Security tab.

**pre-commit** — add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/thesfb/scanaskill
    rev: v1.2.2
    hooks:
      - id: agentscan
        args: ["--severity", "high"]
```

**MCP server** — run `agentscan-mcp` and register it in any MCP client:

```json
{"mcpServers": {"agentscan": {"command": "agentscan-mcp", "args": []}}}
```

The server exposes one tool, `scan`, that returns a portable JSON report
for any local skill directory. Stdlib only, deterministic, executes
nothing.

### Runtimes

Packages install into the agent runtimes found on your machine:

| Runtime      | Detected via            | Skills install to                  |
|--------------|-------------------------|------------------------------------|
| Claude Code  | `~/.claude` or `claude` | `~/.claude/skills/<skill-id>/`     |
| OpenCode     | `~/.config/opencode` or `opencode` | `~/.config/opencode/skills/<skill-id>/` |
| OpenAI Codex | `~/.codex`, `~/.agents`, or `codex` | `~/.agents/skills/<skill-id>/` + AGENTS.md |
| Hermes       | `$HERMES_HOME`, `~/.hermes`, or `hermes` | `$HERMES_HOME/skills/<skill-id>/` (default `~/.hermes/skills/`) |
| Grok Build   | `$GROK_HOME`, `~/.grok`, or `grok` | `$GROK_HOME/skills/<skill-id>/` (default `~/.grok/skills/`) |

`agentscan install` detects installed runtimes automatically. When several
are present it installs into all of them; when none are detected it prompts,
or you can pick explicitly:

```bash
agentscan install trust-pack --runtime claude
agentscan install trust-pack --runtime opencode
agentscan install trust-pack --runtime codex
agentscan install trust-pack --runtime hermes
agentscan install trust-pack --runtime grok
agentscan install trust-pack --runtime all
```

Hermes follows the agentskills.io open standard: skills are discovered
recursively under its skills root and load as slash commands (`/skill-name`).
`HERMES_HOME` is the official override and is honored when set (it also
covers named profiles).

Grok Build (xAI) reads the same agentskills.io SKILL.md standard and
discovers skills recursively under `skills/` dirs — including
`~/.grok/skills/`, `~/.agents/skills/`, and `~/.claude/skills/`. `GROK_HOME`
is the official home override and is honored when set. Skills load as slash
commands (`/skill-name`) and `grok inspect` lists everything discovered.

Codex installs also write the package's `AGENTS.md` (the agents.md
convention) to the repository root when you are inside a git work tree. The
file is marked with a `<!-- agentscan:<package> -->` comment; reinstalling
replaces that section, and the rest of your AGENTS.md is left untouched.

Add `--quiet` (or `-q`) to suppress progress lines for automation; results
and errors still print. Run `agentscan --help` for examples.

### Local state

Everything lives in `~/.agentscan/`:

```
~/.agentscan/
  license          the activated license (JSON)
  installed.json   {package-id: {version, runtimes: {runtime: {skills: [...]}}}}
  config.json      api_url override (optional)
  cache/           downloaded tarballs
```

### Package format

A package is **not** just a skill. It may contain agents, skills, slash
commands, templates, workflows, and knowledge:

```
trust-pack/
  manifest.json     id, title, version, description, license, requires
  agents/           optional agent definitions
  skills/           SKILL.md files
  commands/         optional slash commands
  templates/        optional templates
  knowledge/        reference material
  audit.json        latest deterministic scan result
  signature.sig     placeholder — real signing lands with the Polar milestone
  README.md
```

`manifest.json` ships one package definition per the catalog shape:

```json
{ "packages": [ { "id": "trust-pack", "title": "Trust Pack",
  "version": "1.0.0", "description": "…", "sha256": "…",
  "release": "v1.0.0", "asset": "trust-pack-1.0.0.tar.gz" } ] }
```

### Status of the paid layer

- **License verification is real.** `agentscan activate` validates the key
  against Polar's public customer-portal endpoint on demand. No mock, no
  database, no webhooks.
- **Downloads are real and license-gated.** The CLI sends the license key
  as `Authorization: Bearer <key>`; the site validates it against Polar
  before proxying the tarball from the private GitHub registry. Checksums
  are verified end to end (server-side and CLI-side).
- `signature.sig` is a placeholder; cryptographic signing is designed in
  (`agentscan verify` is structured to add it without CLI changes).

---

## The numbers (4,000 skills measured)

We scanned a random sample of 4,000 unique skills across 174 public repos:

| Signal | % of skills |
|---|---|
| No recognizable license | **93.6%** |
| Invokes shell / interpreter | **75.3%** |
| Supply-chain patterns (curl\|bash, unpinned installs) | **23.1%** |
| Credential-format strings | **14.7%** |
| Destructive filesystem ops | **7.6%** |
| Exfiltration sinks | **4.2%** |
| Prompt-manipulation phrasing | **3.3%** |
| Obfuscation chains | **0.4%** |
| **Any high/critical finding** | **18.0%** |

Full methodology: [`CORPUS-REPORT.md`](CORPUS-REPORT.md)

---

## Development

```bash
python3 -m unittest discover -s tests -v   # 105 tests
```

Pure stdlib, Python 3.8+, works offline. To point the CLI at a local server:

```bash
export AGENTSCAN_API_URL=http://localhost:3100   # overrides the default API
```
##quickstart
##usage 
##contributing

## License

[MIT](LICENSE) © baldbee

*Independent project. Not affiliated with Anthropic, Snyk, or any vendor.
Patterns modeled on gitleaks/trufflehog (secrets), OWASP Agentic Top 10,
MCPGuard threat taxonomy, and Snyk's ToxicSkills findings.*
