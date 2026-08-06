# agentscan

**The trust layer for AI agent skills.**

A deterministic, local security scanner for AI agent skills — plus the
Trusted Distribution: a curated, continuously audited package registry.

```bash
pip install agentscan-cli

agentscan scan ~/.claude/skills     # free, local, deterministic
agentscan activate                  # Trusted Distribution license
agentscan search                    # what's available
agentscan install security-engineer # one command, verified
agentscan update                    # like brew upgrade
```

---

## The scanner (free, open source, MIT)

Scan any skill, MCP server, or agent config for what it actually *does* —
shell, exfiltration, secrets, supply-chain, obfuscation — before you run it
in your agent.

- **Facts, not verdicts.** Every finding is a checkable fact with
  `file:line`. The scanner never calls anything "malicious" — that verdict
  is yours.
- **Deterministic, not ML.** Regex, entropy, structure. Same input, same
  report, every time.
- **Zero dependency, zero execution.** Pure Python stdlib. Never runs a
  skill, never calls out, works offline.

```bash
$ agentscan scan ~/Downloads/suspicious-skill

agentscan 0.4.0 — /home/you/Downloads/suspicious-skill
scanned 1 artifact(s), 14 finding(s)

  ARTIFACT  [claude-skill] auto-updater
  CRITICAL [exfil] Local secret read piped to network
           SKILL.md:41
  CRITICAL [secrets] AWS Access Key
           SKILL.md:24
  ...
  summary: critical=3 high=2 medium=5 low=2 info=2
  note: findings are observed patterns, not verdicts. Review each before acting.
```

Exit codes: `0` clean · `1` findings at/above threshold · `2` usage error.

### What it checks

| Check | Observes |
|---|---|
| `shell` | bash/sh/python -c/node -e/exec/eval/subprocess invocations |
| `filesystem` | rm -r/-f, shutil.rmtree, git reset --hard/clean/push --force, chmod 777 |
| `network` | curl/wget/fetch/requests, URLs, credential-in-URL, IP literals, cleartext http |
| `secrets` | 20+ token formats (AWS, GitHub, Slack, Stripe, OpenAI, Anthropic, JWT, PEM…) |
| `license` | declared license — recognized vs. unrecognized vs. missing |
| `supply_chain` | curl\|bash pipes, git clone, unpinned pip/npm, script downloads |
| `prompt_patterns` | high-risk prompt-manipulation phrasing — flagged, never "detected" |
| `exfil` | credentialed webhooks, env-in-URL, secret-read → network |
| `obfuscation` | decode-to-execute chains, nested eval/exec, hex escapes |
| `config_tamper` | remote MCP servers, hook commands, npm lifecycle scripts |

**Artifacts detected:** `claude-skill`, `mcp-server`, `cursor-rules`,
`context-file`, `github-actions`, `npm-package`, `generic`.

### Usage

```bash
python3 -m agentscan <dir>                  # human report
python3 -m agentscan <dir> --json           # machine-readable
python3 -m agentscan <dir> --sarif          # SARIF 2.1.0 (GitHub code scanning)
python3 -m agentscan <dir> --severity high  # only high+ fails exit code
```

---

## The Trusted Distribution (paid)

Access to curated, security-reviewed packages. Buy once (`$49`), receive a
license key, activate, install. No dashboard, no browser login, no accounts —
it's a developer tool.

```
Buy ($49, Polar checkout)
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
~/.claude/skills/<package>/  installed package
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
agentscan activate                 # prompt for license → verify → store
agentscan logout                   # remove local license
agentscan whoami                   # show active license
agentscan search                   # catalog from GET /api/packages
agentscan install <package>        # verified install into Claude Code
agentscan update                   # upgrade installed packages
agentscan verify                   # signature · latest · audit · intact
```

### Local state

Everything lives in `~/.agentscan/`:

```
~/.agentscan/
  license          the activated license (JSON)
  installed.json   {package-id: version}
  config.json      api_url override (optional)
  cache/           downloaded tarballs
```

### Package format

A package is **not** just a skill. It may contain agents, skills, slash
commands, templates, workflows, and knowledge:

```
security-engineer/
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
{ "packages": [ { "id": "security-engineer", "title": "Security Engineer",
  "version": "1.0.1", "description": "…", "sha256": "…",
  "release": "v1.0.1", "asset": "security-engineer-1.0.1.tar.gz" } ] }
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
python3 -m unittest discover -s tests -v   # 49 tests
```

Pure stdlib, Python 3.8+, works offline. To point the CLI at a local server:

```bash
export AGENTSCAN_API_URL=http://localhost:3100   # overrides the default API
```

## License

[MIT](LICENSE) © baldbee

*Independent project. Not affiliated with Anthropic, Snyk, or any vendor.
Patterns modeled on gitleaks/trufflehog (secrets), OWASP Agentic Top 10,
MCPGuard threat taxonomy, and Snyk's ToxicSkills findings.*
