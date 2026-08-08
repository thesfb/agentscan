# Scanner v2 — Implementation Report (0.8.0 → 1.0.0)

Date: 2026-08-08
Scope: all phases of SCANNER-V2-RESEARCH-AND-PLAN.md implemented.
Verification: 105 tests green, benchmark contract green, real-corpus
measurements below.

## What changed

### 1. Noise reduction (measured on the user's 182-skill corpus)

| Metric | 0.8.0 | 1.0.0 | delta |
|---|---|---|---|
| Total findings | 7,810 | 2,955 | −62% |
| High/critical findings | 366 | 202 | −45% |
| "Invokes shell backticks" (markdown inline code) | 3,508 | 0 | killed |
| "Invokes bash" on ```bash fence lines | 864 | 0 | killed |
| License findings (per-skill now, not per-file) | 402 | 50 | −88% |
| High/critical on benign skills (benchmark) | 6/12 skills | 0/12 | fixed |

Root causes fixed, not band-aided:

- **Fence-aware, context-gated shell analysis** (new `context.py`):
  markdown inline-code spans, fence opener/closer lines, and prose
  mentions are no longer shell invocations. Python patterns fire only
  in python contexts; JS patterns only in JS contexts; untagged fences
  stay shell-capable (evil fixtures still trip).
- **Destination-trust tiering** (network): loopback/private/link-local
  hosts are informational; cloud metadata (169.254.169.254) stays high;
  public cleartext stays high. One finding per URL, at the highest
  applicable class, instead of several.
- **Skill-granularity license** (license): only SKILL.md (or a sibling
  LICENSE) is evaluated; references/, DESCRIPTION.md, knowledge/ no
  longer produce findings.
- **Provenance exemptions** (secrets): config-file reads
  (`cfg.get`, `json.load`, `credential.x`, dotenv) are exempt from
  "secret-like assignment"; token formats inside markdown docs with
  example markers or padded bodies are downgraded to low with a
  "(documentation context)" label.
- **Official-API trust** (exfil): api.telegram.org and similar with
  env-configured credentials are informational; command substitution
  (`$(cat ~/.env)`) and secret reads stay critical on ANY host.
- **Defensive-context detection** (filesystem): deny lists, block
  hooks, and quoted JSON config values are excluded; path scope is
  graded via the shell parser — `rm -rf $HOME` stays high, `rm -rf
  "$TMPDIR/x"` / `./build` drop one level.
- **Dedup + label fix** (scanner): identical (check,title,line)
  findings collapse; label lookup uses the matched group, not the line
  (fixed mislabeled git ops on rm lines).
- **Walker exclusions**: .next/, .turbo/, coverage/, caches, and
  lockfiles are dependency data, not author intent.

### 2. Structural analysis (new `analysis/` package)

- `structure.py`: artifact model — frontmatter, sections, code fences
  with language tags, script regions, per-line region lookup.
- `instructions.py`: deterministic instruction classifier —
  agent-instruction / user-install / documentation-mention, used to
  downgrade user-install unpinned installs in supply_chain.
- `python_ast.py`: stdlib AST walker (Bandit-class) — calls classified
  into env_read/file_read/network/exec/base64/write/delete, with
  imports and assignments. Zero dependencies.
- `shell_parser.py`: shell command parser (pipelines, quotes,
  substitutions, redirects) with per-argument scope classification
  (env/home/tmp/sensitive/absolute/relative).

### 3. Data-flow, capabilities, correlation (new `checks/analysis.py`)

- **Intra-file taint** (`taint.py`): secret-shaped data flowing from
  sources (env reads, sensitive file reads) through propagators to
  sinks (network calls, exec) becomes a critical/high finding with an
  attack path, each hop cited. Works on .py files AND python fences.
  Shell taint covers `cat ~/.env | curl` chains.
- **Capability extraction** (`capabilities.py`): per-file capability
  evidence (secret.access, network.upload, process.exec, ...) reported
  as info findings and aggregated into the report's `capabilities` map.
- **Cross-file one-hop**: SKILL.md references to bundled scripts are
  resolved; dangerous content in the referenced script becomes a chain
  finding citing both locations.
- **Correlation**: a curl|bash line that fired shell + supply_chain
  findings now also produces one "Remote code fetch-and-execute chain"
  finding. Components stay as evidence.
- **Finding model**: every finding carries confidence (separate from
  severity), evidence list, fingerprint, origin, capability, and
  region_class. The old flat fields remain — no consumer breaks.

### 4. Agent-instruction analysis

- **MCP tool-description poisoning** (config_tamper): descriptions
  pairing credential reads with send/upload verbs (CVE-2025-54136
  shape) are flagged high.
- **Explicit credential-transfer instructions** (prompt_patterns):
  "send ~/.ssh to ..." style instructions, guarded against defensive
  phrasings ("never send credentials").
- **SCH-shaped phrasings**: compliance-rule text demanding sensitive
  capabilities goes to the review queue (low confidence, labeled).
- **Drift detection**: skills declaring "offline/read-only" whose
  observed capabilities include network upload get a review-queue
  mismatch finding.
- **Review queue**: `res["review_queue"]` + human-report section —
  semantic signals that are review items, never verdicts.

### 5. Supply chain

- **Dependency extraction** (`dependencies.py`): package.json,
  requirements.txt, pyproject.toml, install instructions, and bundled
  imports → dependency list (stdlib excluded).
- **Typosquat heuristics**: edit-distance-to-popular-name detection.
- **CycloneDX SBOM**: `--sbom` emits a 1.5 SBOM.
- **OSV lookup**: `--osv` (opt-in, online) queries the OSV batch API
  and adds known-vulnerability findings; degrades with an explicit
  note when offline.

### 6. Benchmark (new `bench/`)

- 22-skill corpus: 10 malicious attack classes (webhook exfil,
  secret upload, obfuscated shell, supply-chain pipe, destructive
  home, hardcoded creds, prompt manipulation, MCP poisoning, DDIPE
  doc-embedded exfil, env-interp exfil) and 12 benign FP classes
  (inline code, fences, localhost API, docs installs, config reads,
  official API, deny lists, token-format docs, tmp cleanup, build
  cleanup, security tooling, pinned installs).
- Contract: malicious skills must produce high/critical findings
  (recall at high: 10/10), benign skills must not (0 high/critical),
  per-skill caps on countable findings.
- `python3 bench/run_bench.py --exit` — CI-gateable, prevents the
  scanner from being "improved" by going quiet.

### 7. Phases 6/7 (architecture only, per plan)

- `docs/PHASE6-SANDBOX.md`: bubblewrap/seccomp sandbox design with the
  telemetry schema defined so it slots into the finding model later.
- `docs/PHASE7-LLM.md`: gated LLM triage design — review-queue only,
  never suppresses deterministic findings, pinned model/version,
  offline-degrading.

## Files

New: scanaskill/context.py, scanaskill/sbom.py, scanaskill/analysis/
(structure, instructions, python_ast, shell_parser, taint,
capabilities, dependencies), scanaskill/checks/analysis.py,
scanaskill/checks/dependencies.py, bench/ (corpus, labels.json,
run_bench.py), docs/PHASE6-SANDBOX.md, docs/PHASE7-LLM.md,
tests/test_v2.py (36 tests).

Modified: 10 existing check modules, scanner.py, cli.py, common.py,
README.md, versions → 1.0.0.

## Verification summary

- 105 tests pass (69 existing + 36 new).
- Benchmark contract green (malicious recall at high 10/10, benign
  clean, exit 0).
- Exit codes: 0/1/2 correct. SARIF valid. SBOM valid CycloneDX.
  OSV live queries return real advisories.
- The "injection" word never appears in scanner-authored language
  (verbatim user-content quotes in evidence details are preserved —
  masking evidence would be dishonest).
- Real corpus: 7,810 → 2,955 findings (−62%), 366 → 202
  high/critical (−45%).

## Known tradeoffs (documented in the plan)

- SCH-class payload-less attacks are review-queue signals, not
  detections (0.00% detection is the honest boundary).
- JS deep analysis deferred (structural approximation only) — no
  stdlib parser exists.
- OSV and destination trust need network/curated data; both are
  opt-in or bundled.
- The scanner flags its own docs that quote attack patterns (the
  documented self-scan class) — reword content, never allowlist.
