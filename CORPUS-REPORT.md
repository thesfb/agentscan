# Corpus Report — The Public Agent-Skill Ecosystem, Measured (v2)

**Date:** August 5, 2026
**Scanner:** [scanaskill](README.md) v0.2 (deterministic checks only, 10 modules)
**Method:** random sample of 4,000 unique skills (content-hash deduped) from a
174-repo corpus (8,850 raw SKILL.md files, 8,414 unique after dedupe),
drawn from the skills.sh registry + GitHub collections. Seed 42.

## Headline numbers (4,000 sampled skills)

| Check | Skills affected | What it means |
|---|---|---|
| **License unclear/missing** | **93.6%** | Over 9 in 10 skills declare no recognizable license. Redistribution rights are unclear for almost the entire ecosystem. |
| **Shell / interpreter invocation** | **75.3%** | 3 in 4 skills reference shell or an interpreter. Expected — but it means most skills *can* execute code, unsandboxed. |
| **Supply-chain patterns** | **23.1%** | curl\|bash pipes, unpinned pip/npm installs, git clone, binary downloads — nearly 1 in 4 skills. |
| **Credential-format strings** | **14.7%** | Strings matching AWS keys, GitHub/Slack tokens, JWTs, etc. Placeholders excluded by design, so these skew real. |
| **Destructive filesystem ops** | **7.6%** | rm -r/-f, git reset --hard / clean / push --force, truncating overwrites. |
| **Exfiltration sinks** | **4.2%** | Credentialed webhooks (Discord/Slack/Telegram), env interpolation in URLs, secret-read → network. |
| **Prompt-manipulation phrasing** | **3.3%** | Ignore-previous / conceal-from-user / override tags. Manual review flagged, never "detected". |
| **Obfuscation chains** | **0.4%** | base64/hex decode → shell/interpreter, nested eval. |
| **Any high/critical finding** | **18.0%** | At least one high/critical observation (cleartext http, credential-in-URL, destructive ops, exfil indicators). |

**~1 in 5 skills** carries at least one high/critical-severity observation.
**~1 in 4** pulls or installs something. **~1 in 7** contains credential-format
strings. **Over 9 in 10** can't legally be redistributed.

## Why this matters

- **Snyk's ToxicSkills audit (Feb 2026)** found 36.8% of 3,984 public skills
  flawed, 13.4% critical, 76 confirmed malicious. Our independent
  deterministic scan of a different, larger corpus finds the same order of
  magnitude of review-worthy signal (18% high/critical). The problem is
  ecosystem-wide, not a registry artifact.
- **Skills are dependencies.** They execute in your agent's environment with
  your permissions on your secrets. npm got scanners after incidents; agent
  skills are having incidents now (Clinejection, Feb 2026) with almost no
  tooling.
- **93.6% missing licenses** is the compounding problem: the entire
  "curated pack" economy repackages this corpus, and most of it has no
  clear redistribution rights. This is the quiet legal exposure under the
  whole AI-skill market.

## Methodology & honesty

- **Not** "X% of skills are malicious." Deterministic checks can't claim
  that, and we don't. A shell invocation in a shell-scripting skill is
  correct. Findings are facts with file:line; the verdict is the human's.
- **Random sample, deduped.** 8,850 raw SKILL.md files across 174 repos,
  content-hash deduped to 8,414 unique, then a seeded random sample of
  4,000. Percentages are estimates of the full 8,414-population with
  sampling error bounded by n=4,000.
- Placeholder strings (`sk-...`, `YOUR_API_KEY`) and license/documentation
  URLs excluded by design (tested) — credential numbers skew toward real
  review items.
- Per-file finding cap (200) prevents pathological files (e.g. a 15k-URL
  prompt JSON) from dominating.

## Reproduce

```bash
# corpus already downloaded; sample + scan
python3 /tmp/corpus_scan4.py 4000 42
```

Raw aggregates: `corpus-report-v2.json` in this repo.

---

*scanaskill is an independent project. Not affiliated with Anthropic, Snyk,
or any vendor. The scanner is free, local, deterministic, and executes
nothing.*
