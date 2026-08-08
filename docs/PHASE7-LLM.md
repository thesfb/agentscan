# Phase 7 — Gated LLM Triage (architecture)

Status: DESIGNED, NOT BUILT. The scanner stays deterministic by
default. An LLM stage is optional, default-off, labeled, and
structurally unable to suppress deterministic findings.

## Why (evidence)

- Payload-less attacks (SCH, arXiv:2605.14460) achieve 0.00% detection
  by pattern scanners. An LLM that reads "compliance rules demanding
  ~/.ssh access" can at least route it to review.
- Locate-and-Judge (arXiv:2606.23416): a lightweight deterministic
  locator gating an LLM judge gives order-of-magnitude cost reduction
  and dominates regex baselines. The locate-then-judge shape is
  pre-validated.
- CHASE (arXiv:2601.06838): LLM + deterministic tools = 98.4% recall at
  0.08% FPR. Reliability comes from orchestration (deterministic tools
  for critical ops), not model power.
- Cisco Skill Scanner ships LLM-as-a-judge. The market accepts the shape.

## Why not LLM-everything

- Nondeterminism: same input, different verdicts — fatal for a scanner
  whose identity is "same input, same report" and whose audits are
  timestamped artifacts.
- Prompt injection against the scanner: skill text is attacker-
  controlled. An LLM reading a skill can be steered by the skill. The
  definitive mitigation: the LLM never produces the final verdict and
  never suppresses a deterministic finding.
- Cost/latency at corpus scale; privacy (skills may contain customer
  secrets); reproducibility for the verified-badge story.

## Design rules

1. The deterministic engine defines the review queue; the LLM cannot
   add findings outside it and cannot remove any.
2. LLM stage runs only on the review queue (findings with
   `review: true`), not the full artifact set, unless the user opts
   into full mode.
3. Every LLM-assisted finding carries: model name + version, prompt
   template version, input digest, output, and the deterministic
   evidence it references. `origin: "model-assisted"`.
4. Offline mode: no LLM stage when offline; the scanner degrades
   gracefully.
5. Cost control: cap queue size, batch, cache by input digest.
6. Prompt structure: the skill text is DATA, never instructions. Use
   delimiters, output-format enforcement, and a fixed task template.
   The assistant is told it is reviewing untrusted content.

## Where it helps (in priority order)

1. Triage of the review queue (SCH-shaped phrasing, drift findings,
   low-confidence typosquat candidates) — propose a classification
   and an explanation.
2. Explanation generation for already-evidenced findings (cosmetic).
3. Benchmark gold-labeling assistance with human verification.

## Where it must never go

- Final verdicts.
- Suppressing deterministic findings.
- Anything that must be reproducible for the verified-badge story.
- Full-corpus scanning by default.
