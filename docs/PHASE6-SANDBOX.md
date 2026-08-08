# Phase 6 — Sandboxed Dynamic Analysis (architecture)

Status: DESIGNED, NOT BUILT. This document is the architecture the plan
mandates for Phase 6; the scanner core executes nothing and stays that
way. Build this only after the static pipeline's telemetry schema has
been exercised in production.

## Why

Static analysis misses three real classes:

1. Runtime-decoded payloads (base64 shells that static sees as strings).
2. Install-time behavior — what a package actually does at install.
   DySec (arXiv:2503.00324) measures this with eBPF probes: 95.99%
   accuracy, and it found packages PyPI's scanners called benign.
3. Post-install drift (rug-pull execution: benign at review, malicious
   after trust is set).

## What it cannot detect (be honest)

- Logic bombs and time-delayed payloads (a short sandbox run misses them).
- Attacks requiring a real agent context (SSH keys loaded, specific MCP
  tool calls).
- Payload-less semantic attacks (SCH, arXiv:2605.14460): there is
  nothing to observe; the agent synthesizes the behavior at runtime.

## Security model

Executing an untrusted artifact IS the attack. Snyk's agent-scan warns
users to sandbox it for exactly this reason. Requirements:

- Strong boundary: bubblewrap or rootless container with user-namespace
  isolation, seccomp filter, read-only root filesystem, no home-dir
  access (scratch dir only), network sink (no egress), tight
  CPU/memory/time limits.
- Linux-only v1. No Windows/macOS sandbox — platform honesty beats
  fake coverage.
- The sandbox is a SEPARATE opt-in binary, never part of the scanner
  core. `agentscan sandbox <dir>`.

## Telemetry schema (designed now, consumed later)

Behavioral evidence must fit the existing finding model so the sandbox
slots in without a schema change:

    {
      "severity": "high",
      "check": "sandbox",
      "title": "Observed network egress to 93.184.216.34:443",
      "path": "<artifact>",
      "line": 0,
      "detail": "syscall trace: connect(2) from /tmp/run/install.sh",
      "origin": "sandbox",          # NEVER "deterministic"
      "evidence": [{"kind": "syscall", "data": "..."}]
    }

Findings are labeled "observed in sandbox" — never "observed in your
environment". The sandbox run is ground truth for that run only.

## Syscall/network capture

- strace-style seccomp trace or eBPF probes: execve, connect, sendto,
  open (with paths), chmod, chown, unlink, mkdir, rename.
- Network: connections to endpoints (destination IP:port), bytes out.
- The existing checks run over the telemetry log (evidence, not
  verdicts) — same deterministic rules, new input.

## Cost/complexity

- Cheap tier (bubblewrap + seccomp + network namespace): weeks.
- Strong tier (Firecracker microVM): months, heavy ops surface.
- Conflicts with the zero-dependency identity: sandbox ships as a
  separate download.

## Recommendation

Design is done (this doc + telemetry schema). Build when: (a) the
verified-badge story needs behavioral evidence, or (b) the static
pipeline's benchmark shows a persistent runtime-decoded-payload gap
that rules cannot close.
