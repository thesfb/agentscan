"""Instruction classifier (v2 layer 3).

Deterministic classification of command-bearing text into three
classes:

- agent: the agent is told to run/execute this (feeds severity)
- user-install: the user is told to install/run this in their own
  terminal (downgraded severity)
- doc: documentation mention, no instruction (no severity)

The classifier is feature-based, not an LLM: fence presence, section
heading, imperative verbs, install verbs, and doc markers. This is the
precision backbone for shell/network/supply-chain severity.
"""

from __future__ import annotations

import re

from .structure import section_is_install

# install verbs: someone is being told to install something
INSTALL_VERB = re.compile(
    r"\b(?:pip|pip3|python\s+-m\s+pip|npm|pnpm|yarn|brew|apt|apt-get|aptitude|"
    r"pacman|dnf|yum|zypper|cargo|go\s+(?:get|install)|gem|composer|uv)\s+"
    r"(?:install|add|i|ci|upgrade|update)\b",
    re.IGNORECASE,
)
GIT_CLONE = re.compile(r"\bgit\s+clone\b")
DOWNLOAD = re.compile(r"\b(?:curl|wget)\b[^\n]*(?:\s+-[oO]\s+|\|)")
BREW_TAP = re.compile(r"\bbrew\s+(?:tap|install)\b")

# agent-directed action verbs
AGENT_VERB = re.compile(
    r"\b(?:run|execute|use|call|invoke|start|launch|create|write|read|update|"
    r"download|upload|fetch|send|delete|remove|copy|move|build|compile|"
    r"deploy|configure|set up|install)\b",
    re.IGNORECASE,
)

# user-directed phrasing
USER_PHRASE = re.compile(
    r"(?i)\b(?:you can|you should|you must|user (?:should|can|must)|in your "
    r"terminal|in a terminal|manually|your machine|your system|on your)\b"
)

# agent-directed phrasing
AGENT_PHRASE = re.compile(
    r"(?i)\b(?:the agent|the assistant|your agent|have the agent|ask the agent|"
    r"tell the agent|the model|you are|you will|before you|then you|"
    r"first you|now you)\b"
)

# documentation markers
DOC_MARKER = re.compile(
    r"(?i)\b(?:the skill|this skill|for example|e\.g\.|i\.e\.|note that|"
    r"see also|refer to|is used|can be used|may be used|used to|"
    r"documentation|readme|described|shown below|below is|the following)\b"
)

# destructive/dangerous patterns that are never user-install class
DANGEROUS = re.compile(
    r"\|[^\n]*(?:ba)?sh\b|base64[^\n]*\|[^\n]*(?:ba)?sh|rm\s+-rf?\s+/|"
    r"rm\s+-rf?\s+\$HOME|chmod\s+777|>\s*/etc|mkfs|dd\s+if=|:\(\)\s*\{"
)


def classify_line(line, section="", in_fence=False):
    """Classify one command-bearing line.

    Returns (klass, confidence) where klass is agent | user-install |
    doc. Deterministic feature voting.
    """
    low = line.lower()
    score = {"agent": 0.0, "user-install": 0.0, "doc": 0.0}

    if DANGEROUS.search(line):
        score["agent"] += 2.0  # dangerous patterns are agent-class, always
    if INSTALL_VERB.search(line) or GIT_CLONE.search(line):
        score["user-install"] += 1.0
    if AGENT_VERB.search(line):
        score["agent"] += 0.6
    if USER_PHRASE.search(line):
        score["user-install"] += 0.8
        score["doc"] += 0.3
    if AGENT_PHRASE.search(line):
        score["agent"] += 1.0
    if DOC_MARKER.search(line):
        score["doc"] += 0.7
    if in_fence:
        score["agent"] += 0.5  # fenced code is executable content
    if section_is_install(section):
        score["user-install"] += 0.5

    best = max(score.items(), key=lambda kv: kv[1])[0]
    conf = min(0.99, score[best] / (score["agent"] + score["user-install"] + score["doc"] + 0.001))
    if score[best] == 0:
        return "doc", 0.2
    return best, round(conf, 2)


def classify_fence(lines, section=""):
    """Classify a whole fence/script block. One class for the block."""
    scores = {"agent": 0.0, "user-install": 0.0, "doc": 0.0}
    for line in lines:
        k, _c = classify_line(line, section, in_fence=True)
        scores[k] += 1
    best = max(scores.items(), key=lambda kv: kv[1])[0]
    total = sum(scores.values()) or 1
    return best, round(scores[best] / total, 2)


def is_user_install(line, section=""):
    """True when a line is a user-install instruction (downgrade me)."""
    k, _ = classify_line(line, section)
    return k == "user-install"
