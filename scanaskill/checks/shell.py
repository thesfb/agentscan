"""Check: shell / interpreter invocation (v2 — context-gated).

Deterministic observation of which interpreters and exec primitives a
skill invokes. v2 change: word-level invocation patterns only fire in
real shell/code contexts — inside code fences (untagged or shell-
tagged), in script files, and for python/js patterns inside python/js
contexts. Markdown prose and inline-code spans no longer produce
invocation findings; a backtick span in a sentence is formatting, not
command substitution. Fence opener/closer lines are markup, not
invocations.

Presence is a FACT; whether it is justified is the human's verdict.
"""

import os
import re

from ..common import read_lines
from ..context import LineContext, code_region, line_in_shell_context

NAME = "shell"
TITLE = "Shell / interpreter invocation"

# (regex, label, context)
# context: "shell" = shell fences/scripts; "python" = python code;
#          "js" = javascript/ts code; "code" = any code context
PATTERNS = [
    (r"\bcurl\b", "curl", "shell"),
    (r"\bwget\b", "wget", "shell"),
    (r"\bbash\b", "bash", "shell"),
    (r"\bsh\s+-c\b", "sh -c", "shell"),
    (r"\bzsh\b", "zsh", "shell"),
    (r"\bpython3?\s+-c\b", "python -c", "shell"),
    (r"\bnode\s+-e\b|\bnode\s+--eval\b", "node -e", "shell"),
    (r"\bos\.system\s*\(", "os.system", "python"),
    (r"\bsubprocess\s*\.\s*(run|call|Popen|check_output)\s*\(", "subprocess", "python"),
    (r"\bchild_process\s*\.\s*(exec|execSync|spawn|spawnSync)\s*\(", "child_process", "js"),
    (r"\bexec\s*\(|\beval\s*\(", "exec/eval", "code"),
    (r"`[^`]{3,}`", "shell backticks", "shell"),
]

_PREFILTER = re.compile(
    r"curl|wget|bash|zsh|python|node|\bos\.|subprocess|child_process|exec\(|eval\(|`",
    re.IGNORECASE,
)

_COMBINED = re.compile("|".join(rx for rx, _, _ in PATTERNS))

# fence language -> context sets
_SHELL = frozenset({"sh", "bash", "zsh", "shell", "fish", "ksh", "text", ""})
_PY = frozenset({"python", "py", "python3"})
_JS = frozenset({"js", "javascript", "jsx", "ts", "typescript", "tsx", "node", "mjs", "cjs"})
_CODE = _SHELL | _PY | _JS | frozenset({"rb", "ruby", "go", "rs", "rust", "php", "perl",
                                        "lua", "java", "cs", "ps1", "powershell", "bat"})


def _lang_of(ctx, i, path):
    """Effective language of line i: fence lang, else file language."""
    fl = ctx.fence_lang[i]
    if fl:
        return fl
    ext = os.path.splitext(str(path))[1].lower()
    if ctx.script:
        return "sh"
    if ext in (".py", ".pyw"):
        return "python"
    if ext in (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"):
        return "js"
    return ""


def _contexts_for(lang):
    """Which pattern contexts apply for a language."""
    if lang in _SHELL:
        return frozenset({"shell", "code"})
    if lang in _PY:
        return frozenset({"python", "code"})
    if lang in _JS:
        return frozenset({"js", "code"})
    if lang in _CODE:
        return frozenset({"code"})
    return frozenset()


def _label_for(group):
    for rx, lbl, _ctx in PATTERNS:
        if re.search(rx, group):
            return lbl
    return "command"


def run(path, findings):
    lines = read_lines(path)
    ctx = LineContext(lines, path)
    for lineno, line in enumerate(lines, 1):
        if ctx.is_fence_line[lineno - 1]:
            continue  # fence openers/closers are markup
        if not _PREFILTER.search(line):
            continue
        lang = _lang_of(ctx, lineno - 1, path)
        if not lang:
            continue  # prose outside fences: no invocation findings here
        contexts = _contexts_for(lang)
        if not contexts:
            continue
        for m in _COMBINED.finditer(line):
            label = _label_for(m.group(0))
            need = next(c for _rx, _l, c in PATTERNS if _l == label)
            if need not in contexts:
                continue
            findings.append({
                "severity": "medium",
                "check": NAME,
                "title": f"Invokes {label}",
                "path": str(path),
                "line": lineno,
                "detail": line.strip()[:160],
                "region_class": code_region(ctx, lineno - 1),
            })
