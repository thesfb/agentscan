"""Markdown and code-context awareness for precision-gated checks.

The scanner's worst false-positive classes come from treating markdown
as a flat line stream: inline-code spans look like shell command
substitution, fence openers look like bash invocations, prose mentions
look like calls. This module classifies each line of a file:

- fence language (None outside fences)
- fence opener/closer lines
- inline-code span positions (only outside fences)
- whether a file is a script (shell/python/etc.) vs markdown

Checks gate their word-level findings on context: real shell analysis
happens inside fences, scripts, and heredocs; prose lines only feed
URL and structural analysis.
"""

import os

# languages whose content is executed or interpreted as shell
SHELL_LANGS = {"sh", "bash", "zsh", "shell", "fish", "ksh"}
# fence languages whose content is code we analyze (any code)
CODE_LANGS = SHELL_LANGS | {
    "python", "py", "js", "javascript", "ts", "typescript", "node",
    "rb", "ruby", "go", "rs", "rust", "php", "perl", "lua", "java",
    "c", "cpp", "h", "hpp", "cs", "powershell", "ps1", "bat", "fish",
    "json", "yaml", "yml", "toml", "ini", "dockerfile", "makefile",
    "console", "terminal", "text", "markdown", "md", "sql",
}

MARKDOWN_EXT = {".md", ".markdown", ".mdown", ".mkd"}
SHELL_EXT = {".sh", ".bash", ".zsh", ".fish", ".ksh"}


def _is_markdown(path):
    return os.path.splitext(str(path))[1].lower() in MARKDOWN_EXT


def _is_shell_script(path):
    name = os.path.basename(str(path))
    ext = os.path.splitext(name)[1].lower()
    if ext in SHELL_EXT:
        return True
    # shebang check
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            first = fh.readline()
        return first.startswith("#!") and any(
            s in first for s in ("/bin/sh", "/bin/bash", "/bin/zsh", "/usr/bin/env bash",
                                 "/usr/bin/env sh", "/usr/bin/env zsh", "fish", "ksh"))
    except OSError:
        return False


class LineContext:
    """Per-line context for one file."""

    __slots__ = ("fence_lang", "is_fence_line", "inline_spans", "script")

    def __init__(self, lines, path=""):
        self.script = _is_shell_script(path) if path else False
        n = len(lines)
        self.fence_lang = [None] * n  # type: ignore[list-item]
        self.is_fence_line = [False] * n
        self.inline_spans = [()] * n
        self._classify(lines)

    def _classify(self, lines):
        """Walk lines, tracking fence state and inline-code spans."""
        in_fence = False
        fence_lang = None
        for i, line in enumerate(lines):
            stripped = line.strip()
            # fence open/close: ``` or ~~~ runs of 3+
            if not in_fence:
                m = _FENCE_OPEN.match(stripped)
                if m:
                    in_fence = True
                    fence_lang = m.group(2).strip().lower() or "text"
                    self.fence_lang[i] = fence_lang
                    self.is_fence_line[i] = True
                    continue
            else:
                if _FENCE_CLOSE.match(stripped):
                    self.fence_lang[i] = fence_lang
                    self.is_fence_line[i] = True
                    in_fence = False
                    fence_lang = None
                    continue
                self.fence_lang[i] = fence_lang
                continue
            # outside fences: find inline code spans (1-2 backtick runs)
            self.inline_spans[i] = _inline_spans(line)

    def in_fence(self, i, lang=None):
        """True when line i is inside a code fence (optionally of lang)."""
        fl = self.fence_lang[i]
        if fl is None or self.is_fence_line[i]:
            return False
        if lang is None:
            return True
        return fl in lang if isinstance(lang, (set, frozenset)) else fl == lang

    def in_shell_fence(self, i):
        return self.fence_lang[i] in SHELL_LANGS

    def in_code_fence(self, i):
        fl = self.fence_lang[i]
        return fl is not None and fl in CODE_LANGS

    def is_inside_inline_code(self, i, pos):
        """True when character pos of line i is inside an inline-code span."""
        for start, end in self.inline_spans[i]:
            if start <= pos < end:
                return True
        return False


import re as _re

_FENCE_OPEN = _re.compile(r"^(`{3,}|~{3,})\s*([A-Za-z0-9_+.-]*)\s*$")
_FENCE_CLOSE = _re.compile(r"^(`{3,}|~{3,})\s*$")


def _inline_spans(line):
    """Backtick-delimited inline code spans on a line (outside fences).

    Handles 1-2 backtick delimiters (3+ is a fence). Returns a tuple
    of (start, end) character offsets.
    """
    spans = []
    i = 0
    n = len(line)
    while i < n:
        if line[i] == "`":
            j = i
            while j < n and line[j] == "`":
                j += 1
            delim = j - i
            if delim <= 2:
                k = line.find("`" * delim, j)
                if k != -1:
                    spans.append((i, k + delim))
                    i = k + delim
                    continue
            i = j
        else:
            i += 1
    return tuple(spans)


def line_in_shell_context(ctx, i, path=""):
    """A line that is real shell: inside a shell fence, or a shell script."""
    if ctx.script:
        return True
    return ctx.in_shell_fence(i)


def code_region(ctx, i):
    """Region class for a line: 'script' | 'fence' | 'prose'."""
    if ctx.script:
        return "script"
    if ctx.fence_lang[i]:
        return "fence"
    return "prose"
