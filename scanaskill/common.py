"""Shared types and helpers for scanaskill checks."""

import re
import unicodedata

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}

# Text files scanned for patterns. Everything else (binaries, images,
# node_modules) is ignored. node_modules is skipped wholesale.
TEXT_EXTENSIONS = {
    ".md", ".markdown", ".txt", ".sh", ".bash", ".zsh", ".py", ".js", ".mjs",
    ".cjs", ".ts", ".tsx", ".jsx", ".json", ".yaml", ".yml", ".toml", ".ini",
    ".env", ".cfg", ".conf", ".rb", ".go", ".rs", ".java", ".php", ".pl",
    ".lua", ".ps1", ".bat", ".fish",
}
IGNORED_DIRS = {"node_modules", ".git", ".venv", "venv", "dist", "build", "__pycache__"}


def is_text_file(path):
    """path is a str or _PathLike — true for scannable text extensions."""
    name = path.name if hasattr(path, "name") else os.path.basename(path)
    # security-relevant dotfiles are scanned despite the leading dot
    if name in SECURITY_DOTFILES:
        return True
    if name.startswith("."):
        return False
    suffix = path.suffix if hasattr(path, "suffix") else os.path.splitext(name)[1]
    return suffix.lower() in TEXT_EXTENSIONS


# dotfiles that carry credentials or agent-execution config — always scan
SECURITY_DOTFILES = {
    ".mcp.json", "mcp.json", ".env", ".npmrc", ".pypirc", ".netrc",
    ".git-credentials", ".dockerconfigjson", "Dockerfile", "Makefile",
    ".pre-commit-config.yaml",
}


class _PathLike:
    """Minimal str adapter so is_text_file works on plain paths."""

    def __init__(self, s):
        import posixpath
        self.name = posixpath.basename(s)
        self.suffix = posixpath.splitext(s)[1]


def read_lines(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read().splitlines()


def shannon_entropy(s):
    """Shannon entropy in bits/char for a string (gitleaks-style heuristic).

    Strips common separators first so "sk_live_abc123" and
    "AKIAIOSFODNN7EXAMPLE" score on the token body itself.
    """
    if not s:
        return 0.0
    s = re.sub(r"[\s_\-=:/.]", "", s)
    if len(s) < 8:
        return 0.0
    from collections import Counter
    import math

    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())
