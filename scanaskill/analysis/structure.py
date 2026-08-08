"""Artifact model and structural analysis (v2 layer 1-2).

An artifact is a directory of agent-execution files: SKILL.md (or the
format's entry file), scripts, references, configs. This module parses
the artifact into a model with per-file regions so later layers can ask
"is this line an instruction, an example, a doc mention, or config?"

The region grammar follows the SKILL.md anatomy taxonomy
(arXiv:2607.01456): frontmatter, prose sections, code fences with
language tags, and script files.
"""

from __future__ import annotations

import os
import re

from ..common import read_lines

FRONTMATTER_RE = re.compile(r"^---\s*$")
FIELD_RE = re.compile(r"^([A-Za-z0-9_-]+)\s*:\s*(.*)$")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
FENCE_OPEN_RE = re.compile(r"^(`{3,}|~{3,})\s*([A-Za-z0-9_+.-]*)\s*$")
FENCE_CLOSE_RE = re.compile(r"^(`{3,}|~{3,})\s*$")

# section names that signal install/user-action instructions
_INSTALL_HEADINGS = re.compile(
    r"(?i)^(install|setup|installation|dependencies|getting started|quickstart|"
    r"prerequisit|requirements?|build(ing)?|deploy|uninstall|remove|cleanup|"
    r"configuration|config|usage|use|run(ning)?|how to|examples?)"
)

# region kinds
FRONTMATTER = "frontmatter"
PROSE = "prose"
FENCE = "fence"
SCRIPT = "script"
CONFIG = "config"


class Region:
    __slots__ = ("kind", "start", "end", "lang", "section", "file")

    def __init__(self, kind, start, end, lang=None, section="", file=""):
        self.kind = kind
        self.start = start      # 1-based inclusive
        self.end = end          # 1-based inclusive
        self.lang = lang
        self.section = section
        self.file = file

    def contains(self, lineno):
        return self.start <= lineno <= self.end

    def __repr__(self):
        return (f"Region({self.kind}, {self.start}-{self.end}, "
                f"lang={self.lang!r}, section={self.section!r})")


class Artifact:
    """Parsed view of one skill/artifact directory."""

    def __init__(self, root):
        self.root = os.path.abspath(root)
        self.name = os.path.basename(self.root)
        self.description = ""
        self.license = None
        self.allowed_tools = None
        self.metadata = {}
        self.entry = None                # path of the entry file (SKILL.md etc.)
        self.files = {}                  # relpath -> list[str] lines
        self.regions = {}                # relpath -> list[Region]
        self._load()

    def _load(self):
        """Discover files and parse the entry file."""
        entry_names = ("SKILL.md", "AGENTS.md", "CLAUDE.md")
        for fn in entry_names:
            p = os.path.join(self.root, fn)
            if os.path.isfile(p):
                self.entry = fn
                break
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in {
                "node_modules", ".git", ".venv", "venv", "dist", "build",
                "__pycache__", ".next", ".turbo", "out", "coverage", ".cache",
                ".pytest_cache", ".mypy_cache", "target", ".terraform",
                ".idea", ".vscode", ".ruff_cache", ".tox", ".nox", ".eggs"}]
            for fn in sorted(filenames):
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, self.root)
                try:
                    if os.path.getsize(full) > 4 * 1024 * 1024:
                        continue
                    lines = read_lines(full)
                except OSError:
                    continue
                self.files[rel] = lines
                if rel == self.entry:
                    self._parse_entry(rel, lines)
                self.regions[rel] = _regions_for(rel, lines)

    def _parse_entry(self, rel, lines):
        """Extract frontmatter fields (agentskills.io contract)."""
        if not lines or FRONTMATTER_RE.match(lines[0].strip()) is None:
            return
        for line in lines[1:40]:
            if FRONTMATTER_RE.match(line.strip()):
                break
            m = FIELD_RE.match(line)
            if not m:
                continue
            key, val = m.group(1).lower(), m.group(2).strip().strip('"\'')
            if key == "name":
                self.name = val
            elif key == "description":
                self.description = val
            elif key == "license":
                self.license = val
            elif key == "allowed-tools":
                self.allowed_tools = val
            elif key == "metadata":
                self.metadata[key] = val

    def region_of(self, rel, lineno):
        """The region containing a line in a file."""
        for r in self.regions.get(rel, []):
            if r.contains(lineno):
                return r
        return None

    def shell_lines(self, rel):
        """Yield (lineno, line) for lines in shell code regions of a file."""
        for r in self.regions.get(rel, []):
            if r.kind in (FENCE, SCRIPT) and (r.lang in ("sh", "bash", "zsh",
                                                         "shell", "fish", "text", "") or r.kind == SCRIPT):
                for ln in range(r.start, r.end + 1):
                    yield ln, self.files[rel][ln - 1]

    def code_fences(self, rel):
        """Yield regions that are code fences."""
        return [r for r in self.regions.get(rel, []) if r.kind == FENCE]


def _regions_for(rel, lines):
    """Classify every line of a file into regions."""
    regions = []
    n = len(lines)
    i = 0
    if n and FRONTMATTER_RE.match(lines[0].strip()):
        end = 1
        for j in range(1, min(n, 40)):
            if FRONTMATTER_RE.match(lines[j].strip()):
                end = j
                break
        regions.append(Region(FRONTMATTER, 1, end, file=rel))
        i = end + 1

    section = ""
    ext = os.path.splitext(rel)[1].lower()
    script_kind = SCRIPT if ext in (
        ".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts",
        ".rb", ".go", ".rs", ".php", ".pl", ".lua", ".ps1", ".bat",
        ".fish", ".c", ".cpp", ".java") else None

    while i < n:
        line = lines[i]
        stripped = line.strip()
        hm = HEADING_RE.match(stripped)
        if hm:
            section = hm.group(2).strip()
        m = FENCE_OPEN_RE.match(stripped)
        if m:
            lang = m.group(2).strip().lower() or "text"
            start = i + 1
            j = i + 1
            while j < n and FENCE_CLOSE_RE.match(lines[j].strip()) is None:
                j += 1
            end = j  # opener..closer inclusive
            regions.append(Region(FENCE, start, end, lang=lang,
                                  section=section, file=rel))
            i = j + 1
            continue
        if script_kind and ext in (".sh", ".bash", ".zsh", ".fish"):
            regions.append(Region(SCRIPT, i + 1, n, lang=ext[1:], file=rel))
            break
        # prose run
        start = i + 1
        while i < n and FENCE_OPEN_RE.match(lines[i].strip()) is None:
            i += 1
        regions.append(Region(PROSE, start, i, section=section, file=rel))
    return regions


def section_is_install(section):
    """True when a markdown section heading is install/setup-like."""
    return bool(_INSTALL_HEADINGS.match(section.strip())) if section else False
