"""Dependency extraction (v2 layer 14 seed).

Pulls the dependency list an artifact introduces from package.json,
requirements.txt, pyproject.toml, Python imports, and install
instructions in SKILL.md. Feeds pin detection, typosquat heuristics,
OSV lookup, and the CycloneDX SBOM.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field


@dataclass
class Dependency:
    ecosystem: str          # PyPI | npm | system
    name: str
    version: str = ""       # constraint if pinned, else ""
    pinned: bool = False
    source: str = ""        # file
    line: int = 0
    detail: str = ""

    def purl(self):
        if self.ecosystem == "PyPI":
            return f"pkg:pypi/{self.name}@{self.version}" if self.version else f"pkg:pypi/{self.name}"
        if self.ecosystem == "npm":
            return f"pkg:npm/{self.name}@{self.version}" if self.version else f"pkg:npm/{self.name}"
        return f"pkg:generic/{self.name}"


_PIN_OP = re.compile(r"([=<>~!^]+)\s*([0-9][\w.\-]*)")
_NAME_RX = re.compile(r"^[A-Za-z0-9_.\-]+")

# v3 (FP4): words that are never package names — install-instruction
# conjunctions, shell builtins, and command names.
_NON_PACKAGE_WORDS = frozenset("""
and or the a an with without using via for to from of in on at by as
install add i ci upgrade update uninstall remove latest stable
git clone repo repository pip pip3 npm pnpm yarn brew apt apt-get
pacman dnf yum zypper cargo gem composer uv python node sudo
--user --upgrade --force --no-deps -r -e -U -y -g -q -v
""".split())


def _split_name_version(spec):
    """'requests==2.31.0' -> ('requests', '==2.31.0', True)."""
    spec = spec.strip()
    m = _PIN_OP.search(spec)
    if m:
        name = spec[:m.start()].strip().rstrip(" ")
        return name, m.group(0), True
    # npm @version suffix (opencode-ai@latest) and name[extra]
    at = spec.rfind("@")
    if at > 0 and "/" not in spec[:at]:
        return spec[:at].strip(), spec[at:], True
    # bare name or name[extra]
    name = spec.split("[")[0].strip()
    return name, "", False


def _requirements(path, lines, out):
    for i, line in enumerate(lines, 1):
        line = line.split("#")[0].strip()
        if not line or line.startswith("-") or line.startswith("."):
            continue
        if line.startswith(("git+", "http", "https")):
            out.append(Dependency("PyPI", line.split("#")[0][:60], "",
                                  False, path, i, "VCS/URL requirement"))
            continue
        name, ver, pinned = _split_name_version(line)
        if name and _NAME_RX.match(name):
            out.append(Dependency("PyPI", name, ver, pinned, path, i))


def _pyproject(path, lines, out):
    joined = "\n".join(lines)
    m = re.search(r"\[project\]", joined)
    if not m:
        return
    deps = re.search(r"\[project\]\s*(?:.*?\n)*?dependencies\s*=\s*\[(.*?)\]",
                     joined, re.S)
    if not deps:
        return
    for item in re.findall(r"['\"]([^'\"]+)['\"]", deps.group(1)):
        name, ver, pinned = _split_name_version(item)
        if name:
            out.append(Dependency("PyPI", name, ver, pinned, path, 1))


def _package_json(path, lines, out):
    try:
        data = json.loads("\n".join(lines))
    except ValueError:
        return
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        deps = data.get(key) or {}
        for name, ver in deps.items():
            pinned = bool(re.match(r"^[\^~]?[0-9]", ver or "")) or ":" in (ver or "")
            out.append(Dependency("npm", name, ver or "", pinned, path, 1))


_INSTALL_RX = [
    (re.compile(r"\b(?:pip|pip3)\s+install\s+(.+)$", re.IGNORECASE), "PyPI"),
    (re.compile(r"\bpython\s+-m\s+pip\s+install\s+(.+)$", re.IGNORECASE), "PyPI"),
    (re.compile(r"\bnpm\s+(?:i|install)\s+(.+)$", re.IGNORECASE), "npm"),
    (re.compile(r"\byarn\s+(?:add|install)\s+(.+)$", re.IGNORECASE), "npm"),
]
_ALIAS = {"i": "install", "add": "install"}


def _install_instructions(path, lines, out):
    """Install commands in SKILL.md / scripts become dependencies."""
    for i, line in enumerate(lines, 1):
        for rx, eco in _INSTALL_RX:
            m = rx.search(line)
            if not m:
                continue
            rest = m.group(1)
            # split off flags and the rest of the line
            rest = re.split(r"\s+(?:--\w+|-[a-zA-Z])\s", rest)[0]
            for tok in rest.split():
                tok = tok.strip("\"'`;,")
                if not tok or tok.startswith(("-", "@", "http")):
                    continue
                if eco == "npm" and tok.startswith("-"):
                    continue
                # v3 (FP4): skip conjunction words / command names
                name, ver, pinned = _split_name_version(tok)
                if not name or name in _NON_PACKAGE_WORDS:
                    continue
                if name and _NAME_RX.match(name):
                    out.append(Dependency(eco, name, ver, pinned, path, i))


_IMPORT_RX = re.compile(
    r"^\s*(?:import\s+([A-Za-z0-9_\.]+)|from\s+([A-Za-z0-9_\.]+)\s+import)",
)
_STDLIB = {
    "os", "sys", "re", "json", "math", "time", "random", "subprocess",
    "shutil", "pathlib", "argparse", "collections", "functools", "itertools",
    "datetime", "logging", "io", "csv", "hashlib", "base64", "socket",
    "urllib", "http", "ssl", "threading", "multiprocessing", "asyncio",
    "typing", "dataclasses", "tempfile", "glob", "gzip", "zipfile",
    "tarfile", "unittest", "string", "struct", "binascii", "email",
    "sqlite3", "configparser", "signal", "statistics", "contextlib",
    "weakref", "abc", "enum", "inspect", "traceback", "warnings", "getpass",
    "platform", "ctypes", "curses", "codecs", "copy", "decimal", "difflib",
    "dis", "fnmatch", "fractions", "gc", "heapq", "hmac", "html", "idlelib",
    "imaplib", "importlib", "linecache", "locale", "mailbox", "mimetypes",
    "netrc", "nntplib", "numbers", "operator", "pickle", "pkgutil",
    "poplib", "pprint", "profile", "pstats", "pty", "queue", "quopri",
    "readline", "reprlib", "rlcompleter", "runpy", "sched", "secrets",
    "select", "selectors", "shelve", "shlex", "site", "smtplib", "sndhdr",
    "spwd", "sqlite3", "sre_compile", "stat", "sunau", "symtable", "tabnanny",
    "telnetlib", "textwrap", "this", "token", "tokenize", "turtle", "types",
    "unicodedata", "uu", "uuid", "venv", "warnings", "wave", "webbrowser",
    "wsgiref", "xdrlib", "xml", "zipapp", "zlib",
}


def _imports(path, lines, out):
    """Top-level third-party imports in bundled Python."""
    for i, line in enumerate(lines, 1):
        m = _IMPORT_RX.match(line)
        if not m:
            continue
        mod = (m.group(1) or m.group(2)).split(".")[0]
        if mod in _STDLIB or mod.startswith("_") or mod == "scanaskill":
            continue
        out.append(Dependency("PyPI", mod, "", False, path, i, "import"))


def extract_dependencies(files):
    """files: {relpath: [lines]}. Returns Dependency list."""
    out = []
    for rel, lines in files.items():
        base = os.path.basename(rel)
        if base == "requirements.txt" or base.endswith(".txt") and "require" in base:
            _requirements(rel, lines, out)
        elif base == "pyproject.toml":
            _pyproject(rel, lines, out)
        elif base == "package.json":
            _package_json(rel, lines, out)
        elif base == "SKILL.md" or base.endswith(".md"):
            _install_instructions(rel, lines, out)
        elif base.endswith(".py"):
            _imports(rel, lines, out)
    return out


# ---------------------------------------------------------------------------
# typosquat heuristics
# ---------------------------------------------------------------------------

# curated list of high-value package names attackers typosquat
POPULAR = frozenset("""
requests flask django numpy pandas torch tensorflow scipy matplotlib
scikit-learn fastapi pydantic sqlalchemy pytest boto3 urllib3 rich click
httpx aiohttp beautifulsoup4 lxml pillow openai anthropic langchain
transformers torchvision streamlit celery redis pymongo psycopg2 gunicorn
uvicorn jinja2 cryptography bcrypt pyjwt selenium playwright pyyaml
python-dotenv pygithub slack-sdk twilio stripe sendgrid loguru tqdm
joblib xgboost lightgbm huggingface-hub accelerate einops tiktoken
feedparser praw tweepy discord.py telebot aiogram paho-mqtt grpcio
protobuf express react lodash axios next webpack typescript ts-node
commander chalk dotenv jest mocha eslint prettier vue react-dom
react-router redux styled-components web-vitals
""".split())


def levenshtein(a, b):
    """Iterative Levenshtein distance (small strings only)."""
    if abs(len(a) - len(b)) > 2:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def typosquat_score(name):
    """0 (not suspicious) .. 2 (strong candidate) for a package name."""
    if name in POPULAR:
        return 0
    n = name.lower().replace("_", "-")
    best = 3
    for popular in POPULAR:
        d = levenshtein(n, popular)
        if d < best:
            best = d
    if best == 1:
        return 2
    if best == 2 and len(n) >= 4:
        return 1
    return 0
