"""Check: destructive filesystem operations (v2 — context aware).

Deterministic observation of operations that can modify git state,
delete directories, or overwrite files. v2 changes:

- Label lookup uses the matched group, not the whole line (fixes the
  mislabeling of git ops on lines that also contain rm).
- Defensive context is excluded: destructive commands inside deny
  lists, block hooks, and security documentation are evidence of good
  behavior, not risk. A command quoted inside a JSON/config value is
  configuration, not execution.
- Light path-scope downgrade: deletion targets confined to temporary
  or build directories (TMPDIR, /tmp, ./build, ./dist, caches) drop
  one severity level; targets that cross trust boundaries (/, $HOME,
  ~, /etc, /usr, dotfile roots) keep full severity.
"""

import os
import re

from ..common import read_lines
from ..context import LineContext, code_region

NAME = "filesystem"
TITLE = "Destructive filesystem / git operations"

PATTERNS = [
    (r"\brm\s+-[a-z]*r", "rm -r (recursive delete)", "high"),
    (r"\brm\s+-[a-z]*f", "rm -f (forced delete)", "medium"),
    (r"\bshutil\.rmtree\s*\(", "shutil.rmtree (recursive delete)", "high"),
    (r"\bfs\.rm\s*\(|\bfs\.rmSync\s*\(", "fs.rm / fs.rmSync", "high"),
    (r"\bos\.remove\s*\(|\bos\.unlink\s*\(", "os.remove / os.unlink", "medium"),
    (r"\bgit\s+reset\s+--hard\b", "git reset --hard (discards work)", "high"),
    (r"\bgit\s+clean\s+-[a-z]*f", "git clean -f (deletes untracked)", "high"),
    (r"\bgit\s+push\b[^\n]*(https?://)", "git push to remote URL", "medium"),
    (r"\bgit\s+checkout\s+--\s+\.\b", "git checkout -- . (reverts all)", "medium"),
    (r"(?:^|\s)>\s*/[^\s]*\.(?:log|json|db|sqlite|txt)(?:\s|$)",
     "truncating overwrite of file in root path", "medium"),
    (r"\bchmod\s+(?:-\w+\s+)*777\b|\bchown\b", "permission escalation (chmod 777 / chown)", "medium"),
    # v3: destructive device/disk operations (FN8)
    (r"\bdd\b[^\n]*\bof=(?:/dev/|\$[A-Z_])", "destructive device write (dd)", "high"),
    (r"\b(?:mkfs(?:\.\w+)?|fdisk|shred|parted|wipefs)\b", "destructive disk operation", "high"),
]

# v3: git push to an untrusted remote (FN7)
_GIT_PUSH_URL = re.compile(r"git\s+push\b[^\n]*(https?://[^\s]+)")
WELL_KNOWN_GIT_HOSTS = frozenset({
    "github.com", "gitlab.com", "bitbucket.org", "codeberg.org",
    "git.sr.ht", "gitea.com", "sourceforge.net", "gitlab.gnome.org",
})

_COMBINED = re.compile("|".join(rx for rx, _, _ in PATTERNS))

# defensive/security documentation context (v3: expanded vocabulary —
# scanner/flag/block documentation is the largest remaining FP source)
DEFENSIVE = re.compile(
    r"(?i)\"deny\"|\"command\"|grep\s+-q|grep\s+-qE|block(?:ed)?\s+pattern|"
    r"dangerous-pattern|never\s+(?:run|execute|use|allow)|forbidden|untrusted|"
    r"this\s+is\s+dangerous|example\s+only|"
    r"flagged|the scanner|scanner (?:detects|flags|reports)|denylist|blocklist|"
    r"prevent|guard|quarantin|do not run|don't run|not allowed|disallowed|"
    r"blocked by|to block|blocks?"
)
CONFIG_LANGS = frozenset({"json", "yaml", "yml", "toml", "ini", "config", "conf", "env"})
SHELL_LANGS = frozenset({"sh", "bash", "zsh", "fish", "ksh", "dash", "shell", "console", "text"})


def _label_for(group):
    for rx, lbl, sev in PATTERNS:
        if re.search(rx, group):
            return lbl, sev
    return "unknown", "medium"


def _inside_quoted(line, start):
    """True when position start of line sits inside a quoted string."""
    dq = line.count('"', 0, start)
    sq = line.count("'", 0, start)
    return (dq % 2 == 1) or (sq % 2 == 1)


def _target_of(line, start, end):
    """Best-effort target text after the matched command."""
    return line[end:].strip()


def _scope_shift(line, m):
    """Return a severity adjustment for the matched destructive op.

    Uses the shell parser: when every destructive target on the line is
    confined to scratch space (tmp/build/cache/project-relative), drop
    one level. Any target that crosses a trust boundary (/, ~, $HOME,
    sensitive paths, system dirs) keeps full severity.
    """
    from ..analysis.shell_parser import arg_scope, parse_shell_line

    cmds = parse_shell_line(line)
    dangerous = False
    scratch_only = True
    for cmd in cmds:
        for arg in cmd.args:
            if arg == cmd.verb or arg.startswith("-"):
                continue  # the command itself and its flags are not targets
            scope, _detail = arg_scope(arg)
            if scope in ("home", "sensitive", "absolute"):
                dangerous = True
            elif scope in ("tmp", "relative"):
                pass
            else:
                scratch_only = False
    if dangerous or not scratch_only:
        return 0
    return -1


def run(path, findings):
    from .network import _host_of, host_tier

    lines = read_lines(path)
    ctx = LineContext(lines, path)
    for lineno, line in enumerate(lines, 1):
        for m in _COMBINED.finditer(line):
            label, sev = _label_for(m.group(0))
            region = code_region(ctx, lineno - 1)
            # defensive context: deny lists, block hooks, security docs
            quoted = _inside_quoted(line, m.start())
            lang = ctx.fence_lang[lineno - 1]
            config_ctx = ctx.script is False and (
                lang in CONFIG_LANGS
                or os.path.splitext(str(path))[1].lower() in CONFIG_LANGS
            )
            if DEFENSIVE.search(line) or (quoted and config_ctx):
                continue
            # v3: git push to an untrusted remote escalates (FN7)
            if "git push" in label:
                gm = _GIT_PUSH_URL.search(line)
                if gm:
                    host = _host_of(gm.group(1))
                    if host and host_tier(host) == "public" and host not in WELL_KNOWN_GIT_HOSTS:
                        sev = "high"
                        label = "git push to untrusted remote"
            # scratch-scope downgrade (one level)
            shift = _scope_shift(line, m)
            if shift:
                sev = _downgrade(sev)
            findings.append({
                "severity": sev,
                "check": NAME,
                "title": label,
                "path": str(path),
                "line": lineno,
                "detail": line.strip()[:160],
                "region_class": region,
            })


_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SEVS = ["info", "low", "medium", "high", "critical"]


def _downgrade(sev):
    idx = _SEV_ORDER.get(sev, 2)
    return _SEVS[max(0, idx - 1)]
