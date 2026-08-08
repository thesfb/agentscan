"""Shell parser with command/scope tables (v2 layer 4).

A small deterministic parser for shell command lines: splits pipelines,
conditionals, and redirects (quote- and substitution-aware), tokenizes
arguments, and classifies argument scope. This is what lets the scanner
tell `rm -rf $HOME` from `rm -rf "$TMPDIR/test-output"` and track which
variables flow into which commands.

Not a full shell grammar — covers the constructs that appear in skills:
simple commands, pipes, &&/||, ;, $VAR, ${VAR}, $(...), backticks,
quotes, redirects, heredocs (treated as opaque).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

VAR_RE = re.compile(r"\$(\{?)([A-Za-z_][A-Za-z0-9_]*)\}?")

# split points: | && || ;  at top level (not inside quotes or $())
_SPLIT_RE = re.compile(r"(\|\||&&|[|;])")


@dataclass
class ShellCommand:
    verb: str
    args: list = field(default_factory=list)
    lineno: int = 0
    has_pipe: bool = False
    has_cmd_subst: bool = False
    has_redirect: bool = False
    redirect_target: str = ""
    vars: list = field(default_factory=list)      # $VAR names referenced
    raw: str = ""

    def arg_after(self, flag):
        """The argument following a flag like -o, -O, -d, -F, --data."""
        for i, a in enumerate(self.args):
            if a in (flag,):
                if i + 1 < len(self.args):
                    return self.args[i + 1]
                return ""
            if a.startswith(flag + "="):
                return a[len(flag) + 1:]
        return None


def _split_top_level(line):
    """Split a line on | && || ; outside quotes and substitutions."""
    parts = []
    cur = []
    depth = 0
    i = 0
    n = len(line)
    quote = None
    while i < n:
        ch = line[i]
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            cur.append(ch)
            i += 1
            continue
        if ch == "$" and i + 1 < n and line[i + 1] == "(":
            depth += 1
            cur.append(ch)
            i += 1
            continue
        if depth > 0:
            cur.append(ch)
            if ch == ")":
                depth -= 1
            i += 1
            continue
        if ch == "`":
            # backtick substitution: skip to closing backtick
            j = line.find("`", i + 1)
            if j == -1:
                j = n
            cur.append(line[i:j + 1])
            i = j + 1
            continue
        if ch in "|;&" and (ch != "&" or (i + 1 < n and line[i + 1] == "&") or
                            (i > 0 and line[i - 1] == "&")):
            parts.append("".join(cur).strip())
            cur = []
            if ch == "&" and i + 1 < n and line[i + 1] == "&":
                i += 2
            else:
                i += 1
            continue
        cur.append(ch)
        i += 1
    if cur:
        parts.append("".join(cur).strip())
    return [p for p in parts if p]


def _tokenize(seg):
    """Tokenize one command segment into argv-ish tokens."""
    tokens = []
    cur = []
    i = 0
    n = len(seg)
    quote = None
    while i < n:
        ch = seg[i]
        if quote:
            if ch == quote:
                quote = None
            else:
                cur.append(ch)
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            i += 1
            continue
        if ch == "$" and i + 1 < n and seg[i + 1] == "(":
            j = _match_paren(seg, i + 1)
            cur.append(seg[i:j + 1])
            i = j + 1
            continue
        if ch == "`":
            j = seg.find("`", i + 1)
            if j == -1:
                j = n
            cur.append(seg[i:j + 1])
            i = j + 1
            continue
        if ch.isspace():
            if cur:
                tokens.append("".join(cur))
                cur = []
            i += 1
            continue
        if ch == ">" or ch == "<":
            if cur:
                tokens.append("".join(cur))
                cur = []
            j = i + 1
            while j < n and seg[j] in "> <&|;()":
                j += 1
            tgt = ""
            while j < n and not seg[j].isspace() and seg[j] not in ">|<&;":
                tgt += seg[j]
                j += 1
            tokens.append(">" + tgt if ch == ">" else "<" + tgt)
            i = j
            continue
        cur.append(ch)
        i += 1
    if cur:
        tokens.append("".join(cur))
    return tokens


def _match_paren(s, open_idx):
    depth = 0
    for j in range(open_idx, len(s)):
        if s[j] == "(":
            depth += 1
        elif s[j] == ")":
            depth -= 1
            if depth == 0:
                return j
    return len(s) - 1


def _verb_of(tokens):
    for t in tokens:
        if t.startswith(">"):
            continue
        if t in ("sudo", "env", "nohup", "time", "command", "exec", "xargs"):
            continue
        return t
    return tokens[0] if tokens else ""


def parse_shell_line(line, lineno=0):
    """Parse one shell line into ShellCommand records."""
    cmds = []
    parts = _split_top_level(line)
    nparts = len(parts)
    for idx, seg in enumerate(parts):
        tokens = _tokenize(seg)
        if not tokens:
            continue
        verb = _verb_of(tokens)
        args = [t for t in tokens if not t.startswith(">") and not t.startswith("<")]
        redirect = ""
        for t in tokens:
            if t.startswith(">") and len(t) > 1:
                redirect = t[1:]
        vars_used = sorted(set(m.group(2) for m in VAR_RE.finditer(seg)))
        cmds.append(ShellCommand(
            verb=verb, args=args, lineno=lineno,
            has_pipe=idx < nparts - 1,
            has_cmd_subst="$(" in seg or "`" in seg,
            has_redirect=bool(redirect), redirect_target=redirect,
            vars=vars_used, raw=seg.strip(),
        ))
    return cmds


def parse_shell_lines(lines, start=1):
    """Parse many lines (a script or fence) into commands."""
    out = []
    for i, line in enumerate(lines):
        if line.strip().startswith("#"):
            continue
        out.extend(parse_shell_line(line, lineno=start + i))
    return out


def join_continuations(lines):
    """Join backslash-continued lines into logical lines.

    Returns (joined, line_of) where joined[i] is the joined logical line
    and line_of[i] is the 1-based original line number of its start.
    """
    joined = []
    line_of = []
    buf = []
    start = 1
    for i, line in enumerate(lines, 1):
        rstripped = line.rstrip()
        if rstripped.endswith("\\") and not rstripped.endswith("\\\\"):
            buf.append(rstripped[:-1])
            continue
        buf.append(line)
        joined.append(" ".join(part.strip() for part in buf))
        line_of.append(start)
        buf = []
        start = i + 1
    if buf:
        joined.append(" ".join(part.strip() for part in buf))
        line_of.append(start)
    return joined, line_of


def resolve_var_verbs(lines):
    """{VAR: value} for simple VAR=word assignments (verb indirection).

    Used to resolve `x=curl; $x ...` shapes: the verb is stored in a
    variable and invoked through it.
    """
    out = {}
    for line in lines:
        m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*$", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def apply_var_resolution(line, var_map):
    """Replace $VAR / ${VAR} tokens with their resolved values."""
    if not var_map or "$" not in line:
        return line
    for var, val in sorted(var_map.items(), key=lambda kv: -len(kv[0])):
        line = line.replace("${" + var + "}", val).replace("$" + var, val)
    return line


SENSITIVE_PATH = re.compile(r"(?:\.ssh|\.aws|\.env|\.git-credentials|\.netrc|"
                            r"\.npmrc|\.pypirc|/etc/(?:passwd|shadow)|"
                            r"\.config/.*/(?:token|credentials?|auth))", re.IGNORECASE)


def arg_scope(arg):
    """Classify a path/argument's trust scope.

    Returns (scope, detail): scope is env|sensitive|home|tmp|absolute|
    relative|var|other; detail carries the interesting part.
    """
    if not arg:
        return "other", ""
    if arg.startswith("$"):
        rest = arg[1:]
        if rest.startswith("{"):
            rest = rest[1:]
        name = re.split(r"[/}.]", rest, 1)[0]  # var name up to path sep
        if name in ("HOME", "USER", "LOGNAME", "SHELL"):
            return "home", name
        if name in ("TMPDIR", "TMP", "TEMP"):
            return "tmp", name
        return "var", name
    if arg.startswith("~"):
        return "home", arg
    if SENSITIVE_PATH.search(arg):
        return "sensitive", arg
    if "/tmp/" in arg or arg.startswith("/var/tmp/"):
        return "tmp", arg
    if arg.startswith("/"):
        return "absolute", arg
    if arg.startswith(("./", "../")):
        return "relative", arg
    if arg in (".", ".."):
        return "relative", arg
    return "other", arg
