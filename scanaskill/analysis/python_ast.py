"""Python AST analysis for bundled scripts (v2 layer 4).

Walks a Python file with the stdlib ast module and extracts the
evidence records later layers need: imports, assignments (name ->
expression class), and calls (classified into env reads, file reads,
network, exec, base64, writes, deletes). Deterministic, no execution,
no third-party deps.

This is the Bandit-class depth tier: statement-level analysis within
one file. Cross-file flows are resolved one hop by the taint layer.
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field


@dataclass
class PyCall:
    lineno: int
    kind: str            # env_read|file_read|network|exec|base64|write|delete|decode|other
    func: str            # resolved dotted name, e.g. os.getenv
    args: list = field(default_factory=list)   # stringified arg expressions


@dataclass
class PyAssign:
    name: str
    lineno: int
    rhs_kind: str        # literal|call|name|attribute|subscript|binop|unknown
    rhs: str             # truncated source text


@dataclass
class PyModule:
    path: str
    imports: list = field(default_factory=list)
    assigns: list = field(default_factory=list)
    calls: list = field(default_factory=list)
    funcs: list = field(default_factory=list)
    raw: str = ""
    net_objs: set = field(default_factory=set)   # v3: names bound to network connection objects

    def calls_of_kind(self, kind):
        return [c for c in self.calls if c.kind == kind]


# function name -> kind (prefix matches on dotted names)
_CALL_KINDS = [
    # env reads
    ("os.getenv", "env_read"), ("os.environ.get", "env_read"),
    ("os.environ", "env_read"), ("getenv", "env_read"),
    ("environ", "env_read"),
    ("dotenv.load_dotenv", "env_read"), ("os.environ.__getitem__", "env_read"),
    # file reads
    ("open", "file_read"), ("Path.read_text", "file_read"),
    ("Path.read_bytes", "file_read"), ("json.load", "file_read"),
    ("yaml.safe_load", "file_read"), ("yaml.load", "file_read"),
    ("tomllib.load", "file_read"), ("configparser", "file_read"),
    ("subprocess.check_output", "exec"), ("subprocess.getoutput", "exec"),
    # network
    ("requests.get", "network"), ("requests.post", "network"),
    ("requests.put", "network"), ("requests.patch", "network"),
    ("requests.delete", "network"), ("requests.request", "network"),
    ("urllib.request.urlopen", "network"), ("urllib.request.urlretrieve", "network"),
    ("urllib.request.Request", "network"),
    ("httpx.get", "network"), ("httpx.post", "network"), ("httpx.put", "network"),
    ("httpx.patch", "network"), ("httpx.delete", "network"), ("httpx.request", "network"),
    ("urllib3.request", "network"), ("aiohttp.ClientSession", "network"),
    ("http.client", "network"), ("socket.socket", "network"),
    ("socket.create_connection", "network"), ("websockets.connect", "network"),
    ("ftplib", "network"), ("smtplib", "network"),    # exec
    ("eval", "exec"), ("exec", "exec"), ("compile", "exec"),
    ("os.system", "exec"), ("os.popen", "exec"),
    ("subprocess.run", "exec"), ("subprocess.call", "exec"),
    ("subprocess.Popen", "exec"), ("subprocess.check_call", "exec"),
    ("pty.spawn", "exec"), ("os.exec", "exec"),
    # base64 / encoding
    ("base64.b64encode", "base64"), ("base64.b64decode", "base64"),
    ("base64.encodebytes", "base64"), ("base64.decodebytes", "base64"),
    ("b64encode", "base64"), ("b64decode", "base64"),
    ("binascii.hexlify", "base64"), ("binascii.unhexlify", "base64"),
    ("codecs.encode", "base64"), ("codecs.decode", "base64"),
    # writes / deletes
    ("open.write", "write"), ("Path.write_text", "write"),
    ("Path.write_bytes", "write"), ("shutil.copy", "write"),
    ("shutil.copy2", "write"), ("shutil.move", "write"),
    ("os.rename", "write"),
    ("os.remove", "delete"), ("os.unlink", "delete"),
    ("shutil.rmtree", "delete"), ("os.rmdir", "delete"),
    ("Path.unlink", "delete"),
    # persistence-ish
    ("cron", "other"), ("os.chmod", "other"), ("os.chown", "other"),
    ("os.setuid", "other"), ("os.setgid", "other"), ("os.seteuid", "other"),
]


def _call_kind(func):
    for name, kind in _CALL_KINDS:
        if func == name or func.startswith(name + "."):
            return kind
    return "other"


def _func_name(node):
    """Resolve a Call's function to a dotted name string."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _func_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):  # (lambda...)(...) or decorator pattern
        return _func_name(node.func)
    return ""


def _expr_str(node, maxlen=60):
    try:
        s = ast.unparse(node)
    except Exception:
        s = type(node).__name__
    return s[:maxlen]


def _rhs_kind(node):
    if isinstance(node, ast.Constant):
        return "literal"
    if isinstance(node, ast.Call):
        return "call"
    if isinstance(node, ast.Name):
        return "name"
    if isinstance(node, ast.Attribute):
        return "attribute"
    if isinstance(node, ast.Subscript):
        return "subscript"
    if isinstance(node, (ast.BinOp, ast.JoinedStr, ast.FormattedValue)):
        return "binop"
    if isinstance(node, (ast.List, ast.Dict, ast.Tuple, ast.Set)):
        return "container"
    return "unknown"


# v3: network connection object classes whose instance methods are sinks
# (conn.request(...), session.post(...), client.get(...))
_NET_CONN_CLASSES = frozenset({
    "http.client.HTTPConnection", "http.client.HTTPSConnection",
    "requests.Session", "httpx.Client", "httpx.AsyncClient",
    "urllib3.PoolManager", "urllib3.HTTPConnectionPool",
    "aiohttp.ClientSession", "websockets.connect",
})


def _walk_calls(tree, module):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = _func_name(node.func)
            kind = _call_kind(func)
            # v3: instance methods on known connection objects are sinks
            if kind == "other" and isinstance(node.func, ast.Attribute) \
                    and isinstance(node.func.value, ast.Name) \
                    and node.func.value.id in module.net_objs \
                    and node.func.attr in ("request", "get", "post", "put",
                                           "patch", "delete", "send", "urlopen",
                                           "getresponse", "connect"):
                kind = "network"
            args = [_expr_str(a) for a in node.args]
            for kw in node.keywords:
                args.append(f"{kw.arg}={_expr_str(kw.value)}" if kw.arg else _expr_str(kw.value))
            module.calls.append(PyCall(node.lineno, kind, func, args[:8]))


def _walk_assigns(tree, module):
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value if hasattr(node, "value") and node.value is not None else None
            # v3: record names bound to network connection objects
            if value is not None and len(targets) == 1 and isinstance(targets[0], ast.Name) \
                    and isinstance(value, ast.Call):
                f = _func_name(value.func)
                if f in _NET_CONN_CLASSES:
                    module.net_objs.add(targets[0].id)
            for t in targets:
                name = t.id if isinstance(t, ast.Name) else _expr_str(t)
                module.assigns.append(PyAssign(
                    name, node.lineno,
                    _rhs_kind(value) if value else "unknown",
                    _expr_str(value) if value else "",
                ))
        elif isinstance(node, ast.FunctionDef):
            module.funcs.append(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                module.imports.append(alias.name.split(".")[0])


def _build_module(raw, path=""):
    try:
        tree = ast.parse(raw)
    except SyntaxError:
        return None
    module = PyModule(path=path, raw=raw)
    # v3: assignments first so net_objs (connection objects) are known
    # when calls are classified.
    _walk_assigns(tree, module)
    _walk_calls(tree, module)
    return module


def parse_python_source(raw, path=""):
    """Parse Python source text into a PyModule. Returns None on error."""
    return _build_module(raw, path)


def parse_python(path):
    """Parse a Python file into a PyModule. Returns None on parse error."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError:
        return None
    return _build_module(raw, str(path))


def is_python(path):
    return os.path.splitext(str(path))[1].lower() in (".py", ".pyw")
