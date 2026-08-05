"""Tiny terminal UI: colored status lines, no dependencies.

Colors are emitted only when stdout/stderr is a TTY and NO_COLOR is unset,
so piped output stays clean. The vocabulary is small on purpose:
ok / warn / err / step / banner / prompt.
"""

from __future__ import annotations

import os
import sys

_USE_COLOR = (
    sys.stdout.isatty() and sys.stderr.isatty() and "NO_COLOR" not in os.environ
)


def _paint(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


def green(text: str) -> str:
    return _paint("32", text)


def red(text: str) -> str:
    return _paint("31", text)


def yellow(text: str) -> str:
    return _paint("33", text)


def dim(text: str) -> str:
    return _paint("2", text)


def bold(text: str) -> str:
    return _paint("1", text)


def banner(text: str) -> None:
    print(bold(text))


def ok(text: str) -> None:
    print(f"  {green('✓')} {text}")


def err(text: str) -> None:
    print(f"  {red('✗')} {text}", file=sys.stderr)


def warn(text: str) -> None:
    print(f"  {yellow('!')} {text}")


def step(text: str) -> None:
    print(f"  → {text}")


def prompt(text: str) -> str:
    return input(f"  {text} ").strip()
