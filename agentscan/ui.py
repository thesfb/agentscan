"""Tiny terminal UI: colored status lines, no dependencies.

Colors only when stdout/stderr is a TTY and NO_COLOR is unset, so piped
output stays clean. The vocabulary is small on purpose:

    step   → a phase is starting        (suppressed by --quiet)
    ok     → a phase succeeded          (suppressed by --quiet)
    done   → final success result       (always printed)
    info   → muted detail line          (always printed)
    hint   → helpful next step          (always printed)
    warn   → ⚠ warning                  (always printed)
    err    → ✗ error, on stderr         (always printed)
    prompt → input with a status prefix

--quiet keeps automation clean: progress lines (step/ok) and the download
bar vanish; results, errors and warnings always print.
"""

from __future__ import annotations

import os
import sys

_USE_COLOR = (
    sys.stdout.isatty() and sys.stderr.isatty() and "NO_COLOR" not in os.environ
)

# --quiet: suppress progress lines; results and errors always show.
QUIET = False

BAR_WIDTH = 20
_bar_active = False


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


def rule(char: str = "─", width: int = 34) -> None:
    """Box-drawing separator, e.g. ────────."""
    print(char * width)


def step(text: str) -> None:
    """Progress: a phase is starting. Suppressed by --quiet."""
    if not QUIET:
        print(f"  → {text}")


def ok(text: str) -> None:
    """Progress confirmation. Suppressed by --quiet."""
    if not QUIET:
        print(f"  {green('✓')} {text}")


def done(text: str) -> None:
    """Final success result. Always printed."""
    print(f"  {green('✓')} {text}")


def info(text: str) -> None:
    """Muted detail line. Always printed."""
    print(f"  {dim(text)}")


def hint(text: str) -> None:
    """Helpful next step. Always printed."""
    print(f"  {dim('next:')} {text}")


def warn(text: str) -> None:
    print(f"  {yellow('⚠')} {text}")


def err(text: str) -> None:
    print(f"  {red('✗')} {text}", file=sys.stderr)


def prompt(text: str) -> str:
    return input(f"  {text} ").strip()


def progress(done_bytes: int, total_bytes: int) -> None:
    """Draw an in-place download bar. No-op when quiet or not a TTY."""
    global _bar_active
    if QUIET or not sys.stdout.isatty() or not total_bytes:
        return
    if not _bar_active:
        sys.stdout.write("\n")
        _bar_active = True
    frac = min(1.0, done_bytes / total_bytes)
    filled = int(frac * BAR_WIDTH)
    bar = "█" * filled + "·" * (BAR_WIDTH - filled)
    sys.stdout.write(f"\r  {bar} {frac * 100:5.1f}%")
    sys.stdout.flush()


def progress_end() -> None:
    """Clear the download bar line."""
    global _bar_active
    if _bar_active:
        sys.stdout.write("\r" + " " * (BAR_WIDTH + 12) + "\r")
        sys.stdout.flush()
        _bar_active = False
