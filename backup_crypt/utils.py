"""Utility helpers: logging setup, ANSI colors, and filesystem helpers."""

import logging
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# ANSI color helpers (no external dependency)
# ---------------------------------------------------------------------------

_RESET = "\033[0m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_RED = "\033[31m"
_CYAN = "\033[36m"
_BOLD = "\033[1m"

_ANSI_ENABLED = sys.stdout.isatty()


def _wrap(text: str, code: str) -> str:
    if _ANSI_ENABLED:
        return f"{code}{text}{_RESET}"
    return text


def ok(text: str) -> str:
    """Return text formatted as a success message."""
    return _wrap(text, _GREEN)


def warn(text: str) -> str:
    """Return text formatted as a warning message."""
    return _wrap(text, _YELLOW)


def err(text: str) -> str:
    """Return text formatted as an error message."""
    return _wrap(text, _RED)


def info(text: str) -> str:
    """Return text formatted as an info/highlight message."""
    return _wrap(text, _CYAN)


def bold(text: str) -> str:
    """Return text formatted as bold."""
    return _wrap(text, _BOLD)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging(verbose: bool = False) -> None:
    """Configure the root logger for CLI output.

    Args:
        verbose: If True, set level to DEBUG; otherwise INFO.
    """
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(message)s"
    logging.basicConfig(level=level, format=fmt, stream=sys.stderr)


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------

def collect_files(source: Path) -> list[Path]:
    """Recursively collect all regular files under source.

    Args:
        source: Root directory to scan.

    Returns:
        Sorted list of absolute file paths.
    """
    if source.is_file():
        return [source]
    return sorted(p for p in source.rglob("*") if p.is_file())


def human_size(num_bytes: int) -> str:
    """Format a byte count as a human-readable string.

    Args:
        num_bytes: Number of bytes.

    Returns:
        String like "4.2 MB" or "512 B".
    """
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num_bytes < 1024 or unit == "TB":
            return f"{num_bytes:.1f} {unit}"
        num_bytes //= 1024
    return f"{num_bytes} B"
