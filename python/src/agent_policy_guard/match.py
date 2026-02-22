"""Glob-style pattern matching utilities."""

from __future__ import annotations

import fnmatch


def glob_match(pattern: str, value: str) -> bool:
    """Match a value against a glob pattern.

    Supports:
    - ``*`` matches everything
    - ``prefix*`` matches strings starting with prefix
    - ``*suffix`` matches strings ending with suffix
    - ``pre*suf`` matches strings starting with pre and ending with suf
    - Exact match when no wildcards are present

    Uses :func:`fnmatch.fnmatchcase` for full glob semantics (``*``,
    ``?``, ``[seq]``, ``[!seq]``).
    """
    if not pattern:
        return False
    if pattern == "*":
        return True
    return fnmatch.fnmatchcase(value, pattern)


def list_matches(patterns: list[str] | None, value: str) -> bool:
    """Return True if *patterns* is None (don't care) or any pattern matches *value*."""
    if patterns is None:
        return True
    return any(glob_match(p, value) for p in patterns)
