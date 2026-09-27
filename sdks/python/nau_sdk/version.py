"""The single source of truth for the SDK version.

Upstream ``agent-universe`` v2.5.6 restated its version as a literal in four
Python files -- ``aip/__init__.py:1,31``, ``aip/mcp_client.py:21`` and
``aip/aca.py:68`` -- and all four drifted to ``2.3.6`` while the package itself
still claimed ``2.5.6``.  Nothing in this SDK repeats that mistake: the version
is read from the repository ``VERSION`` file at import time, and the value is
*never* written down in this package.

Resolution order:

1. ``$NAU_SDK_VERSION`` -- an explicit override, useful when the SDK is vendored
   into a tree that has no ``VERSION`` file.
2. The nearest ``VERSION`` file found by walking up from this module's
   ``__file__``.  Inside this repository the first hit is the repository root,
   which is the same file the Rust crate and the CI scripts read.
3. ``FALLBACK_VERSION`` -- an obviously-not-a-release sentinel used only when the
   SDK has been copied somewhere without its ``VERSION`` file.  It is a loud
   marker rather than a plausible-looking stale number, which is precisely the
   failure mode being designed out.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

__all__ = ["VERSION", "VERSION_FILE", "FALLBACK_VERSION"]

#: Name of the file that carries the version.
VERSION_FILE_NAME = "VERSION"

#: Used only when no ``VERSION`` file can be found at all.
#:
#: Deliberately not a release-shaped string: a stale number is indistinguishable
#: from a correct one, whereas this value makes the packaging error obvious.
FALLBACK_VERSION = "0.0.0-unknown"

_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.\-]+)?$")

#: How many parent directories to search for a ``VERSION`` file.
_MAX_WALK_UP = 8


def _looks_like_a_version(text: str) -> bool:
    return bool(_VERSION_RE.match(text))


def _find_version_file(start: Path) -> Path | None:
    """Walk up from ``start`` looking for a readable ``VERSION`` file."""
    current = start
    for _ in range(_MAX_WALK_UP):
        candidate = current / VERSION_FILE_NAME
        try:
            if candidate.is_file():
                return candidate
        except OSError:  # pragma: no cover - unreadable directory
            pass
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


def _load() -> tuple[str, Path | None]:
    override = os.environ.get("NAU_SDK_VERSION", "").strip()
    if override:
        return override, None

    # ``__file__`` is ``<root>/sdks/python/nau_sdk/version.py`` in this checkout,
    # so walking up lands on ``<root>/VERSION``.  ``parents[1]`` (the package
    # root) is used as the starting point: the repository root is two levels
    # above it, and a vendored copy may be anywhere.
    start = Path(__file__).resolve().parent.parent
    found = _find_version_file(start)
    if found is None:
        return FALLBACK_VERSION, None
    text = found.read_text(encoding="utf-8").strip()
    if not _looks_like_a_version(text):
        # Fail loudly rather than advertising a corrupted version everywhere.
        raise ValueError(
            f"{found} does not contain a version number (found {text!r}); "
            f"set NAU_SDK_VERSION to override"
        )
    return text, found


VERSION, VERSION_FILE = _load()
