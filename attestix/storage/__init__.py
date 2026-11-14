"""Pluggable persistence for skjold (the NEAR port of skjold).

This package keeps the :class:`Repository` seam introduced in v0.4.0. The
default install resolves to the file-backed :class:`FileRepository`, which
reproduces the origin on-disk behavior exactly. When ``SKJOLD_REGISTRY_ID`` is
configured the default becomes :class:`NearRepository`: the hybrid adapter that
maps the five chain collections onto the registry contract while keeping
off-chain documents and signed bodies in the local file store.

Selecting a non-default backend explicitly is still opt-in via the
``SKJOLD_STORAGE`` environment variable (or the ``config`` argument to
:func:`select_repository`). Imports stay cheap and cycle-safe: the NEAR adapter
is imported only when the registry environment is present, and
:class:`NearRepository` itself imports ``attestix.config`` inside methods.
"""

import os
from typing import Any, Optional

from attestix.storage.repository import DEFAULT_TENANT, Repository
from attestix.storage.file_repository import FileRepository
from attestix.storage.memory_repository import MemoryRepository

# Submodule re-exports for `from attestix.storage.X import Y` parity.
from attestix.storage import repository
from attestix.storage import file_repository
from attestix.storage import memory_repository

__all__ = [
    "Repository",
    "FileRepository",
    "MemoryRepository",
    "NearRepository",
    "DEFAULT_TENANT",
    "select_repository",
    "default_repository",
    "repository",
    "file_repository",
    "memory_repository",
    "near_repository",
]

# Process-wide default instance. Built lazily on the first call so importing the
# package never reads the environment or touches disk; the default is
# near-backed only when SKJOLD_REGISTRY_ID is set at that point.
_DEFAULT: Optional[Repository] = None


def default_repository() -> Repository:
    """Return the shared default Repository.

    Selection: :class:`NearRepository` when ``SKJOLD_REGISTRY_ID`` is set,
    otherwise the origin :class:`FileRepository`. The NEAR adapter is imported
    lazily so a default install (and the origin file/signer contract suite)
    never loads the contract client machinery.
    """
    global _DEFAULT
    if _DEFAULT is None:
        registry_id = os.environ.get("SKJOLD_REGISTRY_ID", "").strip()
        if registry_id:
            from attestix.storage.near_repository import NearRepository

            _DEFAULT = NearRepository.from_env()
        else:
            _DEFAULT = FileRepository()
    return _DEFAULT


def select_repository(config: Optional[dict] = None) -> Repository:
    """Return the configured Repository.

    Selection precedence:

    1. ``config["storage"]`` if a ``config`` mapping is supplied.
    2. The ``SKJOLD_STORAGE`` environment variable.
    3. Default: ``"file"`` when no registry is configured; ``"near"`` when
       ``SKJOLD_REGISTRY_ID`` is set (see :func:`default_repository`).

    Recognized values:

    - ``"file"`` -> :class:`FileRepository` (origin behavior).
    - ``"memory"`` -> :class:`MemoryRepository` (volatile; tests / smoke).
    - ``"near"`` -> :class:`NearRepository` (registry contract + local bodies).
    """
    choice = None
    if config:
        choice = config.get("storage")
    if choice is None:
        choice = os.environ.get("SKJOLD_STORAGE")
    if choice is None:
        return default_repository()
    choice = str(choice).strip().lower()

    if choice == "file":
        return FileRepository()
    if choice == "memory":
        return MemoryRepository()
    if choice == "near":
        from attestix.storage.near_repository import NearRepository

        return NearRepository.from_env()

    raise ValueError(
        f"Unknown SKJOLD_STORAGE value {choice!r}. "
        "Expected one of: file, memory, near."
    )


def __getattr__(name: str) -> Any:
    """Lazily expose NEAR adapter symbols without closing an import cycle."""
    if name == "NearRepository":
        from attestix.storage.near_repository import NearRepository

        return NearRepository
    if name == "near_repository":
        from attestix.storage import near_repository

        return near_repository
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
