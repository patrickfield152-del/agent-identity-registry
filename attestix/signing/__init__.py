"""Pluggable signing for skjold (v0.4.0 extensibility layer).

This package introduces the :class:`Signer` seam so the service layer can sign
through an abstraction instead of holding a raw Ed25519 private key. The default
install resolves to the in-process :class:`InProcessSigner`, which reproduces
v0.3.0 signatures byte-for-byte.

Selecting a non-default backend is opt-in via the ``SKJOLD_SIGNER`` environment
variable (or the ``config`` argument to :func:`select_signer`). Only the
in-process Ed25519 backend ships with this port.
"""

import os
from typing import Optional

from attestix.signing.signer import Signer
from attestix.signing.inprocess_signer import InProcessSigner

# Submodule re-exports for `from attestix.signing.X import Y` parity.
from attestix.signing import signer
from attestix.signing import inprocess_signer

__all__ = [
    "Signer",
    "InProcessSigner",
    "select_signer",
    "signer",
    "inprocess_signer",
]


def select_signer(config: Optional[dict] = None) -> Signer:
    """Return the configured Signer, defaulting to :class:`InProcessSigner`.

    Selection precedence:

    1. ``config["signer"]`` if a ``config`` mapping is supplied.
    2. The ``SKJOLD_SIGNER`` environment variable.
    3. Default: ``"inprocess"`` -> :class:`InProcessSigner` (v0.3.0 behavior).

    Recognized values:

    - ``"inprocess"`` / ``"in_process"`` (default) -> :class:`InProcessSigner`.

    The default signer is constructed fresh per call so it picks up the current
    ``config.SIGNING_KEY_FILE`` (honoring test monkeypatching); callers that want a
    cached instance should hold the returned signer themselves.
    """
    choice = None
    if config:
        choice = config.get("signer")
    if choice is None:
        choice = os.environ.get("SKJOLD_SIGNER")
    if choice is None:
        choice = "inprocess"
    choice = str(choice).strip().lower()

    if choice in ("inprocess", "in_process", "in-process", "ed25519"):
        return InProcessSigner()
    raise ValueError(
        f"Unknown SKJOLD_SIGNER value {choice!r}. "
        "Expected: inprocess."
    )
