"""NEAR signing helpers for the skjold port.

The VC/UAIT signing key stays in :class:`~attestix.signing.inprocess_signer.InProcessSigner`
(the issuer account's only FullAccess key). This module owns the *transaction*
side of the port:

* NEAR key wire formats (``ed25519:<base58>``) and keypair generation;
* the canonical digest helpers the contract keys on —
  ``uait_digest = sha256(canonicalize_json(UAIT - MUTABLE_FIELDS))`` and the
  labelled ``skjold-vc-digest/v1`` credential profile; and
* :class:`NodeTxSigner`, which shells out to ``sdk/src/tx.mjs`` (near-api-js
  7.5.3) with one JSON request on stdin and returns the client-captured
  ``tx_hash``. Key material never appears on the process command line.

Everything imports lazily enough that importing this module without Node (or
without a configured key) is safe; failures surface at call time with a clear
``RuntimeError``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

#: Profile label for the project's canonical VC digest. This is NOT the stock
#: did:near ProofType cid (which hashes the whole credential).
VC_DIGEST_PROFILE = "skjold-vc-digest/v1"

#: 1 TGas in gas units.
TGAS = 10**12

#: Default gas budget for a registry call.
DEFAULT_GAS_TGAS = 100


class NearSignerError(RuntimeError):
    """Raised when a NEAR key or transaction cannot be produced."""


def _b58encode(raw: bytes) -> str:
    try:
        import base58
    except ImportError as exc:  # pragma: no cover - base58 is a runtime dep
        raise NearSignerError("base58 is required for NEAR key formats") from exc
    return base58.b58encode(raw).decode("ascii")


def public_key_to_near(public_key: Any) -> str:
    """Return ``ed25519:<base58(raw 32 bytes)>`` for a public key.

    Accepts a cryptography ``Ed25519PublicKey``, raw 32 bytes, or an already
    formatted prefixed string.
    """
    if isinstance(public_key, str):
        text = public_key.strip()
        if text.startswith("ed25519:"):
            return text
        if len(text) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in text):
            return "ed25519:" + _b58encode(bytes.fromhex(text))
        try:
            raw = digest_bytes(text)
        except NearSignerError as exc:
            raise NearSignerError(f"unrecognized NEAR public key {public_key!r}") from exc
        return "ed25519:" + _b58encode(raw)
    if hasattr(public_key, "public_bytes"):
        raw = public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    else:
        raw = bytes(public_key)
    if len(raw) != 32:
        raise NearSignerError(
            f"Ed25519 public keys are 32 bytes, got {len(raw)}"
        )
    return "ed25519:" + _b58encode(raw)


def secret_key_to_near(private_key: Ed25519PrivateKey) -> str:
    """Return ``ed25519:<base58(32-byte seed)>`` for an Ed25519 private key.

    near-api-js 7.x accepts the 32-byte seed form; the extension with the public
    key is derived on load, so a minimal seed is the safest wire encoding.
    """
    seed = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return "ed25519:" + _b58encode(seed)


def generate_near_keypair() -> Tuple[Ed25519PrivateKey, str, str]:
    """Generate a fresh Ed25519 keypair.

    Returns ``(private_key, public_key_wire, secret_key_wire)``. The secret key
    is returned exactly once to the caller; it is never persisted by this
    module.
    """
    private_key = Ed25519PrivateKey.generate()
    return (
        private_key,
        public_key_to_near(private_key.public_key()),
        secret_key_to_near(private_key),
    )


def canonical_bytes(payload: dict) -> bytes:
    """Canonical JSON bytes for the project signing profile."""
    from attestix.auth.crypto import canonicalize_json

    return canonicalize_json(payload)


def uait_digest(uait: dict, mutable_fields: Iterable[str]) -> bytes:
    """Return ``sha256(canonicalize_json(UAIT - MUTABLE_FIELDS))``."""
    excluded = set(mutable_fields)
    payload = {key: value for key, value in uait.items() if key not in excluded}
    return hashlib.sha256(canonical_bytes(payload)).digest()


def vc_digest(credential: dict) -> bytes:
    """Return the ``skjold-vc-digest/v1`` digest of a W3C credential.

    ``sha256(canonicalize_json(vc - proof - credentialStatus))``. The digest is
    labelled a project profile because it deliberately differs from the stock
    did:near ProofType cid, which hashes the whole credential.
    """
    if not isinstance(credential, dict):
        raise NearSignerError("credential must be a dict")
    payload = {
        key: value
        for key, value in credential.items()
        if key not in ("proof", "credentialStatus")
    }
    return hashlib.sha256(canonical_bytes(payload)).digest()


def capabilities_digest(capabilities: Iterable[str]) -> bytes:
    """Return the contract's capability-list digest (sha256 of sorted JSON)."""
    canonical = json.dumps(
        sorted(str(item) for item in capabilities),
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).digest()


def digest_to_base64(digest: Any) -> str:
    """Encode a 32-byte digest as standard Base64 (the JSON wire form)."""
    return base64.b64encode(digest_bytes(digest)).decode("ascii")


def digest_to_hex(digest: Any) -> str:
    """Encode a 32-byte digest as lowercase hex (display/legacy form)."""
    return digest_bytes(digest).hex()


def digest_bytes(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    elif isinstance(value, (list, tuple)):
        raw = bytes(int(part) & 0xFF for part in value)
    elif isinstance(value, str):
        text = value.strip()
        if len(text) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in text):
            raw = bytes.fromhex(text)
        else:
            try:
                raw = base64.b64decode(text, validate=True)
            except Exception as exc:
                raise NearSignerError(
                    f"digest is neither hex nor standard Base64: {value!r}"
                ) from exc
    else:
        raise NearSignerError("digest must be bytes, Base64/hex string or byte list")
    if len(raw) != 32:
        raise NearSignerError(f"digest must be 32 bytes, got {len(raw)}")
    return raw


def node_available(node_bin: str = "node") -> bool:
    """Return True when the Node binary is on PATH."""
    return shutil.which(node_bin) is not None


def default_tx_script() -> Path:
    """Return the checked-in ``sdk/src/tx.mjs`` transport path."""
    return Path(__file__).resolve().parents[2] / "sdk" / "src" / "tx.mjs"


def default_rpc_url(network: Optional[str] = None) -> str:
    """Resolve the RPC URL from ``NEAR_RPC_URL`` or the network default."""
    configured = os.getenv("NEAR_RPC_URL")
    if configured:
        return configured
    chosen = (network or os.getenv("NEAR_NETWORK") or "testnet").strip().lower()
    if chosen == "mainnet":
        return "https://rpc.mainnet.near.org"
    return "https://rpc.testnet.near.org"


class NodeTxSigner:
    """Signs and submits registry calls through ``sdk/src/tx.mjs``.

    The JSON request is written to the child's stdin::

        {"mode":"call","network":...,"rpcUrl":...,"contractId":...,
         "signerId":...,"secretKey":...,"method":...,"args":{},
         "depositYocto":"0","gasTgas":100}

    The transport prints ``{"tx_hash": "..."}``. A missing Node binary, a
    missing transport or a nonzero exit raises :class:`NearSignerError`; this
    class never fabricates a transaction hash.
    """

    def __init__(
        self,
        signer_id: str,
        secret_key: str,
        contract_id: str,
        *,
        rpc_url: Optional[str] = None,
        network: Optional[str] = None,
        node_bin: str = "node",
        script_path: Optional[str] = None,
        timeout: float = 180.0,
    ) -> None:
        if not signer_id:
            raise ValueError("NodeTxSigner requires signer_id")
        if not secret_key:
            raise ValueError("NodeTxSigner requires secret_key")
        if not contract_id:
            raise ValueError("NodeTxSigner requires contract_id")
        self.signer_id = signer_id
        self.contract_id = contract_id
        self._secret_key = secret_key
        self.network = (network or os.getenv("NEAR_NETWORK") or "testnet").strip().lower()
        self.rpc_url = rpc_url or default_rpc_url(self.network)
        self.node_bin = node_bin
        self.script_path = Path(script_path) if script_path else default_tx_script()
        self.timeout = timeout

    @classmethod
    def from_env(cls) -> "NodeTxSigner":
        """Build the signer from the canonical skjold environment names."""
        contract_id = os.getenv("SKJOLD_REGISTRY_ID", "").strip()
        secret_key = os.getenv("SKJOLD_OPERATOR_KEY", "").strip()
        if not contract_id:
            raise NearSignerError("SKJOLD_REGISTRY_ID is not configured")
        if not secret_key:
            raise NearSignerError("SKJOLD_OPERATOR_KEY is not configured")
        signer_id = os.getenv("SKJOLD_OPERATOR_ACCOUNT", "").strip() or contract_id
        return cls(signer_id, secret_key, contract_id)

    @property
    def can_sign(self) -> bool:
        return True

    def call(
        self,
        method: str,
        args: Optional[dict] = None,
        *,
        deposit_yocto: Any = 0,
        gas_tgas: int = DEFAULT_GAS_TGAS,
    ) -> dict:
        if not node_available(self.node_bin):
            raise NearSignerError(
                f"Node is not available ({self.node_bin!r}). The NEAR transaction "
                "transport needs Node >= 26.13.1."
            )
        if not self.script_path.exists():
            raise NearSignerError(
                f"NEAR transaction transport not found at {self.script_path}. "
                "Run `pnpm install` in sdk/."
            )
        request = {
            "mode": "call",
            "network": self.network,
            "rpcUrl": self.rpc_url,
            "contractId": self.contract_id,
            "signerId": self.signer_id,
            "secretKey": self._secret_key,
            "method": method,
            "args": args or {},
            # Decimal strings: deposits exceed 2^53 and must not round-trip as floats.
            "depositYocto": str(deposit_yocto),
            "gasTgas": int(gas_tgas),
        }
        try:
            completed = subprocess.run(
                [self.node_bin, str(self.script_path)],
                input=json.dumps(request),
                text=True,
                capture_output=True,
                timeout=self.timeout,
                cwd=str(self.script_path.parent),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise NearSignerError(
                f"NEAR transaction {method} could not start: {exc}"
            ) from exc
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "").strip()
            raise NearSignerError(
                f"NEAR transaction {method} failed (node exit {completed.returncode}): "
                f"{detail[-2000:]}"
            )
        line = (completed.stdout or "").strip().splitlines()
        try:
            result = json.loads(line[-1])
        except (IndexError, ValueError) as exc:
            raise NearSignerError(
                f"NEAR transaction {method} returned an unreadable response"
            ) from exc
        if not isinstance(result, dict) or not result.get("tx_hash"):
            raise NearSignerError(
                f"NEAR transaction {method} response omitted tx_hash"
            )
        return result
