"""DID resolution service for skjold.

Supports:

- ``did:key`` (local Ed25519 resolution, unchanged vectors), and
- ``did:near`` (named-account resolution through ``sdk/src/did-near.mjs``:
  ``view_access_key_list`` -> FullAccess Ed25519 keys -> one ``#owner`` VM).

``did:web`` hosting and the Universal Resolver are removed in the NEAR port.
``create_did_web`` remains registered as a deprecated compatibility response so
the MCP surface keeps its 47 tools; it returns a ``did:near`` redirect and never
a hosting URL.
"""

import json
import os
import shutil
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import base58

from attestix.auth.crypto import (
    public_key_to_bytes,
    did_key_to_public_key,
)
from attestix.audit import AuditEventEmitter, resolve_emitter, safe_emit
from attestix.errors import ErrorCategory, log_and_format_error
from attestix.storage.repository import DEFAULT_TENANT


#: Fields excluded from the UAIT signature (mutable after creation). Mirrors
#: ``IdentityService.MUTABLE_FIELDS``; duplicated here to avoid a service import
#: cycle at module load.
_UAIT_MUTABLE_FIELDS = {
    "signature",
    "revoked",
    "revocation_reason",
    "revoked_at",
    "reputation_score",
    "eu_compliance",
}


def _resolve_script(name: str) -> Path:
    """Return a checked-in sdk script path (repo layout, not site-packages)."""
    return Path(__file__).resolve().parents[2] / "sdk" / "src" / name


class DIDService:
    """Resolves and creates DID documents."""

    #: Actor recorded on DID audit events (DIDService has no server DID of its own).
    AUDIT_ACTOR = "skjold:did-service"

    def __init__(
        self,
        emitter: Optional[AuditEventEmitter] = None,
        tenant_id: str = DEFAULT_TENANT,
    ):
        # v0.4.0 (T033/T034): per-service audit emitter + tenant context (side
        # channel; tenant defaults to "default" for v0.3.0 parity).
        self._emitter = resolve_emitter(emitter)
        self._tenant_id = tenant_id

    def resolve_did(self, did: str) -> dict:
        """Resolve a DID to its DID Document.

        ``did:key`` resolves locally. ``did:near`` shells out to the local
        resolver script. Every other method is unsupported in this port.
        """
        try:
            if did.startswith("did:key:"):
                return self._resolve_did_key(did)
            if did.startswith("did:near:"):
                return self._resolve_did_near(did)
            return {
                "error": (
                    f"Unsupported DID method for {did!r}. "
                    "This port resolves did:key and did:near only."
                ),
                "did": did,
            }
        except Exception as e:
            return {
                "error": log_and_format_error(
                    "resolve_did", e, ErrorCategory.DID, did=did
                )
            }

    def create_did_key(self) -> dict:
        """Create a named ``did:near`` agent sub-account with a fresh keypair.

        Semantic change from the origin: instead of an ephemeral ``did:key``
        with no chain state, this generates an Ed25519 keypair, derives the
        ``<prefix>.<registry>`` sub-account, and registers it through
        ``NearRepository.create`` -> ``create_agent``. The secret key is
        returned exactly once for the caller to store.

        Requires the NEAR registry to be configured (``SKJOLD_REGISTRY_ID``);
        without it a clear error is returned rather than an unbacked DID.
        """
        try:
            from attestix.storage import default_repository

            repository = default_repository()
            if not getattr(repository, "chain_enabled", False):
                raise RuntimeError(
                    "create_did_key requires the NEAR registry: set "
                    "SKJOLD_REGISTRY_ID (and SKJOLD_OPERATOR_KEY for signing) "
                    "before creating a named agent sub-account."
                )
            registry_id = getattr(repository, "registry_id", None)
            if not registry_id:
                raise RuntimeError(
                    "create_did_key requires SKJOLD_REGISTRY_ID to derive the "
                    "agent sub-account."
                )

            from attestix.config import DEFAULT_EXPIRY_DAYS, UAIT_VERSION
            from attestix.signing import InProcessSigner
            from attestix.signing.near_signer import (
                generate_near_keypair,
                uait_digest,
            )

            _private_key, public_key_wire, secret_key_wire = generate_near_keypair()
            prefix = "key" + uuid.uuid4().hex[:12]
            agent_id = f"{prefix}.{registry_id}"
            did = f"did:near:{agent_id}"

            signer = InProcessSigner()
            now = datetime.now(timezone.utc)
            expires = now + timedelta(days=DEFAULT_EXPIRY_DAYS)
            uait = {
                "version": UAIT_VERSION,
                "agent_id": agent_id,
                "agent": agent_id,
                "did": signer.did,
                "display_name": f"DID key agent {prefix}",
                "description": "Named did:near sub-account created by create_did_key",
                "source_protocol": "did",
                "identity_token": "",
                "token_info": {},
                "capabilities": [],
                "issuer": {"name": "self", "did": signer.did},
                "created_at": now.isoformat(),
                "expires_at": expires.isoformat(),
                "revoked": False,
                "revocation_reason": None,
                "reputation_score": None,
                "eu_compliance": None,
                "signature": None,
            }
            signable = {
                key: value
                for key, value in uait.items()
                if key not in _UAIT_MUTABLE_FIELDS
            }
            uait["signature"] = signer.sign(signable)
            digest = uait_digest(uait, _UAIT_MUTABLE_FIELDS)

            record = {
                "agent_id": agent_id,
                "prefix": prefix,
                "full_access_key": public_key_wire,
                "uait_digest": digest,
                "display_name": uait["display_name"],
                "description": uait["description"],
                "source_protocol": "did",
                "issuer_name": "self",
                "issuer_did": signer.did,
                "capabilities": [],
                "expires_at_ns": int(expires.timestamp() * 1_000_000_000),
                "uait": uait,
            }
            created = repository.create("identities", record, id_field="agent_id")

            did_document = self._build_did_near_document(
                did, public_key_wire.removeprefix("ed25519:")
            )
            keypair_id = f"keypair:{prefix}"
            safe_emit(
                self._emitter,
                action="did.create_did_key",
                target_id=did,
                target_collection="did",
                actor=self.AUDIT_ACTOR,
                tenant_id=self._tenant_id,
                after={"did": did, "keypair_id": keypair_id},
            )
            return {
                "did": did,
                "did_document": did_document,
                "keypair_id": keypair_id,
                "account_id": agent_id,
                "full_access_key": public_key_wire,
                "secret_key": secret_key_wire,
                "uait": uait,
                "uait_digest": created.get("uait_digest"),
                "status": created.get("status", "pending"),
                "tx_hash": created.get("tx_hash"),
                "note": (
                    "Named did:near sub-account registered on the skjold "
                    "registry. Store secret_key now: it is returned once and "
                    "never persisted."
                ),
            }
        except Exception as e:
            return {
                "error": log_and_format_error(
                    "create_did_key", e, ErrorCategory.DID
                )
            }

    def create_did_web(self, domain: str, path: str = "") -> dict:
        """Deprecated: ``did:web`` hosting was removed in the NEAR port.

        Returns the documented compatibility response with a ``did:near``
        redirect. No hosting URL is produced.
        """
        try:
            from attestix.config import SKJOLD_REGISTRY_ID

            account = SKJOLD_REGISTRY_ID or "registry.skjold.testnet"
            redirect = f"did:near:{account}"
            safe_emit(
                self._emitter,
                action="did.create_did_web",
                target_id=redirect,
                target_collection="did",
                actor=self.AUDIT_ACTOR,
                tenant_id=self._tenant_id,
                after={"domain": domain, "redirect": redirect, "deprecated": True},
            )
            return {
                "did": None,
                "did_document": None,
                "keypair_id": None,
                "note": "did:web hosting removed in the NEAR port",
                "error": f"did:web removed; use {redirect}",
                "redirect": redirect,
            }
        except Exception as e:
            return {
                "error": log_and_format_error(
                    "create_did_web", e, ErrorCategory.DID, domain=domain
                )
            }

    # --- Internal resolution methods ---

    def _resolve_did_near(self, did: str) -> dict:
        """Resolve did:near through the checked-in Node resolver."""
        script = _resolve_script("did-near.mjs")
        if not script.exists():
            return {
                "error": f"did:near resolver not found at {script}",
                "did": did,
            }
        node_bin = shutil.which("node")
        if not node_bin:
            return {
                "error": (
                    "did:near resolution requires Node >= 22.22.2 on PATH "
                    "(sdk/src/did-near.mjs)."
                ),
                "did": did,
            }
        try:
            from attestix.config import NEAR_RPC_URL
        except Exception:  # pragma: no cover - config is a hard dependency
            NEAR_RPC_URL = os.getenv("NEAR_RPC_URL", "")
        env = dict(os.environ)
        if NEAR_RPC_URL:
            env.setdefault("NEAR_RPC_URL", NEAR_RPC_URL)
        try:
            completed = subprocess.run(
                [node_bin, str(script), did],
                capture_output=True,
                text=True,
                timeout=30,
                env=env,
                cwd=str(script.parent),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return {
                "error": f"did:near resolver could not start: {exc}",
                "did": did,
            }
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "").strip()
            return {
                "error": f"did:near resolution failed: {detail[-1000:]}",
                "did": did,
            }
        try:
            document = json.loads(completed.stdout)
        except ValueError:
            return {
                "error": "did:near resolver returned an unreadable document",
                "did": did,
            }
        if not isinstance(document, dict) or document.get("id") != did:
            return {
                "error": "did:near resolver returned a document for a different DID",
                "did": did,
            }
        return document

    def _resolve_did_key(self, did: str) -> dict:
        """Locally resolve did:key to DID Document."""
        try:
            public_key = did_key_to_public_key(did)
            pub_bytes = public_key_to_bytes(public_key)
            pub_multibase = "z" + base58.b58encode(pub_bytes).decode("ascii")
        except ValueError as e:
            return {"error": str(e), "did": did}

        return self._build_did_key_document(did, pub_multibase)

    def _build_did_key_document(
        self, did: str, pub_multibase: Optional[str] = None
    ) -> dict:
        """Build a DID Document for a did:key."""
        vm = {
            "id": f"{did}#key-1",
            "type": "Ed25519VerificationKey2020",
            "controller": did,
        }
        if pub_multibase:
            vm["publicKeyMultibase"] = pub_multibase

        return {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            "id": did,
            "controller": did,
            "verificationMethod": [vm],
            "authentication": [f"{did}#key-1"],
            "assertionMethod": [f"{did}#key-1"],
        }

    def _build_did_near_document(self, did: str, public_key_base58: str) -> dict:
        """Build the did:near document for a known single FullAccess key."""
        return {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2018/v1",
            ],
            "id": did,
            "controller": did,
            "verificationMethod": [
                {
                    "id": f"{did}#owner",
                    "type": "Ed25519VerificationKey2018",
                    "controller": did,
                    "publicKeyBase58": public_key_base58,
                }
            ],
            "authentication": ["#owner"],
            "assertionMethod": ["#owner"],
        }
