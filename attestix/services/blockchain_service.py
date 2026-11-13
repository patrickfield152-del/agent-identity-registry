"""NEAR registry anchoring service for skjold.

Anchors artifact digests (UAITs, credential digests, audit Merkle roots,
compliance declarations) in the skjold registry contract. No external
attestation service, schema registry or EVM keys are involved.

Semantics:

* anchors are ``AnchorRecord`` values on-chain (typed artifact, explicit
  ``subject_account``, ``anchored_by``, block height/timestamp). The transaction
  hash is captured **client-side** by the transaction transport; the contract
  itself has no tx hash.
* re-anchoring an identical digest is idempotent: the contract keeps one
  record, so callers always see ``anchor_count == 1``.
* credential anchoring uses the labelled ``skjold-vc-digest/v1`` profile
  (``Base64(sha256(canonicalize_json(vc - proof - credentialStatus)))``), not
  the stock did:near ProofType cid.
* anchoring requires the NEAR registry to be configured. Without it the
  methods return a clear error; nothing is recorded locally as if it were
  on-chain.

The local audit emitter stays: contract events and the local hash chain are two
parallel trails (P0 §3.5).
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional

from attestix.audit import AuditEventEmitter, resolve_emitter, safe_emit
from attestix.config import _get_env
from attestix.errors import ErrorCategory, log_and_format_error
from attestix.signing.near_signer import (
    VC_DIGEST_PROFILE,
    digest_to_base64,
    digest_to_hex,
    vc_digest,
)
from attestix.storage.near_repository import ARTIFACT_TYPE_WIRE as _ARTIFACT_WIRE
from attestix.storage.repository import DEFAULT_TENANT


#: Origin artifact-type names accepted by the tools.
VALID_ARTIFACT_TYPES = {"identity", "credential", "declaration", "audit_batch"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class BlockchainService:
    """Manages skjold registry artifact anchoring."""

    def __init__(
        self,
        emitter: Optional[AuditEventEmitter] = None,
        tenant_id: str = DEFAULT_TENANT,
        repository=None,
    ):
        # Resolve lazily so importing the service never opens storage.
        self._repo = repository if repository is not None else None
        self._network = (_get_env("NEAR_NETWORK", "testnet") or "testnet").strip().lower()
        # v0.4.0 (T033/T034): per-service audit emitter + tenant context (side
        # channel; tenant defaults to "default" for v0.3.0 parity).
        self._emitter = resolve_emitter(emitter)
        self._tenant_id = tenant_id

    # --- wiring -----------------------------------------------------------

    @property
    def repository(self):
        if self._repo is None:
            from attestix.storage import default_repository

            self._repo = default_repository()
        return self._repo

    @property
    def is_configured(self) -> bool:
        """True when the default Repository is the NEAR registry adapter."""
        return bool(getattr(self.repository, "chain_enabled", False))

    @property
    def registry_id(self) -> Optional[str]:
        return getattr(self.repository, "registry_id", None)

    def _require_configured(self) -> Optional[str]:
        """Return an error message when chain anchoring is unavailable."""
        if not self.is_configured:
            return (
                "NEAR registry anchoring is not configured. Set "
                "SKJOLD_REGISTRY_ID (and SKJOLD_OPERATOR_KEY for signed writes) "
                "to enable on-chain anchors."
            )
        return None

    # --- Hashing ----------------------------------------------------------

    def hash_artifact(self, artifact: dict) -> str:
        """Return the canonical SHA-256 hex digest of an artifact document."""
        from attestix.auth.crypto import canonicalize_json

        normalized = canonicalize_json(artifact)
        return hashlib.sha256(normalized).hexdigest()

    # --- Core anchoring ---------------------------------------------------

    def anchor_artifact(
        self,
        artifact_digest: Optional[object] = None,
        artifact_type: str = "identity",
        artifact_id: str = "",
        subject_account: Optional[str] = None,
        *,
        artifact_hash: Optional[str] = None,
    ) -> dict:
        """Anchor one artifact digest in the registry.

        ``artifact_digest`` accepts 32 raw bytes, standard Base64 (the JSON wire
        form) or the legacy 64-char hex form. ``artifact_hash`` is accepted as a
        keyword alias for the pre-port REST surface.
        """
        source = artifact_digest if artifact_digest is not None else artifact_hash
        if source in (None, ""):
            return {"error": "artifact_digest is required"}
        artifact_key = str(artifact_type or "").strip().lower()
        if artifact_key not in VALID_ARTIFACT_TYPES:
            return {
                "error": (
                    f"Invalid artifact_type '{artifact_type}'. "
                    f"Must be one of: {', '.join(sorted(VALID_ARTIFACT_TYPES))}"
                )
            }
        if not artifact_id:
            return {"error": "artifact_id is required"}
        err = self._require_configured()
        if err:
            return {"error": err}
        try:
            digest_b64 = digest_to_base64(source)
            digest_hex = digest_to_hex(source)
            created = self.repository.create(
                "anchors",
                {
                    "artifact_digest": digest_b64,
                    "artifact_hash": digest_hex,
                    "artifact_type": artifact_key,
                    "artifact_id": artifact_id,
                    "subject_account": subject_account,
                    "network": self._network,
                    "anchored_at": _now_iso(),
                },
                id_field="artifact_digest",
            )
            result = self._anchor_view(created, artifact_key, artifact_id, digest_b64)
            result["subject_account"] = subject_account
            if artifact_key == "identity":
                result["agent_id"] = subject_account or artifact_id
            safe_emit(
                self._emitter,
                action="blockchain.anchor",
                target_id=result["anchor_id"],
                target_collection="anchors",
                actor=self.registry_id or "skjold:registry",
                tenant_id=self._tenant_id,
                after={
                    "anchor_id": result["anchor_id"],
                    "artifact_type": artifact_key,
                    "artifact_id": artifact_id,
                    "tx_hash": result.get("tx_hash"),
                },
            )
            return result
        except Exception as e:
            return {
                "error": log_and_format_error(
                    "anchor_artifact", e, ErrorCategory.BLOCKCHAIN,
                    artifact_type=artifact_type, artifact_id=artifact_id,
                )
            }

    def anchor_identity(self, agent_id: str) -> dict:
        """Anchor an agent identity document as a typed ``Identity`` artifact."""
        err = self._require_configured()
        if err:
            return {"error": err}
        try:
            identity = self._find_identity(agent_id)
            if identity is None:
                return {"error": f"Identity {agent_id} not found"}
            artifact_hash = self.hash_artifact(identity)
            result = self.anchor_artifact(
                artifact_hash,
                "identity",
                agent_id,
                subject_account=agent_id,
            )
            if "error" in result:
                return result
            result["agent_id"] = agent_id
            return result
        except Exception as e:
            return {
                "error": log_and_format_error(
                    "anchor_identity", e, ErrorCategory.BLOCKCHAIN, agent_id=agent_id
                )
            }

    def anchor_credential(self, credential_id: str) -> dict:
        """Anchor a locally stored credential under ``skjold-vc-digest/v1``."""
        err = self._require_configured()
        if err:
            return {"error": err}
        try:
            credential = self._find_credential(credential_id)
            if credential is None:
                return {"error": f"Credential {credential_id} not found"}
            digest = vc_digest(credential)
            digest_b64 = digest_to_base64(digest)
            subject_did = (credential.get("credentialSubject") or {}).get("id") or ""
            subject_account = self._subject_account(subject_did)
            types = credential.get("type") or []
            cred_type = types[-1] if isinstance(types, list) and types else "VerifiableCredential"
            expires_at_ns = self._expiry_ns(credential.get("expirationDate"))
            created = self.repository.create(
                "credentials",
                {
                    "id": credential_id,
                    "cid": digest_b64,
                    "vc": credential,
                    "subject_did": subject_did,
                    "subject_account": subject_account,
                    "cred_type": cred_type,
                    "expires_at_ns": expires_at_ns,
                },
                id_field="id",
            )
            result = self._anchor_view(
                created, "credential", credential_id, digest_b64
            )
            result.update(
                {
                    "cid": digest_b64,
                    "digest_profile": VC_DIGEST_PROFILE,
                    "subject_did": subject_did,
                    "subject_account": subject_account,
                    "cred_type": cred_type,
                    "expires_at_ns": expires_at_ns,
                }
            )
            safe_emit(
                self._emitter,
                action="blockchain.anchor",
                target_id=result["anchor_id"],
                target_collection="anchors",
                actor=self.registry_id or "skjold:registry",
                tenant_id=self._tenant_id,
                after={
                    "anchor_id": result["anchor_id"],
                    "artifact_type": "credential",
                    "artifact_id": credential_id,
                    "digest_profile": VC_DIGEST_PROFILE,
                    "tx_hash": result.get("tx_hash"),
                },
            )
            return result
        except Exception as e:
            return {
                "error": log_and_format_error(
                    "anchor_credential", e, ErrorCategory.BLOCKCHAIN,
                    credential_id=credential_id,
                )
            }

    # --- Batch anchoring --------------------------------------------------

    def anchor_audit_batch(
        self,
        agent_id: str,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> dict:
        """Anchor the Merkle root of an agent's audit entries as ``AuditBatch``."""
        err = self._require_configured()
        if err:
            return {"error": err}
        try:
            from attestix.blockchain.merkle import compute_merkle_root

            entries = [
                entry
                for entry in self._document("provenance").get("audit_log", [])
                if entry.get("agent_id") == agent_id
            ]
            if start_date:
                entries = [
                    entry for entry in entries
                    if entry.get("timestamp", "") >= start_date
                ]
            if end_date:
                entries = [
                    entry for entry in entries
                    if entry.get("timestamp", "") <= end_date
                ]
            if not entries:
                return {
                    "error": (
                        f"No audit log entries found for {agent_id} "
                        "in the specified range"
                    )
                }
            merkle_root, leaf_count = compute_merkle_root(entries)
            batch_id = f"batch:{uuid.uuid4().hex[:12]}"
            result = self.anchor_artifact(
                merkle_root,
                "audit_batch",
                batch_id,
                subject_account=agent_id,
            )
            if "error" in result:
                return result
            result["batch_metadata"] = {
                "agent_id": agent_id,
                "entry_count": leaf_count,
                "merkle_root": merkle_root,
                "start_date": start_date or entries[0].get("timestamp"),
                "end_date": end_date or entries[-1].get("timestamp"),
            }
            return result
        except Exception as e:
            return {
                "error": log_and_format_error(
                    "anchor_audit_batch", e, ErrorCategory.BLOCKCHAIN, agent_id=agent_id
                )
            }

    # --- Verification -----------------------------------------------------

    def verify_anchor(self, artifact_digest: object) -> dict:
        """Verify an anchor through ``get_anchor`` (chain) or the local index."""
        try:
            digest_b64 = digest_to_base64(artifact_digest)
            digest_hex = digest_to_hex(artifact_digest)
        except Exception as e:
            return {
                "error": log_and_format_error(
                    "verify_anchor", e, ErrorCategory.BLOCKCHAIN,
                )
            }
        if self.is_configured:
            try:
                anchor = self.repository.get(
                    "anchors", digest_b64, id_field="artifact_digest"
                )
            except Exception as e:
                return {
                    "error": log_and_format_error(
                        "verify_anchor", e, ErrorCategory.BLOCKCHAIN,
                        artifact_digest=digest_b64,
                    )
                }
            if anchor is None:
                return {
                    "verified": False,
                    "artifact_digest": digest_b64,
                    "artifact_hash": digest_hex,
                    "anchor_count": 0,
                    "anchors": [],
                    "reason": "No registry anchor found for this digest",
                }
            anchors = [anchor]
            confirmed = anchor.get("chain_status") == "anchored"
            result = {
                "verified": confirmed,
                "artifact_digest": digest_b64,
                "artifact_hash": digest_hex,
                "anchor_count": len(anchors),
                "anchors": anchors,
                "network": self._network,
                "registry_id": self.registry_id,
            }
            if not confirmed:
                result["reason"] = "Anchor is recorded locally but not confirmed on-chain"
            return result

        # No chain configured: report local-only records instead of faking proof.
        local = [
            anchor
            for anchor in self._document("anchors").get("anchors", [])
            if anchor.get("artifact_digest") == digest_b64
            or anchor.get("artifact_hash") == digest_hex
        ]
        if not local:
            return {
                "verified": False,
                "artifact_digest": digest_b64,
                "artifact_hash": digest_hex,
                "anchor_count": 0,
                "anchors": [],
                "reason": "No local anchor record found for this digest",
            }
        return {
            "verified": "local_only",
            "note": "NEAR registry not configured; returning local anchor records only.",
            "artifact_digest": digest_b64,
            "artifact_hash": digest_hex,
            "anchor_count": len(local),
            "anchors": local,
        }

    # --- Status queries ---------------------------------------------------

    def get_anchor_status(self, agent_id: str) -> dict:
        """Return the flat typed anchor list for an agent."""
        if self.is_configured:
            try:
                anchors = self.repository.list(
                    "anchors", filters={"subject_account": agent_id}
                )
                return {
                    "agent_id": agent_id,
                    "anchor_count": len(anchors),
                    "anchors": anchors,
                    "network": self._network,
                    "registry_id": self.registry_id,
                }
            except Exception as e:
                return {
                    "error": log_and_format_error(
                        "get_anchor_status", e, ErrorCategory.BLOCKCHAIN,
                        agent_id=agent_id,
                    )
                }
        anchors = []
        for anchor in self._document("anchors").get("anchors", []):
            artifact_id = anchor.get("artifact_id", "")
            batch_agent = (anchor.get("batch_metadata") or {}).get("agent_id")
            if agent_id in artifact_id or batch_agent == agent_id:
                anchors.append(anchor)
        return {
            "agent_id": agent_id,
            "anchor_count": len(anchors),
            "anchors": anchors,
            "network": self._network,
            "note": "NEAR registry not configured; local anchor records only.",
        }

    # --- Cost estimation --------------------------------------------------

    def estimate_anchor_cost(
        self,
        artifact_type: str = "identity",
        artifact_id_len: int = 64,
        has_subject: bool = False,
    ) -> dict:
        """Estimate the storage deposit for an ``anchor_artifact`` call."""
        artifact_key = str(artifact_type or "").strip().lower()
        if artifact_key not in VALID_ARTIFACT_TYPES:
            return {
                "error": (
                    f"Invalid artifact_type '{artifact_type}'. "
                    f"Must be one of: {', '.join(sorted(VALID_ARTIFACT_TYPES))}"
                )
            }
        err = self._require_configured()
        if err:
            return {"error": err}
        try:
            client = getattr(self.repository, "client", None)
            if client is None:
                return {"error": "NEAR registry client is not configured"}
            estimate = client.view(
                "estimate_anchor_cost",
                {
                    "artifact_type": _ARTIFACT_WIRE[artifact_key],
                    "artifact_id_len": int(artifact_id_len),
                    "has_subject": bool(has_subject),
                },
            )
            yocto = self._near_token_yocto(estimate)
            return {
                "artifact_type": artifact_key,
                "artifact_id_len": int(artifact_id_len),
                "has_subject": bool(has_subject),
                "network": self._network,
                "registry_id": self.registry_id,
                "storage_cost_yocto": yocto,
                "storage_cost_near": self._yocto_to_near(yocto),
            }
        except Exception as e:
            return {
                "error": log_and_format_error(
                    "estimate_anchor_cost", e, ErrorCategory.BLOCKCHAIN,
                    artifact_type=artifact_type,
                )
            }

    # --- helpers ----------------------------------------------------------

    def _anchor_view(
        self, created: dict, artifact_type: str, artifact_id: str, digest_b64: str
    ) -> dict:
        digest_hex = digest_to_hex(digest_b64)
        return {
            "anchor_id": created.get("anchor_id") or f"anchor:{digest_hex[:12]}",
            "artifact_type": artifact_type,
            "artifact_id": artifact_id,
            "artifact_digest": digest_b64,
            "artifact_hash": digest_hex,
            "subject_account": created.get("subject_account"),
            "network": self._network,
            "registry_id": self.registry_id,
            "tx_hash": created.get("tx_hash"),
            "status": created.get("status", "anchored"),
            "anchored_at": created.get("anchored_at") or _now_iso(),
        }

    def _document(self, collection: str) -> dict:
        loader = getattr(self.repository, "load_document", None)
        return loader(collection) if loader is not None else {}

    def _find_identity(self, agent_id: str) -> Optional[dict]:
        for agent in self._document("identities").get("agents", []):
            if agent.get("agent_id") == agent_id or agent.get("agent") == agent_id:
                return agent
        return None

    def _find_credential(self, credential_id: str) -> Optional[dict]:
        for credential in self._document("credentials").get("credentials", []):
            if credential.get("id") == credential_id:
                return credential
        return None

    def _subject_account(self, subject_did: str) -> Optional[str]:
        if not subject_did:
            return None
        account = (
            subject_did[len("did:near:"):]
            if subject_did.startswith("did:near:")
            else subject_did
        )
        registry = self.registry_id
        if registry and account.endswith("." + registry):
            return account
        return None

    @staticmethod
    def _expiry_ns(value: Optional[str]) -> int:
        if not value:
            return 0
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return 0
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return int(parsed.timestamp() * 1_000_000_000)

    @staticmethod
    def _near_token_yocto(estimate) -> str:
        if isinstance(estimate, str):
            return estimate
        if isinstance(estimate, int):
            return str(estimate)
        if isinstance(estimate, dict):
            for key in ("yocto", "yocto_near", "amount", "cost", "storage_cost"):
                value = estimate.get(key)
                if value is not None:
                    return str(value)
            if len(estimate) == 1:
                return str(next(iter(estimate.values())))
        raise ValueError(f"Unsupported estimate_anchor_cost response: {estimate!r}")

    @staticmethod
    def _yocto_to_near(yocto: str) -> str:
        try:
            return f"{int(yocto) / 10**24:.24f}".rstrip("0").rstrip(".")
        except (TypeError, ValueError):
            return ""
