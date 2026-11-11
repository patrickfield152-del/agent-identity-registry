"""Registry anchoring MCP tools for skjold (6 tools).

Anchors off-chain artifacts (identity documents, credential digests, audit
batches, declarations) in the skjold registry on NEAR. Every tool returns a
clear error when ``SKJOLD_REGISTRY_ID`` is not configured; nothing is reported
as on-chain evidence without a contract view or a client-captured transaction
hash.
"""

import json


def _validate_required(params: dict) -> str:
    for name, value in params.items():
        if not value or (isinstance(value, str) and not value.strip()):
            return json.dumps({"error": f"{name} cannot be empty"})
    return ""


def _blockchain_service():
    from attestix.services.blockchain_service import BlockchainService
    from attestix.services.cache import get_service

    return get_service(BlockchainService)


def register(mcp):
    """Register registry anchoring tools with the MCP server."""

    @mcp.tool()
    async def anchor_identity(agent_id: str) -> str:
        """Anchor an agent identity (UAIT) digest in the skjold registry.

        Computes the canonical SHA-256 of the identity record and anchors it as
        a typed ``Identity`` artifact with the agent as ``subject_account``.

        Args:
            agent_id: The agent account id (e.g., agent1.registry.skjold.testnet).
        """
        err = _validate_required({"agent_id": agent_id})
        if err:
            return err

        result = _blockchain_service().anchor_identity(agent_id)
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    async def anchor_credential(credential_id: str) -> str:
        """Anchor a Verifiable Credential under the ``skjold-vc-digest/v1`` profile.

        The digest is Base64(SHA-256 of the canonical credential minus ``proof``
        and ``credentialStatus``); it is not the stock did:near ProofType cid.

        Args:
            credential_id: The credential URN (e.g., urn:uuid:...).
        """
        err = _validate_required({"credential_id": credential_id})
        if err:
            return err

        result = _blockchain_service().anchor_credential(credential_id)
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    async def verify_anchor(
        artifact_id: str = "",
        artifact_hash: str = "",
    ) -> str:
        """Verify a registry anchor for an artifact digest.

        Provide either artifact_id (to look up and digest the artifact) or
        artifact_hash (32-byte Base64 or 64-char hex) to read ``get_anchor``.

        Args:
            artifact_id: The artifact ID (agent account or credential URN).
            artifact_hash: Direct digest (Base64 or hex) to verify.
        """
        if not artifact_id and not artifact_hash:
            return json.dumps({"error": "Provide either artifact_id or artifact_hash"})

        svc = _blockchain_service()
        digest = artifact_hash

        if artifact_id and not digest:
            from attestix.services.cache import get_service
            from attestix.services.identity_service import IdentityService

            artifact = get_service(IdentityService).get_identity(artifact_id)
            if artifact is not None:
                digest = svc.hash_artifact(artifact)
            elif artifact_id.startswith("urn:uuid:"):
                from attestix.signing.near_signer import (
                    digest_to_base64,
                    vc_digest,
                )
                from attestix.services.credential_service import CredentialService

                credential = get_service(CredentialService).get_credential(artifact_id)
                if credential is not None:
                    digest = digest_to_base64(vc_digest(credential))
            if not digest:
                try:
                    matches = svc.repository.list(
                        "anchors", filters={"artifact_id": artifact_id}
                    )
                    if matches:
                        digest = matches[0].get("artifact_digest")
                except Exception:
                    matches = []
                if not digest:
                    return json.dumps({
                        "error": f"Cannot resolve artifact_id '{artifact_id}' to a digest"
                    })

        result = svc.verify_anchor(digest)
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    async def anchor_audit_batch(
        agent_id: str,
        start_date: str = "",
        end_date: str = "",
    ) -> str:
        """Anchor the Merkle root of an agent's audit log entries.

        Computes a Merkle tree of audit log entries in the given range and
        anchors the root as a typed ``AuditBatch`` artifact.

        Args:
            agent_id: The agent account id.
            start_date: ISO date for start of range. Empty = all.
            end_date: ISO date for end of range. Empty = all.
        """
        err = _validate_required({"agent_id": agent_id})
        if err:
            return err

        result = _blockchain_service().anchor_audit_batch(
            agent_id=agent_id,
            start_date=start_date or None,
            end_date=end_date or None,
        )
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    async def get_anchor_status(agent_id: str) -> str:
        """Get the flat typed anchor list recorded for an agent.

        Args:
            agent_id: The agent account id.
        """
        err = _validate_required({"agent_id": agent_id})
        if err:
            return err

        result = _blockchain_service().get_anchor_status(agent_id)
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    async def estimate_anchor_cost(artifact_type: str = "identity") -> str:
        """Estimate the storage deposit for an ``anchor_artifact`` call.

        Args:
            artifact_type: One of identity, credential, declaration, audit_batch.
        """
        result = _blockchain_service().estimate_anchor_cost(
            artifact_type,
            artifact_id_len=64,
            has_subject=artifact_type.strip().lower() == "identity",
        )
        return json.dumps(result, indent=2, default=str)
