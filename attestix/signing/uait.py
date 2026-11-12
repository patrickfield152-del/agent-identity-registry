"""Shared UAIT construction for the file, NEAR and DID creation paths.

The three paths historically copied the same dictionary and signature routine.
Keeping one builder makes a new UAIT field or mutable-field change land everywhere.
"""

from typing import Any, Iterable, Optional

from attestix.config import UAIT_VERSION

#: Fields excluded from the UAIT signature (mutable after creation).
MUTABLE_FIELDS = frozenset(
    {
        "signature",
        "revoked",
        "revocation_reason",
        "revoked_at",
        "reputation_score",
        "eu_compliance",
    }
)


def signable_payload(uait: dict) -> dict:
    """Return only the immutable UAIT fields for signing or verification."""
    return {key: value for key, value in uait.items() if key not in MUTABLE_FIELDS}


def build_uait(
    *,
    agent_id: str,
    did: str,
    display_name: str,
    description: str,
    source_protocol: str,
    created_at: str,
    expires_at: str,
    capabilities: Optional[Iterable[str]] = None,
    identity_token: str = "",
    token_info: Optional[dict] = None,
    issuer_name: str = "self",
    include_agent: bool = False,
) -> dict:
    """Build the canonical UAIT body; ``include_agent`` preserves the NEAR/DID shape."""
    uait = {
        "version": UAIT_VERSION,
        "agent_id": agent_id,
    }
    if include_agent:
        uait["agent"] = agent_id
    uait.update(
        {
            "did": did,
            "display_name": display_name,
            "description": description,
            "source_protocol": source_protocol,
            "identity_token": identity_token,
            "token_info": token_info or {},
            "capabilities": list(capabilities or []),
            "issuer": {"name": issuer_name, "did": did},
            "created_at": created_at,
            "expires_at": expires_at,
            "revoked": False,
            "revocation_reason": None,
            "reputation_score": None,
            "eu_compliance": None,
            "signature": None,
        }
    )
    return uait


def sign_uait(uait: dict, signer: Any) -> dict:
    """Sign the immutable payload in place and return the same UAIT."""
    uait["signature"] = signer.sign(signable_payload(uait))
    return uait
