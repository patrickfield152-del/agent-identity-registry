"""DID operation MCP tools for Attestix (3 tools)."""

import json


def register(mcp):
    """Register DID tools with the MCP server."""

    @mcp.tool()
    async def resolve_did(did: str) -> str:
        """Resolve a DID to its DID Document.

        Supports did:key (local Ed25519) and did:near (on-chain account keys).

        Args:
            did: The DID to resolve (e.g., did:near:agent1.registry.skjold.testnet).
        """
        from attestix.services.cache import get_service
        from attestix.services.did_service import DIDService

        svc = get_service(DIDService)
        result = svc.resolve_did(did)
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    async def create_did_key() -> str:
        """Create a named did:near agent sub-account with a fresh Ed25519 keypair.

        Returns the DID, DID Document, account id and the one-time secret key.
        """
        from attestix.services.cache import get_service
        from attestix.services.did_service import DIDService

        svc = get_service(DIDService)
        result = svc.create_did_key()
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    async def create_did_web(domain: str, path: str = "") -> str:
        """Deprecated: did:web hosting was removed in the NEAR port.

        Returns the compatibility response with a did:near redirect; it never
        produces a hosting URL.

        Args:
            domain: Retained for tool-surface compatibility.
            path: Retained for tool-surface compatibility.
        """
        from attestix.services.cache import get_service
        from attestix.services.did_service import DIDService

        svc = get_service(DIDService)
        result = svc.create_did_web(domain, path)
        return json.dumps(result, indent=2, default=str)
