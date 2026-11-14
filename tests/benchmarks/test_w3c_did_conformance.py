"""W3C DID Core conformance tests for the skjold NEAR port.

Covers the two methods this port supports: ``did:near`` (named accounts, one
``#owner`` verification method per FullAccess Ed25519 key) and the unchanged
``did:key`` vectors. ``did:web`` is a deprecated stub that redirects to
``did:near`` and must never emit a hosting URL.

No test in this module touches the network unless it is explicitly gated on
``SKJOLD_ISSUER_DID`` + ``NEAR_RPC_URL`` (the live issuer proof check).
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import base58
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from attestix.auth.crypto import (
    did_key_to_public_key,
    generate_ed25519_keypair,
    public_key_to_bytes,
    public_key_to_did_key,
    sign_json_payload,
    verify_json_signature,
)
from attestix.services.did_service import DIDService

DID_CORE_CONTEXT = "https://www.w3.org/ns/did/v1"
ED25519_2020_CONTEXT = "https://w3id.org/security/suites/ed25519-2020/v1"
ED25519_2018_CONTEXT = "https://w3id.org/security/suites/ed25519-2018/v1"
DID_NEAR = "did:near:agent1.registry.skjold.testnet"

ISSUER_DID = os.getenv("SKJOLD_ISSUER_DID")
NEAR_RPC_URL = os.getenv("NEAR_RPC_URL")

SKIP_LIVE_ISSUER = pytest.mark.skipif(
    not (ISSUER_DID and NEAR_RPC_URL),
    reason="live issuer resolution needs SKJOLD_ISSUER_DID and NEAR_RPC_URL",
)


def _public_key_base58(public_key: Ed25519PublicKey) -> str:
    """Raw 32-byte Ed25519 key in base58 (did:near publicKeyBase58 form)."""
    return base58.b58encode(public_key_to_bytes(public_key)).decode("ascii")


class TestDIDNearDocument:
    """did:near documents expose exactly one unambiguous ``#owner`` key."""

    @pytest.fixture()
    def document_and_key(self):
        _, public_key = generate_ed25519_keypair()
        document = DIDService()._build_did_near_document(
            DID_NEAR, _public_key_base58(public_key)
        )
        return document, public_key

    def test_id_matches_did(self, document_and_key):
        document, _ = document_and_key
        assert document["id"] == DID_NEAR

    def test_contexts(self, document_and_key):
        document, _ = document_and_key
        assert document["@context"] == [DID_CORE_CONTEXT, ED25519_2018_CONTEXT]

    def test_single_verification_method(self, document_and_key):
        document, _ = document_and_key
        assert len(document["verificationMethod"]) == 1

    def test_verification_method_id(self, document_and_key):
        document, _ = document_and_key
        method = document["verificationMethod"][0]
        assert method["id"] == f"{DID_NEAR}#owner"
        assert method["controller"] == DID_NEAR

    def test_verification_method_type(self, document_and_key):
        document, _ = document_and_key
        assert document["verificationMethod"][0]["type"] == (
            "Ed25519VerificationKey2018"
        )

    def test_pubkey_matches_full_access_key(self, document_and_key):
        document, public_key = document_and_key
        encoded = document["verificationMethod"][0]["publicKeyBase58"]
        assert base58.b58decode(encoded) == public_key_to_bytes(public_key)

    def test_auth_and_assertion_owner_refs(self, document_and_key):
        document, _ = document_and_key
        assert document["authentication"] == ["#owner"]
        assert document["assertionMethod"] == ["#owner"]

    def test_controller_matches_did(self, document_and_key):
        document, _ = document_and_key
        assert document["controller"] == DID_NEAR


class TestDIDNearRoundtrip:
    """Resolution returns the same document twice without spawning the resolver."""

    def test_create_then_resolve(self, monkeypatch):
        _, public_key = generate_ed25519_keypair()
        document = DIDService()._build_did_near_document(
            DID_NEAR, _public_key_base58(public_key)
        )
        service = DIDService()
        calls = []

        def stub_resolver(did):
            calls.append(did)
            return document

        monkeypatch.setattr(service, "_resolve_did_near", stub_resolver)
        monkeypatch.setattr(
            "attestix.services.did_service.subprocess.run",
            lambda *args, **kwargs: pytest.fail(
                "create_then_resolve must not spawn the Node resolver"
            ),
        )

        first = service.resolve_did(DID_NEAR)
        second = service.resolve_did(DID_NEAR)

        assert first == document
        assert second == document
        assert first == second
        assert calls == [DID_NEAR, DID_NEAR]


class TestDIDKeyRoundtrip:
    """The did:key profile is unchanged; vectors are ported verbatim."""

    def test_did_key_document_structure(self, did_service):
        _, public_key = generate_ed25519_keypair()
        did = public_key_to_did_key(public_key)
        document = did_service.resolve_did(did)

        assert document["id"] == did
        assert document["@context"] == [DID_CORE_CONTEXT, ED25519_2020_CONTEXT]
        assert document["controller"] == did
        assert len(document["verificationMethod"]) == 1

        method = document["verificationMethod"][0]
        assert method["id"] == f"{did}#key-1"
        assert method["controller"] == did
        assert method["type"] == "Ed25519VerificationKey2020"
        assert method["publicKeyMultibase"].startswith("z")

        assert document["authentication"] == [f"{did}#key-1"]
        assert document["assertionMethod"] == [f"{did}#key-1"]

    def test_did_key_to_public_key_roundtrip(self):
        """Generate keypair, convert to did:key, convert back; keys must match."""
        _, public_key = generate_ed25519_keypair()
        did = public_key_to_did_key(public_key)
        recovered = did_key_to_public_key(did)
        assert public_key_to_bytes(public_key) == public_key_to_bytes(recovered)


class TestDidWebStub:
    """did:web hosting is removed; the compatibility response redirects to did:near."""

    def test_did_web_stub_redirects(self, did_service):
        result = did_service.create_did_web("example.com")

        assert result["error"]
        assert "did:web removed" in result["error"]
        assert result["did"] is None
        assert result["did_document"] is None
        assert result["redirect"].startswith("did:near:")
        assert "hosting_url" not in result

    def test_did_web_stub_path_redirects(self, did_service):
        result = did_service.create_did_web("example.com", path="agents/v1")

        assert result["redirect"].startswith("did:near:")
        assert "hosting_url" not in result
        assert result["did_document"] is None


def test_two_full_access_keys_duplicate_owner():
    """The local JS resolver emits two VMs with the same ``#owner`` id for two keys."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is required to exercise the reference resolver document builder")
    repo = Path(__file__).resolve().parents[2]
    if not (repo / "sdk" / "node_modules" / "near-api-js").exists():
        pytest.skip("sdk/node_modules/near-api-js is required (pnpm install --prod)")

    key_one = base58.b58encode(b"\x01" * 32).decode("ascii")
    key_two = base58.b58encode(b"\x02" * 32).decode("ascii")
    script = f"""
import {{ buildNearDidDocument }} from './sdk/src/did-near.mjs';
const did = '{DID_NEAR}';
const keys = [
  {{ public_key: 'ed25519:{key_one}', access_key: {{ permission: 'FullAccess' }} }},
  {{ public_key: 'ed25519:{key_two}', access_key: {{ permission: 'FullAccess' }} }},
];
process.stdout.write(JSON.stringify(buildNearDidDocument(did, keys)));
"""
    result = subprocess.run(
        [node, "--input-type=module", "-e", script],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    methods = document["verificationMethod"]
    assert [method["id"] for method in methods] == [f"{DID_NEAR}#owner"] * 2
    assert {method["publicKeyBase58"] for method in methods} == {key_one, key_two}
    assert document["authentication"] == ["#owner"]
    assert document["assertionMethod"] == ["#owner"]


@SKIP_LIVE_ISSUER
def test_issuer_vc_proof_resolves_to_owner_key():
    """The issuer's VC signature verifies against the resolved did:near #owner key."""
    issuer_did = ISSUER_DID
    service = DIDService()
    document = service.resolve_did(issuer_did)
    assert "error" not in document, document.get("error")

    owners = [
        method
        for method in document.get("verificationMethod", [])
        if method.get("id") == f"{issuer_did}#owner"
    ]
    assert len(owners) == 1, "the issuer account must have exactly one FullAccess key"
    raw_public_key = base58.b58decode(owners[0]["publicKeyBase58"])
    assert len(raw_public_key) == 32
    issuer_public_key = Ed25519PublicKey.from_public_bytes(raw_public_key)

    issuer_secret = os.getenv("SKJOLD_VC_ISSUER_KEY")
    if not issuer_secret:
        pytest.skip("SKJOLD_VC_ISSUER_KEY is required to sign the issuer test VC")
    raw_secret = base58.b58decode(issuer_secret.removeprefix("ed25519:"))
    # `signing/near_signer.secret_key_to_near` emits a 32-byte seed; tolerate the
    # legacy 64-byte seed||public form too.
    issuer_signing_key = Ed25519PrivateKey.from_private_bytes(raw_secret[:32])

    credential = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": "urn:uuid:issuer-owner-conformance",
        "type": ["VerifiableCredential", "AgentIdentityCredential"],
        "issuer": issuer_did,
        "issuanceDate": "2026-01-01T00:00:00Z",
        "credentialSubject": {"id": "did:near:agent1.registry.skjold.testnet"},
    }
    proof_value = sign_json_payload(issuer_signing_key, credential)

    assert verify_json_signature(issuer_public_key, credential, proof_value) is True
