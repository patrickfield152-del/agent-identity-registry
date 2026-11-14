"""Executable manifest for ``spec/verify/v1/vectors.json`` (7 conformance vectors).

The vectors are the cross-language verifier contract (README.md §1-§3,
CONFORMANCE.md). This suite loads the shipped file **unmodified** and runs the
real ``attestix.auth.crypto`` primitives against it:

* ``canon-001``       JCS-style canonical bytes (NFC, codepoint sort, float).
* ``didkey-001``      did:key <-> raw ed25519 key round trip.
* ``vc-valid/tampered/expired``  Ed25519 VC proof over canonical bytes.
* ``ucan-chain-valid/escalation`` EdDSA compact-JWT signatures + attenuation.

Everything is offline and deterministic: clocks come from the vectors
(``now_reference``) or a fixed reference instant, never ``time.time()``.
"""

import base64
import json
from datetime import datetime, timezone
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from attestix.auth.crypto import (
    ED25519_MULTICODEC_PREFIX,
    canonicalize_json,
    did_key_fragment,
    did_key_to_public_key,
    private_key_from_bytes,
    public_key_from_bytes,
    public_key_to_bytes,
    public_key_to_did_key,
    verify_json_signature,
    verify_signature,
)

VECTORS_PATH = Path(__file__).resolve().parents[2] / "spec" / "verify" / "v1" / "vectors.json"

with VECTORS_PATH.open("r", encoding="utf-8") as stream:
    MANIFEST = json.load(stream)

VECTORS = MANIFEST["vectors"]
BY_ID = {vector["id"]: vector for vector in VECTORS}

#: Fields excluded from the VC signing payload (``CredentialService.MUTABLE_FIELDS``).
MUTABLE_VC_FIELDS = {"proof", "credentialStatus"}

#: Reference instant for vectors that do not pin ``now_reference``.
REFERENCE_NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)

EXPECTED_VECTORS = [
    ("canon-001", "canonicalize"),
    ("didkey-001", "did_key_decode"),
    ("vc-valid-001", "verify_credential"),
    ("vc-tampered-001", "verify_credential"),
    ("vc-expired-001", "verify_credential"),
    ("ucan-chain-valid-001", "verify_delegation_chain"),
    ("ucan-chain-escalation-002", "verify_delegation_chain"),
]

VC_VECTOR_IDS = ["vc-valid-001", "vc-tampered-001", "vc-expired-001"]
UCAN_VECTOR_IDS = ["ucan-chain-valid-001", "ucan-chain-escalation-002"]


def _issuer_public_key():
    """Ed25519 public key for the fixed issuer seed shipped in the manifest."""
    seed = bytes.fromhex(MANIFEST["issuer_seed_hex"])
    assert len(seed) == 32
    public_key = private_key_from_bytes(seed).public_key()
    assert public_key_to_bytes(public_key).hex() == MANIFEST["issuer_pubkey_raw_hex"]
    return public_key


def _vc_payload(vector):
    return {
        key: value
        for key, value in vector["input"].items()
        if key not in MUTABLE_VC_FIELDS
    }


def _vector_now(vector):
    reference = vector.get("now_reference")
    if reference is None:
        return REFERENCE_NOW
    return datetime.fromisoformat(reference)


def _b64url_decode(value):
    # JWT compact serialization uses unpadded base64url; restore padding.
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _jwt_signing_input(token):
    signing_input, _ = token.rsplit(".", 1)
    return signing_input.encode("ascii")


def _decode_jwt(token, public_key):
    return jwt.decode(
        token,
        public_key,
        algorithms=["EdDSA"],
        options={
            "verify_signature": True,
            "verify_exp": False,
            "verify_nbf": False,
            "verify_iat": False,
            "verify_aud": False,
        },
    )


def test_manifest_has_seven_vectors():
    assert MANIFEST["version"] == "v1"
    assert MANIFEST["spec"] == "skjold-verify-conformance"
    assert MANIFEST["vector_count"] == 7
    assert len(VECTORS) == 7

    assert [(vector["id"], vector["kind"]) for vector in VECTORS] == EXPECTED_VECTORS
    assert len({vector["id"] for vector in VECTORS}) == len(VECTORS)

    assert MANIFEST["issuer_did"] == "did:key:" + BY_ID["didkey-001"]["pubkey_multibase"]
    assert (
        BY_ID["didkey-001"]["pubkey_raw_hex"] == MANIFEST["issuer_pubkey_raw_hex"]
    )
    assert len(bytes.fromhex(MANIFEST["issuer_seed_hex"])) == 32


def test_canonicalize_vector_exact():
    vector = BY_ID["canon-001"]
    canonical = canonicalize_json(vector["input"])

    assert canonical.hex() == vector["canonical_bytes_hex"]
    assert canonical.decode("utf-8") == vector["expected"]["canonical_utf8"]

    # The tricky corners called out by the vector: whole floats lose the
    # fraction, the NFD input is NFC-composed, and keys stay codepoint-sorted.
    utf8 = canonical.decode("utf-8")
    assert '"whole_float":1' in utf8
    assert '"real_float":1.5' in utf8
    assert '"nfc_test":"café"' in utf8
    assert '"big_int":9007199254740993' in utf8
    assert utf8.startswith('{"a_first":null')
    assert utf8.endswith('"z_last":true}')


def test_did_key_vector_roundtrip():
    vector = BY_ID["didkey-001"]
    expected = vector["expected"]
    did = vector["input"]["did"]

    assert did == MANIFEST["issuer_did"]
    assert vector["pubkey_multibase"] == did[len("did:key:") :]

    public_key = did_key_to_public_key(did)
    assert isinstance(public_key, Ed25519PublicKey)
    raw = public_key_to_bytes(public_key)
    assert raw.hex() == vector["pubkey_raw_hex"]
    assert raw.hex() == expected["pubkey_raw_hex"]
    assert raw.hex() == MANIFEST["issuer_pubkey_raw_hex"]

    assert ED25519_MULTICODEC_PREFIX.hex() == expected["multicodec_prefix_hex"] == "ed01"
    assert (
        ED25519_MULTICODEC_PREFIX + raw
    ).hex() == vector["multicodec_full_hex"]

    assert public_key_to_did_key(public_key) == did
    assert did_key_to_public_key("did:key:" + vector["pubkey_multibase"]) is not None

    fragment = did_key_fragment(did)
    assert fragment == expected["fragment"]
    assert fragment == "#" + vector["pubkey_multibase"]
    assert expected["verification_method"] == did + fragment


@pytest.mark.parametrize("vector_id", VC_VECTOR_IDS)
def test_vc_vector_verdict(vector_id):
    vector = BY_ID[vector_id]
    expected = vector["expected"]
    payload = _vc_payload(vector)

    # The signed payload is the VC minus proof/credentialStatus, canonicalized.
    canonical = canonicalize_json(payload)
    assert canonical.hex() == vector["canonical_bytes_hex"]

    public_key = public_key_from_bytes(bytes.fromhex(vector["pubkey_raw_hex"]))
    signature = _b64url_decode(vector["signature_b64url"])
    assert len(signature) == 64

    signature_valid = verify_signature(public_key, signature, canonical)
    assert signature_valid is expected["signature_valid"]
    # The same verdict through the skjold helper (canonicalizes internally).
    assert (
        verify_json_signature(public_key, payload, vector["signature_b64url"])
        is expected["signature_valid"]
    )

    # The proof must reference the issuer key, not just carry a signature.
    issuer_did = vector["input"]["issuer"]["id"]
    assert vector["input"]["proof"]["verificationMethod"] == issuer_did + did_key_fragment(
        issuer_did
    )
    assert vector["input"]["proof"]["proofValue"] == vector["signature_b64url"]

    now = _vector_now(vector)
    expires_at = datetime.fromisoformat(vector["input"]["expirationDate"])
    not_expired = expires_at > now
    not_revoked = not vector["input"]["credentialStatus"]["revoked"]

    assert not_expired is expected["not_expired"]
    assert not_revoked is expected["not_revoked"]
    assert (signature_valid and not_expired and not_revoked) is expected["verify"]


@pytest.mark.parametrize("vector_id", UCAN_VECTOR_IDS)
def test_ucan_vector_attenuation(vector_id):
    vector = BY_ID[vector_id]
    expected = vector["expected"]
    assert vector["signing_alg"] == "EdDSA"

    issuer_public_key = _issuer_public_key()
    assert public_key_to_bytes(issuer_public_key).hex() == vector["pubkey_raw_hex"]
    assert public_key_to_did_key(issuer_public_key) == MANIFEST["issuer_did"]

    parent_token = vector["input"]["parent_token"]
    child_token = vector["input"]["token"]

    for token in (parent_token, child_token):
        header = jwt.get_unverified_header(token)
        assert header["alg"] == "EdDSA"
        assert header["typ"] == "JWT"
        assert header["ucv"] == "0.9.0"
        # Verify the compact-JWT signature independently of PyJWT as well.
        signature = _b64url_decode(token.rsplit(".", 1)[1])
        assert verify_signature(issuer_public_key, signature, _jwt_signing_input(token))

    parent_claims = _decode_jwt(parent_token, issuer_public_key)
    child_claims = _decode_jwt(child_token, issuer_public_key)

    # PyJWT accepted both signatures, matching the expected booleans.
    assert expected["parent_signature_valid"] is True
    assert expected["child_signature_valid"] is True

    assert parent_claims["iss"] == MANIFEST["issuer_did"]
    assert child_claims["iss"] == MANIFEST["issuer_did"]
    assert parent_claims["att"] == vector["input"]["parent_att"]
    assert child_claims["att"] == vector["input"]["child_att"]
    assert parent_claims["prf"] == []
    assert child_claims["prf"] == [parent_token]
    assert child_claims["delegator"] == parent_claims["aud"]

    attenuation_is_subset = set(child_claims["att"]) <= set(parent_claims["att"])
    assert attenuation_is_subset is expected["attenuation_is_subset"]

    verify = (
        expected["child_signature_valid"]
        and expected["parent_signature_valid"]
        and attenuation_is_subset
    )
    assert verify is expected["verify"]
