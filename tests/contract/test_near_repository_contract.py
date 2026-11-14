"""Contract tests for the hybrid :class:`NearRepository` over a fake registry client.

The fake below implements the doc §3.3 view/call surface in memory. It is the
only transport: these tests never import a JSON-RPC client, never touch the
network, and prove the adapter's mapping, tenant rules, update/delete semantics,
and document-shim routing without a sandbox.

Fake protocol (duck-typed, mirrored from ``NearRepository``):
``view(method, args) -> object`` and
``call(method, args, *, deposit_yocto=..., gas_tgas=...) -> {"tx_hash": str}``.
"""

import base64
import hashlib
import json
import socket

import pytest

from attestix.storage import DEFAULT_TENANT, FileRepository, NearRepository, Repository
from attestix.auth.crypto import canonicalize_json

REGISTRY_ID = "registry.skjold.testnet"
OPERATOR = "operator.registry.skjold.testnet"
AGENT = "agent1.registry.skjold.testnet"
AUDIENCE = "aud1.registry.skjold.testnet"
COUNTERPARTY = "counterparty.registry.skjold.testnet"
PUBKEY = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp"
UAT_DIGEST = base64.b64encode(bytes(range(32))).decode("ascii")
ARTIFACT_DIGEST = base64.b64encode(bytes(range(32, 64))).decode("ascii")
CID = base64.b64encode(bytes(range(64, 96))).decode("ascii")

CREATE_AGENT_DEPOSIT = "25000000000000000000"
GROWTH_DEPOSIT = "5000000000000000000"

IDENTITY_RECORD = {
    "agent_id": AGENT,
    "full_access_key": PUBKEY,
    "uait_digest": UAT_DIGEST,
    "display_name": "Agent One",
    "description": "contract-test agent",
    "source_protocol": "mcp",
    "issuer_name": "VibeTensor",
    "issuer_did": "did:key:zIssuerPlaceholder",
    "capabilities": ["read"],
    "expires_at_ns": 0,
    "uait": {
        "agent_id": AGENT,
        "display_name": "Agent One",
        "signature": "sig-local-body",
    },
}

CREDENTIAL_RECORD = {
    "id": "urn:uuid:cred-0001",
    "cid": CID,
    "subject_did": "did:key:zSubjectPlaceholder",
    "cred_type": "EUAIActComplianceCredential",
    "expires_at_ns": 0,
}

CREDENTIAL_VC = {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "id": "urn:uuid:cred-0002",
    "type": ["VerifiableCredential", "EUAIActComplianceCredential"],
    "issuer": {"id": "did:key:zIssuerPlaceholder", "name": "VibeTensor"},
    "issuanceDate": "2026-01-01T00:00:00+00:00",
    "credentialSubject": {"id": "did:key:zSubjectPlaceholder"},
    "proof": {"type": "Ed25519Signature2020", "proofValue": "sig"},
}

DELEGATION_RECORD = {
    "jti": "jti-0001",
    "agent": AGENT,
    "audience": AUDIENCE,
    "fck_pubkey": PUBKEY,
    "capabilities": ["read", "write"],
    "parent_jti": None,
    "expires_at_ns": 0,
}

REPUTATION_RECORD = {
    "agent_id": AGENT,
    "counterparty_id": COUNTERPARTY,
    "interaction_id": "ix-0001",
    "outcome": "success",
    "category": "task",
    "details": "completed",
}

ANCHOR_RECORD = {
    "artifact_digest": ARTIFACT_DIGEST,
    "artifact_type": "declaration",
    "artifact_id": "declaration-0001",
    "subject_account": None,
}


class FakeNearClient:
    """In-memory registry: the only transport used by these tests."""

    can_sign = True

    def __init__(self, registry_id: str = REGISTRY_ID) -> None:
        self.registry_id = registry_id
        self.calls: list[dict] = []
        self.views: list[dict] = []
        self.identities: dict[str, dict] = {}
        self.credential_anchors: dict[str, dict] = {}
        self.delegations: dict[str, dict] = {}
        self.reputation: dict[str, dict] = {}
        self.anchors: dict[str, dict] = {}
        self._tx_counter = 0

    # -- reads -------------------------------------------------------------

    def view(self, method, args=None):
        args = dict(args or {})
        self.views.append({"method": method, "args": args})
        if method == "get_identity":
            return self.identities.get(args["agent"])
        if method == "list_identities":
            return self._list_identities(args)
        if method == "get_credential_anchor":
            return self.credential_anchors.get(args["cid"])
        if method == "list_credentials":
            subject = args.get("subject_did")
            limit = int(args.get("limit") or 1000)
            rows = [
                [cid, dict(anchor)]
                for cid, anchor in self.credential_anchors.items()
                if subject is None or anchor.get("subject_did") == subject
            ]
            return rows[:limit]
        if method == "get_delegation":
            return self.delegations.get(args["jti"])
        if method == "list_delegations":
            agent = args.get("agent")
            limit = int(args.get("limit") or 1000)
            rows = [
                dict(record)
                for record in self.delegations.values()
                if agent is None or record.get("agent") == agent
            ]
            return rows[:limit]
        if method == "get_reputation":
            return self._summary(args["agent"])
        if method == "query_reputation":
            return [
                summary
                for summary in (self._summary(agent) for agent in self.reputation)
                if summary is not None
            ][: int(args.get("limit") or 1000)]
        if method == "get_anchor":
            return self.anchors.get(args["artifact_digest"])
        if method == "get_anchor_status":
            agent = args["agent"]
            return [
                dict(record)
                for record in self.anchors.values()
                if record.get("subject_account") == agent
                or record.get("artifact_id") == agent
            ]
        raise AssertionError(f"unexpected view {method!r}")

    def _list_identities(self, args):
        records = []
        for record in self.identities.values():
            lifecycle = "revoked" if record.get("revoked") else "active"
            wanted = args.get("status")
            if wanted is not None:
                if lifecycle != wanted:
                    continue
            elif not args.get("include_revoked", True) and record.get("revoked"):
                continue
            protocol = args.get("source_protocol")
            if protocol is not None and record.get("source_protocol") != protocol:
                continue
            name = args.get("name_contains")
            if name is not None and name.lower() not in record.get("display_name", "").lower():
                continue
            records.append(dict(record))
        return records[: int(args.get("limit") or 1000)]

    def _summary(self, agent):
        state = self.reputation.get(agent)
        if state is None:
            return None
        return {
            "agent": agent,
            "trust_score": state["score"],
            "total_interactions": state["count"],
            "category_breakdown": dict(state["breakdown"]),
            "last_interaction_ns": 1,
        }

    # -- writes ------------------------------------------------------------

    def call(self, method, args, *, deposit_yocto="0", gas_tgas=100):
        args = dict(args or {})
        self.calls.append(
            {
                "method": method,
                "args": args,
                "deposit_yocto": deposit_yocto,
                "gas_tgas": gas_tgas,
            }
        )
        self._tx_counter += 1
        tx_hash = f"tx-{self._tx_counter:03d}"

        if method == "create_agent":
            agent = f"{args['prefix']}.{self.registry_id}"
            self.identities[agent] = {
                "agent": agent,
                "operator": OPERATOR,
                "full_access_key": args["full_access_key"],
                "uait_digest": args["uait_digest"],
                "display_name": args["display_name"],
                "description": args["description"],
                "source_protocol": args["source_protocol"],
                "issuer_name": args["issuer_name"],
                "issuer_did": args["issuer_did"],
                "capabilities": list(args["capabilities"]),
                "created_at_ns": 1,
                "expires_at_ns": int(args["expires_at_ns"]),
                "revoked": False,
                "revoked_at_ns": None,
                "revocation_reason": None,
            }
        elif method == "anchor_credential":
            self.credential_anchors[args["cid"]] = {
                "subject_did": args["subject_did"],
                "subject_account": args["subject_account"],
                "cred_type": args["cred_type"],
                "expires_at_ns": int(args["expires_at_ns"]),
                "anchored_at_ns": 1,
                "attester": OPERATOR,
                "revoked": False,
                "revoked_at_ns": None,
                "revocation_reason": None,
            }
        elif method == "record_delegation":
            self.delegations[args["jti"]] = {
                "jti": args["jti"],
                "agent": args["agent"],
                "audience": args["audience"],
                "capabilities_hash": args["capabilities_hash"],
                "fck_pubkey": args["fck_pubkey"],
                "parent_jti": args["parent_jti"],
                "expires_at_ns": int(args["expires_at_ns"]),
                "recorded_at_ns": 1,
                "revoked": False,
                "revoked_at_ns": None,
                "revocation_reason": None,
            }
        elif method == "record_interaction":
            state = self.reputation.setdefault(
                args["agent"], {"score": 0.0, "count": 0, "breakdown": {}}
            )
            weights = {"success": 1.0, "partial": 0.5, "failure": 0.0, "timeout": 0.2}
            state["count"] += 1
            state["score"] = (
                state["score"] * (state["count"] - 1)
                + weights[args["outcome"]]
            ) / state["count"]
            category = state["breakdown"].setdefault(args["category"], {})
            category[args["outcome"]] = category.get(args["outcome"], 0) + 1
        elif method == "anchor_artifact":
            self.anchors[args["artifact_digest"]] = {
                "artifact_digest": args["artifact_digest"],
                "artifact_type": args["artifact_type"],
                "artifact_id": args["artifact_id"],
                "subject_account": args["subject_account"],
                "anchored_by": OPERATOR,
                "block_height": 1,
                "block_timestamp_ns": 1,
            }
        elif method == "revoke_identity":
            record = self.identities[args["agent"]]
            record["revoked"] = True
            record["revoked_at_ns"] = 2
            record["revocation_reason"] = args["reason"]
        elif method == "revoke_credential":
            anchor = self.credential_anchors[args["cid"]]
            anchor["revoked"] = True
            anchor["revoked_at_ns"] = 2
            anchor["revocation_reason"] = args["reason"]
        elif method == "revoke_delegation":
            record = self.delegations[args["jti"]]
            record["revoked"] = True
            record["revoked_at_ns"] = 2
            record["revocation_reason"] = args["reason"]
        else:
            raise AssertionError(f"unexpected contract call {method!r}")

        return {"tx_hash": tx_hash}


@pytest.fixture
def client() -> FakeNearClient:
    return FakeNearClient()


@pytest.fixture
def body() -> FileRepository:
    return FileRepository()


@pytest.fixture
def repo(client, body, tmp_path) -> NearRepository:
    return NearRepository(
        client=client,
        body=body,
        body_dir=tmp_path / "near",
        registry_id=REGISTRY_ID,
    )


def _call_methods(client: FakeNearClient) -> list[str]:
    return [call["method"] for call in client.calls]


def _view_methods(client: FakeNearClient) -> list[str]:
    return [view["method"] for view in client.views]


def _body_store(tmp_path) -> dict:
    return json.loads((tmp_path / "near" / "bodies.json").read_text(encoding="utf-8"))


def test_wires_injected_client(client, body, tmp_path):
    repo = NearRepository(
        client=client,
        body=body,
        body_dir=tmp_path / "near",
        registry_id=REGISTRY_ID,
    )
    assert isinstance(repo, Repository)
    assert repo.client is client
    assert repo.registry_id == REGISTRY_ID
    assert repo.chain_enabled is True

    offline = NearRepository(client=None, body=body, body_dir=tmp_path / "offline")
    assert offline.chain_enabled is False


def test_read_without_client_fails(body, tmp_path):
    offline = NearRepository(client=None, body=body, body_dir=tmp_path / "near")
    with pytest.raises(RuntimeError):
        offline.get("identities", AGENT, id_field="agent_id")


def test_default_tenant_is_accepted_everywhere(repo):
    created = repo.create(
        "identities", dict(IDENTITY_RECORD), tenant_id=DEFAULT_TENANT, id_field="agent_id"
    )
    assert created["tenant_id"] == DEFAULT_TENANT

    assert repo.get(
        "identities", AGENT, tenant_id=DEFAULT_TENANT, id_field="agent_id"
    )["tenant_id"] == DEFAULT_TENANT
    assert repo.list(
        "identities", tenant_id=DEFAULT_TENANT, id_field="agent_id"
    )[0]["tenant_id"] == DEFAULT_TENANT
    assert repo.update(
        "identities",
        AGENT,
        {"agent_id": AGENT},
        tenant_id=DEFAULT_TENANT,
        id_field="agent_id",
    )["tenant_id"] == DEFAULT_TENANT
    assert repo.last_record("identities", tenant_id=DEFAULT_TENANT) is not None
    assert repo.delete(
        "identities", AGENT, tenant_id=DEFAULT_TENANT, id_field="agent_id"
    ) is True


TENANT_OPERATIONS = [
    ("create", lambda repo: repo.create("identities", dict(IDENTITY_RECORD), tenant_id="acme", id_field="agent_id")),
    ("get", lambda repo: repo.get("identities", AGENT, tenant_id="acme", id_field="agent_id")),
    ("list", lambda repo: repo.list("identities", tenant_id="acme", id_field="agent_id")),
    (
        "update",
        lambda repo: repo.update(
            "identities", AGENT, {"agent_id": AGENT}, tenant_id="acme", id_field="agent_id"
        ),
    ),
    ("delete", lambda repo: repo.delete("identities", AGENT, tenant_id="acme", id_field="agent_id")),
    ("last_record", lambda repo: repo.last_record("identities", tenant_id="acme")),
    ("body_create", lambda repo: repo.create("compliance", {"id": "c1"}, tenant_id="acme")),
    ("body_get", lambda repo: repo.get("compliance", "c1", tenant_id="acme")),
    ("body_list", lambda repo: repo.list("compliance", tenant_id="acme")),
    ("body_update", lambda repo: repo.update("compliance", "c1", {"id": "c1"}, tenant_id="acme")),
    ("body_delete", lambda repo: repo.delete("compliance", "c1", tenant_id="acme")),
]


@pytest.mark.parametrize(
    "operation", [name for name, _ in TENANT_OPERATIONS], ids=[name for name, _ in TENANT_OPERATIONS]
)
def test_non_default_tenant_is_rejected(repo, operation):
    call = dict(TENANT_OPERATIONS)[operation]
    with pytest.raises(ValueError, match=DEFAULT_TENANT):
        call(repo)


def test_identity_round_trip(repo, client, tmp_path):
    created = repo.create(
        "identities", dict(IDENTITY_RECORD), id_field="agent_id"
    )

    assert created["status"] == "pending"
    assert created["chain_status"] == "pending"
    assert created["tx_hash"] == "tx-001"
    assert created["agent_id"] == AGENT
    assert created["uait_digest"] == UAT_DIGEST
    assert created["tenant_id"] == DEFAULT_TENANT

    call = client.calls[-1]
    assert call["method"] == "create_agent"
    assert call["deposit_yocto"] == CREATE_AGENT_DEPOSIT
    assert call["gas_tgas"] == 100
    assert call["args"]["prefix"] == "agent1"
    assert call["args"]["full_access_key"] == PUBKEY
    assert call["args"]["uait_digest"] == UAT_DIGEST
    assert call["args"]["expires_at_ns"] == "0"
    assert call["args"]["capabilities"] == ["read"]

    # The callback landed in the fake: the view now returns the chain record and
    # get() merges the local signed UAIT body over it.
    merged = repo.get("identities", AGENT, id_field="agent_id")
    assert ("get_identity", {"agent": AGENT}) == (client.views[-1]["method"], client.views[-1]["args"])
    assert merged["agent_id"] == AGENT
    assert merged["chain_status"] == "active"
    assert merged["full_access_key"] == PUBKEY
    assert merged["uait_digest"] == UAT_DIGEST
    assert merged["signature"] == "sig-local-body"
    assert merged["revoked"] is False
    assert merged["tenant_id"] == DEFAULT_TENANT

    assert repo.list("identities", id_field="agent_id")[0]["agent_id"] == AGENT


def test_pending_identity_readable(repo):
    # Persist only the signed UAIT body: the create_agent callback has not
    # landed, so get_identity still returns nothing on chain.
    repo.save_document("identities", {"agents": [dict(IDENTITY_RECORD["uait"])]})

    document = repo.get("identities", AGENT, id_field="agent_id")
    assert document["chain_status"] == "pending"
    assert document["signature"] == "sig-local-body"


def test_credential_round_trip(repo, client):
    created = repo.create("credentials", dict(CREDENTIAL_RECORD), id_field="id")

    assert created["status"] == "anchored"
    assert created["chain_status"] == "active"
    assert created["cid"] == CID
    assert created["tx_hash"] == "tx-001"

    call = client.calls[-1]
    assert call["method"] == "anchor_credential"
    assert call["deposit_yocto"] == GROWTH_DEPOSIT
    assert call["args"]["cid"] == CID
    assert call["args"]["subject_did"] == "did:key:zSubjectPlaceholder"
    assert call["args"]["subject_account"] is None
    assert call["args"]["cred_type"] == "EUAIActComplianceCredential"
    assert call["args"]["expires_at_ns"] == "0"

    document = repo.get("credentials", "urn:uuid:cred-0001", id_field="id")
    assert document["cid"] == CID
    assert document["credentialStatus"]["revoked"] is False
    assert document["chain_status"] == "active"
    assert document["subject_did"] == "did:key:zSubjectPlaceholder"

    listed = repo.list("credentials", id_field="id")
    assert [item["cid"] for item in listed] == [CID]


def test_delegation_round_trip(repo, client):
    created = repo.create("delegations", dict(DELEGATION_RECORD), id_field="jti")

    assert created["status"] == "recorded"
    assert created["chain_status"] == "active"
    assert created["tx_hash"] == "tx-001"
    assert created["capabilities_hash"]  # Base64 digest of the capability list

    call = client.calls[-1]
    assert call["method"] == "record_delegation"
    assert call["args"]["jti"] == "jti-0001"
    assert call["args"]["agent"] == AGENT
    assert call["args"]["audience"] == AUDIENCE
    assert call["args"]["fck_pubkey"] == PUBKEY
    assert call["args"]["parent_jti"] is None

    document = repo.get("delegations", "jti-0001", id_field="jti")
    assert document["jti"] == "jti-0001"
    assert document["agent"] == AGENT
    assert document["audience"] == AUDIENCE
    assert document["revoked"] is False
    assert document["chain_status"] == "active"

    listed = repo.list("delegations", id_field="jti")
    assert [item["jti"] for item in listed] == ["jti-0001"]


def test_reputation_round_trip(repo, client):
    created = repo.create("reputation", dict(REPUTATION_RECORD), id_field="interaction_id")

    assert created["status"] == "recorded"
    assert created["tx_hash"] == "tx-001"

    call = client.calls[-1]
    assert call["method"] == "record_interaction"
    assert call["args"] == {
        "agent": AGENT,
        "counterparty": COUNTERPARTY,
        "interaction_id": "ix-0001",
        "outcome": "success",
        "category": "task",
        "details": "completed",
    }

    document = repo.get("reputation", AGENT, id_field="agent_id")
    assert document["agent_id"] == AGENT
    assert document["trust_score"] == 1.0
    assert document["total_interactions"] == 1
    assert document["category_breakdown"] == {"task": {"success": 1}}
    assert document["interactions"][0]["interaction_id"] == "ix-0001"


def test_anchor_round_trip(repo, client):
    created = repo.create("anchors", dict(ANCHOR_RECORD), id_field="artifact_digest")

    assert created["status"] == "anchored"
    assert created["chain_status"] == "anchored"
    assert created["artifact_type"] == "declaration"
    assert created["tx_hash"] == "tx-001"

    call = client.calls[-1]
    assert call["method"] == "anchor_artifact"
    assert call["args"]["artifact_digest"] == ARTIFACT_DIGEST
    assert call["args"]["artifact_type"] == "Declaration"
    assert call["args"]["artifact_id"] == "declaration-0001"
    assert call["args"]["subject_account"] is None

    document = repo.get("anchors", ARTIFACT_DIGEST, id_field="artifact_digest")
    assert document["artifact_digest"] == ARTIFACT_DIGEST
    assert document["artifact_hash"] == bytes(range(32, 64)).hex()
    assert document["artifact_type"] == "declaration"
    assert document["block_height"] == 1
    assert document["chain_status"] == "anchored"


def test_update_preserves_signed_body(
    repo, client, tmp_path
):
    repo.create("identities", dict(IDENTITY_RECORD), id_field="agent_id")
    assert _call_methods(client) == ["create_agent"]

    updated = repo.update(
        "identities",
        AGENT,
        {"agent_id": AGENT, "revoked": True, "revocation_reason": "compromised"},
        id_field="agent_id",
    )

    assert _call_methods(client) == ["create_agent", "revoke_identity"]
    revoke = client.calls[-1]
    assert revoke["args"] == {"agent": AGENT, "reason": "compromised"}
    assert revoke["deposit_yocto"] == GROWTH_DEPOSIT
    assert updated["revoked"] is True
    assert updated["chain_status"] == "revoked"
    assert updated["revocation_reason"] == "compromised"

    store = _body_store(tmp_path)
    history = store["history"]["identities"][AGENT]
    assert len(history) == 1
    assert history[0]["signature"] == "sig-local-body"
    assert store["records"]["identities"][AGENT]["revoked"] is True


def test_update_rejects_identity_drift(repo):
    repo.create("identities", dict(IDENTITY_RECORD), id_field="agent_id")
    with pytest.raises(ValueError, match="must match"):
        repo.update(
            "identities",
            AGENT,
            {"agent_id": "another.registry.skjold.testnet"},
            id_field="agent_id",
        )
    assert _call_methods(repo.client) == ["create_agent"]


def test_update_missing_record_returns_none(repo, client):
    assert (
        repo.update(
            "identities",
            "ghost.registry.skjold.testnet",
            {"agent_id": "ghost.registry.skjold.testnet"},
            id_field="agent_id",
        )
        is None
    )
    assert client.calls == []
    assert _view_methods(client) == ["get_identity"]


def test_revoke_vc_and_delegation(repo, client):
    repo.create("credentials", dict(CREDENTIAL_RECORD), id_field="id")
    repo.update(
        "credentials",
        "urn:uuid:cred-0001",
        {
            "id": "urn:uuid:cred-0001",
            "cid": CID,
            "revoked": True,
            "revocation_reason": "withdrawn",
        },
        id_field="id",
    )
    assert "revoke_credential" in _call_methods(client)
    revoke = [call for call in client.calls if call["method"] == "revoke_credential"][0]
    assert revoke["args"] == {"cid": CID, "reason": "withdrawn"}

    repo.create("delegations", dict(DELEGATION_RECORD), id_field="jti")
    repo.update(
        "delegations",
        "jti-0001",
        {"jti": "jti-0001", "revoked": True, "revocation_reason": "rotated"},
        id_field="jti",
    )
    assert "revoke_delegation" in _call_methods(client)
    revoke = [call for call in client.calls if call["method"] == "revoke_delegation"][0]
    assert revoke["args"] == {"jti": "jti-0001", "reason": "rotated"}


def test_rep_anchor_updates_off_chain(repo, client):
    repo.create("reputation", dict(REPUTATION_RECORD), id_field="interaction_id")
    repo.create("anchors", dict(ANCHOR_RECORD), id_field="artifact_digest")
    writes_before = len(client.calls)

    repo.update(
        "reputation",
        AGENT,
        {"interaction_id": "ix-0001", "details": "edited"},
        id_field="agent_id",
    )
    repo.update(
        "anchors",
        ARTIFACT_DIGEST,
        {"artifact_digest": ARTIFACT_DIGEST, "artifact_id": "declaration-0001", "note": "local"},
        id_field="artifact_digest",
    )

    assert len(client.calls) == writes_before
    assert _call_methods(client) == ["record_interaction", "anchor_artifact"]


def test_delete_local_tombstone(repo, client, tmp_path):
    repo.create("identities", dict(IDENTITY_RECORD), id_field="agent_id")
    writes_before = len(client.calls)

    assert repo.delete("identities", AGENT, id_field="agent_id") is True
    assert len(client.calls) == writes_before
    assert not any("delete" in method for method in _call_methods(client))
    assert repo.get("identities", AGENT, id_field="agent_id") is None

    store = _body_store(tmp_path)
    assert AGENT in store["tombstones"]["identities"]
    assert AGENT not in store["records"]["identities"]
    assert repo.delete("identities", AGENT, id_field="agent_id") is False


def test_body_collections_use_file_repo(repo, body, client):
    created = repo.create("compliance", {"id": "profile-1", "value": 1}, id_field="id")
    assert created["tenant_id"] == DEFAULT_TENANT
    assert client.calls == []
    assert client.views == []

    assert repo.get("compliance", "profile-1", id_field="id")["value"] == 1
    assert [item["id"] for item in repo.list("compliance", id_field="id")] == ["profile-1"]

    updated = repo.update(
        "compliance", "profile-1", {"id": "profile-1", "value": 2}, id_field="id"
    )
    assert updated["value"] == 2
    assert repo.delete("compliance", "profile-1", id_field="id") is True
    assert repo.delete("compliance", "profile-1", id_field="id") is False
    assert body.list("compliance", id_field="id") == []


def test_document_shim_routing(repo, body):
    document = {"profiles": [{"id": "p1"}], "assessments": [], "declarations": []}
    repo.save_document("compliance", document)
    assert body.load_document("compliance") == document
    assert repo.load_document("compliance") == document

    provenance = {"entries": [{"id": "e1"}], "audit_log": []}
    repo.save_document("provenance", provenance)
    assert body.load_document("provenance") == provenance

    audit_record = {"id": "event-1", "action": "created"}
    repo.append_to_document("audit", audit_record)
    assert body.list("audit", id_field="id")[0]["action"] == "created"

    repo.save_document("idempotency", {"keys": [{"id": "k1"}]})
    assert body.load_document("idempotency")["keys"][0]["id"] == "k1"


def test_identity_projection_shape(repo):
    repo.create("identities", dict(IDENTITY_RECORD), id_field="agent_id")

    projection = repo.load_document("identities")
    assert list(projection) == ["agents"]
    assert len(projection["agents"]) == 1
    agent = projection["agents"][0]
    assert agent["agent_id"] == AGENT
    assert agent["agent"] == AGENT
    assert agent["display_name"] == "Agent One"
    assert agent["source_protocol"] == "mcp"
    assert agent["capabilities"] == ["read"]
    assert agent["issuer"] == {
        "name": "VibeTensor",
        "did": "did:key:zIssuerPlaceholder",
    }
    assert agent["signature"] == "sig-local-body"
    assert agent["chain_status"] == "active"
    assert agent["tenant_id"] == DEFAULT_TENANT


def test_credential_and_delegation_projections(repo):
    repo.create("credentials", dict(CREDENTIAL_RECORD), id_field="id")
    repo.create("delegations", dict(DELEGATION_RECORD), id_field="jti")

    credentials = repo.load_document("credentials")
    assert list(credentials) == ["credentials"]
    assert credentials["credentials"][0]["cid"] == CID
    assert credentials["credentials"][0]["id"] == "urn:uuid:cred-0001"

    delegations = repo.load_document("delegations")
    assert list(delegations) == ["delegations"]
    assert delegations["delegations"][0]["jti"] == "jti-0001"
    assert delegations["delegations"][0]["chain_status"] == "active"


def test_append_identity(
    repo, client, tmp_path
):
    record = {key: value for key, value in IDENTITY_RECORD.items() if key != "uait"}
    appended = repo.append_to_document("identities", record)

    assert appended["status"] == "pending"
    assert appended["tx_hash"] == "tx-001"
    assert _call_methods(client) == ["create_agent"]

    store = _body_store(tmp_path)
    body = store["records"]["identities"][AGENT]
    assert body["agent_id"] == AGENT
    assert body["display_name"] == "Agent One"


def test_append_credential(repo, client, tmp_path):
    appended = repo.append_to_document("credentials", dict(CREDENTIAL_VC))

    payload = {key: value for key, value in CREDENTIAL_VC.items() if key != "proof"}
    expected_cid = base64.b64encode(
        hashlib.sha256(canonicalize_json(payload)).digest()
    ).decode("ascii")
    assert appended["cid"] == expected_cid
    assert appended["tx_hash"] == "tx-001"
    assert _call_methods(client) == ["anchor_credential"]

    store = _body_store(tmp_path)
    stored = store["records"]["credentials"]["urn:uuid:cred-0002"]
    assert stored["proof"]["proofValue"] == "sig"



def test_append_delegation(
    repo, client, tmp_path
):
    appended = repo.append_to_document("delegations", dict(DELEGATION_RECORD))

    assert appended["tx_hash"] == "tx-001"
    assert _call_methods(client) == ["record_delegation"]

    store = _body_store(tmp_path)
    stored = store["records"]["delegations"]["jti-0001"]
    assert stored["audience"] == AUDIENCE
    assert stored["parent_jti"] is None


def test_save_identity_projection(repo, client):
    repo.save_document("identities", {"agents": [dict(IDENTITY_RECORD)]})
    assert _call_methods(client) == ["create_agent"]

    # Re-saving the same projection must not create the sub-account again.
    repo.save_document("identities", {"agents": [dict(IDENTITY_RECORD)]})
    assert _call_methods(client) == ["create_agent"]


def test_no_network_socket_access(repo, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("tests must not open a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)

    repo.create("identities", dict(IDENTITY_RECORD), id_field="agent_id")
    repo.get("identities", AGENT, id_field="agent_id")
    repo.list("identities", id_field="agent_id")

def test_list_anchors_limit(repo, client):
    for index in range(4):
        record = dict(ANCHOR_RECORD)
        record["artifact_digest"] = base64.b64encode(bytes([index + 1]) * 32).decode()
        record["artifact_type"] = "declaration" if index < 2 else "credential"
        record["artifact_id"] = f"anchor-{index}"
        repo.create("anchors", record, id_field="artifact_digest")

    client.views.clear()
    rows = repo.list("anchors", filters={"artifact_type": "declaration"}, limit=2)

    assert len(rows) == 2
    assert all(row["artifact_type"] == "declaration" for row in rows)
    assert len([view for view in client.views if view["method"] == "get_anchor"]) == 2
