"""NEAR-backed hybrid :class:`Repository` (skjold registry).

``NearRepository`` is the W2 storage adapter for the NEAR port. It implements
**both** persistence surfaces the service layer uses:

* the record API (``create`` / ``get`` / ``list`` / ``update`` / ``delete``)
  maps the chain collections — ``identities``, ``credentials``,
  ``delegations``, ``reputation``, ``anchors`` — onto registry contract views
  and calls; and
* the document shims (``load_document`` / ``save_document`` /
  ``append_to_document``) project the contract state back into the origin
  document shapes, so the five services keep calling ``config.load_*`` /
  ``config.save_*`` unchanged.

Off-chain documents (``compliance``, ``provenance``, ``audit``,
``idempotency``) and every signed body (UAIT JSON, VC JSON, UCAN record) live
in a local body store: by default the injected :class:`FileRepository` for
off-chain collections and a small JSON sidecar under ``DATA_DIR/near`` for the
signed bodies. The contract never stores bulky signed payloads.

Rules enforced here (P0 doc §3.2/§3.5, steps 9-12):

* ``DEFAULT_TENANT`` is the only accepted tenant; any other ``tenant_id``
  raises ``ValueError`` (single-tenant demo, no env var, no header).
* chain records are immutable. ``update`` never rewrites a signed record: it
  persists a new body version locally and issues the matching ``revoke_*``
  call when the update marks the record revoked.
* ``delete`` writes an off-chain tombstone only; there is no contract delete.
* every write requires a signing client. When only a read-only viewer is
  configured, mutating paths raise a clear ``RuntimeError`` instead of
  pretending the write landed.

The module deliberately imports ``attestix.config`` (and the file repository)
inside methods only: ``attestix.storage.file_repository`` imports the config
module at import time, so a top-level config import here would close an import
cycle while ``config._repo()`` is being initialised.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple

from attestix.storage.repository import DEFAULT_TENANT, Repository


#: Collections whose authoritative state is the registry contract.
CHAIN_COLLECTIONS = frozenset(
    {"identities", "credentials", "delegations", "reputation", "anchors"}
)

#: Collections that stay entirely off-chain in the body repository.
BODY_COLLECTIONS = frozenset(
    {"compliance", "provenance", "audit", "idempotency"}
)

#: Origin artifact-type names -> contract enum variant names.
ARTIFACT_TYPE_WIRE = {
    "identity": "Identity",
    "credential": "Credential",
    "declaration": "Declaration",
    "audit_batch": "AuditBatch",
}

#: Contract list views are bounded; the demo registry lists at most this many
#: records per projection pass.
VIEW_LIMIT = 1000

#: Storage deposits (yoctoNEAR). Growth methods refund the excess, so these are
#: safe upper bounds: create_agent needs >= 17 mN + record storage; the other
#: payable calls need their own record bytes (<= ~4 mN at documented borsh sizes).
CREATE_AGENT_DEPOSIT_YOCTO = "25000000000000000000"  # 25 mN
GROWTH_DEPOSIT_YOCTO = "5000000000000000000"  # 5 mN

#: 100 TGas covers a registry call; the protocol ceiling is 1 PGas per tx.
DEFAULT_GAS_TGAS = 100

#: Profile label for the project's canonical VC digest. It is NOT the stock
#: did:near ProofType cid, which hashes the whole credential.
VC_DIGEST_PROFILE = "skjold-vc-digest/v1"

_TENANT_ERROR = (
    "NearRepository is single-tenant: tenant_id must be "
    f"{DEFAULT_TENANT!r} (no env var or header selects another tenant)"
)

_NO_CLIENT_ERROR = (
    "NEAR registry client is not configured. Set SKJOLD_REGISTRY_ID (and "
    "SKJOLD_OPERATOR_KEY for signed writes) or inject a NearContractClient."
)


class NearContractClient(Protocol):
    """Minimal contract client the adapter depends on.

    ``view(method, args)`` performs a read-only ``query`` JSON-RPC call and
    returns the decoded JSON value. ``call(method, args, *, deposit_yocto,
    gas_tgas)`` submits a signed function-call transaction and returns a
    mapping that includes ``tx_hash`` (the client-captured transaction hash;
    the contract itself has no transaction hash).
    """

    def view(self, method: str, args: Optional[dict] = None) -> Any:  # pragma: no cover
        ...

    def call(
        self,
        method: str,
        args: Optional[dict] = None,
        *,
        deposit_yocto: Any = 0,
        gas_tgas: int = DEFAULT_GAS_TGAS,
    ) -> dict:  # pragma: no cover
        ...


# ---------------------------------------------------------------------------
# HTTP read-only client
# ---------------------------------------------------------------------------


class HttpNearClient:
    """Read-only NEAR JSON-RPC client for contract views.

    Uses the pinned ``httpx`` runtime dependency, imported lazily so the
    storage package still imports when httpx is absent. Writes are rejected:
    a viewer cannot fake a successful transaction.
    """

    def __init__(
        self,
        registry_id: str,
        rpc_url: Optional[str] = None,
        *,
        timeout: float = 30.0,
    ) -> None:
        if not registry_id:
            raise ValueError("HttpNearClient requires a registry account id")
        self.registry_id = registry_id
        self.rpc_url = rpc_url or default_rpc_url()
        self.timeout = timeout
        self._http = None

    @property
    def can_sign(self) -> bool:
        return False

    def _post(self, payload: dict) -> dict:
        if self._http is None:
            try:
                import httpx  # local import: optional at module import time
            except ImportError as exc:  # pragma: no cover - default install has httpx
                raise RuntimeError(
                    "httpx is required for NEAR RPC views: pip install 'httpx>=0.28'"
                ) from exc
            self._http = httpx.Client(timeout=self.timeout)
        response = self._http.post(self.rpc_url, json=payload)
        response.raise_for_status()
        return response.json()

    def view(self, method: str, args: Optional[dict] = None) -> Any:
        args_bytes = json.dumps(
            args or {}, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        payload = {
            "jsonrpc": "2.0",
            "id": f"skjold:{method}",
            "method": "query",
            "params": {
                "request_type": "call",
                "finality": "final",
                "account_id": self.registry_id,
                "method_name": method,
                "args_base64": base64.b64encode(args_bytes).decode("ascii"),
            },
        }
        body = self._post(payload)
        if "error" in body:
            error = body["error"]
            message = error.get("message") if isinstance(error, dict) else str(error)
            raise RuntimeError(f"NEAR view {method} failed: {message}")
        result = (body.get("result") or {}).get("result")
        if not result:
            return None
        raw = bytes(result)
        text = raw.decode("utf-8")
        return json.loads(text) if text.strip() else None

    def call(
        self,
        method: str,
        args: Optional[dict] = None,
        *,
        deposit_yocto: Any = 0,
        gas_tgas: int = DEFAULT_GAS_TGAS,
    ) -> dict:
        raise RuntimeError(
            "The configured NEAR client is read-only (no SKJOLD_OPERATOR_KEY): "
            f"{method} requires signed transaction submission via sdk/src/tx.mjs."
        )

    def close(self) -> None:
        if self._http is not None:
            self._http.close()
            self._http = None


class NodeNearClient:
    """Full client: views over HTTP, writes through the Node near-api-js glue.

    ``sdk/src/tx.mjs`` receives one JSON request on stdin and prints
    ``{"tx_hash": "..."}``. Private key material travels on stdin, never on the
    process command line.
    """

    def __init__(
        self,
        registry_id: str,
        signer_id: str,
        secret_key: str,
        *,
        rpc_url: Optional[str] = None,
        network: str = "testnet",
        node_bin: str = "node",
        script_path: Optional[str] = None,
        timeout: float = 180.0,
    ) -> None:
        if not registry_id or not signer_id or not secret_key:
            raise ValueError(
                "NodeNearClient requires registry_id, signer_id and secret_key"
            )
        self.registry_id = registry_id
        self.signer_id = signer_id
        self.secret_key = secret_key
        self.rpc_url = rpc_url or default_rpc_url(network)
        self.network = network
        self.node_bin = node_bin
        self.timeout = timeout
        self.script_path = Path(script_path) if script_path else default_tx_script()
        self._viewer = HttpNearClient(registry_id, self.rpc_url)

    def view(self, method: str, args: Optional[dict] = None) -> Any:
        return self._viewer.view(method, args)

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
        from attestix.signing.near_signer import NodeTxSigner

        signer = NodeTxSigner(
            self.signer_id,
            self.secret_key,
            self.registry_id,
            rpc_url=self.rpc_url,
            network=self.network,
            node_bin=self.node_bin,
            script_path=str(self.script_path),
            timeout=self.timeout,
        )
        return signer.call(
            method, args, deposit_yocto=deposit_yocto, gas_tgas=gas_tgas
        )


# ---------------------------------------------------------------------------
# Environment selection
# ---------------------------------------------------------------------------


def default_rpc_url(network: Optional[str] = None) -> str:
    """Return the canonical RPC URL for the configured NEAR network."""
    value = os.getenv("NEAR_RPC_URL")
    if value:
        return value
    chosen = (network or os.getenv("NEAR_NETWORK") or "testnet").strip().lower()
    if chosen == "mainnet":
        return "https://rpc.mainnet.near.org"
    return "https://rpc.testnet.near.org"


def default_tx_script() -> Path:
    """Return the checked-in Node transaction transport path."""
    return Path(__file__).resolve().parents[2] / "sdk" / "src" / "tx.mjs"


def client_from_env() -> Optional[NearContractClient]:
    """Build the registry client from canonical skjold environment names.

    Returns ``None`` when ``SKJOLD_REGISTRY_ID`` is unset (file backend).
    With a registry but no operator key the client is read-only and signed
    writes raise ``RuntimeError``.
    """
    registry_id = os.getenv("SKJOLD_REGISTRY_ID", "").strip()
    if not registry_id:
        return None
    network = (os.getenv("NEAR_NETWORK") or "testnet").strip().lower()
    rpc_url = default_rpc_url(network)
    operator_key = os.getenv("SKJOLD_OPERATOR_KEY", "").strip()
    if not operator_key:
        return HttpNearClient(registry_id, rpc_url)
    # The contract operator is the account that initialized the registry; the
    # canonical deployment uses the registry account itself as operator signer.
    signer_id = os.getenv("SKJOLD_OPERATOR_ACCOUNT", "").strip() or registry_id
    return NodeNearClient(
        registry_id,
        signer_id,
        operator_key,
        rpc_url=rpc_url,
        network=network,
    )


# ---------------------------------------------------------------------------
# Small conversion helpers
# ---------------------------------------------------------------------------


def _require_tenant(tenant_id: str) -> None:
    if tenant_id != DEFAULT_TENANT:
        raise ValueError(_TENANT_ERROR)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _iso_to_ns(value: Any) -> int:
    """Convert an ISO date or numeric timestamp to integer nanoseconds."""
    if value in (None, ""):
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return int(text)
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return 0
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return int(parsed.timestamp() * 1_000_000_000)
    return 0


def _ns_to_iso(value: Any) -> Optional[str]:
    """Convert integer nanoseconds to an ISO timestamp (None for 0/absent)."""
    if value in (None, 0, "0"):
        return None
    try:
        ns = int(value)
    except (TypeError, ValueError):
        return None
    if ns <= 0:
        return None
    return datetime.fromtimestamp(ns / 1_000_000_000, tz=timezone.utc).isoformat()


def _digest_bytes(value: Any) -> bytes:
    """Coerce a contract/base64/hex/raw digest to 32 raw bytes."""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if len(raw) != 32:
            raise ValueError(f"digest must be 32 bytes, got {len(raw)}")
        return raw
    if isinstance(value, (list, tuple)):
        if len(value) != 32:
            raise ValueError("digest array must contain 32 bytes")
        return bytes(int(part) & 0xFF for part in value)
    if isinstance(value, str):
        text = value.strip()
        if len(text) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in text):
            return bytes.fromhex(text)
        try:
            raw = base64.b64decode(text, validate=True)
        except Exception as exc:
            raise ValueError(f"digest is neither hex nor standard Base64: {value!r}") from exc
        if len(raw) != 32:
            raise ValueError(f"digest must decode to 32 bytes, got {len(raw)}")
        return raw
    raise ValueError("digest must be bytes, Base64 string, hex string or byte list")


def _digest_b64(value: Any) -> str:
    return base64.b64encode(_digest_bytes(value)).decode("ascii")


def _digest_hex(value: Any) -> str:
    return _digest_bytes(value).hex()


def _public_key_wire(value: Any) -> str:
    """Return the ``ed25519:<base58(raw 32)>`` wire form of a public key."""
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("ed25519:") or text.startswith("secp256k1:"):
            return text
        try:
            return _public_key_wire(_digest_bytes(text))
        except ValueError:
            raise ValueError(f"unrecognized public key: {value!r}")
    raw: bytes
    if hasattr(value, "public_bytes"):
        from cryptography.hazmat.primitives import serialization

        raw = value.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    else:
        raw = _digest_bytes(value)
    try:
        import base58
    except ImportError as exc:  # pragma: no cover - base58 is a runtime dep
        raise RuntimeError("base58 is required to format NEAR public keys") from exc
    return "ed25519:" + base58.b58encode(raw).decode("ascii")


def _artifact_wire(artifact_type: str) -> str:
    key = str(artifact_type).strip().lower()
    if key in ARTIFACT_TYPE_WIRE:
        return ARTIFACT_TYPE_WIRE[key]
    if artifact_type in ARTIFACT_TYPE_WIRE.values():
        return str(artifact_type)
    raise ValueError(
        f"Invalid artifact_type {artifact_type!r}; expected one of "
        f"{', '.join(sorted(ARTIFACT_TYPE_WIRE))}"
    )


def _artifact_origin(artifact_type: str) -> str:
    for origin, wire in ARTIFACT_TYPE_WIRE.items():
        if artifact_type == wire:
            return origin
    return str(artifact_type).strip().lower()


def _tx_hash(result: Any) -> Optional[str]:
    """Extract the client-captured transaction hash from a call response."""
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        for key in ("tx_hash", "transaction_hash", "hash", "id"):
            value = result.get(key)
            if isinstance(value, str) and value:
                return value
    return None


def _last_label(account_id: str) -> str:
    return account_id.split(".", 1)[0]


def _is_account_id(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value) > 64:
        return False
    if value != value.lower() or value.startswith(".") or value.endswith("."):
        return False
    return all(part and all(ch.isalnum() or ch in "-_" for ch in part) for part in value.split("."))


def _account_from_subject(value: Any, registry_id: Optional[str]) -> Optional[str]:
    """Map a subject DID/identifier to a registry agent account when possible."""
    if not isinstance(value, str) or not value:
        return None
    account = value[len("did:near:"):] if value.startswith("did:near:") else value
    if registry_id and account.endswith("." + registry_id) and _is_account_id(account):
        return account
    return None


class NearRepository(Repository):
    """Hybrid contract + local-body :class:`Repository` for the skjold registry."""

    def __init__(
        self,
        client: Optional[NearContractClient] = None,
        body: Optional[Repository] = None,
        *,
        body_repository: Optional[Repository] = None,
        body_dir: Optional[Path] = None,
        registry_id: Optional[str] = None,
        network: Optional[str] = None,
    ) -> None:
        self._client = client
        self._body = body if body is not None else body_repository
        self._body_dir = Path(body_dir) if body_dir else None
        self._explicit_registry_id = registry_id or getattr(client, "registry_id", None)
        self.network = (
            network or os.getenv("NEAR_NETWORK") or "testnet"
        ).strip().lower()

    # --- wiring -----------------------------------------------------------

    @classmethod
    def from_env(cls) -> "NearRepository":
        """Construct the adapter from canonical skjold environment variables."""
        return cls(client=client_from_env())

    @property
    def client(self) -> Optional[NearContractClient]:
        return self._client

    @property
    def registry_id(self) -> Optional[str]:
        if self._explicit_registry_id:
            return self._explicit_registry_id
        return os.getenv("SKJOLD_REGISTRY_ID") or None

    @property
    def chain_enabled(self) -> bool:
        """True when a registry client (read or read/write) is configured."""
        return self._client is not None

    def _require_client(self) -> NearContractClient:
        if self._client is None:
            raise RuntimeError(_NO_CLIENT_ERROR)
        return self._client

    def _require_signer(self, method: str) -> NearContractClient:
        client = self._require_client()
        if getattr(client, "can_sign", None) is False:
            raise RuntimeError(
                f"{method} requires a signing client; the configured client is read-only"
            )
        return client


    def _body_repository(self) -> Repository:
        if self._body is None:
            from attestix.storage.file_repository import FileRepository

            self._body = FileRepository()
        return self._body

    def _body_path(self) -> Path:
        if self._body_dir is None:
            from attestix import config

            self._body_dir = Path(config.DATA_DIR) / "near"
        self._body_dir.mkdir(parents=True, exist_ok=True)
        return self._body_dir / "bodies.json"

    def flush(self) -> None:
        flush = getattr(self._body_repository(), "flush", None)
        if callable(flush):
            flush()

    # --- signed-body store -------------------------------------------------

    @staticmethod
    def _empty_body_store() -> dict:
        return {"version": 1, "records": {}, "history": {}, "tombstones": {}}

    def _load_body_store(self) -> dict:
        from attestix import config

        document = config._safe_load(self._body_path(), self._empty_body_store())
        if not isinstance(document, dict):
            return self._empty_body_store()
        document.setdefault("version", 1)
        document.setdefault("records", {})
        document.setdefault("history", {})
        document.setdefault("tombstones", {})
        return document

    def _save_body_store(self, document: dict) -> None:
        from attestix import config

        config._safe_save(self._body_path(), document)

    def _body_records(self, collection: str) -> Dict[str, dict]:
        document = self._load_body_store()
        records = document["records"].get(collection, {})
        return records if isinstance(records, dict) else {}

    def _body_record(self, collection: str, key: str) -> Optional[dict]:
        record = self._body_records(collection).get(key)
        return dict(record) if isinstance(record, dict) else None

    def _tombstones(self, collection: str) -> Dict[str, dict]:
        document = self._load_body_store()
        tombstones = document["tombstones"].get(collection, {})
        return tombstones if isinstance(tombstones, dict) else {}

    def _store_body(
        self, collection: str, key: str, record: dict, *, keep_history: bool
    ) -> dict:
        document = self._load_body_store()
        records = document["records"].setdefault(collection, {})
        if keep_history and key in records:
            history = document["history"].setdefault(collection, {}).setdefault(key, [])
            history.append(records[key])
        records[key] = dict(record)
        self._save_body_store(document)
        return dict(record)

    def _tombstone(self, collection: str, key: str) -> bool:
        document = self._load_body_store()
        tombstone = document["tombstones"].setdefault(collection, {})
        existed = (
            key in document["records"].get(collection, {})
            or key in tombstone
        )
        tombstone[key] = {"deleted_at": _now_iso()}
        document["records"].setdefault(collection, {}).pop(key, None)
        self._save_body_store(document)
        return existed

    def _body_keys_by_field(self, collection: str, field: str, value: str) -> List[str]:
        return [
            key
            for key, record in self._body_records(collection).items()
            if isinstance(record, dict) and record.get(field) == value
        ]

    # --- projection helpers ------------------------------------------------

    @staticmethod
    def _agent_record_to_document(record: dict, body: Optional[dict]) -> dict:
        """Merge one contract AgentRecord with its local signed UAIT body."""
        agent = record.get("agent")
        document: dict = dict(body) if body else {}
        document.setdefault("version", "0.1.0")
        document["agent_id"] = agent
        document["agent"] = agent
        document.setdefault("did", record.get("issuer_did"))
        for field in (
            "display_name",
            "description",
            "source_protocol",
            "capabilities",
        ):
            if field not in document or not document.get(field):
                document[field] = record.get(field)
        if "issuer" not in document:
            document["issuer"] = {
                "name": record.get("issuer_name") or "self",
                "did": record.get("issuer_did"),
            }
        if not document.get("created_at"):
            document["created_at"] = _ns_to_iso(record.get("created_at_ns"))
        if not document.get("expires_at"):
            document["expires_at"] = _ns_to_iso(record.get("expires_at_ns"))
        document["full_access_key"] = record.get("full_access_key")
        document["uait_digest"] = record.get("uait_digest")
        document["revoked"] = bool(record.get("revoked"))
        document["revocation_reason"] = record.get("revocation_reason")
        document["revoked_at"] = _ns_to_iso(record.get("revoked_at_ns"))
        document.setdefault("reputation_score", None)
        document.setdefault("eu_compliance", None)
        document.setdefault("signature", None)
        document["tenant_id"] = DEFAULT_TENANT
        document["chain_status"] = "revoked" if record.get("revoked") else "active"
        return document

    @staticmethod
    def _pending_document(body: dict) -> dict:
        document = dict(body)
        document["agent_id"] = body.get("agent_id") or body.get("agent")
        document["agent"] = document["agent_id"]
        document["revoked"] = bool(body.get("revoked"))
        document.setdefault("signature", None)
        document["tenant_id"] = DEFAULT_TENANT
        document["chain_status"] = "pending"
        return document

    @staticmethod
    def _credential_document(anchor: Optional[dict], body: Optional[dict], cid: str) -> dict:
        document: dict = dict(body) if body else {}
        subject_did = (anchor or {}).get("subject_did")
        cred_type = (anchor or {}).get("cred_type")
        if not document:
            document = {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://w3id.org/security/suites/ed25519-2020/v1",
                ],
                "id": cid,
                "type": ["VerifiableCredential"] + ([cred_type] if cred_type else []),
                "credentialSubject": {"id": subject_did},
                "credentialStatus": {
                    "id": f"{cid}#status",
                    "type": "RevocationList2021Status",
                    "revoked": False,
                    "revocation_reason": None,
                    "revoked_at": None,
                },
            }
        document["cid"] = cid
        document["artifact_digest"] = cid
        revoked = bool((anchor or {}).get("revoked"))
        status = dict(document.get("credentialStatus") or {})
        status["revoked"] = revoked
        if revoked:
            status["revocation_reason"] = (anchor or {}).get("revocation_reason")
            status["revoked_at"] = _ns_to_iso((anchor or {}).get("revoked_at_ns"))
        document["credentialStatus"] = status
        if anchor:
            document["subject_did"] = anchor.get("subject_did")
            document["subject_account"] = anchor.get("subject_account")
            document["cred_type"] = anchor.get("cred_type")
            document["anchored_at_ns"] = anchor.get("anchored_at_ns")
            document["expires_at_ns"] = anchor.get("expires_at_ns")
        document["tenant_id"] = DEFAULT_TENANT
        document["chain_status"] = (
            "revoked" if revoked else ("active" if anchor else "body_only")
        )
        return document

    @staticmethod
    def _delegation_document(record: Optional[dict], body: Optional[dict]) -> dict:
        document: dict = dict(body) if body else {}
        if record:
            document.update(
                {
                    "jti": record.get("jti", document.get("jti")),
                    "agent": record.get("agent"),
                    "audience": record.get("audience"),
                    "capabilities_hash": record.get("capabilities_hash"),
                    "fck_pubkey": record.get("fck_pubkey"),
                    "parent_jti": record.get("parent_jti"),
                    "recorded_at_ns": record.get("recorded_at_ns"),
                    "expires_at_ns": record.get("expires_at_ns"),
                    "revoked": bool(record.get("revoked")),
                    "revocation_reason": record.get("revocation_reason"),
                    "revoked_at": _ns_to_iso(record.get("revoked_at_ns")),
                }
            )
            document.setdefault("issuer", record.get("agent"))
            if not document.get("expires_at"):
                document["expires_at"] = _ns_to_iso(record.get("expires_at_ns"))
        document.setdefault("revoked", False)
        document["tenant_id"] = DEFAULT_TENANT
        document["chain_status"] = (
            "revoked" if document.get("revoked") else ("active" if record else "body_only")
        )
        return document

    @staticmethod
    def _reputation_summary(summary: dict) -> dict:
        """Map a ReputationView/ReputationSummary to the origin score shape."""
        breakdown = summary.get("category_breakdown")
        categories: Dict[str, dict] = {}
        if isinstance(breakdown, dict):
            categories = breakdown
        elif isinstance(breakdown, list):
            for item in breakdown:
                if isinstance(item, (list, tuple)) and item:
                    categories[str(item[0])] = item[1] if len(item) > 1 else {}
                elif isinstance(item, dict):
                    name = item.get("category") or item.get("name")
                    if name:
                        categories[str(name)] = item
        return {
            "agent_id": summary.get("agent"),
            "trust_score": round(float(summary.get("trust_score") or 0.0), 4),
            "total_interactions": int(summary.get("total_interactions") or 0),
            "category_breakdown": categories,
            "last_updated": _ns_to_iso(summary.get("last_interaction_ns")),
            "tenant_id": DEFAULT_TENANT,
        }

    @staticmethod
    def _anchor_document(record: Optional[dict], body: Optional[dict], digest: str) -> dict:
        document: dict = dict(body) if body else {}
        document["artifact_digest"] = digest
        document["artifact_hash"] = _digest_hex(digest)
        if record:
            document["artifact_type"] = _artifact_origin(record.get("artifact_type"))
            document["artifact_id"] = record.get("artifact_id")
            document["subject_account"] = record.get("subject_account")
            document["anchored_by"] = record.get("anchored_by")
            document["block_height"] = record.get("block_height")
            document["block_timestamp_ns"] = record.get("block_timestamp_ns")
            document["anchored_at"] = _ns_to_iso(record.get("block_timestamp_ns"))
            document["status"] = "anchored"
        document.setdefault("artifact_type", document.get("artifact_type"))
        document.setdefault("artifact_id", document.get("artifact_id"))
        document.setdefault("network", os.getenv("NEAR_NETWORK") or "testnet")
        document.setdefault("tx_hash", document.get("tx_hash"))
        document.setdefault("anchor_id", document.get("anchor_id"))
        document["tenant_id"] = DEFAULT_TENANT
        document.setdefault("chain_status", "anchored" if record else "body_only")
        return document

    # --- chain reads -------------------------------------------------------

    def _view(self, method: str, args: Optional[dict] = None) -> Any:
        return self._require_client().view(method, args or {})

    def _list_identity_views(
        self,
        *,
        source_protocol: Optional[str] = None,
        status: Optional[str] = None,
        name_contains: Optional[str] = None,
        include_revoked: bool = True,
        limit: int = VIEW_LIMIT,
    ) -> List[dict]:
        result = self._view(
            "list_identities",
            {
                "source_protocol": source_protocol,
                "status": status,
                "name_contains": name_contains,
                "include_revoked": bool(include_revoked),
                "limit": int(limit),
            },
        )
        return [item for item in (result or []) if isinstance(item, dict)]

    def _get_identity_view(self, agent: str) -> Optional[dict]:
        result = self._view("get_identity", {"agent": agent})
        return result if isinstance(result, dict) else None

    def _list_credential_views(self, subject_did: Optional[str]) -> List[dict]:
        result = self._view(
            "list_credentials",
            {"subject_did": subject_did, "limit": VIEW_LIMIT},
        )
        anchors: List[dict] = []
        for item in result or []:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                digest, anchor = item
                if isinstance(anchor, dict):
                    anchor = dict(anchor)
                    anchor.setdefault("cid", digest)
                    anchors.append(anchor)
            elif isinstance(item, dict):
                anchors.append(item)
        return anchors

    def _get_credential_view(self, cid: str) -> Optional[dict]:
        result = self._view("get_credential_anchor", {"cid": cid})
        if not isinstance(result, dict):
            return None
        anchor = dict(result)
        anchor.setdefault("cid", cid)
        return anchor

    def _list_delegation_views(self, agent: Optional[str]) -> List[dict]:
        result = self._view(
            "list_delegations", {"agent": agent, "limit": VIEW_LIMIT}
        )
        return [item for item in (result or []) if isinstance(item, dict)]

    def _get_delegation_view(self, jti: str) -> Optional[dict]:
        result = self._view("get_delegation", {"jti": jti})
        return result if isinstance(result, dict) else None

    def _get_reputation_view(self, agent: str) -> Optional[dict]:
        result = self._view("get_reputation", {"agent": agent})
        return result if isinstance(result, dict) else None

    def _query_reputation_views(self, query: dict) -> List[dict]:
        result = self._view(
            "query_reputation",
            {
                "min_score": float(query.get("min_score", 0.0)),
                "max_score": float(query.get("max_score", 1.0)),
                "min_interactions": int(query.get("min_interactions", 0)),
                "category": query.get("category"),
                "limit": int(query.get("limit", VIEW_LIMIT)),
            },
        )
        return [item for item in (result or []) if isinstance(item, dict)]

    def _get_anchor_view(self, digest: str) -> Optional[dict]:
        result = self._view("get_anchor", {"artifact_digest": digest})
        return result if isinstance(result, dict) else None

    def _anchor_status_views(self, agent: str) -> List[dict]:
        result = self._view("get_anchor_status", {"agent": agent})
        return [item for item in (result or []) if isinstance(item, dict)]

    # --- record API --------------------------------------------------------

    def create(
        self,
        collection: str,
        record: dict,
        *,
        tenant_id: str = DEFAULT_TENANT,
        id_field: str = "id",
    ) -> dict:
        _require_tenant(tenant_id)
        if not isinstance(record, dict):
            raise ValueError("record must be a dict")
        if collection in BODY_COLLECTIONS or collection not in CHAIN_COLLECTIONS:
            return self._body_repository().create(
                collection, record, tenant_id=tenant_id, id_field=id_field
            )
        return self._create_chain_record(collection, record, id_field=id_field)

    def _create_chain_record(self, collection: str, record: dict, *, id_field: str) -> dict:
        if collection == "identities":
            return self._create_identity(record, id_field)
        if collection == "credentials":
            return self._create_credential(record, id_field)
        if collection == "delegations":
            return self._create_delegation(record, id_field)
        if collection == "reputation":
            return self._create_interaction(record, id_field)
        if collection == "anchors":
            return self._create_anchor(record, id_field)
        raise ValueError(f"Unknown chain collection {collection!r}")

    def _create_identity(self, record: dict, id_field: str) -> dict:
        agent = record.get("agent_id") or record.get("agent") or record.get(id_field)
        if not agent:
            raise ValueError("identity record requires agent_id")
        if not _is_account_id(agent):
            raise ValueError(f"agent_id must be a NEAR AccountId, got {agent!r}")
        full_access_key = record.get("full_access_key") or record.get("public_key")
        if not full_access_key:
            raise ValueError("identity record requires full_access_key")
        uait_digest = record.get("uait_digest")
        if not uait_digest:
            raise ValueError("identity record requires uait_digest")
        wire_digest = _digest_b64(uait_digest)
        expires_at_ns = record.get("expires_at_ns")
        if expires_at_ns in (None, ""):
            expires_at_ns = _iso_to_ns(record.get("expires_at"))
        client = self._require_signer("create_agent")
        result = client.call(
            "create_agent",
            {
                "prefix": record.get("prefix") or _last_label(agent),
                "full_access_key": _public_key_wire(full_access_key),
                "uait_digest": wire_digest,
                "display_name": record.get("display_name") or "",
                "description": record.get("description") or "",
                "source_protocol": record.get("source_protocol") or "",
                "issuer_name": record.get("issuer_name") or "",
                "issuer_did": record.get("issuer_did") or "",
                "capabilities": list(record.get("capabilities") or []),
                "expires_at_ns": str(int(expires_at_ns or 0)),
            },
            deposit_yocto=CREATE_AGENT_DEPOSIT_YOCTO,
            gas_tgas=DEFAULT_GAS_TGAS,
        )
        body = record.get("uait") if isinstance(record.get("uait"), dict) else record
        stored = self._store_body("identities", agent, body, keep_history=False)
        stored.setdefault("agent_id", agent)
        stored["tenant_id"] = DEFAULT_TENANT
        return {
            **dict(record),
            "agent_id": agent,
            "uait_digest": wire_digest,
            "status": "pending",
            "chain_status": "pending",
            "tx_hash": _tx_hash(result),
            "tenant_id": DEFAULT_TENANT,
        }

    def _create_credential(self, record: dict, id_field: str) -> dict:
        credential = record.get("vc") or record.get("credential")
        if credential is None and isinstance(record.get("credentialSubject"), dict):
            credential = record
        cid = record.get("cid")
        if not cid:
            if not isinstance(credential, dict):
                raise ValueError("credential record requires cid or a VC body")
            cid = _digest_b64(_vc_digest(credential))
        wire_cid = _digest_b64(cid)
        subject_did = record.get("subject_did")
        if not subject_did and isinstance(credential, dict):
            subject_did = (credential.get("credentialSubject") or {}).get("id")
        if not subject_did:
            raise ValueError("credential record requires subject_did")
        cred_type = record.get("cred_type")
        if not cred_type and isinstance(credential, dict):
            types = credential.get("type") or []
            cred_type = types[-1] if isinstance(types, list) and types else None
        if not cred_type:
            raise ValueError("credential record requires cred_type")
        expires_at_ns = record.get("expires_at_ns")
        if expires_at_ns in (None, "") and isinstance(credential, dict):
            expires_at_ns = _iso_to_ns(credential.get("expirationDate"))
        subject_account = record.get("subject_account") or _account_from_subject(
            subject_did, self.registry_id
        )
        result = self._require_signer("anchor_credential").call(
            "anchor_credential",
            {
                "subject_did": subject_did,
                "subject_account": subject_account,
                "cid": wire_cid,
                "cred_type": cred_type,
                "expires_at_ns": str(int(expires_at_ns or 0)),
            },
            deposit_yocto=GROWTH_DEPOSIT_YOCTO,
            gas_tgas=DEFAULT_GAS_TGAS,
        )
        body = credential if isinstance(credential, dict) else record
        key = body.get("id") or wire_cid
        self._store_body("credentials", key, body, keep_history=False)
        return {
            **dict(record),
            "cid": wire_cid,
            "status": "anchored",
            "chain_status": "active",
            "tx_hash": _tx_hash(result),
            "tenant_id": DEFAULT_TENANT,
        }

    def _create_delegation(self, record: dict, id_field: str) -> dict:
        jti = record.get("jti") or record.get(id_field)
        if not jti:
            raise ValueError("delegation record requires jti")
        agent = record.get("agent") or record.get("issuer")
        audience = record.get("audience")
        fck_pubkey = record.get("fck_pubkey") or record.get("public_key")
        if not agent or not audience or not fck_pubkey:
            raise ValueError(
                "delegation record requires agent, audience and fck_pubkey"
            )
        capabilities_hash = record.get("capabilities_hash")
        if not capabilities_hash:
            capabilities_hash = _digest_b64(
                _capabilities_digest(record.get("capabilities") or record.get("att") or [])
            )
        expires_at_ns = record.get("expires_at_ns")
        if expires_at_ns in (None, ""):
            expires_at_ns = _iso_to_ns(record.get("expires_at"))
        result = self._require_signer("record_delegation").call(
            "record_delegation",
            {
                "jti": str(jti),
                "agent": str(agent),
                "audience": str(audience),
                "capabilities_hash": _digest_b64(capabilities_hash),
                "fck_pubkey": _public_key_wire(fck_pubkey),
                "parent_jti": record.get("parent_jti"),
                "expires_at_ns": str(int(expires_at_ns or 0)),
            },
            deposit_yocto=GROWTH_DEPOSIT_YOCTO,
            gas_tgas=DEFAULT_GAS_TGAS,
        )
        self._store_body("delegations", str(jti), record, keep_history=False)
        return {
            **dict(record),
            "jti": str(jti),
            "agent": str(agent),
            "audience": str(audience),
            "capabilities_hash": _digest_b64(capabilities_hash),
            "status": "recorded",
            "chain_status": "active",
            "tx_hash": _tx_hash(result),
            "tenant_id": DEFAULT_TENANT,
        }

    def _create_interaction(self, record: dict, id_field: str) -> dict:
        agent = record.get("agent_id") or record.get("agent") or record.get("subject")
        counterparty = (
            record.get("counterparty_id")
            or record.get("counterparty")
            or record.get("reporter")
        )
        if not agent or not counterparty:
            raise ValueError("interaction record requires agent and counterparty")
        outcome = record.get("outcome")
        if not outcome:
            raise ValueError("interaction record requires outcome")
        interaction_id = (
            record.get("interaction_id")
            or record.get(id_field)
            or _interaction_id(agent, counterparty, record)
        )
        result = self._require_signer("record_interaction").call(
            "record_interaction",
            {
                "agent": str(agent),
                "counterparty": str(counterparty),
                "interaction_id": str(interaction_id),
                "outcome": str(outcome),
                "category": str(record.get("category") or "general"),
                "details": str(record.get("details") or ""),
            },
            deposit_yocto=GROWTH_DEPOSIT_YOCTO,
            gas_tgas=DEFAULT_GAS_TGAS,
        )
        body = {**dict(record), "interaction_id": str(interaction_id)}
        self._store_body("reputation", str(interaction_id), body, keep_history=False)
        return {
            **body,
            "agent_id": str(agent),
            "counterparty_id": str(counterparty),
            "status": "recorded",
            "chain_status": "active",
            "tx_hash": _tx_hash(result),
            "tenant_id": DEFAULT_TENANT,
        }

    def _create_anchor(self, record: dict, id_field: str) -> dict:
        digest_source = (
            record.get("artifact_digest")
            or record.get("artifact_hash")
            or record.get(id_field)
        )
        if not digest_source:
            raise ValueError("anchor record requires artifact_digest")
        wire_digest = _digest_b64(digest_source)
        artifact_type = record.get("artifact_type")
        if not artifact_type:
            raise ValueError("anchor record requires artifact_type")
        artifact_id = record.get("artifact_id") or record.get("id") or record.get("anchor_id")
        if not artifact_id:
            raise ValueError("anchor record requires artifact_id")
        subject_account = record.get("subject_account")
        result = self._require_signer("anchor_artifact").call(
            "anchor_artifact",
            {
                "artifact_digest": wire_digest,
                "artifact_type": _artifact_wire(artifact_type),
                "artifact_id": str(artifact_id),
                "subject_account": subject_account,
            },
            deposit_yocto=GROWTH_DEPOSIT_YOCTO,
            gas_tgas=DEFAULT_GAS_TGAS,
        )
        body = {**dict(record), "artifact_digest": wire_digest}
        body.setdefault("tx_hash", _tx_hash(result))
        self._store_body("anchors", wire_digest, body, keep_history=False)
        return {
            **body,
            "artifact_type": _artifact_origin(artifact_type),
            "artifact_id": str(artifact_id),
            "subject_account": subject_account,
            "status": "anchored",
            "chain_status": "anchored",
            "tx_hash": body.get("tx_hash") or _tx_hash(result),
            "tenant_id": DEFAULT_TENANT,
        }

    def get(
        self,
        collection: str,
        record_id: str,
        *,
        tenant_id: str = DEFAULT_TENANT,
        id_field: str = "id",
    ) -> Optional[dict]:
        _require_tenant(tenant_id)
        if collection in BODY_COLLECTIONS or collection not in CHAIN_COLLECTIONS:
            return self._body_repository().get(
                collection, record_id, tenant_id=tenant_id, id_field=id_field
            )
        if record_id in self._tombstones(collection):
            return None
        if collection == "identities":
            return self._get_identity(record_id)
        if collection == "credentials":
            return self._get_credential(record_id)
        if collection == "delegations":
            return self._get_delegation(record_id)
        if collection == "reputation":
            return self._get_reputation(record_id)
        if collection == "anchors":
            return self._get_anchor(record_id)
        raise ValueError(f"Unknown chain collection {collection!r}")

    def _get_identity(self, agent: str) -> Optional[dict]:
        body = self._body_record("identities", agent)
        record = self._get_identity_view(agent)
        if record is None:
            return self._pending_document(body) if body else None
        return self._agent_record_to_document(record, body)

    def _credential_lookup(self, record_id: str) -> Tuple[Optional[dict], Optional[str]]:
        records = self._body_records("credentials")
        if record_id in records:
            body = dict(records[record_id])
            cid = body.get("cid")
            if not cid:
                cid = _digest_b64(_vc_digest(body))
            return body, _digest_b64(cid)
        for body in records.values():
            if isinstance(body, dict) and body.get("id") == record_id:
                cid = body.get("cid") or _digest_b64(_vc_digest(body))
                return dict(body), _digest_b64(cid)
        try:
            return None, _digest_b64(record_id)
        except ValueError:
            return None, None

    def _get_credential(self, record_id: str) -> Optional[dict]:
        body, cid = self._credential_lookup(record_id)
        if cid is None:
            return None
        anchor = self._get_credential_view(cid)
        if anchor is None and body is None:
            return None
        return self._credential_document(anchor, body, cid)

    def _get_delegation(self, jti: str) -> Optional[dict]:
        body = self._body_record("delegations", jti)
        record = self._get_delegation_view(jti)
        if record is None and body is None:
            return None
        return self._delegation_document(record, body)

    def _get_reputation(self, agent: str) -> Optional[dict]:
        summary = self._get_reputation_view(agent)
        if summary is None:
            return None
        document = self._reputation_summary(summary)
        document["interactions"] = [
            dict(item)
            for item in self._body_records("reputation").values()
            if isinstance(item, dict) and item.get("agent_id") == agent
        ]
        return document

    def _get_anchor(self, digest: str) -> Optional[dict]:
        try:
            wire_digest = _digest_b64(digest)
        except ValueError:
            return None
        body = self._body_record("anchors", wire_digest)
        record = self._get_anchor_view(wire_digest)
        if record is None and body is None:
            return None
        return self._anchor_document(record, body, wire_digest)

    def list(
        self,
        collection: str,
        *,
        tenant_id: str = DEFAULT_TENANT,
        filters: Optional[dict] = None,
        limit: Optional[int] = None,
        id_field: str = "id",
    ) -> List[dict]:
        _require_tenant(tenant_id)
        if collection in BODY_COLLECTIONS or collection not in CHAIN_COLLECTIONS:
            return self._body_repository().list(
                collection,
                tenant_id=tenant_id,
                filters=filters,
                limit=limit,
                id_field=id_field,
            )
        filters = dict(filters or {})
        if collection == "identities":
            results = self._list_identities(filters, limit)
        elif collection == "credentials":
            results = self._list_credentials(filters, limit)
        elif collection == "delegations":
            results = self._list_delegations(filters, limit)
        elif collection == "reputation":
            results = self._list_reputation(filters, limit)
        elif collection == "anchors":
            results = self._list_anchors(filters, limit)
        else:
            raise ValueError(f"Unknown chain collection {collection!r}")
        return self._apply_filters(results, filters, limit)

    @staticmethod
    def _apply_filters(
        results: List[dict], filters: dict, limit: Optional[int]
    ) -> List[dict]:
        if filters:
            results = [
                record
                for record in results
                if all(record.get(key) == value for key, value in filters.items())
            ]
        if limit is not None:
            results = results[: int(limit)]
        return results

    def _list_identities(self, filters: dict, limit: Optional[int]) -> List[dict]:
        tombstones = self._tombstones("identities")
        view_records = self._list_identity_views(
            source_protocol=filters.get("source_protocol"),
            status=filters.get("status"),
            name_contains=filters.get("name_contains"),
            include_revoked=bool(filters.get("include_revoked", True)),
            limit=int(filters.get("chain_limit", VIEW_LIMIT)),
        )
        results: List[dict] = []
        seen = set()
        for record in view_records:
            agent = record.get("agent")
            if not agent or agent in tombstones:
                continue
            seen.add(agent)
            results.append(
                self._agent_record_to_document(
                    record, self._body_record("identities", agent)
                )
            )
        for key, body in self._body_records("identities").items():
            if key in seen or key in tombstones or not isinstance(body, dict):
                continue
            results.append(self._pending_document(body))
        return results

    def _list_credentials(self, filters: dict, limit: Optional[int]) -> List[dict]:
        tombstones = self._tombstones("credentials")
        subject = (
            filters.get("subject_did")
            or filters.get("agent_id")
            or filters.get("credentialSubject")
        )
        body_records = self._body_records("credentials")
        by_cid: Dict[str, dict] = {}
        for key, body in body_records.items():
            if not isinstance(body, dict) or body.get("id") in tombstones or key in tombstones:
                continue
            try:
                cid = _digest_b64(body.get("cid") or _vc_digest(body))
            except ValueError:
                continue
            by_cid[cid] = dict(body)
        anchors = self._list_credential_views(subject if isinstance(subject, str) else None)
        results: List[dict] = []
        seen = set()
        for anchor in anchors:
            cid = _digest_b64(anchor.get("cid") or anchor.get("artifact_digest"))
            if cid in tombstones:
                continue
            body = by_cid.get(cid)
            if body is not None and body.get("id") in tombstones:
                continue
            seen.add(cid)
            document = self._credential_document(anchor, body, cid)
            if filters.get("valid_only") and document.get("credentialStatus", {}).get("revoked"):
                continue
            results.append(document)
        for cid, body in by_cid.items():
            if cid in seen or cid in tombstones:
                continue
            document = self._credential_document(None, body, cid)
            if filters.get("valid_only") and document.get("credentialStatus", {}).get("revoked"):
                continue
            results.append(document)
        return results

    def _list_delegations(self, filters: dict, limit: Optional[int]) -> List[dict]:
        tombstones = self._tombstones("delegations")
        agent = filters.get("agent") or filters.get("agent_id")
        view_records = self._list_delegation_views(agent if isinstance(agent, str) else None)
        results: List[dict] = []
        seen = set()
        for record in view_records:
            jti = record.get("jti")
            if not jti or jti in tombstones:
                continue
            seen.add(jti)
            results.append(
                self._delegation_document(
                    record, self._body_record("delegations", jti)
                )
            )
        for jti, body in self._body_records("delegations").items():
            if jti in seen or jti in tombstones or not isinstance(body, dict):
                continue
            results.append(self._delegation_document(None, body))
        return results

    def _list_reputation(self, filters: dict, limit: Optional[int]) -> List[dict]:
        agent = filters.get("agent_id") or filters.get("agent")
        if isinstance(agent, str) and agent:
            summary = self._get_reputation_view(agent)
            if summary is None:
                return []
            document = self._reputation_summary(summary)
            document["interactions"] = [
                dict(item)
                for item in self._body_records("reputation").values()
                if isinstance(item, dict) and item.get("agent_id") == agent
            ]
            return [document]
        summaries = self._query_reputation_views(
            {
                "min_score": filters.get("min_score", 0.0),
                "max_score": filters.get("max_score", 1.0),
                "min_interactions": filters.get("min_interactions", 0),
                "category": filters.get("category"),
                "limit": int(filters.get("chain_limit", VIEW_LIMIT)),
            }
        )
        return [self._reputation_summary(summary) for summary in summaries]

    def _list_anchors(self, filters: dict, limit: Optional[int]) -> List[dict]:
        tombstones = self._tombstones("anchors")
        subject = filters.get("subject_account") or filters.get("agent")
        results: List[dict] = []
        seen = set()
        if isinstance(subject, str) and subject:
            for record in self._anchor_status_views(subject):
                digest = _digest_b64(record.get("artifact_digest"))
                if digest in tombstones or digest in seen:
                    continue
                seen.add(digest)
                results.append(
                    self._anchor_document(
                        record, self._body_record("anchors", digest), digest
                    )
                )
        for digest, body in self._body_records("anchors").items():
            if digest in seen or digest in tombstones or not isinstance(body, dict):
                continue
            record = self._get_anchor_view(digest)
            results.append(self._anchor_document(record, body, digest))
        return results

    def update(
        self,
        collection: str,
        record_id: str,
        record: dict,
        *,
        tenant_id: str = DEFAULT_TENANT,
        id_field: str = "id",
    ) -> Optional[dict]:
        _require_tenant(tenant_id)
        if not isinstance(record, dict):
            raise ValueError("record must be a dict")
        if id_field in record and record[id_field] != record_id:
            raise ValueError(
                f"{id_field!r} in record ({record[id_field]!r}) must match "
                f"record_id {record_id!r}; update must not change identity"
            )
        if collection in BODY_COLLECTIONS or collection not in CHAIN_COLLECTIONS:
            return self._body_repository().update(
                collection, record_id, record, tenant_id=tenant_id, id_field=id_field
            )
        existing = self.get(collection, record_id, id_field=id_field)
        if existing is None:
            return None
        stored = {**dict(record), id_field: record_id, "tenant_id": DEFAULT_TENANT}
        key = self._body_key(collection, record_id, stored, existing)
        self._store_body(collection, key, stored, keep_history=True)
        revoked_now = bool(stored.get("revoked"))
        revoked_before = bool(existing.get("revoked"))
        if revoked_now and not revoked_before:
            reason = str(stored.get("revocation_reason") or stored.get("reason") or "")
            self._revoke_on_chain(collection, record_id, existing, reason)
        return self.get(collection, record_id, id_field=id_field)

    def _body_key(
        self, collection: str, record_id: str, record: dict, existing: dict
    ) -> str:
        if collection == "credentials":
            cid = record.get("cid") or existing.get("cid")
            if cid:
                return _digest_b64(cid)
            body_id = record.get("id")
            if body_id:
                return str(body_id)
        if collection == "anchors":
            digest = record.get("artifact_digest") or record.get("artifact_hash")
            if digest:
                return _digest_b64(digest)
        if collection == "reputation":
            return str(record.get("interaction_id") or record_id)
        return str(record_id)

    def _revoke_on_chain(
        self, collection: str, record_id: str, existing: dict, reason: str
    ) -> None:
        if collection == "identities":
            self._require_signer("revoke_identity").call(
                "revoke_identity",
                {"agent": record_id, "reason": reason},
                deposit_yocto=GROWTH_DEPOSIT_YOCTO,
                gas_tgas=DEFAULT_GAS_TGAS,
            )
            return
        if collection == "credentials":
            cid = existing.get("cid") or existing.get("artifact_digest")
            if not cid:
                credential = existing
                cid = _digest_b64(_vc_digest(credential))
            self._require_signer("revoke_credential").call(
                "revoke_credential",
                {"cid": _digest_b64(cid), "reason": reason},
                deposit_yocto=GROWTH_DEPOSIT_YOCTO,
                gas_tgas=DEFAULT_GAS_TGAS,
            )
            return
        if collection == "delegations":
            self._require_signer("revoke_delegation").call(
                "revoke_delegation",
                {"jti": record_id, "reason": reason},
                deposit_yocto=GROWTH_DEPOSIT_YOCTO,
                gas_tgas=DEFAULT_GAS_TGAS,
            )
            return
        # reputation and anchors have no revoke surface: the local body is the
        # only place their mutable metadata lives.

    def delete(
        self,
        collection: str,
        record_id: str,
        *,
        tenant_id: str = DEFAULT_TENANT,
        id_field: str = "id",
    ) -> bool:
        _require_tenant(tenant_id)
        if collection in BODY_COLLECTIONS or collection not in CHAIN_COLLECTIONS:
            return self._body_repository().delete(
                collection, record_id, tenant_id=tenant_id, id_field=id_field
            )
        existing = self.get(collection, record_id, id_field=id_field)
        if existing is None:
            return False
        body_keys = [record_id]
        if collection == "credentials":
            cid = existing.get("cid")
            if cid:
                body_keys.append(_digest_b64(cid))
        removed = False
        for key in dict.fromkeys(body_keys):
            removed = self._tombstone(collection, key) or removed
        return removed or True

    def last_record(
        self,
        collection: str,
        *,
        tenant_id: str = DEFAULT_TENANT,
    ) -> Optional[dict]:
        _require_tenant(tenant_id)
        if collection in BODY_COLLECTIONS or collection not in CHAIN_COLLECTIONS:
            last_record = getattr(self._body_repository(), "last_record", None)
            if callable(last_record):
                return last_record(collection, tenant_id=tenant_id)
            rows = self._body_repository().list(
                collection, tenant_id=tenant_id, id_field="event_id"
            )
            return rows[-1] if rows else None
        rows = self.list(collection)
        return rows[-1] if rows else None

    # --- document shims ----------------------------------------------------

    @staticmethod
    def _document_list_key(collection: str) -> str:
        return {
            "identities": "agents",
            "credentials": "credentials",
            "delegations": "delegations",
            "reputation": "interactions",
            "anchors": "anchors",
        }[collection]

    def load_document(self, collection: str) -> dict:
        if collection in BODY_COLLECTIONS or collection not in CHAIN_COLLECTIONS:
            return self._body_repository().load_document(collection)
        if collection == "identities":
            return {"agents": self._list_identities({}, None)}
        if collection == "credentials":
            return {"credentials": self._list_credentials({}, None)}
        if collection == "delegations":
            return {"delegations": self._list_delegations({}, None)}
        if collection == "reputation":
            summaries = self._query_reputation_views(
                {"min_score": 0.0, "max_score": 1.0, "min_interactions": 0, "limit": VIEW_LIMIT}
            )
            scores = {
                summary["agent_id"]: summary
                for summary in (self._reputation_summary(item) for item in summaries)
                if summary.get("agent_id")
            }
            interactions = [
                dict(item)
                for item in self._body_records("reputation").values()
                if isinstance(item, dict)
                and (item.get("agent_id") or item.get("agent"))
            ]
            return {"interactions": interactions, "scores": scores}
        if collection == "anchors":
            return {"anchors": self._list_anchors({}, None)}
        raise ValueError(f"Unknown collection {collection!r}")

    def save_document(self, collection: str, data: dict) -> None:
        if collection in BODY_COLLECTIONS or collection not in CHAIN_COLLECTIONS:
            self._body_repository().save_document(collection, data)
            return
        if not isinstance(data, dict):
            raise ValueError("document must be a dict")
        list_key = self._document_list_key(collection)
        incoming = data.get(list_key, [])
        if not isinstance(incoming, list):
            raise ValueError(f"{list_key!r} must be a list")
        existing = self.load_document(collection).get(list_key, [])
        if collection == "identities":
            self._save_identities_document(incoming, existing)
        elif collection == "credentials":
            self._save_credentials_document(incoming, existing)
        elif collection == "delegations":
            self._save_delegations_document(incoming, existing)
        elif collection == "reputation":
            self._save_reputation_document(incoming, data.get("scores") or {})
        elif collection == "anchors":
            self._save_anchors_document(incoming, existing)

    def _save_identities_document(
        self, incoming: List[dict], existing: List[dict]
    ) -> None:
        by_id = {
            str(item.get("agent_id") or item.get("agent")): item
            for item in existing
            if isinstance(item, dict)
        }
        tombstones = self._tombstones("identities")
        for agent in incoming:
            if not isinstance(agent, dict):
                continue
            agent_id = str(agent.get("agent_id") or agent.get("agent") or "")
            if not agent_id or agent_id in tombstones:
                continue
            before = by_id.get(agent_id)
            self._store_body("identities", agent_id, agent, keep_history=before is not None)
            if before is None:
                if agent.get("revoked"):
                    continue
                if agent.get("full_access_key") and agent.get("uait_digest"):
                    # A caller supplied the full chain record: register it.
                    self._create_identity({**agent, "uait": agent}, "agent_id")
                continue
            if agent.get("revoked") and not before.get("revoked"):
                self._revoke_on_chain(
                    "identities",
                    agent_id,
                    before,
                    str(agent.get("revocation_reason") or ""),
                )

    def _save_credentials_document(
        self, incoming: List[dict], existing: List[dict]
    ) -> None:
        existing_cids = {}
        for item in existing:
            if not isinstance(item, dict):
                continue
            cid = item.get("cid")
            if not cid:
                try:
                    cid = _digest_b64(_vc_digest(item))
                except ValueError:
                    continue
            existing_cids[_digest_b64(cid)] = item
        tombstones = self._tombstones("credentials")
        for credential in incoming:
            if not isinstance(credential, dict):
                continue
            identifier = credential.get("id")
            if identifier and identifier in tombstones:
                continue
            try:
                cid = _digest_b64(credential.get("cid") or _vc_digest(credential))
            except ValueError:
                continue
            if cid in tombstones:
                continue
            before = existing_cids.get(cid)
            key = identifier or cid
            self._store_body("credentials", key, credential, keep_history=before is not None)
            status = credential.get("credentialStatus") or {}
            revoked = bool(status.get("revoked"))
            if before is None:
                try:
                    self._create_credential(
                        {**credential, "cid": cid, "vc": credential}, "id"
                    )
                except (ValueError, RuntimeError):
                    # Body-only credentials (e.g. external VCs or a read-only
                    # client) stay local; the credential itself is not faked
                    # on-chain.
                    continue
                continue
            if revoked and not (before.get("credentialStatus") or {}).get("revoked"):
                self._revoke_on_chain(
                    "credentials",
                    str(identifier or cid),
                    {**before, "cid": cid},
                    str(status.get("revocation_reason") or ""),
                )

    def _save_delegations_document(
        self, incoming: List[dict], existing: List[dict]
    ) -> None:
        by_jti = {
            str(item.get("jti") or item.get("id")): item
            for item in existing
            if isinstance(item, dict)
        }
        tombstones = self._tombstones("delegations")
        for delegation in incoming:
            if not isinstance(delegation, dict):
                continue
            jti = str(delegation.get("jti") or delegation.get("id") or "")
            if not jti or jti in tombstones:
                continue
            before = by_jti.get(jti)
            self._store_body("delegations", jti, delegation, keep_history=before is not None)
            if before is None:
                if delegation.get("revoked"):
                    continue
                if (
                    delegation.get("fck_pubkey")
                    and delegation.get("capabilities_hash")
                    and (delegation.get("agent") or delegation.get("issuer"))
                ):
                    self._create_delegation(delegation, "jti")
                continue
            if delegation.get("revoked") and not before.get("revoked"):
                self._revoke_on_chain(
                    "delegations",
                    jti,
                    before,
                    str(delegation.get("revocation_reason") or ""),
                )

    def _save_reputation_document(
        self, incoming: List[dict], scores: dict
    ) -> None:
        known = set(self._body_records("reputation"))
        for interaction in incoming:
            if not isinstance(interaction, dict):
                continue
            agent = interaction.get("agent_id") or interaction.get("agent")
            counterparty = interaction.get("counterparty_id") or interaction.get("counterparty")
            if not agent or not counterparty:
                continue
            interaction_id = str(
                interaction.get("interaction_id")
                or _interaction_id(agent, counterparty, interaction)
            )
            if interaction_id in known:
                continue
            known.add(interaction_id)
            self._store_body(
                "reputation",
                interaction_id,
                {**interaction, "interaction_id": interaction_id},
                keep_history=False,
            )
            try:
                self._create_interaction(
                    {**interaction, "interaction_id": interaction_id}, "interaction_id"
                )
            except (ValueError, RuntimeError):
                continue


    def _save_anchors_document(
        self, incoming: List[dict], existing: List[dict]
    ) -> None:
        existing_by_digest = {}
        for item in existing:
            if not isinstance(item, dict):
                continue
            digest = item.get("artifact_digest") or item.get("artifact_hash")
            if digest:
                try:
                    existing_by_digest[_digest_b64(digest)] = item
                except ValueError:
                    continue
        tombstones = self._tombstones("anchors")
        for anchor in incoming:
            if not isinstance(anchor, dict):
                continue
            digest = anchor.get("artifact_digest") or anchor.get("artifact_hash")
            if not digest:
                continue
            try:
                wire_digest = _digest_b64(digest)
            except ValueError:
                continue
            if wire_digest in tombstones:
                continue
            before = existing_by_digest.get(wire_digest)
            self._store_body(
                "anchors",
                wire_digest,
                {**anchor, "artifact_digest": wire_digest},
                keep_history=before is not None,
            )
            if before is None and anchor.get("artifact_type") and anchor.get("artifact_id"):
                try:
                    self._create_anchor({**anchor, "artifact_digest": wire_digest}, "artifact_digest")
                except (ValueError, RuntimeError):
                    continue

    def append_to_document(self, collection: str, record: dict) -> dict:
        if collection in BODY_COLLECTIONS or collection not in CHAIN_COLLECTIONS:
            return self._body_repository().append_to_document(collection, record)
        if collection == "credentials":
            if record.get("cid") or record.get("id"):
                self._store_body(
                    "credentials",
                    str(record.get("id") or _digest_b64(record.get("cid"))),
                    record,
                    keep_history=False,
                )
            if not record.get("cid") and not record.get("id"):
                raise ValueError("credential record requires id or cid")
            created = self._create_credential({**record, "vc": record}, "id")
            return {**record, "cid": created["cid"], "tx_hash": created.get("tx_hash")}
        if collection == "identities":
            created = self._create_identity({**record, "uait": record}, "agent_id")
            return {**record, "status": created.get("status"), "tx_hash": created.get("tx_hash")}
        if collection == "delegations":
            created = self._create_delegation(record, "jti")
            return {**record, "tx_hash": created.get("tx_hash")}
        if collection == "reputation":
            created = self._create_interaction(record, "interaction_id")
            return {**record, "interaction_id": created.get("interaction_id"), "tx_hash": created.get("tx_hash")}
        if collection == "anchors":
            created = self._create_anchor(record, "artifact_digest")
            return {**record, "tx_hash": created.get("tx_hash")}
        raise ValueError(f"Unknown chain collection {collection!r}")

    def recovery_documents(self, collection: str):
        if collection in BODY_COLLECTIONS or collection not in CHAIN_COLLECTIONS:
            reader = getattr(self._body_repository(), "recovery_documents", None)
            if callable(reader):
                return reader(collection)
            return []
        # Chain collections keep no local recovery copies: the contract state is
        # authoritative and signed bodies live in the sidecar store.
        return []

    def erase_from_document(self, collection: str, scrub):
        """Apply an erasure scrubber locally; chain state is never deleted.

        For chain collections the projection is scrubbed for its live removal
        counts and every removed id is tombstoned in the local body store. The
        contract keeps the immutable record, per the single-tenant demo rules.
        """
        if collection in BODY_COLLECTIONS or collection not in CHAIN_COLLECTIONS:
            return self._body_repository().erase_from_document(collection, scrub)
        document = self.load_document(collection)
        list_key = self._document_list_key(collection)
        before = {
            self._record_key(collection, item)
            for item in document.get(list_key, [])
            if isinstance(item, dict)
        }
        cleaned, counts = scrub(json.loads(json.dumps(document)))
        after = {
            self._record_key(collection, item)
            for item in cleaned.get(list_key, [])
            if isinstance(item, dict)
        }
        for key in before - after:
            if key:
                self._tombstone(collection, key)
        return counts

    @staticmethod
    def _record_key(collection: str, record: dict) -> Optional[str]:
        if collection == "identities":
            return record.get("agent_id") or record.get("agent")
        if collection == "credentials":
            return record.get("cid") or record.get("id")
        if collection == "delegations":
            return record.get("jti")
        if collection == "reputation":
            return record.get("interaction_id") or record.get("agent_id")
        if collection == "anchors":
            return record.get("artifact_digest") or record.get("artifact_hash")
        return None


# ---------------------------------------------------------------------------
# Canonical digests shared with the VC issuance path
# ---------------------------------------------------------------------------


def _vc_digest(credential: dict) -> bytes:
    """Return the labelled ``skjold-vc-digest/v1`` credential digest."""
    from attestix.signing.near_signer import vc_digest

    return vc_digest(credential)


def _capabilities_digest(capabilities: Iterable[str]) -> bytes:
    """Return the contract's capability-list digest."""
    from attestix.signing.near_signer import capabilities_digest

    return capabilities_digest(capabilities)


def _interaction_id(agent: str, counterparty: str, record: dict) -> str:
    """Synthesize a stable interaction idempotency key for the origin shape."""
    seed = json.dumps(
        {
            "agent": str(agent),
            "counterparty": str(counterparty),
            "timestamp": record.get("timestamp") or record.get("epoch") or "",
            "outcome": record.get("outcome") or "",
            "category": record.get("category") or "",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]
