//! Record and event payload types for the skjold registry.
//!
//! Values are borsh-encoded in contract state and JSON-encoded when returned from
//! views. Digest fields are raw SHA-256 output, never a multiformats CID.

use near_sdk::{near, AccountId, PublicKey};

/// Raw SHA-256 output. Never a multiformats CID.
pub type Digest32 = [u8; 32];

/// A registered agent identity.
///
/// `operator` is the registry operator (the Responsible Party of the record). The W3C
/// `controller` of the did:near subject IS that account. `full_access_key` is the
/// single FullAccess key of the agent sub-account, so the did:near document has
/// exactly one `#owner` verification method.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct AgentRecord {
    /// Sub-account of the registry account: the did:near subject.
    pub agent: AccountId,
    /// Registry operator account; the W3C controller of the subject.
    pub operator: AccountId,
    /// The sub-account's only FullAccess key; must equal the DID document `#owner` key.
    pub full_access_key: PublicKey,
    /// sha256 of the canonical signed UAIT payload (UAIT minus its mutable fields).
    pub uait_digest: Digest32,
    pub display_name: String,
    pub description: String,
    /// UAIT `source_protocol`.
    pub source_protocol: String,
    /// UAIT `issuer.name`.
    pub issuer_name: String,
    /// UAIT `issuer.did`.
    pub issuer_did: String,
    pub capabilities: Vec<String>,
    pub created_at_ns: u64,
    /// 0 means no expiry.
    pub expires_at_ns: u64,
    pub revoked: bool,
    pub revoked_at_ns: Option<u64>,
    pub revocation_reason: Option<String>,
}

/// An anchored W3C credential digest.
///
/// The map key is the `skjold-vc-digest/v1` digest: Base64(SHA-256 of the canonical
/// credential minus `proof` and `credentialStatus`). Subjects need not be NEAR accounts.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct CredentialAnchor {
    /// DID or `attestix:<hex>` identifier of the credential subject.
    pub subject_did: String,
    /// Set when the subject is a registry agent.
    pub subject_account: Option<AccountId>,
    pub cred_type: String,
    /// 0 means no expiry.
    pub expires_at_ns: u64,
    pub anchored_at_ns: u64,
    /// Predecessor of the anchoring transaction.
    pub attester: AccountId,
    pub revoked: bool,
    pub revoked_at_ns: Option<u64>,
    pub revocation_reason: Option<String>,
}

/// A recorded delegation (UCAN `jti` plus the function-call key that enforces it).
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct DelegationRecord {
    pub agent: AccountId,
    pub audience: AccountId,
    /// sha256 of the canonical capability list.
    pub capabilities_hash: Digest32,
    /// The delegated function-call access key.
    pub fck_pubkey: PublicKey,
    /// UCAN proof chain link, kept off-chain.
    pub parent_jti: Option<String>,
    /// 0 means no expiry.
    pub expires_at_ns: u64,
    pub recorded_at_ns: u64,
    pub revoked: bool,
    pub revoked_at_ns: Option<u64>,
    pub revocation_reason: Option<String>,
}

/// One reputation interaction inside the bounded recent window.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct Interaction {
    /// The reporter, or the operator.
    pub counterparty: AccountId,
    /// Caller-supplied idempotency key.
    pub interaction_id: String,
    /// `success` | `partial` | `failure` | `timeout`.
    pub outcome: String,
    pub category: String,
    pub details: String,
    /// Cached outcome weight used by the decay math.
    pub weight: f64,
    /// Epoch of the interaction, in nanoseconds.
    pub recorded_at_ns: u64,
}

/// Authoritative decayed reputation aggregate.
///
/// Holds `sum(w * decay)` and `sum(decay)`, both decayed forward to `last_update_ns`,
/// so the score is exact and the recent window is only used for the category
/// breakdown.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct ReputationAggregate {
    pub sum_w_decay: f64,
    pub sum_decay: f64,
    pub last_update_ns: u64,
    pub count: u32,
}

/// Which enclave a TEE report proves.
#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureKind {
    /// A provider enclave signs the model execution.
    ProviderTee,
    /// A gateway enclave signature; it cannot carry a model claim.
    Gateway,
}

/// The latest TEE attestation bound to an agent. History lives in events, linked by
/// `previous_report_digest`.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct TeeBinding {
    pub report_digest: Digest32,
    /// A `Gateway` binding must not claim a model.
    pub signature_kind: SignatureKind,
    pub model: Option<String>,
    pub image_digest: Option<Digest32>,
    pub signing_address: String,
    pub signing_algo: String,
    pub attestation_nonce: Digest32,
    /// When the off-chain verifier accepted the quote.
    pub verified_at_ns: u64,
    pub bound_at_ns: u64,
    /// Append-only history pointer, also carried by the event.
    pub previous_report_digest: Option<Digest32>,
}

/// Kind of artifact anchored on-chain.
#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactType {
    Identity,
    Credential,
    Declaration,
    AuditBatch,
}

/// A generic artifact anchor. The digest is the lookup key because the runtime
/// exposes no transaction hash to the contract.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct AnchorRecord {
    pub artifact_digest: Digest32,
    pub artifact_type: ArtifactType,
    pub artifact_id: String,
    /// Explicit owner: the agent for identity anchors, the credential subject for
    /// credential anchors, `None` for operator-owned artifacts.
    pub subject_account: Option<AccountId>,
    /// Predecessor of the anchoring transaction.
    pub anchored_by: AccountId,
    pub block_height: u64,
    pub block_timestamp_ns: u64,
}

/// Payload of the `IdentityCreated` event.
#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct IdentityData {
    pub agent: AccountId,
    pub operator: AccountId,
    pub uait_digest: Digest32,
    pub source_protocol: String,
    pub expires_at_ns: u64,
}

/// Payload of the `IdentityRevoked` event.
#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct AgentRevoked {
    pub agent: AccountId,
    pub reason: String,
    pub revoked_at_ns: u64,
}

/// Payload of the `CredentialRevoked` event.
#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct CredentialRevoked {
    pub digest: Digest32,
    pub reason: String,
    pub revoked_at_ns: u64,
}

/// Payload of the `DelegationRevoked` event.
#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct DelegationRevoked {
    pub jti: String,
    pub reason: String,
    pub revoked_at_ns: u64,
}

/// Payload of the `CredentialAnchored` event.
#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct CredData {
    pub cid: Digest32,
    pub subject_did: String,
    pub cred_type: String,
    pub expires_at_ns: u64,
    pub attester: AccountId,
    pub anchored_at_ns: u64,
}

/// Payload of the `DelegationRecorded` event.
#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct DelegData {
    pub jti: String,
    pub agent: AccountId,
    pub audience: AccountId,
    pub fck_pubkey: PublicKey,
    pub parent_jti: Option<String>,
    pub expires_at_ns: u64,
}

/// Payload of the `InteractionRecorded` event.
#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct InteractionData {
    pub agent: AccountId,
    pub counterparty: AccountId,
    pub interaction_id: String,
    pub outcome: String,
    pub category: String,
    pub details: String,
    pub weight: f64,
    pub recorded_at_ns: u64,
}

/// Payload of the `TeeAttestationBound` event.
#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct TeeData {
    pub agent: AccountId,
    pub report_digest: Digest32,
    pub signature_kind: SignatureKind,
    pub model: Option<String>,
    pub image_digest: Option<Digest32>,
    pub previous_report_digest: Option<Digest32>,
}

/// Payload of the `ArtifactAnchored` event.
#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct AnchorData {
    pub artifact_digest: Digest32,
    pub artifact_type: ArtifactType,
    pub artifact_id: String,
    pub subject_account: Option<AccountId>,
    pub anchored_by: AccountId,
    pub block_height: u64,
    pub block_timestamp_ns: u64,
}

/// An agent's current reputation, decayed to the query timestamp.
///
/// `category_breakdown` holds `(category, score, count)` triples computed over the
/// bounded recent window; the authoritative score comes from the decayed aggregate.
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct ReputationView {
    pub agent: AccountId,
    pub trust_score: f64,
    pub total_interactions: u32,
    pub category_breakdown: Vec<(String, f64, u32)>,
    pub last_interaction_ns: u64,
}

/// One row of `query_reputation`: the same fields as [`ReputationView`], minus the
/// per-category detail that callers can fetch individually.
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct ReputationSummary {
    pub agent: AccountId,
    pub trust_score: f64,
    pub total_interactions: u32,
    pub category_breakdown: Vec<(String, f64, u32)>,
    pub last_interaction_ns: u64,
}
