//! The skjold registry contract: contract state and initialization.
//!
//! This revision ships the state layout, the record and event payload types and the
//! NEP-297 event enum. Identity, credential, delegation, reputation, TEE and artifact
//! anchor methods live in separate modules added by later steps.

use near_sdk::store::{IterableMap, LookupMap, LookupSet};
use near_sdk::{near, AccountId, Gas, PanicOnDefault, PublicKey};

// `event_json` emits a `Event_event_standard` constant in this module.
#[allow(non_upper_case_globals)]
pub mod events;
pub mod types;

use crate::types::{
    AgentRecord, AnchorRecord, CredentialAnchor, DelegationRecord, Interaction,
    ReputationAggregate, TeeBinding,
};
pub use crate::types::Digest32;

/// Gas reserved for a cross-contract callback.
pub const GAS_CALLBACK: Gas = Gas::from_tgas(10);

/// Registry state.
///
/// Every storage structure takes a distinct prefix; two collections sharing a prefix
/// would share storage keys.
#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    /// Registry operator (the Responsible Party). The VC issuer is a separate account
    /// that holds exactly one FullAccess key.
    operator: AccountId,
    /// Identity registry and the DID binding.
    agents: IterableMap<AccountId, AgentRecord>,
    /// Credential digest to anchor. One subject per digest.
    creds: IterableMap<Digest32, CredentialAnchor>,
    /// `jti` to delegation record.
    delegations: IterableMap<String, DelegationRecord>,
    /// Function-call key to `jti`, used for on-chain signer enforcement.
    delegation_by_key: LookupMap<PublicKey, String>,
    /// Bounded recent window; feeds only the category breakdown.
    interactions: IterableMap<AccountId, Vec<Interaction>>,
    /// Authoritative decayed reputation aggregates.
    reputation: IterableMap<AccountId, ReputationAggregate>,
    /// Dedupe keys: sha256(agent || counterparty || interaction_id).
    interaction_ids: LookupSet<Digest32>,
    /// Latest TEE binding; history lives in events.
    tee: IterableMap<AccountId, TeeBinding>,
    /// Attestation-nonce replay guard.
    tee_nonces: LookupSet<Digest32>,
    /// Generic artifact anchors.
    anchors: IterableMap<Digest32, AnchorRecord>,
}

#[near]
impl Contract {
    #[init]
    pub fn new(operator: AccountId) -> Self {
        Self {
            operator,
            agents: IterableMap::new(b"a".to_vec()),
            creds: IterableMap::new(b"c".to_vec()),
            delegations: IterableMap::new(b"d".to_vec()),
            delegation_by_key: LookupMap::new(b"fi".to_vec()),
            interactions: IterableMap::new(b"i".to_vec()),
            reputation: IterableMap::new(b"r".to_vec()),
            interaction_ids: LookupSet::new(b"ix".to_vec()),
            tee: IterableMap::new(b"t".to_vec()),
            tee_nonces: LookupSet::new(b"tn".to_vec()),
            anchors: IterableMap::new(b"n".to_vec()),
        }
    }
}
