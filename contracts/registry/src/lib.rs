//! The skjold registry contract: contract state, initialization and shared helpers.
//!
//! Identity, credential, delegation, reputation, TEE and artifact-anchor methods live
//! in their own modules. Every method that grows state is `#[payable]` and bills its
//! own storage growth, so the registry never subsidises a record from its balance.

use near_sdk::store::{IterableMap, LookupMap, LookupSet};
use near_sdk::{
    env, near, require, AccountId, Gas, NearToken, PanicOnDefault, Promise, PublicKey,
};

// `event_json` emits a `Event_event_standard` constant in this module.
#[allow(non_upper_case_globals)]
pub mod events;
pub mod types;

pub mod anchor;
pub mod credentials;
pub mod delegation;
pub mod identity;
pub mod reputation;
pub mod tee;

use crate::types::{
    AgentRecord, AnchorRecord, CredentialAnchor, DelegationRecord, Interaction,
    ReputationAggregate, TeeBinding,
};
pub use crate::types::Digest32;

/// Gas reserved for a cross-contract callback.
pub const GAS_CALLBACK: Gas = Gas::from_tgas(10);

/// Extra bytes billed per stored record: its storage key plus collection bookkeeping.
pub(crate) const RECORD_OVERHEAD_BYTES: u64 = 40;

/// Registry state.
///
/// Every storage structure takes a distinct prefix; two collections sharing a prefix
/// would share storage keys.
#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    /// Registry operator (the Responsible Party). The VC issuer is a separate account
    /// that holds exactly one FullAccess key.
    pub(crate) operator: AccountId,
    /// Identity registry and the DID binding.
    pub(crate) agents: IterableMap<AccountId, AgentRecord>,
    /// Credential digest to anchor. One subject per digest.
    pub(crate) creds: IterableMap<Digest32, CredentialAnchor>,
    /// `jti` to delegation record.
    pub(crate) delegations: IterableMap<String, DelegationRecord>,
    /// Function-call key to `jti`, used for on-chain signer enforcement.
    pub(crate) delegation_by_key: LookupMap<PublicKey, String>,
    /// Bounded recent window; feeds only the category breakdown.
    pub(crate) interactions: IterableMap<AccountId, Vec<Interaction>>,
    /// Authoritative decayed reputation aggregates.
    pub(crate) reputation: IterableMap<AccountId, ReputationAggregate>,
    /// Dedupe keys: sha256(agent || counterparty || interaction_id).
    pub(crate) interaction_ids: LookupSet<Digest32>,
    /// Latest TEE binding; history lives in events.
    pub(crate) tee: IterableMap<AccountId, TeeBinding>,
    /// Attestation-nonce replay guard.
    pub(crate) tee_nonces: LookupSet<Digest32>,
    /// Generic artifact anchors.
    pub(crate) anchors: IterableMap<Digest32, AnchorRecord>,
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

/// Shared storage-accounting helpers. Plain impl: none of these are contract methods.
impl Contract {
    /// Borsh-serialized length of a record, which is what the runtime actually stores.
    pub(crate) fn borsh_len<T: near_sdk::borsh::BorshSerialize>(v: &T) -> u64 {
        near_sdk::borsh::to_vec(v)
            .expect("contract records always borsh-serialize")
            .len() as u64
    }

    /// Cost of `bytes` of contract storage at the runtime's current byte price.
    pub(crate) fn storage_cost_for(&self, bytes: u64) -> NearToken {
        env::storage_byte_cost().saturating_mul(bytes as u128)
    }

    /// Require a deposit covering exactly `bytes` of contract storage, refunding any
    /// excess to the predecessor. Callers pass the total they will grow, including the
    /// [`RECORD_OVERHEAD_BYTES`] allowance for a new record.
    pub(crate) fn require_storage_deposit(&self, bytes: u64) {
        self.require_deposit(self.storage_cost_for(bytes));
    }

    /// Require at least `required` yoctoNEAR and refund the excess to the predecessor.
    pub(crate) fn require_deposit(&self, required: NearToken) {
        require!(
            env::attached_deposit() >= required,
            "attach at least the storage deposit"
        );
        self.refund_excess(required);
    }

    /// Refund whatever the predecessor attached above `required`.
    pub(crate) fn refund_excess(&self, required: NearToken) {
        let excess = env::attached_deposit().saturating_sub(required);
        if !excess.is_zero() {
            let _ = Promise::new(env::predecessor_account_id()).transfer(excess);
        }
    }

    /// Refund the whole attached deposit. Used on idempotent no-op paths so a retried
    /// call never traps funds in the registry.
    pub(crate) fn refund_deposit(&self) {
        let attached = env::attached_deposit();
        if !attached.is_zero() {
            let _ = Promise::new(env::predecessor_account_id()).transfer(attached);
        }
    }

    /// The raw 32-byte SHA-256 digest of `bytes`.
    pub(crate) fn digest32(bytes: &[u8]) -> Digest32 {
        env::sha256(bytes)
            .try_into()
            .expect("sha256 output is exactly 32 bytes")
    }
}
