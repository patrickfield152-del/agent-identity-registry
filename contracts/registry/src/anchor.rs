//! Generic artifact anchors.
//!
//! The runtime exposes no transaction hash to the contract, so the artifact digest is
//! the lookup key and the client captures the tx hash from the RPC response. Anchors are
//! idempotent on `(digest, type, id, subject)`; a conflicting re-anchor is an error.

use near_sdk::{env, near, require, AccountId, NearToken};

use crate::events::Event;
use crate::types::{AnchorData, AnchorRecord, ArtifactType, Digest32};
use crate::{Contract, ContractExt, RECORD_OVERHEAD_BYTES};

#[near]
impl Contract {
    /// Anchor an artifact. The operator may set any subject; an agent may anchor only
    /// for itself and must pass the FCK check (its own FullAccess key or a live
    /// delegation).
    #[payable]
    pub fn anchor_artifact(
        &mut self,
        artifact_digest: Digest32,
        artifact_type: ArtifactType,
        artifact_id: String,
        subject_account: Option<AccountId>,
    ) {
        let caller = env::predecessor_account_id();
        let subject_account = if caller == self.operator {
            subject_account
        } else {
            let rec = self.agents.get(&caller).cloned().expect("unknown caller");
            require!(!rec.revoked, "agent revoked");
            self.require_agent_signer(&rec);
            Some(caller.clone())
        };

        if let Some(existing) = self.anchors.get(&artifact_digest) {
            require!(
                existing.artifact_type == artifact_type
                    && existing.artifact_id == artifact_id
                    && existing.subject_account == subject_account,
                "artifact_digest already anchored with different data"
            );
            self.refund_deposit();
            return;
        }

        let block_height = env::block_height();
        let block_timestamp_ns = env::block_timestamp();
        let record = AnchorRecord {
            artifact_digest,
            artifact_type,
            artifact_id: artifact_id.clone(),
            subject_account: subject_account.clone(),
            anchored_by: caller.clone(),
            block_height,
            block_timestamp_ns,
        };
        let required = self.storage_cost_for(
            Self::borsh_len(&record).saturating_add(RECORD_OVERHEAD_BYTES),
        );
        if caller == self.operator {
            // The operator pays its own storage deposit.
            self.require_deposit(required);
        } else if env::attached_deposit().is_zero() {
            // A function-call access key cannot attach a deposit, so the agent's
            // prepaid credit covers the record. Fail closed when it is exhausted.
            let credit = self.storage_credit.get(&caller).copied().unwrap_or(0);
            let cost = required.as_yoctonear();
            require!(credit >= cost, "insufficient storage credit");
            let _ = self.storage_credit.insert(caller.clone(), credit - cost);
        } else {
            // FullAccess agent calls may pay directly; never double-charge credit.
            self.require_deposit(required);
        }

        let _ = self.anchors.insert(artifact_digest, record);
        Event::ArtifactAnchored(vec![AnchorData {
            artifact_digest,
            artifact_type,
            artifact_id,
            subject_account,
            anchored_by: caller,
            block_height,
            block_timestamp_ns,
        }])
        .emit();
    }

    pub fn get_anchor(&self, artifact_digest: Digest32) -> Option<AnchorRecord> {
        self.anchors.get(&artifact_digest).cloned()
    }

    /// Every anchor that names `agent`: either as its explicit subject or as the
    /// artifact id (the identity-anchor convention).
    pub fn get_anchor_status(&self, agent: AccountId) -> Vec<AnchorRecord> {
        self.anchors
            .iter()
            .filter(|(_, record)| {
                record.subject_account.as_ref() == Some(&agent)
                    || record.artifact_id.as_str() == agent.as_str()
            })
            .map(|(_, record)| record.clone())
            .collect()
    }

    /// Storage cost of an anchor of the given shape: a probe `AnchorRecord` with an
    /// `artifact_id_len`-byte id, sized with borsh, plus the per-record overhead.
    pub fn estimate_anchor_cost(
        &self,
        artifact_type: ArtifactType,
        artifact_id_len: u32,
        has_subject: bool,
    ) -> NearToken {
        let probe = AnchorRecord {
            artifact_digest: [0u8; 32],
            artifact_type,
            artifact_id: "x".repeat(artifact_id_len as usize),
            subject_account: if has_subject {
                Some(env::current_account_id())
            } else {
                None
            },
            anchored_by: env::current_account_id(),
            block_height: 0,
            block_timestamp_ns: 0,
        };
        self.storage_cost_for(Self::borsh_len(&probe).saturating_add(RECORD_OVERHEAD_BYTES))
    }

    /// Remaining prepaid anchor storage credit for an agent, in yoctoNEAR.
    pub fn get_storage_credit(&self, agent: AccountId) -> NearToken {
        NearToken::from_yoctonear(self.storage_credit.get(&agent).copied().unwrap_or(0))
    }
}
