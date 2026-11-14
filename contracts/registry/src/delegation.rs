//! Delegation records and on-chain function-call-key (FCK) enforcement.
//!
//! The FCK itself lives on the agent account and gives protocol-enforced scope; this
//! record is what the contract checks when an FCK calls an agent-only method, and what
//! `revoke_delegation` flips. A delegation is revoked per `jti`: revoking a parent does
//! not invalidate its children.

use near_sdk::{env, near, require, AccountId, PublicKey};

use crate::events::Event;
use crate::types::{AgentRecord, DelegData, DelegationRecord, DelegationRevoked, Digest32};
use crate::{Contract, ContractExt, RECORD_OVERHEAD_BYTES};

#[near]
impl Contract {
    /// Record a delegation grant. An identical replay is a no-op (`jti` is the
    /// idempotency key); a revoked `jti` is never resurrected.
    #[payable]
    pub fn record_delegation(
        &mut self,
        jti: String,
        agent: AccountId,
        audience: AccountId,
        capabilities_hash: Digest32,
        fck_pubkey: PublicKey,
        parent_jti: Option<String>,
        expires_at_ns: u64,
    ) {
        require!(
            env::predecessor_account_id() == self.operator,
            "operator only"
        );
        if let Some(existing) = self.delegations.get(&jti) {
            require!(!existing.revoked, "jti revoked");
            require!(
                existing.fck_pubkey == fck_pubkey
                    && existing.agent == agent
                    && existing.audience == audience
                    && existing.capabilities_hash == capabilities_hash
                    && existing.parent_jti == parent_jti
                    && existing.expires_at_ns == expires_at_ns,
                "jti exists with a different grant"
            );
            if let Some(bound) = self.delegation_by_key.get(&fck_pubkey) {
                require!(bound == &jti, "fck already bound to another jti");
            }
            self.refund_deposit();
            return;
        }
        if let Some(bound) = self.delegation_by_key.get(&fck_pubkey) {
            require!(bound == &jti, "fck already bound to another jti");
        }

        let record = DelegationRecord {
            agent: agent.clone(),
            audience: audience.clone(),
            capabilities_hash,
            fck_pubkey: fck_pubkey.clone(),
            parent_jti: parent_jti.clone(),
            expires_at_ns,
            recorded_at_ns: env::block_timestamp(),
            revoked: false,
            revoked_at_ns: None,
            revocation_reason: None,
        };
        let growth = Self::borsh_len(&record)
            .saturating_add(Self::borsh_len(&fck_pubkey))
            .saturating_add(jti.len() as u64 + 4)
            .saturating_add(RECORD_OVERHEAD_BYTES.saturating_mul(2));
        self.require_storage_deposit(growth);

        let _ = self.delegations.insert(jti.clone(), record);
        let _ = self
            .delegation_by_key
            .insert(fck_pubkey.clone(), jti.clone());
        Event::DelegationRecorded(vec![DelegData {
            jti,
            agent,
            audience,
            fck_pubkey,
            parent_jti,
            expires_at_ns,
        }])
        .emit();
    }

    /// Revoke a delegation grant. The registry flag is the cut-off; deleting the FCK is
    /// optional hygiene for the key holder.
    #[payable]
    pub fn revoke_delegation(&mut self, jti: String, reason: String) {
        require!(
            env::predecessor_account_id() == self.operator,
            "operator only"
        );
        require!(reason.len() <= 128, "reason > 128 B");
        self.require_storage_deposit(140);
        let mut record = self.delegations.get(&jti).cloned().expect("unknown jti");
        require!(!record.revoked, "already revoked");
        let revoked_at_ns = env::block_timestamp();
        record.revoked = true;
        record.revoked_at_ns = Some(revoked_at_ns);
        record.revocation_reason = Some(reason.clone());
        let _ = self.delegations.insert(jti.clone(), record);
        Event::DelegationRevoked(vec![DelegationRevoked {
            jti,
            reason,
            revoked_at_ns,
        }])
        .emit();
    }

    pub fn get_delegation(&self, jti: String) -> Option<DelegationRecord> {
        self.delegations.get(&jti).cloned()
    }

    pub fn list_delegations(&self, agent: Option<AccountId>, limit: u32) -> Vec<DelegationRecord> {
        self.delegations
            .iter()
            .filter(|(_, record)| agent.as_ref().is_none_or(|wanted| &record.agent == wanted))
            .take(limit as usize)
            .map(|(_, record)| record.clone())
            .collect()
    }
}

/// On-chain FCK enforcement: accept the agent's own FullAccess key, otherwise the
/// signer must be a live function-call key bound to a delegation for this same agent.
///
/// A NEP-366 meta-transaction puts the RELAYER in `signer_account_pk`, so agent-only
/// methods must never be meta-transacted.
impl Contract {
    pub(crate) fn require_agent_signer(&self, rec: &AgentRecord) {
        let pk = env::signer_account_pk();
        if pk == rec.full_access_key {
            return;
        }
        let jti = self
            .delegation_by_key
            .get(&pk)
            .expect("signer key is not delegated");
        let delegation = self.delegations.get(jti).expect("dangling fck index");
        require!(
            delegation.agent == rec.agent,
            "delegation belongs to another agent"
        );
        require!(!delegation.revoked, "delegation revoked");
        require!(
            delegation.expires_at_ns == 0 || env::block_timestamp() < delegation.expires_at_ns,
            "delegation expired"
        );
    }
}
