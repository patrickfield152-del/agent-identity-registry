//! TEE attestation binding.
//!
//! The quote is verified off-chain (NEAR AI Inference SDK, Python); this contract only
//! records the verified report digest. A `Gateway` signature proves the gateway enclave,
//! not model execution, so a gateway binding may not carry a model claim.

use near_sdk::{env, near, require, AccountId};

use crate::events::Event;
use crate::types::{Digest32, SignatureKind, TeeBinding, TeeData};
use crate::{Contract, ContractExt, RECORD_OVERHEAD_BYTES};

#[near]
impl Contract {
    /// Bind a verified TEE report to an agent. Bindings are append-only history via
    /// `previous_report_digest` (in the record and the event); the nonce set is the
    /// replay guard.
    #[payable]
    pub fn bind_tee_attestation(
        &mut self,
        agent: AccountId,
        report_digest: Digest32,
        signature_kind: SignatureKind,
        model: Option<String>,
        image_digest: Option<Digest32>,
        signing_address: String,
        signing_algo: String,
        attestation_nonce: Digest32,
        verified_at_ns: u64,
    ) {
        require!(
            env::predecessor_account_id() == self.operator,
            "operator only"
        );
        require!(self.agents.contains_key(&agent), "unknown agent");
        require!(
            matches!(signature_kind, SignatureKind::ProviderTee) || model.is_none(),
            "gateway evidence cannot claim a model"
        );
        require!(
            !self.tee_nonces.contains(&attestation_nonce),
            "nonce already bound"
        );

        let previous_report_digest = self.tee.get(&agent).map(|binding| binding.report_digest);
        let binding = TeeBinding {
            report_digest,
            signature_kind,
            model: model.clone(),
            image_digest,
            signing_address,
            signing_algo,
            attestation_nonce,
            verified_at_ns,
            bound_at_ns: env::block_timestamp(),
            previous_report_digest,
        };
        self.require_storage_deposit(
            Self::borsh_len(&binding)
                .saturating_add(attestation_nonce.len() as u64)
                .saturating_add(RECORD_OVERHEAD_BYTES.saturating_mul(2)),
        );

        let _ = self.tee.insert(agent.clone(), binding);
        let _ = self.tee_nonces.insert(attestation_nonce);
        Event::TeeAttestationBound(vec![TeeData {
            agent,
            report_digest,
            signature_kind,
            model,
            image_digest,
            previous_report_digest,
        }])
        .emit();
    }

    pub fn get_tee_attestation(&self, agent: AccountId) -> Option<TeeBinding> {
        self.tee.get(&agent).cloned()
    }
}
