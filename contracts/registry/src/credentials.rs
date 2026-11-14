//! W3C credential anchoring.
//!
//! `cid` is the `skjold-vc-digest/v1` project profile: Base64(SHA-256 of the canonical
//! credential minus `proof` and `credentialStatus`). The contract stores the raw 32
//! bytes. Standard Base64 is only the wire/DID-string form.

use near_sdk::{env, near, require, AccountId};

use crate::events::Event;
use crate::types::{CredData, CredentialAnchor, CredentialRevoked, Digest32};
use crate::{Contract, ContractExt, RECORD_OVERHEAD_BYTES};

#[near]
impl Contract {
    /// Anchor one credential digest. `credentials` is keyed by `cid` alone: the cid
    /// hashes the credential body including `credentialSubject.id`, so a second subject
    /// is necessarily a different cid.
    #[payable]
    pub fn anchor_credential(
        &mut self,
        subject_did: String,
        subject_account: Option<AccountId>,
        cid: Digest32,
        cred_type: String,
        expires_at_ns: u64,
    ) {
        require!(
            env::predecessor_account_id() == self.operator,
            "issuer only"
        );
        if let Some(existing) = self.creds.get(&cid) {
            // An identical retry is a no-op success; any drift is a conflict.
            require!(
                existing.subject_did == subject_did
                    && existing.subject_account == subject_account
                    && existing.cred_type == cred_type
                    && existing.expires_at_ns == expires_at_ns,
                "cid already anchored with different data"
            );
            self.refund_deposit();
            return;
        }

        let attester = env::predecessor_account_id();
        let anchored_at_ns = env::block_timestamp();
        let anchor = CredentialAnchor {
            subject_did: subject_did.clone(),
            subject_account: subject_account.clone(),
            cred_type: cred_type.clone(),
            expires_at_ns,
            anchored_at_ns,
            attester: attester.clone(),
            revoked: false,
            revoked_at_ns: None,
            revocation_reason: None,
        };
        self.require_storage_deposit(
            Self::borsh_len(&anchor).saturating_add(RECORD_OVERHEAD_BYTES),
        );
        let _ = self.creds.insert(cid, anchor);
        Event::CredentialAnchored(vec![CredData {
            cid,
            subject_did,
            cred_type,
            expires_at_ns,
            attester,
            anchored_at_ns,
        }])
        .emit();
    }

    /// Revoke a credential anchor. Revocation is monotonic.
    #[payable]
    pub fn revoke_credential(&mut self, cid: Digest32, reason: String) {
        require!(
            env::predecessor_account_id() == self.operator,
            "issuer only"
        );
        require!(reason.len() <= 128, "reason > 128 B");
        self.require_storage_deposit(140);
        let mut anchor = self.creds.get(&cid).cloned().expect("unknown cid");
        require!(!anchor.revoked, "already revoked");
        let revoked_at_ns = env::block_timestamp();
        anchor.revoked = true;
        anchor.revoked_at_ns = Some(revoked_at_ns);
        anchor.revocation_reason = Some(reason.clone());
        let _ = self.creds.insert(cid, anchor);
        Event::CredentialRevoked(vec![CredentialRevoked {
            digest: cid,
            reason,
            revoked_at_ns,
        }])
        .emit();
    }

    /// A credential is valid while it is anchored, not revoked and not expired
    /// (`expires_at_ns == 0` means no expiry).
    pub fn is_credential_valid(&self, cid: Digest32) -> bool {
        self.creds.get(&cid).is_some_and(|anchor| {
            !anchor.revoked
                && (anchor.expires_at_ns == 0 || env::block_timestamp() < anchor.expires_at_ns)
        })
    }

    pub fn get_credential_anchor(&self, cid: Digest32) -> Option<CredentialAnchor> {
        self.creds.get(&cid).cloned()
    }

    /// Credential anchors filtered by subject DID. Subject account, validity and
    /// credential-type filters join against the off-chain VC bodies.
    pub fn list_credentials(
        &self,
        subject_did: Option<String>,
        limit: u32,
    ) -> Vec<(Digest32, CredentialAnchor)> {
        self.creds
            .iter()
            .filter(|(_, anchor)| {
                subject_did
                    .as_ref()
                    .is_none_or(|did| &anchor.subject_did == did)
            })
            .take(limit as usize)
            .map(|(cid, anchor)| (*cid, anchor.clone()))
            .collect()
    }
}
