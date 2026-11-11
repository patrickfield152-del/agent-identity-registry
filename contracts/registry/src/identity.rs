//! Agent identity sub-accounts and the did:near registry binding.
//!
//! Each agent is a sub-account of the registry with exactly ONE FullAccess key, so its
//! did:near document has exactly one `#owner` verification method. The on-chain
//! `AgentRecord` (not the key list) is the authoritative revocation cut-off.

use near_sdk::{
    env, near, require, AccountId, NearToken, Promise, PublicKey,
};

use crate::events::Event;
use crate::types::{AgentRecord, AgentRevoked, Digest32, IdentityData};
use crate::{Contract, ContractExt, GAS_CALLBACK, RECORD_OVERHEAD_BYTES};

#[near]
impl Contract {
    /// Create the agent sub-account, hand it its single FullAccess key and stage the
    /// identity record for the callback.
    ///
    /// The deposit covers the 10 mN stake that is forwarded to the sub-account plus the
    /// 7 mN CreateAccount charge the protocol deducts from this receipt's refund, plus
    /// the AgentRecord's own storage. The registry must not subsidise either.
    #[payable]
    pub fn create_agent(
        &mut self,
        prefix: String,
        full_access_key: PublicKey,
        uait_digest: Digest32,
        display_name: String,
        description: String,
        source_protocol: String,
        issuer_name: String,
        issuer_did: String,
        capabilities: Vec<String>,
        expires_at_ns: u64,
    ) -> Promise {
        require!(
            env::predecessor_account_id() == self.operator,
            "operator only"
        );
        require!(
            !prefix.is_empty()
                && prefix.len() <= 32
                && !prefix.starts_with('-')
                && !prefix.ends_with('-')
                && prefix
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_'),
            "prefix: 1-32 chars of [a-z0-9-_], no leading/trailing '-'"
        );
        require!(
            display_name.chars().count() <= 500,
            "display_name > 500 chars"
        );
        require!(capabilities.len() <= 32, "too many capabilities");

        let sub: AccountId = format!("{}.{}", prefix, env::current_account_id())
            .parse()
            .expect("valid sub-account id");
        require!(!self.agents.contains_key(&sub), "agent already registered");

        let record = AgentRecord {
            agent: sub.clone(),
            operator: self.operator.clone(),
            full_access_key: full_access_key.clone(),
            uait_digest,
            display_name,
            description,
            source_protocol,
            issuer_name,
            issuer_did,
            capabilities,
            created_at_ns: env::block_timestamp(),
            expires_at_ns,
            revoked: false,
            revoked_at_ns: None,
            revocation_reason: None,
        };

        let record_cost = self.storage_cost_for(
            Self::borsh_len(&record).saturating_add(RECORD_OVERHEAD_BYTES),
        );
        let required = NearToken::from_millinear(17).saturating_add(record_cost);
        require!(
            env::attached_deposit() >= required,
            "attach >= 17 mN + record storage"
        );
        self.refund_excess(required);

        Promise::new(sub)
            .create_account()
            .transfer(NearToken::from_millinear(10))
            .add_full_access_key(full_access_key)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_CALLBACK)
                    .on_agent_created(record),
            )
    }

    /// Callback after the create-account batch. A failed CreateAccount/AddKey does not
    /// roll this contract back, so only a `Successful` promise result may write state.
    /// Duplicate deliveries are idempotent.
    #[private]
    pub fn on_agent_created(&mut self, record: AgentRecord) -> bool {
        if env::promise_results_count() == 0 {
            return false;
        }
        if env::promise_result_checked(0, 1024).is_err() {
            return false;
        }
        if self.agents.contains_key(&record.agent) {
            return true;
        }
        let agent = record.agent.clone();
        let event = IdentityData {
            agent: agent.clone(),
            operator: record.operator.clone(),
            uait_digest: record.uait_digest,
            source_protocol: record.source_protocol.clone(),
            expires_at_ns: record.expires_at_ns,
        };
        let _ = self.agents.insert(agent, record);
        Event::IdentityCreated(vec![event]).emit();
        true
    }

    /// Revoke an agent. Revocation is monotonic: there is no un-revoke path.
    #[payable]
    pub fn revoke_identity(&mut self, agent: AccountId, reason: String) {
        require!(
            env::predecessor_account_id() == self.operator,
            "operator only"
        );
        require!(reason.len() <= 128, "reason > 128 B");
        self.require_storage_deposit(140);
        let mut rec = self
            .agents
            .get(&agent)
            .cloned()
            .expect("unknown agent");
        require!(!rec.revoked, "already revoked");
        let revoked_at_ns = env::block_timestamp();
        rec.revoked = true;
        rec.revoked_at_ns = Some(revoked_at_ns);
        rec.revocation_reason = Some(reason.clone());
        let _ = self.agents.insert(agent.clone(), rec);
        Event::IdentityRevoked(vec![AgentRevoked {
            agent,
            reason,
            revoked_at_ns,
        }])
        .emit();
    }

    pub fn get_identity(&self, agent: AccountId) -> Option<AgentRecord> {
        self.agents.get(&agent).cloned()
    }

    /// List identities with the ported filter subset. `risk_category` stays off-chain
    /// because it needs the compliance join. An explicit `status` (`active`, `revoked`,
    /// `expired`) is authoritative over `include_revoked`.
    pub fn list_identities(
        &self,
        source_protocol: Option<String>,
        status: Option<String>,
        name_contains: Option<String>,
        include_revoked: bool,
        limit: u32,
    ) -> Vec<AgentRecord> {
        let now = env::block_timestamp();
        let wanted_status = status.map(|s| s.to_lowercase());
        let wanted_name = name_contains.map(|s| s.to_lowercase());
        self.agents
            .iter()
            .map(|(_, rec)| rec)
            .filter(|rec| {
                let expired = rec.expires_at_ns != 0 && now >= rec.expires_at_ns;
                let lifecycle = if rec.revoked {
                    "revoked"
                } else if expired {
                    "expired"
                } else {
                    "active"
                };
                match wanted_status.as_deref() {
                    Some(wanted) => lifecycle == wanted,
                    None => include_revoked || !rec.revoked,
                }
            })
            .filter(|rec| {
                source_protocol
                    .as_ref()
                    .map_or(true, |protocol| &rec.source_protocol == protocol)
            })
            .filter(|rec| {
                wanted_name
                    .as_ref()
                    .map_or(true, |needle| rec.display_name.to_lowercase().contains(needle))
            })
            .take(limit as usize)
            .cloned()
            .collect()
    }
}
