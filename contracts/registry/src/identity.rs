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
use crate::{Contract, ContractExt, AGENT_STORAGE_CREDIT, GAS_CALLBACK, RECORD_OVERHEAD_BYTES};

#[near]
impl Contract {
    /// Create the agent sub-account, hand it its single FullAccess key and stage the
    /// identity record for the callback.
    ///
    /// The deposit covers the 10 mN stake that is forwarded to the sub-account plus the
    /// 7 mN CreateAccount charge the protocol deducts from this receipt's refund, plus
    /// the AgentRecord's own storage. The registry must not subsidise either.
    ///
    /// `full_access_key` is the key agent-callable methods compare against
    /// `env::signer_account_pk()` (see `require_agent_signer`). A NEP-366 meta-transaction
    /// puts the RELAYER's key in `signer_account_pk()`, so agent-only calls must never be
    /// relayed: a relayed call fails the signer check instead of being accepted.
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
        let required = NearToken::from_millinear(17)
            .saturating_add(record_cost)
            .saturating_add(self.agent_credit_cost(&sub));
        require!(
            env::attached_deposit() >= required,
            "attach >= 17 mN + record storage + 50 mN agent credit"
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
    /// The gate never panics: a missing, failed or oversized result returns `false`
    /// without writing state.
    #[private]
    pub fn on_agent_created(&mut self, record: AgentRecord) -> bool {
        if env::promise_results_count() == 0 {
            return false;
        }
        // RK17/RK25: `promise_result_checked` returns `Ok(bytes)` only for a successful
        // CreateAccount/AddKey batch; `Err` covers both a failed promise and an oversized
        // result, and the count check above keeps a missing result from aborting.
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
        let _ = self
            .storage_credit
            .insert(agent.clone(), AGENT_STORAGE_CREDIT.as_yoctonear());
        let _ = self.agents.insert(agent, record);
        Event::IdentityCreated(vec![event]).emit();
        true
    }

    /// Repair a sub-account that exists on-chain but whose `create_agent` callback never
    /// landed, so it has no `AgentRecord`.
    ///
    /// Operator-only. No cross-contract call is issued: the account already exists, so
    /// the record is written in this receipt and the call returns `true` synchronously.
    /// The 17 mN that `create_agent` bills (10 mN stake forwarded to the sub-account plus
    /// the 7 mN CreateAccount charge) is NOT due on this path — no account is created and
    /// no stake is transferred — so only the `AgentRecord`'s own storage is charged, and
    /// any excess is refunded. A repeat call once the record exists is an idempotent
    /// no-op that refunds the whole deposit and never overwrites (or resurrects) the
    /// stored record; `true` then only means "a record exists", not "the supplied fields
    /// match it" — read `get_identity` when that distinction matters.
    ///
    /// The contract cannot inspect another account's key list synchronously, so the
    /// operator MUST verify off-chain that `agent` exists and holds exactly the one
    /// FullAccess key `full_access_key` before calling; did:near `#owner` resolution
    /// reads the account's key list, not this record.
    ///
    /// Agent-callable methods compare `full_access_key` against
    /// `env::signer_account_pk()` (see `require_agent_signer`). A NEP-366 meta-transaction
    /// puts the RELAYER's key in `signer_account_pk()`, so a relayed agent-only call
    /// fails the signer check; never relay these methods.
    #[payable]
    pub fn register_existing_agent(
        &mut self,
        agent: AccountId,
        full_access_key: PublicKey,
        uait_digest: Digest32,
        display_name: String,
        description: String,
        source_protocol: String,
        issuer_name: String,
        issuer_did: String,
        capabilities: Vec<String>,
        expires_at_ns: u64,
    ) -> bool {
        require!(
            env::predecessor_account_id() == self.operator,
            "operator only"
        );

        // The repair path only ever registers a direct sub-account of this registry.
        let suffix = format!(".{}", env::current_account_id());
        require!(
            agent.as_str().ends_with(&suffix),
            "agent must be a sub-account of this registry"
        );
        let prefix = &agent.as_str()[..agent.as_str().len() - suffix.len()];
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

        // Idempotent repair: the stored record (revoked or not) is authoritative and is
        // never overwritten. Return the deposit so a retried call traps no funds.
        if self.agents.contains_key(&agent) {
            self.refund_deposit();
            return true;
        }

        let record = AgentRecord {
            agent: agent.clone(),
            operator: self.operator.clone(),
            full_access_key,
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
        let required = self
            .storage_cost_for(Self::borsh_len(&record).saturating_add(RECORD_OVERHEAD_BYTES))
            .saturating_add(self.agent_credit_cost(&agent));
        self.require_deposit(required);

        let event = IdentityData {
            agent: agent.clone(),
            operator: record.operator.clone(),
            uait_digest: record.uait_digest,
            source_protocol: record.source_protocol.clone(),
            expires_at_ns: record.expires_at_ns,
        };
        let _ = self
            .storage_credit
            .insert(agent.clone(), AGENT_STORAGE_CREDIT.as_yoctonear());
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
