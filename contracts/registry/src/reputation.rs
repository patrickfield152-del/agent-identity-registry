//! Trust scoring as decayed aggregates.
//!
//! The score is `sum(w * decay) / sum(decay)` with exponential decay and a 30-day
//! half-life, exactly the origin's `_compute_score`, but kept as an aggregate that is
//! decayed forward instead of a truncated history. Parities therefore hold at any
//! interaction count; the bounded recent window only feeds the category breakdown.
//!
//! f64 is intentional: the score is advisory, never money. Balances stay u128.

use near_sdk::{env, near, require, AccountId};

use crate::events::Event;
use crate::types::{Interaction, InteractionData, ReputationAggregate, ReputationView};
use crate::{Contract, ContractExt, RECORD_OVERHEAD_BYTES};

/// Exponential-decay half-life in days.
pub const HALF_LIFE_DAYS: f64 = 30.0;

/// Outcome weights: success, partial, failure, timeout.
pub const OUTCOME_WEIGHTS: [(&str, f64); 4] = [
    ("success", 1.0),
    ("partial", 0.5),
    ("failure", 0.0),
    ("timeout", 0.2),
];

/// Maximum number of recent interactions kept for the category breakdown only.
pub const RECENT_WINDOW: usize = 64;

/// Decay rate per second: `ln(2) / (30 days)`.
pub fn decay_lambda() -> f64 {
    std::f64::consts::LN_2 / (HALF_LIFE_DAYS * 86400.0)
}

/// Decay the stored sums forward to `now_ns`.
pub fn decay_to(agg: &mut ReputationAggregate, now_ns: u64) {
    let dt = now_ns.saturating_sub(agg.last_update_ns) as f64 / 1e9;
    if dt > 0.0 {
        let factor = (-decay_lambda() * dt).exp();
        agg.sum_w_decay *= factor;
        agg.sum_decay *= factor;
        agg.last_update_ns = now_ns;
    }
}

/// `sum(w * decay) / sum(decay)`; zero when no decayed sample remains.
pub fn score(agg: &ReputationAggregate) -> f64 {
    if agg.sum_decay == 0.0 {
        0.0
    } else {
        agg.sum_w_decay / agg.sum_decay
    }
}

/// Cached weight of an outcome, or `None` for an unknown outcome string.
pub fn outcome_weight(outcome: &str) -> Option<f64> {
    OUTCOME_WEIGHTS
        .iter()
        .find(|(name, _)| *name == outcome)
        .map(|(_, weight)| *weight)
}

/// Append to the bounded window, dropping the oldest entry at the cap.
fn push_to_window(window: &mut Vec<Interaction>, interaction: Interaction) {
    if window.len() >= RECENT_WINDOW {
        window.remove(0);
    }
    window.push(interaction);
}

/// Per-category `(category, decayed score, count)` rows over the recent window.
fn category_breakdown(interactions: &[Interaction], now_ns: u64) -> Vec<(String, f64, u32)> {
    let lambda = decay_lambda();
    // Keyed accumulator: the window has at most RECENT_WINDOW entries, but a
    // per-entry linear position scan is O(window * categories); a keyed map is
    // O(window) with the same float order of operations per category.
    let mut rows: Vec<(String, f64, f64, u32)> = Vec::new();
    let mut index: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for interaction in interactions {
        let dt = now_ns.saturating_sub(interaction.recorded_at_ns) as f64 / 1e9;
        let decay = (-lambda * dt).exp();
        let entry = index.entry(interaction.category.as_str());
        match entry {
            std::collections::hash_map::Entry::Occupied(occupied) => {
                let row = &mut rows[*occupied.get()];
                row.1 += interaction.weight * decay;
                row.2 += decay;
                row.3 += 1;
            }
            std::collections::hash_map::Entry::Vacant(vacant) => {
                vacant.insert(rows.len());
                rows.push((
                    interaction.category.clone(),
                    interaction.weight * decay,
                    decay,
                    1,
                ));
            }
        }
    }
    let mut breakdown: Vec<(String, f64, u32)> = rows
        .into_iter()
        .map(|(category, weighted, total, count)| {
            (
                category,
                if total == 0.0 { 0.0 } else { weighted / total },
                count,
            )
        })
        .collect();
    breakdown.sort_by(|a, b| a.0.cmp(&b.0));
    breakdown
}

fn empty_aggregate(now_ns: u64) -> ReputationAggregate {
    ReputationAggregate {
        sum_w_decay: 0.0,
        sum_decay: 0.0,
        last_update_ns: now_ns,
        count: 0,
    }
}

#[near]
impl Contract {
    /// Record one interaction. The reporter is the counterparty (or the operator on its
    /// behalf); the dedupe key makes one interaction one vote, even across retries.
    #[payable]
    pub fn record_interaction(
        &mut self,
        agent: AccountId,
        counterparty: AccountId,
        interaction_id: String,
        outcome: String,
        category: String,
        details: String,
    ) {
        let caller = env::predecessor_account_id();
        require!(
            caller == counterparty || caller == self.operator,
            "counterparty or operator only"
        );
        require!(agent != counterparty, "self-interaction");
        require!(
            details.len() <= 256 && category.len() <= 64 && interaction_id.len() <= 64,
            "field too long"
        );
        let weight =
            outcome_weight(&outcome).expect("outcome must be success|partial|failure|timeout");
        require!(self.agents.contains_key(&agent), "unknown agent");

        let key = env::sha256_array(
            [
                agent.as_bytes(),
                counterparty.as_bytes(),
                interaction_id.as_bytes(),
            ]
            .concat(),
        );
        if self.interaction_ids.contains(&key) {
            self.refund_deposit();
            return;
        }

        let now = env::block_timestamp();
        let interaction = Interaction {
            counterparty: counterparty.clone(),
            interaction_id: interaction_id.clone(),
            outcome: outcome.clone(),
            category: category.clone(),
            details: details.clone(),
            weight,
            recorded_at_ns: now,
        };
        let mut growth = Self::borsh_len(&interaction)
            .saturating_add(key.len() as u64)
            .saturating_add(RECORD_OVERHEAD_BYTES.saturating_mul(2));
        if !self.reputation.contains_key(&agent) {
            growth = growth
                .saturating_add(Self::borsh_len(&empty_aggregate(now)))
                .saturating_add(RECORD_OVERHEAD_BYTES);
        }
        self.require_storage_deposit(growth);

        let mut aggregate = self
            .reputation
            .get(&agent)
            .cloned()
            .unwrap_or_else(|| empty_aggregate(now));
        decay_to(&mut aggregate, now);
        aggregate.sum_w_decay += weight;
        aggregate.sum_decay += 1.0;
        aggregate.count += 1;
        let _ = self.reputation.insert(agent.clone(), aggregate);

        let mut window = self.interactions.get(&agent).cloned().unwrap_or_default();
        push_to_window(&mut window, interaction);
        let _ = self.interactions.insert(agent.clone(), window);
        let _ = self.interaction_ids.insert(key);

        Event::InteractionRecorded(vec![InteractionData {
            agent,
            counterparty,
            interaction_id,
            outcome,
            category,
            details,
            weight,
            recorded_at_ns: now,
        }])
        .emit();
    }

    /// Current reputation. The aggregate is decayed on a clone, so views never mutate
    /// state; `last_interaction_ns` is 0 for an agent with no interactions.
    pub fn get_reputation(&self, agent: AccountId) -> ReputationView {
        let now = env::block_timestamp();
        let stored = self.reputation.get(&agent);
        let last_interaction_ns = stored
            .map(|aggregate| aggregate.last_update_ns)
            .unwrap_or(0);
        let mut aggregate = stored.cloned().unwrap_or_else(|| empty_aggregate(now));
        decay_to(&mut aggregate, now);
        let window = self
            .interactions
            .get(&agent)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        ReputationView {
            agent,
            trust_score: score(&aggregate),
            total_interactions: aggregate.count,
            category_breakdown: category_breakdown(window, now),
            last_interaction_ns: if aggregate.count == 0 {
                0
            } else {
                last_interaction_ns
            },
        }
    }

    /// Agents filterable by score, interaction count and a category tag, sorted by
    /// score descending. The category filter is answered from the recent window (the
    /// aggregate is all-category); pagination belongs in a later revision.
    pub fn query_reputation(
        &self,
        min_score: f64,
        max_score: f64,
        min_interactions: u32,
        category: Option<String>,
        limit: u32,
    ) -> Vec<ReputationView> {
        let now = env::block_timestamp();
        let lambda = decay_lambda();
        let mut candidates: Vec<(f64, AccountId, u32, u64, &[Interaction])> = Vec::new();
        for (agent, stored) in self.reputation.iter() {
            if stored.count < min_interactions {
                continue;
            }
            let window = self
                .interactions
                .get(agent)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            if let Some(wanted) = category.as_ref() {
                if !window.iter().any(|entry| &entry.category == wanted) {
                    continue;
                }
            }
            let dt = now.saturating_sub(stored.last_update_ns) as f64 / 1e9;
            let factor = if dt > 0.0 { (-lambda * dt).exp() } else { 1.0 };
            let sum_decay = stored.sum_decay * factor;
            let trust_score = if sum_decay == 0.0 {
                0.0
            } else {
                (stored.sum_w_decay * factor) / sum_decay
            };
            if trust_score < min_score || trust_score > max_score {
                continue;
            }
            candidates.push((
                trust_score,
                agent.clone(),
                stored.count,
                stored.last_update_ns,
                window,
            ));
        }
        let take = (limit as usize).min(candidates.len());
        if take < candidates.len() {
            candidates.select_nth_unstable_by(take, |a, b| {
                b.0.total_cmp(&a.0)
                    .then_with(|| a.1.as_str().cmp(b.1.as_str()))
            });
            candidates.truncate(take);
        }
        candidates.sort_by(|a, b| {
            b.0.total_cmp(&a.0)
                .then_with(|| a.1.as_str().cmp(b.1.as_str()))
        });
        candidates
            .into_iter()
            .map(
                |(trust_score, agent, total_interactions, last_interaction_ns, window)| {
                    ReputationView {
                        agent,
                        trust_score,
                        total_interactions,
                        category_breakdown: category_breakdown(window, now),
                        last_interaction_ns,
                    }
                },
            )
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;

    /// Deterministic pseudo-random history of 1000 interactions with increasing
    /// timestamps.
    fn seeded_history() -> Vec<(u64, f64)> {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let weights = [1.0, 0.5, 0.0, 0.2];
        let mut timestamp_ns = 1_700_000_000_000_000_000u64;
        let mut history = Vec::with_capacity(1000);
        for _ in 0..1000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let weight = weights[((state >> 33) % weights.len() as u64) as usize];
            let jitter_seconds = state % 300;
            timestamp_ns += 7 * 3600 * 1_000_000_000 + jitter_seconds * 1_000_000_000;
            history.push((timestamp_ns, weight));
        }
        history
    }

    fn full_history_score(history: &[(u64, f64)], now_ns: u64) -> f64 {
        let lambda = decay_lambda();
        let mut weighted = 0.0;
        let mut total = 0.0;
        for &(timestamp_ns, weight) in history {
            let dt = now_ns.saturating_sub(timestamp_ns) as f64 / 1e9;
            let decay = (-lambda * dt).exp();
            weighted += weight * decay;
            total += decay;
        }
        if total == 0.0 {
            0.0
        } else {
            weighted / total
        }
    }

    #[test]
    fn aggregate_recurrence_matches_full_history() {
        let history = seeded_history();
        let mut aggregate = empty_aggregate(history[0].0);
        for &(timestamp_ns, weight) in &history {
            decay_to(&mut aggregate, timestamp_ns);
            aggregate.sum_w_decay += weight;
            aggregate.sum_decay += 1.0;
            aggregate.count += 1;
        }
        let now_ns = history.last().expect("non-empty history").0;
        let error = (score(&aggregate) - full_history_score(&history, now_ns)).abs();
        assert!(
            error <= 1e-12,
            "aggregate parity error {error} exceeds 1e-12"
        );
        assert_eq!(aggregate.count, 1000);
    }

    #[test]
    fn recent_window_caps_at_64_and_drops_oldest() {
        let mut window = Vec::new();
        for index in 0..100u64 {
            push_to_window(
                &mut window,
                Interaction {
                    counterparty: "counterparty.near".parse().expect("valid account"),
                    interaction_id: format!("interaction-{index}"),
                    outcome: "success".to_string(),
                    category: "general".to_string(),
                    details: String::new(),
                    weight: 1.0,
                    recorded_at_ns: index,
                },
            );
        }
        assert_eq!(window.len(), RECENT_WINDOW);
        assert_eq!(
            window.first().expect("non-empty window").interaction_id,
            "interaction-36"
        );
        assert_eq!(
            window.last().expect("non-empty window").interaction_id,
            "interaction-99"
        );
    }

    #[test]
    fn outcome_weights_match_the_origin() {
        assert_eq!(outcome_weight("success"), Some(1.0));
        assert_eq!(outcome_weight("partial"), Some(0.5));
        assert_eq!(outcome_weight("failure"), Some(0.0));
        assert_eq!(outcome_weight("timeout"), Some(0.2));
        assert_eq!(outcome_weight("unknown"), None);
    }
    #[test]
    fn query_reputation_orders_limits_and_builds_breakdowns_for_selected_rows() {
        testing_env!(VMContextBuilder::new()
            .current_account_id(accounts(0))
            .predecessor_account_id(accounts(0))
            .build());
        let mut contract = Contract::new(accounts(0));
        for (agent, weighted, category) in [
            (accounts(1), 1.0, "task"),
            (accounts(2), 0.8, "task"),
            (accounts(3), 0.5, "other"),
        ] {
            contract.reputation.insert(
                agent.clone(),
                ReputationAggregate {
                    sum_w_decay: weighted,
                    sum_decay: 1.0,
                    last_update_ns: 0,
                    count: 1,
                },
            );
            contract.interactions.insert(
                agent,
                vec![Interaction {
                    counterparty: accounts(5),
                    interaction_id: format!("ix-{category}"),
                    outcome: "success".to_string(),
                    category: category.to_string(),
                    details: String::new(),
                    weight: 1.0,
                    recorded_at_ns: 0,
                }],
            );
        }

        let rows = contract.query_reputation(0.0, 1.0, 1, None, 2);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].agent, accounts(1));
        assert_eq!(rows[1].agent, accounts(2));
        assert!(rows[0].trust_score > rows[1].trust_score);
        assert!(!rows[0].category_breakdown.is_empty());
        assert!(!rows[1].category_breakdown.is_empty());

        assert!(contract.query_reputation(0.0, 1.0, 1, None, 0).is_empty());
        let filtered = contract.query_reputation(0.0, 1.0, 1, Some("task".to_string()), 10);
        assert_eq!(filtered.len(), 2);
    }
}
