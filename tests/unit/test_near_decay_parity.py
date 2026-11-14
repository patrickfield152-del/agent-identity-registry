"""Decay parity: origin ``ReputationService._compute_score`` vs the contract.

The Rust contract does not keep a truncated interaction history for the score.
It keeps a decayed aggregate ``(sum_w_decay, sum_decay, last_update_ns)``,
decays that aggregate forward to each new sample's ``block_timestamp``, adds the
new sample with decay 1, and decays a clone to "now" when a view reads it
(``src/reputation.rs``, doc step 6 / C27 / ST06a).

This module re-models both sides in pure Python and asserts they agree to
``1e-12`` on deterministic and seeded-random fixtures, including 1000-sample
histories (well above the 64-entry breakdown window). It also proves the 64
entry ``RECENT_WINDOW`` cannot influence the aggregate score. No network, no
sleeps, no wall clock: every timestamp is an explicit fixture value.
"""

import math
import random

import pytest

#: Contract constants (``src/reputation.rs``; CONSTANTS.md §4).
HALF_LIFE_DAYS = 30.0
DECAY_LAMBDA = math.log(2.0) / (HALF_LIFE_DAYS * 86400.0)
OUTCOME_WEIGHTS = {
    "success": 1.0,
    "partial": 0.5,
    "failure": 0.0,
    "timeout": 0.2,
}
RECENT_WINDOW = 64

SECOND_NS = 1_000_000_000
DAY_NS = 86_400 * SECOND_NS

#: 2026-01-01T00:00:00Z, a fixed epoch so runs are reproducible.
EPOCH_START_NS = 1_767_225_600 * SECOND_NS

#: Maximum absolute score error the two formulations may exhibit.
TOLERANCE = 1e-12


def origin_score(interactions, agent_id, now_ns):
    """Origin ``_compute_score``: full history, ages measured from ``now``.

    ``ReputationService._compute_score`` filters ``agent_id``, computes
    ``weight = exp(-lambda * age_seconds)`` per interaction and returns
    ``sum(outcome_weight * weight) / sum(weight)`` (0.0 when empty).
    """
    now_seconds = now_ns / 1e9
    weighted_sum = 0.0
    weight_total = 0.0
    for interaction in interactions:
        if interaction["agent_id"] != agent_id:
            continue
        age = max(now_seconds - interaction["epoch_ns"] / 1e9, 0.0)
        decay = math.exp(-DECAY_LAMBDA * age)
        weighted_sum += OUTCOME_WEIGHTS[interaction["outcome"]] * decay
        weight_total += decay
    if weight_total == 0.0:
        return 0.0
    return weighted_sum / weight_total


class DecayedAggregate:
    """Mirror of ``ReputationAggregate`` and ``decay_to``/``score``."""

    __slots__ = ("sum_w_decay", "sum_decay", "last_update_ns", "count")

    def __init__(self):
        self.sum_w_decay = 0.0
        self.sum_decay = 0.0
        self.last_update_ns = None
        self.count = 0

    def decay_to(self, now_ns):
        """``decay_to``: multiply both sums by ``exp(-lambda * dt)``."""
        if self.last_update_ns is None:
            self.last_update_ns = now_ns
            return
        if now_ns <= self.last_update_ns:
            # The contract saturates on u64 and only decays when dt > 0.
            return
        dt_seconds = (now_ns - self.last_update_ns) / 1e9
        factor = math.exp(-DECAY_LAMBDA * dt_seconds)
        self.sum_w_decay *= factor
        self.sum_decay *= factor
        self.last_update_ns = now_ns

    def add(self, outcome, now_ns):
        """``record_interaction``: decay forward, then add with decay 1."""
        self.decay_to(now_ns)
        self.sum_w_decay += OUTCOME_WEIGHTS[outcome]
        self.sum_decay += 1.0
        self.count += 1

    def score(self):
        if self.sum_decay == 0.0:
            return 0.0
        return self.sum_w_decay / self.sum_decay


def contract_score(interactions, agent_id, now_ns, *, track_window=False):
    """Replay ``record_interaction`` calls, then score as ``get_reputation``.

    When ``track_window`` is true, also maintain the 64-entry recent window the
    contract keeps for the category breakdown. The window is never consulted
    for the score; tracking it here only lets a test assert that.
    """
    aggregate = DecayedAggregate()
    window = []
    for interaction in interactions:
        if interaction["agent_id"] != agent_id:
            continue
        aggregate.add(interaction["outcome"], interaction["epoch_ns"])
        if track_window:
            if len(window) == RECENT_WINDOW:
                window.pop(0)
            window.append(interaction)
    # ``get_reputation`` decays a clone to the view's now before scoring.
    aggregate.decay_to(now_ns)
    return (aggregate.score(), window) if track_window else aggregate.score()


def interaction(agent_id, epoch_ns, outcome, index=0):
    return {
        "agent_id": agent_id,
        "epoch_ns": epoch_ns,
        "outcome": outcome,
        "interaction_id": f"i-{index}",
    }


def fixture_50():
    """50 interactions, mixed outcomes, one interleaved unrelated agent."""
    outcomes = ["success", "partial", "failure", "timeout"]
    records = []
    step = 3 * DAY_NS
    for index in range(50):
        records.append(
            interaction(
                "agent:50",
                EPOCH_START_NS + index * step,
                outcomes[index % len(outcomes)],
                index,
            )
        )
        if index % 5 == 0:
            records.append(
                interaction(
                    "agent:other",
                    EPOCH_START_NS + index * step + SECOND_NS,
                    "success",
                    index,
                )
            )
    now_ns = EPOCH_START_NS + 50 * step + 5 * DAY_NS
    return records, now_ns


def fixture_1000():
    """1000 interactions over ~25 days with a cycling outcome mix."""
    outcomes = ["success", "success", "partial", "failure", "timeout", "success"]
    step = 36 * 60 * SECOND_NS
    records = []
    for index in range(1000):
        records.append(
            interaction(
                "agent:1000",
                EPOCH_START_NS + index * step,
                outcomes[index % len(outcomes)],
                index,
            )
        )
        if index % 3 == 0:
            records.append(
                interaction(
                    "agent:noise",
                    EPOCH_START_NS + index * step + SECOND_NS,
                    "failure",
                    index,
                )
            )
    now_ns = EPOCH_START_NS + 1000 * step + DAY_NS
    return records, now_ns


def fixture_random():
    """Seeded random but monotonically increasing interaction epochs."""
    rng = random.Random(20261111)
    outcomes = list(OUTCOME_WEIGHTS)
    records = []
    epoch_ns = EPOCH_START_NS
    for index in range(500):
        epoch_ns += rng.randrange(0, 2 * DAY_NS)
        records.append(interaction("agent:random", epoch_ns, rng.choice(outcomes), index))
    now_ns = epoch_ns + rng.randrange(0, 5 * DAY_NS)
    return records, now_ns


FIXTURES = {
    "50-interactions": fixture_50,
    "1000-interactions": fixture_1000,
    "random-monotonic": fixture_random,
}


@pytest.mark.parametrize("fixture", list(FIXTURES), ids=list(FIXTURES))
def test_aggregate_matches_origin(fixture):
    records, now_ns = FIXTURES[fixture]()
    agent_id = records[0]["agent_id"]

    expected = origin_score(records, agent_id, now_ns)
    actual = contract_score(records, agent_id, now_ns)

    error = abs(expected - actual)
    assert error <= TOLERANCE, f"{fixture}: |origin - contract| = {error!r}"


@pytest.mark.parametrize("fixture", list(FIXTURES), ids=list(FIXTURES))
def test_window_preserves_aggregate(fixture):
    records, now_ns = FIXTURES[fixture]()
    agent_id = records[0]["agent_id"]

    without_window = contract_score(records, agent_id, now_ns)
    with_window, window = contract_score(
        records, agent_id, now_ns, track_window=True
    )

    assert without_window == with_window
    assert len(window) == min(
        sum(1 for record in records if record["agent_id"] == agent_id),
        RECENT_WINDOW,
    )


def test_window_rescore_diverges():
    """A score recomputed from the 64-entry window would NOT equal the aggregate.

    This is the regression the decayed aggregate fixes (P2-4): truncating the
    history to ``RECENT_WINDOW`` changes the weighted mean once the window is
    full. The aggregate must ignore the window entirely.
    """
    records = []
    step = 6 * 60 * SECOND_NS
    for index in range(1000):
        outcome = "success" if index < 920 else "failure"
        records.append(interaction("agent:window", EPOCH_START_NS + index * step, outcome, index))
    now_ns = EPOCH_START_NS + 1000 * step

    aggregate = contract_score(records, "agent:window", now_ns)
    window = records[-RECENT_WINDOW:]
    window_only = origin_score(window, "agent:window", now_ns)
    origin_full = origin_score(records, "agent:window", now_ns)

    assert abs(origin_full - aggregate) <= TOLERANCE
    assert window_only != pytest.approx(aggregate, abs=TOLERANCE)
    # The last 64 entries are all failures, so a window-derived score is 0.
    assert window_only == 0.0
    assert aggregate > 0.9


def test_empty_history_scores_zero():
    records, now_ns = fixture_50()
    assert origin_score(records, "agent:unknown", now_ns) == 0.0
    assert contract_score(records, "agent:unknown", now_ns) == 0.0


def test_all_failure_history_scores_zero():
    records = [
        interaction("agent:failure", EPOCH_START_NS + index * DAY_NS, "failure", index)
        for index in range(10)
    ]
    now_ns = EPOCH_START_NS + 10 * DAY_NS
    assert origin_score(records, "agent:failure", now_ns) == 0.0
    assert contract_score(records, "agent:failure", now_ns) == 0.0


def test_single_sample_scores_its_outcome_weight():
    for outcome, weight in OUTCOME_WEIGHTS.items():
        records = [interaction("agent:one", EPOCH_START_NS, outcome)]
        now_ns = EPOCH_START_NS + 30 * DAY_NS
        # One sample keeps weight 1 in both formulas regardless of age.
        assert origin_score(records, "agent:one", now_ns) == pytest.approx(weight)
        assert contract_score(records, "agent:one", now_ns) == pytest.approx(weight)


def test_half_life_halves_weight():
    """A 30-day gap halves the earlier sample's relative weight exactly."""
    records = [
        interaction("agent:half", EPOCH_START_NS, "success", 0),
        interaction("agent:half", EPOCH_START_NS + 30 * DAY_NS, "failure", 1),
    ]
    now_ns = EPOCH_START_NS + 30 * DAY_NS

    # Earlier success weight 0.5, later failure weight 1 (outcome 0.0):
    # score = 0.5 / (0.5 + 1.0).
    expected = 0.5 / 1.5
    assert origin_score(records, "agent:half", now_ns) == pytest.approx(expected)
    assert contract_score(records, "agent:half", now_ns) == pytest.approx(expected)
    assert abs(contract_score(records, "agent:half", now_ns) - expected) <= TOLERANCE
