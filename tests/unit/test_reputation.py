"""Behavior, perf, and parity tests for services/reputation_service.py."""

import time

from attestix.config import load_reputation, save_reputation


def test_record_and_rank_outcomes(reputation_service):
    bad_out = reputation_service.record_interaction("skjold:bot1", "skjold:bot2", "invalid_outcome")
    assert "error" in bad_out

    res = reputation_service.record_interaction("a:1", "a:2", "success")
    assert res["recorded"] is True and res["updated_score"]["trust_score"] > 0
    reputation_service.record_interaction("a:3", "a:4", "failure")
    assert (
        reputation_service.get_reputation("a:1")["trust_score"]
        > reputation_service.get_reputation("a:3")["trust_score"]
    )


def test_get_reputation_and_breakdown(reputation_service):
    empty = reputation_service.get_reputation("skjold:unknown")
    assert empty["trust_score"] is None and empty["total_interactions"] == 0

    reputation_service.record_interaction("a:1", "a:2", "success", category="task")
    reputation_service.record_interaction("a:1", "a:3", "failure", category="delegation")
    got = reputation_service.get_reputation("a:1")
    assert got["category_breakdown"]["task"]["success"] == 1
    assert got["category_breakdown"]["delegation"]["failure"] == 1


def test_query_reputation_filters(reputation_service):
    reputation_service.record_interaction("a:good", "a:x", "success")
    reputation_service.record_interaction("a:good", "a:x", "success")
    reputation_service.record_interaction("a:bad", "a:x", "failure")
    by_score = [r["agent_id"] for r in reputation_service.query_reputation(min_score=0.5)]
    assert "a:good" in by_score and "a:bad" not in by_score
    by_count = reputation_service.query_reputation(min_interactions=2)
    assert [r["agent_id"] for r in by_count] == ["a:good"]


def test_proactive_query_budget_and_parity(reputation_service):
    now = int(time.time())
    data = {
        "interactions": [
            {
                "agent_id": f"a:{i % 25}",
                "counterparty_id": "cp:1",
                "outcome": ("success", "partial", "failure", "timeout")[i % 4],
                "category": "task",
                "epoch": now - (i % 100) * 60,
            }
            for i in range(1000)
        ],
        "scores": {},
    }
    save_reputation(data)
    t0 = time.perf_counter()
    rows = reputation_service.query_reputation(limit=50)
    assert (time.perf_counter() - t0) < 0.5
    assert len(rows) == 25
    loaded = load_reputation()["interactions"]
    for row in rows[:5]:
        expected = round(reputation_service._compute_score(loaded, row["agent_id"]), 4)
        assert abs(row["trust_score"] - expected) <= 1e-4
