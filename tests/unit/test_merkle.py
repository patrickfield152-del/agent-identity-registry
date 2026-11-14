"""Behavior/scenario tests for the Merkle audit-log primitive.

Consolidates 12 unit tests into 7 higher-signal scenarios. Each scenario
asserts a consumer-visible bug class, not wiring or tautologies. Adds a
proactive perf budget and a reactive canonical-order oracle fuzz case.
"""
import hashlib
import random
import time

import pytest

from attestix.blockchain.merkle import (
    hash_leaf,
    hash_pair,
    build_merkle_tree,
    compute_merkle_root,
    _LEAF_PREFIX,
    _NODE_PREFIX,
)


class TestLeafBehavior:
    def test_canonical_distinct_deterministic(self):
        # sort_keys, distinctness and determinism in one behavior spec
        assert hash_leaf({"z": 1, "a": 2}) == hash_leaf({"a": 2, "z": 1})
        assert hash_leaf({"key": "value"}) == hash_leaf({"key": "value"})
        assert hash_leaf({"a": 1}) != hash_leaf({"a": 2})

    def test_domain_separation_prefixes(self):
        data = b"\x00" * 32
        assert (hashlib.sha256(_LEAF_PREFIX + data).digest()
                != hashlib.sha256(_NODE_PREFIX + data + data).digest())


class TestTreeBehavior:
    def test_hash_pair_position_and_determinism(self):
        a, b = hash_leaf({"a": 1}), hash_leaf({"b": 2})
        assert hash_pair(a, b) == hash_pair(a, b)
        assert hash_pair(a, b) != hash_pair(b, a)

    def test_single_two_three_leaves_and_empty(self):
        a, b, c = hash_leaf({"a": 1}), hash_leaf({"b": 2}), hash_leaf({"c": 3})
        root, levels = build_merkle_tree([a])
        assert root == a and len(levels) == 1
        root, levels = build_merkle_tree([a, b])
        assert root == hash_pair(a, b) and len(levels) == 2
        root, _ = build_merkle_tree([a, b, c])
        assert root == hash_pair(hash_pair(a, b), c)
        with pytest.raises(ValueError, match="empty"):
            build_merkle_tree([])


class TestRootBehavior:
    def test_hex_count_and_determinism(self):
        entries = [{"i": 1}, {"i": 2}, {"i": 3}]
        hex1, count = compute_merkle_root(entries)
        hex2, _ = compute_merkle_root(entries)
        assert len(hex1) == 64 and count == 3 and hex1 == hex2


def test_proactive_build_budget():
    # Proactive perf guard: a 1000-leaf tree must build well under 1 s.
    leaves = [hash_leaf({"i": i}) for i in range(1000)]
    t = time.perf_counter()
    build_merkle_tree(leaves)
    assert (time.perf_counter() - t) < 1.0


def test_reactive_canonical_order_oracle():
    # Reactive oracle: key order never changes a leaf hash (RFC 6962 profile).
    rng = random.Random(1794613236)
    for _ in range(200):
        d = {k: rng.randrange(1000) for k in "abcdef"}
        assert hash_leaf(d) == hash_leaf(dict(reversed(list(d.items()))))
