"""skjold blockchain helpers.

Modules:
    - merkle: Merkle tree construction for audit-batch anchoring
"""

# Re-export the Merkle helpers used for batch roots.
from .merkle import (
    build_merkle_tree,
    compute_merkle_root,
    hash_leaf,
    hash_pair,
)

# Re-export the submodule for namespace access.
from . import merkle

__all__ = [
    "build_merkle_tree",
    "compute_merkle_root",
    "hash_leaf",
    "hash_pair",
    "merkle",
]
