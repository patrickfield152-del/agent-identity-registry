"""Shared fixtures for the skjold test suite."""

import sys
from pathlib import Path

import pytest

# Ensure the project root is on sys.path so imports work
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture(autouse=True)
def tmp_skjold(tmp_path, monkeypatch):
    """Redirect all skjold storage to a temp directory.

    This patches every *_FILE path in config.py so that no test
    reads or writes production JSON files.
    """
    from attestix import config

    file_attrs = [
        "IDENTITIES_FILE",
        "REPUTATION_FILE",
        "DELEGATIONS_FILE",
        "COMPLIANCE_FILE",
        "CREDENTIALS_FILE",
        "PROVENANCE_FILE",
        "ANCHORS_FILE",
        "AUDIT_FILE",
        "IDEMPOTENCY_FILE",
        "BLOCKCHAIN_CONFIG_FILE",
        "SIGNING_KEY_FILE",
        "LOG_FILE",
    ]

    for attr in file_attrs:
        original = getattr(config, attr)
        monkeypatch.setattr(config, attr, tmp_path / original.name)

    # The HTTP API fails closed when no SKJOLD_API_KEY is set. Tests exercise
    # the app without a key, so opt into no-auth mode explicitly. A dedicated
    # auth test can monkeypatch.delenv("SKJOLD_ALLOW_NO_AUTH") to assert the
    # fail-closed behaviour.
    monkeypatch.setenv("SKJOLD_ALLOW_NO_AUTH", "1")

    # Also patch PROJECT_DIR and DATA_DIR so any code using them resolves to tmp
    monkeypatch.setattr(config, "PROJECT_DIR", tmp_path)
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)

    # Clear the service cache so services re-initialize with patched paths
    from attestix.services.cache import clear_cache
    clear_cache()

    yield tmp_path

    # Cleanup: clear cache again after test
    clear_cache()


@pytest.fixture
def identity_service():
    """Fresh IdentityService instance using tmp storage."""
    from attestix.services.identity_service import IdentityService
    return IdentityService()


@pytest.fixture
def credential_service():
    """Fresh CredentialService instance using tmp storage."""
    from attestix.services.credential_service import CredentialService
    return CredentialService()


@pytest.fixture
def delegation_service():
    """Fresh DelegationService instance using tmp storage."""
    from attestix.services.delegation_service import DelegationService
    return DelegationService()


@pytest.fixture
def reputation_service():
    """Fresh ReputationService instance using tmp storage."""
    from attestix.services.reputation_service import ReputationService
    return ReputationService()


@pytest.fixture
def did_service():
    """Fresh DIDService instance using tmp storage."""
    from attestix.services.did_service import DIDService
    return DIDService()


@pytest.fixture
def sample_agent_id(identity_service):
    """Create a sample agent and return its ID."""
    result = identity_service.create_identity(
        display_name="Test Agent",
        source_protocol="mcp",
        capabilities=["read", "write"],
        description="A test agent",
    )
    return result["agent_id"]
