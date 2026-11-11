//! Host-side unit tests for the skjold registry contract.
//!
//! These tests exercise the contract without a sandbox: `near_sdk::testing_env!`
//! installs a mocked chain context, so views run against real storage and the
//! authority guards panic before any state-changing promise is executed. Happy
//! paths that return `Promise` are deliberately not driven here; the sandbox
//! suite (`tests/test_basics.rs`, W3) covers the cross-contract flows.
//!
//! The contract crate's dev-dependencies enable near-sdk's `unit-testing`
//! feature, which is what makes `testing_env!` and the mocked storage available.

use std::str::FromStr;

use near_sdk::test_utils::{accounts, VMContextBuilder};
use near_sdk::{testing_env, AccountId, NearToken, PublicKey};
use skjold_registry::events::Event;
use skjold_registry::types::*;
use skjold_registry::Contract;

/// The registry operator; `accounts(0)` is `alice`.
fn operator() -> AccountId {
    accounts(0)
}

/// A funded account that is not the operator; `accounts(1)` is `bob`.
fn outsider() -> AccountId {
    accounts(1)
}

/// A deterministic 32-byte digest for view lookups.
fn digest(byte: u8) -> Digest32 {
    [byte; 32]
}

/// A valid ed25519 public key literal, used for record arguments only.
fn public_key() -> PublicKey {
    PublicKey::from_str("ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp")
        .expect("valid ed25519 public key")
}

/// Install a fresh mocked context and return an empty contract.
fn new_contract() -> Contract {
    testing_env!(VMContextBuilder::new()
        .current_account_id(operator())
        .predecessor_account_id(operator())
        .build());
    Contract::new(operator())
}

/// Install a context where `outsider()` is the predecessor and `deposit` is
/// attached. Methods are payable, so the deposit must be present for the
/// authority check to be the failing guard.
fn outsider_context(deposit: NearToken) {
    testing_env!(VMContextBuilder::new()
        .current_account_id(operator())
        .predecessor_account_id(outsider())
        .attached_deposit(deposit)
        .build());
}

#[test]
fn contract_state_round_trips_through_borsh() {
    let contract = new_contract();

    let bytes = near_sdk::borsh::to_vec(&contract).expect("state must borsh-serialize");
    assert!(!bytes.is_empty(), "serialized state must not be empty");

    let restored: Contract =
        near_sdk::borsh::from_slice(&bytes).expect("state must borsh-deserialize");
    let restored_bytes =
        near_sdk::borsh::to_vec(&restored).expect("restored state must re-serialize");

    assert_eq!(
        bytes, restored_bytes,
        "a borsh round trip must preserve the state byte-for-byte"
    );
}

#[test]
fn empty_state_views_return_none_or_empty() {
    let contract = new_contract();

    let agent = accounts(2);
    assert!(contract.get_identity(agent.clone()).is_none());
    assert!(contract.get_credential_anchor(digest(7)).is_none());
    assert!(!contract.is_credential_valid(digest(7)));
    assert!(contract.get_delegation("missing-jti".to_string()).is_none());
    assert!(contract.get_tee_attestation(agent).is_none());
    assert!(contract.get_anchor(digest(7)).is_none());

    assert!(contract
        .list_identities(None, None, None, false, 10)
        .is_empty());
    assert!(contract.list_credentials(None, 10).is_empty());
    assert!(contract.list_delegations(None, 10).is_empty());
}

#[test]
fn estimate_anchor_cost_is_positive_under_mocked_context() {
    let contract = new_contract();

    let cost = contract.estimate_anchor_cost(ArtifactType::Identity, 10, true);
    assert!(
        cost.as_yoctonear() > 0,
        "storage cost must be positive, got {cost:?}"
    );
}

#[test]
#[should_panic(expected = "operator only")]
fn create_agent_rejects_non_operator() {
    let mut contract = new_contract();
    outsider_context(NearToken::from_near(1));

    let _ = contract.create_agent(
        "agent1".to_string(),
        public_key(),
        digest(1),
        "Agent One".to_string(),
        "unit-test agent".to_string(),
        "mcp".to_string(),
        "VibeTensor".to_string(),
        "did:key:zIssuerPlaceholder".to_string(),
        vec!["read".to_string()],
        0,
    );
}

#[test]
#[should_panic(expected = "operator only")]
fn revoke_identity_rejects_non_operator() {
    let mut contract = new_contract();
    outsider_context(NearToken::from_near(1));

    contract.revoke_identity(accounts(2), "compromised".to_string());
}

#[test]
#[should_panic(expected = "issuer only")]
fn anchor_credential_rejects_non_operator() {
    let mut contract = new_contract();
    outsider_context(NearToken::from_near(1));

    contract.anchor_credential(
        "did:key:zSubjectPlaceholder".to_string(),
        None,
        digest(2),
        "VerifiableCredential".to_string(),
        0,
    );
}

#[test]
#[should_panic(expected = "operator only")]
fn record_delegation_rejects_non_operator() {
    let mut contract = new_contract();
    outsider_context(NearToken::from_near(1));

    contract.record_delegation(
        "jti-1".to_string(),
        accounts(2),
        accounts(3),
        digest(4),
        public_key(),
        None,
        0,
    );
}

#[test]
#[should_panic(expected = "operator only")]
fn bind_tee_attestation_rejects_non_operator() {
    let mut contract = new_contract();
    outsider_context(NearToken::from_near(1));

    contract.bind_tee_attestation(
        accounts(2),
        digest(5),
        SignatureKind::ProviderTee,
        Some("model-a".to_string()),
        None,
        "signing-address".to_string(),
        "ecdsa".to_string(),
        digest(6),
        0,
    );
}

#[test]
fn identity_created_event_matches_nep297_envelope() {
    let event = Event::IdentityCreated(vec![IdentityData {
        agent: accounts(2),
        operator: operator(),
        uait_digest: digest(3),
        source_protocol: "mcp".to_string(),
        expires_at_ns: 1_700_000_000_000_000_000,
    }]);

    assert_eq!(event.standard(), "skjold-registry");
    assert_eq!(event.version(), "1.0.0");
    assert_eq!(event.event(), "identity_created");

    let json = event.to_json();
    assert_eq!(json["standard"], "skjold-registry");
    assert_eq!(json["version"], "1.0.0");
    assert_eq!(json["event"], "identity_created");

    let envelope = json.as_object().expect("event json is an object");
    assert_eq!(
        envelope.len(),
        4,
        "NEP-297 envelope carries exactly standard/version/event/data"
    );

    let data = json["data"].as_array().expect("data is an array");
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["agent"], "charlie");
    assert_eq!(data[0]["operator"], "alice");
    assert_eq!(data[0]["source_protocol"], "mcp");
    assert_eq!(data[0]["expires_at_ns"], 1_700_000_000_000_000_000u64);

    let uait_digest = data[0]["uait_digest"]
        .as_array()
        .expect("digest is a 32-byte array in JSON");
    assert_eq!(uait_digest.len(), 32);
    assert!(uait_digest.iter().all(|byte| byte.as_u64() == Some(3)));
}

#[test]
fn identity_revoked_event_is_named_and_versioned() {
    let event = Event::IdentityRevoked(vec![AgentRevoked {
        agent: accounts(2),
        reason: "key compromised".to_string(),
        revoked_at_ns: 42,
    }]);

    assert_eq!(event.standard(), "skjold-registry");
    assert_eq!(event.version(), "1.0.0");
    assert_eq!(event.event(), "identity_revoked");

    let json = event.to_json();
    assert_eq!(json["event"], "identity_revoked");
    assert_eq!(json["version"], "1.0.0");
    assert_eq!(json["data"][0]["agent"], "charlie");
    assert_eq!(json["data"][0]["reason"], "key compromised");
    assert_eq!(json["data"][0]["revoked_at_ns"], 42u64);
}
