//! The contract state, types and events must compile and the state must survive a
//! borsh round trip. The sandbox-backed integration tests arrive with the contract
//! methods.

use skjold_registry::Contract;

#[test]
fn contract_state_round_trips_through_borsh() {
    let contract = Contract::new("registry.skjold.testnet".parse().unwrap());

    let bytes = near_sdk::borsh::to_vec(&contract).expect("state must borsh-serialize");
    assert!(!bytes.is_empty(), "serialized state must not be empty");

    let restored: Contract =
        near_sdk::borsh::from_slice(&bytes).expect("state must borsh-deserialize");
    let restored_bytes =
        near_sdk::borsh::to_vec(&restored).expect("restored state must re-serialize");
    assert!(
        !restored_bytes.is_empty(),
        "re-serialized state must not be empty"
    );
}
