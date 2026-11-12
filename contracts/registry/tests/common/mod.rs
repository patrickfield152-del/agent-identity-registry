#![allow(dead_code)]

//! Shared near-sandbox helpers for the Linux-gated registry integration tests.

use std::sync::Arc;

use near_api::{
    signer::generate_secret_key, AccountId, Contract, NearToken, NetworkConfig, SecretKey, Signer,
};
use near_sdk::serde_json::json;

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A sandbox account plus the in-memory signer for its fresh Ed25519 key.
pub struct SandboxAccount {
    pub id: AccountId,
    pub signer: Arc<Signer>,
    pub public_key: String,
    pub secret: String,
}

/// Create a funded sandbox account whose only FullAccess key is a fresh Ed25519 key.
pub async fn create_account(
    sandbox: &near_sandbox::Sandbox,
    account_id: &str,
    balance_near: u128,
) -> TestResult<SandboxAccount> {
    let id: AccountId = account_id.parse().map_err(|error| {
        std::io::Error::other(format!("invalid sandbox account id {account_id}: {error}"))
    })?;
    // near-sandbox 0.4.0 uses near-account-id 3; near-api 0.8.7 uses 2.x.
    let sandbox_id: near_sdk::AccountId = account_id.parse().map_err(|error| {
        std::io::Error::other(format!("invalid sandbox account id {account_id}: {error}"))
    })?;
    let secret: SecretKey = generate_secret_key()?;
    let public_key = secret.public_key().to_string();
    sandbox
        .create_account(sandbox_id)
        .initial_balance(NearToken::from_near(balance_near))
        .public_key(public_key.clone())
        .send()
        .await
        .map_err(|error| {
            std::io::Error::other(format!("creating sandbox account {account_id}: {error}"))
        })?;
    let signer = Signer::from_secret_key(secret.clone())?;
    Ok(SandboxAccount {
        id,
        signer,
        public_key,
        secret: secret.to_string(),
    })
}

/// Build `registry.wasm` for this crate and deploy it with the `new(operator)` init call.
pub async fn deploy_registry(
    registry: &SandboxAccount,
    operator: &AccountId,
    network: &NetworkConfig,
) -> TestResult<Contract> {
    let wasm_path = cargo_near_build::build_with_cli(Default::default())
        .map_err(|error| std::io::Error::other(format!("cargo-near-build failed: {error}")))?;
    let wasm = std::fs::read(&wasm_path).map_err(|error| {
        std::io::Error::other(format!("reading built wasm at {wasm_path}: {error}"))
    })?;
    Contract::deploy(registry.id.clone())
        .use_code(wasm)
        .with_init_call("new", json!({ "operator": operator }))?
        .max_gas()
        .with_signer(registry.signer.clone())
        .send_to(network)
        .await?
        .assert_success();
    Ok(Contract(registry.id.clone()))
}
