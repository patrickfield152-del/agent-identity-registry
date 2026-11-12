#![cfg(target_os = "linux")]
//! W4-D zero-funds dry-run: local `near-sandbox` + the real Node demo.
//!
//! Starts a sandbox, creates the registry/operator/issuer accounts, deploys the
//! registry, then runs `node sdk/src/demo.js` against the sandbox RPC with the
//! generated keys. No testnet funds, no API keys. The demo transcript is printed
//! as `DEMO_TRANSCRIPT=<json>` for the coordinator to archive.

use std::path::PathBuf;

use near_api::NetworkConfig;
use near_sdk::serde_json::Value;

mod common;

use common::{create_account, deploy_registry, TestResult};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_demo_zero_funds() -> TestResult {
    let sandbox = near_sandbox::Sandbox::start_sandbox()
        .await
        .map_err(|error| format!("starting near-sandbox: {error}"))?;
    let network = NetworkConfig::from_rpc_url("sandbox", sandbox.rpc_addr.parse()?);

    let registry = create_account(&sandbox, "registry.sandbox", 500).await?;
    let operator = create_account(&sandbox, "operator.sandbox", 5000).await?;
    let issuer_id = format!("vc-issuer.{}", registry.id);
    let issuer = create_account(&sandbox, &issuer_id, 100).await?;
    let _contract = deploy_registry(&registry, &operator.id, &network).await?;

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo = manifest
        .parent()
        .and_then(|path| path.parent())
        .ok_or("cannot locate repo root from CARGO_MANIFEST_DIR")?;
    let output = std::process::Command::new("node")
        .arg(repo.join("sdk/src/demo.js"))
        .current_dir(repo)
        .env("SKJOLD_REGISTRY_ID", registry.id.to_string())
        .env("SKJOLD_OPERATOR_ACCOUNT", operator.id.to_string())
        .env("SKJOLD_OPERATOR_KEY", &operator.secret)
        .env("SKJOLD_VC_ISSUER_ACCOUNT", issuer.id.to_string())
        .env("SKJOLD_VC_ISSUER_KEY", &issuer.secret)
        .env("NEAR_RPC_URL", &sandbox.rpc_addr)
        .env("NEAR_NETWORK", "sandbox")
        .output()
        .map_err(|error| format!("running node demo: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        return Err(format!(
            "node demo exited {}: stderr={stderr} stdout={stdout}",
            output.status
        )
        .into());
    }
    let summary: Value = near_sdk::serde_json::from_str(&stdout)
        .map_err(|error| format!("demo stdout is not JSON ({error}): {stdout}"))?;

    let steps = summary["steps"]
        .as_array()
        .ok_or("demo summary has no steps array")?;
    assert_eq!(steps.len(), 9, "demo must report 9 steps: {summary}");
    assert_eq!(
        summary["identity"]["callback_landed"].as_bool(),
        Some(true),
        "create_agent callback must land: {summary}"
    );
    assert_eq!(
        summary["credential"]["valid_on_chain"].as_bool(),
        Some(true),
        "credential must be valid on-chain: {summary}"
    );
    assert_eq!(
        summary["delegation"]["revoked"].as_bool(),
        Some(true),
        "delegation must be revoked: {summary}"
    );
    assert_eq!(
        summary["refusal"]["rejected"].as_bool(),
        Some(true),
        "revoked FCK call must be refused by the registry: {summary}"
    );
    let credit: u128 = summary["identity"]["storage_credit_yocto"]
        .as_str()
        .ok_or("storage_credit_yocto missing")?
        .parse()?;
    assert!(
        credit < 50_000_000_000_000_000_000_000,
        "zero-deposit FCK anchor must debit the 50 mN credit, got {credit}"
    );
    let agent_did = summary["agent"]["did"]
        .as_str()
        .ok_or("agent.did missing")?;
    assert!(agent_did.starts_with("did:near:"), "agent did: {agent_did}");
    assert_eq!(
        summary["did_document"]["verification_method"].as_str(),
        Some(format!("{agent_did}#owner").as_str()),
        "did:near document must expose one #owner method: {summary}"
    );

    println!(
        "DEMO_TRANSCRIPT={}",
        near_sdk::serde_json::to_string(&summary)?
    );
    Ok(())
}
