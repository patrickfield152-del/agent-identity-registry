#![cfg(target_os = "linux")]
//! End-to-end sandbox flow for the skjold registry (W3-F2, `p0-security.md` step 13).
//!
//! The suite starts a local `near-sandbox` node, creates funded operator and
//! counterparty accounts, builds the contract with `cargo-near-build`, deploys and
//! initialises it, then drives the identity → credential → delegation → reputation →
//! revocation flow over RPC.
//!
//! `near-sandbox-rs` ships Linux x86_64 and macOS ARM64 binaries only, so the whole
//! file is `cfg(target_os = "linux")`; Windows/macOS check builds compile it to an
//! empty crate. `fast_forward` is deliberately not used: it advances height only
//! (`blocks: u64`), and a 30-day decay check would need ~2.59M blocks at 1 s/block.
//! Decay parity is covered offline by the Python parity suite; the views here simply
//! decay to the sandbox's current block timestamp.
//!
//! API pins verified against docs.rs for `near-sandbox 0.4.0`, `near-api 0.8.7` and
//! `cargo-near-build 0.11.5`.

use std::sync::Arc;
use std::time::Duration;

use near_api::types::transaction::actions::{AccessKeyPermission, FunctionCallPermission};
use near_api::types::Data;
use near_api::{
    signer::generate_secret_key, Account, AccountId, Contract, NearToken, NetworkConfig, SecretKey,
    Signer,
};
use near_sdk::serde::Deserialize;
use near_sdk::serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const NETWORK_NAME: &str = "sandbox";
const IDENTITY_POLL_ATTEMPTS: usize = 40;
const IDENTITY_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// A sandbox account plus the in-memory signer for its fresh Ed25519 key.
struct SandboxAccount {
    id: AccountId,
    signer: Arc<Signer>,
    public_key: String,
}

/// The subset of `AgentRecord` this suite asserts on. Unknown JSON fields are
/// ignored; `Digest32` and `PublicKey` are JSON arrays/strings on the wire.
#[derive(Clone, Debug, Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct AgentRecordView {
    agent: String,
    operator: String,
    full_access_key: String,
    uait_digest: Vec<u8>,
    display_name: String,
    created_at_ns: u64,
    revoked: bool,
    revoked_at_ns: Option<u64>,
}

/// The subset of `DelegationRecord` this suite asserts on.
#[derive(Clone, Debug, Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct DelegationRecordView {
    agent: String,
    fck_pubkey: String,
    revoked: bool,
    revoked_at_ns: Option<u64>,
}

/// The subset of `ReputationView` this suite asserts on.
#[derive(Clone, Debug, Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct ReputationView {
    agent: String,
    trust_score: f64,
    total_interactions: u32,
    last_interaction_ns: u64,
}

/// Deposit for `create_agent`: 17 mN (10 mN stake + 7 mN CreateAccount), the
/// AgentRecord storage, and the 50 mN prepaid storage credit; excess is refunded.
fn create_agent_deposit() -> NearToken {
    NearToken::from_millinear(100)
}

/// Storage deposit for a new record (credential anchor, delegation, interaction,
/// artifact anchor); the contract refunds the excess.
fn growth_deposit() -> NearToken {
    NearToken::from_millinear(5)
}

/// Deposit for a revoke path (`require_storage_deposit(140)`).
fn revoke_deposit() -> NearToken {
    NearToken::from_millinear(2)
}

/// Create a funded sandbox account whose only FullAccess key is a fresh Ed25519 key.
async fn create_account(
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
    let signer = Signer::from_secret_key(secret)?;
    Ok(SandboxAccount {
        id,
        signer,
        public_key,
    })
}

/// Build `registry.wasm` for this crate and deploy it with the `new(operator)` init call.
async fn deploy_registry(
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

/// Send a state-changing contract call and require the transaction to succeed.
async fn call_ok(
    contract: &Contract,
    network: &NetworkConfig,
    signer_id: &AccountId,
    signer: &Arc<Signer>,
    method: &str,
    args: Value,
    deposit: NearToken,
) -> TestResult<()> {
    contract
        .call_function(method, args)
        .transaction()
        .max_gas()
        .deposit(deposit)
        .with_signer(signer_id.clone(), signer.clone())
        .send_to(network)
        .await
        .map_err(|error| std::io::Error::other(format!("{method}: send failed: {error}")))?
        .assert_success();
    Ok(())
}

/// Send a state-changing call that the contract is expected to reject.
async fn call_fails(
    contract: &Contract,
    network: &NetworkConfig,
    signer_id: &AccountId,
    signer: &Arc<Signer>,
    method: &str,
    args: Value,
    deposit: NearToken,
) -> TestResult<bool> {
    let outcome = contract
        .call_function(method, args)
        .transaction()
        .max_gas()
        .deposit(deposit)
        .with_signer(signer_id.clone(), signer.clone())
        .send_to(network)
        .await
        .map_err(|error| std::io::Error::other(format!("{method}: send failed: {error}")))?;
    Ok(outcome.is_failure())
}

/// Read-only contract call deserialized into `T`.
async fn view<T: near_sdk::serde::de::DeserializeOwned + Send + Sync + 'static>(
    contract: &Contract,
    network: &NetworkConfig,
    method: &str,
    args: Value,
) -> TestResult<T> {
    let data: Data<T> = contract
        .call_function(method, args)
        .read_only()
        .fetch_from(network)
        .await
        .map_err(|error| std::io::Error::other(format!("{method}: view failed: {error}")))?;
    Ok(data.data)
}

/// Poll `get_identity` until the `#[private]` create-agent callback lands.
///
/// `create_agent` returns a promise; the record is written by `on_agent_created`
/// one receipt later, so a single view can legitimately observe `None`.
async fn wait_for_identity(
    contract: &Contract,
    network: &NetworkConfig,
    agent: &AccountId,
) -> TestResult<AgentRecordView> {
    for _ in 0..IDENTITY_POLL_ATTEMPTS {
        let found: Option<AgentRecordView> =
            view(contract, network, "get_identity", json!({ "agent": agent })).await?;
        if let Some(record) = found {
            return Ok(record);
        }
        tokio::time::sleep(IDENTITY_POLL_INTERVAL).await;
    }
    Err(std::io::Error::other(format!(
        "get_identity({agent}) stayed None after {IDENTITY_POLL_ATTEMPTS} polls; \
         the create_agent callback did not land"
    ))
    .into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registry_flow_end_to_end() -> TestResult {
    let sandbox = near_sandbox::Sandbox::start_sandbox()
        .await
        .map_err(|error| std::io::Error::other(format!("starting near-sandbox: {error}")))?;
    let network = NetworkConfig::from_rpc_url(NETWORK_NAME, sandbox.rpc_addr.parse()?);

    // --- funded accounts ---------------------------------------------------
    let registry = create_account(&sandbox, "registry.sandbox", 100).await?;
    let operator = create_account(&sandbox, "operator.sandbox", 5000).await?;
    let counterparty = create_account(&sandbox, "counterparty.sandbox", 25).await?;

    // --- build, deploy and initialise -------------------------------------
    let contract = deploy_registry(&registry, &operator.id, &network).await?;

    // --- create_agent + callback -----------------------------------------
    let agent_secret: SecretKey = generate_secret_key()?;
    let agent_public = agent_secret.public_key().to_string();
    let agent_signer = Signer::from_secret_key(agent_secret)?;
    let agent_id: AccountId = format!("agent1.{}", registry.id).parse()?;
    let uait_digest = vec![7u8; 32];

    call_ok(
        &contract,
        &network,
        &operator.id,
        &operator.signer,
        "create_agent",
        json!({
            "prefix": "agent1",
            "full_access_key": &agent_public,
            "uait_digest": &uait_digest,
            "display_name": "Sandbox Agent",
            "description": "sandbox flow agent",
            "source_protocol": "sandbox",
            "issuer_name": "operator",
            "issuer_did": format!("did:near:{}", operator.id),
            "capabilities": ["anchor_artifact"],
            "expires_at_ns": 0u64,
        }),
        create_agent_deposit(),
    )
    .await?;

    let record = wait_for_identity(&contract, &network, &agent_id).await?;
    assert_eq!(record.agent, agent_id.to_string(), "agent record account");
    assert_eq!(
        record.operator,
        operator.id.to_string(),
        "operator is the W3C controller"
    );
    assert_eq!(
        record.full_access_key, agent_public,
        "record carries the single FullAccess key"
    );
    assert_eq!(record.uait_digest, uait_digest, "uait digest round trip");
    assert_eq!(record.display_name, "Sandbox Agent");
    assert!(!record.revoked, "freshly created agent is not revoked");

    // The sub-account is created with 10 mN; top it up so its FCK can pay the
    // anchor call's storage deposit and gas from the agent account.
    near_api::Tokens::account(operator.id.clone())
        .send_to(agent_id.clone())
        .near(NearToken::from_near(1000))
        .with_signer(operator.signer.clone())
        .send_to(&network)
        .await
        .map_err(|error| std::io::Error::other(format!("funding agent sub-account: {error}")))?
        .assert_success();

    // --- anchor_credential (operator/issuer) ------------------------------
    let cid = vec![9u8; 32];
    call_ok(
        &contract,
        &network,
        &operator.id,
        &operator.signer,
        "anchor_credential",
        json!({
            "subject_did": format!("did:near:{}", agent_id),
            "subject_account": &agent_id,
            "cid": &cid,
            "cred_type": "KYA",
            "expires_at_ns": 0u64,
        }),
        growth_deposit(),
    )
    .await?;
    let valid: bool = view(
        &contract,
        &network,
        "is_credential_valid",
        json!({ "cid": &cid }),
    )
    .await?;
    assert!(valid, "anchored credential is valid");

    // --- delegation + function-call key -----------------------------------
    let fck_secret: SecretKey = generate_secret_key()?;
    let fck_public = fck_secret.public_key();
    let fck_signer = Signer::from_secret_key(fck_secret)?;
    let jti = "jti-sandbox-1".to_string();

    call_ok(
        &contract,
        &network,
        &operator.id,
        &operator.signer,
        "record_delegation",
        json!({
            "jti": &jti,
            "agent": &agent_id,
            "audience": &operator.id,
            "capabilities_hash": vec![3u8; 32],
            "fck_pubkey": fck_public.to_string(),
            "parent_jti": Value::Null,
            "expires_at_ns": 0u64,
        }),
        growth_deposit(),
    )
    .await?;

    // Install the delegated function-call key on the agent account.
    let permission = AccessKeyPermission::FunctionCall(FunctionCallPermission {
        allowance: Some(NearToken::from_near(1000)),
        receiver_id: registry.id.to_string(),
        method_names: vec!["anchor_artifact".to_string()],
    });
    Account(agent_id.clone())
        .add_key(permission, fck_public.clone())
        .with_signer(agent_signer.clone())
        .send_to(&network)
        .await
        .map_err(|error| {
            std::io::Error::other(format!("adding function-call key: {error}"))
        })?
        .assert_success();

    // A live FCK anchors with ZERO attached deposit; the record cost is debited
    // from the agent's prepaid 50 mN storage credit (FCKs cannot attach deposits).
    let credit_before: String = view(
        &contract,
        &network,
        "get_storage_credit",
        json!({ "agent": &agent_id }),
    )
    .await?;
    assert_eq!(
        credit_before.parse::<u128>()?,
        50_000_000_000_000_000_000_000,
        "create_agent funds exactly 50 mN of credit"
    );

    call_ok(
        &contract,
        &network,
        &agent_id,
        &fck_signer,
        "anchor_artifact",
        json!({
            "artifact_digest": vec![1u8; 32],
            "artifact_type": "Identity",
            "artifact_id": "agent1",
            "subject_account": &agent_id,
        }),
        NearToken::from_yoctonear(0),
    )
    .await?;
    let credit_after_anchor: u128 = view::<String>(
        &contract,
        &network,
        "get_storage_credit",
        json!({ "agent": &agent_id }),
    )
    .await?
    .parse()?;
    assert!(
        credit_after_anchor < 50_000_000_000_000_000_000_000 && credit_after_anchor > 0,
        "zero-deposit FCK anchor debits credit, leaving {credit_after_anchor}"
    );

    // Idempotent replay: same digest/id, no second credit charge.
    call_ok(
        &contract,
        &network,
        &agent_id,
        &fck_signer,
        "anchor_artifact",
        json!({
            "artifact_digest": vec![1u8; 32],
            "artifact_type": "Identity",
            "artifact_id": "agent1",
            "subject_account": &agent_id,
        }),
        NearToken::from_yoctonear(0),
    )
    .await?;
    let credit_after_replay: u128 = view::<String>(
        &contract,
        &network,
        "get_storage_credit",
        json!({ "agent": &agent_id }),
    )
    .await?
    .parse()?;
    assert_eq!(
        credit_after_replay, credit_after_anchor,
        "idempotent replay must not double-charge credit"
    );

    // FullAccess agent call with a deposit: credit untouched, excess refunded.
    call_ok(
        &contract,
        &network,
        &agent_id,
        &agent_signer,
        "anchor_artifact",
        json!({
            "artifact_digest": vec![5u8; 32],
            "artifact_type": "Declaration",
            "artifact_id": "agent-fa-paid",
            "subject_account": &agent_id,
        }),
        growth_deposit(),
    )
    .await?;
    let credit_after_fa: u128 = view::<String>(
        &contract,
        &network,
        "get_storage_credit",
        json!({ "agent": &agent_id }),
    )
    .await?
    .parse()?;
    assert_eq!(
        credit_after_fa, credit_after_anchor,
        "a deposited FullAccess call must not touch credit"
    );


    // --- record_interaction + get_reputation ------------------------------
    call_ok(
        &contract,
        &network,
        &counterparty.id,
        &counterparty.signer,
        "record_interaction",
        json!({
            "agent": &agent_id,
            "counterparty": &counterparty.id,
            "interaction_id": "interaction-1",
            "outcome": "success",
            "category": "task",
            "details": "sandbox flow",
        }),
        growth_deposit(),
    )
    .await?;

    let reputation: ReputationView = view(
        &contract,
        &network,
        "get_reputation",
        json!({ "agent": &agent_id }),
    )
    .await?;
    assert_eq!(reputation.agent, agent_id.to_string());
    assert_eq!(reputation.total_interactions, 1, "one deduped interaction");
    assert!(
        reputation.trust_score > 0.0,
        "a success interaction yields trust_score > 0, got {}",
        reputation.trust_score
    );
    assert!(
        reputation.last_interaction_ns > 0,
        "reputation view timestamp is populated"
    );

    // --- revoke_delegation: next FCK call is refused ----------------------
    call_ok(
        &contract,
        &network,
        &operator.id,
        &operator.signer,
        "revoke_delegation",
        json!({ "jti": &jti, "reason": "sandbox revoke" }),
        revoke_deposit(),
    )
    .await?;

    let delegation: DelegationRecordView = view(
        &contract,
        &network,
        "get_delegation",
        json!({ "jti": &jti }),
    )
    .await?;
    assert!(delegation.revoked, "delegation flag is flipped");
    assert!(delegation.revoked_at_ns.is_some(), "revocation timestamp");
    assert_eq!(delegation.agent, agent_id.to_string());
    assert_eq!(delegation.fck_pubkey, fck_public.to_string());

    let denied = contract
        .call_function(
            "anchor_artifact",
            json!({
                "artifact_digest": vec![2u8; 32],
                "artifact_type": "Identity",
                "artifact_id": "agent1-revoked",
                "subject_account": &agent_id,
            }),
        )
        .transaction()
        .max_gas()
        .deposit(NearToken::from_yoctonear(0))
        .with_signer(agent_id.clone(), fck_signer.clone())
        .send_to(&network)
        .await
        .map_err(|error| {
            std::io::Error::other(format!("revoked FCK anchor send failed: {error}"))
        })?;
    assert!(denied.is_failure(), "revoked FCK call is a failed receipt");
    let failure_text = format!("{denied:?}");
    assert!(
        failure_text.contains("delegation revoked"),
        "failure must be the on-chain delegation cut-off: {failure_text}"
    );
    // Insufficient credit: an oversized record costs more than the 50 mN credit.
    let huge_id = "x".repeat(60_000);
    let credit_refused = call_fails(
        &contract,
        &network,
        &agent_id,
        &fck_signer,
        "anchor_artifact",
        json!({
            "artifact_digest": vec![9u8; 32],
            "artifact_type": "Declaration",
            "artifact_id": huge_id,
            "subject_account": &agent_id,
        }),
        NearToken::from_yoctonear(0),
    )
    .await?;
    assert!(credit_refused, "oversized anchor must fail on insufficient credit");
    let credit_after_refusal: u128 = view::<String>(
        &contract,
        &network,
        "get_storage_credit",
        json!({ "agent": &agent_id }),
    )
    .await?
    .parse()?;
    assert_eq!(
        credit_after_refusal, credit_after_anchor,
        "a refused anchor must not debit credit"
    );

    assert!(
        call_fails(
            &contract,
            &network,
            &operator.id,
            &operator.signer,
            "revoke_delegation",
            json!({ "jti": &jti, "reason": "second revoke" }),
            revoke_deposit(),
        )
        .await?,
        "a second revoke_delegation must fail"
    );

    // --- revoke_identity: monotonic --------------------------------------
    call_ok(
        &contract,
        &network,
        &operator.id,
        &operator.signer,
        "revoke_identity",
        json!({ "agent": &agent_id, "reason": "sandbox revoke" }),
        revoke_deposit(),
    )
    .await?;

    let revoked = wait_for_identity(&contract, &network, &agent_id).await?;
    assert!(revoked.revoked, "identity revocation is visible");
    assert!(revoked.revoked_at_ns.is_some(), "revocation timestamp");

    assert!(
        call_fails(
            &contract,
            &network,
            &operator.id,
            &operator.signer,
            "revoke_identity",
            json!({ "agent": &agent_id, "reason": "second revoke" }),
            revoke_deposit(),
        )
        .await?,
        "a second revoke_identity must fail"
    );

    // --- register_existing_agent: repair an account whose callback was lost
    // Simulate the documented failure mode: the sub-account exists on chain but
    // `create_agent` never ran, so there is no AgentRecord.
    let repair = create_account(&sandbox, &format!("repair1.{}", registry.id), 25).await?;
    let repair_digest = vec![5u8; 32];
    let repair_args = json!({
        "agent": &repair.id,
        "full_access_key": &repair.public_key,
        "uait_digest": &repair_digest,
        "display_name": "Repaired Agent",
        "description": "repaired after a lost callback",
        "source_protocol": "repair",
        "issuer_name": "operator",
        "issuer_did": format!("did:near:{}", operator.id),
        "capabilities": Vec::<String>::new(),
        "expires_at_ns": 0u64,
    });

    // Force the callback to fail: the sub-account already exists, so the
    // CreateAccount action fails and `on_agent_created` must return false
    // without writing a record (RK17/RK25 failure-injection).
    call_ok(
        &contract,
        &network,
        &operator.id,
        &operator.signer,
        "create_agent",
        json!({
            "prefix": "repair1",
            "full_access_key": &repair.public_key,
            "uait_digest": &repair_digest,
            "display_name": "Repaired Agent",
            "description": "repaired after a lost callback",
            "source_protocol": "repair",
            "issuer_name": "operator",
            "issuer_did": format!("did:near:{}", operator.id),
            "capabilities": Vec::<String>::new(),
            "expires_at_ns": 0u64,
        }),
        create_agent_deposit(),
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(750)).await;
    let ghost: Option<AgentRecordView> = view(
        &contract,
        &network,
        "get_identity",
        json!({ "agent": &repair.id }),
    )
    .await?;
    assert!(
        ghost.is_none(),
        "a failed create_agent callback must not write an AgentRecord"
    );

    call_ok(
        &contract,
        &network,
        &operator.id,
        &operator.signer,
        "register_existing_agent",
        repair_args.clone(),
        create_agent_deposit(),
    )
    .await?;
    let repaired = wait_for_identity(&contract, &network, &repair.id).await?;
    assert_eq!(repaired.agent, repair.id.to_string());
    assert_eq!(repaired.uait_digest, repair_digest);
    assert!(!repaired.revoked);

    let repair_credit: u128 = view::<String>(
        &contract,
        &network,
        "get_storage_credit",
        json!({ "agent": &repair.id }),
    )
    .await?
    .parse()?;
    assert_eq!(
        repair_credit, 50_000_000_000_000_000_000_000,
        "repair funds exactly 50 mN of credit"
    );

    // Idempotent repair: a second call succeeds but must not rewrite the record.
    call_ok(
        &contract,
        &network,
        &operator.id,
        &operator.signer,
        "register_existing_agent",
        repair_args,
        create_agent_deposit(),
    )
    .await?;
    let repaired_again = wait_for_identity(&contract, &network, &repair.id).await?;
    assert_eq!(
        repaired_again.created_at_ns, repaired.created_at_ns,
        "idempotent repair must not overwrite the landed record"
    );

    let repair_credit_again: u128 = view::<String>(
        &contract,
        &network,
        "get_storage_credit",
        json!({ "agent": &repair.id }),
    )
    .await?
    .parse()?;
    assert_eq!(
        repair_credit_again, repair_credit,
        "idempotent repair must not re-fund credit"
    );

    Ok(())
}
