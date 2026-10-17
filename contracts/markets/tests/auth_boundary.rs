//! Auth boundary tests for the MarketsContract admin entrypoints.
//!
//! Verifies:
//! * `initialize` requires caller auth and sets admin atomically.
//! * `initialize` cannot be called twice.
//! * `pause_markets` / `unpause_markets` require admin auth.
//! * `transfer_ownership` requires admin auth and rejects self-transfer.
//! * `add_admin` requires admin auth.
//! * Non-admin callers are rejected on all admin entrypoints.
//! * Read-only entrypoints (`get_admin`, `is_paused`, `version`) require no auth.
//! * Admin check returns false (not true) when admin is unset.

#![cfg(test)]

use soroban_sdk::{testutils::Address as _, Address, Env};
use markets::{ContractError, MarketsContract, MarketsContractClient};

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

/// Register, initialize, and drain the init auth snapshot.
fn register_and_initialize<'a>(env: &Env, admin: &Address) -> MarketsContractClient<'a> {
    let contract_id = env.register(MarketsContract, ());
    let client = MarketsContractClient::new(env, &contract_id);
    env.mock_all_auths();
    client.initialize(admin);
    let _ = env.auths();
    client
}

// ---------------------------------------------------------------------------
// initialize
// ---------------------------------------------------------------------------

#[test]
fn test_initialize_sets_admin() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let client = register_and_initialize(&env, &admin);
    let stored_admin = client.get_admin();
    assert!(stored_admin.is_some());
    assert_eq!(stored_admin.unwrap(), admin);
}

#[test]
fn test_initialize_cannot_reinitialize() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let client = register_and_initialize(&env, &admin);

    let result = client.try_initialize(&admin);
    assert_eq!(
        result.unwrap_err().unwrap(),
        ContractError::AdminOperationNotPermitted
    );

    let new_admin = Address::generate(&env);
    let result = client.try_initialize(&new_admin);
    assert_eq!(
        result.unwrap_err().unwrap(),
        ContractError::AdminOperationNotPermitted
    );
}

#[test]
fn test_initialize_requires_auth() {
    let env = Env::default();
    let admin = Address::generate(&env);
    // Do NOT mock all auths — we want to verify auth is required.
    let contract_id = env.register(MarketsContract, ());
    let client = MarketsContractClient::new(&env, &contract_id);

    // Without auth, this should fail.
    let result = client.try_initialize(&admin);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// pause_markets / unpause_markets
// ---------------------------------------------------------------------------

#[test]
fn test_pause_markets_requires_admin() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let attacker = Address::generate(&env);
    let client = register_and_initialize(&env, &admin);

    // Attacker tries to pause — should be rejected.
    let result = client.try_pause_markets(&attacker);
    assert_eq!(result.unwrap_err().unwrap(), ContractError::Unauthorized);

    // Markets should not be paused.
    assert_eq!(client.is_paused(), false);
}

#[test]
fn test_pause_unpause_succeeds_with_admin() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let client = register_and_initialize(&env, &admin);

    client.pause_markets(&admin);
    assert_eq!(client.is_paused(), true);

    client.unpause_markets(&admin);
    assert_eq!(client.is_paused(), false);
}

#[test]
fn test_unpause_markets_requires_admin() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let attacker = Address::generate(&env);
    let client = register_and_initialize(&env, &admin);

    client.pause_markets(&admin);
    assert_eq!(client.is_paused(), true);

    // Attacker tries to unpause — should be rejected.
    let result = client.try_unpause_markets(&attacker);
    assert_eq!(result.unwrap_err().unwrap(), ContractError::Unauthorized);
}

// ---------------------------------------------------------------------------
// transfer_ownership
// ---------------------------------------------------------------------------

#[test]
fn test_transfer_ownership_succeeds_with_admin() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let client = register_and_initialize(&env, &admin);

    client.transfer_ownership(&admin, &new_admin);

    let stored = client.get_admin().unwrap();
    assert_eq!(stored, admin);
    client.set_pause_config(&new_admin, &0, &1);
    assert_eq!(client.get_pause_config(), (0, 1));
}

#[test]
fn test_transfer_ownership_rejects_non_admin() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let attacker = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let client = register_and_initialize(&env, &admin);

    let result = client.try_transfer_ownership(&attacker, &new_admin);
    assert_eq!(result.unwrap_err().unwrap(), ContractError::Unauthorized);

    // Admin should remain unchanged.
    assert_eq!(client.get_admin().unwrap(), admin);
}

#[test]
fn test_transfer_ownership_rejects_self_transfer() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let client = register_and_initialize(&env, &admin);

    let result = client.try_transfer_ownership(&admin, &admin);
    assert_eq!(result.unwrap_err().unwrap(), ContractError::AdminAddressInvalid);
}

// ---------------------------------------------------------------------------
// add_admin
// ---------------------------------------------------------------------------

#[test]
fn test_add_admin_succeeds_with_admin() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let client = register_and_initialize(&env, &admin);

    client.add_admin(&admin, &new_admin);

    let stored = client.get_admin().unwrap();
    assert_eq!(stored, new_admin);
}

#[test]
fn test_add_admin_rejects_non_admin() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let attacker = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let client = register_and_initialize(&env, &admin);

    let result = client.try_add_admin(&attacker, &new_admin);
    assert_eq!(result.unwrap_err().unwrap(), ContractError::Unauthorized);
}

#[test]
fn test_add_admin_rejects_self() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let client = register_and_initialize(&env, &admin);

    let result = client.try_add_admin(&admin, &admin);
    assert_eq!(result.unwrap_err().unwrap(), ContractError::AdminAddressInvalid);
}

// ---------------------------------------------------------------------------
// Admin unset — the CRITICAL security fix
// ---------------------------------------------------------------------------

#[test]
fn test_admin_unset_non_admin_rejected_before_init() {
    let env = Env::default();
    env.mock_all_auths();
    let attacker = Address::generate(&env);
    let contract_id = env.register(MarketsContract, ());
    let client = MarketsContractClient::new(&env, &contract_id);

    // Before initialization, get_admin returns None.
    assert!(client.get_admin().is_none());

    // Attacker tries to pause — must be rejected (this is the critical fix).
    let result = client.try_pause_markets(&attacker);
    assert_eq!(result.unwrap_err().unwrap(), ContractError::Unauthorized);

    // Attacker tries transfer_ownership — must be rejected.
    let some_addr = Address::generate(&env);
    let result = client.try_transfer_ownership(&attacker, &some_addr);
    assert_eq!(result.unwrap_err().unwrap(), ContractError::Unauthorized);

    // Attacker tries add_admin — must be rejected.
    let result = client.try_add_admin(&attacker, &some_addr);
    assert_eq!(result.unwrap_err().unwrap(), ContractError::Unauthorized);
}

// ---------------------------------------------------------------------------
// Read-only entrypoints — no auth required
// ---------------------------------------------------------------------------

#[test]
fn test_read_only_entrypoints_no_auth() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let client = register_and_initialize(&env, &admin);

    // These should all succeed without any auth.
    assert!(client.get_admin().is_some());
    assert_eq!(client.is_paused(), false);
    assert_eq!(client.version(), 7);
}
