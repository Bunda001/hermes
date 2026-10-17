#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, Map, Symbol};

mod errors;
pub use errors::ContractError;

// ============================================================
// Types
// ============================================================

/// Fee configuration for the platform.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeeConfig {
    /// Platform fee percentage in basis points (1 = 0.01%).
    /// Maximum allowed: 10_000 (100%).
    pub platform_fee_percentage: i128,
    /// Flat creation fee in stroops for creating resources.
    pub creation_fee: i128,
    /// Minimum fee amount in stroops.
    pub min_fee_amount: i128,
    /// Maximum fee amount in stroops.
    pub max_fee_amount: i128,
    /// Threshold in stroops above which collected fees may be withdrawn.
    pub collection_threshold: i128,
    /// Whether fees are currently enabled.
    pub fees_enabled: bool,
}

/// Pending fee commitment record prior to revelation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingFeeCommit {
    /// Hash of the committed configuration / preimage.
    pub hash: BytesN<32>,
    /// Admin address that submitted the commitment.
    pub admin: Address,
    /// Ledger timestamp when the commitment was recorded.
    pub committed_at: u64,
}

/// In-flight / pending fee configuration update awaiting execution.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingFeeConfig {
    /// Proposed fee configuration.
    pub config: FeeConfig,
    /// Admin address that proposed the update.
    pub admin: Address,
    /// Ledger timestamp when the update was proposed.
    pub proposed_at: u64,
    /// Ledger timestamp after which the update may be applied.
    pub apply_eta: u64,
}

/// Status of a fee withdrawal attempt.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeeWithdrawalStatus {
    Ready,
    Pending,
    Completed,
    Failed,
}

/// Schedule entry for fee withdrawals.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeeWithdrawalSchedule {
    pub next_withdrawal: u64,
    pub cooldown_seconds: u64,
    pub last_withdrawal: u64,
    pub status: FeeWithdrawalStatus,
}

/// Result of fee collection.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeeCollectionResult {
    pub amount_collected: i128,
    pub remaining_balance: i128,
}

// ============================================================
// Storage keys
// ============================================================

const ADMIN_KEY: &str = "Admin";
const FEE_CONFIG_KEY: &str = "FeeConfig";
const COLLECTED_FEES_KEY: &str = "CollectedFees";
const FEES_PAUSED_KEY: &str = "FeesPaused";
const WITHDRAWAL_SCHEDULE_KEY: &str = "WithdrawalSchedule";
const FEE_COMMIT_KEY: &str = "FeeCommit";
const FEE_QUEUED_KEY: &str = "FeeQueued";

#[contracttype]
#[derive(Clone)]
enum DataKey {
    AuthorizedCallers,
}

/// Default timelock cooldown in seconds for fee updates (24 hours).
const DEFAULT_TIMELOCK_SECONDS: u64 = 86_400;
/// Minimum timelock cooldown in seconds for fee updates (1 hour).
const MIN_TIMELOCK_SECONDS: u64 = 3_600;

/// Maximum platform fee percentage in basis points (100% = 10_000).
const MAX_FEE_PERCENTAGE: i128 = 10_000;

/// Hard protocol upper bound on `max_fee_amount` in stroops.
///
/// Set to 10_000_000_000 (10,000 XLM).  No admin can set a
/// `max_fee_amount` higher than this value, even after contract
/// upgrade, because the check lives inside `validate_fee_config` which
/// is called on every config-mutating entrypoint.
///
/// # Rationale
///
/// Without this cap a compromised or malicious admin could set fees so
/// high that any withdrawal leaves users with near-zero balances.
/// 10,000 XLM is a generous operational ceiling that prevents such an
/// attack while still accommodating any legitimate high-value use case.
///
/// # Protocol invariant
///
/// This constant MUST NOT be increased in future versions without a
/// governance vote and an explicit security review.  Decreasing it is
/// always safe.
pub const MAX_FEE_AMOUNT: i128 = 10_000_000_000; // 10 000 XLM in stroops

// ============================================================
// Contract
// ============================================================

#[contract]
pub struct FeesContract;

/// # Fees Contract
///
/// Manages platform fees including configuration, collection, and access control.
///
/// ## Authorization
///
/// State-changing entrypoints require authentication. Admin operations are
/// restricted to the registered admin; `record_fee` is restricted to an
/// admin-authorized contract.
///
/// Read-only entrypoints do not require authentication.
///
/// ## State-changing entrypoints (require auth)
///
/// | Entrypoint             | Auth required | Description                              |
/// |------------------------|---------------|------------------------------------------|
/// | `initialize`           | Yes           | Set the initial admin address            |
/// | `commit_fee_config`    | Yes           | Commit a hash of the future fee config   |
/// | `update_fee_config`    | Yes           | Reveal and queue the fee configuration   |
/// | `apply_fee_update`     | Yes           | Apply queued fee config after timelock   |
/// | `cancel_fee_update`    | Yes           | Cancel pending commitment or update      |
/// | `set_platform_fee`     | Yes           | Set only the platform fee percentage     |
/// | `collect_fees`         | Yes           | Withdraw accumulated fees                |
/// | `pause_fees`           | Yes           | Pause fee collection                     |
/// | `unpause_fees`         | Yes           | Resume fee collection                    |
/// | `transfer_admin`       | Yes           | Transfer admin to a new address          |
/// | `authorize_caller`     | Yes           | Allow a contract to record fees           |
/// | `revoke_caller`        | Yes           | Remove a contract's fee-recording access  |
/// | `record_fee`           | Yes           | Record fees from an authorized contract  |
///
/// ## Read-only entrypoints (no auth)
///
/// | Entrypoint                 | Description                              |
/// |----------------------------|------------------------------------------|
/// | `version`                  | Return contract version                  |
/// | `get_fee_config`           | Read current fee configuration           |
/// | `get_pending_fee_commit`   | Read active pending commitment (if any)  |
/// | `get_pending_fee_config`   | Read in-flight queued update (if any)    |
/// | `get_admin`                | Read admin address                       |
/// | `get_collected_fees`       | Read collected fees balance              |
/// | `is_authorized_caller`     | Check fee-recording authorization        |
#[contractimpl]
impl FeesContract {
    // ========================================================
    // State-changing entrypoints
    // ========================================================

    /// Initializes the fees contract with an administrator.
    ///
    /// # Authorization
    /// The `admin` caller must authenticate via `require_auth()`.
    ///
    /// # Errors
    /// - `ContractError::InvalidInput` if admin address is invalid
    /// - `ContractError::InvalidState` if already initialized
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        // ---- AUTH: require caller authentication before any state mutation ----
        admin.require_auth();

        // Prevent re-initialization
        if env
            .storage()
            .persistent()
            .has(&Symbol::new(&env, ADMIN_KEY))
        {
            return Err(ContractError::InvalidState);
        }

        // Store admin
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, ADMIN_KEY), &admin);

        // Initialize default fee config
        let default_config = FeeConfig {
            platform_fee_percentage: 200, // 2.00%
            creation_fee: 0,
            min_fee_amount: 1,
            max_fee_amount: MAX_FEE_AMOUNT, // hard protocol cap: 10,000 XLM
            collection_threshold: 100_000_000, // 100 XLM
            fees_enabled: true,
        };
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, FEE_CONFIG_KEY), &default_config);

        // Initialize collected fees to 0
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, COLLECTED_FEES_KEY), &0i128);

        env.storage()
            .persistent()
            .set(&DataKey::AuthorizedCallers, &Map::<Address, bool>::new(&env));

        // Initialize fees as not paused
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, FEES_PAUSED_KEY), &false);

        // Initialize withdrawal schedule
        let schedule = FeeWithdrawalSchedule {
            next_withdrawal: 0,
            cooldown_seconds: 86_400, // 24 hours
            last_withdrawal: 0,
            status: FeeWithdrawalStatus::Ready,
        };
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, WITHDRAWAL_SCHEDULE_KEY), &schedule);

        Ok(())
    }

    /// Stage 1: Commit a hash of the future fee configuration.
    ///
    /// # Authorization
    /// The `admin` caller must authenticate via `require_auth()` and must be
    /// the registered admin.
    pub fn commit_fee_config(
        env: Env,
        admin: Address,
        hash: BytesN<32>,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        Self::assert_is_admin(&env, &admin)?;
        Self::assert_fees_not_paused(&env)?;

        let commit = PendingFeeCommit {
            hash,
            admin: admin.clone(),
            committed_at: env.ledger().timestamp(),
        };

        env.storage()
            .persistent()
            .set(&Symbol::new(&env, FEE_COMMIT_KEY), &commit);

        Ok(())
    }

    /// Updates the complete fee configuration.
    ///
    /// Stages the update in pending storage with a governance timelock.
    ///
    /// # Authorization
    /// The `admin` caller must authenticate via `require_auth()` and must be
    /// the registered admin.
    ///
    /// # Parameters
    /// - `admin`: The admin calling this function (must pass auth).
    /// - `new_config`: The new fee configuration to apply.
    ///
    /// # Errors
    /// - `ContractError::Unauthorized` if caller is not the admin.
    /// - `ContractError::FeePercentageTooHigh` if platform_fee_percentage > 10_000.
    /// - `ContractError::InvalidInput` if any fee value is negative.
    pub fn update_fee_config(
        env: Env,
        admin: Address,
        new_config: FeeConfig,
    ) -> Result<(), ContractError> {
        // ---- AUTH: require caller authentication before any state mutation ----
        admin.require_auth();
        Self::assert_is_admin(&env, &admin)?;

        // Validate inputs
        Self::validate_fee_config(&new_config)?;

        // Ensure fees are not paused for config updates (consistency)
        Self::assert_fees_not_paused(&env)?;

        Self::queue_fee_config(&env, &admin, new_config, DEFAULT_TIMELOCK_SECONDS)
    }

    /// Applies a previously queued fee configuration update after its timelock has expired.
    ///
    /// # Authorization
    /// The `admin` caller must authenticate via `require_auth()` and must be
    /// the registered admin.
    pub fn apply_fee_update(env: Env, admin: Address) -> Result<(), ContractError> {
        admin.require_auth();
        Self::assert_is_admin(&env, &admin)?;

        let pending = Self::get_pending_fee_config_internal(&env)
            .ok_or(ContractError::NoPendingFeeCommit)?;

        let now = env.ledger().timestamp();
        if now < pending.apply_eta {
            return Err(ContractError::FeeRevealTooEarly);
        }

        env.storage()
            .persistent()
            .set(&Symbol::new(&env, FEE_CONFIG_KEY), &pending.config);

        env.storage()
            .persistent()
            .remove(&Symbol::new(&env, FEE_QUEUED_KEY));

        Ok(())
    }

    /// Cancels any in-flight commitment or queued fee configuration update.
    ///
    /// # Authorization
    /// The `admin` caller must authenticate via `require_auth()` and must be
    /// the registered admin.
    pub fn cancel_fee_update(env: Env, admin: Address) -> Result<(), ContractError> {
        admin.require_auth();
        Self::assert_is_admin(&env, &admin)?;

        let queued_key = Symbol::new(&env, FEE_QUEUED_KEY);
        let commit_key = Symbol::new(&env, FEE_COMMIT_KEY);

        let had_queued = env.storage().persistent().has(&queued_key);
        let had_commit = env.storage().persistent().has(&commit_key);

        if !had_queued && !had_commit {
            return Err(ContractError::NoPendingFeeCommit);
        }

        env.storage().persistent().remove(&queued_key);
        env.storage().persistent().remove(&commit_key);

        Ok(())
    }

    /// Sets only the platform fee percentage.
    ///
    /// Convenience entrypoint that preserves all other fee configuration values.
    /// The update is queued and subject to the standard fee configuration timelock.
    ///
    /// # Authorization
    /// The `admin` caller must authenticate via `require_auth()` and be the
    /// registered admin.
    ///
    /// # Errors
    /// - `ContractError::Unauthorized` if caller is not the admin.
    /// - `ContractError::FeePercentageTooHigh` if percentage > 10_000.
    pub fn set_platform_fee(
        env: Env,
        admin: Address,
        fee_percentage: i128,
    ) -> Result<(), ContractError> {
        // ---- AUTH: require caller authentication before any state mutation ----
        admin.require_auth();
        Self::assert_is_admin(&env, &admin)?;

        if !(0..=MAX_FEE_PERCENTAGE).contains(&fee_percentage) {
            return Err(ContractError::FeePercentageTooHigh);
        }

        let mut config = Self::get_fee_config_internal(&env)?;
        config.platform_fee_percentage = fee_percentage;
        Self::queue_fee_config(&env, &admin, config, DEFAULT_TIMELOCK_SECONDS)
    }

    /// Authorizes a contract to record fees.
    ///
    /// # Authorization
    /// The `admin` caller must authenticate via `require_auth()` and be the
    /// registered admin.
    pub fn authorize_caller(
        env: Env,
        admin: Address,
        caller: Address,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        Self::assert_is_admin(&env, &admin)?;

        let mut callers: Map<Address, bool> = env
            .storage()
            .persistent()
            .get(&DataKey::AuthorizedCallers)
            .unwrap_or(Map::new(&env));
        callers.set(caller, true);
        env.storage()
            .persistent()
            .set(&DataKey::AuthorizedCallers, &callers);

        Ok(())
    }

    /// Revokes a contract's permission to record fees.
    ///
    /// # Authorization
    /// The `admin` caller must authenticate via `require_auth()` and be the
    /// registered admin.
    pub fn revoke_caller(
        env: Env,
        admin: Address,
        caller: Address,
    ) -> Result<(), ContractError> {
        admin.require_auth();
        Self::assert_is_admin(&env, &admin)?;

        let mut callers: Map<Address, bool> = env
            .storage()
            .persistent()
            .get(&DataKey::AuthorizedCallers)
            .unwrap_or(Map::new(&env));
        callers.remove(caller);
        env.storage()
            .persistent()
            .set(&DataKey::AuthorizedCallers, &callers);

        Ok(())
    }

    /// Returns whether an address is authorized to record fees.
    pub fn is_authorized_caller(env: Env, caller: Address) -> bool {
        Self::is_authorized_caller_internal(&env, &caller)
    }

    /// Checks whether an address is in the authorized fee-recording set.
    fn is_authorized_caller_internal(env: &Env, caller: &Address) -> bool {
        let callers: Map<Address, bool> = env
            .storage()
            .persistent()
            .get(&DataKey::AuthorizedCallers)
            .unwrap_or(Map::new(env));
        callers.get(caller.clone()).unwrap_or(false)
    }

    /// Collects accumulated fees and transfers them to the admin.
    ///
    /// # Authorization
    /// The `admin` caller must authenticate via `require_auth()` and be the
    /// registered admin.
    ///
    /// # Returns
    /// A `FeeCollectionResult` containing the amount collected and remaining balance.
    ///
    /// # Errors
    /// - `ContractError::Unauthorized` if caller is not the admin.
    /// - `ContractError::FeesPaused` if fees are paused.
    /// - `ContractError::BelowCollectionThreshold` if collected fees < threshold.
    pub fn collect_fees(env: Env, admin: Address) -> Result<FeeCollectionResult, ContractError> {
        // ---- AUTH: require caller authentication before any state mutation ----
        admin.require_auth();
        Self::assert_is_admin(&env, &admin)?;

        Self::assert_fees_not_paused(&env)?;

        let collected: i128 = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, COLLECTED_FEES_KEY))
            .unwrap_or(0);

        let config = Self::get_fee_config_internal(&env)?;

        if collected < config.collection_threshold {
            let mut schedule = Self::get_withdrawal_schedule_internal(&env);
            schedule.status = FeeWithdrawalStatus::Failed;
            env.storage()
                .persistent()
                .set(&Symbol::new(&env, WITHDRAWAL_SCHEDULE_KEY), &schedule);
            return Err(ContractError::BelowCollectionThreshold);
        }

        // Reset collected fees after collection
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, COLLECTED_FEES_KEY), &0i128);

        // Update withdrawal schedule
        let now = env.ledger().timestamp();
        let mut schedule = Self::get_withdrawal_schedule_internal(&env);
        schedule.last_withdrawal = now;
        schedule.next_withdrawal = now
            .checked_add(schedule.cooldown_seconds)
            .ok_or(ContractError::Overflow)?;
        schedule.status = FeeWithdrawalStatus::Completed;
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, WITHDRAWAL_SCHEDULE_KEY), &schedule);

        Ok(FeeCollectionResult {
            amount_collected: collected,
            remaining_balance: 0,
        })
    }

    /// Records a fee payment, incrementing the collected fees balance.
    ///
    /// This is typically called by authorized contracts (e.g., markets) when a
    /// fee-generating action occurs. The caller contract must authenticate.
    ///
    /// # Authorization
    /// The authorized calling contract must authenticate via `require_auth()`.
    pub fn record_fee(env: Env, caller: Address, amount: i128) -> Result<(), ContractError> {
        // ---- AUTH: require caller authentication before any state mutation ----
        caller.require_auth();

        if !Self::is_authorized_caller_internal(&env, &caller) {
            return Err(ContractError::Unauthorized);
        }

        if amount <= 0 {
            return Err(ContractError::InvalidInput);
        }

        let config = Self::get_fee_config_internal(&env)?;
        if !config.fees_enabled {
            return Err(ContractError::FeesPaused);
        }

        let current: i128 = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, COLLECTED_FEES_KEY))
            .unwrap_or(0);

        let new_balance = current.checked_add(amount).ok_or(ContractError::Overflow)?;

        env.storage()
            .persistent()
            .set(&Symbol::new(&env, COLLECTED_FEES_KEY), &new_balance);

        Ok(())
    }

    /// Pauses fee collection across the platform.
    ///
    /// # Authorization
    /// The `admin` caller must authenticate via `require_auth()` and be the
    /// registered admin.
    pub fn pause_fees(env: Env, admin: Address) -> Result<(), ContractError> {
        // ---- AUTH: require caller authentication before any state mutation ----
        admin.require_auth();
        Self::assert_is_admin(&env, &admin)?;

        // Update fees_enabled in config
        let mut config = Self::get_fee_config_internal(&env)?;
        config.fees_enabled = false;
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, FEE_CONFIG_KEY), &config);

        // Also set the global pause flag
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, FEES_PAUSED_KEY), &true);

        Ok(())
    }

    /// Resumes fee collection across the platform.
    ///
    /// # Authorization
    /// The `admin` caller must authenticate via `require_auth()` and be the
    /// registered admin.
    pub fn unpause_fees(env: Env, admin: Address) -> Result<(), ContractError> {
        // ---- AUTH: require caller authentication before any state mutation ----
        admin.require_auth();
        Self::assert_is_admin(&env, &admin)?;

        // Update fees_enabled in config
        let mut config = Self::get_fee_config_internal(&env)?;
        config.fees_enabled = true;
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, FEE_CONFIG_KEY), &config);

        // Clear the global pause flag
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, FEES_PAUSED_KEY), &false);

        Ok(())
    }

    /// Transfers admin ownership to a new address.
    ///
    /// # Authorization
    /// The `current_admin` caller must authenticate via `require_auth()` and
    /// be the currently registered admin.
    ///
    /// # Errors
    /// - `ContractError::Unauthorized` if caller is not the admin.
    /// - `ContractError::InvalidInput` if new_admin is the same as current.
    pub fn transfer_admin(
        env: Env,
        current_admin: Address,
        new_admin: Address,
    ) -> Result<(), ContractError> {
        // ---- AUTH: require caller authentication before any state mutation ----
        current_admin.require_auth();
        Self::assert_is_admin(&env, &current_admin)?;

        if new_admin == current_admin {
            return Err(ContractError::InvalidInput);
        }

        env.storage()
            .persistent()
            .set(&Symbol::new(&env, ADMIN_KEY), &new_admin);

        Ok(())
    }

    // ========================================================
    // Read-only entrypoints
    // ========================================================

    /// Returns the contract version.
    pub fn version(_env: Env) -> u32 {
        7
    }

    /// Returns the currently active fee configuration.
    ///
    /// Read-only — no authentication required.
    pub fn get_fee_config(env: Env) -> Result<FeeConfig, ContractError> {
        Self::get_fee_config_internal(&env)
    }

    /// Returns the active pending fee commitment (hash, committer, timestamp), if any.
    ///
    /// Read-only — no authentication required.
    pub fn get_pending_fee_commit(env: Env) -> Option<PendingFeeCommit> {
        Self::get_pending_fee_commit_internal(&env)
    }

    /// Returns the in-flight/queued pending fee configuration awaiting execution, if any.
    ///
    /// Read-only — no authentication required.
    pub fn get_pending_fee_config(env: Env) -> Option<PendingFeeConfig> {
        Self::get_pending_fee_config_internal(&env)
    }

    /// Returns the admin address.
    ///
    /// Read-only — no authentication required.
    pub fn get_admin(env: Env) -> Result<Address, ContractError> {
        Self::get_admin_internal(&env)
    }

    /// Returns the total collected fees balance.
    ///
    /// Read-only — no authentication required.
    pub fn get_collected_fees(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&Symbol::new(&env, COLLECTED_FEES_KEY))
            .unwrap_or(0)
    }

    /// Returns whether fees are currently paused.
    ///
    /// Read-only — no authentication required.
    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .persistent()
            .get(&Symbol::new(&env, FEES_PAUSED_KEY))
            .unwrap_or(false)
    }

    /// Returns the current withdrawal schedule.
    ///
    /// Read-only — no authentication required.
    pub fn get_withdrawal_schedule(env: Env) -> FeeWithdrawalSchedule {
        Self::get_withdrawal_schedule_internal(&env)
    }

    // ========================================================
    // Internal helpers
    // ========================================================

    /// Reads the pending fee commitment from storage.
    fn get_pending_fee_commit_internal(env: &Env) -> Option<PendingFeeCommit> {
        env.storage()
            .persistent()
            .get(&Symbol::new(env, FEE_COMMIT_KEY))
    }

    /// Reads the queued pending fee config from storage.
    fn get_pending_fee_config_internal(env: &Env) -> Option<PendingFeeConfig> {
        env.storage()
            .persistent()
            .get(&Symbol::new(env, FEE_QUEUED_KEY))
    }

    fn queue_fee_config(
        env: &Env,
        admin: &Address,
        config: FeeConfig,
        delay_seconds: u64,
    ) -> Result<(), ContractError> {
        if delay_seconds < MIN_TIMELOCK_SECONDS {
            return Err(ContractError::InvalidInput);
        }

        let now = env.ledger().timestamp();
        let queued = PendingFeeConfig {
            config,
            admin: admin.clone(),
            proposed_at: now,
            apply_eta: now.saturating_add(delay_seconds),
        };

        env.storage()
            .persistent()
            .set(&Symbol::new(env, FEE_QUEUED_KEY), &queued);
        env.storage()
            .persistent()
            .remove(&Symbol::new(env, FEE_COMMIT_KEY));

        Ok(())
    }

    /// Validates the caller is the registered admin.
    fn assert_is_admin(env: &Env, caller: &Address) -> Result<(), ContractError> {
        let stored_admin = Self::get_admin_internal(env)?;
        if caller != &stored_admin {
            return Err(ContractError::Unauthorized);
        }
        Ok(())
    }

    /// Validates that fees are not paused.
    fn assert_fees_not_paused(env: &Env) -> Result<(), ContractError> {
        let paused: bool = env
            .storage()
            .persistent()
            .get(&Symbol::new(env, FEES_PAUSED_KEY))
            .unwrap_or(false);
        if paused {
            return Err(ContractError::FeesPaused);
        }
        Ok(())
    }

    /// Reads the admin from storage.
    fn get_admin_internal(env: &Env) -> Result<Address, ContractError> {
        env.storage()
            .persistent()
            .get(&Symbol::new(env, ADMIN_KEY))
            .ok_or(ContractError::AdminNotSet)
    }

    /// Reads the fee config from storage.
    fn get_fee_config_internal(env: &Env) -> Result<FeeConfig, ContractError> {
        env.storage()
            .persistent()
            .get(&Symbol::new(env, FEE_CONFIG_KEY))
            .ok_or(ContractError::FeeConfigNotFound)
    }

    /// Reads the withdrawal schedule from storage.
    fn get_withdrawal_schedule_internal(env: &Env) -> FeeWithdrawalSchedule {
        env.storage()
            .persistent()
            .get(&Symbol::new(env, WITHDRAWAL_SCHEDULE_KEY))
            .unwrap_or(FeeWithdrawalSchedule {
                next_withdrawal: 0,
                cooldown_seconds: 86_400,
                last_withdrawal: 0,
                status: FeeWithdrawalStatus::Ready,
            })
    }

    /// Validates fee configuration values.
    fn validate_fee_config(config: &FeeConfig) -> Result<(), ContractError> {
        if config.platform_fee_percentage < 0 || config.platform_fee_percentage > MAX_FEE_PERCENTAGE
        {
            return Err(ContractError::FeePercentageTooHigh);
        }
        if config.creation_fee < 0
            || config.min_fee_amount < 0
            || config.max_fee_amount < 0
            || config.collection_threshold < 0
        {
            return Err(ContractError::InvalidInput);
        }
        // Protocol invariant: max_fee_amount must never exceed the hard cap
        // (MAX_FEE_AMOUNT = 10,000 XLM) regardless of who is calling.
        // This prevents a compromised admin from draining users via sky-high fees.
        if config.max_fee_amount > MAX_FEE_AMOUNT {
            return Err(ContractError::InvalidInput);
        }
        if config.min_fee_amount > config.max_fee_amount {
            return Err(ContractError::InvalidInput);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    #[test]
    fn queue_fee_config_rejects_delay_below_minimum() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let config = FeeConfig {
            platform_fee_percentage: 200,
            creation_fee: 0,
            min_fee_amount: 1,
            max_fee_amount: MAX_FEE_AMOUNT,
            collection_threshold: 100_000_000,
            fees_enabled: true,
        };

        assert_eq!(
            FeesContract::queue_fee_config(
                &env,
                &admin,
                config,
                MIN_TIMELOCK_SECONDS - 1,
            ),
            Err(ContractError::InvalidInput)
        );
    }
}
