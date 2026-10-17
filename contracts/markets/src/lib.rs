#![no_std]
#![allow(clippy::too_many_arguments)]

//! Markets contract with auth-gated entrypoints and hardened security controls.
//!
//! Provides a prediction-market subsystem where every state-changing
//! entrypoint enforces `require_auth` on the acting [`Address`].
//!
//! # Auth Matrix
//!
//! | Function                    | Required Role              |
//! |-----------------------------|----------------------------|
//! | `create_market`             | Creator (any address)      |
//! | `create_market_with_curve`  | Creator (any address)      |
//! | `set_market_payout_curve`   | Market creator or Admin    |
//! | `place_bet`                 | Bettor (any address)       |
//! | `resolve_market`            | Market creator or Admin    |
//! | `claim_winnings`            | Winner / Claimant (bettor) |
//! | `cancel_market`             | Market creator             |
//! | `withdraw_funds`            | Market creator             |
//! | `update_market_params`      | Market creator             |
//! | `add_liquidity`             | Liquidity provider         |
//! | `remove_liquidity`          | Liquidity provider         |
//! | `pause_markets`             | Admin                      |
//! | `unpause_markets`           | Admin                      |
//! | `set_market_limit`          | Admin                      |
//! | `get_market_limit`          | Anyone (read-only)          |
//! | `propose_pause`             | Admin                      |
//! | `approve_pause`             | Admin                      |
//! | `execute_pause`             | Admin                      |
//! | `cancel_pause`              | Admin                      |
//! | `get_pause_proposal`        | Admin                      |
//! | `set_pause_config`          | Admin                      |
//! | `add_admin`                 | Admin                      |
//! | `transfer_ownership`        | Admin                      |
//! | `deposit_user_balance`      | User (any address)         |
//! | `withdraw_user_balance`     | User (any address)         |
//! | `collect_user_fees`         | Admin                      |
//! | `set_fee_config`            | Admin                      |
//! | `version`                   | Anyone (read-only)         |

pub mod errors;

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String, Vec};

pub use errors::ContractError;

/// Type alias used by generated client code and test harnesses.
pub type Error = ContractError;

/// Finite safety bound for deployments that have not configured a market limit.
const DEFAULT_MAX_MARKET_COUNT: u32 = 10_000;

/// Persistent-storage keys used by the Markets contract.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Sequential counter for generating unique market IDs.
    MarketCounter,
    /// Maximum number of markets that may be created.
    MarketLimit,
    /// Market data keyed by the numeric market ID.
    Market(u32),
    /// Bet placed by a user on a specific market.
    Bet(u32, Address),
    /// Whether the markets subsystem is globally paused (`true` = paused).
    Paused,
    /// The primary admin / owner address.
    Admin,
    /// Whether the contract has been initialized.
    Initialized,
    /// Liquidity provided by a user to a specific market.
    Liquidity(u32, Address),
    /// Records that a winner has already claimed their payout for a market.
    /// Written **before** any token transfer in `claim_winnings` to uphold the
    /// checks-effects-interactions pattern and prevent reentrancy double-claims.
    ClaimedBet(u32, Address),
    /// Fractional payout numerator carried forward per market outcome.
    PayoutRemainder(u32, u32),

    /// Winning outcome indices recorded when a market is resolved.
    WinningOutcomes(u32),

    // ── Issue #007: Hardened Pause Keys ─────────────────────────────
    /// Counter for generating unique pause proposal IDs.
    PauseProposalCounter,
    /// Pause proposal data keyed by proposal ID.
    PauseProposal(u32),
    /// Timelock delay in seconds required before executing a pause proposal.
    PauseDelaySeconds,
    /// Number of distinct admin approvals required to execute a pause proposal.
    PauseRequiredApprovals,

    // ── Issue #022: Bet Enumeration Keys ────────────────────────────
    /// Ordered list of market IDs a user has placed bets on.
    UserBetMarkets(Address),

    // ── Issue #014: Payout Curve Keys ───────────────────────────────
    /// Payout curve configuration for a market.
    MarketPayoutCurve(u32),
    /// Total wager pool for a market.
    MarketTotalPool(u32),
    /// Total wager pool for a specific outcome index within a market.
    OutcomePool(u32, u32),

    // ── Issue #012: Dust-Safe Balance & Fee Keys ────────────────────
    /// Internal balance for a user.
    UserBalance(Address),
    /// Token contract used to fund user balances.
    TokenAddress,
    /// Minimum fee amount threshold in stroops.
    MinFeeAmount,
    /// Withdrawal fee in basis points (1 = 0.01%).
    WithdrawalFeeBps,
    /// Cumulative platform fees collected.
    CollectedFees,
}

/// On-chain representation of a prediction market.
#[contracttype]
#[derive(Clone)]
pub struct MarketData {
    /// The address that created the market.
    pub creator: Address,
    /// The prediction question.
    pub question: String,
    /// A human-readable description of the market.
    pub description: String,
    /// Unix timestamp (seconds) when betting closes.
    pub end_time: u64,
    /// Identifies the data source used at resolution time.
    pub resolution_source: String,
    /// Ordered list of possible outcomes.
    pub outcome_tags: Vec<String>,
    /// Whether a winning outcome has been recorded.
    pub resolved: bool,
    /// Index (0-based) of the winning outcome.
    pub winning_outcome: u32,
    /// Whether the market has been cancelled.
    pub cancelled: bool,
}

/// On-chain record of a user's bet on a market.
#[contracttype]
#[derive(Clone)]
pub struct BetData {
    /// Index of the selected outcome.
    pub outcome_index: u32,
    /// Amount staked in the platform's base unit.
    pub amount: i128,
}

/// Tracks how much liquidity a user has added to a market.
#[contracttype]
#[derive(Clone)]
pub struct LiquidityData {
    /// Total amount of liquidity provided.
    pub total_amount: i128,
}

/// Pause proposal record for multi-step / timelocked pause operations (#007).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseProposal {
    /// Sequential proposal identifier.
    pub id: u32,
    /// Admin address that created the proposal.
    pub proposer: Address,
    /// Reason or justification for the pause.
    pub reason: String,
    /// Ledger timestamp when the proposal was created.
    pub created_at: u64,
    /// Earliest ledger timestamp when the proposal may be executed.
    pub eta: u64,
    /// List of admin addresses that have approved the proposal.
    pub approvals: Vec<Address>,
    /// Whether the proposal has already been executed.
    pub executed: bool,
    /// Whether the proposal was cancelled.
    pub cancelled: bool,
}

/// Contract-level query record for a user's bet (#022).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserBetInfo {
    /// Numeric ID of the market.
    pub market_id: u32,
    /// Chosen outcome index (0-based).
    pub outcome_index: u32,
    /// Amount staked. Always positive — represented as unsigned to enforce the invariant at
    /// the type level and avoid defensive negative-value handling by callers.
    pub amount: u128,
    /// Whether winnings for this bet have already been claimed.
    pub claimed: bool,
}

/// Configurable payout curve configuration for distributing market pool funds (#014).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayoutCurveConfig {
    /// 0 = WinnerTakesAll, 1 = Tiered, 2 = CustomWeights
    pub curve_type: u32,
    /// Outcome index receiving runner-up credit (for Tiered).
    pub runner_up_outcome: u32,
    /// Percentage in basis points awarded to runner-up (e.g. 2000 = 20%).
    pub runner_up_bps: u32,
    /// Custom basis point weights per outcome tag (for CustomWeights).
    pub custom_weights: Vec<u32>,
}

impl PayoutCurveConfig {
    pub const WINNER_TAKES_ALL: u32 = 0;
    pub const TIERED: u32 = 1;
    pub const CUSTOM_WEIGHTS: u32 = 2;

    pub fn winner_takes_all(env: &Env) -> Self {
        Self {
            curve_type: Self::WINNER_TAKES_ALL,
            runner_up_outcome: 0,
            runner_up_bps: 0,
            custom_weights: Vec::new(env),
        }
    }

    pub fn tiered(env: &Env, runner_up_outcome: u32, runner_up_bps: u32) -> Self {
        Self {
            curve_type: Self::TIERED,
            runner_up_outcome,
            runner_up_bps,
            custom_weights: Vec::new(env),
        }
    }

    pub fn custom_weights(weights: Vec<u32>) -> Self {
        Self {
            curve_type: Self::CUSTOM_WEIGHTS,
            runner_up_outcome: 0,
            runner_up_bps: 0,
            custom_weights: weights,
        }
    }
}

/// Result of a dust-safe user balance withdrawal (#012).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawalResult {
    /// Net amount received by the user.
    pub net_amount: i128,
    /// Fee deducted (0 if dust waiver applied).
    pub fee_deducted: i128,
    /// Remaining balance in the contract.
    pub remaining_balance: i128,
}

pub mod admin;

#[contract]
pub struct MarketsContract;

impl MarketsContract {
    // -----------------------------------------------------------------------
    //  Internal Helpers
    // -----------------------------------------------------------------------

    fn is_admin_internal(env: &Env, caller: &Address) -> bool {
        if let Some(admin) = env
            .storage()
            .persistent()
            .get::<_, Address>(&DataKey::Admin)
        {
            if &admin == caller {
                return true;
            }
        } else {
            // First caller with admin action becomes initial admin if unset.
            return true;
        }

        let admin_list: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::AdminList)
            .unwrap_or(Vec::new(env));
        admin_list.contains(caller)
    }

    fn require_admin(env: &Env, caller: &Address) {
        caller.require_auth();
        if !Self::is_admin_internal(env, caller) {
            panic_with_error!(env, ContractError::Unauthorized);
        }
    }

    fn validate_payout_curve(env: &Env, curve: &PayoutCurveConfig, num_outcomes: u32) {
        match curve.curve_type {
            PayoutCurveConfig::WINNER_TAKES_ALL => {}
            PayoutCurveConfig::TIERED => {
                if curve.runner_up_outcome >= num_outcomes {
                    panic_with_error!(env, ContractError::InvalidPayoutCurve);
                }
                if curve.runner_up_bps == 0 || curve.runner_up_bps >= 10_000 {
                    panic_with_error!(env, ContractError::InvalidPayoutCurve);
                }
            }
            PayoutCurveConfig::CUSTOM_WEIGHTS => {
                if curve.custom_weights.len() != num_outcomes {
                    panic_with_error!(env, ContractError::InvalidPayoutCurve);
                }
                let mut sum: u32 = 0;
                for w in curve.custom_weights.iter() {
                    sum = match sum.checked_add(w) {
                        Some(s) => s,
                        None => panic_with_error!(env, ContractError::InvalidPayoutCurve),
                    };
                }
                if sum == 0 || sum > 10_000 {
                    panic_with_error!(env, ContractError::InvalidPayoutCurve);
                }
            }
            _ => panic_with_error!(env, ContractError::InvalidPayoutCurve),
        }
    }

    fn winning_outcomes(env: &Env, market_id: u32, market: &MarketData) -> Vec<u32> {
        env.storage()
            .persistent()
            .get(&DataKey::WinningOutcomes(market_id))
            .unwrap_or_else(|| {
                let mut outcomes = Vec::new(env);
                if market.resolved {
                    outcomes.push_back(market.winning_outcome);
                }
                outcomes
            })
    }
}

#[contractimpl]
impl MarketsContract {
    // -----------------------------------------------------------------------
    //  Read-only Entrypoints
    // -----------------------------------------------------------------------

    /// @notice Returns the contract version.
    pub fn version(_env: Env) -> u32 {
        7
    }

    /// @notice Read a market from persistent storage and bump its TTL.
    pub fn get_market(env: Env, market_id: soroban_sdk::Symbol) -> Option<soroban_sdk::Val> {
        let market: Option<soroban_sdk::Val> = env.storage().persistent().get(&market_id);
        if market.is_some() {
            env.storage()
                .persistent()
                .extend_ttl(&market_id, 6307200, 6307200);
        }
        market
    }

    /// Read the metadata required by the resolution subsystem.
    pub fn get_market_for_resolution(
        env: Env,
        market_id: u32,
    ) -> Option<(Address, u64, u32, bool, bool)> {
        let key = DataKey::Market(market_id);
        let market: Option<MarketData> = env.storage().persistent().get(&key);
        if market.is_some() {
            let ttl = 6_307_200u32.min(env.storage().max_ttl());
            env.storage().persistent().extend_ttl(&key, ttl, ttl);
        }
        market.map(|market| {
            (
                market.creator,
                market.end_time,
                market.outcome_tags.len(),
                market.resolved,
                market.cancelled,
            )
        })
    }

    /// Return every winning outcome for a resolved market.
    pub fn get_winning_outcomes(env: Env, market_id: u32) -> Option<Vec<u32>> {
        let market_key = DataKey::Market(market_id);
        let market: Option<MarketData> = env.storage().persistent().get(&market_key);
        market.map(|market| {
            let ttl = 6_307_200u32.min(env.storage().max_ttl());
            env.storage().persistent().extend_ttl(&market_key, ttl, ttl);
            let outcomes_key = DataKey::WinningOutcomes(market_id);
            if env.storage().persistent().has(&outcomes_key) {
                env.storage()
                    .persistent()
                    .extend_ttl(&outcomes_key, ttl, ttl);
            }
            Self::winning_outcomes(&env, market_id, &market)
        })
    }

    /// Returns whether market operations are currently paused globally.
    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    /// Returns the primary admin address if set.
    pub fn get_admin(env: Env) -> Option<Address> {
        env.storage().persistent().get(&DataKey::Admin)
    }

    /// Returns the configured market limit, or the finite default if unset.
    pub fn get_market_limit(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::MarketLimit)
            .unwrap_or(DEFAULT_MAX_MARKET_COUNT)
    }

    // -----------------------------------------------------------------------
    //  Market Lifecycle
    // -----------------------------------------------------------------------

    /// Creates a new prediction market with default WinnerTakesAll payout curve.
    pub fn create_market(
        env: Env,
        creator: Address,
        question: String,
        description: String,
        end_time: u64,
        resolution_source: String,
        outcome_tags: Vec<String>,
    ) -> u32 {
        Self::create_market_with_curve(
            env.clone(),
            creator,
            question,
            description,
            end_time,
            resolution_source,
            outcome_tags,
            PayoutCurveConfig::winner_takes_all(&env),
        )
    }

    /// Creates a new prediction market with a specific configurable payout curve (#014).
    pub fn create_market_with_curve(
        env: Env,
        creator: Address,
        question: String,
        description: String,
        end_time: u64,
        resolution_source: String,
        outcome_tags: Vec<String>,
        curve: PayoutCurveConfig,
    ) -> u32 {
        creator.require_auth();

        let counter: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::MarketCounter)
            .unwrap_or(0u32);
        if counter >= Self::get_market_limit(env.clone()) {
            panic_with_error!(env, ContractError::MarketLimitReached);
        }

        if outcome_tags.len() < 2 {
            panic_with_error!(env, ContractError::InvalidConfig);
        }

        Self::validate_payout_curve(&env, &curve, outcome_tags.len());

        let market_id = match counter.checked_add(1) {
            Some(id) => id,
            None => panic_with_error!(env, ContractError::Overflow),
        };

        env.storage()
            .persistent()
            .set(&DataKey::MarketCounter, &market_id);

        let market = MarketData {
            creator: creator.clone(),
            question,
            description,
            end_time,
            resolution_source,
            outcome_tags,
            resolved: false,
            winning_outcome: 0,
            cancelled: false,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Market(market_id), &market);

        env.storage()
            .persistent()
            .set(&DataKey::MarketPayoutCurve(market_id), &curve);

        market_id
    }

    /// Configures the payout curve for an existing market before resolution and betting (#014).
    pub fn set_market_payout_curve(
        env: Env,
        caller: Address,
        market_id: u32,
        curve: PayoutCurveConfig,
    ) {
        caller.require_auth();

        let market: MarketData = match env.storage().persistent().get(&DataKey::Market(market_id)) {
            Some(m) => m,
            None => panic_with_error!(env, ContractError::MarketNotFound),
        };

        let now = env.ledger().timestamp();
        if now >= market.end_time {
            panic_with_error!(env, ContractError::MarketClosed);
        }

        if market.resolved || market.cancelled {
            panic_with_error!(env, ContractError::InvalidState);
        }

        if caller != market.creator && !Self::is_admin_internal(&env, &caller) {
            panic_with_error!(env, ContractError::Unauthorized);
        }

        // Prevent modifying curve if wagers are already placed on the market
        let total_pool: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::MarketTotalPool(market_id))
            .unwrap_or(0);
        if total_pool > 0 {
            panic_with_error!(env, ContractError::InvalidState);
        }

        Self::validate_payout_curve(&env, &curve, market.outcome_tags.len());

        env.storage()
            .persistent()
            .set(&DataKey::MarketPayoutCurve(market_id), &curve);
    }

    /// Reads the configured payout curve for a market (#014).
    pub fn get_market_payout_curve(env: Env, market_id: u32) -> PayoutCurveConfig {
        env.storage()
            .persistent()
            .get(&DataKey::MarketPayoutCurve(market_id))
            .unwrap_or_else(|| PayoutCurveConfig::winner_takes_all(&env))
    }

    /// Places a bet on a specific market outcome, updating bet enumeration (#022)
    /// and pool balances (#014).
    pub fn place_bet(env: Env, user: Address, market_id: u32, outcome_index: u32, amount: i128) {
        user.require_auth();

        if Self::is_paused(env.clone()) {
            panic_with_error!(env, ContractError::InvalidState);
        }

        let market: MarketData = match env.storage().persistent().get(&DataKey::Market(market_id)) {
            Some(m) => m,
            None => panic_with_error!(env, ContractError::MarketNotFound),
        };

        if market.resolved || market.cancelled {
            panic_with_error!(env, ContractError::InvalidState);
        }

        if outcome_index >= market.outcome_tags.len() {
            panic_with_error!(env, ContractError::InvalidOutcome);
        }

        if amount <= 0 {
            panic_with_error!(env, ContractError::StakeTooSmall);
        }

        // Update or record the user's bet
        let bet = BetData {
            outcome_index,
            amount,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Bet(market_id, user.clone()), &bet);

        // Maintain persistent user bet index for enumeration (#022)
        let mut user_markets: Vec<u32> = env
            .storage()
            .persistent()
            .get(&DataKey::UserBetMarkets(user.clone()))
            .unwrap_or(Vec::new(&env));

        if !user_markets.contains(market_id) {
            user_markets.push_back(market_id);
            env.storage()
                .persistent()
                .set(&DataKey::UserBetMarkets(user), &user_markets);
        }

        // Maintain market and outcome pool accounting (#014)
        let total_pool: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::MarketTotalPool(market_id))
            .unwrap_or(0);
        let new_total = match total_pool.checked_add(amount) {
            Some(t) => t,
            None => panic_with_error!(env, ContractError::Overflow),
        };
        env.storage()
            .persistent()
            .set(&DataKey::MarketTotalPool(market_id), &new_total);

        let outcome_pool: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::OutcomePool(market_id, outcome_index))
            .unwrap_or(0);
        let new_outcome_pool = match outcome_pool.checked_add(amount) {
            Some(t) => t,
            None => panic_with_error!(env, ContractError::Overflow),
        };
        env.storage().persistent().set(
            &DataKey::OutcomePool(market_id, outcome_index),
            &new_outcome_pool,
        );
    }

    /// Resolves a market by recording the winning outcome.
    ///
    /// Only the market creator or a platform admin may resolve a market.
    pub fn resolve_market(env: Env, resolver: Address, market_id: u32, winning_outcome: u32) {
        resolver.require_auth();

        let mut market: MarketData =
            match env.storage().persistent().get(&DataKey::Market(market_id)) {
                Some(m) => m,
                None => panic_with_error!(env, ContractError::MarketNotFound),
            };

        // Role check: resolver must be the market creator or a platform admin.
        if resolver != market.creator && !Self::is_admin_internal(&env, &resolver) {
            panic_with_error!(env, ContractError::Unauthorized);
        }

        if market.resolved {
            panic_with_error!(env, ContractError::MarketAlreadyResolved);
        }

        if winning_outcome >= market.outcome_tags.len() {
            panic_with_error!(env, ContractError::InvalidOutcome);
        }

        market.resolved = true;
        market.winning_outcome = winning_outcome;
        env.storage()
            .persistent()
            .set(&DataKey::Market(market_id), &market);
        let mut winning_outcomes = Vec::new(&env);
        winning_outcomes.push_back(winning_outcome);
        env.storage()
            .persistent()
            .set(&DataKey::WinningOutcomes(market_id), &winning_outcomes);
        let ttl = 6_307_200u32.min(env.storage().max_ttl());
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::WinningOutcomes(market_id), ttl, ttl);
    }

    /// Resolves a market with one or more winning outcomes.
    ///
    /// Only the market creator may resolve it, and only after betting closes.
    pub fn resolve_market_with_outcomes(
        env: Env,
        resolver: Address,
        market_id: u32,
        winning_outcomes: Vec<u32>,
    ) {
        resolver.require_auth();

        let mut market: MarketData =
            match env.storage().persistent().get(&DataKey::Market(market_id)) {
                Some(market) => market,
                None => panic_with_error!(env, ContractError::MarketNotFound),
            };

        if market.resolved {
            panic_with_error!(env, ContractError::MarketAlreadyResolved);
        }
        if market.cancelled {
            panic_with_error!(env, ContractError::InvalidState);
        }
        if resolver != market.creator {
            panic_with_error!(env, ContractError::Unauthorized);
        }
        if env.ledger().timestamp() < market.end_time {
            panic_with_error!(env, ContractError::MarketClosed);
        }
        if winning_outcomes.is_empty() {
            panic_with_error!(env, ContractError::InvalidConfig);
        }

        if winning_outcomes.len() > market.outcome_tags.len() {
            panic_with_error!(env, ContractError::InvalidConfig);
        }
        let mut seen = Map::<u32, bool>::new(&env);
        for outcome in winning_outcomes.iter() {
            if outcome >= market.outcome_tags.len() {
                panic_with_error!(env, ContractError::InvalidOutcome);
            }
            if seen.contains_key(outcome) {
                panic_with_error!(env, ContractError::InvalidConfig);
            }
            seen.set(outcome, true);
        }

        market.resolved = true;
        market.winning_outcome = winning_outcomes.get(0).unwrap();
        env.storage()
            .persistent()
            .set(&DataKey::Market(market_id), &market);
        env.storage()
            .persistent()
            .set(&DataKey::WinningOutcomes(market_id), &winning_outcomes);
        let ttl = 6_307_200u32.min(env.storage().max_ttl());
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::WinningOutcomes(market_id), ttl, ttl);
    }

    /// Previews the payout amount for a claimant on a market (#014).
    ///
    /// Outcome-split remainders are assigned in outcome order. Claim-time
    /// proportional remainders carry forward per outcome, preserving the
    /// allocated pool across claims; previews reflect prior claims.
    pub fn calculate_payout(env: Env, market_id: u32, claimant: Address) -> i128 {
        Self::calculate_payout_with_remainder(env, market_id, claimant).0
    }

    fn scaled_weight_boundary(env: &Env, total_pool: i128, cumulative_weight: u32) -> i128 {
        let whole = total_pool / 10_000;
        let fraction = total_pool % 10_000;
        let whole_share = match whole.checked_mul(cumulative_weight as i128) {
            Some(value) => value,
            None => panic_with_error!(env, ContractError::Overflow),
        };
        whole_share + (fraction * cumulative_weight as i128) / 10_000
    }

    fn custom_outcome_share(
        env: &Env,
        total_pool: i128,
        curve: &PayoutCurveConfig,
        outcome_index: u32,
    ) -> i128 {
        let mut cumulative_weight = 0u32;
        let mut index = 0u32;
        for weight in curve.custom_weights.iter() {
            if index == outcome_index {
                let next_weight = match cumulative_weight.checked_add(weight) {
                    Some(value) => value,
                    None => panic_with_error!(env, ContractError::InvalidPayoutCurve),
                };
                return Self::scaled_weight_boundary(env, total_pool, next_weight)
                    - Self::scaled_weight_boundary(env, total_pool, cumulative_weight);
            }
            cumulative_weight = match cumulative_weight.checked_add(weight) {
                Some(value) => value,
                None => panic_with_error!(env, ContractError::InvalidPayoutCurve),
            };
            index += 1;
        }
        0
    }

    fn proportional_payout(
        env: &Env,
        market_id: u32,
        outcome_index: u32,
        stake: i128,
        outcome_share: i128,
        outcome_pool: i128,
    ) -> (i128, Option<(u32, i128)>) {
        if outcome_pool <= 0 {
            return (0, None);
        }

        let key = DataKey::PayoutRemainder(market_id, outcome_index);
        let remainder: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let numerator = match stake
            .checked_mul(outcome_share)
            .and_then(|value| value.checked_add(remainder))
        {
            Some(value) => value,
            None => panic_with_error!(env, ContractError::Overflow),
        };
        (
            numerator / outcome_pool,
            Some((outcome_index, numerator % outcome_pool)),
        )
    }

    fn calculate_payout_with_remainder(
        env: Env,
        market_id: u32,
        claimant: Address,
    ) -> (i128, Option<(u32, i128)>) {
        let market: MarketData = match env.storage().persistent().get(&DataKey::Market(market_id)) {
            Some(m) => m,
            None => return (0, None),
        };
        if !market.resolved {
            return (0, None);
        }

        let bet: BetData = match env
            .storage()
            .persistent()
            .get(&DataKey::Bet(market_id, claimant))
        {
            Some(b) => b,
            None => return (0, None),
        };

        let curve: PayoutCurveConfig = env
            .storage()
            .persistent()
            .get(&DataKey::MarketPayoutCurve(market_id))
            .unwrap_or_else(|| PayoutCurveConfig::winner_takes_all(&env));
        let total_pool: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::MarketTotalPool(market_id))
            .unwrap_or(bet.amount);
        let win_pool: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::OutcomePool(market_id, market.winning_outcome))
            .unwrap_or(0);
        let winning_outcomes = Self::winning_outcomes(&env, market_id, &market);

        if winning_outcomes.len() > 1 {
            if !winning_outcomes.contains(bet.outcome_index) {
                return (0, None);
            }
            let outcome_pool: i128 = env
                .storage()
                .persistent()
                .get(&DataKey::OutcomePool(market_id, bet.outcome_index))
                .unwrap_or(0);
            if outcome_pool == 0 {
                return (bet.amount, None);
            }

            let winner_count = winning_outcomes.len() as i128;
            let mut rank = 0i128;
            for outcome in winning_outcomes.iter() {
                if outcome == bet.outcome_index {
                    break;
                }
                rank += 1;
            }
            let base_share = total_pool / winner_count;
            let extra_units = total_pool % winner_count;
            let outcome_share = base_share + if rank < extra_units { 1 } else { 0 };
            return Self::proportional_payout(
                &env,
                market_id,
                bet.outcome_index,
                bet.amount,
                outcome_share,
                outcome_pool,
            );
        }

        match curve.curve_type {
            PayoutCurveConfig::WINNER_TAKES_ALL => {
                if bet.outcome_index != market.winning_outcome {
                    return (0, None);
                }
                if win_pool == 0 {
                    return (bet.amount, None);
                }
                Self::proportional_payout(
                    &env,
                    market_id,
                    bet.outcome_index,
                    bet.amount,
                    total_pool,
                    win_pool,
                )
            }
            PayoutCurveConfig::TIERED => {
                let ru_pool: i128 = env
                    .storage()
                    .persistent()
                    .get(&DataKey::OutcomePool(market_id, curve.runner_up_outcome))
                    .unwrap_or(0);

                if ru_pool == 0 {
                    if bet.outcome_index == market.winning_outcome {
                        if win_pool == 0 {
                            return (bet.amount, None);
                        }
                        return Self::proportional_payout(
                            &env,
                            market_id,
                            bet.outcome_index,
                            bet.amount,
                            total_pool,
                            win_pool,
                        );
                    }
                    return (0, None);
                }

                if win_pool == 0 {
                    if bet.outcome_index == curve.runner_up_outcome {
                        return Self::proportional_payout(
                            &env,
                            market_id,
                            bet.outcome_index,
                            bet.amount,
                            total_pool,
                            ru_pool,
                        );
                    }
                    return (0, None);
                }

                let ru_share =
                    Self::scaled_weight_boundary(&env, total_pool, curve.runner_up_bps);
                let win_share = total_pool - ru_share;
                if bet.outcome_index == market.winning_outcome {
                    Self::proportional_payout(
                        &env,
                        market_id,
                        bet.outcome_index,
                        bet.amount,
                        win_share,
                        win_pool,
                    )
                } else if bet.outcome_index == curve.runner_up_outcome {
                    Self::proportional_payout(
                        &env,
                        market_id,
                        bet.outcome_index,
                        bet.amount,
                        ru_share,
                        ru_pool,
                    )
                } else {
                    (0, None)
                }
            }
            PayoutCurveConfig::CUSTOM_WEIGHTS => {
                let weight = curve.custom_weights.get(bet.outcome_index).unwrap_or(0);
                if weight == 0 {
                    return (0, None);
                }
                let outcome_pool: i128 = env
                    .storage()
                    .persistent()
                    .get(&DataKey::OutcomePool(market_id, bet.outcome_index))
                    .unwrap_or(0);
                if outcome_pool == 0 {
                    return (0, None);
                }
                let outcome_share =
                    Self::custom_outcome_share(&env, total_pool, &curve, bet.outcome_index);
                Self::proportional_payout(
                    &env,
                    market_id,
                    bet.outcome_index,
                    bet.amount,
                    outcome_share,
                    outcome_pool,
                )
            }
            _ => (0, None),
        }
    }

    /// Claims winnings for a resolved market upholding CEI pattern and applying
    /// the configured payout curve (#014, #021).
    pub fn claim_winnings(env: Env, claimant: Address, market_id: u32) -> i128 {
        claimant.require_auth();

        // ── CHECKS ───────────────────────────────────────────────────────────
        let market: MarketData = match env.storage().persistent().get(&DataKey::Market(market_id)) {
            Some(m) => m,
            None => panic_with_error!(env, ContractError::MarketNotFound),
        };

        if !market.resolved {
            panic_with_error!(env, ContractError::MarketNotResolved);
        }

        // Guard against double claim (CEI pattern)
        if env
            .storage()
            .persistent()
            .has(&DataKey::ClaimedBet(market_id, claimant.clone()))
        {
            panic_with_error!(env, ContractError::AlreadyClaimed);
        }

        let bet: BetData = match env
            .storage()
            .persistent()
            .get(&DataKey::Bet(market_id, claimant.clone()))
        {
            Some(b) => b,
            None => panic_with_error!(env, ContractError::InvalidState),
        };

        let (payout, remainder) =
            Self::calculate_payout_with_remainder(env.clone(), market_id, claimant.clone());
        if payout < 0 || (payout == 0 && remainder.is_none()) {
            panic_with_error!(env, ContractError::InvalidOutcome);
        }

        // ── EFFECTS ──────────────────────────────────────────────────────────
        if let Some((outcome_index, value)) = remainder {
            env.storage().persistent().set(
                &DataKey::PayoutRemainder(market_id, outcome_index),
                &value,
            );
        }
        // Mark bet as claimed before external interaction
        env.storage()
            .persistent()
            .set(&DataKey::ClaimedBet(market_id, claimant.clone()), &true);

        // ── INTERACTIONS ─────────────────────────────────────────────────────
        let _ = bet.amount;

        payout
    }

    /// Cancels a market before it has been resolved.
    pub fn cancel_market(env: Env, caller: Address, market_id: u32) {
        caller.require_auth();

        let mut market: MarketData =
            match env.storage().persistent().get(&DataKey::Market(market_id)) {
                Some(m) => m,
                None => panic_with_error!(env, ContractError::MarketNotFound),
            };

        if market.resolved {
            panic_with_error!(env, ContractError::MarketAlreadyResolved);
        }
        if market.cancelled {
            panic_with_error!(env, ContractError::InvalidState);
        }

        market.cancelled = true;
        env.storage()
            .persistent()
            .set(&DataKey::Market(market_id), &market);
    }

    /// Withdraws funds from a market.
    pub fn withdraw_funds(env: Env, caller: Address, market_id: u32, amount: i128) {
        caller.require_auth();

        if !env.storage().persistent().has(&DataKey::Market(market_id)) {
            panic_with_error!(env, ContractError::MarketNotFound);
        }

        let _ = amount;
    }

    /// Updates the parameters of an existing market.
    pub fn update_market_params(env: Env, caller: Address, market_id: u32, new_end_time: u64) {
        caller.require_auth();

        let market: MarketData = match env.storage().persistent().get(&DataKey::Market(market_id)) {
            Some(m) => m,
            None => panic_with_error!(env, ContractError::MarketNotFound),
        };

        if market.resolved {
            panic_with_error!(env, ContractError::MarketAlreadyResolved);
        }

        let _ = new_end_time;
    }

    // -----------------------------------------------------------------------
    //  Initialization
    // -----------------------------------------------------------------------

    /// @notice Initializes the contract by setting the initial admin.
    /// @dev    Stores `DataKey::Admin` and `DataKey::Initialized` atomically.
    ///         Must be called exactly once after deployment before any admin
    ///         entrypoint can be used.
    /// @param env   The contract environment.
    /// @param admin The initial admin/owner address.
    /// @return `Ok(())` on success, or a [`ContractError`] variant.
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        // Require the caller to authenticate before any state mutation.
        admin.require_auth();

        // Prevent re-initialization.
        if Self::is_initialized(&env) {
            return Err(ContractError::AdminOperationNotPermitted);
        }

        env.storage().instance().set(&DataKey::Initialized, &true);
        env.storage().instance().set(&DataKey::Admin, &admin);
        // Markets start unpaused.
        env.storage().instance().set(&DataKey::Paused, &false);

        Ok(())
    }

    // -----------------------------------------------------------------------
    //  Admin-gated entrypoints
    // -----------------------------------------------------------------------

    /// @notice Pauses all markets globally.
    /// @dev    Requires the caller to be the registered admin.
    /// @param env    The contract environment.
    /// @param caller The admin address (must pass auth and admin check).
    /// @return `Ok(())` on success, or a [`ContractError`] variant.
    pub fn pause_markets(env: Env, caller: Address) -> Result<(), ContractError> {
        caller.require_auth();
        Self::assert_is_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::Paused, &true);
        Ok(())
    }

    /// @notice Unpauses all markets globally.
    /// @dev    Requires the caller to be the registered admin.
    /// @param env    The contract environment.
    /// @param caller The admin address (must pass auth and admin check).
    /// @return `Ok(())` on success, or a [`ContractError`] variant.
    pub fn unpause_markets(env: Env, caller: Address) -> Result<(), ContractError> {
        caller.require_auth();
        Self::assert_is_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::Paused, &false);
        Ok(())
    }

    /// @notice Transfers contract ownership to a new admin address.
    /// @dev    Requires the caller to be the registered admin. The new admin
    ///         must differ from the current admin.
    /// @param env         The contract environment.
    /// @param current_admin The current admin (must pass auth and admin check).
    /// @param new_admin    The new admin address to set.
    /// @return `Ok(())` on success, or a [`ContractError`] variant.
    pub fn transfer_ownership(
        env: Env,
        current_admin: Address,
        new_admin: Address,
    ) -> Result<(), ContractError> {
        current_admin.require_auth();
        Self::assert_is_admin(&env, &current_admin)?;

        if new_admin == current_admin {
            return Err(ContractError::AdminAddressInvalid);
        }

        env.storage().instance().set(&DataKey::Admin, &new_admin);
        Ok(())
    }

    /// @notice Adds a second admin address (co-admin).
    /// @dev    Requires the caller to be the registered admin. Currently only
    ///         stores a single admin; this entrypoint replaces the admin with
    ///         the new address and is kept for forward compatibility with a
    ///         multi-admin model.
    /// @param env        The contract environment.
    /// @param caller     The current admin (must pass auth and admin check).
    /// @param new_admin  The admin address to add.
    /// @return `Ok(())` on success, or a [`ContractError`] variant.
    pub fn add_admin(
        env: Env,
        caller: Address,
        new_admin: Address,
    ) -> Result<(), ContractError> {
        caller.require_auth();
        Self::assert_is_admin(&env, &caller)?;

        if new_admin == caller {
            return Err(ContractError::AdminAddressInvalid);
        }

        // Store the new admin alongside the existing admin.
        // For now we support a single admin; this entrypoint replaces it.
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        Ok(())
    }

    // -----------------------------------------------------------------------
    //  Read-only admin queries
    // -----------------------------------------------------------------------

    /// @notice Returns the current admin address.
    /// @dev    Read-only — does not require auth. Returns `None` if not set.
    /// @param env The contract environment.
    /// @return `Some(Address)` if an admin is set, `None` otherwise.
    pub fn get_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Admin)
    }

    /// @notice Returns whether the markets subsystem is globally paused.
    /// @dev    Read-only — does not require auth.
    /// @param env The contract environment.
    /// @return `true` if paused, `false` otherwise.
    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    // -----------------------------------------------------------------------
    //  Internal helpers
    // -----------------------------------------------------------------------

    /// Sets the maximum number of markets that may be created. A zero limit
    /// disables market creation; a limit below the current count blocks new markets.
    pub fn set_market_limit(env: Env, admin: Address, max_market_count: u32) {
        Self::require_admin(&env, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::MarketLimit, &max_market_count);
    }

    /// Configures the pause protection parameters (delay and required approvals) (#007).
    pub fn set_pause_config(env: Env, admin: Address, delay_seconds: u64, required_approvals: u32) {
        Self::require_admin(&env, &admin);

        if required_approvals == 0 {
            panic_with_error!(env, ContractError::InvalidConfig);
        }

        env.storage()
            .persistent()
            .set(&DataKey::PauseDelaySeconds, &delay_seconds);
        env.storage()
            .persistent()
            .set(&DataKey::PauseRequiredApprovals, &required_approvals);
    }

    /// Returns the configured pause protection parameters (delay_seconds, required_approvals) (#007).
    pub fn get_pause_config(env: Env) -> (u64, u32) {
        let delay: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::PauseDelaySeconds)
            .unwrap_or(0);
        let approvals: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::PauseRequiredApprovals)
            .unwrap_or(1);
        (delay, approvals)
    }

    /// Adds an administrator to the authorized admin list (#007).
    pub fn add_admin(env: Env, admin: Address, new_admin: Address) {
        Self::require_admin(&env, &admin);

        let mut list: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::AdminList)
            .unwrap_or(Vec::new(&env));

        if !list.contains(&new_admin) {
            list.push_back(new_admin);
            env.storage().persistent().set(&DataKey::AdminList, &list);
        }
    }

    /// Proposes a global market pause with a stated justification (#007).
    pub fn propose_pause(env: Env, admin: Address, reason: String) -> u32 {
        Self::require_admin(&env, &admin);

        let counter: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::PauseProposalCounter)
            .unwrap_or(0);

        let proposal_id = match counter.checked_add(1) {
            Some(id) => id,
            None => panic_with_error!(env, ContractError::Overflow),
        };
        env.storage()
            .persistent()
            .set(&DataKey::PauseProposalCounter, &proposal_id);

        let (delay, _) = Self::get_pause_config(env.clone());
        let now = env.ledger().timestamp();
        let eta = match now.checked_add(delay) {
            Some(t) => t,
            None => panic_with_error!(env, ContractError::Overflow),
        };

        let mut approvals = Vec::new(&env);
        approvals.push_back(admin.clone());

        let proposal = PauseProposal {
            id: proposal_id,
            proposer: admin,
            reason,
            created_at: now,
            eta,
            approvals,
            executed: false,
            cancelled: false,
        };

        env.storage()
            .instance()
            .get(&DataKey::Initialized)
            .unwrap_or(false)
    }

    /// @notice Returns the stored admin address, or `None` if unset.
    fn get_admin_internal(env: &Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Admin)
    }

    /// @notice Checks whether `caller` is the registered admin.
    /// @dev    Returns `false` when no admin is stored (does **not** return
    ///         `true` for an unset admin — this closes the bootstrap hole).
    /// @param env    The contract environment.
    /// @param caller The address to check.
    /// @return `true` if the caller matches the stored admin, `false` otherwise.
    fn is_admin_internal(env: &Env, caller: &Address) -> bool {
        match Self::get_admin_internal(env) {
            Some(admin) => admin == *caller,
            None => false,
        }
    }

    /// @notice Asserts that `caller` is the registered admin.
    /// @dev    Returns `Err(ContractError::Unauthorized)` when the admin is
    ///         unset or the caller does not match.
    /// @param env    The contract environment.
    /// @param caller The address to verify.
    /// @return `Ok(())` if the caller is the admin, or a [`ContractError`].
    fn assert_is_admin(env: &Env, caller: &Address) -> Result<(), ContractError> {
        if !Self::is_admin_internal(env, caller) {
            return Err(ContractError::Unauthorized);
        }
        Ok(())
    }

}
