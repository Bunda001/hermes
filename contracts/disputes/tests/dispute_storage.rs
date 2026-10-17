use disputes::{
    DisputeOutcome, DisputeStatus, DisputesContract, DisputesContractClient,
};
use soroban_sdk::{Env, Symbol};

#[test]
fn dispute_lifecycle_is_persisted_and_uses_unique_ids() {
    let env = Env::default();
    let contract_id = env.register(DisputesContract, ());
    let client = DisputesContractClient::new(&env, &contract_id);
    let market_id = Symbol::new(&env, "MARKET1");
    let creator = Symbol::new(&env, "CREATOR");

    let opened = client.open_dispute(&market_id, &creator);
    assert_eq!(opened.id, 1);
    assert_eq!(opened.status, DisputeStatus::Open);
    assert_eq!(client.get_dispute(&opened.id), Some(opened.clone()));

    let mut stale_input = opened.clone();
    stale_input.creator = Symbol::new(&env, "FORGED");
    let voting = client.start_voting(&stale_input);
    assert_eq!(voting.creator, creator);
    assert_eq!(voting.status, DisputeStatus::Voting);
    assert_eq!(client.get_dispute(&opened.id), Some(voting.clone()));

    let resolved = client.resolve_dispute(&voting, &DisputeOutcome::ChallengerWins);
    assert_eq!(resolved.status, DisputeStatus::Resolved);
    assert_eq!(resolved.outcome, DisputeOutcome::ChallengerWins);
    assert_eq!(client.get_dispute(&opened.id), Some(resolved));

    let second = client.open_dispute(&Symbol::new(&env, "MARKET2"), &creator);
    assert_eq!(second.id, 2);
    let withdrawn = client.withdraw_dispute(&second, &creator);
    assert_eq!(withdrawn.status, DisputeStatus::Withdrawn);
    assert_eq!(client.get_dispute(&second.id), Some(withdrawn));
}