//! The three outcomes of MemoryBudgetStore::try_consume (audit P0-2/P1-4/P2-1).

use veritell_token::{BudgetStore, Consumed, MemoryBudgetStore};

const NOW: u64 = 1_800_000_000;

#[test]
fn used_then_spent() {
    let s = MemoryBudgetStore::new(10);
    assert_eq!(s.try_consume(&[1; 16], 2, NOW + 60, NOW), Consumed::Used);
    assert_eq!(s.try_consume(&[1; 16], 2, NOW + 60, NOW), Consumed::Used);
    assert_eq!(s.try_consume(&[1; 16], 2, NOW + 60, NOW), Consumed::Spent);
    assert_eq!(s.try_consume(&[2; 16], 0, NOW + 60, NOW), Consumed::Spent);
}

#[test]
fn a_full_store_says_full_not_spent() {
    let s = MemoryBudgetStore::new(2);
    assert_eq!(s.try_consume(&[1; 16], 1, NOW + 60, NOW), Consumed::Used);
    assert_eq!(s.try_consume(&[2; 16], 1, NOW + 60, NOW), Consumed::Used);
    // A new id with no room: not a replay.
    assert_eq!(s.try_consume(&[3; 16], 1, NOW + 60, NOW), Consumed::Full);
    // An id already there is still judged on its own budget.
    assert_eq!(s.try_consume(&[1; 16], 1, NOW + 60, NOW), Consumed::Spent);
    // Once entries expire there is room again.
    assert_eq!(s.try_consume(&[3; 16], 1, NOW + 200, NOW + 61), Consumed::Used);
}

#[test]
fn consume_is_yes_only_for_used() {
    let s = MemoryBudgetStore::new(1);
    assert!(s.consume(&[1; 16], 1, NOW + 60, NOW));
    assert!(!s.consume(&[1; 16], 1, NOW + 60, NOW));
    assert!(!s.consume(&[2; 16], 1, NOW + 60, NOW));
}

#[test]
fn a_failed_challenges_difficulty_can_be_read_back_but_not_forged() {
    use veritell_token::pow;
    use veritell_token::{Binding, Keys};
    let keys = Keys::from_secret(b"0123456789abcdef0123456789abcdef").unwrap();
    let other = Keys::from_secret(b"another secret, 32 bytes long!!!").unwrap();
    let binding = Binding([1; 16]);
    let ch = pow::issue_challenge(&keys, &binding, NOW, 120, 14);
    assert_eq!(pow::issued_difficulty(&keys, &ch), Some(14));
    // Expired, or for another client: still ours, still readable.
    assert!(pow::verify_solution(&keys, &ch, 0, &Binding([2; 16]), NOW + 500).is_err());
    assert_eq!(pow::issued_difficulty(&keys, &ch), Some(14));
    // Signed with other keys, or garbage: not ours.
    assert_eq!(pow::issued_difficulty(&other, &ch), None);
    assert_eq!(pow::issued_difficulty(&keys, "8.not-a-challenge"), None);
}
