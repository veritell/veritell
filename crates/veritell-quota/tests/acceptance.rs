//! Acceptance tests written by the project lead. DO NOT EDIT.

use std::sync::Arc;

use veritell_quota::*;

/// The start of a day and of a slot: 19676 * 86400.
const T0: u64 = 1_700_006_400;

fn config() -> Config {
    Config { hash_seed: Some([7; 16]), ..Config::default() }
}

fn quotas() -> Quotas {
    Quotas::new(config()).unwrap()
}

#[test]
fn t0_is_where_the_tests_think_it_is() {
    assert_eq!(T0 % 86_400, 0);
    assert_eq!(T0 % 10, 0);
}

// ---- configuration ----

#[test]
fn configuration_is_checked() {
    for bad in [
        Config { slot_secs: 0, ..config() },
        Config { window_slots: 0, ..config() },
        Config { day_secs: 0, ..config() },
        Config { max_identities: 0, ..config() },
        // Zero is reported before TooLarge.
        Config { slot_secs: 0, window_slots: 61, ..config() },
    ] {
        assert_eq!(Quotas::new(bad).err(), Some(ConfigError::Zero));
    }
    for bad in [
        Config { slot_secs: 3601, ..config() },
        Config { window_slots: 61, ..config() },
        Config { max_identities: 1_000_001, ..config() },
    ] {
        assert_eq!(Quotas::new(bad).err(), Some(ConfigError::TooLarge));
    }
    for good in [
        Config { slot_secs: 3600, window_slots: 60, max_identities: 1_000_000, ..config() },
        Config { slot_secs: 1, window_slots: 1, day_secs: 1, max_identities: 1, ..config() },
        Config { hash_seed: None, ..config() },
    ] {
        assert!(Quotas::new(good).is_ok());
    }
}

// ---- rate ----

#[test]
fn rate_allows_up_to_the_limit_in_one_window() {
    let q = quotas();
    assert!(q.allow_rate("a", 3, T0));
    assert!(q.allow_rate("a", 3, T0 + 1));
    assert!(q.allow_rate("a", 3, T0 + 9));
    assert!(!q.allow_rate("a", 3, T0 + 9));
    // T0+59 is slot 5: the window is slots 0..=5 and still holds all three.
    assert!(!q.allow_rate("a", 3, T0 + 59));
    // T0+60 is slot 6: the window is slots 1..=6, slot 0 has left it.
    assert!(q.allow_rate("a", 3, T0 + 60));
}

#[test]
fn rate_window_slides_by_slots() {
    let q = quotas();
    // Slot 0: two. Slot 3: one. Limit 3.
    assert!(q.allow_rate("a", 3, T0));
    assert!(q.allow_rate("a", 3, T0 + 5));
    assert!(q.allow_rate("a", 3, T0 + 30));
    assert!(!q.allow_rate("a", 3, T0 + 31));
    // Slot 6: window 1..=6 holds slot 3's one. Two more fit.
    assert!(q.allow_rate("a", 3, T0 + 60));
    assert!(q.allow_rate("a", 3, T0 + 61));
    assert!(!q.allow_rate("a", 3, T0 + 62));
    // Slot 9: window 4..=9 holds slot 6's two. One more fits.
    assert!(q.allow_rate("a", 3, T0 + 90));
    assert!(!q.allow_rate("a", 3, T0 + 99));
    // Slot 20: everything has left the window.
    assert!(q.allow_rate("a", 3, T0 + 200));
    assert!(q.allow_rate("a", 3, T0 + 200));
    assert!(q.allow_rate("a", 3, T0 + 200));
    assert!(!q.allow_rate("a", 3, T0 + 200));
}

#[test]
fn a_refused_request_is_not_counted() {
    let q = quotas();
    assert!(q.allow_rate("a", 2, T0));
    assert!(q.allow_rate("a", 2, T0));
    for _ in 0..50 {
        // Slot 1.
        assert!(!q.allow_rate("a", 2, T0 + 10));
    }
    // Slot 6: window 1..=6. Had the refusals been counted it would be full.
    assert!(q.allow_rate("a", 2, T0 + 60));
    assert!(q.allow_rate("a", 2, T0 + 60));
    assert!(!q.allow_rate("a", 2, T0 + 60));
}

#[test]
fn rate_limit_zero_and_changing_limits() {
    let q = quotas();
    assert!(!q.allow_rate("a", 0, T0));
    assert!(q.allow_rate("a", 1, T0));
    assert!(!q.allow_rate("a", 1, T0));
    // The count is compared with whatever limit this call names.
    assert!(q.allow_rate("a", 5, T0));
    assert!(!q.allow_rate("a", 2, T0));
    assert!(q.allow_rate("a", u32::MAX, T0));
}

#[test]
fn identities_do_not_share_a_rate() {
    let q = quotas();
    assert!(q.allow_rate("agent-a", 1, T0));
    assert!(!q.allow_rate("agent-a", 1, T0));
    assert!(q.allow_rate("agent-b", 1, T0));
    assert!(q.allow_rate("", 1, T0));
    assert!(q.allow_rate("agent-a\0", 1, T0));
    assert!(q.allow_rate("AGENT-A", 1, T0));
}

#[test]
fn the_whole_identity_counts_whatever_its_length() {
    let q = quotas();
    let long = "x".repeat(100_000);
    let other = format!("{long}y");
    assert!(q.allow_rate(&long, 1, T0));
    assert!(!q.allow_rate(&long, 1, T0));
    assert!(q.allow_rate(&other, 1, T0));
    assert_eq!(q.take(&long, 2, T0), 2);
    assert_eq!(q.take(&other, 2, T0), 2);
    assert_eq!(q.take(&long, 2, T0), 1);
    assert_eq!(q.tracked(), 2);
}

#[test]
fn a_clock_that_steps_back_gives_nothing_back() {
    let q = quotas();
    assert!(q.allow_rate("a", 2, T0 + 100));
    assert!(q.allow_rate("a", 2, T0 + 100));
    // Earlier times are treated as T0+100.
    assert!(!q.allow_rate("a", 2, T0));
    assert!(!q.allow_rate("a", 2, 0));
    // The latest time is shared by every identity and every method.
    assert!(q.allow_rate("b", 1, T0 + 1000));
    // "a" at "T0" is now seen at T0+1000: its window is empty again.
    assert!(q.allow_rate("a", 2, T0));
}

// ---- day ----

#[test]
fn a_day_counts_down_and_starts_again_the_next_day() {
    let q = quotas();
    assert_eq!(q.left("a", 3, T0), 3);
    assert_eq!(q.take("a", 3, T0), 3);
    assert_eq!(q.take("a", 3, T0 + 1), 2);
    assert_eq!(q.left("a", 3, T0 + 1), 1);
    assert_eq!(q.take("a", 3, T0 + 40_000), 1);
    assert_eq!(q.take("a", 3, T0 + 40_001), 0);
    assert_eq!(q.take("a", 3, T0 + 86_399), 0);
    assert_eq!(q.left("a", 3, T0 + 86_399), 0);
    // The next day.
    assert_eq!(q.left("a", 3, T0 + 86_400), 3);
    assert_eq!(q.take("a", 3, T0 + 86_400), 3);
    assert_eq!(q.take("a", 3, T0 + 86_401), 2);
}

#[test]
fn the_rate_window_does_not_touch_the_day() {
    let q = quotas();
    assert_eq!(q.take("a", 5, T0), 5);
    assert_eq!(q.take("a", 5, T0), 4);
    // Many windows come and go inside the day.
    for step in 1..=100u64 {
        assert!(q.allow_rate("a", 1, T0 + step * 600));
    }
    assert_eq!(q.take("a", 5, T0 + 70_000), 3);
    // And the day does not touch the rate.
    assert!(q.allow_rate("b", 1, T0 + 70_000));
    assert_eq!(q.take("b", 1, T0 + 70_000), 1);
    assert_eq!(q.take("b", 1, T0 + 70_000), 0);
    assert!(!q.allow_rate("b", 1, T0 + 70_001));
}

#[test]
fn a_clock_that_steps_back_does_not_reopen_a_day() {
    let q = quotas();
    assert_eq!(q.take("a", 3, T0 + 86_400), 3);
    // Yesterday, by the caller's clock: still counted against today.
    assert_eq!(q.take("a", 3, T0 + 5), 2);
    assert_eq!(q.left("a", 3, T0), 1);
    assert_eq!(q.take("a", 3, 0), 1);
    assert_eq!(q.take("a", 3, T0 + 86_400), 0);
}

#[test]
fn a_quota_below_what_was_taken_reads_zero() {
    let q = quotas();
    assert_eq!(q.take("a", 10, T0), 10);
    assert_eq!(q.take("a", 10, T0), 9);
    assert_eq!(q.take("a", 1, T0), 0);
    assert_eq!(q.take("a", 0, T0), 0);
    // Nothing was taken by the two calls above.
    assert_eq!(q.take("a", 10, T0), 8);
    assert_eq!(q.take("a", u32::MAX, T0), u32::MAX - 3);
}

#[test]
fn identities_do_not_share_a_day() {
    let q = quotas();
    assert_eq!(q.take("a", 1, T0), 1);
    assert_eq!(q.take("a", 1, T0), 0);
    assert_eq!(q.take("b", 1, T0), 1);
    assert_eq!(q.left("c", 1, T0), 1);
}

// ---- bounds ----

#[test]
fn the_least_recently_used_identity_is_forgotten() {
    let q = Quotas::new(Config { max_identities: 2, ..config() }).unwrap();
    assert_eq!(q.take("a", 3, T0), 3);
    assert_eq!(q.take("b", 3, T0), 3);
    assert_eq!(q.tracked(), 2);
    // "c" pushes out "a".
    assert_eq!(q.take("c", 3, T0), 3);
    assert_eq!(q.tracked(), 2);
    // "a" starts afresh and pushes out "b"; "c" is still known.
    assert_eq!(q.take("a", 3, T0), 3);
    assert_eq!(q.take("c", 3, T0), 2);
    assert_eq!(q.take("b", 3, T0), 3);
    assert_eq!(q.tracked(), 2);
}

#[test]
fn use_order_not_the_clock_decides_who_is_forgotten() {
    let q = Quotas::new(Config { max_identities: 2, ..config() }).unwrap();
    assert_eq!(q.take("a", 3, T0), 3);
    assert_eq!(q.take("b", 3, T0), 3);
    // A rate check is a use too: "a" is now the most recent.
    assert!(q.allow_rate("a", 9, T0));
    assert_eq!(q.take("c", 3, T0), 3);
    assert_eq!(q.take("a", 3, T0), 2);
}

#[test]
fn left_tracks_nothing_and_is_not_a_use() {
    let q = Quotas::new(Config { max_identities: 2, ..config() }).unwrap();
    assert_eq!(q.left("ghost", 3, T0), 3);
    assert_eq!(q.tracked(), 0);
    assert_eq!(q.take("a", 3, T0), 3);
    assert_eq!(q.take("b", 3, T0), 3);
    // Looking at "a" does not make it recent: "c" still pushes it out.
    assert_eq!(q.left("a", 3, T0), 2);
    assert_eq!(q.take("c", 3, T0), 3);
    assert_eq!(q.left("a", 3, T0), 3);
    assert_eq!(q.left("b", 3, T0), 2);
    assert_eq!(q.tracked(), 2);
}

#[test]
fn memory_is_bounded_whatever_arrives() {
    let q = Quotas::new(Config { max_identities: 100, ..config() }).unwrap();
    for n in 0..10_000u32 {
        let id = format!("identity-{n}");
        assert!(q.allow_rate(&id, 1, T0 + u64::from(n)));
        assert_eq!(q.take(&id, 1, T0 + u64::from(n)), 1);
        assert!(q.tracked() <= 100);
    }
    assert_eq!(q.tracked(), 100);
}

#[test]
fn extreme_values_do_not_panic() {
    let q = Quotas::new(Config { slot_secs: 3600, window_slots: 60, ..config() }).unwrap();
    for now in [0, 1, u64::MAX - 1, u64::MAX, 0] {
        let _ = q.allow_rate("a", u32::MAX, now);
        let _ = q.take("a", u32::MAX, now);
        let _ = q.left("a", u32::MAX, now);
    }
    let q = Quotas::new(Config { slot_secs: 1, window_slots: 1, day_secs: 1, max_identities: 1, ..config() }).unwrap();
    assert!(q.allow_rate("a", 1, 5));
    assert!(!q.allow_rate("a", 1, 5));
    assert!(q.allow_rate("a", 1, 6));
    assert_eq!(q.take("a", 1, 6), 1);
    assert_eq!(q.take("a", 1, 6), 0);
    assert_eq!(q.take("a", 1, 7), 1);
}

#[test]
fn shared_across_threads_the_limit_is_exact() {
    let q = Arc::new(quotas());
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let q = Arc::clone(&q);
            std::thread::spawn(move || {
                let mut allowed = 0u32;
                let mut taken = 0u32;
                for _ in 0..500 {
                    if q.allow_rate("shared", 1000, T0) {
                        allowed += 1;
                    }
                    if q.take("shared", 700, T0) > 0 {
                        taken += 1;
                    }
                }
                (allowed, taken)
            })
        })
        .collect();
    let (mut allowed, mut taken) = (0, 0);
    for h in handles {
        let (a, t) = h.join().unwrap();
        allowed += a;
        taken += t;
    }
    assert_eq!(allowed, 1000);
    assert_eq!(taken, 700);
}
