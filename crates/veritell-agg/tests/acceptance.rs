//! Acceptance tests written by the project lead. DO NOT EDIT.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use veritell_agg::*;
use veritell_core::{Class, Layer};

const T0: u64 = 1_700_000_000; // a multiple of 10: the start of a slot

fn config() -> Config {
    // The route rule is switched off here so that it cannot add to what
    // the other tests count; its own test switches it back on.
    Config { warmup_secs: 0, route_min_requests: u32::MAX, hash_seed: Some([7; 16]), ..Config::default() }
}

fn agg(config: Config) -> Aggregates {
    Aggregates::new(config).unwrap()
}

/// The n-th /24 network, host `.9`.
fn net(n: u32) -> IpAddr {
    let n = n + 0x0100_0000; // start at 1.0.0.x
    IpAddr::V4(Ipv4Addr::new((n >> 16) as u8, (n >> 8) as u8, n as u8, 9))
}

fn client(n: u32) -> [u8; 16] {
    let mut c = [0u8; 16];
    c[..4].copy_from_slice(&n.to_be_bytes());
    c
}

fn see(a: &Aggregates, fp: &str, ip: IpAddr, now: u64) -> Vec<String> {
    see_as(a, fp, ip, client(0), "/", now)
}

fn see_as(a: &Aggregates, fp: &str, ip: IpAddr, client: [u8; 16], route: &str, now: u64) -> Vec<String> {
    a.observe(&Observation { fingerprint: fp, ip, client, route }, now)
        .into_iter()
        .map(|d| d.id)
        .collect()
}

fn has(ids: &[String], id: &str) -> bool {
    ids.iter().any(|i| i == id)
}

// ---- helpers and configuration ----

#[test]
fn networks_are_slash_24_and_slash_48() {
    let a = network_of("203.0.113.7".parse().unwrap());
    assert_eq!(a, network_of("203.0.113.250".parse().unwrap()));
    assert_ne!(a, network_of("203.0.114.7".parse().unwrap()));
    assert_eq!(a, network_of("::ffff:203.0.113.99".parse().unwrap()));
    let b = network_of("2001:db8:1:2::1".parse().unwrap());
    assert_eq!(b, network_of("2001:db8:1:ffff::9".parse().unwrap()));
    assert_ne!(b, network_of("2001:db8:2:2::1".parse().unwrap()));
    assert_ne!(network_of(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), network_of(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
}

#[test]
fn bad_configuration_is_refused() {
    for c in [
        Config { slot_secs: 0, ..config() },
        Config { window_slots: 0, ..config() },
        Config { max_keys: 0, ..config() },
    ] {
        assert_eq!(Aggregates::new(c).err(), Some(ConfigError::Zero));
    }
    for c in [
        Config { slot_secs: 3601, ..config() },
        Config { window_slots: 61, ..config() },
        Config { max_keys: 1_000_001, ..config() },
    ] {
        assert_eq!(Aggregates::new(c).err(), Some(ConfigError::TooLarge));
    }
    assert!(Aggregates::new(Config::default()).is_ok());
}

// ---- counting and windows ----

#[test]
fn requests_are_counted_exactly_and_roll_out_of_the_window() {
    let a = agg(config());
    // Window is 6 slots of 10 s. Three requests in the first slot, two in the fourth.
    for _ in 0..3 {
        see(&a, "fp", net(1), T0 + 9);
    }
    for _ in 0..2 {
        see(&a, "fp", net(1), T0 + 30);
    }
    assert_eq!(a.requests("fp", T0 + 30), 5);
    assert_eq!(a.requests("other", T0 + 30), 0);
    // Last second in which the first slot is still inside the window.
    assert_eq!(a.requests("fp", T0 + 59), 5);
    // One second later the first slot has left.
    assert_eq!(a.requests("fp", T0 + 60), 2);
    assert_eq!(a.requests("fp", T0 + 89), 2);
    assert_eq!(a.requests("fp", T0 + 90), 0);
    // Much later, and after a long silence, nothing is left and nothing breaks.
    assert_eq!(a.requests("fp", T0 + 10_000_000), 0);
    see(&a, "fp", net(1), T0 + 10_000_000);
    assert_eq!(a.requests("fp", T0 + 10_000_000), 1);
}

#[test]
fn time_going_backwards_is_treated_as_now() {
    let a = agg(config());
    see(&a, "fp", net(1), T0 + 100);
    see(&a, "fp", net(2), T0); // a late clock: counted in the latest slot
    assert_eq!(a.requests("fp", T0 + 100), 2);
    assert_eq!(a.requests("fp", T0), 2);
    see(&a, "fp", net(3), 0);
    assert_eq!(a.requests("fp", T0 + 100), 3);
}

#[test]
fn distinct_networks_are_estimated_within_the_stated_error() {
    for (n, slack) in [(1u32, 0u64), (5, 3), (19, 3), (50, 15), (100, 30), (1_000, 300), (5_000, 1_500), (20_000, 6_000)] {
        let a = agg(config());
        for i in 0..n {
            // Spread over three slots, each network seen twice, two hosts each.
            let t = T0 + u64::from(i % 3) * 10;
            see(&a, "fp", net(i), t);
            let other_host = match net(i) {
                IpAddr::V4(v4) => IpAddr::V4(Ipv4Addr::new(v4.octets()[0], v4.octets()[1], v4.octets()[2], 200)),
                x => x,
            };
            see(&a, "fp", other_host, t);
        }
        let got = a.networks("fp", T0 + 25);
        let n = u64::from(n);
        assert!(got.abs_diff(n) <= slack, "true {n}, estimated {got}");
        assert_eq!(a.requests("fp", T0 + 25), 2 * n);
        assert_eq!(a.networks("never-seen", T0 + 25), 0);
    }
}

#[test]
fn the_estimate_holds_with_a_random_hash_key() {
    // No fixed seed: this is what a gateway runs.
    let a = agg(Config { warmup_secs: 0, ..Config::default() });
    for i in 0..2_000 {
        see(&a, "fp", net(i), T0);
    }
    let got = a.networks("fp", T0);
    assert!(got.abs_diff(2_000) <= 600, "estimated {got}");
}

#[test]
fn distinct_networks_roll_out_of_the_window() {
    let a = agg(config());
    for i in 0..300 {
        see(&a, "fp", net(i), T0);
    }
    for i in 300..400 {
        see(&a, "fp", net(i), T0 + 50);
    }
    assert!(a.networks("fp", T0 + 59).abs_diff(400) <= 120);
    assert!(a.networks("fp", T0 + 60).abs_diff(100) <= 30);
    assert_eq!(a.networks("fp", T0 + 110), 0);
}

// ---- cluster: one fingerprint over many networks ----

#[test]
fn one_fingerprint_over_many_networks_fires_and_leaves_an_entry() {
    let a = agg(config());
    let mut first_hit = None;
    for i in 0..120 {
        let ids = see(&a, "rotator", net(i), T0 + u64::from(i % 20));
        if first_hit.is_none() && has(&ids, FP_SPREAD) {
            first_hit = Some(i);
        }
    }
    // Threshold 50, estimate within 30%: it fires somewhere between the
    // 39th and the 72nd network (index 38 to 71).
    let hit = first_hit.expect("never fired");
    assert!((37..=72).contains(&hit), "fired at network index {hit}");

    let d = a
        .observe(&Observation { fingerprint: "rotator", ip: net(5000), client: client(1), route: "/" }, T0 + 20)
        .into_iter()
        .find(|d| d.id == FP_SPREAD)
        .unwrap();
    assert_eq!((d.layer, d.penalty, d.class_hint), (Layer::Population, 25, Some(Class::Automated)));
    assert!(!d.detail.is_empty());

    // Another fingerprint on one of the same networks is not touched.
    assert!(see(&a, "bystander", net(3), T0 + 20).is_empty());

    // The entry was last confirmed at T0+20 and lasts 600 s. One request
    // long after the traffic stopped still carries it; later it is gone.
    assert!(has(&see(&a, "rotator", net(1), T0 + 20 + 599), FP_SPREAD));
    assert!(!has(&see(&a, "rotator", net(1), T0 + 20 + 601), FP_SPREAD));
    assert!(!has(&see(&a, "rotator", net(1), T0 + 20 + 3000), FP_SPREAD));
}

#[test]
fn few_networks_or_one_busy_network_do_not_fire() {
    let a = agg(config());
    for i in 0..20 {
        for _ in 0..10 {
            assert!(see(&a, "small", net(i), T0 + u64::from(i)).is_empty());
        }
    }
    // An office behind one address: thousands of requests, a dozen browser builds.
    let office: IpAddr = "198.51.100.20".parse().unwrap();
    for i in 0..3_000u32 {
        let fp = format!("browser-{}", i % 12);
        let ids = see_as(&a, &fp, office, client(i % 40), "/app", T0 + u64::from(i % 50));
        assert!(!has(&ids, FP_SPREAD) && !has(&ids, NET_FANOUT), "{ids:?}");
    }
}

#[test]
fn a_fingerprint_that_was_already_common_does_not_fire() {
    // With no history at all a rule cannot tell "common" from "new": that is
    // what warm-up is for.
    let a = agg(Config { warmup_secs: 120, ..config() });
    // Steady traffic: "chrome" from the same 400 networks every 10 seconds,
    // "firefox" from 100 others, for five minutes.
    for slot in 0..30u64 {
        let now = T0 + slot * 10;
        for i in 0..400 {
            assert!(!has(&see(&a, "chrome", net(i), now), FP_SPREAD), "slot {slot}");
        }
        for i in 400..500 {
            assert!(!has(&see(&a, "firefox", net(i), now), FP_SPREAD), "slot {slot}");
        }
    }
}

#[test]
fn a_crowd_that_grows_together_does_not_fire_but_a_newcomer_does() {
    let a = agg(Config { warmup_secs: 60, ..config() });
    // One window of quiet: chrome on 60 networks, firefox on 40.
    for slot in 0..6u64 {
        for i in 0..60 {
            see(&a, "chrome", net(i), T0 + slot * 10);
        }
        for i in 60..100 {
            see(&a, "firefox", net(i), T0 + slot * 10);
        }
    }
    // Next window: everything is five times bigger (a link went viral), and a
    // new fingerprint turns up on 300 networks of its own.
    let now = T0 + 110; // the quiet window is now exactly the previous one
    let mut newcomer_fired = false;
    for i in 0..300 {
        assert!(!has(&see(&a, "chrome", net(1_000 + i), now), FP_SPREAD), "chrome at {i}");
        if i < 200 {
            assert!(!has(&see(&a, "firefox", net(2_000 + i), now), FP_SPREAD), "firefox at {i}");
        }
        newcomer_fired |= has(&see(&a, "newcomer", net(3_000 + i), now), FP_SPREAD);
    }
    assert!(newcomer_fired);
}

#[test]
fn nothing_fires_during_warm_up() {
    let a = agg(Config { warmup_secs: 120, ..config() });
    for i in 0..500 {
        assert!(see(&a, "rotator", net(i), T0 + u64::from(i % 100)).is_empty());
    }
    // After warm-up the same pattern from a new fingerprint fires.
    let mut fired = false;
    for i in 0..500 {
        fired |= has(&see(&a, "rotator-2", net(i), T0 + 130), FP_SPREAD);
    }
    assert!(fired);
}

// ---- cluster: many fingerprints from one network ----

#[test]
fn one_network_with_a_new_fingerprint_per_request_fires() {
    let a = agg(config());
    let farm: IpAddr = "192.0.2.50".parse().unwrap();
    let mut fired_at = None;
    for i in 0..100u32 {
        let ids = see_as(&a, &format!("fake-{i}"), farm, client(i), "/", T0 + u64::from(i % 30));
        if fired_at.is_none() && has(&ids, NET_FANOUT) {
            fired_at = Some(i);
        }
    }
    let at = fired_at.expect("never fired");
    // Threshold 30, estimate within 30%: between the 24th and the 43rd.
    assert!((22..=43).contains(&at), "fired at fingerprint index {at}");

    // Another host in the same /24 carries the entry; a neighbour network does not.
    let d = a
        .observe(&Observation { fingerprint: "anything", ip: "192.0.2.77".parse().unwrap(), client: client(999), route: "/" }, T0 + 30)
        .into_iter()
        .find(|d| d.id == NET_FANOUT)
        .unwrap();
    assert_eq!((d.layer, d.penalty, d.class_hint), (Layer::Population, 25, Some(Class::Automated)));
    assert!(see(&a, "anything", "192.0.3.77".parse().unwrap(), T0 + 30).is_empty());

    assert!(has(&see(&a, "x", farm, T0 + 30 + 599), NET_FANOUT));
    assert!(!has(&see(&a, "x", farm, T0 + 30 + 601), NET_FANOUT));
}

#[test]
fn many_fingerprints_with_many_requests_each_do_not_fire() {
    let a = agg(config());
    // A campus network: ten browsers do most of the traffic, fifty more are
    // seen once each. Sixty fingerprints, but far fewer than one per two requests.
    let campus: IpAddr = "192.0.2.50".parse().unwrap();
    for i in 0..200u32 {
        assert!(see_as(&a, &format!("regular-{}", i % 10), campus, client(i % 10), "/", T0).is_empty());
    }
    for i in 0..50u32 {
        assert!(see_as(&a, &format!("visitor-{i}"), campus, client(100 + i), "/", T0 + 5).is_empty());
        assert!(see_as(&a, "regular-0", campus, client(0), "/", T0 + 5).is_empty());
    }
}

// ---- strikes ----

#[test]
fn repeated_rejections_mark_the_client() {
    let a = agg(config());
    let (bad, good) = (client(1), client(2));
    a.strike(&bad, T0);
    a.strike(&bad, T0 + 5);
    assert!(see_as(&a, "fp", net(1), bad, "/", T0 + 6).is_empty());
    a.strike(&bad, T0 + 7);
    let found = a.observe(&Observation { fingerprint: "fp", ip: net(1), client: bad, route: "/" }, T0 + 8);
    assert_eq!(found.len(), 1);
    let d = &found[0];
    assert_eq!(d.id, CLIENT_REJECTIONS);
    assert_eq!((d.layer, d.penalty, d.class_hint), (Layer::Population, 40, Some(Class::Automated)));
    // Same fingerprint and network, another client: nothing.
    assert!(see_as(&a, "fp", net(1), good, "/", T0 + 8).is_empty());
    // The rule last held at T0+8, and the entry lasts 600 s from then.
    assert!(has(&see_as(&a, "fp", net(1), bad, "/", T0 + 8 + 599), CLIENT_REJECTIONS));
    assert!(!has(&see_as(&a, "fp", net(1), bad, "/", T0 + 8 + 601), CLIENT_REJECTIONS));
}

#[test]
fn strikes_spread_over_time_do_not_add_up() {
    let a = agg(config());
    let c = client(1);
    for k in 0..10u64 {
        a.strike(&c, T0 + k * 60); // one per window
        assert!(see_as(&a, "fp", net(1), c, "/", T0 + k * 60 + 1).is_empty());
    }
}

// ---- route baseline ----

#[test]
fn a_route_surge_is_reported_only_while_it_lasts() {
    let a = agg(Config { route_min_requests: 200, ..config() });
    // Slot 3: 50 requests on /login, 300 on /.
    for i in 0..300u32 {
        see_as(&a, "fp", net(i % 5), client(i % 5), "/", T0 + 30);
        if i < 50 {
            see_as(&a, "fp", net(i % 5), client(i % 5), "/login", T0 + 30);
        }
    }
    // Slot 9: slot 3 is now in the previous window. / stays level, /login gets 400.
    let now = T0 + 90;
    let mut fired_at = None;
    for i in 0..400u32 {
        assert!(!has(&see_as(&a, "fp", net(i % 5), client(i % 5), "/", now), ROUTE_SURGE));
        let ids = see_as(&a, "fp", net(i % 5), client(i % 5), "/login", now);
        if fired_at.is_none() && has(&ids, ROUTE_SURGE) {
            fired_at = Some(i + 1);
        }
    }
    // 5 times the previous 50, and above the minimum of 200.
    assert_eq!(fired_at, Some(250));
    let d = a
        .observe(&Observation { fingerprint: "fp", ip: net(1), client: client(1), route: "/login" }, T0 + 95)
        .into_iter()
        .find(|d| d.id == ROUTE_SURGE)
        .unwrap();
    assert_eq!((d.layer, d.penalty, d.class_hint), (Layer::Population, 5, None));
    // No entry is left: once the window has moved on, it is quiet again.
    assert!(!has(&see_as(&a, "fp", net(1), client(1), "/login", T0 + 400), ROUTE_SURGE));
}

// ---- bounds and hostile input ----

#[test]
fn memory_is_bounded_and_stated() {
    let default_bound = agg(Config::default()).memory_bound_bytes();
    assert!(default_bound > 0 && default_bound < 160 * 1024 * 1024, "{default_bound}");

    let small = Config { max_keys: 100, ..config() };
    let a = agg(small);
    let bound = a.memory_bound_bytes();
    assert!(bound < default_bound / 50, "{bound} against {default_bound}");
    // Far more keys of every kind than fit.
    for i in 0..20_000u32 {
        let fp = format!("fp-{i}");
        let route = format!("/r/{i}");
        see_as(&a, &fp, net(i), client(i), &route, T0 + u64::from(i % 120));
        a.strike(&client(i + 1_000_000), T0 + u64::from(i % 120));
        assert!(a.tracked() <= 400, "tracked {} after {i}", a.tracked());
    }
    assert_eq!(a.memory_bound_bytes(), bound);
    // Still working: a new burst is counted.
    for _ in 0..7 {
        see(&a, "after", net(1), T0 + 200);
    }
    assert_eq!(a.requests("after", T0 + 200), 7);
}

#[test]
fn eviction_does_not_erase_a_live_reputation_entry_cheaply() {
    // A marked client cannot wash its entry by sending a few other keys.
    let a = agg(Config { max_keys: 1_000, ..config() });
    for _ in 0..3 {
        a.strike(&client(7), T0);
    }
    for i in 0..500u32 {
        see_as(&a, &format!("noise-{i}"), net(i), client(100 + i), "/", T0 + 1);
    }
    assert!(has(&see_as(&a, "fp", net(1), client(7), "/", T0 + 2), CLIENT_REJECTIONS));
}

#[test]
fn hostile_keys_do_not_panic_or_grow() {
    let a = agg(Config { max_keys: 50, ..config() });
    let huge = "x".repeat(1_000_000);
    let odd = ["", "\0", "é\u{202e}\u{10ffff}", "a\nb", huge.as_str()];
    for (i, key) in odd.iter().enumerate() {
        for ip in ["0.0.0.0", "255.255.255.255", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::ffff:1.2.3.4"] {
            let _ = a.observe(
                &Observation { fingerprint: key, ip: ip.parse().unwrap(), client: [0xff; 16], route: key },
                [0, 1, u64::MAX, u64::MAX - 1, T0][i % 5],
            );
        }
    }
    a.strike(&[0; 16], u64::MAX);
    a.strike(&[0; 16], 0);
    let _ = a.networks(&huge, u64::MAX);
    let _ = a.requests("", 0);
    assert!(a.tracked() <= 200);
    // Keys longer than the limit are cut, so two that share a long prefix are one key.
    let b = agg(config());
    let long_a = format!("{}{}", "p".repeat(MAX_KEY_BYTES), "tail-a");
    let long_b = format!("{}{}", "p".repeat(MAX_KEY_BYTES), "tail-b");
    see(&b, &long_a, net(1), T0);
    see(&b, &long_b, net(1), T0);
    assert_eq!(b.requests(&long_a, T0), 2);
}

#[test]
fn extreme_thresholds_do_not_overflow() {
    for c in [
        Config { spread_min_networks: 0, spread_growth: u32::MAX, fanout_min_fingerprints: 0, fanout_ratio_pct: u32::MAX,
                 strikes_max: 0, route_min_requests: 0, route_growth: u32::MAX, reputation_ttl_secs: u64::MAX,
                 warmup_secs: u64::MAX, ..config() },
        Config { spread_min_networks: u32::MAX, spread_growth: 0, fanout_min_fingerprints: u32::MAX, fanout_ratio_pct: 0,
                 strikes_max: u32::MAX, route_min_requests: u32::MAX, route_growth: 0, reputation_ttl_secs: 0,
                 slot_secs: 3600, window_slots: 60, ..config() },
        Config { spread_min_networks: 0, spread_growth: 0, fanout_min_fingerprints: 0, fanout_ratio_pct: 0,
                 strikes_max: 0, route_min_requests: 0, route_growth: 0, reputation_ttl_secs: u64::MAX, ..config() },
    ] {
        let a = agg(c);
        for i in 0..200u32 {
            let _ = see_as(&a, "fp", net(i), client(i), "/", T0 + u64::from(i));
            a.strike(&client(i), u64::MAX - u64::from(i));
        }
        let _ = see(&a, "fp", net(1), u64::MAX);
    }
}

#[test]
fn concurrent_use_loses_nothing() {
    let a = Arc::new(agg(config()));
    let threads: Vec<_> = (0..8u32)
        .map(|t| {
            let a = a.clone();
            std::thread::spawn(move || {
                for i in 0..2_000u32 {
                    see_as(&a, "shared", net(t * 10_000 + i % 50), client(t), "/", T0 + u64::from(i % 10));
                    if i % 100 == 0 {
                        a.strike(&client(t + 500), T0);
                    }
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(a.requests("shared", T0 + 10), 16_000);
    assert!(a.networks("shared", T0 + 10).abs_diff(400) <= 120);
}
