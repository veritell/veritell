//! The policy the rollout kit installs (`deploy/policy.yaml`).

use veritell_core::{Action, ChallengeKind, Class};
use veritell_policy::{Mode, Policy, PolicyInput, NO_QUOTA};

const POLICY: &str = include_str!("../../../deploy/policy.yaml");

fn policy() -> Policy {
    Policy::from_yaml(POLICY).expect("the kit's policy loads")
}

fn input<'a>(score: u8, class: Class, detections: &'a [String]) -> PolicyInput<'a> {
    PolicyInput {
        path: "/",
        method: "GET",
        host: "shop.example",
        score,
        class,
        detections,
        ja4: "",
        user_agent: "",
        ip: "203.0.113.9",
        asn: 0,
        net_class: "unknown",
        verified_bot: "",
        has_token: false,
        identity: "",
        quota_left: NO_QUOTA,
    }
}

fn ids(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn it_is_shadow_and_acts_on_nothing() {
    let p = policy();
    assert_eq!(p.mode(), Mode::Shadow);
    assert!(!p.evaluate(&input(10, Class::Automated, &[])).enforced);
}

#[test]
fn the_page_rates_throttle_a_client_that_scores_well() {
    let p = policy();
    for found in [ids(&["rate_client_high"]), ids(&["rate_net_high"])] {
        let d = p.evaluate(&input(70, Class::Automated, &found));
        assert_eq!(d.action, Action::Throttle { per_minute: 30 }, "{found:?}");
    }
    assert_eq!(
        p.evaluate(&input(70, Class::Human, &[])).action,
        Action::Pass
    );
}

#[test]
fn the_throttles_do_not_hide_the_blocks_and_challenges() {
    let p = policy();
    let fast = ids(&["rate_client_high"]);
    assert_eq!(
        p.evaluate(&input(20, Class::Automated, &fast)).action,
        Action::Block
    );
    assert_eq!(
        p.evaluate(&input(70, Class::Malicious, &fast)).action,
        Action::Block
    );
    assert_eq!(
        p.evaluate(&input(50, Class::Automated, &fast)).action,
        Action::Challenge(ChallengeKind::Pow)
    );
}

#[test]
fn pages_without_a_probe_report_get_a_silent_challenge() {
    let p = policy();
    let found = ids(&["pages_no_probe"]);
    assert_eq!(
        p.evaluate(&input(65, Class::Automated, &found)).action,
        Action::Challenge(ChallengeKind::Silent)
    );
    // A low score still decides first.
    assert_eq!(
        p.evaluate(&input(50, Class::Automated, &found)).action,
        Action::Challenge(ChallengeKind::Pow)
    );
}

#[test]
fn a_proven_identity_past_its_quota_is_throttled() {
    let p = policy();
    assert_eq!(p.quota_for("googlebot"), Some(10_000));
    let mut i = input(95, Class::VerifiedBot, &[]);
    i.identity = "googlebot";
    i.quota_left = 5;
    assert_eq!(p.evaluate(&i).action, Action::Pass);
    i.quota_left = 0;
    assert_eq!(p.evaluate(&i).action, Action::Throttle { per_minute: 10 });
}
