//! Acceptance tests written by the project lead. DO NOT EDIT.

use veritell_core::{Action, ChallengeKind, Class};
use veritell_policy::*;

const POLICY: &str = r#"
mode: enforce
default_action: pass
routes:
  - name: login
    match: path.startsWith("/api/login")
    rules:
      - when: class == "malicious" || score < 10
        action: decoy
      - when: score < 40
        action: challenge(pow)
  - name: assets
    match: path.startsWith("/static/") || path.endsWith(".css")
    rules: []
  - name: catalog
    match: path.startsWith("/products") && method == "GET"
    rules:
      - when: verified_bot != ""
        action: pass
      - when: class in ["signed_agent", "unverified_agent"]
        action: throttle(30/min)
      - when: '"tls_known_tool" in detections'
        action: block
      - when: net_class == "hosting" && !has_token && score < 60
        action: challenge(silent)
  - rules:
      - when: score < 20
        action: tarpit
"#;

fn input<'a>(path: &'a str, score: u8, class: Class) -> PolicyInput<'a> {
    PolicyInput {
        path,
        method: "GET",
        host: "shop.example",
        score,
        class,
        detections: &[],
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

fn policy() -> Policy {
    Policy::from_yaml(POLICY).expect("policy should compile")
}

#[test]
fn first_matching_rule_in_first_matching_route_wins() {
    let p = policy();
    assert_eq!(p.mode(), Mode::Enforce);

    let d = p.evaluate(&input("/api/login", 5, Class::Automated));
    assert_eq!(d.action, Action::Decoy);
    assert_eq!((d.route.as_deref(), d.rule, d.enforced), (Some("login"), Some(0), true));
    assert!(d.error.is_none());

    let d = p.evaluate(&input("/api/login", 80, Class::Malicious));
    assert_eq!((d.action, d.rule), (Action::Decoy, Some(0)));

    let d = p.evaluate(&input("/api/login", 35, Class::Human));
    assert_eq!((d.action, d.rule), (Action::Challenge(ChallengeKind::Pow), Some(1)));
}

#[test]
fn matched_route_without_firing_rule_gives_default_and_stops() {
    let p = policy();
    // Matches "login"; no rule fires; must not fall through to the catch-all tarpit.
    let d = p.evaluate(&input("/api/login", 90, Class::Human));
    assert_eq!(d.action, Action::Pass);
    assert_eq!((d.route.as_deref(), d.rule), (Some("login"), None));

    // "assets" has no rules: always default, even at score 1.
    let d = p.evaluate(&input("/static/app.js", 1, Class::Automated));
    assert_eq!((d.action, d.route.as_deref(), d.rule), (Action::Pass, Some("assets"), None));
    let d = p.evaluate(&input("/theme/site.css", 1, Class::Automated));
    assert_eq!(d.route.as_deref(), Some("assets"));
}

#[test]
fn catalog_rules_use_every_variable_kind() {
    let p = policy();

    let mut i = input("/products/42", 20, Class::Automated);
    i.verified_bot = "Googlebot";
    assert_eq!(p.evaluate(&i).action, Action::Pass);

    let i = input("/products/42", 70, Class::UnverifiedAgent);
    assert_eq!(p.evaluate(&i).action, Action::Throttle { per_minute: 30 });

    let dets = vec!["missing_client_hints".to_string(), "tls_known_tool".to_string()];
    let mut i = input("/products/42", 70, Class::Automated);
    i.detections = &dets;
    let d = p.evaluate(&i);
    assert_eq!((d.action, d.rule), (Action::Block, Some(2)));

    let mut i = input("/products/42", 50, Class::Human);
    i.net_class = "hosting";
    assert_eq!(p.evaluate(&i).action, Action::Challenge(ChallengeKind::Silent));
    i.has_token = true;
    assert_eq!(p.evaluate(&i).action, Action::Pass);

    // POST does not match the catalog route, so the catch-all applies.
    let mut i = input("/products/42", 10, Class::Automated);
    i.method = "POST";
    let d = p.evaluate(&i);
    assert_eq!((d.action, d.route.as_deref()), (Action::Tarpit, Some("route-3")));
}

#[test]
fn catch_all_route_and_no_route() {
    let p = policy();
    let d = p.evaluate(&input("/about", 10, Class::Automated));
    assert_eq!((d.action, d.route.as_deref(), d.rule), (Action::Tarpit, Some("route-3"), Some(0)));

    let p = Policy::from_yaml("routes: []").unwrap();
    let d = p.evaluate(&input("/about", 1, Class::Malicious));
    assert_eq!((d.action, d.route, d.rule), (Action::Pass, None, None));
}

#[test]
fn shadow_is_the_default_mode() {
    let p = Policy::from_yaml(
        "routes:\n  - rules:\n      - when: score < 50\n        action: block\n",
    )
    .unwrap();
    assert_eq!(p.mode(), Mode::Shadow);
    let d = p.evaluate(&input("/", 10, Class::Automated));
    // The selected action is still reported so it can be logged.
    assert_eq!((d.action, d.enforced), (Action::Block, false));

    let p = Policy::default_shadow();
    assert_eq!(p.mode(), Mode::Shadow);
    let d = p.evaluate(&input("/", 1, Class::Malicious));
    assert_eq!((d.action, d.enforced, d.route), (Action::Pass, false, None));

    assert_eq!(Policy::from_yaml("").unwrap().mode(), Mode::Shadow);
}

#[test]
fn default_action_is_configurable() {
    let p = Policy::from_yaml("mode: enforce\ndefault_action: challenge(pow)\nroutes: []\n").unwrap();
    let d = p.evaluate(&input("/", 99, Class::Human));
    assert_eq!((d.action, d.enforced), (Action::Challenge(ChallengeKind::Pow), true));
}

#[test]
fn other_variables_are_available() {
    let p = Policy::from_yaml(
        r#"
mode: enforce
routes:
  - match: host == "shop.example" && ip.startsWith("203.0.113.")
    rules:
      - when: asn == 16509 || ja4.startsWith("t13d4907") || user_agent.contains("curl")
        action: block
"#,
    )
    .unwrap();
    let mut i = input("/", 99, Class::Human);
    assert_eq!(p.evaluate(&i).action, Action::Pass);
    i.asn = 16509;
    assert_eq!(p.evaluate(&i).action, Action::Block);
    i.asn = 0;
    i.ja4 = "t13d4907h2_0d8feac7bc37_7395dae3b2f3";
    assert_eq!(p.evaluate(&i).action, Action::Block);
    i.ja4 = "";
    i.user_agent = "curl/8.7.1";
    assert_eq!(p.evaluate(&i).action, Action::Block);
    i.host = "other.example";
    assert_eq!(p.evaluate(&i).route, None);
}

#[test]
fn load_time_errors() {
    assert!(matches!(Policy::from_yaml("routes: [unclosed"), Err(PolicyError::Yaml(_))));

    match Policy::from_yaml("routes:\n  - match: 'path.startsWith('\n    rules: []\n") {
        Err(PolicyError::Expression { location, .. }) => assert_eq!(location, "routes[0].match"),
        other => panic!("expected Expression error, got {:?}", other.err()),
    }
    match Policy::from_yaml(
        "routes:\n  - rules: []\n  - rules:\n      - when: score < 5\n        action: pass\n      - when: 'score <'\n        action: pass\n",
    ) {
        Err(PolicyError::Expression { location, .. }) => {
            assert_eq!(location, "routes[1].rules[1].when")
        }
        other => panic!("expected Expression error, got {:?}", other.err()),
    }
    match Policy::from_yaml(
        "routes:\n  - rules:\n      - when: score < 5\n        action: explode\n",
    ) {
        Err(PolicyError::Action { location, .. }) => {
            assert_eq!(location, "routes[0].rules[0].action")
        }
        other => panic!("expected Action error, got {:?}", other.err()),
    }
    assert!(matches!(
        Policy::from_yaml("default_action: nope\n"),
        Err(PolicyError::Action { .. })
    ));
    assert!(matches!(Policy::from_yaml("mode: yolo\n"), Err(PolicyError::Invalid(_))));
    // Typos in field names must not be silently ignored.
    assert!(Policy::from_yaml("routes:\n  - mtach: 'true'\n    rules: []\n").is_err());
    // A rule needs both fields.
    assert!(Policy::from_yaml("routes:\n  - rules:\n      - when: score < 5\n").is_err());
}

#[test]
fn request_time_errors_fail_open() {
    // Compiles, but fails or yields a non-boolean when evaluated.
    let p = Policy::from_yaml(
        r#"
mode: enforce
routes:
  - name: broken
    rules:
      - when: no_such_variable > 3
        action: block
      - when: score < 99
        action: block
"#,
    )
    .unwrap();
    let d = p.evaluate(&input("/", 1, Class::Malicious));
    assert_eq!(d.action, Action::Pass);
    assert!(d.error.is_some());

    let p = Policy::from_yaml(
        "mode: enforce\nroutes:\n  - rules:\n      - when: score + 1\n        action: block\n",
    )
    .unwrap();
    let d = p.evaluate(&input("/", 1, Class::Malicious));
    assert_eq!(d.action, Action::Pass);
    assert!(d.error.is_some());
}

#[test]
fn policy_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Policy>();
}
