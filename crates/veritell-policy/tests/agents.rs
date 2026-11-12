//! Acceptance tests written by the project lead. DO NOT EDIT.
//! Phase 3 wave A: identity, daily quotas and the `charge` action.

use veritell_core::{Action, ChallengeKind, Class};
use veritell_policy::*;

const POLICY: &str = r#"
mode: enforce
quotas:
  default: 100
  identities:
    big-agent: 5000
    Googlebot: 0
offers:
  crawl:
    price: "0.002"
    currency: USD
    unit: request
    terms: https://shop.example/agents/terms
  bulk:
    price: "15"
    currency: EUR
    unit: day-pass
    terms: https://shop.example/t?x=1&y=2
    receipt_header: payment-receipt
  unused:
    price: "1"
    currency: USD
    unit: request
    terms: https://shop.example/
routes:
  - name: priced
    match: path.startsWith("/data")
    rules:
      - when: quota_left == 0
        action: charge(crawl)
      - when: identity == "big-agent"
        action: throttle(600/min)
      - when: class == "signed_agent"
        action: throttle(60/min)
      - when: score < 30
        action: block
  - name: pass-or-pay
    match: path.startsWith("/bulk")
    rules:
      - when: 'true'
        action: charge(bulk)
      - when: 'true'
        action: challenge(pow)
  - name: broken-charge
    match: path.startsWith("/broken")
    rules:
      - when: nope > 1
        action: charge(crawl)
      - when: score < 30
        action: block
"#;

fn input<'a>(path: &'a str, identity: &'a str, quota_left: u32) -> PolicyInput<'a> {
    PolicyInput {
        path,
        method: "GET",
        host: "shop.example",
        score: 99,
        class: if identity.is_empty() { Class::Human } else { Class::SignedAgent },
        detections: &[],
        ja4: "",
        user_agent: "",
        ip: "203.0.113.9",
        asn: 0,
        net_class: "unknown",
        verified_bot: "",
        has_token: false,
        identity,
        quota_left,
    }
}

fn policy() -> Policy {
    Policy::from_yaml(POLICY).expect("policy should compile")
}

fn crawl() -> Offer {
    Offer {
        name: "crawl".to_string(),
        price: "0.002".to_string(),
        currency: "USD".to_string(),
        unit: "request".to_string(),
        terms: "https://shop.example/agents/terms".to_string(),
        receipt_header: None,
    }
}

// ---------- quotas ----------

#[test]
fn quota_lookup() {
    let p = policy();
    assert_eq!(p.quota_for("big-agent"), Some(5000));
    assert_eq!(p.quota_for("Googlebot"), Some(0));
    assert_eq!(p.quota_for("someone-else"), Some(100));
    // Exact comparison: another spelling is another identity.
    assert_eq!(p.quota_for("Big-Agent"), Some(100));
    assert_eq!(p.quota_for("big-agent "), Some(100));
    // Nobody proven, no quota.
    assert_eq!(p.quota_for(""), None);

    let none = Policy::from_yaml("mode: enforce\n").unwrap();
    assert_eq!(none.quota_for("big-agent"), None);
    assert_eq!(Policy::default_shadow().quota_for("big-agent"), None);

    let listed_only = Policy::from_yaml("quotas:\n  identities:\n    a: 7\n").unwrap();
    assert_eq!(listed_only.quota_for("a"), Some(7));
    assert_eq!(listed_only.quota_for("b"), None);

    let default_only = Policy::from_yaml("quotas:\n  default: 4294967295\n").unwrap();
    assert_eq!(default_only.quota_for("b"), Some(u32::MAX));
    assert_eq!(default_only.quota_for(""), None);
}

// ---------- identity and quota_left as inputs ----------

#[test]
fn rules_can_name_an_identity() {
    let p = policy();
    let d = p.evaluate(&input("/data/1", "big-agent", 4000));
    assert_eq!((d.action, d.rule, d.route.as_deref()), (Action::Throttle { per_minute: 600 }, Some(1), Some("priced")));
    assert_eq!(d.offer, None);
    let d = p.evaluate(&input("/data/1", "small-agent", 50));
    assert_eq!((d.action, d.rule), (Action::Throttle { per_minute: 60 }, Some(2)));
}

#[test]
fn a_claim_is_not_an_identity() {
    let p = policy();
    // Says it is big-agent everywhere a client can say so; proves nothing.
    let mut i = input("/data/1", "", NO_QUOTA);
    i.user_agent = "big-agent";
    i.host = "big-agent";
    let d = p.evaluate(&i);
    assert_eq!((d.action, d.rule, d.error), (Action::Pass, None, None));
}

#[test]
fn quota_left_is_a_number_and_no_quota_is_large() {
    let p = Policy::from_yaml(
        "mode: enforce\nroutes:\n  - rules:\n      - when: quota_left < 10\n        action: block\n      - when: quota_left == 4294967295\n        action: tarpit\n      - when: identity.startsWith(\"big\")\n        action: decoy\n",
    )
    .unwrap();
    assert_eq!(p.evaluate(&input("/", "a", 9)).action, Action::Block);
    assert_eq!(p.evaluate(&input("/", "a", 0)).action, Action::Block);
    assert_eq!(p.evaluate(&input("/", "a", NO_QUOTA)).action, Action::Tarpit);
    assert_eq!(p.evaluate(&input("/", "", NO_QUOTA)).action, Action::Tarpit);
    assert_eq!(p.evaluate(&input("/", "big-agent", 10)).action, Action::Decoy);
    assert_eq!(p.evaluate(&input("/", "a", 10)).action, Action::Pass);
}

// ---------- charge ----------

#[test]
fn an_empty_quota_is_charged() {
    let p = policy();
    let d = p.evaluate(&input("/data/1", "small-agent", 0));
    assert_eq!(d.action, Action::Charge);
    assert_eq!(d.offer, Some(crawl()));
    assert_eq!((d.rule, d.route.as_deref(), d.enforced, d.error), (Some(0), Some("priced"), true, None));
}

#[test]
fn nobody_unproven_is_charged() {
    let p = policy();
    // The charge rule's condition holds, but there is no one to charge.
    let d = p.evaluate(&input("/data/1", "", 0));
    assert_eq!((d.action, d.rule, d.offer), (Action::Pass, None, None));
    // The rules after it still apply.
    let mut i = input("/data/1", "", 0);
    i.score = 20;
    let d = p.evaluate(&i);
    assert_eq!((d.action, d.rule, d.offer), (Action::Block, Some(3), None));

    let d = p.evaluate(&input("/bulk/x", "", NO_QUOTA));
    assert_eq!((d.action, d.rule, d.offer), (Action::Challenge(ChallengeKind::Pow), Some(1), None));
}

#[test]
fn the_offer_comes_with_the_decision() {
    let p = policy();
    let d = p.evaluate(&input("/bulk/x", "small-agent", NO_QUOTA));
    assert_eq!((d.action, d.rule), (Action::Charge, Some(0)));
    let offer = d.offer.expect("a charge carries its offer");
    assert_eq!(offer.name, "bulk");
    assert_eq!(offer.receipt_header.as_deref(), Some("payment-receipt"));
    assert_eq!(
        offer.header_value(),
        r#"offer="bulk", price="15", currency="EUR", unit="day-pass", terms="https://shop.example/t?x=1&y=2""#
    );
    assert_eq!(
        offer.body_json(),
        r#"{"offer":"bulk","price":"15","currency":"EUR","unit":"day-pass","terms":"https://shop.example/t?x=1&y=2"}"#
    );
    assert_eq!(
        crawl().header_value(),
        r#"offer="crawl", price="0.002", currency="USD", unit="request", terms="https://shop.example/agents/terms""#
    );
    assert_eq!(
        crawl().body_json(),
        r#"{"offer":"crawl","price":"0.002","currency":"USD","unit":"request","terms":"https://shop.example/agents/terms"}"#
    );
}

#[test]
fn a_skipped_charge_rule_is_not_evaluated() {
    let p = policy();
    // Unproven: the broken condition is never run, so there is no error.
    let mut i = input("/broken", "", NO_QUOTA);
    i.score = 20;
    let d = p.evaluate(&i);
    assert_eq!((d.action, d.rule, d.error), (Action::Block, Some(1), None));
    // Proven: it is run, fails, and the policy fails open as it always does.
    let d = p.evaluate(&input("/broken", "small-agent", NO_QUOTA));
    assert_eq!((d.action, d.rule, d.offer), (Action::Pass, None, None));
    assert!(d.error.is_some());
    assert_eq!(d.route.as_deref(), Some("broken-charge"));
}

#[test]
fn shadow_mode_still_names_the_charge() {
    let p = Policy::from_yaml(&POLICY.replace("mode: enforce", "mode: shadow")).unwrap();
    let d = p.evaluate(&input("/data/1", "small-agent", 0));
    assert_eq!((d.action, d.enforced), (Action::Charge, false));
    assert_eq!(d.offer, Some(crawl()));
}

// ---------- load-time checks ----------

fn with_action(action: &str) -> String {
    format!(
        "offers:\n  crawl:\n    price: \"1\"\n    currency: USD\n    unit: request\n    terms: https://shop.example/\nroutes:\n  - rules:\n      - when: 'true'\n        action: {action}\n"
    )
}

#[test]
fn charge_must_name_a_known_offer() {
    assert!(Policy::from_yaml(&with_action("charge(crawl)")).is_ok());
    assert!(Policy::from_yaml(&with_action("' charge( crawl ) '")).is_ok());
    for bad in ["charge", "charge()", "charge(nope)", "charge(Crawl)", "charge(crawl", "charge(crawl)x", "charge(crawl, crawl)"] {
        match Policy::from_yaml(&with_action(bad)) {
            Err(PolicyError::Action { location, .. }) => assert_eq!(location, "routes[0].rules[0].action", "{bad}"),
            other => panic!("{bad} should be an action error, got {:?}", other.err()),
        }
    }
    // An offer must exist even when no offers are defined at all.
    assert!(matches!(
        Policy::from_yaml("routes:\n  - rules:\n      - when: 'true'\n        action: charge(crawl)\n"),
        Err(PolicyError::Action { .. })
    ));
}

#[test]
fn charge_cannot_be_the_default() {
    let base = with_action("pass");
    assert!(Policy::from_yaml(&format!("default_action: charge(crawl)\n{base}")).is_err());
    assert!(Policy::from_yaml(&format!("default_action: charge\n{base}")).is_err());
    assert!(Policy::from_yaml(&format!("default_action: block\n{base}")).is_ok());
}

/// A policy with one offer whose fields are given as YAML lines.
fn with_offer(name: &str, fields: &[&str]) -> String {
    let mut y = format!("offers:\n  {name}:\n");
    for f in fields {
        y.push_str("    ");
        y.push_str(f);
        y.push('\n');
    }
    y
}

const PRICE: &str = "price: \"1\"";
const CURRENCY: &str = "currency: USD";
const UNIT: &str = "unit: request";
const TERMS: &str = "terms: https://shop.example/";

#[test]
fn offers_within_the_limits_load() {
    let long_terms = format!("terms: https://shop.example/{}", "a".repeat(512 - 21));
    assert_eq!(long_terms.len() - "terms: ".len(), 512);
    let name_32 = "a".repeat(32);
    let unit_32 = format!("unit: {}", "u".repeat(32));
    let header_64 = format!("receipt_header: {}", "h".repeat(64));
    let good: Vec<String> = vec![
        with_offer("crawl", &[PRICE, CURRENCY, UNIT, TERMS]),
        with_offer("a_b-9", &["price: \"123456789.123456\"", CURRENCY, "unit: gb_month-1", TERMS]),
        with_offer("crawl", &["price: \"0\"", "currency: JPY", UNIT, TERMS, "receipt_header: payment-receipt"]),
        with_offer("crawl", &["price: \"0.5\"", CURRENCY, UNIT, long_terms.as_str()]),
        with_offer(&name_32, &[PRICE, CURRENCY, unit_32.as_str(), TERMS, header_64.as_str()]),
        with_offer("crawl", &[PRICE, CURRENCY, UNIT, TERMS, "receipt_header: x-receipt"]),
    ];
    for y in &good {
        if let Err(e) = Policy::from_yaml(y) {
            panic!("should load: {e}\n{y}");
        }
    }
    let mut many = String::from("offers:\n");
    for n in 0..64 {
        many.push_str(&format!("  o{n}:\n    {PRICE}\n    {CURRENCY}\n    {UNIT}\n    {TERMS}\n"));
    }
    assert!(Policy::from_yaml(&many).is_ok());
    many.push_str(&format!("  o64:\n    {PRICE}\n    {CURRENCY}\n    {UNIT}\n    {TERMS}\n"));
    assert!(Policy::from_yaml(&many).is_err());
}

#[test]
fn offers_outside_the_limits_are_refused() {
    let long_terms = format!("terms: https://shop.example/{}", "a".repeat(512 - 20));
    let name_33 = "a".repeat(33);
    let unit_33 = format!("unit: {}", "u".repeat(33));
    let header_65 = format!("receipt_header: {}", "h".repeat(65));
    let bad: Vec<String> = vec![
        // Missing or unknown fields.
        with_offer("crawl", &[CURRENCY, UNIT, TERMS]),
        with_offer("crawl", &[PRICE, UNIT, TERMS]),
        with_offer("crawl", &[PRICE, CURRENCY, TERMS]),
        with_offer("crawl", &[PRICE, CURRENCY, UNIT]),
        with_offer("crawl", &[PRICE, CURRENCY, UNIT, TERMS, "discount: 5"]),
        // Names.
        with_offer("Crawl", &[PRICE, CURRENCY, UNIT, TERMS]),
        with_offer("\"a b\"", &[PRICE, CURRENCY, UNIT, TERMS]),
        with_offer("\"\"", &[PRICE, CURRENCY, UNIT, TERMS]),
        with_offer(&name_33, &[PRICE, CURRENCY, UNIT, TERMS]),
        // Prices.
        with_offer("crawl", &["price: \"\"", CURRENCY, UNIT, TERMS]),
        with_offer("crawl", &["price: \"1.\"", CURRENCY, UNIT, TERMS]),
        with_offer("crawl", &["price: \".5\"", CURRENCY, UNIT, TERMS]),
        with_offer("crawl", &["price: \"1.2345678\"", CURRENCY, UNIT, TERMS]),
        with_offer("crawl", &["price: \"1234567890\"", CURRENCY, UNIT, TERMS]),
        with_offer("crawl", &["price: \"-1\"", CURRENCY, UNIT, TERMS]),
        with_offer("crawl", &["price: \"1e3\"", CURRENCY, UNIT, TERMS]),
        with_offer("crawl", &["price: \"1,5\"", CURRENCY, UNIT, TERMS]),
        with_offer("crawl", &["price: \" 1\"", CURRENCY, UNIT, TERMS]),
        with_offer("crawl", &["price: \"1.2.3\"", CURRENCY, UNIT, TERMS]),
        // Currencies.
        with_offer("crawl", &[PRICE, "currency: usd", UNIT, TERMS]),
        with_offer("crawl", &[PRICE, "currency: US", UNIT, TERMS]),
        with_offer("crawl", &[PRICE, "currency: USDX", UNIT, TERMS]),
        with_offer("crawl", &[PRICE, "currency: U$D", UNIT, TERMS]),
        // Units.
        with_offer("crawl", &[PRICE, CURRENCY, "unit: \"\"", TERMS]),
        with_offer("crawl", &[PRICE, CURRENCY, "unit: Per Request", TERMS]),
        with_offer("crawl", &[PRICE, CURRENCY, unit_33.as_str(), TERMS]),
        // Terms.
        with_offer("crawl", &[PRICE, CURRENCY, UNIT, "terms: http://shop.example/"]),
        with_offer("crawl", &[PRICE, CURRENCY, UNIT, "terms: shop.example/terms"]),
        with_offer("crawl", &[PRICE, CURRENCY, UNIT, "terms: \"https://shop.example/a b\""]),
        with_offer("crawl", &[PRICE, CURRENCY, UNIT, "terms: 'https://shop.example/\"x'"]),
        with_offer("crawl", &[PRICE, CURRENCY, UNIT, "terms: 'https://shop.example/\\x'"]),
        with_offer("crawl", &[PRICE, CURRENCY, UNIT, "terms: \"https://shop.example/caf\u{e9}\""]),
        with_offer("crawl", &[PRICE, CURRENCY, UNIT, "terms: \"https://shop.example/\\r\\nSet-Cookie: a=b\""]),
        with_offer("crawl", &[PRICE, CURRENCY, UNIT, long_terms.as_str()]),
        // Receipt headers.
        with_offer("crawl", &[PRICE, CURRENCY, UNIT, TERMS, "receipt_header: \"\""]),
        with_offer("crawl", &[PRICE, CURRENCY, UNIT, TERMS, "receipt_header: Payment-Receipt"]),
        with_offer("crawl", &[PRICE, CURRENCY, UNIT, TERMS, "receipt_header: x-veritell-receipt"]),
        with_offer("crawl", &[PRICE, CURRENCY, UNIT, TERMS, "receipt_header: a b"]),
        with_offer("crawl", &[PRICE, CURRENCY, UNIT, TERMS, "receipt_header: \"a:b\""]),
        with_offer("crawl", &[PRICE, CURRENCY, UNIT, TERMS, header_65.as_str()]),
    ];
    for y in &bad {
        assert!(Policy::from_yaml(y).is_err(), "should be refused:\n{y}");
    }
}

#[test]
fn quota_limits() {
    for bad in [
        "quotas:\n  default: -1\n",
        "quotas:\n  default: 4294967296\n",
        "quotas:\n  default: many\n",
        "quotas:\n  default: 1.5\n",
        "quotas:\n  per_hour: 5\n",
        "quotas:\n  identities:\n    \"\": 5\n",
        "quotas:\n  identities:\n    a: -1\n",
        "quotas:\n  identities:\n    a: lots\n",
    ] {
        assert!(Policy::from_yaml(bad).is_err(), "should be refused:\n{bad}");
    }
    let key_256 = "k".repeat(256);
    assert!(Policy::from_yaml(&format!("quotas:\n  identities:\n    {key_256}: 5\n")).is_ok());
    assert!(Policy::from_yaml(&format!("quotas:\n  identities:\n    {key_256}k: 5\n")).is_err());

    let mut many = String::from("quotas:\n  identities:\n");
    for n in 0..1024 {
        many.push_str(&format!("    id-{n}: {n}\n"));
    }
    let p = Policy::from_yaml(&many).unwrap();
    assert_eq!(p.quota_for("id-1023"), Some(1023));
    assert_eq!(p.quota_for("id-0"), Some(0));
    many.push_str("    id-1024: 1\n");
    assert!(Policy::from_yaml(&many).is_err());

    // An identity may be any text the identity layer can produce.
    let p = Policy::from_yaml("quotas:\n  identities:\n    \"Example Agent/2 (https://a.example)\": 9\n").unwrap();
    assert_eq!(p.quota_for("Example Agent/2 (https://a.example)"), Some(9));
}
