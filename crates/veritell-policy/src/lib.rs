//! Policy: a YAML file of routes and CEL rules that turns a verdict into an action.
//!
//! PUBLIC API IS FIXED. Implement the bodies; do not change signatures.
//!
//! ```yaml
//! mode: shadow            # "shadow" (default) or "enforce"
//! default_action: pass    # optional, defaults to pass
//! routes:
//!   - name: login                       # optional, defaults to "route-<index>"
//!     match: path.startsWith("/login")  # optional CEL; absent means match all
//!     rules:
//!       - when: class == "malicious" || score < 10
//!         action: decoy
//!       - when: score < 40
//!         action: challenge(pow)
//! ```
//!
//! # Agents as customers (Phase 3)
//!
//! ```yaml
//! quotas:                      # requests per day for a proven identity
//!   default: 1000              # optional: any proven identity not listed
//!   identities:                # optional
//!     example-agent: 5000
//! offers:                      # what `charge(<name>)` answers with
//!   crawl:
//!     price: "0.002"
//!     currency: USD
//!     unit: request
//!     terms: https://shop.example/agents/terms
//!     receipt_header: payment-receipt     # optional
//! routes:
//!   - rules:
//!       - when: identity != "" && quota_left == 0
//!         action: charge(crawl)
//!       - when: class == "signed_agent"
//!         action: throttle(60/min)
//! ```
//!
//! `identity` is the name of the verified crawler or signed agent, and is
//! `""` for everyone else: a `Signature-Agent` header or a User-Agent proves
//! nothing, and the caller only fills this in after verification.
//! `quota_left` is what the identity had left of its day before this request
//! ([`NO_QUOTA`] when no quota applies).
//!
//! `charge(<offer>)` selects [`Action::Charge`] and puts the named offer in
//! [`Decision::offer`]. A request with no proven identity cannot be charged:
//! for it a `charge` rule is skipped without evaluating its `when`, and
//! evaluation goes on to the next rule. `charge` is not allowed as
//! `default_action`, and a bare `charge`, `charge()` or an unknown offer
//! name is a `PolicyError::Action` at load time.
//!
//! Limits, all checked at load time (`PolicyError::Invalid`):
//! - offer name and `unit`: 1 to 32 of `a-z`, `0-9`, `-`, `_`.
//! - `price`: 1 to 9 digits, optionally `.` and 1 to 6 digits, kept as the
//!   text that was written (never converted to a number, so never rounded).
//! - `currency`: exactly three of `A-Z`.
//! - `terms`: starts with `https://`, at most 512 bytes, printable ASCII
//!   (0x21..=0x7e) without `"` or `\`.
//! - `receipt_header`: 1 to 64 of `a-z`, `0-9`, `-`; not starting with
//!   `x-veritell-`.
//! - `price`, `currency`, `unit` and `terms` are required; unknown fields
//!   are refused, as everywhere in this file.
//! - at most 64 offers and 1024 listed identities; an identity key is 1 to
//!   256 bytes; a quota is a whole number from 0 to 4294967295.

use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use cel::{Context, Env, Program, Value};
use veritell_core::{Action, ChallengeKind, Class};
use serde::Deserialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Decide and log, but let every request through.
    Shadow,
    Enforce,
}

/// Everything a rule can look at. Each field is a CEL variable of the same name.
#[derive(Clone, Debug)]
pub struct PolicyInput<'a> {
    pub path: &'a str,
    pub method: &'a str,
    pub host: &'a str,
    /// CEL int, 1..=99.
    pub score: u8,
    /// CEL string: `Class::as_str()`, e.g. "automated".
    pub class: Class,
    /// CEL list of strings: detection ids.
    pub detections: &'a [String],
    /// CEL string, "" when absent.
    pub ja4: &'a str,
    /// CEL string, "" when absent.
    pub user_agent: &'a str,
    /// CEL string, textual IP address.
    pub ip: &'a str,
    /// CEL int, 0 when unknown.
    pub asn: u32,
    /// CEL string: "hosting", "other" or "unknown".
    pub net_class: &'a str,
    /// CEL string: verified crawler name, "" when none.
    pub verified_bot: &'a str,
    /// CEL bool: the request carried a valid session token.
    pub has_token: bool,
    /// CEL string: the proven identity (verified crawler or signed agent
    /// name), "" when nothing is proven.
    pub identity: &'a str,
    /// CEL int: what the identity had left of its daily quota before this
    /// request, or [`NO_QUOTA`].
    pub quota_left: u32,
}

/// `quota_left` when no quota applies. Large, so that a rule such as
/// `quota_left < 10` never fires for a client without a quota.
pub const NO_QUOTA: u32 = u32::MAX;

/// What a `charge` rule offers. Every field passed the limits in the crate
/// documentation, so none can break out of a header or a JSON string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    pub name: String,
    pub price: String,
    pub currency: String,
    pub unit: String,
    pub terms: String,
    /// A request header whose presence the operator accepts as a claim of
    /// payment. The gateway does not check it; the origin must.
    pub receipt_header: Option<String>,
}

impl Offer {
    /// The value of the `Veritell-Offer` response header, a structured-field
    /// dictionary in this exact order and spelling:
    /// `offer="crawl", price="0.002", currency="USD", unit="request", terms="https://shop.example/agents/terms"`
    pub fn header_value(&self) -> String {
        format!(
            "offer=\"{}\", price=\"{}\", currency=\"{}\", unit=\"{}\", terms=\"{}\"",
            self.name, self.price, self.currency, self.unit, self.terms
        )
    }

    /// The 402 body: one JSON object with the same five members in the same
    /// order, all strings, no whitespace:
    /// `{"offer":"crawl","price":"0.002","currency":"USD","unit":"request","terms":"https://shop.example/agents/terms"}`
    pub fn body_json(&self) -> String {
        format!(
            "{{\"offer\":\"{}\",\"price\":\"{}\",\"currency\":\"{}\",\"unit\":\"{}\",\"terms\":\"{}\"}}",
            self.name, self.price, self.currency, self.unit, self.terms
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    /// The action the policy selected, regardless of mode.
    pub action: Action,
    /// False in shadow mode: the caller must let the request through.
    pub enforced: bool,
    /// Name of the route that matched, if any.
    pub route: Option<String>,
    /// Index of the rule that fired within that route, if any.
    pub rule: Option<usize>,
    /// Set when a CEL expression failed at request time. The decision is then
    /// `Action::Pass` (fail open), whatever the policy's default action: a
    /// broken expression must not block everyone. Evaluation stops at the
    /// error; later rules are not tried.
    pub error: Option<String>,
    /// The offer, when and only when `action` is `Action::Charge`.
    pub offer: Option<Offer>,
}

#[derive(Debug)]
pub enum PolicyError {
    Yaml(String),
    /// Where (e.g. `routes[1].rules[0].when`) and why.
    Expression { location: String, message: String },
    /// Where and the offending action text.
    Action { location: String, message: String },
    /// Any other structural problem (unknown mode, unknown field, ...).
    Invalid(String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::Yaml(e) => write!(f, "policy is not valid YAML: {e}"),
            PolicyError::Expression { location, message } => {
                write!(f, "{location}: invalid expression: {message}")
            }
            PolicyError::Action { location, message } => write!(f, "{location}: {message}"),
            PolicyError::Invalid(e) => write!(f, "invalid policy: {e}"),
        }
    }
}

impl std::error::Error for PolicyError {}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    mode: Option<String>,
    default_action: Option<String>,
    quotas: Option<RawQuotas>,
    offers: Option<BTreeMap<String, RawOffer>>,
    #[serde(default)]
    routes: Vec<RawRoute>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawQuotas {
    default: Option<u32>,
    identities: Option<BTreeMap<String, u32>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOffer {
    price: String,
    currency: String,
    unit: String,
    terms: String,
    receipt_header: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoute {
    name: Option<String>,
    #[serde(rename = "match")]
    match_: Option<String>,
    #[serde(default)]
    rules: Vec<RawRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    when: String,
    action: String,
}

struct Rule {
    when: Program,
    action: Action,
    /// Set exactly when `action` is `Action::Charge`.
    offer: Option<Offer>,
}

struct Route {
    name: String,
    matcher: Option<Program>,
    rules: Vec<Rule>,
}

/// A compiled policy. Cheap to evaluate, safe to share across threads.
pub struct Policy {
    mode: Mode,
    default_action: Action,
    routes: Vec<Route>,
    env: Arc<Env>,
    quota_default: Option<u32>,
    quota_identities: BTreeMap<String, u32>,
}

const MAX_OFFERS: usize = 64;
const MAX_IDENTITIES: usize = 1024;
const MAX_IDENTITY_LEN: usize = 256;
const MAX_TERMS_LEN: usize = 512;

fn invalid(what: &str, field: &str, why: &str) -> PolicyError {
    PolicyError::Invalid(format!("{what}: {field} {why}"))
}

/// 1..=max bytes, each one of `a-z`, `0-9`, `-` (and `_` when allowed).
fn is_token(s: &str, max: usize, underscore: bool) -> bool {
    (1..=max).contains(&s.len())
        && s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || (underscore && b == b'_')
        })
}

fn is_digits(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
}

fn valid_price(s: &str) -> bool {
    match s.split_once('.') {
        None => is_digits(s, 1, 9),
        Some((whole, frac)) => is_digits(whole, 1, 9) && is_digits(frac, 1, 6),
    }
}

fn valid_terms(s: &str) -> bool {
    s.starts_with("https://")
        && s.len() <= MAX_TERMS_LEN
        && s.bytes().all(|b| (0x21..=0x7e).contains(&b) && b != b'"' && b != b'\\')
}

fn validate_offer(name: &str, raw: RawOffer) -> Result<Offer, PolicyError> {
    let what = format!("offers.{name:?}");
    if !is_token(name, 32, true) {
        return Err(PolicyError::Invalid(format!(
            "offer name {name:?} must be 1 to 32 of a-z, 0-9, '-', '_'"
        )));
    }
    if !valid_price(&raw.price) {
        return Err(invalid(&what, "price", "must be digits with an optional '.' and 1 to 6 digits"));
    }
    if raw.currency.len() != 3 || !raw.currency.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(invalid(&what, "currency", "must be exactly three of A-Z"));
    }
    if !is_token(&raw.unit, 32, true) {
        return Err(invalid(&what, "unit", "must be 1 to 32 of a-z, 0-9, '-', '_'"));
    }
    if !valid_terms(&raw.terms) {
        return Err(invalid(
            &what,
            "terms",
            "must be an https:// URL of printable ASCII without '\"' or '\\', at most 512 bytes",
        ));
    }
    if let Some(h) = &raw.receipt_header {
        if !is_token(h, 64, false) || h.starts_with("x-veritell-") {
            return Err(invalid(
                &what,
                "receipt_header",
                "must be 1 to 64 of a-z, 0-9, '-' and not start with x-veritell-",
            ));
        }
        // Its mere presence lets a charged agent through, so it must be a
        // header that requests do not carry anyway.
        if COMMON_REQUEST_HEADERS.contains(&h.as_str()) || h.starts_with("sec-") {
            return Err(invalid(
                &what,
                "receipt_header",
                "must not be a header ordinary requests carry (its presence alone lets the request through)",
            ));
        }
    }
    Ok(Offer {
        name: name.to_string(),
        price: raw.price,
        currency: raw.currency,
        unit: raw.unit,
        terms: raw.terms,
        receipt_header: raw.receipt_header,
    })
}

fn compile(env: &Env, src: &str, location: String) -> Result<Program, PolicyError> {
    match catch_unwind(AssertUnwindSafe(|| env.compile(src))) {
        Ok(Ok(p)) => Ok(p),
        Ok(Err(e)) => Err(PolicyError::Expression { location, message: e.to_string() }),
        Err(_) => Err(PolicyError::Expression {
            location,
            message: "expression parser failed unexpectedly".to_string(),
        }),
    }
}

/// Parses an action. `charge(<offer>)` is handled here; `offers` is `None`
/// where charging is not allowed (the default action). Returns the offer
/// exactly when the action is `Action::Charge`.
fn parse_action(
    text: &str,
    location: String,
    offers: Option<&BTreeMap<String, Offer>>,
) -> Result<(Action, Option<Offer>), PolicyError> {
    let trimmed = text.trim();
    if let Some(rest) = trimmed.strip_prefix("charge") {
        let message = match offers {
            None => "charge is not allowed here".to_string(),
            Some(offers) => {
                let name = rest.strip_prefix('(').and_then(|r| r.strip_suffix(')')).map(str::trim);
                match name.and_then(|n| offers.get(n)) {
                    Some(offer) => return Ok((Action::Charge, Some(offer.clone()))),
                    None => format!(
                        "expected charge(<offer>) naming an offer defined under offers, got {trimmed:?}"
                    ),
                }
            }
        };
        return Err(PolicyError::Action { location, message });
    }
    match text.parse::<Action>() {
        Ok(Action::Charge) => Err(PolicyError::Action {
            location,
            message: "expected charge(<offer>)".to_string(),
        }),
        // There is no visible challenge yet; refused rather than quietly
        // served as a proof of work.
        Ok(Action::Challenge(ChallengeKind::Interactive)) => Err(PolicyError::Action {
            location,
            message: "challenge(interactive) is not available; use challenge(pow) or challenge(silent)".to_string(),
        }),
        Ok(a) => Ok((a, None)),
        Err(e) => Err(PolicyError::Action { location, message: e.to_string() }),
    }
}

impl Policy {
    /// Parses and compiles a policy. Every CEL expression is compiled here,
    /// so a typo fails at load time rather than on a live request.
    pub fn from_yaml(yaml: &str) -> Result<Policy, PolicyError> {
        let raw: Option<RawPolicy> =
            serde_yaml_ng::from_str(yaml).map_err(|e| PolicyError::Yaml(e.to_string()))?;
        let raw = raw.unwrap_or_default();

        let mode = match raw.mode.as_deref() {
            None | Some("shadow") => Mode::Shadow,
            Some("enforce") => Mode::Enforce,
            Some(other) => {
                return Err(PolicyError::Invalid(format!(
                    "unknown mode {other:?} (expected \"shadow\" or \"enforce\")"
                )))
            }
        };
        let default_action = match raw.default_action.as_deref() {
            None => Action::Pass,
            Some(t) => parse_action(t, "default_action".to_string(), None)?.0,
        };

        let mut offers: BTreeMap<String, Offer> = BTreeMap::new();
        let raw_offers = raw.offers.unwrap_or_default();
        if raw_offers.len() > MAX_OFFERS {
            return Err(PolicyError::Invalid(format!("at most {MAX_OFFERS} offers are allowed")));
        }
        for (name, o) in raw_offers {
            let offer = validate_offer(&name, o)?;
            offers.insert(name, offer);
        }

        let (quota_default, quota_identities) = match raw.quotas {
            None => (None, BTreeMap::new()),
            Some(q) => {
                let ids = q.identities.unwrap_or_default();
                if ids.len() > MAX_IDENTITIES {
                    return Err(PolicyError::Invalid(format!(
                        "at most {MAX_IDENTITIES} identities may be listed under quotas"
                    )));
                }
                if ids.keys().any(|k| k.is_empty() || k.len() > MAX_IDENTITY_LEN) {
                    return Err(PolicyError::Invalid(format!(
                        "a quota identity must be 1 to {MAX_IDENTITY_LEN} bytes"
                    )));
                }
                (q.default, ids)
            }
        };

        let env = Arc::new(Env::stdlib());
        let mut routes = Vec::with_capacity(raw.routes.len());
        for (i, r) in raw.routes.into_iter().enumerate() {
            let matcher = match r.match_.as_deref() {
                None => None,
                Some(src) => Some(compile(&env, src, format!("routes[{i}].match"))?),
            };
            let mut rules = Vec::with_capacity(r.rules.len());
            for (j, rule) in r.rules.iter().enumerate() {
                let when = compile(&env, &rule.when, format!("routes[{i}].rules[{j}].when"))?;
                let (action, offer) = parse_action(
                    &rule.action,
                    format!("routes[{i}].rules[{j}].action"),
                    Some(&offers),
                )?;
                rules.push(Rule { when, action, offer });
            }
            routes.push(Route {
                name: r.name.unwrap_or_else(|| format!("route-{i}")),
                matcher,
                rules,
            });
        }
        Ok(Policy { mode, default_action, routes, env, quota_default, quota_identities })
    }

    /// The policy used when no file is given: shadow mode, no routes.
    pub fn default_shadow() -> Policy {
        Policy {
            mode: Mode::Shadow,
            default_action: Action::Pass,
            routes: Vec::new(),
            env: Arc::new(Env::stdlib()),
            quota_default: None,
            quota_identities: BTreeMap::new(),
        }
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The daily quota for a proven identity: its entry under
    /// `quotas.identities`, else `quotas.default`, else `None`. Always `None`
    /// for the empty identity. Names are compared exactly.
    pub fn quota_for(&self, identity: &str) -> Option<u32> {
        if identity.is_empty() {
            return None;
        }
        self.quota_identities.get(identity).copied().or(self.quota_default)
    }

    fn build_context(&self, input: &PolicyInput<'_>) -> Context<'static, 'static> {
        let mut ctx = Context::with_env(Arc::clone(&self.env));
        let s = |v: &str| Value::from(v.to_string());
        ctx.add_variable_from_value("path", s(input.path));
        ctx.add_variable_from_value("method", s(input.method));
        ctx.add_variable_from_value("host", s(input.host));
        ctx.add_variable_from_value("score", Value::Int(i64::from(input.score)));
        ctx.add_variable_from_value("class", s(input.class.as_str()));
        let dets: Vec<Value> = input.detections.iter().map(|d| s(d)).collect();
        ctx.add_variable_from_value("detections", Value::List(Arc::new(dets)));
        ctx.add_variable_from_value("ja4", s(input.ja4));
        ctx.add_variable_from_value("user_agent", s(input.user_agent));
        ctx.add_variable_from_value("ip", s(input.ip));
        ctx.add_variable_from_value("asn", Value::Int(i64::from(input.asn)));
        ctx.add_variable_from_value("net_class", s(input.net_class));
        ctx.add_variable_from_value("verified_bot", s(input.verified_bot));
        ctx.add_variable_from_value("has_token", Value::Bool(input.has_token));
        ctx.add_variable_from_value("identity", s(input.identity));
        ctx.add_variable_from_value("quota_left", Value::Int(i64::from(input.quota_left)));
        ctx
    }

    /// First matching route wins; inside it, first rule whose `when` is true
    /// wins. No match anywhere means the default action.
    pub fn evaluate(&self, input: &PolicyInput<'_>) -> Decision {
        let enforced = self.mode == Mode::Enforce;
        let ctx = match catch_unwind(AssertUnwindSafe(|| self.build_context(input))) {
            Ok(c) => c,
            Err(_) => {
                return Decision {
                    action: Action::Pass,
                    enforced,
                    route: None,
                    rule: None,
                    error: Some("failed to build evaluation context".to_string()),
                    offer: None,
                }
            }
        };

        // Pass, not the default action: with `default_action: block` a
        // broken expression would otherwise block every request.
        let fail_open = |route: &Route, message: String| Decision {
            action: Action::Pass,
            enforced,
            route: Some(route.name.clone()),
            rule: None,
            error: Some(message),
            offer: None,
        };

        for route in &self.routes {
            if let Some(m) = &route.matcher {
                match run_bool(m, &ctx) {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(e) => return fail_open(route, format!("match: {e}")),
                }
            }
            for (idx, rule) in route.rules.iter().enumerate() {
                // Nobody proven, nobody to charge: skip without evaluating.
                if rule.offer.is_some() && input.identity.is_empty() {
                    continue;
                }
                match run_bool(&rule.when, &ctx) {
                    Ok(true) => {
                        return Decision {
                            action: rule.action,
                            enforced,
                            route: Some(route.name.clone()),
                            rule: Some(idx),
                            error: None,
                            offer: rule.offer.clone(),
                        }
                    }
                    Ok(false) => {}
                    Err(e) => return fail_open(route, format!("rules[{idx}].when: {e}")),
                }
            }
            return Decision {
                action: self.default_action,
                enforced,
                route: Some(route.name.clone()),
                rule: None,
                error: None,
                            offer: None,
            };
        }
        Decision {
            action: self.default_action,
            enforced,
            route: None,
            rule: None,
            error: None,
                            offer: None,
        }
    }
}

/// Headers ordinary requests carry, which a receipt header must not be.
const COMMON_REQUEST_HEADERS: &[&str] = &[
    "accept", "accept-encoding", "accept-language", "authorization", "cache-control", "connection",
    "content-length", "content-type", "cookie", "dnt", "forwarded", "host", "if-modified-since",
    "if-none-match", "origin", "pragma", "priority", "range", "referer", "signature", "signature-agent",
    "signature-input", "te", "upgrade-insecure-requests", "user-agent", "via", "x-forwarded-for",
    "x-forwarded-host", "x-forwarded-proto", "x-real-ip", "x-requested-with",
];

/// Executes a program, requiring a boolean result. Panics inside the CEL
/// interpreter are contained and reported as errors.
fn run_bool(program: &Program, ctx: &Context<'_, '_>) -> Result<bool, String> {
    match catch_unwind(AssertUnwindSafe(|| program.execute(ctx))) {
        Ok(Ok(Value::Bool(b))) => Ok(b),
        Ok(Ok(other)) => Err(format!("expression returned a non-boolean value: {other:?}")),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("expression evaluation failed unexpectedly".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> PolicyInput<'static> {
        PolicyInput {
            path: "/x",
            method: "GET",
            host: "h",
            score: 50,
            class: Class::Human,
            detections: &[],
            ja4: "",
            user_agent: "",
            ip: "1.2.3.4",
            asn: 0,
            net_class: "unknown",
            verified_bot: "",
            has_token: false,
            identity: "",
            quota_left: NO_QUOTA,
        }
    }

    #[test]
    fn match_error_fails_open_with_route_name() {
        let p = Policy::from_yaml(
            "mode: enforce\nroutes:\n  - name: bad\n    match: nope > 1\n    rules:\n      - when: 'true'\n        action: block\n  - rules:\n      - when: 'true'\n        action: block\n",
        )
        .unwrap();
        let d = p.evaluate(&input());
        assert_eq!(d.action, Action::Pass);
        assert!(d.error.is_some());
        assert_eq!((d.route.as_deref(), d.rule, d.enforced), (Some("bad"), None, true));
    }

    #[test]
    fn a_receipt_header_cannot_be_one_every_request_carries() {
        for h in ["user-agent", "accept", "authorization", "sec-fetch-mode", "host"] {
            let yaml = format!(
                "offers:\n  x:\n    price: \"1\"\n    currency: EUR\n    unit: request\n    terms: https://example.test/t\n    receipt_header: {h}\nroutes: []\n"
            );
            assert!(Policy::from_yaml(&yaml).is_err(), "{h} was accepted");
        }
        let ok = "offers:\n  x:\n    price: \"1\"\n    currency: EUR\n    unit: request\n    terms: https://example.test/t\n    receipt_header: payment-receipt\nroutes: []\n";
        assert!(Policy::from_yaml(ok).is_ok());
    }

    #[test]
    fn an_interactive_challenge_is_refused_at_load() {
        let rule = "routes:\n  - rules:\n      - when: 'true'\n        action: challenge(interactive)\n";
        let err = Policy::from_yaml(rule).err().expect("accepted").to_string();
        assert!(err.contains("interactive"), "{err}");
        assert!(Policy::from_yaml("default_action: challenge(interactive)\nroutes: []\n").is_err());
        assert!(Policy::from_yaml(&rule.replace("interactive", "pow")).is_ok());
    }

    #[test]
    fn an_error_passes_even_when_the_default_blocks() {
        let p = Policy::from_yaml(
            "mode: enforce\ndefault_action: block\nroutes:\n  - rules:\n      - when: nope > 1\n        action: challenge(pow)\n",
        )
        .unwrap();
        let d = p.evaluate(&input());
        assert_eq!(d.action, Action::Pass);
        assert!(d.error.is_some());
        // Without an error, the default applies as before.
        let p = Policy::from_yaml("mode: enforce\ndefault_action: block\nroutes:\n  - rules: []\n").unwrap();
        assert_eq!(p.evaluate(&input()).action, Action::Block);
    }

    #[test]
    fn non_boolean_match_fails_open() {
        let p = Policy::from_yaml("routes:\n  - match: score\n    rules: []\n").unwrap();
        let d = p.evaluate(&input());
        assert!(d.error.is_some());
        assert_eq!(d.route.as_deref(), Some("route-0"));
    }

    #[test]
    fn route_name_defaults_use_position() {
        let p = Policy::from_yaml(
            "routes:\n  - name: a\n    match: 'false'\n  - match: 'false'\n  - name: c\n    match: 'false'\n  - match: 'true'\n",
        )
        .unwrap();
        let d = p.evaluate(&input());
        assert_eq!(d.route.as_deref(), Some("route-3"));
    }

    #[test]
    fn null_document_and_unknown_keys() {
        assert!(Policy::from_yaml("null").is_ok());
        assert!(Policy::from_yaml("# nothing\n").is_ok());
        assert!(Policy::from_yaml("bogus: 1\n").is_err());
    }

    #[test]
    fn validators() {
        assert!(valid_price("0") && valid_price("123456789.123456") && valid_price("1.5"));
        for bad in ["", ".5", "1.", "1.2.3", "1234567890", "1.1234567", "-1", "1e3", " 1"] {
            assert!(!valid_price(bad), "{bad}");
        }
        assert!(valid_terms("https://a.example/x?y=1&z=2"));
        for bad in ["http://a", "https://a b", "https://a\"b", "https://a\\b", "https://caf\u{e9}", "https://a\n"] {
            assert!(!valid_terms(bad), "{bad:?}");
        }
        assert!(!valid_terms(&format!("https://{}", "a".repeat(505))));
        assert!(is_token("a_b-9", 32, true) && !is_token("a_b", 32, false));
        assert!(!is_token("", 32, true) && !is_token("A", 32, true) && !is_token(&"a".repeat(33), 32, true));
    }

    #[test]
    fn charge_parsing() {
        let y = "offers:\n  o:\n    price: \"1\"\n    currency: USD\n    unit: u\n    terms: https://a.example/\n";
        let ok = |a: &str| Policy::from_yaml(&format!("{y}routes:\n  - rules:\n      - when: 'true'\n        action: \"{a}\"\n"));
        assert!(ok("charge(o)").is_ok() && ok(" charge( o ) ").is_ok());
        for bad in ["charge", "charge()", "charge(p)", "chargeo", "charge (o)", "charge(o)x"] {
            assert!(matches!(ok(bad), Err(PolicyError::Action { .. })), "{bad}");
        }
        assert!(Policy::from_yaml(&format!("default_action: charge(o)\n{y}")).is_err());
    }

    #[test]
    fn quota_and_offer_structure() {
        assert!(Policy::from_yaml("quotas:\n  identities:\n  default: 3\n").is_ok());
        assert!(Policy::from_yaml("offers:\n  o: {price: '1'}\n").is_err());
        let p = Policy::from_yaml("quotas:\n  default: 3\n  identities:\n    a: 0\n").unwrap();
        assert_eq!((p.quota_for("a"), p.quota_for("b"), p.quota_for("")), (Some(0), Some(3), None));
    }

    #[test]
    fn evaluates_from_two_threads() {
        let p = Arc::new(
            Policy::from_yaml(
                "mode: enforce\nroutes:\n  - rules:\n      - when: score < 60\n        action: block\n",
            )
            .unwrap(),
        );
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let p = Arc::clone(&p);
                std::thread::spawn(move || {
                    for _ in 0..200 {
                        let d = p.evaluate(&input());
                        assert_eq!(d.action, Action::Block);
                    }
                })
            })
            .collect();
        for h in handles {
            assert!(h.join().is_ok());
        }
    }
}
