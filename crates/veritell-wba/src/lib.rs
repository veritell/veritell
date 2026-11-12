//! Web Bot Auth: verifies that a request was signed by a known agent.
//!
//! The scheme is HTTP Message Signatures (RFC 9421) with Ed25519 keys, as
//! profiled by the IETF Web Bot Auth draft: the signature must cover
//! `@authority`, carry `created`, `expires` and `keyid`, and use
//! `tag="web-bot-auth"`. The key id is the RFC 7638 JWK thumbprint of the key.
//!
//! Trust is configured by the operator ([`TrustedAgents`]). This crate never
//! fetches a key directory named by the request.
//!
//! `Signature-Agent` comes in two forms. The current one
//! (draft-ietf-webbotauth-httpsig-protocol-01, section 5.2.1) is a
//! structured-field dictionary with one member per signature, keyed by the
//! signature's label: `Signature-Agent: sig2="https://agent.example/keys"`,
//! covered as `"signature-agent";key="sig2"`. The earlier one is a single
//! quoted string covered as `"signature-agent"`; the draft lets a verifier
//! keep accepting it and this crate does. The draft also says a signed
//! request must carry the header; a request without one is still accepted
//! here when its key is one the operator configured directly.
//!
//! Replay: a signature only binds what it covers, and the profile requires
//! no more than `@authority`. Until it expires, a captured signed request can
//! be sent again, to any method and path the signature does not cover. This
//! crate keeps no state; a caller that wants to refuse replays passes each
//! verified request through a [`ReplayCache`], and one that wants the method
//! and path bound checks [`SignatureInfo::covers`].
//!
//! PUBLIC API IS FIXED. Implement the bodies; do not change signatures.
//! All times are Unix seconds supplied by the caller (no clock access here).
//! Every input is attacker-controlled: nothing here may panic.

use std::collections::{BTreeSet, HashMap};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use veritell_core::{Class, Detection, Layer};
use sha2::{Digest, Sha256};

mod sf;

use sf::{param, Bare, Item, Params, Value};

/// The only signature tag this crate looks at.
pub const TAG: &str = "web-bot-auth";
/// Longest accepted `expires - created`. Kept short because a signature can
/// be replayed until it expires.
pub const MAX_WINDOW_SECS: u64 = 3_600;
/// Tolerance applied to `created` (in the future) and `expires` (in the past).
pub const CLOCK_SKEW_SECS: u64 = 60;
/// Longest accepted `Signature-Input`, `Signature` or `Signature-Agent` value.
pub const MAX_HEADER_BYTES: usize = 4096;
/// Most covered components accepted in one signature.
pub const MAX_COMPONENTS: usize = 16;
/// Longest accepted `keyid`.
pub const MAX_KEYID_BYTES: usize = 128;
/// Most keys accepted in one directory.
pub const MAX_KEYS: usize = 64;

/// The parts of a request that can be covered by a signature.
#[derive(Clone, Copy, Debug)]
pub struct RequestParts<'a> {
    /// Any case. The signature base uses it uppercased: RFC 9421 keeps the
    /// method as received, but HTTP methods in use are uppercase.
    pub method: &'a str,
    /// Host and optional port. Lowercased when building the signature base.
    pub authority: &'a str,
    /// Path without the query string, for example `/foo`.
    pub path: &'a str,
    /// Query string without the leading `?`, if the request had one.
    pub query: Option<&'a str>,
    /// Header names in any case. A name may appear more than once.
    pub headers: &'a [(&'a str, &'a str)],
}

/// One Ed25519 verification key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed25519Key {
    /// RFC 7638 thumbprint, base64url without padding.
    pub keyid: String,
    pub public: [u8; 32],
    /// The key is not valid before this time (JWK `nbf`), if set.
    pub not_before: Option<u64>,
    /// The key is not valid after this time (JWK `exp`), if set.
    pub not_after: Option<u64>,
}

impl Ed25519Key {
    /// Builds a key with no validity limits and its computed thumbprint.
    pub fn from_public(public: [u8; 32]) -> Ed25519Key {
        Ed25519Key {
            keyid: jwk_thumbprint_ed25519(&public),
            public,
            not_before: None,
            not_after: None,
        }
    }
}

/// RFC 7638 thumbprint of an Ed25519 public key: base64url (no padding) of
/// SHA-256 over `{"crv":"Ed25519","kty":"OKP","x":"<base64url of the key>"}`.
pub fn jwk_thumbprint_ed25519(public: &[u8; 32]) -> String {
    let x = URL_SAFE_NO_PAD.encode(public);
    let jwk = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}");
    URL_SAFE_NO_PAD.encode(Sha256::digest(jwk.as_bytes()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WbaError {
    /// Not JSON, or not the expected shape.
    Json(String),
    /// More than [`MAX_KEYS`] keys.
    TooManyKeys,
    /// An Ed25519 key whose `x` is not 32 bytes of base64url.
    BadKey(String),
    /// An agent entry that cannot be used (empty name, no usable key,
    /// or a key id already registered to another agent).
    BadAgent(String),
}

impl std::fmt::Display for WbaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WbaError::Json(m) => write!(f, "invalid JSON: {m}"),
            WbaError::TooManyKeys => write!(f, "too many keys (limit {MAX_KEYS})"),
            WbaError::BadKey(m) => write!(f, "invalid key: {m}"),
            WbaError::BadAgent(m) => write!(f, "invalid agent: {m}"),
        }
    }
}

impl std::error::Error for WbaError {}

/// Parses a key directory in JWKS form: `{"keys":[{...}, ...]}`.
///
/// Keys with `"kty":"OKP"` and `"crv":"Ed25519"` are returned, with `nbf` and
/// `exp` copied to `not_before` and `not_after`. Other key types are skipped.
/// `kid` is ignored; the key id is always the computed thumbprint.
pub fn parse_directory(json: &str) -> Result<Vec<Ed25519Key>, WbaError> {
    let root: serde_json::Value =
        serde_json::from_str(json).map_err(|e| WbaError::Json(e.to_string()))?;
    let keys = root
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| WbaError::Json("expected an object with a \"keys\" array".into()))?;
    parse_key_array(keys)
}

fn parse_key_array(keys: &[serde_json::Value]) -> Result<Vec<Ed25519Key>, WbaError> {
    if keys.len() > MAX_KEYS {
        return Err(WbaError::TooManyKeys);
    }
    let mut out = Vec::new();
    for jwk in keys {
        let obj = jwk
            .as_object()
            .ok_or_else(|| WbaError::Json("a key is not an object".into()))?;
        let text = |name: &str| obj.get(name).and_then(serde_json::Value::as_str);
        if text("kty") != Some("OKP") || text("crv") != Some("Ed25519") {
            continue;
        }
        let x = text("x").ok_or_else(|| WbaError::BadKey("missing x".into()))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(x)
            .map_err(|_| WbaError::BadKey("x is not base64url".into()))?;
        let public: [u8; 32] = bytes
            .try_into()
            .map_err(|_| WbaError::BadKey("x is not 32 bytes".into()))?;
        let time = |name: &str| -> Result<Option<u64>, WbaError> {
            match obj.get(name) {
                None | Some(serde_json::Value::Null) => Ok(None),
                Some(v) => v
                    .as_u64()
                    .map(Some)
                    .ok_or_else(|| WbaError::BadKey(format!("{name} is not a Unix time"))),
            }
        };
        let mut key = Ed25519Key::from_public(public);
        key.not_before = time("nbf")?;
        key.not_after = time("exp")?;
        out.push(key);
    }
    Ok(out)
}

/// The agents an operator has chosen to trust, indexed by key id.
#[derive(Clone, Debug, Default)]
pub struct TrustedAgents {
    agents: Vec<AgentEntry>,
    /// Key id to (index into `agents`, key).
    keys: HashMap<String, (usize, Ed25519Key)>,
}

#[derive(Clone, Debug)]
struct AgentEntry {
    name: String,
    signature_agent: Option<String>,
}

impl TrustedAgents {
    pub fn new() -> TrustedAgents {
        TrustedAgents::default()
    }

    /// Registers an agent.
    ///
    /// `signature_agent`, if set, is the value the request's `Signature-Agent`
    /// header must have (compared without the surrounding quotes).
    /// Fails with `BadAgent` if `name` is empty, `keys` is empty, or a key id
    /// is already registered.
    pub fn add(
        &mut self,
        name: &str,
        signature_agent: Option<&str>,
        keys: Vec<Ed25519Key>,
    ) -> Result<(), WbaError> {
        if name.is_empty() {
            return Err(WbaError::BadAgent("empty name".into()));
        }
        if keys.is_empty() {
            return Err(WbaError::BadAgent(format!("{name}: no keys")));
        }
        // Validate everything before changing any state.
        for (i, key) in keys.iter().enumerate() {
            let dup_inside = keys.iter().skip(i.saturating_add(1)).any(|k| k.keyid == key.keyid);
            if dup_inside || self.keys.contains_key(&key.keyid) {
                return Err(WbaError::BadAgent(format!(
                    "{name}: key id {} is already registered",
                    key.keyid
                )));
            }
        }
        let idx = self.agents.len();
        self.agents.push(AgentEntry {
            name: name.to_string(),
            signature_agent: signature_agent.map(str::to_string),
        });
        for key in keys {
            self.keys.insert(key.keyid.clone(), (idx, key));
        }
        Ok(())
    }

    /// Loads the operator's file:
    /// `{"agents":[{"name":"...","signature_agent":"https://...","keys":[JWK, ...]}]}`
    /// where `signature_agent` is optional and `keys` is as in [`parse_directory`].
    pub fn from_json(json: &str) -> Result<TrustedAgents, WbaError> {
        let root: serde_json::Value =
            serde_json::from_str(json).map_err(|e| WbaError::Json(e.to_string()))?;
        let agents = root
            .get("agents")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| WbaError::Json("expected an object with an \"agents\" array".into()))?;
        let mut trusted = TrustedAgents::new();
        for agent in agents {
            let name = agent
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| WbaError::Json("agent without a string \"name\"".into()))?;
            let signature_agent = match agent.get("signature_agent") {
                None | Some(serde_json::Value::Null) => None,
                Some(v) => Some(v.as_str().ok_or_else(|| {
                    WbaError::Json("\"signature_agent\" is not a string".into())
                })?),
            };
            let keys = agent
                .get("keys")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| WbaError::Json("agent without a \"keys\" array".into()))?;
            trusted.add(name, signature_agent, parse_key_array(keys)?)?;
        }
        Ok(trusted)
    }

    /// Number of registered keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Why a signature that claimed to be Web Bot Auth was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WbaInvalid {
    /// Headers could not be parsed, exceeded a size limit, the `Signature`
    /// member is missing or not 64 bytes, or a covered header is absent.
    Malformed,
    /// `@authority` is not among the covered components.
    MissingAuthority,
    /// `created`, `expires` or `keyid` is missing.
    MissingParams,
    /// `alg` is present and is not `ed25519`.
    UnsupportedAlg,
    /// A covered component this crate does not implement, or one with
    /// parameters.
    UnsupportedComponent,
    /// `created` is more than [`CLOCK_SKEW_SECS`] in the future.
    NotYetValid,
    /// `expires` is more than [`CLOCK_SKEW_SECS`] in the past.
    Expired,
    /// `expires <= created`, or the window exceeds [`MAX_WINDOW_SECS`].
    WindowTooLong,
    /// The request has a `Signature-Agent` header that is not covered.
    SignatureAgentUnsigned,
    /// The key is outside its `not_before`..`not_after` range.
    KeyExpired,
    /// `Signature-Agent` does not match the one configured for this agent.
    AgentMismatch,
    /// The Ed25519 signature does not verify.
    BadSignature,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WbaVerdict {
    /// No signature tagged `web-bot-auth`. Not a detection.
    Absent,
    /// Signed by a trusted agent.
    Verified { agent: String, keyid: String },
    /// Well-formed and in its time window, but the key is not trusted.
    /// The signature is not checked in this case.
    UnknownKey { keyid: String },
    Invalid(WbaInvalid),
}

impl WbaVerdict {
    /// The detection for this verdict, all in `Layer::Identity`:
    ///
    /// | verdict | id | penalty | class hint |
    /// |---|---|---|---|
    /// | `Absent`, `Verified` | none | | |
    /// | `UnknownKey` | `wba_unknown_key` | 20 | `UnverifiedAgent` |
    /// | `BadSignature`, `AgentMismatch`, `SignatureAgentUnsigned` | `wba_bad_signature` | 70 | `Malicious` |
    /// | `Expired`, `NotYetValid`, `WindowTooLong`, `KeyExpired` | `wba_expired` | 30 | `UnverifiedAgent` |
    /// | every other `Invalid` | `wba_malformed` | 30 | `UnverifiedAgent` |
    pub fn detection(&self) -> Option<Detection> {
        let invalid = match self {
            WbaVerdict::Absent | WbaVerdict::Verified { .. } => return None,
            WbaVerdict::UnknownKey { .. } => {
                return Some(
                    Detection::new(
                        "wba_unknown_key",
                        Layer::Identity,
                        20,
                        "request signed with a key that is not trusted",
                    )
                    .with_class(Class::UnverifiedAgent),
                )
            }
            WbaVerdict::Invalid(why) => *why,
        };
        let d = match invalid {
            WbaInvalid::BadSignature
            | WbaInvalid::AgentMismatch
            | WbaInvalid::SignatureAgentUnsigned => Detection::new(
                "wba_bad_signature",
                Layer::Identity,
                70,
                format!("web bot auth signature rejected: {invalid:?}"),
            )
            .with_class(Class::Malicious),
            WbaInvalid::Expired
            | WbaInvalid::NotYetValid
            | WbaInvalid::WindowTooLong
            | WbaInvalid::KeyExpired => Detection::new(
                "wba_expired",
                Layer::Identity,
                30,
                format!("web bot auth signature outside its validity: {invalid:?}"),
            )
            .with_class(Class::UnverifiedAgent),
            WbaInvalid::Malformed
            | WbaInvalid::MissingAuthority
            | WbaInvalid::MissingParams
            | WbaInvalid::UnsupportedAlg
            | WbaInvalid::UnsupportedComponent => Detection::new(
                "wba_malformed",
                Layer::Identity,
                30,
                format!("web bot auth signature unusable: {invalid:?}"),
            )
            .with_class(Class::UnverifiedAgent),
        };
        Some(d)
    }
}

/// Builds the RFC 9421 signature base (section 2.5) for one signature.
///
/// `member` is the value of one `Signature-Input` dictionary member, that is
/// the text after `label=`: an inner list of component identifiers followed
/// by parameters. The final `"@signature-params"` line repeats `member`
/// exactly as given (trimmed).
///
/// Supported components: `@method`, `@authority`, `@path`, `@query` (the
/// value is `?` followed by the query, or `?` alone when there is none) and
/// plain header fields. A header value is trimmed; repeated headers are
/// joined with `", "` in request order. Lines are separated by `\n` with no
/// trailing newline.
///
/// One component parameter is supported, on header fields only: `key`
/// (RFC 9421 section 2.1.2), written `"name";key="member"` with a string
/// value. The header (joined as above) must parse as a structured-field
/// dictionary that has that member, and the member must be a single item
/// without parameters. The line is the identifier as written in canonical
/// form, then the member's value as it appears in the header:
/// `"signature-agent";key="sig2": "https://signature-agent.test"`.
/// Two components with the same name and different keys are different
/// components; the same name with and without a key are too.
///
/// Errors: `Malformed` for unparseable input, more than [`MAX_COMPONENTS`]
/// components, a duplicate component, a covered header that the request
/// does not have, or a `key` whose header is not a dictionary or lacks the
/// member; `UnsupportedComponent` for any other `@` component, any parameter
/// other than a single string-valued `key`, a `key` on an `@` component, or
/// a `key` naming a member that is an inner list or carries parameters.
pub fn signature_base(req: &RequestParts<'_>, member: &str) -> Result<String, WbaInvalid> {
    let (items, _params) = sf::parse_inner_list(member).ok_or(WbaInvalid::Malformed)?;
    if items.len() > MAX_COMPONENTS {
        return Err(WbaInvalid::Malformed);
    }
    let mut seen: Vec<(&str, Option<&str>)> = Vec::new();
    let mut base = String::new();
    for item in &items {
        let name = match &item.bare {
            Bare::Str(n) => n.as_str(),
            _ => return Err(WbaInvalid::Malformed),
        };
        let key = match item.params.as_slice() {
            [] => None,
            [(p, Bare::Str(k))] if p == "key" => Some(k.as_str()),
            _ => return Err(WbaInvalid::UnsupportedComponent),
        };
        let value = match key {
            None => component_value(req, name)?,
            Some(k) => dictionary_member_value(req, name, k)?,
        };
        if seen.contains(&(name, key)) {
            return Err(WbaInvalid::Malformed);
        }
        seen.push((name, key));
        // A line break in a value would let one component forge another.
        if value.contains(['\r', '\n']) {
            return Err(WbaInvalid::Malformed);
        }
        base.push('"');
        base.push_str(name);
        base.push('"');
        if let Some(k) = key {
            // A member key that matched cannot contain a quote or a backslash.
            base.push_str(";key=\"");
            base.push_str(k);
            base.push('"');
        }
        base.push_str(": ");
        base.push_str(&value);
        base.push('\n');
    }
    base.push_str("\"@signature-params\": ");
    base.push_str(member.trim_matches(|c| c == ' ' || c == '\t'));
    Ok(base)
}

fn is_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(
                    b,
                    b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^'
                        | b'_' | b'`' | b'|' | b'~'
                )
        })
}

fn component_value(req: &RequestParts<'_>, name: &str) -> Result<String, WbaInvalid> {
    if let Some(derived) = name.strip_prefix('@') {
        return match derived {
            "method" => Ok(req.method.to_ascii_uppercase()),
            "authority" => Ok(req.authority.to_ascii_lowercase()),
            "path" => Ok(if req.path.is_empty() { "/" } else { req.path }.to_string()),
            "query" => Ok(format!("?{}", req.query.unwrap_or(""))),
            _ => Err(WbaInvalid::UnsupportedComponent),
        };
    }
    // Header names must already be lowercase and plain tokens.
    if !is_header_name(name) {
        return Err(WbaInvalid::Malformed);
    }
    joined_header(req.headers, name, true).ok_or(WbaInvalid::Malformed)
}

/// The value text of member `key` of the dictionary header `name`, for the
/// `key` component parameter.
fn dictionary_member_value(
    req: &RequestParts<'_>,
    name: &str,
    key: &str,
) -> Result<String, WbaInvalid> {
    if name.starts_with('@') {
        return Err(WbaInvalid::UnsupportedComponent);
    }
    if !is_header_name(name) {
        return Err(WbaInvalid::Malformed);
    }
    let joined = joined_header(req.headers, name, true).ok_or(WbaInvalid::Malformed)?;
    let members = sf::parse_dictionary(&joined).ok_or(WbaInvalid::Malformed)?;
    let member = members
        .iter()
        .find(|m| m.key == key)
        .ok_or(WbaInvalid::Malformed)?;
    match &member.value {
        Value::Item(item) if item.params.is_empty() => {
            // A boolean true written as a bare key has no value text.
            Ok(if member.text.is_empty() { "?1" } else { member.text }.to_string())
        }
        _ => Err(WbaInvalid::UnsupportedComponent),
    }
}

/// Values of all headers called `name` (any case), joined with `", "`.
/// Stops collecting once the result is longer than [`MAX_HEADER_BYTES`] plus
/// one value, so an attacker cannot make this allocate without bound; callers
/// that care compare the length with the limit.
fn joined_header(headers: &[(&str, &str)], name: &str, trim: bool) -> Option<String> {
    let mut out: Option<String> = None;
    for (k, v) in headers {
        if !k.eq_ignore_ascii_case(name) {
            continue;
        }
        let v = if trim { v.trim_matches(|c| c == ' ' || c == '\t') } else { v };
        match &mut out {
            Some(s) => {
                if s.len() > MAX_HEADER_BYTES {
                    break;
                }
                s.push_str(", ");
                s.push_str(v);
            }
            None => out = Some(v.to_string()),
        }
    }
    out
}

fn nonneg_int(params: &Params, name: &str) -> Option<Option<u64>> {
    // Outer None: parameter absent. Inner None: present but unusable.
    param(params, name).map(|b| match b {
        Bare::Int(i) => u64::try_from(*i).ok(),
        _ => None,
    })
}

/// Step 6 of [`verify`]: the agent that the `Signature-Agent` header `raw`
/// names for the signature labelled `label`, given how it was covered.
fn signature_agent_of(
    raw: &str,
    label: &str,
    whole: bool,
    keyed: bool,
) -> Result<String, WbaInvalid> {
    if let Some(Item { bare: Bare::Str(agent), params }) = sf::parse_item(raw) {
        if params.is_empty() {
            return if whole { Ok(agent) } else { Err(WbaInvalid::SignatureAgentUnsigned) };
        }
    }
    let members = sf::parse_dictionary(raw).ok_or(WbaInvalid::Malformed)?;
    let member = members
        .into_iter()
        .filter(|m| m.value.params().is_empty())
        .find(|m| m.key == label)
        .ok_or(WbaInvalid::SignatureAgentUnsigned)?;
    let Value::Item(Item { bare: Bare::Str(agent), .. }) = member.value else {
        return Err(WbaInvalid::Malformed);
    };
    if whole || keyed {
        Ok(agent)
    } else {
        Err(WbaInvalid::SignatureAgentUnsigned)
    }
}

/// Checks a request for a Web Bot Auth signature.
///
/// Steps, in order; the first failure decides the verdict:
/// 1. No `Signature-Input` header: `Absent`. A `Signature-Input`,
///    `Signature` or `Signature-Agent` value longer than
///    [`MAX_HEADER_BYTES`]: `Invalid(Malformed)`.
/// 2. Parse `Signature-Input` as a dictionary and take the first member whose
///    `tag` parameter equals [`TAG`]. If parsing fails: `Invalid(Malformed)`
///    when the raw value contains the text `web-bot-auth`, otherwise
///    `Absent`. If no member has the tag: `Absent`.
/// 3. `@authority` must be covered (`MissingAuthority`). `created`, `expires`
///    and `keyid` must be present, `keyid` at most [`MAX_KEYID_BYTES`]
///    (`MissingParams`, or `Malformed` for an oversized key id). `alg`, if
///    present, must be `ed25519` (`UnsupportedAlg`).
/// 4. Time window: `NotYetValid`, `Expired`, `WindowTooLong` as documented on
///    [`WbaInvalid`].
/// 5. The `Signature` header must have a member with the same label holding
///    a 64-byte byte sequence (`:base64:`), else `Malformed`.
/// 6. If the request has a `Signature-Agent` header, it must be covered, and
///    it names this signature's agent:
///    - The header is one quoted string (the earlier form): the component
///      `"signature-agent"`, without parameters, must be covered, else
///      `SignatureAgentUnsigned`. The agent is the string.
///    - Otherwise it must parse as a dictionary, else `Malformed`. Members
///      that carry parameters are ignored. There must be a member whose key
///      is this signature's label, else `SignatureAgentUnsigned`; it must be
///      a string, else `Malformed`. Either `"signature-agent";key="<label>"`
///      or the whole header (`"signature-agent"`) must be covered, else
///      `SignatureAgentUnsigned`: covering another label's member is not
///      enough. The agent is that member's string.
/// 7. Build the signature base (its errors as in [`signature_base`]) and
///    check that the signature bytes could verify under some key: the `R`
///    half a valid, not small-order point and the `S` half below the group
///    order, else `BadSignature`. Junk bytes therefore never reach
///    `UnknownKey`.
/// 8. Look up `keyid`. Not trusted: `UnknownKey`. Outside the key's validity:
///    `KeyExpired`. The agent has a configured `signature_agent` and the
///    request's agent (from step 6; none when there is no header) differs:
///    `AgentMismatch`.
/// 9. Verify strictly (`BadSignature`).
/// 10. `Verified`.
pub fn verify(req: &RequestParts<'_>, trusted: &TrustedAgents, now: u64) -> WbaVerdict {
    match verify_inner(req, trusted, now) {
        Ok(v) => v,
        Err(e) => WbaVerdict::Invalid(e),
    }
}

fn verify_inner(
    req: &RequestParts<'_>,
    trusted: &TrustedAgents,
    now: u64,
) -> Result<WbaVerdict, WbaInvalid> {
    use WbaInvalid::*;

    // 1. Presence and sizes.
    let Some(raw_input) = joined_header(req.headers, "signature-input", false) else {
        return Ok(WbaVerdict::Absent);
    };
    let raw_sig = joined_header(req.headers, "signature", false);
    let raw_agent = joined_header(req.headers, "signature-agent", false);
    if raw_input.len() > MAX_HEADER_BYTES
        || raw_sig.as_ref().is_some_and(|s| s.len() > MAX_HEADER_BYTES)
        || raw_agent.as_ref().is_some_and(|s| s.len() > MAX_HEADER_BYTES)
    {
        return Err(Malformed);
    }

    // 2. Find our member.
    let Some(members) = sf::parse_dictionary(&raw_input) else {
        return if raw_input.contains(TAG) {
            Err(Malformed)
        } else {
            Ok(WbaVerdict::Absent)
        };
    };
    let Some(member) = members
        .iter()
        .find(|m| matches!(param(m.value.params(), "tag"), Some(Bare::Str(t)) if t == TAG))
    else {
        return Ok(WbaVerdict::Absent);
    };
    let Value::List { items, params } = &member.value else {
        return Err(Malformed);
    };

    // 3. Required components and parameters.
    let mut has_authority = false;
    // `"signature-agent"` as written, and `"signature-agent";key="<label>"`.
    let (mut agent_whole, mut agent_keyed) = (false, false);
    for Item { bare, params } in items {
        let Bare::Str(n) = bare else {
            return Err(Malformed);
        };
        match n.as_str() {
            "@authority" => has_authority = true,
            "signature-agent" => match params.as_slice() {
                [] => agent_whole = true,
                [(p, Bare::Str(k))] if p == "key" && *k == member.key => agent_keyed = true,
                _ => {}
            },
            _ => {}
        }
    }
    if !has_authority {
        return Err(MissingAuthority);
    }
    let (created, expires, keyid) = (
        nonneg_int(params, "created"),
        nonneg_int(params, "expires"),
        param(params, "keyid"),
    );
    let (Some(created), Some(expires), Some(keyid)) = (created, expires, keyid) else {
        return Err(MissingParams);
    };
    let (Some(created), Some(expires)) = (created, expires) else {
        return Err(Malformed);
    };
    let Bare::Str(keyid) = keyid else {
        return Err(Malformed);
    };
    if keyid.len() > MAX_KEYID_BYTES {
        return Err(Malformed);
    }
    if let Some(alg) = param(params, "alg") {
        if !matches!(alg, Bare::Str(a) if a == "ed25519") {
            return Err(UnsupportedAlg);
        }
    }

    // 4. Time window.
    if created > now.saturating_add(CLOCK_SKEW_SECS) {
        return Err(NotYetValid);
    }
    if expires.saturating_add(CLOCK_SKEW_SECS) < now {
        return Err(Expired);
    }
    if expires <= created || expires.saturating_sub(created) > MAX_WINDOW_SECS {
        return Err(WindowTooLong);
    }

    // 5. The signature itself.
    let sig_members = sf::parse_dictionary(raw_sig.as_deref().ok_or(Malformed)?).ok_or(Malformed)?;
    let sig_bytes = sig_members
        .iter()
        .find(|m| m.key == member.key)
        .and_then(|m| match &m.value {
            Value::Item(Item {
                bare: Bare::Bytes(b),
                ..
            }) => Some(b),
            _ => None,
        })
        .ok_or(Malformed)?;
    let sig_bytes: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| Malformed)?;

    // 6. A Signature-Agent header must be signed.
    let request_agent = match &raw_agent {
        None => None,
        Some(raw) => Some(signature_agent_of(raw, &member.key, agent_whole, agent_keyed)?),
    };

    // 7. A well-formed request and a signature that could verify.
    let base = signature_base(req, member.text)?;
    if !plausible_signature(&sig_bytes) {
        return Err(BadSignature);
    }

    // 8. Trust.
    let Some((agent_idx, key)) = trusted.keys.get(keyid.as_str()) else {
        return Ok(WbaVerdict::UnknownKey {
            keyid: keyid.clone(),
        });
    };
    if key.not_before.is_some_and(|nbf| now < nbf) || key.not_after.is_some_and(|exp| now > exp) {
        return Err(KeyExpired);
    }
    let agent = trusted.agents.get(*agent_idx).ok_or(Malformed)?;
    if let Some(want) = &agent.signature_agent {
        match &request_agent {
            Some(got) if got == want => {}
            _ => return Err(AgentMismatch),
        }
    }

    // 9. Signature.
    let verifying = VerifyingKey::from_bytes(&key.public).map_err(|_| BadSignature)?;
    verifying
        .verify_strict(base.as_bytes(), &Signature::from_bytes(&sig_bytes))
        .map_err(|_| BadSignature)?;

    // 10.
    Ok(WbaVerdict::Verified {
        agent: agent.name.clone(),
        keyid: keyid.clone(),
    })
}

/// The Ed25519 group order, little-endian.
const ED25519_ORDER: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// Whether 64 bytes have the shape of a signature that strict verification
/// could accept under some key: `R` decodes to a point that is not of small
/// order, and `S` is below the group order.
fn plausible_signature(sig: &[u8; 64]) -> bool {
    let (r, s) = sig.split_at(32);
    let Ok(r) = <[u8; 32]>::try_from(r) else {
        return false;
    };
    match VerifyingKey::from_bytes(&r) {
        Ok(point) if !point.is_weak() => {}
        _ => return false,
    }
    // Compare from the most significant byte.
    for (a, b) in s.iter().rev().zip(ED25519_ORDER.iter().rev()) {
        if a != b {
            return a < b;
        }
    }
    false
}

/// What a caller needs to refuse replays of a signed request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureInfo {
    /// SHA-256 over the key id and the signature bytes. Ed25519 signatures
    /// are deterministic, so the same signed request always gives the same
    /// value, and a new `created` or `nonce` gives a new one.
    pub replay_id: [u8; 32],
    /// The signature's `expires`.
    pub expires: u64,
    /// The covered components as written, for example `@authority`, or
    /// `signature-agent;key=sig2` for a keyed one.
    pub components: Vec<String>,
}

impl SignatureInfo {
    /// Whether a component without parameters (`@method`, `@path`, a header
    /// name) is covered.
    pub fn covers(&self, component: &str) -> bool {
        self.components.iter().any(|c| c == component)
    }
}

/// The replay facts of the request's `web-bot-auth` signature, read the same
/// way [`verify`] reads them. `None` when there is no such signature or it
/// lacks what [`verify`] requires. This checks nothing: call it after
/// [`verify`] returned `Verified`.
pub fn signature_info(req: &RequestParts<'_>) -> Option<SignatureInfo> {
    let raw_input = joined_header(req.headers, "signature-input", false)?;
    let raw_sig = joined_header(req.headers, "signature", false)?;
    if raw_input.len() > MAX_HEADER_BYTES || raw_sig.len() > MAX_HEADER_BYTES {
        return None;
    }
    let members = sf::parse_dictionary(&raw_input)?;
    let member = members
        .iter()
        .find(|m| matches!(param(m.value.params(), "tag"), Some(Bare::Str(t)) if t == TAG))?;
    let Value::List { items, params } = &member.value else {
        return None;
    };
    let expires = nonneg_int(params, "expires")??;
    let Some(Bare::Str(keyid)) = param(params, "keyid") else {
        return None;
    };
    let sig_members = sf::parse_dictionary(&raw_sig)?;
    let sig = sig_members.iter().find(|m| m.key == member.key).and_then(|m| match &m.value {
        Value::Item(Item {
            bare: Bare::Bytes(b),
            ..
        }) => Some(b),
        _ => None,
    })?;
    let mut h = Sha256::new();
    h.update((keyid.len() as u64).to_be_bytes());
    h.update(keyid.as_bytes());
    h.update(sig);
    let mut components = Vec::new();
    for Item { bare, params } in items {
        let Bare::Str(n) = bare else {
            return None;
        };
        components.push(match params.as_slice() {
            [] => n.clone(),
            [(p, Bare::Str(k))] if p == "key" => format!("{n};key={k}"),
            _ => return None,
        });
    }
    Some(SignatureInfo {
        replay_id: h.finalize().into(),
        expires,
        components,
    })
}

/// Remembers the signatures seen until they expire, to refuse a second use.
///
/// Bounded: when full, the entry closest to expiry is dropped first, so a
/// flood can at worst let an old signature through again, never grow memory.
/// Feed it only verified requests, so that only trusted keys can fill it.
#[derive(Clone, Debug)]
pub struct ReplayCache {
    capacity: usize,
    seen: HashMap<[u8; 32], u64>,
    by_expiry: BTreeSet<(u64, [u8; 32])>,
}

impl ReplayCache {
    /// A cache holding at most `capacity` signatures (at least one).
    pub fn new(capacity: usize) -> ReplayCache {
        ReplayCache {
            capacity: capacity.max(1),
            seen: HashMap::new(),
            by_expiry: BTreeSet::new(),
        }
    }

    /// Records `info` and returns `true` the first time a signature is seen,
    /// `false` when it is a replay. An entry is kept until its `expires` plus
    /// [`CLOCK_SKEW_SECS`], the last moment [`verify`] still accepts it.
    pub fn first_use(&mut self, info: &SignatureInfo, now: u64) -> bool {
        self.purge(now);
        if self.seen.contains_key(&info.replay_id) {
            return false;
        }
        let until = info.expires.saturating_add(CLOCK_SKEW_SECS);
        while self.seen.len() >= self.capacity {
            let Some(oldest) = self.by_expiry.pop_first() else {
                break;
            };
            self.seen.remove(&oldest.1);
        }
        self.seen.insert(info.replay_id, until);
        self.by_expiry.insert((until, info.replay_id));
        true
    }

    /// Number of signatures remembered.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    fn purge(&mut self, now: u64) {
        while let Some(&(until, id)) = self.by_expiry.first() {
            if until >= now {
                break;
            }
            self.by_expiry.pop_first();
            self.seen.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts<'a>(headers: &'a [(&'a str, &'a str)]) -> RequestParts<'a> {
        RequestParts {
            method: "get",
            authority: "Example.COM",
            path: "",
            query: Some(""),
            headers,
        }
    }

    #[test]
    fn derived_components_are_normalised() {
        let r = parts(&[]);
        let base = signature_base(&r, "(\"@method\" \"@authority\" \"@path\" \"@query\");created=1").unwrap();
        assert_eq!(
            base,
            "\"@method\": GET\n\"@authority\": example.com\n\"@path\": /\n\"@query\": ?\n\"@signature-params\": (\"@method\" \"@authority\" \"@path\" \"@query\");created=1"
        );
    }

    #[test]
    fn member_text_is_repeated_verbatim_but_trimmed() {
        let r = parts(&[]);
        let base = signature_base(&r, "  ( \"@method\"  );created=1; keyid=\"k\"  ").unwrap();
        assert!(base.ends_with("\"@signature-params\": ( \"@method\"  );created=1; keyid=\"k\""));
    }

    #[test]
    fn signature_base_rejects_bad_components() {
        let h = [("X-Up", "v"), ("Bad", "line\nbreak"), ("ok", "1")];
        let r = parts(&h);
        let cases = [
            ("(\"X-Up\")", WbaInvalid::Malformed),
            ("(\"bad\")", WbaInvalid::Malformed),
            ("(\"ok\" \"ok\")", WbaInvalid::Malformed),
            ("(\"missing\")", WbaInvalid::Malformed),
            ("(5)", WbaInvalid::Malformed),
            ("\"@method\"", WbaInvalid::Malformed),
            ("(\"@method\"", WbaInvalid::Malformed),
            ("(\"@signature-params\")", WbaInvalid::UnsupportedComponent),
            ("(\"@method\";req)", WbaInvalid::UnsupportedComponent),
            ("(\"a b\")", WbaInvalid::Malformed),
        ];
        for (member, want) in cases {
            assert_eq!(signature_base(&r, member), Err(want), "{member}");
        }
    }

    #[test]
    fn repeated_headers_are_joined_in_order() {
        let h = [("A", " 1 "), ("b", "x"), ("a", "2")];
        let r = parts(&h);
        let base = signature_base(&r, "(\"a\")").unwrap();
        assert!(base.starts_with("\"a\": 1, 2\n"));
    }

    #[test]
    fn multiple_signature_input_headers_form_one_dictionary() {
        let (a, b) = ("x=(\"@authority\");tag=\"other\"", "y=(\"@method\");tag=\"web-bot-auth\"");
        let h = [("Signature-Input", a), ("signature-input", b)];
        // Our member is found in the second header; it lacks @authority.
        assert_eq!(
            verify(&parts(&h), &TrustedAgents::new(), 0),
            WbaVerdict::Invalid(WbaInvalid::MissingAuthority)
        );
    }

    #[test]
    fn bad_integer_parameters_are_malformed() {
        for p in ["created=-1;expires=5", "created=1.5;expires=5", "created=\"1\";expires=5", "created=1;expires=-5"] {
            let input = format!("s=(\"@authority\");{p};keyid=\"k\";tag=\"web-bot-auth\"");
            let h = [("Signature-Input", input.as_str()), ("Signature", "s=:AAAA:")];
            assert_eq!(
                verify(&parts(&h), &TrustedAgents::new(), 1),
                WbaVerdict::Invalid(WbaInvalid::Malformed),
                "{p}"
            );
        }
    }

    #[test]
    fn huge_times_do_not_overflow() {
        let input =
            "s=(\"@authority\");created=999999999999999;expires=999999999999999;keyid=\"k\";tag=\"web-bot-auth\"";
        let h = [("Signature-Input", input), ("Signature", "s=:AAAA:")];
        let v = verify(&parts(&h), &TrustedAgents::new(), u64::MAX);
        assert_eq!(v, WbaVerdict::Invalid(WbaInvalid::Expired));
    }

    #[test]
    fn add_is_atomic_and_rejects_duplicates_within_one_call() {
        let k = Ed25519Key::from_public([7; 32]);
        let mut t = TrustedAgents::new();
        assert!(t.add("a", None, vec![k.clone(), k.clone()]).is_err());
        assert!(t.is_empty());
        t.add("a", None, vec![k.clone()]).unwrap();
        assert!(t.add("b", None, vec![Ed25519Key::from_public([8; 32]), k]).is_err());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn directory_edge_cases() {
        assert!(matches!(parse_directory("[]"), Err(WbaError::Json(_))));
        assert!(matches!(parse_directory(r#"{"keys":[1]}"#), Err(WbaError::Json(_))));
        assert!(matches!(
            parse_directory(r#"{"keys":[{"kty":"OKP","crv":"Ed25519"}]}"#),
            Err(WbaError::BadKey(_))
        ));
        let x = URL_SAFE_NO_PAD.encode([1u8; 32]);
        let bad_time = format!(r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{x}","nbf":-1}}]}}"#);
        assert!(matches!(parse_directory(&bad_time), Err(WbaError::BadKey(_))));
        assert!(matches!(
            TrustedAgents::from_json(r#"{"agents":[{"keys":[]}]}"#),
            Err(WbaError::Json(_))
        ));
    }

    #[test]
    fn detection_for_unknown_key_and_clean_verdicts() {
        assert!(WbaVerdict::Absent.detection().is_none());
        let d = WbaVerdict::UnknownKey { keyid: "k".into() }.detection().unwrap();
        assert_eq!((d.id.as_str(), d.penalty), ("wba_unknown_key", 20));
    }

    #[test]
    fn non_ascii_and_control_input_never_panics() {
        let weird = "s=(\"@authörity\" \"\u{0}\");created=1;keyid=\"\u{e9}\u{1f600}\";tag=\"web-bot-auth\"";
        let h = [("Signature-Input", weird), ("Signature", "s=:\u{e9}:")];
        let r = RequestParts { method: "\u{e9}", authority: "\u{1f600}", path: "\u{0}", query: Some("\n"), headers: &h };
        let _ = verify(&r, &TrustedAgents::new(), 5);
        let _ = signature_base(&r, weird);
    }
}
