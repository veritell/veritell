#![no_main]
// Web Bot Auth: a request's method, authority, path, query and its
// Signature-Input, Signature and Signature-Agent headers, all attacker
// controlled. Fields are separated by 0xFF. The first byte picks the mode:
//
//   0      a key directory, as a remote server supplies it
//   1      an agents file, as an operator supplies it
//   2..=4  a request whose signature is whatever the input says
//   5..=7  a request the harness signs with a trusted key, so the fuzzer
//          gets past the signature check and reaches what comes after it
//          (time window, Signature-Agent rules, key validity, replay
//          facts); bits 6 and 7 pick the key
//
// Properties checked on every `Verified` verdict, beyond "does not panic":
// `@authority` is covered; the signature is not expired; a Signature-Agent
// header is covered; an agent pinned to a Signature-Agent value got it; a
// key with validity dates is used only within them; the
// replay facts exist and are stable; and changing any covered request part
// that changes the signature base makes verification fail.
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use std::sync::OnceLock;
use veritell_wba::{
    jwk_thumbprint_ed25519, parse_directory, signature_base, signature_info, verify, Ed25519Key, RequestParts,
    TrustedAgents, WbaVerdict, CLOCK_SKEW_SECS,
};

/// RFC 9421 B.1.4's public key, trusted directly.
const RFC_KEY_X: [u8; 32] = [
    0x26, 0xb4, 0x0b, 0x8f, 0x93, 0xff, 0xf3, 0xd8, 0x97, 0x11, 0x2f, 0x7e, 0xbc, 0x58, 0x2b, 0x23,
    0x2d, 0xbd, 0x72, 0x51, 0x7d, 0x08, 0x2f, 0xe8, 0x3c, 0xfb, 0x30, 0xdd, 0xce, 0x43, 0xd1, 0xbb,
];
const CREATED: u64 = 1_735_689_600;
/// The Signature-Agent value the agent "listed" is pinned to.
const LISTED_AGENT: &str = "https://signature-agent.test";

/// The "dated" key's validity, in seconds after `CREATED`.
const DATED_FROM: u64 = 1_000;
const DATED_UNTIL: u64 = 5_000;

/// Throwaway signing keys: "listed" (pinned to a Signature-Agent), "plain"
/// (not pinned) and "dated" (valid only from `DATED_FROM` to `DATED_UNTIL`).
fn signers() -> &'static [(SigningKey, String); 3] {
    static S: OnceLock<[(SigningKey, String); 3]> = OnceLock::new();
    S.get_or_init(|| {
        [0x42u8, 0x43, 0x44].map(|seed| {
            let k = SigningKey::from_bytes(&[seed; 32]);
            let id = jwk_thumbprint_ed25519(&k.verifying_key().to_bytes());
            (k, id)
        })
    })
}

fn trusted() -> &'static TrustedAgents {
    static T: OnceLock<TrustedAgents> = OnceLock::new();
    T.get_or_init(|| {
        let mut t = TrustedAgents::new();
        t.add("direct", None, vec![Ed25519Key::from_public(RFC_KEY_X)]).unwrap();
        let [listed, plain, dated] = signers();
        t.add("listed", Some(LISTED_AGENT), vec![Ed25519Key::from_public(listed.0.verifying_key().to_bytes())])
            .unwrap();
        t.add("plain", None, vec![Ed25519Key::from_public(plain.0.verifying_key().to_bytes())]).unwrap();
        let mut key = Ed25519Key::from_public(dated.0.verifying_key().to_bytes());
        key.not_before = Some(CREATED + DATED_FROM);
        key.not_after = Some(CREATED + DATED_UNTIL);
        t.add("dated", None, vec![key]).unwrap();
        t
    })
}

fn text(b: &[u8]) -> &str {
    std::str::from_utf8(b).unwrap_or("")
}

/// The request's parts, owned so a mutated copy can be built.
#[derive(Clone)]
struct Req {
    method: String,
    authority: String,
    path: String,
    query: Option<String>,
    headers: Vec<(String, String)>,
}

impl Req {
    fn check(&self, now: u64) -> (WbaVerdict, Option<veritell_wba::SignatureInfo>) {
        let headers: Vec<(&str, &str)> = self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let parts = RequestParts {
            method: &self.method,
            authority: &self.authority,
            path: &self.path,
            query: self.query.as_deref(),
            headers: &headers,
        };
        (verify(&parts, trusted(), now), signature_info(&parts))
    }

    fn base(&self, member: &str) -> Option<String> {
        let headers: Vec<(&str, &str)> = self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let parts = RequestParts {
            method: &self.method,
            authority: &self.authority,
            path: &self.path,
            query: self.query.as_deref(),
            headers: &headers,
        };
        signature_base(&parts, member).ok()
    }

    fn header(&self, name: &str) -> bool {
        self.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
    }
}

/// The member that `verify` reads: the first in `Signature-Input` tagged
/// `web-bot-auth`. Found here by text, which is enough for the seeds' shape.
fn tagged_member(req: &Req) -> Option<(String, String)> {
    let raw: Vec<&str> = req
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("signature-input"))
        .map(|(_, v)| v.as_str())
        .collect();
    let joined = raw.join(", ");
    let (label, member) = joined.split_once('=')?;
    member.contains("tag=\"web-bot-auth\"").then(|| (label.trim().to_string(), member.trim().to_string()))
}

/// `VERITELL_FUZZ_DEBUG=1` prints each verdict, to check that seeds reach
/// the verdict they are meant to.
fn debug() -> bool {
    static D: OnceLock<bool> = OnceLock::new();
    *D.get_or_init(|| std::env::var_os("VERITELL_FUZZ_DEBUG").is_some())
}

fn properties(req: &Req, now: u64) {
    let (verdict, info) = req.check(now);
    if debug() {
        eprintln!("verdict: {verdict:?}");
    }
    let WbaVerdict::Verified { agent, .. } = &verdict else { return };
    let info = info.expect("Verified but signature_info found no signature");
    assert!(info.covers("@authority"), "Verified without @authority covered: {:?}", info.components);
    assert!(info.expires.saturating_add(CLOCK_SKEW_SECS) >= now, "Verified an expired signature");
    if req.header("signature-agent") {
        assert!(
            info.components.iter().any(|c| c == "signature-agent" || c.starts_with("signature-agent;key=")),
            "Verified with an uncovered Signature-Agent: {:?}",
            info.components
        );
    }
    if agent == "listed" {
        assert!(req.header("signature-agent"), "pinned agent verified without a Signature-Agent header");
    }
    if agent == "dated" {
        assert!((CREATED + DATED_FROM..=CREATED + DATED_UNTIL).contains(&now), "key used outside its validity");
    }
    assert_eq!(req.check(now).1.map(|i| i.replay_id), Some(info.replay_id), "replay id not stable");

    // Change each covered part. Where the signature base changes, the
    // signature must no longer verify.
    let Some((_, member)) = tagged_member(req) else { return };
    let Some(base) = req.base(&member) else { return };
    let mut variants: Vec<Req> = Vec::new();
    let mut v = req.clone();
    v.method.push('X');
    variants.push(v);
    let mut v = req.clone();
    v.authority.insert(0, 'x');
    variants.push(v);
    let mut v = req.clone();
    v.path.push('x');
    variants.push(v);
    let mut v = req.clone();
    v.query = Some(format!("{}x", v.query.unwrap_or_default()));
    variants.push(v);
    for i in 0..req.headers.len() {
        let name = req.headers[i].0.to_ascii_lowercase();
        if name == "signature" || name == "signature-input" {
            continue;
        }
        let mut v = req.clone();
        v.headers[i].1.push('x');
        variants.push(v);
        let mut v = req.clone();
        v.headers.remove(i);
        variants.push(v);
    }
    for v in variants {
        if v.base(&member).as_deref() == Some(base.as_str()) {
            continue;
        }
        if let (WbaVerdict::Verified { .. }, _) = v.check(now) {
            panic!("a changed request still verifies; base was:\n{base}\nnow:\n{:?}", v.base(&member));
        }
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else { return };
    match pick % 8 {
        0 => {
            if let Ok(keys) = parse_directory(text(rest)) {
                for k in &keys {
                    assert_eq!(k.keyid, jwk_thumbprint_ed25519(&k.public), "key id is not the thumbprint");
                }
            }
        }
        1 => {
            let _ = TrustedAgents::from_json(text(rest));
        }
        mode => {
            let f: Vec<&str> = rest.split(|&b| b == 0xFF).map(text).collect();
            let get = |i: usize| f.get(i).copied().unwrap_or("");
            let signed = mode >= 5;
            // Bits 6 and 7 pick the key: listed, plain, dated, plain.
            let (key, keyid) = &signers()[[0, 1, 2, 1][usize::from(pick >> 6)]];
            // In signed mode `%k` in Signature-Input stands for the signing
            // key's id, so the fuzzer need not find 43 exact characters.
            let input = if signed { get(4).replace("%k", keyid) } else { get(4).to_string() };
            let mut req = Req {
                method: if get(0).is_empty() { "GET" } else { get(0) }.to_string(),
                authority: if get(1).is_empty() { "example.com" } else { get(1) }.to_string(),
                path: if get(2).is_empty() { "/" } else { get(2) }.to_string(),
                query: (f.len() > 3 && !get(3).is_empty()).then(|| get(3).to_string()),
                headers: Vec::new(),
            };
            if f.len() > 4 {
                req.headers.push(("signature-input".into(), input.clone()));
            }
            // Fields 6 and 7 add a header only when not empty, so that a
            // later field can be reached without them.
            if !get(6).is_empty() {
                req.headers.push(("signature-agent".into(), get(6).to_string()));
            }
            // Repeated or oddly cased headers, as a client may send them.
            if !get(7).is_empty() {
                req.headers.push(("Signature-Input".into(), get(7).to_string()));
            }
            if f.len() > 8 {
                req.headers.push((get(8).to_string(), get(9).to_string()));
            }
            let signature = if signed {
                // Sign the base of the first member, as a well-behaved
                // client would; field 5, if it has `%s`, says where the
                // signature goes, else it is `label=:sig:`.
                let (label, member) = input.split_once('=').unwrap_or(("sig1", ""));
                match req.base(member.trim()) {
                    Some(base) => {
                        let sig = base64::engine::general_purpose::STANDARD.encode(key.sign(base.as_bytes()).to_bytes());
                        if get(5).contains("%s") {
                            get(5).replace("%s", &format!(":{sig}:"))
                        } else {
                            format!("{}=:{sig}:", label.trim())
                        }
                    }
                    None => get(5).to_string(),
                }
            } else {
                get(5).to_string()
            };
            if f.len() > 5 {
                req.headers.insert(1.min(req.headers.len()), ("signature".into(), signature));
            }
            let now = CREATED + u64::from(pick) * 37;
            properties(&req, now);
            if let Some((_, member)) = input.split_once('=') {
                let _ = req.base(member);
            }
        }
    }
});
