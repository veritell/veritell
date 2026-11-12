//! Agents whose keys are fetched: reading the agents file, and the
//! background thread that keeps each agent's key directory current.
//!
//! Which directories are fetched is the operator's decision, never the
//! request's. A request names a directory in `Signature-Agent`; the gateway
//! fetches only the ones listed in the agents file, on this thread, and a
//! request reads whatever was last fetched. A `Signature-Agent` that is not
//! listed is never fetched, so a client cannot make the gateway connect
//! anywhere.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use veritell_directory::{fetch_with, Cache, DirectoryUrl, FetchConfig, Transport};
use veritell_feed::Live;
use veritell_wba::{Ed25519Key, TrustedAgents};

/// Most agents with a fetched directory.
pub const MAX_FETCHED_AGENTS: usize = 256;
/// The trusted set is rebuilt at least this often, so keys that have aged
/// out are dropped even when nothing was fetched.
const REBUILD_EVERY_SECS: u64 = 60;

/// An agent whose keys are written in the agents file.
pub struct FixedAgent {
    pub name: String,
    pub signature_agent: Option<String>,
    pub keys: Vec<Ed25519Key>,
}

/// An agent whose keys are published at the URL it sends in
/// `Signature-Agent`.
pub struct FetchedAgent {
    pub name: String,
    /// Exactly as the operator wrote it: a request's `Signature-Agent`
    /// member must be this text.
    pub signature_agent: String,
    pub url: DirectoryUrl,
}

#[derive(Default)]
pub struct AgentsConfig {
    pub fixed: Vec<FixedAgent>,
    pub fetched: Vec<FetchedAgent>,
}

/// Reads the agents file:
/// `{"agents":[{"name":"a","keys":[JWK, ...]},
///             {"name":"b","signature_agent":"https://b.example/keys.json"}]}`.
/// An entry with `keys` is trusted for those keys (and, if it also has
/// `signature_agent`, only when the request names it). An entry without
/// `keys` must have `signature_agent`, and its keys are fetched from there.
pub fn parse_agents(json: &str) -> Result<AgentsConfig, String> {
    let root: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("invalid JSON: {e}"))?;
    let agents = root
        .get("agents")
        .and_then(serde_json::Value::as_array)
        .ok_or("expected an object with an \"agents\" array")?;
    let mut config = AgentsConfig::default();
    for agent in agents {
        let name = agent
            .get("name")
            .and_then(serde_json::Value::as_str)
            .filter(|n| !n.is_empty())
            .ok_or("agent without a \"name\"")?;
        let signature_agent = match agent.get("signature_agent") {
            None | Some(serde_json::Value::Null) => None,
            Some(v) => Some(v.as_str().ok_or_else(|| format!("{name}: \"signature_agent\" is not a string"))?),
        };
        match (agent.get("keys"), signature_agent) {
            (Some(keys), _) => {
                let keys = veritell_wba::parse_directory(&serde_json::json!({ "keys": keys }).to_string())
                    .map_err(|e| format!("{name}: {e}"))?;
                config.fixed.push(FixedAgent {
                    name: name.to_string(),
                    signature_agent: signature_agent.map(str::to_string),
                    keys,
                });
            }
            (None, Some(text)) => {
                let url = veritell_directory::parse_url(text).map_err(|e| format!("{name}: {e}"))?;
                if config.fetched.len() >= MAX_FETCHED_AGENTS {
                    return Err(format!("more than {MAX_FETCHED_AGENTS} agents with a fetched directory"));
                }
                config.fetched.push(FetchedAgent { name: name.to_string(), signature_agent: text.to_string(), url });
            }
            (None, None) => return Err(format!("{name}: needs \"keys\" or \"signature_agent\"")),
        }
    }
    // The fixed part must be usable as it stands.
    build(&config, &[], 0).1.into_iter().next().map_or(Ok(config), Err)
}

/// The agents to trust at `now`: the fixed ones, then each fetched agent
/// with the keys its directory last gave. `caches` runs parallel to
/// `config.fetched`. A key is trusted for one agent only. A key that a fixed
/// agent has, or that more than one fetched directory publishes, is trusted
/// for no fetched agent; each fetched agent keeps its other keys, and every
/// such key is reported. The result does not depend on the order of the
/// agents in the file, nor on which directory published the key first.
pub fn build(config: &AgentsConfig, caches: &[Cache], now: u64) -> (TrustedAgents, Vec<String>) {
    use std::collections::{HashMap, HashSet};
    let mut trusted = TrustedAgents::new();
    let mut problems = Vec::new();
    for agent in &config.fixed {
        if let Err(e) = trusted.add(&agent.name, agent.signature_agent.as_deref(), agent.keys.clone()) {
            problems.push(e.to_string());
        }
    }
    let fixed: HashSet<&str> = config.fixed.iter().flat_map(|a| a.keys.iter().map(|k| k.keyid.as_str())).collect();
    let fetched: Vec<(&FetchedAgent, &[Ed25519Key])> =
        config.fetched.iter().zip(caches).map(|(a, c)| (a, c.keys(now))).collect();
    // Which fetched agents publish each key id (each agent counted once).
    let mut publishers: HashMap<&str, Vec<&str>> = HashMap::new();
    for (agent, keys) in &fetched {
        let mut ids: Vec<&str> = keys.iter().map(|k| k.keyid.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        for id in ids {
            publishers.entry(id).or_default().push(agent.name.as_str());
        }
    }
    let contested = |id: &str| fixed.contains(id) || publishers.get(id).is_some_and(|p| p.len() > 1);
    for (agent, keys) in fetched {
        if keys.is_empty() {
            continue;
        }
        let mut kept: Vec<Ed25519Key> = Vec::new();
        for key in keys {
            if contested(&key.keyid) {
                let others: Vec<&str> = publishers
                    .get(key.keyid.as_str())
                    .map(|p| p.iter().copied().filter(|n| *n != agent.name).collect())
                    .unwrap_or_default();
                let by = if fixed.contains(key.keyid.as_str()) { "a fixed agent".to_string() } else { others.join(", ") };
                problems.push(format!("{}: key id {} is also published by {by}; trusted for no fetched agent", agent.name, key.keyid));
            } else if !kept.iter().any(|k| k.keyid == key.keyid) {
                kept.push(key.clone());
            }
        }
        if kept.is_empty() {
            problems.push(format!("{}: no key left to trust", agent.name));
            continue;
        }
        if let Err(e) = trusted.add(&agent.name, Some(&agent.signature_agent), kept) {
            problems.push(e.to_string());
        }
    }
    (trusted, problems)
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Runs forever on its own thread.
pub fn run(config: AgentsConfig, live: Arc<Live<TrustedAgents>>, transport: impl Transport, fetch: FetchConfig) {
    let mut caches: Vec<Cache> = config.fetched.iter().map(|_| Cache::new()).collect();
    let mut last_build = 0u64;
    let mut last_problems: Vec<String> = Vec::new();
    loop {
        let mut changed = false;
        for (agent, cache) in config.fetched.iter().zip(caches.iter_mut()) {
            let now = now_secs();
            if !cache.due(now) {
                continue;
            }
            match fetch_with(&transport, &agent.url, &fetch) {
                Ok(fetched) => {
                    eprintln!(
                        "veritell: key directory for {} loaded: {} keys, next fetch in {} s",
                        agent.name,
                        fetched.keys.len(),
                        fetched.ttl_secs
                    );
                    cache.on_success(fetched, now_secs());
                }
                Err(e) => {
                    eprintln!("veritell: key directory for {} refused: {e}", agent.name);
                    cache.on_failure(now_secs());
                }
            }
            changed = true;
        }
        let now = now_secs();
        if changed || now.saturating_sub(last_build) >= REBUILD_EVERY_SECS {
            let (trusted, problems) = build(&config, &caches, now);
            if problems != last_problems {
                for p in &problems {
                    eprintln!("veritell: agent left out: {p}");
                }
                last_problems = problems;
            }
            live.store(trusted);
            last_build = now;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veritell_directory::Fetched;

    const FILE: &str = r#"{"agents":[
        {"name":"fixed","keys":[{"kty":"OKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}]},
        {"name":"fetched","signature_agent":"https://agent.example/keys.json"},
        {"name":"second","signature_agent":"https://second.example:8443/k"}
    ]}"#;

    fn key(seed: u8) -> Ed25519Key {
        Ed25519Key::from_public([seed; 32])
    }

    #[test]
    fn the_file_is_split_into_fixed_and_fetched() {
        let c = parse_agents(FILE).unwrap();
        assert_eq!(c.fixed.len(), 1);
        assert_eq!(c.fetched.len(), 2);
        assert_eq!(c.fetched[0].url.host, "agent.example");
        assert_eq!(c.fetched[1].url.port, 8443);
    }

    #[test]
    fn entries_that_are_refused() {
        for bad in [
            "{}",
            r#"{"agents":[{"name":"a"}]}"#,
            r#"{"agents":[{"name":"","signature_agent":"https://a.example/"}]}"#,
            r#"{"agents":[{"name":"a","signature_agent":"http://a.example/"}]}"#,
            r#"{"agents":[{"name":"a","signature_agent":"https://user@a.example/"}]}"#,
            r#"{"agents":[{"name":"a","signature_agent":7}]}"#,
            r#"{"agents":[{"name":"a","keys":[]}]}"#,
            // One key for two agents.
            r#"{"agents":[{"name":"a","keys":[{"kty":"OKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}]},
                         {"name":"b","keys":[{"kty":"OKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}]}]}"#,
        ] {
            assert!(parse_agents(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn fetched_keys_are_trusted_only_while_the_cache_has_them() {
        let c = parse_agents(FILE).unwrap();
        let mut caches = vec![Cache::new(), Cache::new()];
        assert_eq!(build(&c, &caches, 100).0.len(), 1);
        caches[0].on_success(Fetched { keys: vec![key(1), key(2)], ttl_secs: 600 }, 100);
        let (trusted, problems) = build(&c, &caches, 100);
        assert_eq!((trusted.len(), problems.len()), (3, 0));
        // Long after every refresh failed, they are gone again.
        let later = 100 + 600 + veritell_directory::MAX_STALE_SECS + 1;
        assert_eq!(build(&c, &caches, later).0.len(), 1);
    }

    #[test]
    fn a_key_two_directories_publish_is_trusted_for_neither() {
        let c = parse_agents(FILE).unwrap();
        let mut caches = vec![Cache::new(), Cache::new()];
        caches[0].on_success(Fetched { keys: vec![key(1), key(2)], ttl_secs: 600 }, 100);
        // The second directory publishes the first agent's key beside its own.
        caches[1].on_success(Fetched { keys: vec![key(9), key(1)], ttl_secs: 600 }, 100);
        let (trusted, problems) = build(&c, &caches, 100);
        // `len` counts keys: the fixed one, key 2 (fetched), key 9 (second).
        // Nobody is left out whole, and key 1 is trusted for neither.
        assert_eq!(trusted.len(), 3, "{problems:?}");
        assert_eq!(problems.len(), 2, "one line per agent that lost key 1: {problems:?}");
        assert!(problems.iter().all(|p| p.contains(&key(1).keyid)));
        // Nor the fixed agent's key: "second", with only that key, is out;
        // key 1 is no longer contested, so "fetched" has keys 1 and 2 again.
        let fixed = c.fixed[0].keys[0].clone();
        caches[1].on_success(Fetched { keys: vec![fixed], ttl_secs: 600 }, 100);
        let (trusted, problems) = build(&c, &caches, 100);
        assert_eq!(trusted.len(), 3, "{problems:?}");
        assert!(problems.iter().any(|p| p.contains("a fixed agent")));
    }

    #[test]
    fn the_result_does_not_depend_on_the_order_of_the_file() {
        let a = parse_agents(FILE).unwrap();
        let b = parse_agents(&FILE.replace(
            r#"{"name":"fetched","signature_agent":"https://agent.example/keys.json"},
        {"name":"second","signature_agent":"https://second.example:8443/k"}"#,
            r#"{"name":"second","signature_agent":"https://second.example:8443/k"},
        {"name":"fetched","signature_agent":"https://agent.example/keys.json"}"#,
        ))
        .unwrap();
        assert_eq!(b.fetched[0].name, "second");
        let caches = |first: Vec<Ed25519Key>, second: Vec<Ed25519Key>| {
            let mut c = vec![Cache::new(), Cache::new()];
            c[0].on_success(Fetched { keys: first, ttl_secs: 600 }, 100);
            c[1].on_success(Fetched { keys: second, ttl_secs: 600 }, 100);
            c
        };
        let (ta, pa) = build(&a, &caches(vec![key(1), key(2)], vec![key(9), key(1)]), 100);
        let (tb, pb) = build(&b, &caches(vec![key(9), key(1)], vec![key(1), key(2)]), 100);
        assert_eq!((ta.len(), pa.len()), (tb.len(), pb.len()));
    }
}
