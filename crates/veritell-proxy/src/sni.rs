//! More than one certificate on one listener, chosen by SNI (`--sni-dir`).
//!
//! `--cert`/`--key` stay the default. `--sni-dir` names a directory whose
//! subdirectories each hold `fullchain.pem` and `privkey.pem` (the layout of
//! `/etc/letsencrypt/live/<name>/`). Each certificate is served to clients
//! that ask, by SNI, for one of the DNS names it lists, including a
//! `*.example.org` wildcard for one label. Any other name, or no SNI at all,
//! gets the default certificate, so adding a directory never changes what an
//! existing site serves.
//!
//! A per-name certificate is applied by switching the connection to a small
//! context that holds only that certificate and its chain, as nginx does.
//! BoringSSL reads the ALPN callback from the switched context, so each one
//! is given the listener's preference: HTTP/2, then HTTP/1.1.

use std::collections::HashMap;
use std::path::Path;

use boring::ssl::{select_next_proto, AlpnError, SslContext, SslContextBuilder, SslFiletype, SslMethod};
use boring::x509::X509;

/// h2 first, then http/1.1, in ALPN wire format.
const ALPN_H2_H1: &[u8] = b"\x02h2\x08http/1.1";

pub struct SniCerts {
    exact: HashMap<String, SslContext>,
    /// `*.example.org` stored as `example.org`.
    wildcard: HashMap<String, SslContext>,
    /// Directory name and the names it serves, for the start-up line.
    pub loaded: Vec<(String, Vec<String>)>,
}

impl std::fmt::Debug for SniCerts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniCerts").field("loaded", &self.loaded).finish_non_exhaustive()
    }
}

impl SniCerts {
    /// Loads every `<dir>/<name>/{fullchain,privkey}.pem`. A subdirectory
    /// without both files is skipped; one with a broken pair, or a DNS name
    /// already served by another certificate, is an error.
    pub fn load(dir: &Path) -> Result<SniCerts, String> {
        let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let mut dirs: Vec<_> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_dir())
            .collect();
        dirs.sort();
        let mut out = SniCerts { exact: HashMap::new(), wildcard: HashMap::new(), loaded: Vec::new() };
        for sub in dirs {
            let (chain, key) = (sub.join("fullchain.pem"), sub.join("privkey.pem"));
            if !chain.is_file() || !key.is_file() {
                continue;
            }
            let label = sub.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let names = dns_names(&chain).map_err(|e| format!("{}: {e}", chain.display()))?;
            if names.is_empty() {
                return Err(format!("{}: the certificate lists no DNS names", chain.display()));
            }
            let ctx = context(&chain, &key).map_err(|e| format!("{}: {e}", sub.display()))?;
            for name in &names {
                let (map, key_name) = match name.strip_prefix("*.") {
                    Some(rest) => (&mut out.wildcard, rest.to_string()),
                    None => (&mut out.exact, name.clone()),
                };
                if map.insert(key_name, ctx.clone()).is_some() {
                    return Err(format!("{name} is listed by more than one certificate in {}", dir.display()));
                }
            }
            out.loaded.push((label, names));
        }
        Ok(out)
    }

    /// The context for a requested name: an exact match, else a wildcard
    /// for its first label. Names compare without case.
    pub fn find(&self, server_name: &str) -> Option<&SslContext> {
        let name = server_name.trim_end_matches('.').to_ascii_lowercase();
        if let Some(ctx) = self.exact.get(&name) {
            return Some(ctx);
        }
        let (_, parent) = name.split_once('.')?;
        // A wildcard covers exactly one label, never a bare parent domain.
        parent.contains('.').then(|| self.wildcard.get(parent)).flatten()
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcard.is_empty()
    }
}

/// The DNS names in the leaf certificate's subjectAltName, lower case.
fn dns_names(chain: &Path) -> Result<Vec<String>, String> {
    let pem = std::fs::read(chain).map_err(|e| e.to_string())?;
    let leaf = X509::from_pem(&pem).map_err(|e| e.to_string())?;
    let mut names: Vec<String> = leaf
        .subject_alt_names()
        .map(|sans| sans.iter().filter_map(|n| n.dnsname().map(str::to_ascii_lowercase)).collect())
        .unwrap_or_default();
    names.sort();
    names.dedup();
    Ok(names)
}

fn context(chain: &Path, key: &Path) -> Result<SslContext, String> {
    let mut b = SslContextBuilder::new(SslMethod::tls()).map_err(|e| e.to_string())?;
    b.set_certificate_chain_file(chain).map_err(|e| format!("certificate: {e}"))?;
    b.set_private_key_file(key, SslFiletype::PEM).map_err(|e| format!("private key: {e}"))?;
    b.check_private_key().map_err(|_| "the private key does not match the certificate".to_string())?;
    b.set_alpn_select_callback(|_, client| select_next_proto(ALPN_H2_H1, client).ok_or(AlpnError::NOACK));
    Ok(b.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certs(dir: &Path, sub: &str, names: &[&str]) {
        let d = dir.join(sub);
        std::fs::create_dir_all(&d).unwrap();
        let san = names.iter().map(|n| format!("DNS:{n}")).collect::<Vec<_>>().join(",");
        let ok = std::process::Command::new("openssl")
            .args(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1"])
            .args(["-subj", &format!("/CN={}", names[0]), "-addext", &format!("subjectAltName={san}")])
            .arg("-keyout").arg(d.join("privkey.pem"))
            .arg("-out").arg(d.join("fullchain.pem"))
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        assert!(ok, "openssl could not make a test certificate");
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("veritell-sni-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn exact_and_wildcard_names() {
        let d = tmp("names");
        certs(&d, "a", &["veritell.io", "www.veritell.io"]);
        certs(&d, "b", &["*.apps.example.org"]);
        let s = SniCerts::load(&d).unwrap();
        assert!(s.find("veritell.io").is_some());
        assert!(s.find("WWW.Veritell.IO.").is_some());
        assert!(s.find("x.apps.example.org").is_some());
        assert!(s.find("apps.example.org").is_none(), "a wildcard does not cover its parent");
        assert!(s.find("a.b.apps.example.org").is_none(), "a wildcard covers one label");
        assert!(s.find("other.example").is_none());
        assert_eq!(s.loaded.len(), 2);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn incomplete_folders_are_skipped_and_duplicates_refused() {
        let d = tmp("dupes");
        std::fs::create_dir_all(d.join("empty")).unwrap();
        certs(&d, "a", &["veritell.io"]);
        assert_eq!(SniCerts::load(&d).unwrap().loaded.len(), 1);
        certs(&d, "b", &["veritell.io"]);
        assert!(SniCerts::load(&d).unwrap_err().contains("more than one certificate"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_key_that_does_not_match_is_refused() {
        let d = tmp("mismatch");
        certs(&d, "a", &["a.test"]);
        certs(&d, "b", &["b.test"]);
        std::fs::copy(d.join("b/privkey.pem"), d.join("a/privkey.pem")).unwrap();
        // BoringSSL refuses the pair while loading the key, or at the check.
        let err = SniCerts::load(&d).unwrap_err();
        assert!(err.contains("private key"), "{err}");
        let _ = std::fs::remove_dir_all(&d);
    }
}
