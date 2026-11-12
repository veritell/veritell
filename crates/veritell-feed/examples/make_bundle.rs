//! Signs a feed bundle. A test and operations helper; the gateway never
//! signs.
//!
//!   make_bundle pubkey <seed-hex>
//!   make_bundle seal <seed-hex> <version> <created> <expires> <name>=<path>...
//!
//! `seed-hex` is the 32-byte Ed25519 private seed as 64 hex characters.
//! `pubkey` prints the public key in the form `--feed-key` expects. `seal`
//! writes the bundle to standard output.

use std::collections::BTreeMap;
use std::io::Write;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

fn fail(message: &str) -> ! {
    eprintln!("make_bundle: {message}");
    std::process::exit(2);
}

fn seed(hex: &str) -> [u8; 32] {
    let bytes: Option<Vec<u8>> = (0..hex.len())
        .step_by(2)
        .map(|i| hex.get(i..i + 2).and_then(|pair| u8::from_str_radix(pair, 16).ok()))
        .collect();
    bytes
        .and_then(|b| b.try_into().ok())
        .unwrap_or_else(|| fail("seed must be 64 hex characters"))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg = |i: usize| args.get(i).map(String::as_str).unwrap_or_else(|| fail("missing argument"));
    match arg(0) {
        "pubkey" => println!("{}", URL_SAFE_NO_PAD.encode(veritell_feed::public_key(&seed(arg(1))).0)),
        "seal" => {
            let number = |i: usize| arg(i).parse::<u64>().unwrap_or_else(|_| fail("version and times must be integers"));
            let mut files = BTreeMap::new();
            for spec in args.iter().skip(5) {
                let (name, path) = spec.split_once('=').unwrap_or_else(|| fail("files are given as name=path"));
                let content = std::fs::read(path).unwrap_or_else(|e| fail(&format!("{path}: {e}")));
                files.insert(name.to_string(), content);
            }
            match veritell_feed::seal(&files, number(2), number(3), number(4), &seed(arg(1))) {
                Ok(bundle) => {
                    if std::io::stdout().write_all(&bundle).is_err() {
                        fail("could not write the bundle");
                    }
                }
                Err(e) => fail(&e.to_string()),
            }
        }
        _ => fail("usage: make_bundle pubkey <seed-hex> | seal <seed-hex> <version> <created> <expires> <name>=<path>..."),
    }
}
