//! Seals a version 1 report the way a browser would. Used by the end-to-end
//! script and the bot lab to produce reports without a browser.
//!
//!   seal_report <template path> <secret> <build id> <nonce> < report.json
//!
//! Writes the sealed body to standard output.

use std::io::{Read, Write};

fn fail(message: &str) -> ! {
    eprintln!("seal_report: {message}");
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [template, secret, build_id, nonce] = args.as_slice() else {
        fail("usage: seal_report <template path> <secret> <build id> <nonce> < report.json");
    };
    let template = std::fs::read_to_string(template).unwrap_or_else(|e| fail(&e.to_string()));
    let builder = veritell_probe_build::Builder::new(&template, secret.as_bytes())
        .unwrap_or_else(|e| fail(&e.to_string()));
    let mut report = Vec::new();
    if std::io::stdin().read_to_end(&mut report).is_err() {
        fail("could not read the report");
    }
    let mut iv = [0u8; 12];
    if getrandom::fill(&mut iv).is_err() {
        fail("no random source");
    }
    match builder.seal(build_id, nonce, &report, iv) {
        Ok(body) => {
            if std::io::stdout().write_all(&body).is_err() {
                fail("could not write the sealed report");
            }
        }
        Err(e) => fail(&e.to_string()),
    }
}
