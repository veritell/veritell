//! `open_report <template path> <secret> <unix now> < sealed-body`: prints the
//! version 1 report JSON, or the error on stderr with exit code 1.

use std::io::Read;

use veritell_probe_build::Builder;

fn fail(message: &str) -> ! {
    eprintln!("open_report: {message}");
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [path, secret, now] = match <[String; 3]>::try_from(args) {
        Ok(a) => a,
        Err(_) => fail("usage: open_report <template path> <secret> <unix now> < sealed-body"),
    };
    let now: u64 = now.parse().unwrap_or_else(|_| fail("unix now must be an integer"));
    let template = std::fs::read_to_string(&path).unwrap_or_else(|e| fail(&format!("{path}: {e}")));
    let builder = Builder::new(&template, secret.as_bytes()).unwrap_or_else(|e| fail(&e.to_string()));
    let mut body = Vec::new();
    if let Err(e) = std::io::stdin().take(1 << 20).read_to_end(&mut body) {
        fail(&format!("stdin: {e}"));
    }
    match builder.open(&body, now) {
        Ok(opened) => println!("{}", String::from_utf8_lossy(&opened.report_json)),
        Err(e) => fail(&e.to_string()),
    }
}
