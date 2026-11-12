//! `make_build <template path> <secret> <unix now> <ttl secs>`: prints a new
//! build of the probe to stdout. Used by the browser test harness.

use veritell_probe_build::Builder;

fn fail(message: &str) -> ! {
    eprintln!("make_build: {message}");
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [path, secret, now, ttl] = match <[String; 4]>::try_from(args) {
        Ok(a) => a,
        Err(_) => fail("usage: make_build <template path> <secret> <unix now> <ttl secs>"),
    };
    let now: u64 = now.parse().unwrap_or_else(|_| fail("unix now must be an integer"));
    let ttl: u64 = ttl.parse().unwrap_or_else(|_| fail("ttl must be an integer"));
    let template = std::fs::read_to_string(&path).unwrap_or_else(|e| fail(&format!("{path}: {e}")));
    let builder = Builder::new(&template, secret.as_bytes()).unwrap_or_else(|e| fail(&e.to_string()));
    print!("{}", builder.build(now, ttl).script);
}
