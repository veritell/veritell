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
        Ok(opened) => {
            // The order a run of this build writes the page's keys in (the
            // gateway refuses a report that does not have it).
            let page = page_keys(&opened.report_json);
            for order in builder.key_order(&opened.build_id).unwrap_or_default() {
                let written: Vec<&String> = page.iter().filter(|k| order.contains(k)).collect();
                let expected: Vec<&String> = order.iter().filter(|k| page.contains(k)).collect();
                if written != expected {
                    fail(&format!("keys not in the build's order: {written:?}, expected {expected:?}"));
                }
            }
            println!("{}", String::from_utf8_lossy(&opened.report_json));
        }
        Err(e) => fail(&e.to_string()),
    }
}

/// The keys of the top-level `page` object in written order
/// (`serde_json::Value` would sort them); empty when there is none.
fn page_keys(json: &[u8]) -> Vec<String> {
    use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};

    struct Keys(Vec<String>);
    impl<'de> serde::Deserialize<'de> for Keys {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Keys;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("an object")
                }
                fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Keys, A::Error> {
                    let mut keys = Vec::new();
                    while let Some((key, IgnoredAny)) = map.next_entry::<String, IgnoredAny>()? {
                        keys.push(key);
                    }
                    Ok(Keys(keys))
                }
            }
            d.deserialize_map(V)
        }
    }

    struct Top(Vec<String>);
    impl<'de> serde::Deserialize<'de> for Top {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Top;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("an object")
                }
                fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Top, A::Error> {
                    let mut page = Vec::new();
                    while let Some(key) = map.next_key::<String>()? {
                        if key == "page" {
                            page = map.next_value::<Keys>()?.0;
                        } else {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                    Ok(Top(page))
                }
            }
            d.deserialize_map(V)
        }
    }

    serde_json::from_slice::<Top>(json).map(|t| t.0).unwrap_or_default()
}
