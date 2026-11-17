#![no_main]
// The probe template, as an operator or a release supplies it:
// `veritell_probe_build::Builder::new`, then `build_with_seed`, `seal` and
// `open` with the builds it makes. The first byte holds flags: bit 0 uses
// a 31-byte secret, bit 1 pads the template past `MAX_TEMPLATE_BYTES`,
// bits 2 to 7 pick the seed. The rest is the template.
//
// Properties checked, beyond "does not panic", all from the contract in
// `Builder::new` and `Builder::build_with_seed`:
// - `new` refuses exactly what a separate check of the documented rules
//   refuses, with the same error (secret, size, token counts, shuffle
//   markers with their line numbers), and every error has a message. It
//   also refuses tokens that overlap (checked here as documented), and a
//   token that comment stripping could remove; that rule is cautious, so
//   it is checked from both sides: such a refusal needs a comment in the
//   template, and an accepted template keeps both tokens in builds from
//   two seeds (two shuffle orders).
// - A build is a function of its seed: the same seed gives the same build,
//   another seed another id.
// - The id is `[A-Za-z0-9_-]`, at most 64 characters, and authenticates.
// - The script keeps `CONFIG_TOKEN` exactly once and carries the build's
//   configuration exactly once; no identifier of the template is left
//   whole (`$$` before a renamed one is text, so `$$$$a` becomes `$$_x`); no line
//   is empty, untrimmed or a `//` comment.
// - The key map names every `VOCAB` key, with distinct names of 2 to 4
//   characters of `[a-z]`.
// - A report sealed for the build opens to the same value.
use veritell_probe_build::{
    BuildError, Builder, BUILD_TOKEN, CONFIG_TOKEN, MAX_TEMPLATE_BYTES, RENAME_PREFIX, SHUFFLE_CLOSE, SHUFFLE_OPEN, VOCAB,
};

const SECRET: &[u8] = b"fuzz secret for templates, at least 32 bytes";
const NOW: u64 = 1_800_000_000;

/// The rules `Builder::new` documents, checked in its order.
fn expected(template: &str, secret: &[u8]) -> Result<(), BuildError> {
    if secret.len() < 32 {
        return Err(BuildError::WeakSecret);
    }
    if template.len() > MAX_TEMPLATE_BYTES {
        return Err(BuildError::TooLarge);
    }
    for token in [BUILD_TOKEN, CONFIG_TOKEN] {
        if template.matches(token).count() != 1 {
            return Err(BuildError::Token(token));
        }
    }
    // Overlapping: the BUILD_TOKEN occurrence shares bytes with CONFIG_TOKEN's.
    let (b, c) = (template.find(BUILD_TOKEN).unwrap(), template.find(CONFIG_TOKEN).unwrap());
    if b < c + CONFIG_TOKEN.len() && c < b + BUILD_TOKEN.len() {
        return Err(BuildError::Token(CONFIG_TOKEN));
    }
    // A region: opened, holding at least one non-blank line, then closed.
    let mut open: Option<(usize, bool)> = None;
    for (i, line) in template.split('\n').enumerate() {
        let n = i + 1;
        match (line.trim(), open) {
            (SHUFFLE_OPEN, Some(_)) => return Err(BuildError::Marker(n)),
            (SHUFFLE_OPEN, None) => open = Some((n, false)),
            (SHUFFLE_CLOSE, None) => return Err(BuildError::Marker(n)),
            (SHUFFLE_CLOSE, Some((at, false))) => return Err(BuildError::Marker(at)),
            (SHUFFLE_CLOSE, Some(_)) => open = None,
            (t, Some((at, _))) if !t.is_empty() => open = Some((at, true)),
            _ => {}
        }
    }
    match open {
        Some((at, _)) => Err(BuildError::Marker(at)),
        None => Ok(()),
    }
}

fn ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The template's renamable identifiers, by the documented rule: the prefix
/// and the longest run of `[A-Za-z0-9_]` after it; a bare prefix is text
/// and the scan moves on by one byte.
fn identifiers(text: &str) -> std::collections::BTreeSet<&str> {
    let (b, p) = (text.as_bytes(), RENAME_PREFIX.as_bytes());
    let mut out = std::collections::BTreeSet::new();
    let mut i = 0;
    while i + p.len() <= b.len() {
        if &b[i..i + p.len()] == p {
            let n = b[i + p.len()..].iter().take_while(|&&c| ident_byte(c)).count();
            if n > 0 {
                out.insert(&text[i..i + p.len() + n]);
                i += p.len() + n;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// A template identifier still in the script as a whole identifier.
fn leftover_identifier<'a>(template: &'a str, script: &str) -> Option<&'a str> {
    identifiers(template).into_iter().find(|id| {
        script.match_indices(id).any(|(at, _)| !script.as_bytes().get(at + id.len()).is_some_and(|&c| ident_byte(c)))
    })
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&flags, rest)) = data.split_first() else { return };
    let Ok(text) = std::str::from_utf8(rest) else { return };
    let secret = if flags & 1 == 1 { &SECRET[..31] } else { SECRET };
    let padded;
    let template = if flags & 2 == 2 {
        padded = format!("{text}{}", " ".repeat(MAX_TEMPLATE_BYTES + 1 - text.len().min(MAX_TEMPLATE_BYTES)));
        padded.as_str()
    } else {
        text
    };

    let builder = Builder::new(template, secret);
    match (builder.as_ref().err(), expected(template, secret).err()) {
        (Some(BuildError::Token(_)), None) => {
            assert!(template.contains("//") || template.contains("/*"), "token refused with no comment around");
        }
        (got, want) => assert_eq!(got, want.as_ref(), "Builder::new disagrees with its rules"),
    }
    let builder = match builder {
        Ok(b) => b,
        Err(e) => {
            assert!(!e.to_string().is_empty(), "empty error message");
            return;
        }
    };

    let seed = [flags >> 2; 16];
    let build = builder.build_with_seed(seed, NOW, 600);
    let again = builder.build_with_seed(seed, NOW, 600);
    assert_eq!(
        (&build.id, &build.script, build.expires_at, &build.key_map),
        (&again.id, &again.script, again.expires_at, &again.key_map),
        "a build is not a function of its seed"
    );
    let mut other_seed = seed;
    other_seed[0] ^= 0x80;
    let other = builder.build_with_seed(other_seed, NOW, 600);
    assert_ne!(other.id, build.id, "two seeds, one id");
    assert_eq!(other.script.matches(CONFIG_TOKEN).count(), 1, "CONFIG_TOKEN lost under another seed");
    assert!(other.script.contains(&format!("{{\"id\":\"{}\"", other.id)), "configuration lost under another seed");

    assert!(
        !build.id.is_empty()
            && build.id.len() <= 64
            && build.id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        "build id {:?}",
        build.id
    );
    assert!(builder.key_order(&build.id).is_some(), "the build's own id does not authenticate");

    let s = &build.script;
    assert_eq!(s.matches(CONFIG_TOKEN).count(), 1, "CONFIG_TOKEN not kept exactly once:\n{s}");
    let config = format!("{{\"id\":\"{}\",\"k\":\"", build.id);
    assert_eq!(s.matches(&config).count(), 1, "build configuration not embedded exactly once:\n{s}");
    assert!(!s.contains(BUILD_TOKEN), "BUILD_TOKEN left in the script");
    if let Some(left) = leftover_identifier(template, s) {
        panic!("identifier not renamed: {left:?}");
    }
    for line in s.split('\n') {
        assert!(!line.is_empty() || s.is_empty(), "empty line in the script");
        assert_eq!(line, line.trim(), "untrimmed line in the script");
        assert!(!line.starts_with("//"), "comment line left in the script: {line:?}");
    }

    let names: std::collections::BTreeSet<&String> = build.key_map.values().collect();
    assert_eq!(names.len(), VOCAB.len(), "key map names not distinct");
    for k in VOCAB {
        let name = build.key_map.get(k).unwrap_or_else(|| panic!("no name for {k}"));
        assert!((2..=4).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_lowercase()), "name {name:?}");
    }

    let report = br#"{"v":1,"nonce":"n","main":{"ua":"x","hc":4}}"#;
    let body = builder.seal(&build.id, "n", report, [flags; 12]).expect("seal for the build's own id");
    let opened = builder.open(&body, NOW).expect("a report sealed for the build does not open");
    let sent: serde_json::Value = serde_json::from_slice(report).unwrap();
    let got: serde_json::Value = serde_json::from_slice(&opened.report_json).expect("opened report is not JSON");
    assert_eq!(got, sent, "a sealed report opened to another value");
});
