//! Acceptance tests for veritell-persist. FIXED BY THE PROJECT LEAD: DO NOT EDIT.

use std::fs;
use std::path::PathBuf;

use veritell_persist::{read, write, PersistError, MAX_BYTES};
use sha2::{Digest, Sha256};

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("veritell-persist-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn corrupt(r: Result<Option<Vec<u8>>, PersistError>) -> bool {
    matches!(r, Err(PersistError::Corrupt(_)))
}

#[test]
fn round_trip() {
    let d = dir("rt");
    let p = d.join("state");
    for payload in [&b""[..], b"x", &[0u8, 255, 10, 13][..], &vec![7u8; 100_000][..]] {
        write(&p, "quota", payload).unwrap();
        assert_eq!(read(&p, "quota").unwrap().as_deref(), Some(payload));
    }
}

#[test]
fn the_format_is_as_documented() {
    let d = dir("fmt");
    let p = d.join("state");
    write(&p, "used-tokens", b"abc").unwrap();
    let mut want = b"VERITELL-STATE 1\n".to_vec();
    want.push(11);
    want.extend_from_slice(b"used-tokens");
    want.extend_from_slice(&3u64.to_be_bytes());
    want.extend_from_slice(b"abc");
    let digest = Sha256::digest(&want);
    want.extend_from_slice(&digest);
    assert_eq!(fs::read(&p).unwrap(), want);
}

#[test]
fn a_missing_file_is_none() {
    let d = dir("missing");
    assert!(read(&d.join("nothing"), "quota").unwrap().is_none());
}

#[test]
fn every_truncation_is_refused() {
    let d = dir("trunc");
    let p = d.join("state");
    write(&p, "quota", b"some payload bytes").unwrap();
    let whole = fs::read(&p).unwrap();
    let q = d.join("cut");
    for n in 0..whole.len() {
        fs::write(&q, &whole[..n]).unwrap();
        assert!(corrupt(read(&q, "quota")), "accepted a file cut to {n} bytes");
    }
}

#[test]
fn every_flipped_byte_is_refused() {
    let d = dir("flip");
    let p = d.join("state");
    write(&p, "quota", b"some payload bytes").unwrap();
    let whole = fs::read(&p).unwrap();
    let q = d.join("flipped");
    for i in 0..whole.len() {
        let mut bad = whole.clone();
        bad[i] ^= 0x01;
        fs::write(&q, &bad).unwrap();
        assert!(corrupt(read(&q, "quota")), "accepted a file with byte {i} changed");
    }
}

#[test]
fn trailing_bytes_are_refused() {
    let d = dir("trail");
    let p = d.join("state");
    write(&p, "quota", b"payload").unwrap();
    let mut whole = fs::read(&p).unwrap();
    whole.push(0);
    fs::write(&p, &whole).unwrap();
    assert!(corrupt(read(&p, "quota")));
}

#[test]
fn another_kind_is_refused() {
    let d = dir("kind");
    let p = d.join("state");
    write(&p, "quota", b"payload").unwrap();
    assert!(corrupt(read(&p, "used-tokens")));
    assert!(corrupt(read(&p, "quot")));
}

#[test]
fn a_length_beyond_the_file_is_refused_without_allocating_it() {
    let d = dir("len");
    let p = d.join("state");
    let mut bytes = b"VERITELL-STATE 1\n".to_vec();
    bytes.push(5);
    bytes.extend_from_slice(b"quota");
    bytes.extend_from_slice(&u64::MAX.to_be_bytes());
    bytes.extend_from_slice(&[0u8; 40]);
    fs::write(&p, &bytes).unwrap();
    assert!(corrupt(read(&p, "quota")));
}

#[test]
fn an_oversized_file_is_refused_unread() {
    let d = dir("big");
    let p = d.join("state");
    let f = fs::File::create(&p).unwrap();
    f.set_len(MAX_BYTES + 1).unwrap(); // sparse: nothing is written
    assert!(corrupt(read(&p, "quota")));
}

#[test]
fn bad_kinds_are_not_written() {
    let d = dir("badkind");
    for kind in ["", "Quota", "a b", "dot.ted", "slash/x", &"k".repeat(65)] {
        let p = d.join("state");
        match write(&p, kind, b"x") {
            Err(PersistError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{kind:?}"),
            other => panic!("{kind:?}: {other:?}"),
        }
        assert!(!p.exists(), "{kind:?} wrote a file");
    }
    write(&d.join("ok"), &"k".repeat(64), b"x").unwrap();
}

#[test]
fn a_write_replaces_and_leaves_no_temporary_file() {
    let d = dir("replace");
    let p = d.join("state");
    write(&p, "quota", b"first").unwrap();
    write(&p, "quota", b"second").unwrap();
    assert_eq!(read(&p, "quota").unwrap().as_deref(), Some(&b"second"[..]));
    let names: Vec<String> = fs::read_dir(&d).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    assert_eq!(names, vec!["state".to_string()]);
}

#[test]
fn a_failed_write_leaves_the_old_file() {
    let d = dir("fail");
    let p = d.join("state");
    write(&p, "quota", b"old").unwrap();
    // Writing into a directory that does not exist fails.
    assert!(matches!(write(&d.join("no-such-dir").join("state"), "quota", b"new"), Err(PersistError::Io(_))));
    assert_eq!(read(&p, "quota").unwrap().as_deref(), Some(&b"old"[..]));
}

#[cfg(unix)]
#[test]
fn the_file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let d = dir("mode");
    let p = d.join("state");
    write(&p, "quota", b"x").unwrap();
    assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn errors_never_echo_content() {
    let d = dir("echo");
    let p = d.join("state");
    fs::write(&p, b"SECRET-CONTENT-1234").unwrap();
    let e = read(&p, "quota").unwrap_err();
    assert!(!format!("{e} {e:?}").contains("SECRET"));
}
