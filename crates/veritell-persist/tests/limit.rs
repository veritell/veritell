//! `write` refuses what `read` would refuse for its size.

use veritell_persist::{read, write, PersistError, MAX_BYTES};

#[test]
fn a_payload_over_the_limit_is_not_written() {
    let dir = std::env::temp_dir().join(format!("veritell-persist-limit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("big.state");
    write(&path, "big", b"small").unwrap();

    let big = vec![0u8; usize::try_from(MAX_BYTES).unwrap() + 1];
    match write(&path, "big", &big) {
        Err(PersistError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput),
        other => panic!("expected InvalidInput, got {other:?}"),
    }
    assert_eq!(read(&path, "big").unwrap().as_deref(), Some(&b"small"[..]), "the old file is untouched");
    let _ = std::fs::remove_dir_all(&dir);
}
