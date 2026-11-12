#![no_main]

// No catch_unwind here: a panic inside loona-hpack is a finding.
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut dec = loona_hpack::Decoder::new();
    let _ = dec.decode(data);
});
