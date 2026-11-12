#![no_main]
use veritell_fp::h2::{self, Parse};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Parse::Done(fp) = h2::parse(data) {
        // `settings|window_update|priorities|pseudo_order`
        let bars = fp.akamai.matches('|').count();
        assert_eq!(bars, 3, "akamai string: {:?}", fp.akamai);
    }
});
