//! iOS's own icon fetcher ("NetworkingExtension/… iOS/…") passes only over
//! WebKit's network stack.

use veritell_ua::{Observed, TruthTable};

const UA: &str = "NetworkingExtension/8626.1.12.10.3 Network/6681.60.32 iOS/27.3";
const SAFARI_JA4: &str = "t13d2013h2_a09f3c656075_7f0f34a4126d";
const SAFARI_H2: &str = "2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p";
const CURL_JA4: &str = "t13d3112h2_e8f1e7e78f70_6bebaf5329ac";

fn ids(ua: &str, ja4: Option<&str>, h2: Option<&str>) -> Vec<String> {
    let headers: Vec<String> = Vec::new();
    let obs = Observed { user_agent: Some(ua), ja4, h2_akamai: h2, header_names: &headers };
    TruthTable::builtin().check(&obs).into_iter().map(|d| d.id.to_string()).collect()
}

#[test]
fn over_safaris_stack_it_passes_clean() {
    assert!(ids(UA, Some(SAFARI_JA4), Some(SAFARI_H2)).is_empty());
}

#[test]
fn another_tls_stack_is_still_unknown() {
    assert_eq!(ids(UA, Some(CURL_JA4), Some(SAFARI_H2)), ["ua_unknown"]);
}

#[test]
fn other_http2_settings_are_still_unknown() {
    assert_eq!(ids(UA, Some(SAFARI_JA4), Some("1:65536;2:0;4:6291456|15663105|0|m,a,s,p")), ["ua_unknown"]);
}

#[test]
fn over_http1_it_is_still_unknown() {
    assert_eq!(ids(UA, Some(SAFARI_JA4), None), ["ua_unknown"]);
}

#[test]
fn a_look_alike_user_agent_is_still_unknown() {
    for ua in [
        "NetworkingExtension/8626.1 Network/6681.60 iOS/27.3 extra/1",
        "NetworkingExtension/8626.1 iOS/27.3",
        "NetworkingExtension/x Network/6681.60 iOS/27.3",
        "Foo NetworkingExtension/8626.1 Network/6681.60 iOS/27.3",
    ] {
        assert_eq!(ids(ua, Some(SAFARI_JA4), Some(SAFARI_H2)), ["ua_unknown"], "{ua}");
    }
}
