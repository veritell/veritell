//! Acceptance tests written by the project lead. DO NOT EDIT.

use veritell_core::Class;
use veritell_ua::*;

const CHROME_WIN: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";
const EDGE_WIN: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0";
const FIREFOX_LINUX: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0";
const SAFARI_MAC: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15";
const CHROME_IOS: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/142.0.7444.77 Mobile/15E148 Safari/604.1";
const FIREFOX_IOS: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/144.0 Mobile/15E148 Safari/605.1.15";
const CHROME_ANDROID: &str = "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36";
const HEADLESS: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/142.0.0.0 Safari/537.36";
const GOOGLEBOT: &str = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
const GOOGLEBOT_SMARTPHONE: &str = "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";

// Observed on the project's own test bench.
const CHROMIUM_JA4: &str = "t13d1516h2_8daaf6152771_806a8c22fdea";
const CURL_JA4: &str = "t13d4907h2_0d8feac7bc37_7395dae3b2f3";
const CHROMIUM_H2: &str = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p";
const CURL_H2: &str = "3:100;4:10485760;2:0|1048510465|0|m,s,a,p";

fn browser(ua: &str) -> (Engine, String, u32) {
    match parse_user_agent(Some(ua)).kind {
        UaKind::Browser { engine, name, major } => (engine, name, major),
        other => panic!("expected a browser for {ua:?}, got {other:?}"),
    }
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

fn chrome_headers() -> Vec<String> {
    names(&[
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "upgrade-insecure-requests",
        "user-agent",
        "accept",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-user",
        "sec-fetch-dest",
        "accept-encoding",
        "accept-language",
    ])
}

fn ids(d: &[veritell_core::Detection]) -> Vec<&str> {
    d.iter().map(|d| d.id.as_str()).collect()
}

#[test]
fn parses_desktop_browsers() {
    assert_eq!(browser(CHROME_WIN), (Engine::Chromium, "chrome".into(), 142));
    assert_eq!(browser(EDGE_WIN), (Engine::Chromium, "edge".into(), 142));
    assert_eq!(browser(FIREFOX_LINUX), (Engine::Gecko, "firefox".into(), 144));
    assert_eq!(browser(SAFARI_MAC), (Engine::WebKit, "safari".into(), 18));
}

#[test]
fn parses_os_and_mobile() {
    let c = parse_user_agent(Some(CHROME_WIN));
    assert_eq!((c.os, c.mobile), (Os::Windows, false));
    let c = parse_user_agent(Some(FIREFOX_LINUX));
    assert_eq!((c.os, c.mobile), (Os::Linux, false));
    let c = parse_user_agent(Some(SAFARI_MAC));
    assert_eq!((c.os, c.mobile), (Os::MacOs, false));
    let c = parse_user_agent(Some(CHROME_ANDROID));
    assert_eq!((c.os, c.mobile), (Os::Android, true));
    let c = parse_user_agent(Some(CHROME_IOS));
    assert_eq!((c.os, c.mobile), (Os::Ios, true));
}

#[test]
fn every_ios_browser_is_webkit() {
    let (engine, name, major) = browser(CHROME_IOS);
    assert_eq!((engine, name.as_str(), major), (Engine::WebKit, "chrome", 142));
    let (engine, name, major) = browser(FIREFOX_IOS);
    assert_eq!((engine, name.as_str(), major), (Engine::WebKit, "firefox", 144));
}

#[test]
fn non_browser_kinds() {
    assert_eq!(parse_user_agent(None).kind, UaKind::Missing);
    assert_eq!(parse_user_agent(Some("")).kind, UaKind::Missing);
    assert_eq!(parse_user_agent(Some("   ")).kind, UaKind::Missing);
    assert_eq!(parse_user_agent(Some(HEADLESS)).kind, UaKind::Headless);
    for (ua, tool) in [
        ("curl/8.7.1", "curl"),
        ("python-requests/2.32.3", "python-requests"),
        ("Go-http-client/2.0", "go-http-client"),
        ("Wget/1.21.4", "wget"),
        ("okhttp/4.12.0", "okhttp"),
        ("python-httpx/0.27.0", "python-httpx"),
        ("Scrapy/2.11.2 (+https://scrapy.org)", "scrapy"),
        ("axios/1.7.2", "axios"),
        ("node-fetch", "node-fetch"),
    ] {
        assert_eq!(
            parse_user_agent(Some(ua)).kind,
            UaKind::DeclaredTool { name: tool.into() },
            "{ua}"
        );
    }
    assert_eq!(
        parse_user_agent(Some(GOOGLEBOT)).kind,
        UaKind::DeclaredBot { name: "Googlebot".into() }
    );
    // A bot token wins even when the rest looks like a browser.
    assert_eq!(
        parse_user_agent(Some(GOOGLEBOT_SMARTPHONE)).kind,
        UaKind::DeclaredBot { name: "Googlebot".into() }
    );
    for (ua, bot) in [
        ("Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", "bingbot"),
        ("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)", "GPTBot"),
        ("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)", "ClaudeBot"),
    ] {
        assert_eq!(
            parse_user_agent(Some(ua)).kind,
            UaKind::DeclaredBot { name: bot.into() },
            "{ua}"
        );
    }
    assert_eq!(parse_user_agent(Some("something odd")).kind, UaKind::Unknown);
}

#[test]
fn parser_survives_hostile_input() {
    let long = "A".repeat(100_000);
    let _ = parse_user_agent(Some(&long));
    let _ = parse_user_agent(Some("Chrome/"));
    let _ = parse_user_agent(Some("Chrome/99999999999999999999999 Safari/537.36"));
    let _ = parse_user_agent(Some("Mozilla/5.0 (\u{0}\u{ffff}) Firefox/\u{1F600}"));
    let _ = parse_user_agent(Some("Version/ Safari/"));
}

#[test]
fn real_chromium_is_clean() {
    let table = TruthTable::builtin();
    let headers = chrome_headers();
    let d = table.check(&Observed {
        user_agent: Some(CHROME_WIN),
        ja4: Some(CHROMIUM_JA4),
        h2_akamai: Some(CHROMIUM_H2),
        header_names: &headers,
    });
    assert!(d.is_empty(), "unexpected detections: {:?}", ids(&d));
}

#[test]
fn curl_with_default_ua_is_a_declared_tool() {
    let table = TruthTable::builtin();
    let headers = names(&["user-agent", "accept"]);
    let d = table.check(&Observed {
        user_agent: Some("curl/8.7.1"),
        ja4: Some(CURL_JA4),
        h2_akamai: Some(CURL_H2),
        header_names: &headers,
    });
    assert_eq!(ids(&d), vec!["ua_declared_tool"]);
    assert_eq!(d[0].penalty, 60);
    assert_eq!(d[0].class_hint, Some(Class::Automated));
}

#[test]
fn curl_pretending_to_be_chrome_is_caught_on_every_layer() {
    let table = TruthTable::builtin();
    let headers = names(&["user-agent", "accept"]);
    let d = table.check(&Observed {
        user_agent: Some(CHROME_WIN),
        ja4: Some(CURL_JA4),
        h2_akamai: Some(CURL_H2),
        header_names: &headers,
    });
    let got = ids(&d);
    // A known tool fingerprint replaces the generic mismatch.
    assert!(got.contains(&"tls_known_tool"), "{got:?}");
    assert!(!got.contains(&"tls_ua_mismatch"), "{got:?}");
    assert!(got.contains(&"h2_settings_mismatch"), "{got:?}");
    assert!(got.contains(&"h2_pseudo_order_mismatch"), "{got:?}");
    assert!(got.contains(&"missing_client_hints"), "{got:?}");
    assert!(got.contains(&"missing_sec_fetch"), "{got:?}");
    assert!(got.contains(&"missing_accept_language"), "{got:?}");

    let known = d.iter().find(|d| d.id == "tls_known_tool").unwrap();
    assert_eq!(known.penalty, 60);
    assert_eq!(known.class_hint, Some(Class::Automated));
    // Chromium HTTP/2 values are verified in the builtin table: strong penalty.
    let h2 = d.iter().find(|d| d.id == "h2_settings_mismatch").unwrap();
    assert_eq!(h2.penalty, 35);
    assert_eq!(h2.class_hint, Some(Class::Automated));
}

// Observed from real browsers on the project's test bench, 2026-11-09.
#[test]
fn real_browser_observations_are_clean() {
    let table = TruthTable::builtin();
    let headers = chrome_headers();
    for (ua, ja4, h2) in [
        (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
            "t13d1517h2_8daaf6152771_dcad5a053991",
            CHROMIUM_H2,
        ),
        (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.7977.167 Safari/537.36",
            "t13d1516h2_8daaf6152771_806a8c22fdea",
            CHROMIUM_H2,
        ),
        (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:159.0) Gecko/20100101 Firefox/159.0",
            "t13d1517h2_8daaf6152771_3cbfd9057e0d",
            "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
        ),
    ] {
        let d = table.check(&Observed {
            user_agent: Some(ua),
            ja4: Some(ja4),
            h2_akamai: Some(h2),
            header_names: &headers,
        });
        assert!(d.is_empty(), "{ua}: {:?}", ids(&d));
    }
}

#[test]
fn firefox_ua_on_a_chromium_http2_stack_is_caught() {
    // Same cipher hash for both engines, so TLS is silent; HTTP/2 is not.
    let table = TruthTable::builtin();
    let headers = chrome_headers();
    let d = table.check(&Observed {
        user_agent: Some(FIREFOX_LINUX),
        ja4: Some(CHROMIUM_JA4),
        h2_akamai: Some(CHROMIUM_H2),
        header_names: &headers,
    });
    assert_eq!(ids(&d), vec!["h2_settings_mismatch", "h2_pseudo_order_mismatch"]);
    assert_eq!(d[0].penalty, 35);
}

#[test]
fn unknown_tls_stack_with_chrome_ua_is_a_mismatch() {
    let table = TruthTable::builtin();
    let headers = chrome_headers();
    let d = table.check(&Observed {
        user_agent: Some(CHROME_WIN),
        ja4: Some("t13d1715h2_aaaaaaaaaaaa_bbbbbbbbbbbb"),
        h2_akamai: Some(CHROMIUM_H2),
        header_names: &headers,
    });
    assert_eq!(ids(&d), vec!["tls_ua_mismatch"]);
    // Chromium cipher hash is verified: strong penalty and a class hint.
    assert_eq!(d[0].penalty, 45);
    assert_eq!(d[0].class_hint, Some(Class::Automated));
}

#[test]
fn unverified_dimension_gives_weak_tls_penalty() {
    let table = TruthTable::from_json(
        r#"{"version": 1, "engines": {"gecko": {
            "ja4_cipher_hash": {"verified": false, "values": ["5b57614c22b0"]}}}, "tools": []}"#,
    )
    .unwrap();
    let headers = names(&["user-agent", "accept", "accept-language", "sec-fetch-site"]);
    let d = table.check(&Observed {
        user_agent: Some(FIREFOX_LINUX),
        ja4: Some("t13d1715h2_aaaaaaaaaaaa_bbbbbbbbbbbb"),
        h2_akamai: None,
        header_names: &headers,
    });
    assert_eq!(ids(&d), vec!["tls_ua_mismatch"]);
    assert_eq!(d[0].penalty, 15);
    assert_eq!(d[0].class_hint, None);
}

#[test]
fn empty_dimension_is_not_checked() {
    // Amended by the lead (Phase 3, 2026-11-10): the builtin table now has
    // WebKit values, so this table leaves WebKit's dimensions empty itself.
    let table = TruthTable::from_json(
        r#"{"version": 1, "engines": {"webkit": {
            "ja4_cipher_hash": {"verified": true, "values": []},
            "h2_settings": {"verified": true, "values": []},
            "h2_pseudo_order": {"verified": true, "values": []}}}, "tools": []}"#,
    )
    .unwrap();
    let headers = names(&["user-agent", "accept", "accept-language", "sec-fetch-site"]);
    let d = table.check(&Observed {
        user_agent: Some(SAFARI_MAC),
        ja4: Some("t13d2014h2_aaaaaaaaaaaa_bbbbbbbbbbbb"),
        h2_akamai: Some("2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p"),
        header_names: &headers,
    });
    assert!(d.is_empty(), "{:?}", ids(&d));
}

#[test]
fn builtin_webkit_values_were_observed() {
    // Added by the lead (Phase 3, 2026-11-10). Safari and DuckDuckGo on an
    // iPhone and on a Mac, and Firefox Focus on the iPhone, sent exactly this.
    let table = TruthTable::builtin();
    let headers = names(&["user-agent", "accept", "accept-language", "sec-fetch-site"]);
    let real = table.check(&Observed {
        user_agent: Some(SAFARI_MAC),
        ja4: Some("t13d2013h2_a09f3c656075_7f0f34a4126d"),
        h2_akamai: Some("2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p"),
        header_names: &headers,
    });
    assert!(real.is_empty(), "{:?}", ids(&real));
    // Chrome's network fingerprint under a Safari User-Agent.
    let fake = table.check(&Observed {
        user_agent: Some(SAFARI_MAC),
        ja4: Some("t13d1516h2_8daaf6152771_02713d6af862"),
        h2_akamai: Some("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"),
        header_names: &headers,
    });
    assert_eq!(ids(&fake), vec!["tls_ua_mismatch", "h2_settings_mismatch", "h2_pseudo_order_mismatch"]);
    assert_eq!(fake[0].penalty, 45);
    assert_eq!(fake[0].class_hint, Some(Class::Automated));
    assert!(fake[1..].iter().all(|d| d.penalty == 35));
}

#[test]
fn missing_and_headless_user_agents() {
    let table = TruthTable::builtin();
    let d = table.check(&Observed::default());
    assert_eq!(ids(&d), vec!["ua_missing"]);
    assert_eq!((d[0].penalty, d[0].class_hint), (40, Some(Class::Automated)));

    let d = table.check(&Observed {
        user_agent: Some(HEADLESS),
        ..Default::default()
    });
    assert_eq!(ids(&d), vec!["ua_headless"]);
    assert_eq!((d[0].penalty, d[0].class_hint), (70, Some(Class::Automated)));
}

#[test]
fn declared_bot_is_reported_without_penalty() {
    let table = TruthTable::builtin();
    let d = table.check(&Observed {
        user_agent: Some(GOOGLEBOT),
        ja4: Some(CURL_JA4),
        ..Default::default()
    });
    assert_eq!(ids(&d), vec!["ua_declared_bot"]);
    assert_eq!((d[0].penalty, d[0].class_hint), (0, None));
}

#[test]
fn http1_requests_skip_h2_rules() {
    let table = TruthTable::builtin();
    let headers = chrome_headers();
    let d = table.check(&Observed {
        user_agent: Some(CHROME_WIN),
        ja4: Some(CHROMIUM_JA4),
        h2_akamai: None,
        header_names: &headers,
    });
    assert!(d.is_empty(), "{:?}", ids(&d));
}

#[test]
fn custom_table_and_errors() {
    let json = r#"{
      "version": 1,
      "engines": {
        "chromium": {
          "ja4_cipher_hash": { "verified": true, "values": ["111111111111"] },
          "h2_settings": { "verified": true, "values": ["1:1"] },
          "h2_pseudo_order": { "verified": true, "values": ["m,a,s,p"] }
        }
      },
      "tools": []
    }"#;
    let table = TruthTable::from_json(json).unwrap();
    let headers = chrome_headers();
    let d = table.check(&Observed {
        user_agent: Some(CHROME_WIN),
        ja4: Some(CHROMIUM_JA4),
        h2_akamai: Some(CHROMIUM_H2),
        header_names: &headers,
    });
    assert_eq!(ids(&d), vec!["tls_ua_mismatch", "h2_settings_mismatch"]);
    assert_eq!(d[1].penalty, 35);

    assert!(matches!(TruthTable::from_json("{"), Err(TruthError::Json(_))));
    assert!(matches!(
        TruthTable::from_json(r#"{"version": 2, "engines": {}, "tools": []}"#),
        Err(TruthError::UnsupportedVersion(2))
    ));
}

#[test]
fn malformed_fingerprints_do_not_panic() {
    let table = TruthTable::builtin();
    let headers = chrome_headers();
    for (ja4, h2) in [("", ""), ("_", "|"), ("t13d", "|||"), ("a_b", "1:1|x"), ("___", "||||||")] {
        let _ = table.check(&Observed {
            user_agent: Some(CHROME_WIN),
            ja4: Some(ja4),
            h2_akamai: Some(h2),
            header_names: &headers,
        });
    }
}
