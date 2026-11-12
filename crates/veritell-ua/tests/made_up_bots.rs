//! A crawler name we don't know must not hide the rest of the request.

use veritell_core::Class;
use veritell_ua::{parse_user_agent, Observed, TruthTable, UaKind};

const CURL_JA4: &str = "t13d4907h2_0d8feac7bc37_7395dae3b2f3";
const CHROMIUM_JA4: &str = "t13d1516h2_8daaf6152771_806a8c22fdea";
const CURL_H2: &str = "3:100;4:10485760;2:0|1048510465|0|m,s,a,p";

fn ids(d: &[veritell_core::Detection]) -> Vec<&str> {
    d.iter().map(|d| d.id.as_str()).collect()
}

fn penalty(d: &[veritell_core::Detection]) -> u32 {
    d.iter().map(|d| u32::from(d.penalty)).sum()
}

#[test]
fn made_up_bot_on_a_tool_tls_stack_is_caught() {
    let table = TruthTable::builtin();
    assert_eq!(
        parse_user_agent(Some("Foobot/1.0")).kind,
        UaKind::DeclaredBot { name: "Foobot".into() }
    );
    let d = table.check(&Observed {
        user_agent: Some("Foobot/1.0"),
        ja4: Some(CURL_JA4),
        ..Default::default()
    });
    assert_eq!(ids(&d), vec!["ua_declared_bot", "tls_known_tool"]);
    assert_eq!(d[1].class_hint, Some(Class::Automated));
    // Not better than saying "curl" outright.
    let curl = table.check(&Observed {
        user_agent: Some("curl/8.4.0"),
        ja4: Some(CURL_JA4),
        ..Default::default()
    });
    assert!(penalty(&d) >= penalty(&curl));
}

#[test]
fn made_up_bot_after_a_tool_name_keeps_the_tool_claim() {
    let table = TruthTable::builtin();
    let d = table.check(&Observed {
        user_agent: Some("python-requests/2.32 Foobot/1.0"),
        ..Default::default()
    });
    assert_eq!(ids(&d), vec!["ua_declared_bot", "ua_declared_tool"]);
    assert_eq!(d[1].penalty, 60);
}

#[test]
fn made_up_bot_in_a_browser_ua_gets_the_browser_checks() {
    let table = TruthTable::builtin();
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Foobot/1.0";
    let d = table.check(&Observed {
        user_agent: Some(ua),
        ja4: Some(CURL_JA4),
        h2_akamai: Some(CURL_H2),
        header_names: &[],
    });
    let got = ids(&d);
    assert_eq!(got[0], "ua_declared_bot");
    for id in [
        "tls_known_tool",
        "h2_settings_mismatch",
        "missing_client_hints",
        "missing_accept_language",
    ] {
        assert!(got.contains(&id), "{id} missing from {got:?}");
    }
}

#[test]
fn made_up_headless_bot_is_still_headless() {
    let table = TruthTable::builtin();
    let ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/142.0.0.0 Safari/537.36 MyCrawler/1.0";
    let d = table.check(&Observed {
        user_agent: Some(ua),
        ..Default::default()
    });
    assert_eq!(ids(&d), vec!["ua_declared_bot", "ua_headless"]);
}

#[test]
fn made_up_bot_on_an_unremarkable_stack_adds_nothing() {
    let table = TruthTable::builtin();
    let d = table.check(&Observed {
        user_agent: Some("Foobot/1.0"),
        ja4: Some(CHROMIUM_JA4),
        ..Default::default()
    });
    assert_eq!(ids(&d), vec!["ua_declared_bot"]);
}

#[test]
fn known_crawler_variants_are_not_rechecked() {
    let table = TruthTable::builtin();
    for ua in ["Googlebot-Image/1.0", "Mozilla/5.0 (compatible; bingbot/2.0)"] {
        let d = table.check(&Observed {
            user_agent: Some(ua),
            ja4: Some(CURL_JA4),
            ..Default::default()
        });
        assert_eq!(ids(&d), vec!["ua_declared_bot"], "{ua}");
    }
}
