//! Analysis rules: what a probe report shows about the browser that sent it.

use veritell_core::{Class, Detection, Layer};

use crate::types::{
    Claimed, Engine, EngineProfile, EngineSignals, EngineTruth, Os, ProbeReport, Realm,
};

/// Patches made by privacy browsers: User-Agent marker, engine, targets.
/// Each was observed from the real browser, not taken from documentation.
const PRIVACY_PATCHES: &[(&str, Engine, &[&str])] = &[
    // DuckDuckGo 27.2 on iOS 27.2 (Phase 3, 2026-11-10): both patches in the
    // page, the second also in an iframe.
    (
        " Ddg/",
        Engine::Webkit,
        &["Navigator.prototype.hardwareConcurrency", "Permissions.prototype.query"],
    ),
];

/// Whether a patch to `target` is one the claimed browser makes itself.
fn privacy_patch(claimed: &Claimed<'_>, target: &str) -> bool {
    let Some(ua) = claimed.user_agent else {
        return false;
    };
    PRIVACY_PATCHES
        .iter()
        .any(|(marker, engine, targets)| ua.contains(marker) && claimed.engine == Some(*engine) && targets.contains(&target))
}

/// Turns a report into detections. All are `Layer::Client`.
///
/// Rules are evaluated in the order below and each id appears at most once.
/// "Realms" means `main`, plus `iframe` and `worker` when present.
///
/// | # | id | penalty | class hint | fires when |
/// |---|---|---|---|---|
/// | 1 | `webdriver_true` | 70 | Automated | any realm has `webdriver == Some(true)` |
/// | 2 | `automation_globals` | 70 | Automated | `page.globals` is not empty |
/// | 3 | `native_tampered` | 50 | Automated | any realm has a non-empty `tamper`, leaving out the patches a privacy browser is known to make when the User-Agent names it (`PRIVACY_PATCHES`) |
/// | 4 | `realm_mismatch` | 50 | Automated | `iframe` or `worker` differs from `main` in `ua`, `platform`, `languages`, `hc`, `engine.err_msg` or `engine.eval_len`; or `iframe.webdriver` and `main.webdriver` are both `Some` and differ |
/// | 5 | `http_ua_mismatch` | 50 | Automated | `claimed.user_agent` is `Some` and differs from `main.ua` |
/// | 6 | `engine_mismatch` | 60 or 20 | Automated or none | see below |
/// | 7 | `platform_mismatch` | 40 | none | `claimed.os` is `Some` and `main.platform` does not fit it (table below) |
/// | 8 | `uad_mismatch` | 40 | none | `main.uad` is `Some` and: `claimed.engine` is Gecko or Webkit; or `claimed.os` is `Some`, not Ios, and `uad.platform` is not the expected name; or `uad.mobile != claimed.mobile` |
/// | 9 | `touch_mismatch` | 25 | none | `claimed.mobile` and `page.touch_points == 0` |
/// | 10 | `gpu_platform_mismatch` | 40 | none | `claimed.os` is `Some` and `page.webgl_renderer` (lowercased) contains a marker of another platform (table below) |
/// | 11 | `gpu_software` | 25 | none | `page.webgl_renderer` (lowercased) contains `swiftshader`, `llvmpipe` or `softpipe` |
/// | 12 | `window_implausible` | 20 | none | `page.window[2] == 0`, `page.window[3] == 0`, `page.screen[0] == 0` or `page.screen[1] == 0` |
/// | 13 | `languages_empty` | 30 | none | `main.languages` is empty |
/// | 14 | `headless_permissions` | 30 | Automated | `page.notif_permission == "denied"` and `page.perm_query_notif == "prompt"` |
///
/// Rule 6, engine truth. Skipped when `claimed.engine` is `None` or `truth`
/// has no profile for it. A dimension of a profile (`err_msg`, `eval_len`,
/// `stack_at`, each listed feature, `math`) is checked only when the profile
/// specifies it; a listed feature that the report omits counts as a
/// mismatch. The rule fires when at least one checked dimension of the
/// claimed engine's profile does not match `main.engine`. Penalty 60 with
/// class hint Automated when that profile is `verified`, otherwise penalty 20
/// with no class hint. `detail` names the failed dimensions and, if some
/// other profile matches on all of its checked dimensions (and checks at
/// least one), says which engine the signals fit.
///
/// Rule 7, `main.platform` must start with (case-sensitive):
/// Windows: `Win`. MacOs: `Mac`. Linux, ChromeOs: `Linux`. Android: `Linux`
/// or `Android`. Ios: `iPhone`, `iPad` or `iPod`.
///
/// Rule 8, expected `uad.platform`: Windows `Windows`, MacOs `macOS`,
/// Linux `Linux`, Android `Android`, ChromeOs `Chrome OS` or `Chromium OS`.
///
/// Rule 10, markers that do not belong: Windows: `apple`, `metal`.
/// MacOs, Ios: `direct3d`, `d3d11`. Linux, Android, ChromeOs: `direct3d`,
/// `d3d11`, `apple`.
///
/// Rule 3 and privacy browsers: some browsers patch built-in functions to
/// resist fingerprinting, which is what the rule looks for. A patch listed
/// in `PRIVACY_PATCHES` for a browser is not counted when the User-Agent
/// carries that browser's marker and claims its engine. Any other patch
/// still counts. A client can claim the marker, so the list holds only
/// patches that were observed from the real browser.
///
/// `detail` is for people. Any text copied from the report into `detail`
/// must first be reduced to ASCII letters, digits, space and `._-:/()`
/// (other characters become `?`) and cut to 64 characters per value, and the
/// whole `detail` to 256 characters.
pub fn analyze(report: &ProbeReport, claimed: &Claimed<'_>, truth: &EngineTruth) -> Vec<Detection> {
    let mut out = Vec::new();
    let main = &report.main;
    let page = &report.page;
    let mut realms: Vec<(&'static str, &Realm)> = vec![("main", main)];
    if let Some(r) = &report.iframe {
        realms.push(("iframe", r));
    }
    if let Some(r) = &report.worker {
        realms.push(("worker", r));
    }
    let renderer = page.webgl_renderer.as_deref().map(str::to_lowercase);

    // 1
    let wd: Vec<&str> = realms
        .iter()
        .filter(|(_, r)| r.webdriver == Some(true))
        .map(|(n, _)| *n)
        .collect();
    if !wd.is_empty() {
        push(&mut out, "webdriver_true", 70, Some(Class::Automated), format!("webdriver true in: {}", wd.join(", ")));
    }

    // 2
    if !page.globals.is_empty() {
        let names: Vec<String> = page.globals.iter().map(|g| clean(g)).collect();
        push(&mut out, "automation_globals", 70, Some(Class::Automated), format!("globals: {}", names.join(", ")));
    }

    // 3
    let mut tampered = Vec::new();
    for (name, r) in &realms {
        for t in r.tamper.iter().filter(|t| !privacy_patch(claimed, &t.target)) {
            let kinds: Vec<String> = t.kinds.iter().map(|k| clean(k)).collect();
            tampered.push(format!("{name}: {} ({})", clean(&t.target), kinds.join(",")));
        }
    }
    if !tampered.is_empty() {
        push(&mut out, "native_tampered", 50, Some(Class::Automated), tampered.join("; "));
    }

    // 4
    let mut diffs = Vec::new();
    for (name, r) in realms.iter().skip(1) {
        let mut f = realm_diffs(main, r);
        if *name == "iframe" {
            if let (Some(a), Some(b)) = (main.webdriver, r.webdriver) {
                if a != b {
                    f.push("webdriver");
                }
            }
        }
        if !f.is_empty() {
            diffs.push(format!("{name} differs in {}", f.join(", ")));
        }
    }
    if !diffs.is_empty() {
        push(&mut out, "realm_mismatch", 50, Some(Class::Automated), diffs.join("; "));
    }

    // 5
    if let Some(ua) = claimed.user_agent {
        if ua != main.ua {
            push(
                &mut out,
                "http_ua_mismatch",
                50,
                Some(Class::Automated),
                format!("http ua={}; report ua={}", clean(ua), clean(&main.ua)),
            );
        }
    }

    // 6
    engine_rule(&mut out, claimed, truth, &main.engine);

    // 7
    if let Some(os) = claimed.os {
        if !platform_fits(os, &main.platform) {
            push(&mut out, "platform_mismatch", 40, None, format!("claimed os {os:?}; platform={}", clean(&main.platform)));
        }
    }

    // 8
    if let Some(uad) = &main.uad {
        let mut why = Vec::new();
        if matches!(claimed.engine, Some(Engine::Gecko | Engine::Webkit)) {
            why.push("userAgentData present for non-blink engine".to_string());
        }
        if let Some(os) = claimed.os {
            if let Some(names) = uad_names(os) {
                if !names.contains(&uad.platform.as_str()) {
                    why.push(format!("uad platform={}", clean(&uad.platform)));
                }
            }
        }
        if uad.mobile != claimed.mobile {
            why.push(format!("uad mobile={}; claimed mobile={}", uad.mobile, claimed.mobile));
        }
        if !why.is_empty() {
            push(&mut out, "uad_mismatch", 40, None, why.join("; "));
        }
    }

    // 9
    if claimed.mobile && page.touch_points == 0 {
        push(&mut out, "touch_mismatch", 25, None, "mobile claimed but no touch points".to_string());
    }

    // 10
    if let (Some(os), Some(r)) = (claimed.os, renderer.as_deref()) {
        let found: Vec<&str> = foreign_gpu_markers(os).iter().copied().filter(|m| r.contains(m)).collect();
        if !found.is_empty() {
            push(
                &mut out,
                "gpu_platform_mismatch",
                40,
                None,
                format!("renderer={}; markers: {}", clean(r), found.join(", ")),
            );
        }
    }

    // 11
    if let Some(r) = renderer.as_deref() {
        if ["swiftshader", "llvmpipe", "softpipe"].iter().any(|m| r.contains(m)) {
            push(&mut out, "gpu_software", 25, None, format!("software renderer={}", clean(r)));
        }
    }

    // 12
    let [sw, sh, _, _] = page.screen;
    let [_, _, ow, oh] = page.window;
    if ow == 0 || oh == 0 || sw == 0 || sh == 0 {
        push(&mut out, "window_implausible", 20, None, "zero sized window or screen".to_string());
    }

    // 13
    if main.languages.is_empty() {
        push(&mut out, "languages_empty", 30, None, "navigator.languages is empty".to_string());
    }

    // 14
    if page.notif_permission.as_deref() == Some("denied")
        && page.perm_query_notif.as_deref() == Some("prompt")
    {
        push(&mut out, "headless_permissions", 30, Some(Class::Automated), "Notification denied but permissions query says prompt".to_string());
    }

    out
}

fn push(out: &mut Vec<Detection>, id: &str, penalty: u8, class: Option<Class>, detail: String) {
    let detail: String = detail.chars().take(256).collect();
    let d = Detection::new(id, Layer::Client, penalty, detail);
    out.push(match class {
        Some(c) => d.with_class(c),
        None => d,
    });
}

/// Reduces report text to ASCII letters, digits, space and `._-:/()`; other
/// characters become `?`. Cut to 64 characters.
fn clean(text: &str) -> String {
    text.chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || " ._-:/()".contains(c) {
                c
            } else {
                '?'
            }
        })
        .collect()
}

fn realm_diffs(a: &Realm, b: &Realm) -> Vec<&'static str> {
    let mut f = Vec::new();
    if a.ua != b.ua {
        f.push("ua");
    }
    if a.platform != b.platform {
        f.push("platform");
    }
    if a.languages != b.languages {
        f.push("languages");
    }
    if a.hc != b.hc {
        f.push("hc");
    }
    if a.engine.err_msg != b.engine.err_msg {
        f.push("err_msg");
    }
    if a.engine.eval_len != b.engine.eval_len {
        f.push("eval_len");
    }
    f
}

/// Failed dimensions of a profile against signals, and how many dimensions
/// the profile checks.
fn profile_check(p: &EngineProfile, e: &EngineSignals) -> (Vec<String>, usize) {
    let mut failed = Vec::new();
    let mut checked = 0usize;
    if !p.err_msg.is_empty() {
        checked = checked.saturating_add(1);
        if !p.err_msg.contains(&e.err_msg) {
            failed.push("err_msg".to_string());
        }
    }
    if !p.eval_len.is_empty() {
        checked = checked.saturating_add(1);
        if !p.eval_len.contains(&e.eval_len) {
            failed.push("eval_len".to_string());
        }
    }
    if let Some(want) = p.stack_at {
        checked = checked.saturating_add(1);
        if want != e.stack_at {
            failed.push("stack_at".to_string());
        }
    }
    for (name, want) in &p.features {
        checked = checked.saturating_add(1);
        if e.features.get(name) != Some(want) {
            failed.push(format!("feature {}", clean(name)));
        }
    }
    if !p.math.is_empty() {
        checked = checked.saturating_add(1);
        if !p.math.contains(&e.math) {
            failed.push("math".to_string());
        }
    }
    (failed, checked)
}

fn engine_rule(out: &mut Vec<Detection>, claimed: &Claimed<'_>, truth: &EngineTruth, e: &EngineSignals) {
    let Some(want) = claimed.engine else { return };
    let Some(profile) = truth.profiles.iter().find(|p| p.engine == want) else { return };
    let (failed, _) = profile_check(profile, e);
    if failed.is_empty() {
        return;
    }
    let fits: Vec<&str> = truth
        .profiles
        .iter()
        .filter(|p| p.engine != want)
        .filter(|p| {
            let (f, c) = profile_check(p, e);
            f.is_empty() && c > 0
        })
        .map(|p| p.engine.as_str())
        .collect();
    let mut detail = format!("claimed {}; failed: {}", want.as_str(), failed.join(", "));
    if !fits.is_empty() {
        detail.push_str(&format!("; signals fit {}", fits.join(", ")));
    }
    if profile.verified {
        push(out, "engine_mismatch", 60, Some(Class::Automated), detail);
    } else {
        push(out, "engine_mismatch", 20, None, detail);
    }
}

fn platform_fits(os: Os, platform: &str) -> bool {
    let prefixes: &[&str] = match os {
        Os::Windows => &["Win"],
        Os::MacOs => &["Mac"],
        Os::Linux | Os::ChromeOs => &["Linux"],
        Os::Android => &["Linux", "Android"],
        Os::Ios => &["iPhone", "iPad", "iPod"],
    };
    prefixes.iter().any(|p| platform.starts_with(p))
}

fn uad_names(os: Os) -> Option<&'static [&'static str]> {
    match os {
        Os::Windows => Some(&["Windows"]),
        Os::MacOs => Some(&["macOS"]),
        Os::Linux => Some(&["Linux"]),
        Os::Android => Some(&["Android"]),
        Os::ChromeOs => Some(&["Chrome OS", "Chromium OS"]),
        Os::Ios => None,
    }
}

fn foreign_gpu_markers(os: Os) -> &'static [&'static str] {
    match os {
        Os::Windows => &["apple", "metal"],
        Os::MacOs | Os::Ios => &["direct3d", "d3d11"],
        Os::Linux | Os::Android | Os::ChromeOs => &["direct3d", "d3d11", "apple"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_replaces_and_cuts() {
        assert_eq!(clean("a<b>\"é,;=x"), "a?b??????x");
        assert_eq!(clean(&"a".repeat(100)).len(), 64);
        assert_eq!(clean("ok._-:/() 1"), "ok._-:/() 1");
    }

    #[test]
    fn push_truncates_detail() {
        let mut v = Vec::new();
        push(&mut v, "x", 1, None, "a".repeat(300));
        assert_eq!(v.first().map(|d| d.detail.len()), Some(256));
    }

    #[test]
    fn platform_prefixes_are_case_sensitive() {
        assert!(platform_fits(Os::Windows, "Win32"));
        assert!(!platform_fits(Os::Windows, "win32"));
        assert!(!platform_fits(Os::MacOs, "mac"));
    }
}
