//! Parsing with limits. Implement the bodies; do not change signatures.

use crate::types::{
    EngineTruth, Page, ProbeReport, Realm, ReportError, TruthError, MAX_ITEMS, MAX_REPORT_BYTES,
    MAX_STRING_BYTES, REPORT_VERSION,
};

/// Field names of one realm, as string literals for [`ReportError::Limit`].
struct RealmNames {
    ua: &'static str,
    platform: &'static str,
    languages: &'static str,
    uad_platform: &'static str,
    uad_brands: &'static str,
    err_msg: &'static str,
    features: &'static str,
    math: &'static str,
    tamper: &'static str,
    tamper_target: &'static str,
    tamper_kinds: &'static str,
}

macro_rules! realm_names {
    ($p:literal) => {
        RealmNames {
            ua: concat!($p, ".ua"),
            platform: concat!($p, ".platform"),
            languages: concat!($p, ".languages"),
            uad_platform: concat!($p, ".uad.platform"),
            uad_brands: concat!($p, ".uad.brands"),
            err_msg: concat!($p, ".engine.err_msg"),
            features: concat!($p, ".engine.features"),
            math: concat!($p, ".engine.math"),
            tamper: concat!($p, ".tamper"),
            tamper_target: concat!($p, ".tamper.target"),
            tamper_kinds: concat!($p, ".tamper.kinds"),
        }
    };
}

const MAIN: RealmNames = realm_names!("main");
const IFRAME: RealmNames = realm_names!("iframe");
const WORKER: RealmNames = realm_names!("worker");

type Check = Result<(), ReportError>;

fn s(value: &str, field: &'static str) -> Check {
    if value.len() > MAX_STRING_BYTES {
        Err(ReportError::Limit(field))
    } else {
        Ok(())
    }
}

fn n(count: usize, field: &'static str) -> Check {
    if count > MAX_ITEMS {
        Err(ReportError::Limit(field))
    } else {
        Ok(())
    }
}

fn opt(value: &Option<String>, field: &'static str) -> Check {
    match value {
        Some(v) => s(v, field),
        None => Ok(()),
    }
}

fn strings(values: &[String], field: &'static str) -> Check {
    n(values.len(), field)?;
    values.iter().try_for_each(|v| s(v, field))
}

fn check_realm(r: &Realm, f: &RealmNames) -> Check {
    s(&r.ua, f.ua)?;
    s(&r.platform, f.platform)?;
    strings(&r.languages, f.languages)?;
    if let Some(uad) = &r.uad {
        s(&uad.platform, f.uad_platform)?;
        strings(&uad.brands, f.uad_brands)?;
    }
    s(&r.engine.err_msg, f.err_msg)?;
    n(r.engine.features.len(), f.features)?;
    r.engine.features.keys().try_for_each(|k| s(k, f.features))?;
    s(&r.engine.math, f.math)?;
    n(r.tamper.len(), f.tamper)?;
    for t in &r.tamper {
        s(&t.target, f.tamper_target)?;
        strings(&t.kinds, f.tamper_kinds)?;
    }
    Ok(())
}

fn check_page(p: &Page) -> Check {
    opt(&p.webgl_vendor, "page.webgl_vendor")?;
    opt(&p.webgl_renderer, "page.webgl_renderer")?;
    opt(&p.notif_permission, "page.notif_permission")?;
    opt(&p.perm_query_notif, "page.perm_query_notif")?;
    strings(&p.globals, "page.globals")?;
    s(&p.tz, "page.tz")
}

/// Parses a report body.
///
/// Checks, in this order: body length (`TooLarge`), JSON shape (`Json`),
/// version (`Version`), then every string against `MAX_STRING_BYTES` and
/// every array or map against `MAX_ITEMS` (`Limit` naming the field, for
/// example `"main.ua"`, `"page.globals"`, `"worker.tamper.kinds"`).
/// Unknown fields are ignored.
pub fn parse_report(body: &[u8]) -> Result<ProbeReport, ReportError> {
    if body.len() > MAX_REPORT_BYTES {
        return Err(ReportError::TooLarge);
    }
    let report: ProbeReport =
        serde_json::from_slice(body).map_err(|e| ReportError::Json(e.to_string()))?;
    if report.v != REPORT_VERSION {
        return Err(ReportError::Version(report.v));
    }
    s(&report.nonce, "nonce")?;
    check_realm(&report.main, &MAIN)?;
    if let Some(r) = &report.iframe {
        check_realm(r, &IFRAME)?;
    }
    if let Some(r) = &report.worker {
        check_realm(r, &WORKER)?;
    }
    check_page(&report.page)?;
    strings(&report.errors, "errors")?;
    Ok(report)
}

/// Parses an engine truth file and rejects two profiles for one engine.
pub fn parse_truth(json: &str) -> Result<EngineTruth, TruthError> {
    let truth: EngineTruth =
        serde_json::from_str(json).map_err(|e| TruthError::Json(e.to_string()))?;
    let mut seen = Vec::new();
    for p in &truth.profiles {
        if seen.contains(&p.engine) {
            return Err(TruthError::Duplicate(p.engine));
        }
        seen.push(p.engine);
    }
    Ok(truth)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> serde_json::Value {
        let realm = serde_json::json!({
            "ua": "u", "platform": "p", "languages": [], "hc": 1, "webdriver": null,
            "uad": {"platform": "x", "mobile": false, "brands": []},
            "engine": {"err_msg": "", "eval_len": 1, "stack_at": true, "features": {}, "math": ""}
        });
        serde_json::json!({
            "v": 1, "nonce": "n", "main": realm, "iframe": null, "worker": null,
            "page": {"plugins": 0, "screen": [1,1,1,1], "window": [1,1,1,1], "dpr_x100": 100,
                "touch_points": 0, "webgl_vendor": null, "webgl_renderer": null,
                "chrome_obj": false, "notif_permission": null, "perm_query_notif": null,
                "tz": "", "tz_offset_min": 0}
        })
    }

    fn limit(v: &serde_json::Value) -> Option<&'static str> {
        match parse_report(v.to_string().as_bytes()) {
            Err(ReportError::Limit(f)) => Some(f),
            _ => None,
        }
    }

    #[test]
    fn named_limits() {
        let long = "a".repeat(MAX_STRING_BYTES + 1);
        let many = vec!["a"; MAX_ITEMS + 1];
        assert!(parse_report(base().to_string().as_bytes()).is_ok());
        let cases: Vec<(Vec<&str>, serde_json::Value, &str)> = vec![
            (vec!["nonce"], long.clone().into(), "nonce"),
            (vec!["main", "languages"], many.clone().into(), "main.languages"),
            (vec!["main", "uad", "brands"], many.clone().into(), "main.uad.brands"),
            (vec!["main", "uad", "platform"], long.clone().into(), "main.uad.platform"),
            (vec!["main", "engine", "err_msg"], long.clone().into(), "main.engine.err_msg"),
            (vec!["main", "engine", "math"], long.clone().into(), "main.engine.math"),
            (vec!["page", "tz"], long.clone().into(), "page.tz"),
            (vec!["main", "tamper"], serde_json::json!(vec![serde_json::json!({"target":"t","kinds":[]}); MAX_ITEMS + 1]), "main.tamper"),
            (vec!["main", "tamper"], serde_json::json!([{"target": long, "kinds": []}]), "main.tamper.target"),
        ];
        for (path, value, expect) in cases {
            let mut v = base();
            let mut cur = &mut v;
            for p in &path {
                cur = &mut cur[*p];
            }
            *cur = value;
            assert_eq!(limit(&v), Some(expect));
        }
    }

    #[test]
    fn feature_keys_count_as_strings() {
        let mut v = base();
        v["main"]["engine"]["features"] = serde_json::json!({ "k".repeat(MAX_STRING_BYTES + 1): true });
        assert_eq!(limit(&v), Some("main.engine.features"));
    }

    #[test]
    fn multibyte_strings_are_measured_in_bytes() {
        let mut v = base();
        v["main"]["ua"] = "é".repeat(MAX_STRING_BYTES / 2 + 1).into();
        assert_eq!(limit(&v), Some("main.ua"));
    }

    #[test]
    fn exact_body_limit() {
        let mut body = base().to_string().into_bytes();
        body.resize(MAX_REPORT_BYTES, b' ');
        assert!(parse_report(&body).is_ok());
        body.push(b' ');
        assert_eq!(parse_report(&body), Err(ReportError::TooLarge));
    }

    #[test]
    fn truth_duplicates_and_shape() {
        assert!(parse_truth(r#"{"version":1,"profiles":[{"engine":"blink","verified":true},{"engine":"gecko","verified":false}]}"#).is_ok());
        assert!(matches!(parse_truth("{}"), Err(TruthError::Json(_))));
    }
}
