//! Report schema and analysis inputs. FIXED BY THE PROJECT LEAD: DO NOT EDIT.
//!
//! The JavaScript probe (`probe/probe.js`) produces a [`ProbeReport`] as JSON.
//! `probe/SCHEMA.md` describes the same structure for the script's author.
//! The report carries raw observations; every judgement is made on the
//! server so that rules can change without shipping a new script.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Largest accepted report body.
pub const MAX_REPORT_BYTES: usize = 32 * 1024;
/// Longest accepted string anywhere in a report, in bytes.
pub const MAX_STRING_BYTES: usize = 512;
/// Most entries accepted in any array or map in a report.
pub const MAX_ITEMS: usize = 64;
/// The only report version this crate understands.
pub const REPORT_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeReport {
    pub v: u32,
    /// The nonce the server embedded in the script.
    pub nonce: String,
    /// The page's own JavaScript world.
    pub main: Realm,
    /// A fresh same-origin iframe, or null if it could not be created.
    pub iframe: Option<Realm>,
    /// A dedicated worker, or null if it could not be created.
    pub worker: Option<Realm>,
    /// Observations that only exist in the main world.
    pub page: Page,
    /// Internal probe failures (short messages), for diagnosis only.
    #[serde(default)]
    pub errors: Vec<String>,
}

/// What one JavaScript realm says about itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Realm {
    /// `navigator.userAgent`
    pub ua: String,
    /// `navigator.platform`
    pub platform: String,
    /// `navigator.languages`
    pub languages: Vec<String>,
    /// `navigator.hardwareConcurrency`, 0 when unavailable.
    pub hc: u32,
    /// `navigator.webdriver`; null when the property does not exist
    /// (workers do not have it).
    pub webdriver: Option<bool>,
    /// `navigator.userAgentData` low-entropy values; null when unsupported.
    pub uad: Option<UaData>,
    pub engine: EngineSignals,
    /// Native functions that look modified. Empty in an untouched browser.
    #[serde(default)]
    pub tamper: Vec<Tamper>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UaData {
    pub platform: String,
    pub mobile: bool,
    /// Brand names only, in the order the browser lists them.
    pub brands: Vec<String>,
}

/// Behaviour of the JavaScript engine itself, independent of `navigator`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineSignals {
    /// `message` of the TypeError thrown by reading property `x` of `null`.
    pub err_msg: String,
    /// `eval.toString().length`
    pub eval_len: u32,
    /// Whether the second line of `new Error("p").stack` starts with
    /// four spaces and `at `.
    pub stack_at: bool,
    /// Named feature tests; see `probe/SCHEMA.md` for the fixed list.
    pub features: BTreeMap<String, bool>,
    /// A few transcendental results joined by commas; see `probe/SCHEMA.md`.
    pub math: String,
}

/// One native function or accessor that failed an integrity check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tamper {
    /// What was checked, for example `Navigator.prototype.webdriver`.
    pub target: String,
    /// Which checks failed, for example `to_string`, `own_property`.
    pub kinds: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page {
    /// `navigator.plugins.length`
    pub plugins: u32,
    /// `screen.width`, `screen.height`, `screen.availWidth`, `screen.availHeight`
    pub screen: [u32; 4],
    /// `innerWidth`, `innerHeight`, `outerWidth`, `outerHeight`
    pub window: [u32; 4],
    /// `devicePixelRatio` times 100, rounded.
    pub dpr_x100: u32,
    /// `navigator.maxTouchPoints`
    pub touch_points: u32,
    /// Unmasked WebGL vendor and renderer; null when unavailable.
    pub webgl_vendor: Option<String>,
    pub webgl_renderer: Option<String>,
    /// Whether `window.chrome` is an object.
    pub chrome_obj: bool,
    /// `Notification.permission`; null when `Notification` does not exist.
    pub notif_permission: Option<String>,
    /// `state` from `navigator.permissions.query({name: "notifications"})`;
    /// null when unavailable or rejected.
    pub perm_query_notif: Option<String>,
    /// Names of automation-framework globals that are present.
    #[serde(default)]
    pub globals: Vec<String>,
    /// `Intl.DateTimeFormat().resolvedOptions().timeZone`, or "".
    pub tz: String,
    /// `new Date().getTimezoneOffset()`
    pub tz_offset_min: i32,
}

/// A JavaScript engine family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Engine {
    Blink,
    Gecko,
    Webkit,
}

impl Engine {
    pub fn as_str(&self) -> &'static str {
        match self {
            Engine::Blink => "blink",
            Engine::Gecko => "gecko",
            Engine::Webkit => "webkit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Os {
    Windows,
    MacOs,
    Linux,
    Android,
    Ios,
    ChromeOs,
}

/// What the HTTP request claimed, as parsed by the caller from the
/// User-Agent header.
#[derive(Clone, Copy, Debug, Default)]
pub struct Claimed<'a> {
    /// The HTTP User-Agent header of the request that delivered the report.
    pub user_agent: Option<&'a str>,
    /// The browser engine that User-Agent implies, if it names a browser.
    pub engine: Option<Engine>,
    /// The operating system that User-Agent implies, if recognised.
    pub os: Option<Os>,
    /// Whether that User-Agent is a phone or tablet one.
    pub mobile: bool,
}

/// What one engine family is known to answer. A dimension that is absent or
/// empty is not checked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineProfile {
    pub engine: Engine,
    /// True when every value was captured from a real browser on the
    /// project's bench. Unverified profiles produce weak detections only.
    pub verified: bool,
    /// Accepted `err_msg` values (exact match).
    #[serde(default)]
    pub err_msg: Vec<String>,
    /// Accepted `eval_len` values.
    #[serde(default)]
    pub eval_len: Vec<u32>,
    #[serde(default)]
    pub stack_at: Option<bool>,
    /// Expected feature test results. Features not listed are not checked.
    #[serde(default)]
    pub features: BTreeMap<String, bool>,
    /// Accepted `math` values (exact match).
    #[serde(default)]
    pub math: Vec<String>,
}

/// The engine truth table: at most one profile per engine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineTruth {
    pub version: u32,
    #[serde(default)]
    pub note: String,
    pub profiles: Vec<EngineProfile>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReportError {
    /// Body longer than [`MAX_REPORT_BYTES`].
    TooLarge,
    /// Not JSON, or not the report shape.
    Json(String),
    /// `v` is not [`REPORT_VERSION`].
    Version(u32),
    /// A string longer than [`MAX_STRING_BYTES`] or a collection with more
    /// than [`MAX_ITEMS`] entries. The payload names the field.
    Limit(&'static str),
}

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportError::TooLarge => write!(f, "report too large"),
            ReportError::Json(m) => write!(f, "invalid report: {m}"),
            ReportError::Version(v) => write!(f, "unsupported report version {v}"),
            ReportError::Limit(field) => write!(f, "report field over limit: {field}"),
        }
    }
}

impl std::error::Error for ReportError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TruthError {
    Json(String),
    /// Two profiles for the same engine.
    Duplicate(Engine),
}

impl std::fmt::Display for TruthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TruthError::Json(m) => write!(f, "invalid engine truth: {m}"),
            TruthError::Duplicate(e) => write!(f, "duplicate profile for {}", e.as_str()),
        }
    }
}

impl std::error::Error for TruthError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonceError {
    Malformed,
    BadMac,
    Expired,
    BindingMismatch,
}

/// A verified nonce. `id` is what the caller records to enforce single use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonceInfo {
    pub id: [u8; 16],
    pub expires_at: u64,
}
