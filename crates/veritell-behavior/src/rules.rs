//! Rules over a parsed behaviour summary.

use veritell_core::{Class, Detection, Layer};

use crate::types::{Params, Summary};
use crate::{
    AGENT_RHYTHM, CADENCE_FIXED, CLICK_CENTERED, CLICK_JUMPED, KEYS_METRONOMIC, NO_INPUT,
    POINTER_SCRIPTED, UNTRUSTED_SUBMIT,
};

/// Returns one detection per rule that fires, in the order below. Every
/// detection is in `Layer::Behavior`; `detail` states the numbers the rule
/// saw. Comparisons use integer arithmetic that cannot overflow.
///
/// | id | fires when | penalty | class hint |
/// |---|---|---|---|
/// | `behavior_no_input` | `submits >= 1` and `!has_input()` | 40 | Automated |
/// | `behavior_untrusted_submit` | `submits >= 1`, `untrusted >= 1`, and `clicks`, `touches`, `keys` and `pastes` all zero: the form was submitted with script-made events and nothing a person does to submit one | 40 | Automated |
/// | `behavior_pointer_scripted` | `strokes >= min_strokes` and (`straight * 100 >= strokes * straight_pct` or `steady * 100 >= strokes * steady_pct`) | 35 | Automated |
/// | `behavior_click_centered` | `sized >= min_sized_clicks` and `centered == sized` | 35 | Automated |
/// | `behavior_click_jumped` | `touches == 0`, `teleport >= min_jumped_clicks` and `teleport * 100 >= clicks * jumped_pct` | 30 | none: a script and an LLM-driven agent both do this, and the agent rule must be able to name its class |
/// | `behavior_keys_metronomic` | `keys >= min_keys` and `key_gap_cv` is `Some(cv)` with `cv <= key_cv_max` | 30 | Automated |
/// | `behavior_cadence_fixed` | `actions >= min_actions` and `gap_cv` is `Some(cv)` with `cv <= cadence_cv_max` | 30 | Automated |
/// | `behavior_agent_rhythm` | `actions >= agent_min_actions`, `gap_med_ms` is `Some(m)` with `m >= agent_think_ms`, `touches == 0`, `clicks >= 1`, `teleport == clicks` and `moves <= clicks * agent_moves_per_click` | 30 | UnverifiedAgent |
pub fn analyze(summary: &Summary, params: &Params) -> Vec<Detection> {
    let s = summary;
    let p = params;
    let mut out = Vec::new();

    if s.submits >= 1 && !s.has_input() {
        out.push(
            Detection::new(
                NO_INPUT,
                Layer::Behavior,
                40,
                format!(
                    "form submitted {} time(s) after {} ms with no pointer, touch, key, paste or scroll input",
                    s.submits, s.dur_ms
                ),
            )
            .with_class(Class::Automated),
        );
    }

    if s.submits >= 1 && s.untrusted >= 1 && s.clicks == 0 && s.touches == 0 && s.keys == 0 && s.pastes == 0 {
        out.push(
            Detection::new(
                UNTRUSTED_SUBMIT,
                Layer::Behavior,
                40,
                format!(
                    "form submitted {} time(s) with {} script-made (untrusted) event(s) and no click, touch, key or paste by the user before the submit",
                    s.submits, s.untrusted
                ),
            )
            .with_class(Class::Automated),
        );
    }

    let strokes_straight = u64::from(s.strokes).saturating_mul(u64::from(p.straight_pct));
    let strokes_steady = u64::from(s.strokes).saturating_mul(u64::from(p.steady_pct));
    let straight_hit = u64::from(s.straight).saturating_mul(100) >= strokes_straight;
    let steady_hit = u64::from(s.steady).saturating_mul(100) >= strokes_steady;
    if s.strokes >= p.min_strokes && (straight_hit || steady_hit) {
        out.push(
            Detection::new(
                POINTER_SCRIPTED,
                Layer::Behavior,
                35,
                format!(
                    "{} of {} pointer strokes were straight and {} were at constant speed (thresholds {}% and {}%, at least {} strokes)",
                    s.straight, s.strokes, s.steady, p.straight_pct, p.steady_pct, p.min_strokes
                ),
            )
            .with_class(Class::Automated),
        );
    }

    if s.sized >= p.min_sized_clicks && s.centered == s.sized {
        out.push(
            Detection::new(
                CLICK_CENTERED,
                Layer::Behavior,
                35,
                format!(
                    "{} of {} clicks on targets of at least 24 by 24 pixels landed on the exact centre (at least {} needed)",
                    s.centered, s.sized, p.min_sized_clicks
                ),
            )
            .with_class(Class::Automated),
        );
    }

    let jumped_share = u64::from(s.teleport).saturating_mul(100) >= u64::from(s.clicks).saturating_mul(u64::from(p.jumped_pct));
    // On a touch screen there is no pointer to travel: every tap "jumps".
    if s.touches == 0 && s.teleport >= p.min_jumped_clicks && jumped_share {
        out.push(
            Detection::new(
                CLICK_JUMPED,
                Layer::Behavior,
                30,
                format!(
                    "{} of {} mouse clicks arrived without the pointer travelling there (at least {} needed, {}% of clicks)",
                    s.teleport, s.clicks, p.min_jumped_clicks, p.jumped_pct
                ),
            ),
        );
    }

    if let Some(cv) = s.key_gap_cv {
        if s.keys >= p.min_keys && cv <= p.key_cv_max {
            out.push(
                Detection::new(
                    KEYS_METRONOMIC,
                    Layer::Behavior,
                    30,
                    format!(
                        "{} keys with gap variation {} (times 1000), at most {} counts as metronomic",
                        s.keys, cv, p.key_cv_max
                    ),
                )
                .with_class(Class::Automated),
            );
        }
    }

    if let Some(cv) = s.gap_cv {
        if s.actions >= p.min_actions && cv <= p.cadence_cv_max {
            out.push(
                Detection::new(
                    CADENCE_FIXED,
                    Layer::Behavior,
                    30,
                    format!(
                        "{} actions with gap variation {} (times 1000), at most {} counts as a fixed timer",
                        s.actions, cv, p.cadence_cv_max
                    ),
                )
                .with_class(Class::Automated),
            );
        }
    }

    if let Some(m) = s.gap_med_ms {
        let move_cap = u64::from(s.clicks).saturating_mul(u64::from(p.agent_moves_per_click));
        if s.actions >= p.agent_min_actions
            && m >= p.agent_think_ms
            && s.touches == 0
            && s.clicks >= 1
            && s.teleport == s.clicks
            && u64::from(s.moves) <= move_cap
        {
            out.push(
                Detection::new(
                    AGENT_RHYTHM,
                    Layer::Behavior,
                    30,
                    format!(
                        "{} actions with a median gap of {} ms; all {} clicks jumped with {} pointer moves in total",
                        s.actions, m, s.clicks, s.moves
                    ),
                )
                .with_class(Class::UnverifiedAgent),
            );
        }
    }

    out
}
