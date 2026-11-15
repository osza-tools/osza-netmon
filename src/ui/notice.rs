// SPDX-License-Identifier: GPL-3.0-only

//! The authorization-notice screen (FR-ST-01, ADR-004; task T-302
//! §5.1) — the full-screen notice requiring `y` before **any**
//! discovery.
//!
//! The notice text is ADR-004 **verbatim** with `{DISPLAY_NAME}`
//! substituted; the second paragraph restates the plan's own scope
//! promises (plan §2.2/§2.3, as the §10.2 wireframe shows it). The
//! text's version is [`NOTICE_VERSION`](crate::app::config::NOTICE_VERSION)
//! (starts at 1; bumps only when the text changes — the O-6 ruling of
//! plan v1.12.0): a stored acknowledgment of a different version
//! reads as unacknowledged, so the full notice re-appears.
//!
//! The keys are the core's (§10.3 / FR-ST-01): `y` acknowledges — the
//! only key that does — and `q`/`Ctrl+C` quit; this module only
//! renders, the state machine is `app::update`'s.
//!
//! # §8.2 discipline
//!
//! This module imports the app's constant and the crate root's
//! display name only; it draws through the frame it is handed and
//! mutates nothing.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::style::Stylize;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Block;
use ratatui::widgets::Borders;
use ratatui::widgets::Paragraph;

use crate::DISPLAY_NAME;

/// The ADR-004 notice text, verbatim, with `{DISPLAY_NAME}`
/// substituted (three sentences; ADR-004's own quotation is the
/// authority — do not reword).
pub const NOTICE_TEXT: &str = "is intended only for networks you own or are \
explicitly authorized to monitor. Local discovery sends network probes. Use \
this tool only within an authorized network.";

/// The scope-promise paragraph the plan's §10.2 notice wireframe shows
/// under the ADR-004 text (plan §2.2/§2.3, honest and factual).
pub const SCOPE_PROMISE_TEXT: &str = "It does not scan ports, capture traffic, \
or send device information to any external service.";

/// Renders the notice screen into `area`.
pub fn render(frame: &mut Frame, area: Rect) {
    let title = format!("{DISPLAY_NAME} — Authorization notice");
    let mut lines: Vec<Line> = Vec::new();
    // The ADR-004 text, wrapped as the wireframe shows it, prefixed by
    // the display name (the {DISPLAY_NAME} substitution).
    for paragraph in [NOTICE_TEXT, SCOPE_PROMISE_TEXT] {
        let full = if paragraph == NOTICE_TEXT {
            format!("{DISPLAY_NAME} {paragraph}")
        } else {
            paragraph.to_owned()
        };
        for chunk in wrap(&full, (area.width.saturating_sub(4)).max(20) as usize) {
            lines.push(Line::from(chunk));
        }
        lines.push(Line::from(""));
    }
    lines.push(Line::from(vec![
        Span::from(" [y] I understand and continue      "),
        Span::from("[q] Quit").dim(),
    ]));
    let notice = Paragraph::new(lines)
        .block(
            Block::new()
                .borders(Borders::NONE)
                .title(format!(" {title} ")),
        )
        .style(Style::new());
    frame.render_widget(notice, area);
}

/// Greedy word wrap for the notice's paragraphs (the text is static
/// and ASCII; the width comes from the area).
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split(' ') {
        if current.is_empty() {
            current.push_str(word);
        } else if current.chars().count() + 1 + word.chars().count() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(core::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::config::NOTICE_VERSION;
    use ratatui::backend::TestBackend;

    /// The full drawn buffer as one string.
    fn drawn(width: u16, height: u16) -> String {
        let mut terminal =
            ratatui::Terminal::new(TestBackend::new(width, height)).expect("test backend");
        terminal
            .draw(|frame| render(frame, frame.area()))
            .expect("drawing cannot fail");
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol().to_owned())
            .collect()
    }

    #[test]
    fn the_notice_shows_the_adr004_text_verbatim_with_the_display_name() {
        // The drawn buffer wraps the text to the area's width, so the
        // assertions use wrap-robust fragments (the full sentences are
        // pinned verbatim in the text-constant test below).
        let text = drawn(80, 24);
        assert!(
            text.contains("osza Network Monitor is intended only for networks you own"),
            "{text}"
        );
        assert!(text.contains("explicitly"), "{text}");
        assert!(text.contains("authorized to monitor."), "{text}");
        assert!(
            text.contains("Local discovery sends network probes."),
            "{text}"
        );
        assert!(text.contains("Use this tool"), "{text}");
        assert!(text.contains("within an authorized network."), "{text}");
        assert!(text.contains("It does not scan ports"), "{text}");
        assert!(text.contains("capture traffic"), "{text}");
        assert!(text.contains("[y] I understand and continue"), "{text}");
        assert!(text.contains("[q] Quit"), "{text}");
    }

    #[test]
    fn the_notice_renders_at_both_snapshot_sizes() {
        // §5.6: 80×24 and 100×30 without panic or blank output.
        for (width, height) in [(80u16, 24u16), (100, 30)] {
            let text = drawn(width, height);
            assert!(text.contains("Authorization notice"), "{width}×{height}");
            assert!(text.contains("authorized"), "{width}×{height}");
        }
    }

    #[test]
    fn the_notice_text_is_pinned_and_versioned() {
        // The version constant and the text change together, by
        // review: pinning the exact sentences here makes an accidental
        // reword fail loudly (a deliberate change bumps
        // NOTICE_VERSION and updates this pin).
        assert_eq!(
            NOTICE_TEXT,
            "is intended only for networks you own or are explicitly authorized to monitor. \
Local discovery sends network probes. Use this tool only within an authorized network."
        );
        assert_eq!(NOTICE_VERSION, 1);
    }

    #[test]
    fn the_wrap_never_produces_overlong_or_empty_output() {
        let wrapped = wrap(&format!("{DISPLAY_NAME} {NOTICE_TEXT}"), 60);
        assert!(!wrapped.is_empty());
        for line in &wrapped {
            assert!(line.chars().count() <= 60, "{line}");
            assert!(!line.is_empty());
        }
        // A single long word cannot be split — it stays one line (the
        // terminal clips; the notice's words are all short).
        let one = wrap("authorized", 4);
        assert_eq!(one, vec!["authorized".to_owned()]);
    }
}
