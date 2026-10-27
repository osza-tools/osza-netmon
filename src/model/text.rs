// SPDX-License-Identifier: GPL-3.0-only

//! Validated text boundary types: [`Hostname`] and [`DisplayText`]
//! (plan §5.2, FR-EN-04, SR-04, task T-002).
//!
//! Every string that originates from the network or from data files passes
//! through one of these types before it can reach the UI. Both types have
//! private fields and **no** public constructor that accepts a raw string;
//! the only way to create a value is the validating
//! [`TryFrom<&str>`](TryFrom) / [`FromStr`] conversion, so an unvalidated
//! string cannot enter the model by construction.
//!
//! * [`Hostname`] — strict: ASCII `[A-Za-z0-9._-]`, at most 253 characters.
//!   Anything else is rejected; nothing is trimmed or repaired.
//! * [`DisplayText`] — sanitizing: free text (e.g. vendor names) reduced to
//!   a safe, single-line, whitespace-collapsed form of at most 64
//!   characters. ANSI escape sequences, non-whitespace control characters
//!   (C0/C1/DEL), bidi controls and zero-width characters are removed.

use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;

/// Maximum length of a [`Hostname`] in characters (plan §5.2).
pub const HOSTNAME_MAX_CHARS: usize = 253;

/// Maximum length of a [`DisplayText`] in characters (plan §5.2).
pub const DISPLAY_TEXT_MAX_CHARS: usize = 64;

/// Errors returned when text is rejected by [`Hostname`] or [`DisplayText`].
///
/// Wording follows the controlled vocabulary of plan §5.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    /// The hostname input was empty.
    #[error("hostname is empty")]
    HostnameEmpty,
    /// The hostname contains a character outside `[A-Za-z0-9._-]`.
    #[error(
        "hostname contains disallowed character {found:?} at position {position} (allowed: ASCII letters, digits, '.', '_' and '-')"
    )]
    HostnameCharacter {
        /// The offending character.
        found: char,
        /// Zero-based character position of `found`.
        position: usize,
    },
    /// The hostname exceeds [`HOSTNAME_MAX_CHARS`].
    #[error("hostname exceeds the maximum of 253 characters: found {found}")]
    HostnameTooLong {
        /// Total number of characters in the rejected input.
        found: usize,
    },
    /// The display text was empty (or only whitespace/escapes) after
    /// sanitization.
    #[error("display text is empty after sanitization")]
    DisplayTextEmpty,
}

/// A validated hostname (plan §5.2).
///
/// Constructible only through validation; the charset is ASCII
/// `[A-Za-z0-9._-]` and the length is at most [`HOSTNAME_MAX_CHARS`]
/// characters. Note that this is a *syntactic* boundary check for safe
/// display and map keys — full RFC label validation is out of scope for the
/// MVP (nothing downstream depends on it; reverse-DNS answers that fail
/// here simply become `Unknown`, see plan ADR-003).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hostname {
    inner: String,
}

impl TryFrom<&str> for Hostname {
    type Error = ValidationError;

    /// Validates exactly: no trimming, no case folding, no silent
    /// truncation. The length rule is checked first (plan §5.2 lists it
    /// with the charset), then every character against the allowed set.
    fn try_from(input: &str) -> Result<Self, Self::Error> {
        let count = input.chars().count();
        if count == 0 {
            return Err(ValidationError::HostnameEmpty);
        }
        if count > HOSTNAME_MAX_CHARS {
            return Err(ValidationError::HostnameTooLong { found: count });
        }
        for (position, c) in input.chars().enumerate() {
            if !is_hostname_char(c) {
                return Err(ValidationError::HostnameCharacter { found: c, position });
            }
        }
        Ok(Self {
            inner: input.to_owned(),
        })
    }
}

impl FromStr for Hostname {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Hostname::try_from(s)
    }
}

impl Hostname {
    /// The validated text.
    pub fn as_str(&self) -> &str {
        &self.inner
    }
}

impl fmt::Display for Hostname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.inner)
    }
}

/// A sanitized, single-line display string of at most
/// [`DISPLAY_TEXT_MAX_CHARS`] characters (plan §5.2: "sanitized free text
/// (vendor names)").
///
/// Sanitization (applied in this order):
///
/// 1. **ANSI escape sequences are removed whole**: CSI (`ESC [ … final`),
///    OSC (`ESC ] … BEL` or `ESC ] … ESC \`), two-character escapes
///    (`ESC c`) and escapes with intermediate bytes (`ESC ( B`). An
///    unterminated OSC sequence swallows the rest of the input — the safe
///    direction for a display string.
/// 2. **Whitespace runs collapse to one ASCII space**: leading and trailing
///    whitespace is dropped entirely; any run of whitespace characters
///    (including tab, newline, and non-ASCII spaces) inside the text becomes
///    a single `' '`. Word separation survives sanitization.
/// 3. **Remaining unsafe characters are stripped**: non-whitespace C0 and
///    C1 controls, DEL, bidi controls `U+202A–U+202E`, and zero-width
///    characters `U+200B–U+200F` and `U+FEFF`.
/// 4. **Truncation to 64 characters**, never splitting a character.
///
/// If the result is empty, the input is rejected with
/// [`ValidationError::DisplayTextEmpty`] — an absent value is modeled by
/// `Field::Unknown`/`Field::Unavailable`, never by an empty display string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DisplayText {
    inner: String,
}

impl TryFrom<&str> for DisplayText {
    type Error = ValidationError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        // Worst case each kept char is 4 bytes; the cap keeps this bounded.
        let mut out = String::with_capacity(4 * DISPLAY_TEXT_MAX_CHARS);
        let mut state = EscapeState::Ground;
        let mut chars = 0usize;
        let mut started = false; // a non-space character has been emitted
        let mut pending_space = false; // a space is due before the next char

        for c in input.chars() {
            match state {
                EscapeState::Ground => {
                    if c == '\u{1b}' {
                        state = EscapeState::Escape;
                    } else if c.is_whitespace() {
                        // Collapse: remember one space; drop it if nothing
                        // precedes the next real character (leading trim) or
                        // if the budget is exhausted (trailing trim).
                        pending_space = started;
                    } else if is_stripped(c) {
                        // Removed outright; does not break a word.
                    } else {
                        if chars == DISPLAY_TEXT_MAX_CHARS {
                            break; // truncation point reached
                        }
                        if pending_space {
                            out.push(' ');
                            chars += 1;
                            pending_space = false;
                            if chars == DISPLAY_TEXT_MAX_CHARS {
                                break;
                            }
                        }
                        out.push(c);
                        chars += 1;
                        started = true;
                    }
                }
                EscapeState::Escape => match c {
                    '[' => state = EscapeState::Csi,
                    ']' => state = EscapeState::Osc,
                    '\u{1b}' => {} // ESC ESC: stay, next char decides
                    '\u{20}'..='\u{2f}' => state = EscapeState::EscapeIntermediate,
                    _ => state = EscapeState::Ground, // two-character escape consumed
                },
                EscapeState::EscapeIntermediate => match c {
                    '\u{20}'..='\u{2f}' => {} // more intermediate bytes
                    '\u{30}'..='\u{7e}' => state = EscapeState::Ground, // final byte
                    '\u{1b}' => state = EscapeState::Escape,
                    _ => state = EscapeState::Ground, // malformed; drop and resume
                },
                EscapeState::Csi => match c {
                    '\u{20}'..='\u{3f}' => {} // parameter + intermediate bytes
                    '\u{40}'..='\u{7e}' => state = EscapeState::Ground, // final byte
                    '\u{1b}' => state = EscapeState::Escape,
                    _ => {} // non-ASCII inside CSI: dropped, sequence continues
                },
                EscapeState::Osc => match c {
                    '\u{07}' => state = EscapeState::Ground,    // BEL terminator
                    '\u{1b}' => state = EscapeState::OscEscape, // ST begins
                    _ => {}                                     // payload dropped
                },
                EscapeState::OscEscape => match c {
                    '\\' => state = EscapeState::Ground, // ST terminator
                    '\u{1b}' => state = EscapeState::Escape,
                    _ => state = EscapeState::Ground, // malformed; drop and resume
                },
            }
        }

        // Truncation or end of input can leave a single trailing space (a
        // space pushed for a word that then did not fit); collapse rules
        // guarantee there is never more than one.
        while out.ends_with(' ') {
            out.pop();
        }
        if out.is_empty() {
            return Err(ValidationError::DisplayTextEmpty);
        }
        Ok(Self { inner: out })
    }
}

impl FromStr for DisplayText {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DisplayText::try_from(s)
    }
}

impl DisplayText {
    /// The sanitized text.
    pub fn as_str(&self) -> &str {
        &self.inner
    }
}

impl fmt::Display for DisplayText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.inner)
    }
}

/// State of the ANSI escape-sequence recognizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EscapeState {
    /// Normal text.
    Ground,
    /// Saw `ESC`.
    Escape,
    /// Saw `ESC` followed by an intermediate byte (e.g. `ESC (`).
    EscapeIntermediate,
    /// Inside a CSI sequence (`ESC [`).
    Csi,
    /// Inside an OSC string (`ESC ]`).
    Osc,
    /// Saw `ESC` inside an OSC string (possible ST terminator).
    OscEscape,
}

/// `true` for characters allowed in a [`Hostname`] (plan §5.2).
fn is_hostname_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
}

/// `true` for characters removed outright during [`DisplayText`]
/// sanitization: non-whitespace C0 and C1 controls, DEL, bidi controls
/// (`U+202A–U+202E`) and zero-width characters (`U+200B–U+200F`, `U+FEFF`).
///
/// Whitespace controls (tab, newline, NEL, …) are *not* listed here: they
/// take the whitespace branch and collapse to a single space, so word
/// separation survives sanitization.
fn is_stripped(c: char) -> bool {
    matches!(c,
        '\u{0000}'..='\u{001f}'   // C0 controls (whitespace members handled earlier)
        | '\u{007f}'..='\u{009f}' // DEL and C1 controls
        | '\u{200b}'..='\u{200f}' // zero-width chars, LRM, RLM
        | '\u{202a}'..='\u{202e}' // bidi controls
        | '\u{feff}') // zero-width no-break space
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::testing::Lcg;

    // ---- Hostname: acceptance ----------------------------------------------

    #[test]
    fn hostname_accepts_the_allowed_charset() {
        for text in [
            "a",
            "my-host.example.com",
            "MY-HOST.EXAMPLE.COM",
            "router_1.lan",
            "x0-y9.z8_w7",
            "192.168.1.1", // dotted quads are syntactically fine here
        ] {
            let host = Hostname::try_from(text);
            assert!(host.is_ok(), "expected {text:?} to be accepted");
            assert_eq!(host.expect("checked above").as_str(), text);
        }
    }

    #[test]
    fn hostname_accepts_exactly_253_characters() {
        let max = "a".repeat(HOSTNAME_MAX_CHARS);
        assert!(Hostname::try_from(max.as_str()).is_ok());
        let over = "a".repeat(HOSTNAME_MAX_CHARS + 1);
        assert_eq!(
            Hostname::try_from(over.as_str()).unwrap_err(),
            ValidationError::HostnameTooLong { found: 254 }
        );
    }

    // ---- Hostname: rejection ------------------------------------------------

    #[test]
    fn hostname_rejects_empty_and_reports_positions() {
        assert_eq!(
            Hostname::try_from("").unwrap_err(),
            ValidationError::HostnameEmpty
        );
        let cases: [(&str, char, usize); 6] = [
            ("bad host", ' ', 3),
            ("h\u{e9}llo", '\u{e9}', 1),
            ("host!", '!', 4),
            ("a\u{202e}evil", '\u{202e}', 1),
            ("tab\there", '\t', 3),
            ("\u{ff41}bc", '\u{ff41}', 0),
        ];
        for (input, found, position) in cases {
            assert_eq!(
                Hostname::try_from(input).unwrap_err(),
                ValidationError::HostnameCharacter { found, position },
                "input: {input:?}"
            );
        }
    }

    #[test]
    fn hostname_length_rule_is_checked_before_charset() {
        // 300 characters, one of them invalid: the length error wins (the
        // documented precedence).
        let text = format!("{}!{}", "a".repeat(100), "b".repeat(199));
        assert_eq!(
            Hostname::try_from(text.as_str()).unwrap_err(),
            ValidationError::HostnameTooLong { found: 300 }
        );
    }

    // ---- Hostname: property-style tests --------------------------------------

    /// Property: every string over the allowed alphabet validates and
    /// round-trips byte-exactly.
    #[test]
    fn property_hostname_round_trip_valid_alphabet() {
        const ALPHABET: [char; 26] = [
            'a', 'B', 'z', '0', '9', '.', '_', '-', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
            'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
        ];
        let mut rng = Lcg::seeded(0x1057_0001);
        for _ in 0..200 {
            let len = 1 + rng.next_below(HOSTNAME_MAX_CHARS as u64) as usize;
            let mut text = String::new();
            for _ in 0..len {
                let index = rng.next_below(ALPHABET.len() as u64) as usize;
                text.push(ALPHABET[index]);
            }
            let host = Hostname::try_from(text.as_str()).expect("valid alphabet must pass");
            assert_eq!(host.as_str(), text);
            assert_eq!(host.to_string(), text);
        }
    }

    /// Property: corrupting one character of a valid hostname with a
    /// disallowed character is always rejected at that exact position.
    #[test]
    fn property_hostname_rejects_single_corruption() {
        const BAD: [char; 8] = [
            ' ', '!', '\t', '\u{e9}', '\u{4e2d}', '\u{202e}', '\u{feff}', ':',
        ];
        let mut rng = Lcg::seeded(0x1057_0002);
        for _ in 0..200 {
            let len = 1 + rng.next_below(64) as usize;
            let base = "host".repeat(len / 4 + 1);
            let base = &base[..len.min(base.len())];
            let position = rng.next_below(base.chars().count() as u64) as usize;
            let bad = BAD[rng.next_below(BAD.len() as u64) as usize];
            let mut corrupted: String = base.chars().take(position).collect();
            corrupted.push(bad);
            corrupted.extend(base.chars().skip(position + 1));
            assert_eq!(
                Hostname::try_from(corrupted.as_str()).unwrap_err(),
                ValidationError::HostnameCharacter {
                    found: bad,
                    position
                },
                "input: {corrupted:?}"
            );
        }
    }

    // ---- DisplayText: sanitization -------------------------------------------

    #[test]
    fn display_text_keeps_plain_text() {
        let cases: [(&str, &str); 5] = [
            ("Cisco Systems, Inc", "Cisco Systems, Inc"),
            ("Raspberry Pi Foundation", "Raspberry Pi Foundation"),
            ("a", "a"),
            ("Ünïcödé vëndör", "Ünïcödé vëndör"),
            ("64", "64"),
        ];
        for (input, expected) in cases {
            let text = DisplayText::try_from(input).expect("plain text is safe");
            assert_eq!(text.as_str(), expected, "input: {input:?}");
        }
    }

    #[test]
    fn display_text_collapses_and_trims_whitespace() {
        let cases: [(&str, &str); 7] = [
            ("  Hello   World  ", "Hello World"),
            ("a\tb", "a b"),           // tab is whitespace: collapses, not removed
            ("a\r\nb", "a b"),         // CRLF collapses to one space
            ("a\u{00a0}b", "a b"),     // non-breaking space
            ("a\u{2003}b", "a b"),     // em space
            ("   leading", "leading"), // leading dropped, not collapsed-to-space
            ("trailing   ", "trailing"),
        ];
        for (input, expected) in cases {
            let text = DisplayText::try_from(input).expect("whitespace is sanitized, not fatal");
            assert_eq!(text.as_str(), expected, "input: {input:?}");
        }
    }

    #[test]
    fn display_text_strips_ansi_escape_sequences() {
        let cases: [(&str, &str); 10] = [
            ("\u{1b}[31mred\u{1b}[0m", "red"),           // SGR color
            ("\u{1b}[1;31mX\u{1b}[2J", "X"),             // params + clear screen
            ("\u{1b}]0;window title\u{07}rest", "rest"), // OSC, BEL terminated
            ("\u{1b}]0;title\u{1b}\\rest", "rest"),      // OSC, ST terminated
            ("\u{1b}]0;unterminated", ""),               // unterminated OSC swallows all
            ("\u{1b}(Bcharset", "charset"),              // ESC ( B intermediate form
            ("\u{1b}c", ""),                             // two-character escape
            ("\u{1b}", ""),                              // bare ESC
            ("before\u{1b}[Kafter", "beforeafter"),      // CSI erase-line mid-text
            ("\u{1b}[38;5;9mX\u{1b}[m", "X"),            // 256-color SGR
        ];
        for (input, expected) in cases {
            let sanitized = DisplayText::try_from(input);
            if expected.is_empty() {
                assert_eq!(
                    sanitized.unwrap_err(),
                    ValidationError::DisplayTextEmpty,
                    "input: {input:?}"
                );
            } else {
                assert_eq!(
                    sanitized.expect("must sanitize").as_str(),
                    expected,
                    "input: {input:?}"
                );
            }
        }
    }

    #[test]
    fn display_text_strips_control_bidi_and_zero_width_characters() {
        let cases: [(&str, &str); 10] = [
            ("a\u{0}b", "ab"),    // NUL
            ("a\u{7}b", "ab"),    // BEL outside OSC
            ("a\u{7f}b", "ab"),   // DEL
            ("a\u{8b}b", "ab"),   // C1 CSI (8-bit)
            ("a\u{9c}b", "ab"),   // C1 ST
            ("a\u{202a}b", "ab"), // bidi LRE
            ("a\u{202b}b", "ab"), // bidi RLE
            ("a\u{202e}b", "ab"), // bidi RLO (Trojan Source)
            ("a\u{200b}b", "ab"), // zero-width space
            ("a\u{feff}b", "ab"), // zero-width no-break space
        ];
        for (input, expected) in cases {
            let text = DisplayText::try_from(input).expect("must sanitize");
            assert_eq!(text.as_str(), expected, "input: {input:?}");
        }
    }

    #[test]
    fn display_text_truncates_to_64_chars() {
        let long = "a".repeat(1000);
        let text = DisplayText::try_from(long.as_str()).expect("long input truncates");
        assert_eq!(text.as_str().chars().count(), DISPLAY_TEXT_MAX_CHARS);
        assert_eq!(text.as_str(), "a".repeat(64));

        // Exactly at the limit and one over.
        let exact = "b".repeat(64);
        assert_eq!(
            DisplayText::try_from(exact.as_str())
                .expect("exactly 64")
                .as_str(),
            exact
        );
        let over = "c".repeat(65);
        assert_eq!(
            DisplayText::try_from(over.as_str())
                .expect("65 truncates")
                .as_str(),
            "c".repeat(64)
        );

        // Truncation counts characters, not bytes.
        let utf8 = "é".repeat(100); // 2 bytes per char
        let text = DisplayText::try_from(utf8.as_str()).expect("sanitizes");
        assert_eq!(text.as_str().chars().count(), DISPLAY_TEXT_MAX_CHARS);
        assert_eq!(text.as_str().len(), 128);
    }

    #[test]
    fn display_text_rejects_empty_and_blank_input() {
        for input in [
            "",
            "   ",
            "\t\n",
            "\u{1b}[31m",
            "\u{200b}\u{feff}",
            "\u{1b}]0;x",
        ] {
            assert_eq!(
                DisplayText::try_from(input).unwrap_err(),
                ValidationError::DisplayTextEmpty,
                "input: {input:?}"
            );
        }
    }

    // ---- DisplayText: property-style tests ------------------------------------

    /// Property: sanitizing arbitrary hostile strings never panics, and the
    /// result (when accepted) contains no control, bidi or zero-width
    /// characters, no doubled spaces, and at most 64 characters.
    #[test]
    fn property_display_text_never_panics_and_output_is_safe() {
        const ALPHABET: [char; 22] = [
            'a', 'Z', '3', '.', ' ', '\t', '\n', '\u{0}', '\u{1b}', '[', 'm', ']', '\u{7}',
            '\u{7f}', '\u{9b}', '\u{202e}', '\u{200b}', '\u{feff}', '\u{e9}', '-', ',', '_',
        ];
        let mut rng = Lcg::seeded(0x0D15_0003);
        let mut accepted = 0usize;
        for _ in 0..1000 {
            let len = rng.next_below(120) as usize;
            let mut text = String::new();
            for _ in 0..len {
                let index = rng.next_below(ALPHABET.len() as u64) as usize;
                text.push(ALPHABET[index]);
            }
            // Total sanitizer: Ok or Err, never a panic (SR-02). A
            // rejection can only mean "empty after sanitization" — inputs
            // built purely from control/escape characters sanitize away.
            let sanitized = DisplayText::try_from(text.as_str());
            let Ok(sanitized) = sanitized else {
                continue;
            };
            accepted += 1;
            let out = sanitized.as_str();
            assert!(
                out.chars().count() <= DISPLAY_TEXT_MAX_CHARS,
                "too long: {out:?}"
            );
            for c in out.chars() {
                assert!(!is_stripped(c), "stripped char leaked: {c:?} in {out:?}");
                assert!(
                    !c.is_whitespace() || c == ' ',
                    "raw whitespace leaked: {c:?}"
                );
            }
            assert!(!out.contains("  "), "uncollapsed space run in {out:?}");
            assert!(
                !out.starts_with(' ') && !out.ends_with(' '),
                "untrimmed edge in {out:?}"
            );
        }
        // Most generated strings contain letters and survive; the guard
        // keeps the invariant checks from becoming silently vacuous.
        assert!(accepted > 0, "no input survived sanitization");
    }

    /// Property: whitespace-only corruption of a plain string never yields
    /// leading or trailing spaces.
    #[test]
    fn property_display_text_whitespace_never_leaks_edges() {
        let mut rng = Lcg::seeded(0x0D15_0004);
        for _ in 0..300 {
            let word_len = 1 + rng.next_below(40) as usize;
            let mut text = String::new();
            let pad = rng.next_below(10) as usize;
            for c in " \t\n".chars().cycle().take(pad) {
                text.push(c);
            }
            text.push_str(&"w".repeat(word_len));
            text.push_str(&" \t".repeat(rng.next_below(10) as usize));
            let sanitized = DisplayText::try_from(text.as_str()).expect("non-blank input");
            assert_eq!(sanitized.as_str(), "w".repeat(word_len));
        }
    }
}
