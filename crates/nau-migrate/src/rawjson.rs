//! Verbatim recovery of JSON scalars from the source text.
//!
//! # Why a scanner exists at all
//!
//! `serde_json`'s default build parses a JSON number into an `f64` as soon as it
//! has a fraction or an exponent, and the `arbitrary_precision` feature that would
//! preserve the original text is not enabled anywhere in this workspace. Round-
//! tripping through `f64` and printing the shortest representation back would
//! *usually* reproduce the same decimal text — but "usually" is exactly the kind of
//! reasoning that produced the tolerance-based ledger this project is replacing.
//!
//! So the money fields are read from the **bytes on disk**: [`top_level_scalar`]
//! locates a top-level key and returns its literal text untouched (`1e-3` comes
//! back as `1e-3`, not as `0.001`), and [`root_slices`] splits a file that holds a
//! JSON array into the verbatim text of each element, so per-record extraction
//! still sees the original bytes.
//!
//! Structural parsing for every *non-money* field stays with `serde_json`; this
//! module only has to be right about where a value starts and where it ends.
//!
//! [`crate::amount`] then converts that text exactly, or refuses.

use std::fmt;

/// Maximum nesting accepted while skipping a value.
///
/// The same bound as the canonical-payload layer, so a document that this crate
/// can scan is also a document that layer can canonicalize.
pub const MAX_DEPTH: u32 = 64;

/// Where and how scanning failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanError {
    /// Byte offset in the scanned text.
    pub offset: usize,
    /// What went wrong.
    pub detail: &'static str,
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "at byte {}: {}", self.offset, self.detail)
    }
}

impl std::error::Error for ScanError {}

/// A scalar recovered verbatim from the source text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawScalar {
    /// A JSON number, as the exact literal text that appeared on disk.
    Number(String),
    /// A JSON string, with escape sequences decoded.
    Str(String),
}

/// Recover the literal text of a **top-level** key's value.
///
/// Returns:
///
/// * `Ok(Some(RawScalar::Number(text)))` — the value is a JSON number and `text`
///   is the literal exactly as written (`1e-3`, `0.10`, `12.5`);
/// * `Ok(Some(RawScalar::Str(text)))` — the value is a JSON string, decoded;
/// * `Ok(None)` — the key is absent, **or** its value is not a string or number
///   (an object, array, boolean or null). Callers that need to tell those apart
///   ask the parsed `serde_json::Value` for the field's kind, which is what
///   [`crate::plan`] does;
/// * `Err(ScanError)` — the text is not JSON at all.
///
/// Only the top level is searched; a nested `"amount"` inside some sub-object does
/// not match.
///
/// The **whole document is validated** before anything is reported, so a literal is
/// never returned out of a file that is not valid JSON (`{"amount":01}` is an
/// error, not `0`).
///
/// # Errors
///
/// [`ScanError`] when `text` is not a syntactically valid JSON value.
pub fn top_level_scalar(
    text: &str,
    key: &str,
) -> std::result::Result<Option<RawScalar>, ScanError> {
    let mut scanner = Scanner::new(text);
    scanner.skip_ws();
    if scanner.peek() != Some(b'{') {
        return Err(scanner.error("the root value is not an object"));
    }
    scanner.pos += 1;
    scanner.skip_ws();
    if scanner.peek() == Some(b'}') {
        scanner.pos += 1;
        return finish(&mut scanner, None);
    }
    let mut found: Option<RawScalar> = None;
    loop {
        scanner.skip_ws();
        let found_key = scanner.parse_string()?;
        scanner.expect(b':')?;
        scanner.skip_ws();
        if found_key == key {
            found = match scanner.peek() {
                Some(b'"') => Some(RawScalar::Str(scanner.parse_string()?)),
                Some(b'[' | b'{' | b't' | b'f' | b'n') => {
                    scanner.skip_value(0)?;
                    None
                }
                Some(_) => Some(RawScalar::Number(scanner.scan_number()?.to_string())),
                None => return Err(scanner.error("unexpected end of input after `:`")),
            };
        } else {
            scanner.skip_value(0)?;
        }
        scanner.skip_ws();
        match scanner.pos_bump() {
            Some(b',') => continue,
            Some(b'}') => break,
            _ => return Err(scanner.error("expected `,` or `}`")),
        }
    }
    finish(&mut scanner, found)
}

/// Require only whitespace after the root object, then return what was found.
fn finish(
    scanner: &mut Scanner<'_>,
    found: Option<RawScalar>,
) -> std::result::Result<Option<RawScalar>, ScanError> {
    scanner.skip_ws();
    if scanner.pos != scanner.bytes.len() {
        return Err(scanner.error("trailing data after the root object"));
    }
    Ok(found)
}

/// Split a document that is either one object or a root array of values.
///
/// Returns the verbatim text of each value: the whole document for an object, one
/// slice per element for an array. An array nested inside an object is **not**
/// flattened — only a root array is a record list.
///
/// # Errors
///
/// [`ScanError`] when the text is not one JSON value, or when anything but
/// whitespace follows it.
pub fn root_slices(text: &str) -> std::result::Result<Vec<&str>, ScanError> {
    let mut scanner = Scanner::new(text);
    scanner.skip_ws();
    match scanner.peek() {
        Some(b'{') => {
            let start = scanner.pos;
            scanner.skip_value(0)?;
            let end = scanner.pos;
            scanner.skip_ws();
            if scanner.pos != scanner.bytes.len() {
                return Err(scanner.error("trailing data after the root object"));
            }
            Ok(vec![&text[start..end]])
        }
        Some(b'[') => {
            scanner.pos += 1;
            let mut slices = Vec::new();
            scanner.skip_ws();
            if scanner.peek() == Some(b']') {
                scanner.pos += 1;
            } else {
                loop {
                    scanner.skip_ws();
                    let start = scanner.pos;
                    scanner.skip_value(0)?;
                    slices.push(&text[start..scanner.pos]);
                    scanner.skip_ws();
                    match scanner.pos_bump() {
                        Some(b',') => continue,
                        Some(b']') => break,
                        _ => return Err(scanner.error("expected `,` or `]`")),
                    }
                }
            }
            scanner.skip_ws();
            if scanner.pos != scanner.bytes.len() {
                return Err(scanner.error("trailing data after the root array"));
            }
            Ok(slices)
        }
        Some(_) => Err(scanner.error("the root value is neither an object nor an array")),
        None => Err(scanner.error("the input is empty")),
    }
}

/// A byte-level JSON scanner. It never allocates except when decoding a string.
struct Scanner<'a> {
    bytes: &'a [u8],
    source: &'a str,
    pos: usize,
}

impl<'a> Scanner<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            bytes: source.as_bytes(),
            source,
            pos: 0,
        }
    }

    fn error(&self, detail: &'static str) -> ScanError {
        ScanError {
            offset: self.pos,
            detail,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn byte_at(&self, index: usize) -> Option<u8> {
        self.bytes.get(index).copied()
    }

    fn pos_bump(&mut self) -> Option<u8> {
        let byte = self.peek();
        if byte.is_some() {
            self.pos += 1;
        }
        byte
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, expected: u8) -> std::result::Result<(), ScanError> {
        self.skip_ws();
        if self.peek() == Some(expected) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.error("expected a `:`"))
        }
    }

    /// Decode a JSON string, including `\uXXXX` escapes and surrogate pairs.
    fn parse_string(&mut self) -> std::result::Result<String, ScanError> {
        if self.pos_bump() != Some(b'"') {
            return Err(self.error("expected a string"));
        }
        let mut out = String::new();
        loop {
            let byte = self
                .pos_bump()
                .ok_or_else(|| self.error("unterminated string"))?;
            match byte {
                b'"' => return Ok(out),
                b'\\' => {
                    let escape = self
                        .pos_bump()
                        .ok_or_else(|| self.error("unterminated escape sequence"))?;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let high = self.hex4()?;
                            if (0xD800..=0xDBFF).contains(&high) {
                                // A high surrogate must be followed by a low one.
                                if self.peek() == Some(b'\\')
                                    && self.byte_at(self.pos + 1) == Some(b'u')
                                {
                                    self.pos += 2;
                                    let low = self.hex4()?;
                                    if (0xDC00..=0xDFFF).contains(&low) {
                                        let combined =
                                            0x1_0000 + ((high - 0xD800) << 10) + (low - 0xDC00);
                                        out.push(char::from_u32(combined).unwrap_or('\u{fffd}'));
                                    } else {
                                        // Not a low surrogate: the text is malformed
                                        // JSON, but a scanner that only has to find
                                        // boundaries reports it as a replacement
                                        // character rather than failing the record.
                                        out.push('\u{fffd}');
                                        out.push(char::from_u32(low).unwrap_or('\u{fffd}'));
                                    }
                                } else {
                                    out.push('\u{fffd}');
                                }
                            } else if (0xDC00..=0xDFFF).contains(&high) {
                                out.push('\u{fffd}');
                            } else {
                                out.push(char::from_u32(high).unwrap_or('\u{fffd}'));
                            }
                        }
                        _ => return Err(self.error("unknown string escape")),
                    }
                }
                _ => {
                    // A raw UTF-8 sequence: copy the whole character.
                    let width = utf8_width(byte).ok_or_else(|| self.error("invalid UTF-8"))?;
                    let start = self.pos - 1;
                    let end = start + width;
                    let text = self
                        .bytes
                        .get(start..end)
                        .and_then(|slice| std::str::from_utf8(slice).ok())
                        .ok_or_else(|| self.error("invalid UTF-8 in string"))?;
                    out.push_str(text);
                    self.pos = end;
                }
            }
        }
    }

    fn hex4(&mut self) -> std::result::Result<u32, ScanError> {
        let end = self.pos + 4;
        let digits = self
            .bytes
            .get(self.pos..end)
            .and_then(|slice| std::str::from_utf8(slice).ok())
            .ok_or_else(|| self.error("truncated `\\u` escape"))?;
        let value =
            u32::from_str_radix(digits, 16).map_err(|_| self.error("invalid `\\u` escape"))?;
        self.pos = end;
        Ok(value)
    }

    /// Skip one value, validating the JSON grammar as it goes.
    fn skip_value(&mut self, depth: u32) -> std::result::Result<(), ScanError> {
        if depth > MAX_DEPTH {
            return Err(self.error("nesting is deeper than the supported maximum"));
        }
        self.skip_ws();
        match self.peek() {
            Some(b'"') => {
                self.parse_string()?;
                Ok(())
            }
            Some(b'{') => {
                self.pos += 1;
                self.skip_ws();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(());
                }
                loop {
                    self.skip_ws();
                    self.parse_string()?;
                    self.expect(b':')?;
                    self.skip_value(depth + 1)?;
                    self.skip_ws();
                    match self.pos_bump() {
                        Some(b',') => continue,
                        Some(b'}') => return Ok(()),
                        _ => return Err(self.error("expected `,` or `}`")),
                    }
                }
            }
            Some(b'[') => {
                self.pos += 1;
                self.skip_ws();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return Ok(());
                }
                loop {
                    self.skip_value(depth + 1)?;
                    self.skip_ws();
                    match self.pos_bump() {
                        Some(b',') => continue,
                        Some(b']') => return Ok(()),
                        _ => return Err(self.error("expected `,` or `]`")),
                    }
                }
            }
            Some(b't') => self.literal("true"),
            Some(b'f') => self.literal("false"),
            Some(b'n') => self.literal("null"),
            Some(_) => {
                self.scan_number()?;
                Ok(())
            }
            None => Err(self.error("unexpected end of input")),
        }
    }

    fn literal(&mut self, word: &str) -> std::result::Result<(), ScanError> {
        let end = self.pos + word.len();
        if self.bytes.get(self.pos..end) == Some(word.as_bytes()) {
            self.pos = end;
            Ok(())
        } else {
            Err(self.error("expected a JSON literal"))
        }
    }

    /// Validate and return a JSON number literal (RFC 8259 grammar).
    fn scan_number(&mut self) -> std::result::Result<&'a str, ScanError> {
        let source: &'a str = self.source;
        let start = self.pos;
        let mut cursor = start;
        let at = |index: usize| self.byte_at(index);

        if at(cursor) == Some(b'-') {
            cursor += 1;
        }
        match at(cursor) {
            Some(b'0') => cursor += 1,
            Some(digit) if digit.is_ascii_digit() => {
                cursor += 1;
                while at(cursor).is_some_and(|b| b.is_ascii_digit()) {
                    cursor += 1;
                }
            }
            _ => {
                return Err(ScanError {
                    offset: cursor,
                    detail: "expected a number",
                })
            }
        }
        if at(cursor) == Some(b'.') {
            cursor += 1;
            let first = cursor;
            while at(cursor).is_some_and(|b| b.is_ascii_digit()) {
                cursor += 1;
            }
            if cursor == first {
                return Err(ScanError {
                    offset: cursor,
                    detail: "expected a digit after the decimal point",
                });
            }
        }
        if matches!(at(cursor), Some(b'e' | b'E')) {
            cursor += 1;
            if matches!(at(cursor), Some(b'+' | b'-')) {
                cursor += 1;
            }
            let first = cursor;
            while at(cursor).is_some_and(|b| b.is_ascii_digit()) {
                cursor += 1;
            }
            if cursor == first {
                return Err(ScanError {
                    offset: cursor,
                    detail: "expected a digit in the exponent",
                });
            }
        }

        let literal = source.get(start..cursor).ok_or(ScanError {
            offset: start,
            detail: "the number is not valid UTF-8",
        })?;
        self.pos = cursor;
        Ok(literal)
    }
}

/// Width of a UTF-8 sequence, given its first byte.
fn utf8_width(first: u8) -> Option<usize> {
    match first {
        0x00..=0x7F => Some(1),
        0xC2..=0xDF => Some(2),
        0xE0..=0xEF => Some(3),
        0xF0..=0xF4 => Some(4),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn number(text: &str, key: &str) -> String {
        match top_level_scalar(text, key).expect("scans") {
            Some(RawScalar::Number(value)) => value,
            other => panic!("expected a number for `{key}`, got {other:?}"),
        }
    }

    #[test]
    fn number_literals_come_back_byte_for_byte() {
        // This is the whole point of the module: `1e-3` must NOT be normalised to
        // `0.001` by a float round-trip, and `0.10` must keep its trailing zero.
        assert_eq!(number(r#"{"amount":1e-3}"#, "amount"), "1e-3");
        assert_eq!(number(r#"{"amount":0.10}"#, "amount"), "0.10");
        assert_eq!(number(r#"{"amount":0.1}"#, "amount"), "0.1");
        assert_eq!(number(r#"{"amount":12.5}"#, "amount"), "12.5");
        assert_eq!(number(r#"{"amount":-1.5E+2}"#, "amount"), "-1.5E+2");
        assert_eq!(number(r#"{"amount":100}"#, "amount"), "100");
        assert_eq!(
            number(r#"{"amount":0.0000001}"#, "amount"),
            "0.0000001",
            "the literal that must be refused, not rounded, survives scanning"
        );
    }

    #[test]
    fn string_values_are_decoded_and_escapes_are_understood() {
        assert_eq!(
            top_level_scalar(r#"{"amount":"12.5"}"#, "amount").expect("scans"),
            Some(RawScalar::Str("12.5".to_string()))
        );
        assert_eq!(
            top_level_scalar(r#"{"amount":"1\u0032.5"}"#, "amount").expect("scans"),
            Some(RawScalar::Str("12.5".to_string()))
        );
        assert_eq!(
            top_level_scalar(r#"{"a\"b":1,"amount":"x\ny"}"#, "amount").expect("scans"),
            Some(RawScalar::Str("x\ny".to_string()))
        );
        assert_eq!(
            top_level_scalar(r#"{"amount":"\ud83d\ude00"}"#, "amount").expect("scans"),
            Some(RawScalar::Str("😀".to_string()))
        );
        assert_eq!(
            top_level_scalar(r#"{"amount":"智能体宇宙"}"#, "amount").expect("scans"),
            Some(RawScalar::Str("智能体宇宙".to_string()))
        );
    }

    #[test]
    fn only_the_top_level_matters() {
        let text = r#"{"nested":{"amount":1,"deep":[{"amount":2}]},"amount":3}"#;
        assert_eq!(number(text, "amount"), "3");
        assert_eq!(top_level_scalar(text, "missing").expect("scans"), None);
        // A key whose value is not a scalar reports `None`; the caller asks the
        // parsed value for the kind.
        assert_eq!(
            top_level_scalar(r#"{"amount":true}"#, "amount").expect("scans"),
            None
        );
        assert_eq!(
            top_level_scalar(r#"{"amount":{"inner":1}}"#, "amount").expect("scans"),
            None
        );
        assert_eq!(
            top_level_scalar(r#"{"amount":null}"#, "amount").expect("scans"),
            None
        );
        assert_eq!(top_level_scalar("{}", "amount").expect("scans"), None);
    }

    #[test]
    fn root_arrays_are_split_into_verbatim_elements() {
        let text = r#"[
            {"amount": 1e-3, "name": "a"},
            {"amount": 0.10},
            {"nested": {"amount": 5}}
        ]"#;
        let slices = root_slices(text).expect("splits");
        assert_eq!(slices.len(), 3);
        assert_eq!(number(slices[0], "amount"), "1e-3");
        assert_eq!(number(slices[1], "amount"), "0.10");
        assert_eq!(slices[2], r#"{"nested": {"amount": 5}}"#);
        assert_eq!(
            top_level_scalar(slices[2], "amount").expect("scans"),
            None,
            "a nested `amount` is not a top-level `amount`"
        );
        assert_eq!(root_slices("[]").expect("splits").len(), 0);
        assert_eq!(root_slices("[1]").expect("splits").len(), 1);
    }

    #[test]
    fn a_root_object_is_returned_as_one_slice_minus_surrounding_whitespace() {
        let slices = root_slices("  \n {\"a\":1}  \n").expect("splits");
        assert_eq!(slices.len(), 1);
        assert_eq!(slices[0], "{\"a\":1}");
    }

    #[test]
    fn malformed_input_is_reported_with_a_position() {
        for text in [
            "",
            "   ",
            "1",
            "\"x\"",
            "{",
            "{\"a\"}",
            "{\"a\":}",
            "{\"a\":1,}",
            "{\"a\":1} trailing",
            "[1,",
            "[1]]",
            "{\"a\":01}",
            "{\"a\":1.}",
            "{\"a\":.5}",
            "{\"a\":1e}",
            "{\"a\":+1}",
            "{\"a\":'x'}",
            "{\"a\":\"unterminated}",
        ] {
            let error = top_level_scalar(text, "a").expect_err(&format!("`{text}` must fail"));
            assert!(error.offset <= text.len());
            assert!(!error.detail.is_empty());
        }
    }

    #[test]
    fn deeply_nested_hostile_input_is_refused_rather_than_overflowing_the_stack() {
        let mut text = String::from("{\"a\":");
        for _ in 0..(MAX_DEPTH + 5) {
            text.push('[');
        }
        for _ in 0..(MAX_DEPTH + 5) {
            text.push(']');
        }
        text.push('}');
        let error = top_level_scalar(&text, "b").expect_err("too deep");
        // The scan aborts inside `skip_value`, so the offset is at the failure.
        assert!(error.detail.contains("deeper"), "{error}");
    }

    #[test]
    fn utf8_width_covers_every_valid_leading_byte_and_rejects_the_rest() {
        assert_eq!(utf8_width(b'a'), Some(1));
        assert_eq!(utf8_width(0xC3), Some(2));
        assert_eq!(utf8_width(0xE4), Some(3));
        assert_eq!(utf8_width(0xF0), Some(4));
        assert_eq!(utf8_width(0x80), None, "continuation byte cannot lead");
        assert_eq!(utf8_width(0xF5), None, "beyond U+10FFFF");
    }
}
