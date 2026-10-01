//! Exact conversion of upstream decimal literals into integer minor units.
//!
//! # Why this module is the heart of the migration
//!
//! Upstream `agent-universe` v2.5.6 recorded every amount as an `f64`
//! (`gsn-core/src/marketplace/settlement.rs:28,37-40,47,52-59`) and checked
//! conservation with a tolerance:
//!
//! ```text
//! let conserved = (self.balance_sum - expected_sum).abs() < 0.001   // :173
//! ```
//!
//! Migrating those numbers by parsing them as `f64` and scaling by 1e6 would
//! import the defect this project exists to remove. `0.1` and `0.2` are already
//! inexact as binary fractions, so the error would be baked into the new ledger on
//! day one; and `(x * 1e6) as i64` truncates rather than refuses.
//!
//! # The rule: exact, or refuse
//!
//! * The **decimal text** is parsed digit by digit. No floating-point value is
//!   ever constructed: this crate contains no float arithmetic at all, which is
//!   checked with `cargo clippy -p nau-migrate --all-targets -- -W
//!   clippy::float_arithmetic` (see the crate documentation for exactly what that
//!   command reports).
//! * A literal that needs more than six decimal places (`0.0000001`, `1e-7`) is
//!   refused with a typed error naming the file and the field, never rounded.
//! * Exponent notation (`1e-3`, `2.5e3`), a leading `+`, a leading `.` and a
//!   trailing `.` are understood, because upstream wrote JSON numbers and JSON
//!   admits all of them.
//! * Trailing zeros beyond the sixth decimal place are *accepted*, because
//!   `"1.0000000"` is exactly `1`; refusing it would reject data that migrates
//!   perfectly.
//! * A value outside the `i64` minor-unit range is a typed error, not a wrapped
//!   number.
//!
//! The final step delegates to [`Money::parse`], so the workspace keeps exactly
//! one implementation of the scale arithmetic. `Money::parse` alone is not enough
//! for this job: it deliberately refuses exponent notation, and an upstream ledger
//! legitimately contains `1e-3`.

use nau_core::Money;

use crate::error::{MigrateError, Result};

/// Decimal places this crate keeps, pinned to `nau-core`'s scale below.
const KEEP_DECIMALS: usize = 6;

/// Largest number of *integer* digits that can still reach `Money::parse`.
///
/// `i64::MAX` has 19 decimal digits, and a 19-digit major amount always overflows
/// when scaled to minor units (10^18 times 10^6 exceeds 2^63), so refusing longer
/// integers up front is both correct and a bound on the padding work.
const MAX_INTEGER_DIGITS: u64 = 19;

const _: () = assert!(
    nau_core::domain::DECIMALS == KEEP_DECIMALS as u32,
    "nau-core changed its minor-unit scale: nau-migrate's exactness rules must be revisited"
);

/// Which way an exact conversion failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmountDefect {
    /// The literal is not a decimal number.
    NotANumber,
    /// The value needs more than six decimal places.
    NotExact,
    /// The value is outside the range of `i64` minor units.
    OutOfRange,
}

impl AmountDefect {
    /// The defect carried by `err`, if it is an amount defect.
    pub fn of(err: &MigrateError) -> Option<AmountDefect> {
        match err {
            MigrateError::AmountNotANumber { .. } => Some(AmountDefect::NotANumber),
            MigrateError::AmountNotExact { .. } => Some(AmountDefect::NotExact),
            MigrateError::AmountOutOfRange { .. } => Some(AmountDefect::OutOfRange),
            _ => None,
        }
    }
}

/// Convert an upstream decimal literal to [`Money`], exactly or not at all.
///
/// `path` and `field` are carried into every error variant so that a rejection can
/// be reported as "`ledger.jsonl`: field `amount` = `0.0000001` needs more than 6
/// decimal places ..." rather than as a bare parse failure.
///
/// # Errors
///
/// * [`MigrateError::AmountNotANumber`] - the literal is not a decimal number.
/// * [`MigrateError::AmountNotExact`] - more than six significant decimal places.
/// * [`MigrateError::AmountOutOfRange`] - outside the `i64` minor-unit range.
pub fn amount_from_decimal(path: &str, field: &str, raw: &str) -> Result<Money> {
    let text = normalise(raw).map_err(|defect| match defect {
        AmountDefect::NotANumber => MigrateError::AmountNotANumber {
            path: path.to_string(),
            field: field.to_string(),
            value: raw.to_string(),
        },
        AmountDefect::NotExact => MigrateError::AmountNotExact {
            path: path.to_string(),
            field: field.to_string(),
            value: raw.to_string(),
            decimals: nau_core::domain::DECIMALS,
        },
        AmountDefect::OutOfRange => MigrateError::AmountOutOfRange {
            path: path.to_string(),
            field: field.to_string(),
            value: raw.to_string(),
        },
    })?;
    // After normalisation the only remaining failure mode is magnitude: the text
    // has at most six decimal places and digits only.
    Money::parse(&text).map_err(|_| MigrateError::AmountOutOfRange {
        path: path.to_string(),
        field: field.to_string(),
        value: raw.to_string(),
    })
}

/// [`amount_from_decimal`] for callers with no source coordinates.
///
/// # Errors
///
/// The same three amount errors, with `<literal>` in the `path` and `field`
/// positions.
pub fn parse_decimal_exact(raw: &str) -> Result<Money> {
    amount_from_decimal("<literal>", "<value>", raw)
}

/// An exponent that did not fit in `i64`; only its sign still matters.
#[derive(Debug, Clone, Copy)]
enum Exp {
    Value(i64),
    Huge { negative: bool },
}

/// Rewrite one decimal literal as plain decimal text with at most six places.
///
/// This is the whole exactness argument in one function: it works on the digit
/// string, so no value is ever approximated.
// upstream v2.5.6 fix: upstream stored every amount as `f64` and asserted
// conservation with `(balance_sum - expected_sum).abs() < 0.001`
// (`marketplace/settlement.rs:173`), six orders of magnitude looser than its own
// JavaScript mirror. There is no float on this path and no tolerance: the literal
// becomes an exact `i64` minor-unit count or the record is refused.
fn normalise(raw: &str) -> std::result::Result<String, AmountDefect> {
    let text = raw.trim();
    if text.is_empty() {
        return Err(AmountDefect::NotANumber);
    }
    let (negative, rest) = match text.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    if rest.is_empty() {
        return Err(AmountDefect::NotANumber);
    }

    // Split off an exponent, if there is one.
    let (mantissa, exponent) = match rest.find(['e', 'E']) {
        Some(index) => {
            let (mantissa, tail) = rest.split_at(index);
            let body = &tail[1..];
            let (exp_negative, exp_digits) = match body.strip_prefix('-') {
                Some(digits) => (true, digits),
                None => (false, body.strip_prefix('+').unwrap_or(body)),
            };
            if exp_digits.is_empty() || !exp_digits.bytes().all(|b| b.is_ascii_digit()) {
                return Err(AmountDefect::NotANumber);
            }
            let parsed = match exp_digits.parse::<i64>() {
                // The sign is part of the value: `1e-3` is one thousandth, and
                // dropping this negation would migrate it as one thousand.
                Ok(value) => Exp::Value(if exp_negative { -value } else { value }),
                // An exponent too large for i64. The sign still decides whether the
                // value is astronomically large (out of range) or infinitesimal
                // (impossible to represent at six places).
                Err(_) => Exp::Huge {
                    negative: exp_negative,
                },
            };
            (mantissa, parsed)
        }
        None => (rest, Exp::Value(0)),
    };

    let (int_part, frac_part) = match mantissa.split_once('.') {
        Some((integer, fraction)) => (integer, fraction),
        None => (mantissa, ""),
    };
    if int_part.is_empty() && frac_part.is_empty() {
        return Err(AmountDefect::NotANumber);
    }
    if !int_part.bytes().all(|b| b.is_ascii_digit())
        || !frac_part.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(AmountDefect::NotANumber);
    }
    // `0`, `0.0`, `000`, `.000` are exactly zero whatever the exponent says.
    if int_part.bytes().chain(frac_part.bytes()).all(|b| b == b'0') {
        return Ok("0".to_string());
    }

    let exponent = match exponent {
        Exp::Value(value) => value,
        Exp::Huge { negative: false } => return Err(AmountDefect::OutOfRange),
        Exp::Huge { negative: true } => return Err(AmountDefect::NotExact),
    };

    // The value is `digits` times `10^shift`, with `digits` the mantissa's digits
    // read as an integer (leading zeros are insignificant).
    let mut digits = String::with_capacity(int_part.len() + frac_part.len());
    digits.push_str(int_part);
    digits.push_str(frac_part);
    let frac_len = i64::try_from(frac_part.len()).map_err(|_| AmountDefect::OutOfRange)?;
    let shift = exponent
        .checked_sub(frac_len)
        .ok_or(AmountDefect::OutOfRange)?;

    // Leading zeros are value-neutral for a digit string and make the length
    // arithmetic below exact.
    let mut kept = digits.trim_start_matches('0').to_string();
    debug_assert!(!kept.is_empty(), "an all-zero mantissa returned above");

    let sign = if negative { "-" } else { "" };
    if shift >= 0 {
        let shift = u64::try_from(shift).map_err(|_| AmountDefect::OutOfRange)?;
        let total = u64::try_from(kept.len())
            .unwrap_or(u64::MAX)
            .saturating_add(shift);
        if total > MAX_INTEGER_DIGITS {
            return Err(AmountDefect::OutOfRange);
        }
        for _ in 0..shift {
            kept.push('0');
        }
        return Ok(format!("{sign}{kept}"));
    }

    // `places` is how many decimal places the value has.
    let places = shift.unsigned_abs();
    let digit_count = u64::try_from(kept.len()).unwrap_or(u64::MAX);
    if places > digit_count.saturating_add(KEEP_DECIMALS as u64) {
        // Every significant digit sits past the sixth decimal place.
        return Err(AmountDefect::NotExact);
    }
    let places = usize::try_from(places).map_err(|_| AmountDefect::OutOfRange)?;
    if places >= kept.len() {
        // Left-pad so the integer part has at least one digit; value-neutral.
        let mut padded = String::with_capacity(places + 1);
        for _ in 0..(places + 1 - kept.len()) {
            padded.push('0');
        }
        padded.push_str(&kept);
        kept = padded;
    }

    // Drop the digits past the sixth place, but only if they are all zeros.
    let extra = places.saturating_sub(KEEP_DECIMALS);
    if extra > 0 {
        let keep = kept.len() - extra;
        if !kept.as_bytes()[keep..].iter().all(|b| *b == b'0') {
            return Err(AmountDefect::NotExact);
        }
        kept.truncate(keep);
    }
    let kept_places = places - extra;
    let split = kept.len() - kept_places;

    let mut out = String::with_capacity(kept.len() + 2);
    out.push_str(sign);
    out.push_str(&kept[..split]);
    if kept_places > 0 {
        out.push('.');
        out.push_str(&kept[split..]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minor(raw: &str) -> i64 {
        parse_decimal_exact(raw)
            .unwrap_or_else(|e| panic!("`{raw}` should convert exactly: {e}"))
            .minor()
    }

    #[test]
    fn exact_decimals_convert_without_touching_a_float() {
        // Every literal below is exactly representable at six decimal places.
        for (literal, expected) in [
            ("0", 0),
            ("1", 1_000_000),
            ("100", 100_000_000),
            ("100.0", 100_000_000),
            ("0.1", 100_000),
            ("0.2", 200_000),
            ("0.3", 300_000),
            ("12.5", 12_500_000),
            ("1.5", 1_500_000),
            ("0.000001", 1),
            ("-0.000001", -1),
            ("-1000.25", -1_000_250_000),
            ("+7", 7_000_000),
            (".5", 500_000),
            ("5.", 5_000_000),
            ("000123.450", 123_450_000),
            ("0.001", 1_000),
            ("1e2", 100_000_000),
            ("1E2", 100_000_000),
            ("1e-3", 1_000),
            ("1e-6", 1),
            ("2.5e3", 2_500_000_000),
            ("25e-1", 2_500_000),
            ("-1.5e1", -15_000_000),
            ("1.0000000", 1_000_000),
            ("1.00000000", 1_000_000),
            ("0.100000000000", 100_000),
            ("-0", 0),
            ("0e999999", 0),
        ] {
            assert_eq!(minor(literal), expected, "literal `{literal}`");
        }
    }

    #[test]
    fn one_tenth_plus_two_tenths_migrates_to_exactly_three_tenths() {
        // The canonical demonstration of the defect being migrated away from: in
        // binary floating point this sum is not 0.3. Here it is exact because the
        // arithmetic is done in minor units.
        let tenth = minor("0.1");
        let fifth = minor("0.2");
        let sum = Money::from_minor(tenth)
            .checked_add(Money::from_minor(fifth))
            .expect("in range");
        assert_eq!(sum.minor(), 300_000);
        assert_eq!(sum, Money::parse("0.3").expect("0.3 parses"));
        assert_eq!(sum.to_decimal_string(), "0.3");
    }

    #[test]
    fn a_seventh_decimal_place_is_refused_rather_than_rounded() {
        for literal in [
            "0.0000001",
            "1e-7",
            "0.00000001",
            "1E-7",
            "0.1234567",
            "1.0000001",
            "-0.0000001",
            "0.00000010",
            "1e-99999999999999999999",
        ] {
            let err =
                parse_decimal_exact(literal).expect_err(&format!("`{literal}` must be refused"));
            assert_eq!(
                AmountDefect::of(&err),
                Some(AmountDefect::NotExact),
                "`{literal}` gave {err}"
            );
        }
    }

    #[test]
    fn trailing_zeros_past_the_sixth_place_are_still_exact() {
        // Dropping these digits loses nothing, so refusing them would be a false
        // negative that rejects migratable data.
        assert_eq!(minor("1.0000000"), 1_000_000);
        assert_eq!(minor("0.5000000000"), 500_000);
        assert_eq!(minor("1.230000000000"), 1_230_000);
    }

    #[test]
    fn magnitudes_outside_the_minor_unit_range_are_typed_errors() {
        for literal in [
            "1e19",
            "9223372036854775807",
            "18446744073709551615",
            "1e99999999999999999999",
            "-99999999999999999999",
        ] {
            let err = parse_decimal_exact(literal)
                .expect_err(&format!("`{literal}` must be out of range"));
            assert_eq!(
                AmountDefect::of(&err),
                Some(AmountDefect::OutOfRange),
                "`{literal}` gave {err}"
            );
        }
        // The largest exactly representable amount is i64::MAX minor units, and it
        // is reachable from the decimal text of the same value.
        assert_eq!(
            parse_decimal_exact("9223372036854.775807")
                .expect("i64::MAX minor units is representable")
                .minor(),
            i64::MAX
        );
    }

    #[test]
    fn anything_that_is_not_a_decimal_number_is_refused() {
        for literal in [
            "", "   ", "-", "+", ".", "abc", "1,000", "NaN", "inf", "-inf", "0x10", "1.2.3", "--1",
            "1e", "1e+", "+-1", "1 000", "1_000", "1.0.0", "'1'",
        ] {
            let err =
                parse_decimal_exact(literal).expect_err(&format!("`{literal}` must be refused"));
            assert_eq!(
                AmountDefect::of(&err),
                Some(AmountDefect::NotANumber),
                "`{literal}` gave {err}"
            );
        }
    }

    #[test]
    fn error_messages_name_the_file_the_field_and_the_value() {
        let err = amount_from_decimal("ledger.jsonl#7", "amount", "0.0000001")
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains("ledger.jsonl#7"), "{text}");
        assert!(text.contains("amount"), "{text}");
        assert!(text.contains("0.0000001"), "{text}");
        assert!(text.contains("refusing to round"), "{text}");
        assert_eq!(nau_core::domain::DECIMALS, 6);
    }

    #[test]
    fn normalised_text_round_trips_through_money_parse() {
        // The normaliser must produce text `Money::parse` accepts, for every form
        // that is exactly representable.
        for literal in [
            "0.1",
            "1e-3",
            "12.5",
            "100.0",
            "-1.5e1",
            ".5",
            "5.",
            "1.0000000",
        ] {
            let text = normalise(literal).expect("exactly representable");
            assert_eq!(
                Money::parse(&text).expect("normalised text parses"),
                parse_decimal_exact(literal).expect("converts")
            );
        }
    }
}
