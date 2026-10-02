//! Exact, integer-only monetary amounts.
//!
//! # Why this type exists
//!
//! Upstream v2.5.6 models every balance, settlement and slash as `f64`
//! (`gsn-core/src/marketplace/settlement.rs:28,37-40,47,52-59`) and then asserts
//! conservation with a **tolerance**:
//!
//! ```text
//! let conserved = (self.balance_sum - expected_sum).abs() < 0.001
//! ```
//!
//! Binary floating point cannot represent most decimal fractions, so repeated
//! `+= amount` / `-= amount` cycles accumulate error. A ledger that is only
//! "conserved to within 0.001" is not conserved: the error is real money, it
//! grows without bound, and a determined participant can steer the drift in
//! their favour. The same code also compares balances with `<`, so a balance of
//! `100.00000000000001` and a price of `100.0` take different branches.
//!
//! `Money` is an integer count of **minor units** (10⁻⁶ of a unit, so six
//! decimal places) held in an `i64`. Every arithmetic operation is checked and
//! returns a `Result`; there is deliberately no `Add`/`Sub` operator impl, so
//! the compiler forces callers to decide what an overflow means.
//!
//! # Wire format
//!
//! `Money` serializes as a **JSON integer** (`#[serde(transparent)]`). That is
//! required for the canonical-payload rules, which reject floats outright —
//! which in turn removes the cross-language divergence where Python would emit
//! `100.0`, JavaScript `100` and Rust `100.0` for "the same" value.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{NauError, Result};

/// Minor units per major unit: six decimal places.
pub const MINOR_UNITS_PER_MAJOR: i64 = 1_000_000;

/// Number of decimal digits in the minor-unit scale.
pub const DECIMALS: u32 = 6;

/// Currency ticker used by the settlement ledger.
pub const CURRENCY: &str = "NAU";

/// An exact amount, counted in minor units (10⁻⁶).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Money(i64);

impl Money {
    /// Zero.
    pub const ZERO: Money = Money(0);

    /// The most that can be held in one account.
    pub const MAX: Money = Money(i64::MAX);

    /// Wrap a raw minor-unit count.
    pub const fn from_minor(minor: i64) -> Self {
        Self(minor)
    }

    /// The raw minor-unit count.
    pub const fn minor(self) -> i64 {
        self.0
    }

    /// True when the amount is exactly zero.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// True when strictly positive.
    pub const fn is_positive(self) -> bool {
        self.0 > 0
    }

    /// True when strictly negative.
    pub const fn is_negative(self) -> bool {
        self.0 < 0
    }

    /// The magnitude, saturating (never panics, even for `i64::MIN`).
    pub const fn abs_minor(self) -> i64 {
        self.0.saturating_abs()
    }

    /// Checked addition.
    pub fn checked_add(self, other: Self) -> Result<Self> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or(NauError::Overflow("Money::checked_add"))
    }

    /// Checked subtraction.
    pub fn checked_sub(self, other: Self) -> Result<Self> {
        self.0
            .checked_sub(other.0)
            .map(Self)
            .ok_or(NauError::Overflow("Money::checked_sub"))
    }

    /// Checked negation.
    pub fn checked_neg(self) -> Result<Self> {
        self.0
            .checked_neg()
            .map(Self)
            .ok_or(NauError::Overflow("Money::checked_neg"))
    }

    /// Multiply by an integer count (e.g. units × unit price), checked.
    pub fn checked_mul_int(self, factor: i64) -> Result<Self> {
        self.0
            .checked_mul(factor)
            .map(Self)
            .ok_or(NauError::Overflow("Money::checked_mul_int"))
    }

    /// Split `self` into `parts` equal shares plus a remainder.
    ///
    /// Returns `(share, remainder)` where `share * parts + remainder == self`.
    /// Integer division never invents or destroys value the way `f64 / n` does,
    /// and the remainder is handed back explicitly so the caller must decide
    /// where it goes. Used by committee reward splits.
    pub fn split(self, parts: u32) -> Result<(Self, Self)> {
        if parts == 0 {
            return Err(NauError::InvalidAmount(
                "cannot split into zero parts".into(),
            ));
        }
        let parts_i64 = i64::from(parts);
        let share = self.0 / parts_i64;
        let remainder = self.0 % parts_i64;
        Ok((Self(share), Self(remainder)))
    }

    /// Parse a decimal string such as `"12.5"`, `"-0.000001"`, `"1000"`.
    ///
    /// Parsing is textual — the string never passes through `f64` — so
    /// `"0.1"` is exactly 100000 minor units.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Err(NauError::InvalidAmount("empty string".into()));
        }
        let (negative, rest) = match s.strip_prefix('-') {
            Some(r) => (true, r),
            None => (false, s.strip_prefix('+').unwrap_or(s)),
        };
        if rest.is_empty() {
            return Err(NauError::InvalidAmount(format!("`{s}` has no digits")));
        }
        let (int_part, frac_part) = match rest.split_once('.') {
            Some((i, f)) => (i, f),
            None => (rest, ""),
        };
        if int_part.is_empty() && frac_part.is_empty() {
            return Err(NauError::InvalidAmount(format!("`{s}` has no digits")));
        }
        if !int_part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(NauError::InvalidAmount(format!(
                "`{s}` has a non-digit in the integer part"
            )));
        }
        if !frac_part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(NauError::InvalidAmount(format!(
                "`{s}` has a non-digit in the fractional part"
            )));
        }
        if frac_part.len() > DECIMALS as usize {
            return Err(NauError::InvalidAmount(format!(
                "`{s}` has more than {DECIMALS} decimal places; the smallest unit is 1e-{DECIMALS}"
            )));
        }

        let int_value: i64 = if int_part.is_empty() {
            0
        } else {
            int_part.parse::<i64>().map_err(|_| {
                NauError::InvalidAmount(format!("`{s}` integer part is out of range"))
            })?
        };

        let mut padded = String::with_capacity(DECIMALS as usize);
        padded.push_str(frac_part);
        while padded.len() < DECIMALS as usize {
            padded.push('0');
        }
        let frac_value: i64 = if padded.is_empty() {
            0
        } else {
            padded.parse::<i64>().map_err(|_| {
                NauError::InvalidAmount(format!("`{s}` fractional part is out of range"))
            })?
        };

        let scale = MINOR_UNITS_PER_MAJOR;
        let magnitude = int_value
            .checked_mul(scale)
            .and_then(|v| v.checked_add(frac_value))
            .ok_or(NauError::Overflow("Money::parse"))?;
        Ok(Self(if negative { -magnitude } else { magnitude }))
    }

    /// Render as a decimal string, trimming trailing zeros in the fraction.
    ///
    /// `Money::parse(&m.to_decimal_string()) == Ok(m)` for every `m`.
    pub fn to_decimal_string(self) -> String {
        // Widen to i128 so that i64::MIN cannot overflow during negation.
        let widened = i128::from(self.0);
        let negative = widened < 0;
        let magnitude = widened.unsigned_abs();
        let scale = MINOR_UNITS_PER_MAJOR as u128;
        let int_part = magnitude / scale;
        let frac_part = magnitude % scale;

        let mut out = String::new();
        if negative {
            out.push('-');
        }
        out.push_str(&int_part.to_string());
        if frac_part != 0 {
            let mut frac = format!("{frac_part:0width$}", width = DECIMALS as usize);
            while frac.ends_with('0') {
                frac.pop();
            }
            out.push('.');
            out.push_str(&frac);
        }
        out
    }
}

impl fmt::Display for Money {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {CURRENCY}", self.to_decimal_string())
    }
}

impl fmt::Debug for Money {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Money({} minor = {})", self.0, self.to_decimal_string())
    }
}

impl FromStr for Money {
    type Err = NauError;
    fn from_str(s: &str) -> Result<Self> {
        Money::parse(s)
    }
}

/// Build a `Money` from whole major units in a `const` context (tests, defaults).
pub const fn major(units: i64) -> Money {
    Money(units * MINOR_UNITS_PER_MAJOR)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_without_ever_touching_a_float() {
        assert_eq!(Money::parse("1").unwrap().minor(), 1_000_000);
        // 0.1 is exactly 100000 minor units; `(0.1f64 * 1e6) as i64` is 100000
        // only by luck, and "0.3" would not survive addition.
        assert_eq!(Money::parse("0.1").unwrap().minor(), 100_000);
        assert_eq!(Money::parse("0.3").unwrap().minor(), 300_000);
        assert_eq!(
            Money::parse("0.1")
                .unwrap()
                .checked_add(Money::parse("0.2").unwrap())
                .unwrap(),
            Money::parse("0.3").unwrap(),
            "exact decimal addition must hold"
        );
        assert_eq!(Money::parse("12.5").unwrap().minor(), 12_500_000);
        assert_eq!(Money::parse("-0.000001").unwrap().minor(), -1);
        assert_eq!(Money::parse("+7").unwrap().minor(), 7_000_000);
        assert_eq!(Money::parse(".5").unwrap().minor(), 500_000);
        assert_eq!(Money::parse("5.").unwrap().minor(), 5_000_000);
    }

    #[test]
    fn rejects_input_that_would_lose_precision_or_was_never_a_number() {
        assert!(Money::parse("1.0000001").is_err(), "7 dp exceeds the scale");
        assert!(Money::parse("").is_err());
        assert!(Money::parse("-").is_err());
        assert!(Money::parse("abc").is_err());
        assert!(Money::parse("1e6").is_err(), "exponent notation is refused");
        assert!(Money::parse("1,000").is_err());
        assert!(Money::parse("NaN").is_err());
        assert!(Money::parse("inf").is_err());
        assert!(Money::parse("0x10").is_err());
    }

    #[test]
    fn decimal_string_round_trips_exactly() {
        for s in [
            "0",
            "1",
            "-1",
            "0.000001",
            "-0.000001",
            "12.5",
            "1000",
            "-1000.25",
            "999999.999999",
        ] {
            let m = Money::parse(s).unwrap();
            assert_eq!(m.to_decimal_string(), s, "round trip failed for {s}");
            assert_eq!(Money::parse(&m.to_decimal_string()).unwrap(), m);
        }
    }

    #[test]
    fn overflow_is_reported_not_wrapped() {
        assert!(Money::MAX.checked_add(Money::from_minor(1)).is_err());
        assert!(Money::from_minor(i64::MIN)
            .checked_sub(Money::from_minor(1))
            .is_err());
        assert!(Money::MAX.checked_mul_int(2).is_err());
        assert!(Money::from_minor(i64::MIN).checked_neg().is_err());
    }

    #[test]
    fn magnitude_of_i64_min_does_not_panic() {
        // `i64::MIN.abs()` panics in debug; `saturating_abs` must not.
        assert_eq!(Money::from_minor(i64::MIN).abs_minor(), i64::MAX);
        // And the decimal rendering must handle it too.
        assert!(Money::from_minor(i64::MIN)
            .to_decimal_string()
            .starts_with('-'));
    }

    #[test]
    fn split_conserves_value_with_an_explicit_remainder() {
        let pot = Money::parse("10").unwrap();
        let (share, remainder) = pot.split(3).unwrap();
        assert_eq!(share.minor(), 3_333_333);
        assert_eq!(remainder.minor(), 1, "10 - 3*3.333333 = 0.000001");
        let recomposed = share
            .checked_mul_int(3)
            .unwrap()
            .checked_add(remainder)
            .unwrap();
        assert_eq!(
            recomposed, pot,
            "splitting must not create or destroy value"
        );
        assert!(pot.split(0).is_err());
    }

    #[test]
    fn serializes_as_a_json_integer_so_canonical_payloads_accept_it() {
        let v = serde_json::to_value(Money::parse("1.5").unwrap()).unwrap();
        assert_eq!(v, serde_json::json!(1_500_000));
        // and the canonical layer must accept it (no float rejection)
        let canon = crate::identity::canonical::canonical_string(&serde_json::json!({ "amt": v }))
            .expect("Money must survive canonicalization");
        assert_eq!(canon, r#"{"amt":1500000}"#);
    }
}
