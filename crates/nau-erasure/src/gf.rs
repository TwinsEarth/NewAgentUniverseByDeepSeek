//! Arithmetic in the finite field GF(2^8).
//!
//! The field is built with the standard Reed-Solomon primitive polynomial
//!
//! ```text
//! p(x) = x^8 + x^4 + x^3 + x^2 + 1        (0x11d)
//! ```
//!
//! which is the polynomial used by every widely deployed RS implementation
//! (Backblaze `reed-solomon`, Intel ISA-L, Klaus Post's `reedsolomon`,
//! `zfec`). `0x11d` is primitive, so `x = 0x02` is a *generator* of the
//! multiplicative group `GF(256)*`, which has order `255`. That is exactly why
//! an RS code over this field can be at most `255` shards wide.
//!
//! Everything here is table driven and integer only:
//!
//! * `EXP[i] = 2^i` for `i` in `0..=254`, then the table repeats with period
//!   `255` (`EXP[i] = 2^(i mod 255)`).
//! * `LOG[v] = i` such that `2^i = v`, for `v != 0`.
//! * `INV[v] = 1 / v = 2^(255 - i)` for `v != 0`.
//!
//! The three tables are built exactly once per process behind a
//! [`OnceLock`], so no caller pays for table construction twice.
//!
//! ## No panics, ever
//!
//! Every function in this module is total. There is no `unwrap`, no indexing
//! that can be out of bounds, and no `panic!`. Division by zero — the only
//! operation with no answer in a field — takes an explicit error path and
//! therefore has two entry points:
//!
//! * [`mul`], [`pow`], [`inverse`] take raw bytes and are total; `inverse(0)`
//!   returns `0` (the field's `x * 0 == 0` convention, used internally where
//!   the zero case is provably unreachable).
//! * [`div`], [`try_inverse`] return [`NauError::Validation`] for a zero
//!   divisor, which is the checked API callers should prefer.
//!
//! `x / 0` returning an error rather than panicking matters because the
//! upstream module this crate replaces built its "parity" shards from
//! `sha2` digests rather than from field arithmetic; there is no established
//! behaviour to preserve, so the honest choice is an error.

use nau_core::{NauError, Result};
use std::sync::OnceLock;

/// The primitive polynomial of GF(2^8) used throughout this crate:
/// `x^8 + x^4 + x^3 + x^2 + 1`.
pub const PRIMITIVE_POLYNOMIAL: u16 = 0x11d;

/// The generator of the multiplicative group: `x`, i.e. the byte `0x02`.
pub const GENERATOR: u8 = 0x02;

/// Order of the multiplicative group of GF(2^8): `2^8 - 1`.
pub const MULTIPLICATIVE_ORDER: usize = 255;

/// `EXP[i] == 2^i` (with exponent reduced modulo 255), `EXP` has 512 entries
/// so that `EXP[a + b]` never needs a modulo for `a, b < 255`.
struct Tables {
    exp: [u8; 512],
    log: [u8; 256],
    inv: [u8; 256],
}

/// The process-wide GF(256) tables.
static TABLES: OnceLock<Tables> = OnceLock::new();

/// Build the exp/log/inv tables by repeated multiplication by `x`.
///
/// This is the only place the tables are constructed. It is called at most
/// once per process (via [`OnceLock::get_or_init`]) and is `O(255)`.
///
/// The build is deliberately **two-pass**: the first pass fills `exp` and
/// `log`, and only once `exp` is complete does the second pass fill `inv`.
/// Filling `inv` inside the first pass is a trap — `1 / 2^i` is
/// `2^(255 - i)`, an entry of `exp` that has not been written yet for small
/// `i`, so the lookup returns the zero initialiser. That bug is invisible in
/// the `log` and `exp` tables and shows up only as every inverse of a small
/// element being wrong (and, downstream, as division returning zero, which
/// silently produces an all-zero generator polynomial and a degenerate code).
fn build_tables() -> Tables {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let inv = [0u8; 256];

    // exp[i] = 2^i. The field element is a polynomial of degree < 8 over
    // GF(2), and multiplying by x = 2 is a left shift followed by reduction
    // modulo 0x11d when the shift overflows into bit 8.
    //
    // The order of these three statements is load-bearing. `value <<= 1` can
    // produce a 9-bit value; XORing 0x11d then cancels bit 8 (0x11d has bit 8
    // set) while folding in the low bits 0x1d. Masking *before* the XOR would
    // throw away bit 8 first, so the XOR would no longer cancel it and the
    // low bits would be folded into an already-truncated value — the
    // generator would then only have order 127 rather than 255.
    let mut value: u16 = 1;
    let mut i = 0;
    while i < MULTIPLICATIVE_ORDER {
        let byte = value as u8;
        exp[i] = byte;
        log[byte as usize] = i as u8;
        value <<= 1;
        if value & 0x100 != 0 {
            value ^= PRIMITIVE_POLYNOMIAL;
        }
        value &= 0xff;
        i += 1;
    }
    // exp[255] == 1 and the table continues with period 255 into 256..511, so
    // `EXP[a + b]` never needs an explicit modulo for `a, b < 255`.
    let mut j = MULTIPLICATIVE_ORDER;
    while j < 512 {
        exp[j] = exp[j - MULTIPLICATIVE_ORDER];
        j += 1;
    }

    // Second pass: the multiplicative inverses. `1 / 2^i == 2^(255 - i)`, and
    // every non-zero element of GF(256) is `2^i` for a unique `i` in
    // `0..255`. `inv[0]` is left at zero, the crate's documented
    // "zero has no inverse" convention.
    let mut inv = inv;
    let mut i = 0;
    while i < MULTIPLICATIVE_ORDER {
        let byte = exp[i] as usize;
        inv[byte] = if i == 0 {
            1
        } else {
            exp[MULTIPLICATIVE_ORDER - i]
        };
        i += 1;
    }

    Tables { exp, log, inv }
}

/// Borrow the process-wide tables, building them on first use.
///
/// `get_or_init` cannot fail, so this function has no error case.
#[inline]
fn tables() -> &'static Tables {
    TABLES.get_or_init(build_tables)
}

/// `a + b` in GF(2^8): addition is XOR.
///
/// # Examples
///
/// ```
/// # use nau_erasure::gf::add;
/// assert_eq!(add(0b1100, 0b1010), 0b0110);
/// assert_eq!(add(7, 7), 0);
/// ```
#[must_use]
#[inline]
pub const fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// `a - b` in GF(2^8): in characteristic 2 subtraction *is* addition.
///
/// Provided under its own name because Reed-Solomon decoding reads much
/// better when the elimination step says "subtract".
///
/// # Examples
///
/// ```
/// # use nau_erasure::gf::{add, sub};
/// assert_eq!(sub(0b1100, 0b1010), add(0b1100, 0b1010));
/// ```
#[must_use]
#[inline]
pub const fn sub(a: u8, b: u8) -> u8 {
    a ^ b
}

/// `a * b` in GF(2^8).
///
/// Zero is handled explicitly because `LOG[0]` is undefined; this is a branch,
/// not a panic.
#[must_use]
#[inline]
pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = tables();
    // a * b = 2^(log a + log b), with the exponent reduced mod 255.
    let mut sum = t.log[a as usize] as usize + t.log[b as usize] as usize;
    if sum >= MULTIPLICATIVE_ORDER {
        sum -= MULTIPLICATIVE_ORDER;
    }
    t.exp[sum]
}

/// `a / b` in GF(2^8).
///
/// # Errors
///
/// Returns [`NauError::Validation`] when `b == 0`, the only input with no
/// value in the field. Nothing can panic.
#[inline]
pub fn div(a: u8, b: u8) -> Result<u8> {
    if b == 0 {
        return Err(NauError::Validation(
            "GF(256) division by zero: the divisor is not invertible".to_string(),
        ));
    }
    if a == 0 {
        return Ok(0);
    }
    let t = tables();
    // a / b = 2^(log a - log b) with the exponent kept in 0..255.
    let mut diff = t.log[a as usize] as isize - t.log[b as usize] as isize;
    if diff < 0 {
        diff += MULTIPLICATIVE_ORDER as isize;
    }
    Ok(t.exp[diff as usize])
}

/// `a^n` in GF(2^8), for any non-negative `n`.
///
/// Total by construction: `0^0 == 1` (the empty product), `0^n == 0` for
/// `n > 0`.
#[must_use]
#[inline]
pub fn pow(a: u8, n: usize) -> u8 {
    if n == 0 {
        return 1;
    }
    if a == 0 {
        return 0;
    }
    let t = tables();
    let exponent = (t.log[a as usize] as usize * (n % MULTIPLICATIVE_ORDER)) % MULTIPLICATIVE_ORDER;
    t.exp[exponent]
}

/// The multiplicative inverse of `a`, i.e. the `b` with `a * b == 1`.
///
/// Returns `0` for `a == 0`, which has no inverse. Use [`try_inverse`] when a
/// zero input must be reported as an error rather than absorbed.
#[must_use]
#[inline]
pub fn inverse(a: u8) -> u8 {
    tables().inv[a as usize]
}

/// The multiplicative inverse of `a`, or an error when `a == 0`.
///
/// # Errors
///
/// Returns [`NauError::Validation`] when `a == 0`.
#[inline]
pub fn try_inverse(a: u8) -> Result<u8> {
    if a == 0 {
        return Err(NauError::Validation(
            "GF(256) has no inverse for zero".to_string(),
        ));
    }
    Ok(tables().inv[a as usize])
}

/// `2^n` in GF(2^8); the exp table exposed directly, with `n` reduced
/// modulo 255 so any input is valid.
#[must_use]
#[inline]
pub fn exp(n: usize) -> u8 {
    tables().exp[n % MULTIPLICATIVE_ORDER]
}

/// The discrete logarithm base `2` of `a`.
///
/// Returns `None` for `a == 0`, which is not in the multiplicative group.
#[must_use]
#[inline]
pub fn log(a: u8) -> Option<u8> {
    if a == 0 {
        None
    } else {
        Some(tables().log[a as usize])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitive_polynomial_is_0x11d() {
        assert_eq!(PRIMITIVE_POLYNOMIAL, 0x11d);
    }

    #[test]
    fn the_generator_x_has_order_255() {
        // 2^255 == 1 and no smaller positive power is 1.
        assert_eq!(pow(GENERATOR, 255), 1);
        let mut value = 1u8;
        let mut order = 0usize;
        while value != 1 || order == 0 {
            value = mul(value, GENERATOR);
            order += 1;
            assert!(order <= 255, "generator order exceeded 255");
        }
        assert_eq!(order, 255);
    }

    #[test]
    fn exp_table_is_the_inverse_of_the_log_table() {
        for i in 0..MULTIPLICATIVE_ORDER {
            let v = exp(i);
            assert_ne!(v, 0, "2^{i} must be a unit");
            assert_eq!(log(v), Some(i as u8));
        }
        assert_eq!(exp(MULTIPLICATIVE_ORDER), 1);
        assert_eq!(log(0), None);
    }

    #[test]
    fn multiplication_matches_brute_force_carry_less_polynomial_reduction() {
        // Independent reference: shift-and-reduce, no tables involved.
        fn reference_mul(a: u8, b: u8) -> u8 {
            let mut result: u16 = 0;
            let mut x = a as u16;
            let mut y = b as u16;
            while y != 0 {
                if y & 1 != 0 {
                    result ^= x;
                }
                y >>= 1;
                x <<= 1;
                if x & 0x100 != 0 {
                    x ^= PRIMITIVE_POLYNOMIAL;
                }
            }
            (result & 0xff) as u8
        }
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(mul(a, b), reference_mul(a, b), "mul({a}, {b})");
            }
        }
    }

    #[test]
    fn multiplication_is_commutative_associative_and_distributive() {
        let samples: [u8; 16] = [
            0, 1, 2, 3, 5, 7, 0x0f, 0x10, 0x1d, 0x57, 0x80, 0xa5, 0xbf, 0xfe, 0xff, 0x42,
        ];
        for &a in &samples {
            for &b in &samples {
                assert_eq!(mul(a, b), mul(b, a));
                for &c in &samples {
                    assert_eq!(mul(mul(a, b), c), mul(a, mul(b, c)));
                    assert_eq!(mul(a, add(b, c)), add(mul(a, b), mul(a, c)));
                }
            }
        }
    }

    #[test]
    fn one_is_the_multiplicative_identity() {
        for a in 0..=255u8 {
            assert_eq!(mul(a, 1), a);
            assert_eq!(mul(1, a), a);
            assert_eq!(mul(a, 0), 0);
        }
    }

    #[test]
    fn inverse_is_the_multiplicative_inverse() {
        assert_eq!(inverse(0), 0);
        for a in [1u8, 2, 3, 5, 0x1d, 0x80, 0xff] {
            let inv = inverse(a);
            assert_ne!(inv, 0, "a = {a}: inverse must be a unit, got {inv}");
            assert_eq!(mul(a, inv), 1, "a = {a}, inv = {inv}");
        }
        for a in 1..=255u8 {
            assert_eq!(mul(a, inverse(a)), 1, "a = {a}");
            assert_eq!(mul(inverse(a), a), 1, "a = {a}");
            assert_eq!(try_inverse(a).ok(), Some(inverse(a)));
        }
    }

    #[test]
    fn try_inverse_rejects_zero() {
        let err = try_inverse(0);
        assert!(err.is_err(), "inverse of zero must be an error");
        if let Err(NauError::Validation(message)) = err {
            assert!(message.contains("zero"), "message was {message}");
        } else {
            panic!("expected NauError::Validation");
        }
    }

    #[test]
    fn division_is_the_inverse_of_multiplication() {
        for a in 0..=255u8 {
            for b in 1..=255u8 {
                let quotient = div(a, b);
                assert!(quotient.is_ok(), "div({a}, {b}) must succeed");
                if let Ok(q) = quotient {
                    assert_eq!(mul(q, b), a, "{a} / {b} * {b} != {a}");
                }
            }
        }
    }

    #[test]
    fn division_by_zero_returns_an_error_and_never_panics() {
        for a in [0u8, 1, 0x7f, 0xff] {
            let err = div(a, 0);
            assert!(err.is_err(), "div({a}, 0) must fail");
            if let Err(NauError::Validation(message)) = err {
                assert!(
                    message.contains("division by zero"),
                    "message was {message}"
                );
            } else {
                panic!("expected NauError::Validation");
            }
        }
    }

    #[test]
    fn power_agrees_with_repeated_multiplication() {
        for a in [0u8, 1, 2, 3, 0x1d, 0x80, 0xff] {
            let mut expected = 1u8;
            for n in 0..300usize {
                assert_eq!(pow(a, n), expected, "pow({a}, {n})");
                expected = mul(expected, a);
            }
        }
        // 0^0 == 1 and 0^n == 0 for n > 0.
        assert_eq!(pow(0, 0), 1);
        assert_eq!(pow(0, 1), 0);
        assert_eq!(pow(0, 999), 0);
    }

    #[test]
    fn sub_is_add_and_a_minus_a_is_zero() {
        for a in 0..=255u8 {
            assert_eq!(sub(a, a), 0);
            for b in [0u8, 1, 0x55, 0xaa, 0xff] {
                assert_eq!(sub(a, b), add(a, b));
            }
        }
    }

    /// Every non-zero element must have a correct inverse. This is the check
    /// that catches a first-pass-only `inv` table, where `exp[255 - i]` is
    /// still zero.
    #[test]
    fn every_non_zero_element_has_a_correct_inverse() {
        let t = tables();
        let mut seen = [false; 256];
        for i in 0..MULTIPLICATIVE_ORDER {
            let value = t.exp[i];
            assert_ne!(value, 0, "exp[{i}] must be a unit");
            assert!(!seen[value as usize], "exp[{i}] = {value} is a repeat");
            seen[value as usize] = true;
            let inverse = t.inv[value as usize];
            assert_ne!(inverse, 0, "inv[{value}] is zero");
            assert_eq!(mul(value, inverse), 1, "value = {value}");
        }
        assert_eq!(t.inv[0], 0, "zero has no inverse");
    }

    #[test]
    fn known_products_are_exact() {
        // (x + 1) * (x + 1) = x^2 + 1, so 3 * 3 must be 5 in GF(2^8).
        assert_eq!(mul(3, 3), 5, "3 * 3 = (x+1)^2 = x^2 + 1 = 5");
        // 2 * 3 = x * (x + 1) = x^2 + x = 6.
        assert_eq!(mul(2, 3), 6);
        // x^8 = 0x11d, reduced to the low byte 0x1d.
        assert_eq!(pow(2, 8), 0x1d);
        // 3 * 5 = (x + 1)(x^2 + 1) = x^3 + x^2 + x + 1 = 15.
        assert_eq!(mul(3, 5), 15);
        // The log/exp tables must round-trip for these.
        assert_eq!(exp(log(3).unwrap_or(0) as usize), 3);
        assert_eq!(exp(log(5).unwrap_or(0) as usize), 5);
        assert_eq!(log(5), Some(50));
    }

    #[test]
    fn tables_are_shared_by_every_caller() {
        // Two fetches must hand out the same allocation; this is what makes
        // the OnceLock worthwhile (and proves we are not rebuilding tables).
        let first = tables() as *const Tables;
        let second = tables() as *const Tables;
        assert_eq!(first, second);
    }
}
