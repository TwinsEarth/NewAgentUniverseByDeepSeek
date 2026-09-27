//! Dense matrices over GF(2^8) and Gauss-Jordan elimination.
//!
//! This is the linear-algebra half of the Reed-Solomon code. Encoding is one
//! matrix-vector product; decoding is a matrix inversion followed by a
//! matrix-vector product. Nothing in this module is Reed-Solomon specific —
//! it is ordinary linear algebra over a finite field, which makes it easy to
//! test in isolation with matrices over the small field `GF(2)` embedded in
//! `GF(256)` (elements `0` and `1`, so arithmetic is ordinary integer
//! arithmetic modulo 2).
//!
//! ## Why Gaussian elimination and not a Vandermonde shortcut
//!
//! A Vandermonde system can be inverted in closed form, but the closed form
//! is only valid for a *specific* row layout. The upstream module this crate
//! replaces never inverted anything at all (it concatenated data shards and
//! ignored parity), so there is no layout to stay bug-compatible with. A
//! general elimination routine is:
//!
//! * correct for any `k x k` submatrix we hand it,
//! * testable against an independent oracle (see the `GF(2)` tests below),
//! * and honest about singularity: [`invert`] reports it instead of
//!   computing garbage.

use nau_core::{NauError, Result};

use crate::gf;

/// A row-major dense matrix of field elements.
///
/// Dimensions are fixed at construction; all arithmetic is checked, and no
/// method can panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matrix {
    rows: usize,
    cols: usize,
    data: Vec<u8>,
}

impl Matrix {
    /// Allocate a `rows x cols` zero matrix.
    ///
    /// # Errors
    ///
    /// Returns [`NauError::Validation`] if `rows` or `cols` is zero or if the
    /// element count would overflow `usize`.
    pub fn zeros(rows: usize, cols: usize) -> Result<Self> {
        if rows == 0 || cols == 0 {
            return Err(NauError::Validation(format!(
                "matrix dimensions must be non-zero, got {rows}x{cols}"
            )));
        }
        let len = rows.checked_mul(cols).ok_or_else(|| {
            NauError::Validation(format!("matrix {rows}x{cols} is too large to index"))
        })?;
        Ok(Self {
            rows,
            cols,
            data: vec![0u8; len],
        })
    }

    /// Build a matrix from row-major data.
    ///
    /// # Errors
    ///
    /// Returns [`NauError::Validation`] when `data.len() != rows * cols`.
    pub fn from_rows(rows: usize, cols: usize, data: Vec<u8>) -> Result<Self> {
        let expected = rows.checked_mul(cols).ok_or_else(|| {
            NauError::Validation(format!("matrix {rows}x{cols} is too large to index"))
        })?;
        if rows == 0 || cols == 0 || data.len() != expected {
            return Err(NauError::Validation(format!(
                "matrix {rows}x{cols} needs {expected} elements, got {}",
                data.len()
            )));
        }
        Ok(Self { rows, cols, data })
    }

    /// The `n x n` identity matrix.
    ///
    /// # Errors
    ///
    /// Returns [`NauError::Validation`] when `n == 0`.
    pub fn identity(n: usize) -> Result<Self> {
        let mut matrix = Self::zeros(n, n)?;
        for i in 0..n {
            matrix.set(i, i, 1)?;
        }
        Ok(matrix)
    }

    /// Number of rows.
    #[must_use]
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Number of columns.
    #[must_use]
    pub fn cols(&self) -> usize {
        self.cols
    }

    /// Read element `(row, col)`, or `None` when out of bounds.
    #[must_use]
    pub fn get(&self, row: usize, col: usize) -> Option<u8> {
        if row >= self.rows || col >= self.cols {
            return None;
        }
        // Bounds were checked immediately above, so indexing is safe; the
        // `?`-free formulation keeps this function panic-free even if the
        // dimensions were somehow inconsistent.
        self.data.get(row * self.cols + col).copied()
    }

    /// Write element `(row, col)`.
    ///
    /// # Errors
    ///
    /// Returns [`NauError::Validation`] when the index is out of bounds.
    pub fn set(&mut self, row: usize, col: usize, value: u8) -> Result<()> {
        if row >= self.rows || col >= self.cols {
            return Err(NauError::Validation(format!(
                "index ({row}, {col}) is outside {}x{}",
                self.rows, self.cols
            )));
        }
        let index = row * self.cols + col;
        let slot = self.data.get_mut(index).ok_or_else(|| {
            NauError::Validation(format!("index ({row}, {col}) is outside the backing store"))
        })?;
        *slot = value;
        Ok(())
    }

    /// Copy `row` into a freshly allocated vector.
    ///
    /// # Errors
    ///
    /// Returns [`NauError::Validation`] when `row` is out of bounds.
    pub fn row(&self, row: usize) -> Result<Vec<u8>> {
        if row >= self.rows {
            return Err(NauError::Validation(format!(
                "row {row} is outside {}x{}",
                self.rows, self.cols
            )));
        }
        let start = row * self.cols;
        let end = start + self.cols;
        match self.data.get(start..end) {
            Some(slice) => Ok(slice.to_vec()),
            None => Err(NauError::Validation(format!(
                "row {row} is not addressable in the backing store"
            ))),
        }
    }

    /// Multiply the matrix by a vector of length `cols`.
    ///
    /// This is the single operation the encoder uses: every output shard is
    /// one dot product.
    ///
    /// # Errors
    ///
    /// Returns [`NauError::Validation`] when `vector.len() != cols`.
    pub fn mul_vec(&self, vector: &[u8]) -> Result<Vec<u8>> {
        if vector.len() != self.cols {
            return Err(NauError::Validation(format!(
                "vector of length {} cannot be multiplied by a {}x{} matrix",
                vector.len(),
                self.rows,
                self.cols
            )));
        }
        let mut out = vec![0u8; self.rows];
        for (row_index, slot) in out.iter_mut().enumerate() {
            let start = row_index * self.cols;
            let mut acc = 0u8;
            for (coefficient, byte) in self
                .data
                .iter()
                .skip(start)
                .take(self.cols)
                .zip(vector.iter())
            {
                acc = gf::add(acc, gf::mul(*coefficient, *byte));
            }
            *slot = acc;
        }
        Ok(out)
    }

    /// Swap two rows in place; a no-op when the indices are equal.
    ///
    /// # Errors
    ///
    /// Returns [`NauError::Validation`] when either index is out of bounds.
    pub fn swap_rows(&mut self, a: usize, b: usize) -> Result<()> {
        if a >= self.rows || b >= self.rows {
            return Err(NauError::Validation(format!(
                "cannot swap rows {a} and {b} of a {}-row matrix",
                self.rows
            )));
        }
        if a == b {
            return Ok(());
        }
        for col in 0..self.cols {
            let left = a * self.cols + col;
            let right = b * self.cols + col;
            // `split_at_mut` avoids `unsafe` and avoids a temporary copy.
            if left < right {
                let (head, tail) = self.data.split_at_mut(right);
                if let (Some(x), Some(y)) = (head.get_mut(left), tail.first_mut()) {
                    std::mem::swap(x, y);
                }
            } else {
                let (head, tail) = self.data.split_at_mut(left);
                if let (Some(x), Some(y)) = (head.get_mut(right), tail.first_mut()) {
                    std::mem::swap(x, y);
                }
            }
        }
        Ok(())
    }

    /// Invert this matrix by Gauss-Jordan elimination.
    ///
    /// The matrix is augmented with the identity and reduced to reduced row
    /// echelon form. When that succeeds the identity block has become the
    /// inverse.
    ///
    /// # Errors
    ///
    /// * [`NauError::Validation`] if the matrix is not square.
    /// * [`NauError::Validation`] if a pivot column is entirely zero — the
    ///   matrix is singular and has no inverse. For the Reed-Solomon
    ///   distribution matrices this crate builds, a singular submatrix
    ///   indicates a bug in the row selection rather than bad user input, so
    ///   the error message says so explicitly.
    pub fn invert(&self) -> Result<Matrix> {
        if self.rows != self.cols {
            return Err(NauError::Validation(format!(
                "only square matrices can be inverted, got {}x{}",
                self.rows, self.cols
            )));
        }
        let n = self.rows;
        let mut augmented = Matrix::zeros(
            n,
            n.checked_mul(2)
                .ok_or_else(|| NauError::Validation("matrix is too wide to augment".to_string()))?,
        )?;

        for row in 0..n {
            for col in 0..n {
                let value = self.get(row, col).unwrap_or(0);
                augmented.set(row, col, value)?;
            }
            augmented.set(row, n + row, 1)?;
        }

        for pivot_col in 0..n {
            // Find a row at or below `pivot_col` whose pivot entry is non-zero.
            let mut pivot_row = None;
            for candidate in pivot_col..n {
                if augmented.get(candidate, pivot_col).unwrap_or(0) != 0 {
                    pivot_row = Some(candidate);
                    break;
                }
            }
            let pivot_row = pivot_row.ok_or_else(|| {
                NauError::Validation(format!(
                    "matrix is singular: column {pivot_col} has no non-zero pivot, \
                     so this set of shards cannot reconstruct the data"
                ))
            })?;
            augmented.swap_rows(pivot_col, pivot_row)?;

            // Scale the pivot row so the pivot becomes 1.
            let pivot = augmented.get(pivot_col, pivot_col).unwrap_or(0);
            if pivot != 1 {
                let scale = gf::try_inverse(pivot)?;
                for col in 0..(2 * n) {
                    let value = augmented.get(pivot_col, col).unwrap_or(0);
                    augmented.set(pivot_col, col, gf::mul(value, scale))?;
                }
            }

            // Eliminate this column from every other row.
            for row in 0..n {
                if row == pivot_col {
                    continue;
                }
                let factor = augmented.get(row, pivot_col).unwrap_or(0);
                if factor == 0 {
                    continue;
                }
                for col in 0..(2 * n) {
                    let pivot_value = augmented.get(pivot_col, col).unwrap_or(0);
                    let target = augmented.get(row, col).unwrap_or(0);
                    augmented.set(row, col, gf::add(target, gf::mul(factor, pivot_value)))?;
                }
            }
        }

        // Extract the right-hand block.
        let mut inverse = Matrix::zeros(n, n)?;
        for row in 0..n {
            for col in 0..n {
                let value = augmented.get(row, n + col).unwrap_or(0);
                inverse.set(row, col, value)?;
            }
        }
        Ok(inverse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gf::mul;

    /// Multiply two matrices, as an independent check on `invert`.
    fn matmul(a: &Matrix, b: &Matrix) -> Matrix {
        assert_eq!(a.cols(), b.rows());
        let mut out = Matrix::zeros(a.rows(), b.cols()).expect("non-zero test dimensions");
        for row in 0..a.rows() {
            for col in 0..b.cols() {
                let mut acc = 0u8;
                for k in 0..a.cols() {
                    acc ^= mul(a.get(row, k).unwrap_or(0), b.get(k, col).unwrap_or(0));
                }
                out.set(row, col, acc).expect("in-bounds test write");
            }
        }
        out
    }

    #[test]
    fn zeros_rejects_degenerate_shapes() {
        assert!(Matrix::zeros(0, 3).is_err());
        assert!(Matrix::zeros(3, 0).is_err());
        assert!(Matrix::zeros(0, 0).is_err());
    }

    #[test]
    fn from_rows_checks_the_element_count() {
        assert!(Matrix::from_rows(2, 2, vec![1, 2, 3, 4]).is_ok());
        assert!(Matrix::from_rows(2, 2, vec![1, 2, 3]).is_err());
        assert!(Matrix::from_rows(0, 0, vec![]).is_err());
    }

    #[test]
    fn get_and_set_are_bounds_checked() {
        let mut m = Matrix::zeros(2, 2).expect("2x2");
        assert!(m.set(1, 1, 9).is_ok());
        assert_eq!(m.get(1, 1), Some(9));
        assert_eq!(m.get(2, 0), None);
        assert_eq!(m.get(0, 2), None);
        assert!(m.set(2, 0, 1).is_err());
        assert!(m.row(2).is_err());
    }

    #[test]
    fn identity_times_anything_is_that_thing() {
        let m = Matrix::from_rows(3, 3, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]).expect("3x3");
        let identity = Matrix::identity(3).expect("3x3 identity");
        assert_eq!(matmul(&identity, &m), m);
        assert_eq!(matmul(&m, &identity), m);
    }

    #[test]
    fn mul_vec_matches_hand_computation() {
        let m = Matrix::from_rows(2, 3, vec![1, 2, 3, 4, 5, 6]).expect("2x3");
        let v = vec![1u8, 1, 1];
        let out = m.mul_vec(&v).expect("dimensions match");
        assert_eq!(out[0], 1 ^ 2 ^ 3);
        assert_eq!(out[1], 4 ^ 5 ^ 6);

        let v = vec![1u8, 0, 1];
        let out = m.mul_vec(&v).expect("dimensions match");
        assert_eq!(out[0], 1 ^ 3);
        assert_eq!(out[1], 4 ^ 6);

        assert!(m.mul_vec(&[1, 2]).is_err());
    }

    #[test]
    fn mul_vec_by_identity_is_the_identity_on_vectors() {
        let identity = Matrix::identity(4).expect("4x4");
        for value in 0..=255u8 {
            let v = vec![value, value ^ 1, value.wrapping_mul(7), 0xff];
            assert_eq!(identity.mul_vec(&v).expect("length 4"), v);
        }
    }

    /// Matrices over `GF(2)` are just parity arithmetic; a brute-force
    /// enumeration over *all* 2x2 and 3x3 binary matrices gives an
    /// independent oracle for `invert`.
    #[test]
    fn invert_agrees_with_brute_force_over_gf2() {
        for bits in 0u32..(1 << 4) {
            let data: Vec<u8> = (0..4).map(|i| ((bits >> i) & 1) as u8).collect();
            let m = Matrix::from_rows(2, 2, data).expect("2x2");
            let det = m.get(0, 0).unwrap_or(0) & m.get(1, 1).unwrap_or(0)
                ^ m.get(0, 1).unwrap_or(0) & m.get(1, 0).unwrap_or(0);
            match m.invert() {
                Ok(inverse) => {
                    assert_eq!(det, 1, "singular GF(2) matrix reported invertible: {m:?}");
                    let product = matmul(&m, &inverse);
                    assert_eq!(product, Matrix::identity(2).expect("2x2 identity"));
                }
                Err(_) => assert_eq!(det, 0, "invertible GF(2) matrix reported singular: {m:?}"),
            }
        }

        for bits in 0u32..(1 << 9) {
            let data: Vec<u8> = (0..9).map(|i| ((bits >> i) & 1) as u8).collect();
            let m = Matrix::from_rows(3, 3, data).expect("3x3");
            // Independent determinant over GF(2) by the Leibniz rule.
            let a = |r: usize, c: usize| m.get(r, c).unwrap_or(0);
            let det = (a(0, 0) & a(1, 1) & a(2, 2))
                ^ (a(0, 1) & a(1, 2) & a(2, 0))
                ^ (a(0, 2) & a(1, 0) & a(2, 1))
                ^ (a(0, 2) & a(1, 1) & a(2, 0))
                ^ (a(0, 0) & a(1, 2) & a(2, 1))
                ^ (a(0, 1) & a(1, 0) & a(2, 2));
            match m.invert() {
                Ok(inverse) => {
                    assert_eq!(det, 1, "singular GF(2) matrix reported invertible: {m:?}");
                    assert_eq!(
                        matmul(&m, &inverse),
                        Matrix::identity(3).expect("3x3 identity")
                    );
                }
                Err(_) => assert_eq!(det, 0, "invertible GF(2) matrix reported singular: {m:?}"),
            }
        }
    }

    #[test]
    fn invert_rejects_a_singular_matrix() {
        // Two identical rows: rank 1.
        let m = Matrix::from_rows(2, 2, vec![3, 5, 3, 5]).expect("2x2");
        let err = m.invert();
        assert!(err.is_err(), "singular matrix must not invert");
        if let Err(NauError::Validation(message)) = err {
            assert!(message.contains("singular"), "message was {message}");
        } else {
            panic!("expected NauError::Validation");
        }

        // An all-zero matrix is the extreme case.
        let zero_m = Matrix::zeros(2, 2).expect("2x2");
        assert!(zero_m.invert().is_err());
    }

    #[test]
    fn invert_rejects_non_square_matrices() {
        let m = Matrix::from_rows(2, 3, vec![1, 0, 0, 0, 1, 0]).expect("2x3");
        assert!(m.invert().is_err());
    }

    #[test]
    fn invert_inverts_a_matrix_over_the_full_field() {
        // A Vandermonde matrix with distinct non-zero nodes is invertible over
        // any field; this one uses nodes 1, 2, 3, 4 so the entries spread
        // across GF(256) once the powers are reduced.
        let nodes = [0x01u8, 0x02, 0x03, 0x04];
        let mut data = Vec::with_capacity(16);
        for node in nodes {
            let mut power = 1u8;
            for _ in 0..4 {
                data.push(power);
                power = gf::mul(power, node);
            }
        }
        let m = Matrix::from_rows(4, 4, data).expect("4x4");
        let inverse = m.invert().expect("a Vandermonde matrix is invertible");
        assert_eq!(matmul(&m, &inverse), Matrix::identity(4).expect("4x4"));
        assert_eq!(matmul(&inverse, &m), Matrix::identity(4).expect("4x4"));

        // A deliberately singular matrix is still rejected.
        let singular =
            Matrix::from_rows(4, 4, vec![1, 2, 4, 8, 1, 2, 4, 8, 3, 3, 3, 3, 5, 6, 7, 9])
                .expect("4x4");
        assert!(singular.invert().is_err());
    }

    #[test]
    fn swap_rows_actually_swaps_and_checks_bounds() {
        let mut m = Matrix::from_rows(2, 2, vec![1, 2, 3, 4]).expect("2x2");
        m.swap_rows(0, 1).expect("in bounds");
        assert_eq!(m.get(0, 0), Some(3));
        assert_eq!(m.get(1, 0), Some(1));
        m.swap_rows(1, 1).expect("self swap is a no-op");
        assert_eq!(m.get(1, 0), Some(1));
        assert!(m.swap_rows(0, 5).is_err());
    }
}
