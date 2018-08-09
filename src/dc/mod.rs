use rand::Rng;

pub mod xor;
pub mod fp;

// TODO https://github.com/rust-lang/rust/issues/41517
// trait DcGroup = Add + AddAssign + Sub + SubAssign + Neg + Randomize;

/// Trait for types that can be randomized by mutation while preserving their structure.
///
/// This is useful for vectors for example, which can differ in their structure, namely in their
/// length, which precludes a canonical implementation of the `Rand` trait for `Vec<T>`, even if
/// `Rand` is implemented for `T`. However, given a vector with an already defined length, it is
/// possible to randomize the vector by preserving its length and randomizing its elements.
pub trait Randomize {
    fn randomize<R: Rng + ?Sized>(&mut self, rng: &mut R);
}
