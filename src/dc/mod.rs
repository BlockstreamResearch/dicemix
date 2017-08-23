use rand::{Rand, Rng};

pub mod xor;

// TODO https://github.com/rust-lang/rust/issues/41517
// trait DcGroup = Add + AddAssign + Sub + SubAssign + Neg + Randomize;

pub trait Randomize {
    fn randomize<R: Rng>(&mut self, rng: &mut R);
}

impl<T> Randomize for T where T: Rand {
    fn randomize<R: Rng>(&mut self, rng: &mut R) {
        *self = T::rand(rng);
    }
}

