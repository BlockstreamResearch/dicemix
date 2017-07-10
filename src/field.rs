use std::ops::{Add, AddAssign, Sub, SubAssign, Mul, MulAssign};

// The field size.
const P : i64 = (1 << 61) - 1;

// A finite field element.
//
// It is consistent iff 0 <= self.0 <= P.
// Note that this implies that the zero element has two internal representations.
#[derive(Clone, Copy, Default, Debug)]
pub struct Fp(i64);

trait Reduce : Sized
{
    fn reduce_once(self) -> i64;

    #[inline]
    fn reduce_once_assert(self) -> i64 {
        let red : i64 = self.reduce_once();
        debug_assert!(0 <= red && red <= P);
        red
    }
}

impl Reduce for i64 {
    #[inline]
    fn reduce_once(self) -> i64 {
        (self & P) + (self >> 61)
    }
}

impl Reduce for i128 {
    #[inline]
    fn reduce_once(self) -> i64 {
        ((self & (P as i128)) + (self >> 61)) as i64
    }
}

impl Fp {
    #[inline]
    pub fn new(x: i64) -> Fp {
        Fp(x.reduce_once_assert())
    }

    #[inline]
    pub fn prime() -> i64 {
        P
    }
}

impl From<i64> for Fp {
    #[inline]
    fn from(x: i64) -> Self {
        Fp::new(x)
    }
}

impl From<Fp> for i64 {
    #[inline]
    fn from(x: Fp) -> i64 {
        let red = x.0.reduce_once_assert();
        if red == P { 0 } else { red }
    }
}

impl Add for Fp {
    type Output = Self;
    #[inline]
    fn add(self, other: Self) -> Self {
        Fp((self.0 + other.0).reduce_once_assert())
    }
}

impl AddAssign for Fp {
    #[inline]
    fn add_assign(&mut self, other: Self) {
        *self = *self + other
    }
}

impl Sub for Fp {
    type Output = Self;
    #[inline]
    fn sub(self, other: Self) -> Self {
        Fp((self.0 - other.0).reduce_once_assert())
    }
}

impl SubAssign for Fp {
    #[inline]
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other
    }
}

impl Mul for Fp {
    type Output = Self;
    #[inline]
    fn mul(self, other: Self) -> Self {
        let prod : i128 = (self.0 as i128) * (other.0 as i128);
        Fp(prod.reduce_once().reduce_once_assert() as i64)
    }
}

impl MulAssign for Fp {
    #[inline]
    fn mul_assign(&mut self, other: Self) {
        *self = *self * other
    }
}

impl PartialEq for Fp {
    fn eq(&self, other: &Self) -> bool {
        i64::from(*self) == i64::from(*other)
    }
}

impl Eq for Fp {}

mod tests {
    use super::*;

    #[test]
    fn add() {
        assert_eq!(Fp(7) + Fp(5), Fp(12));
        assert_eq!(Fp(P - 2) + Fp(5), Fp(3));
        assert_eq!(Fp(2193980333835211996) + Fp(621408416523297271), Fp(509545741144815316));
    }

    #[test]
    fn sub() {
        assert_eq!(Fp(7) - Fp(5), Fp(2));
        assert_eq!(Fp(4) - Fp(8), Fp(P - 4));
        assert_eq!(Fp(-5) - Fp(P), Fp(-5));
    }

    #[test]
    fn mul() {
        assert_eq!(Fp(4) * Fp(3), Fp(12));
        assert_eq!(Fp(-6) * Fp(5), Fp(-30));

        // Two reductions are necessary for the following examples.
        assert_eq!(Fp(2239513929391938494) * Fp(1021644029483981869), Fp(619009326837417152));
        assert_eq!(Fp(-2239513929391938494) * Fp(1021644029483981869), Fp(-619009326837417152));
        assert_eq!(Fp(-2239513929391938494) * Fp(-1021644029483981869), Fp(619009326837417152));
    }

    #[test]
    fn eq() {
        assert_eq!(Fp(0), Fp(P));
        assert_eq!(Fp(-P), Fp(P));
        assert_eq!(Fp(-P), Fp(0));
        assert_eq!(Fp(-1), Fp(P - 1));
        assert!(Fp(17) != Fp(4));
        assert!(Fp(0) != Fp(4));
        assert!(Fp(P) != Fp(17));
    }

    #[test]
    fn assign() {
        let mut a = Fp(17);

        a += Fp(3);
        assert_eq!(a, Fp(20));

        a -= Fp(5);
        assert_eq!(a, Fp(15));

        a *= Fp(2);
        assert_eq!(a, Fp(30));
    }
}
