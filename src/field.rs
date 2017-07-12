use std::ops::{Add, AddAssign, Sub, SubAssign, Mul, MulAssign};

// The field size.
const P: u128 = (1 << 127) - 1;

// A finite field element.
//
// It is consistent iff 0 <= self.0 <= P.
// Note that this implies that the zero element has two internal representations.
#[derive(Clone, Copy, Default, Debug)]
pub struct Fp(u128);

#[inline]
fn as_limbs(x: u128) -> (u64, u64) {
    ((x >> 64) as u64, x as u64)
}

trait Reduce: Sized {
    fn reduce_once(self) -> u128;

    #[inline]
    fn reduce_once_assert(self) -> u128 {
        let red: u128 = self.reduce_once();
        debug_assert!(0 <= red && red <= P);
        red
    }
}

impl Reduce for u128 {
    #[inline]
    fn reduce_once(self) -> u128 {
        (self & P) + (self >> 127)
    }
}

impl Reduce for (u128, u128) {
    #[inline]
    fn reduce_once(self) -> u128 {
        let (h, l) = self;
        // (h, l) >> 127;
        let shift = (h << 1) | (l >> 127);
        (l & P) + shift
    }
}

impl Fp {
    #[inline]
    pub fn new(x: u128) -> Fp {
        Fp(x.reduce_once_assert())
    }

    #[inline]
    pub fn prime() -> u128 {
        P
    }
}

impl From<u128> for Fp {
    #[inline]
    fn from(x: u128) -> Self {
        Fp::new(x)
    }
}

impl From<Fp> for u128 {
    #[inline]
    fn from(x: Fp) -> u128 {
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
        Fp((self.0 + P - other.0).reduce_once_assert())
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
        let (sh, sl) = as_limbs(self.0);
        let (oh, ol) = as_limbs(other.0);

        // (64 bits * 63 bits) + (64 bits * 63 bits) = 128 bits
        let m: u128 = (sh as u128 * ol as u128) + (oh as u128 * sl as u128);
        let (mh, ml) = as_limbs(m);

        // (64 bits * 64 bits) + 128 bits = 129 bits
        let (rl, carry) = (sl as u128 * ol as u128).overflowing_add((ml as u128) << 64);

        // (63 bits * 63 bits) + 64 bits + 1 bit = 127 bits
        let rh: u128 = (sh as u128 * oh as u128) + (mh as u128) + (carry as u128);

        Fp((rh, rl).reduce_once().reduce_once_assert())
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
        u128::from(*self) == u128::from(*other)
    }
}

impl Eq for Fp {}

mod tests {
    use super::*;

    #[test]
    fn add() {
        assert_eq!(Fp(7) + Fp(5), Fp(12));
        assert_eq!(Fp(P - 2) + Fp(5), Fp(3));
        assert_eq!(
            Fp(75661398932549814984099328258351945610) + Fp(154440289138086217180118920884960981429),
            Fp(59960504610166800432530945427428821312)
        );
    }

    #[test]
    fn sub() {
        assert_eq!(Fp(7) - Fp(5), Fp(2));
        assert_eq!(Fp(4) - Fp(8), Fp(P - 4));
    }

    #[test]
    fn mul() {
        assert_eq!(Fp(4) * Fp(3), Fp(12));
        assert_eq!(Fp(P) * Fp(291298091), Fp(0));
        assert_eq!(
            Fp(14766549069271113692204649107775507741) * Fp(153613967287097206589234951623852979690),
            Fp(113548737858505840193892055835373785352)
        );
        // Two reductions are necessary for the following example.
        assert_eq!(
            Fp(75661398932549814984099328258351945610) * Fp(154440289138086217180118920884960981429),
            Fp(109146875586984049909139102289297416971)
        );
    }

    #[test]
    fn eq() {
        assert_eq!(Fp(0), Fp(P));
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
