use std::ffi::CString;
use std::os::raw::{c_int, c_char};

use super::Solve;
use ::dc::fp::Fp;

// "bindgen --whitelist-function solve --output ffi.rs solver_flint.h"
// was used to generate the bindings.
mod ffi;

const RET_OK : c_int = 0;
const RET_INVALID : c_int = 1;

pub struct Solver;

impl Solve for Solver {
    fn solve(power_sums: &Vec<Fp>) -> Option<Vec<Fp>> {
        // The hex conversions are certainly unnecessary overhead. However, we keep them for now,
        // because they are simple: we don't have to care about word sizes, endianness, etc.
        // If the goal is to optimize the solver, then it's anyway time to switch to NTL,
        // or implement our own solver that relies on the fast field arithmetic.
        #[inline]
        fn hex_c_str<T>(num: T) -> CString
            where T: ::std::fmt::UpperHex
        {
            CString::new(format!("{:X}", num)).unwrap()
        }

        let hex_len_u128 = ::std::mem::size_of::<u128>() * 2 + 1;

        let n = power_sums.len();
        let mut out_messages_hex = vec!(vec!(0u8; hex_len_u128 + 1); n);
        let out_messages_hex_ptrs : Vec<_> =
            out_messages_hex.iter_mut().map(|x| x.as_mut_ptr()).collect();
        let prime_hex = hex_c_str(Fp::prime());

        let power_sums_hex : Vec<_> =
            power_sums.iter().map(|x| hex_c_str(u128::from(*x))).collect();
        let power_sums_hex_ptrs : Vec<_> =
            power_sums_hex.iter().map(|x| x.as_ptr()).collect();

        let ret;
        unsafe {
            ret = ffi::solve(out_messages_hex_ptrs.as_ptr() as *const *mut c_char,
                       prime_hex.as_ptr(),
                       power_sums_hex_ptrs.as_ptr(),
                       n);
        }

        match ret {
            RET_OK => { Some(
                out_messages_hex.iter().map(|m_hex| {
                    let leading_non_zero = m_hex.iter().take_while(|c| **c != 0).count();
                    let rust_string = ::std::str::from_utf8(&m_hex[0..leading_non_zero]).unwrap();
                    Fp::from_u127(u128::from_str_radix(rust_string, 16).unwrap())
                }).collect()
            )},
            RET_INVALID => None,
            x => panic!("Internal error in flint solver, return value = {}", x),
        }
    }
}

#[cfg(test)]
mod tests {
    use ::dc::fp::Fp;
    use super::Solver;
    use super::super::Solve;

    #[test]
    fn simple_cases() {
        let power_sums = vec![
            Fp::from_u127(0x384ae5480f49d67c51b83df1fff94e90),
            Fp::from_u127(0x6e9de51c5deca89883084cd992088c11),
            Fp::from_u127(0x38132da941235c87e3f33762aa488840),
            Fp::from_u127(0x75bc93bff8a8ce7b4fb23af15dbbaebc),
            Fp::from_u127(0x1f8abf68afa44bf42a0da59b4885d94c),
        ];
        let expected = vec![
            Fp::from_u127(0x0b1b5dcbb65d530c4a19d3cfe5033887),
            Fp::from_u127(0x27d9803748f6be6875282823a6ac5d5a),
            Fp::from_u127(0x3a3112db6e48449711521bbc42944db3),
            Fp::from_u127(0x52027185cadce683709dfb288e7de45b),
            Fp::from_u127(0x792282e3d6d099ed10862b19a337869f),
        ];

        let mut result = Solver::solve(&power_sums).unwrap();
        result.sort();
        assert_eq!(expected, result);
    }

    #[test]
    fn zero() {
        let power_sums = vec![
            Fp::from_u127(0),
            Fp::from_u127(0),
            Fp::from_u127(0),
        ];

        let mut result = Solver::solve(&power_sums).unwrap();
        result.sort();
        assert_eq!(result, power_sums);
    }
}
