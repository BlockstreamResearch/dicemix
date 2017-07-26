#![feature(i128_type)]

extern crate rand;
extern crate byteorder;
extern crate secp256k1;
extern crate bytes;
extern crate tokio_io;
extern crate tokio_serde_bincode;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate vec_map;
extern crate futures;
#[macro_use]
extern crate lazy_static;

use secp256k1::Secp256k1;

mod solver;
mod rng;
mod field;
mod messages;

type SymmetricKey = [u8; 32];
type PeerIndex = u32;
type SequenceNum = u32;

// FIXME We store the peer ID in two [u8; 32], as this allows us to derive various traits.
// This can be resolved in the future using const generics, see the corresponding Rust RFC:
// https://github.com/rust-lang/rfcs/pull/2000/files
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PeerId([u8; 32], [u8; 32]);

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SessionId([u8; 32]);

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
enum ConfirmationVariant {
    EcdsaSignatures,
    ValueShuffle,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Options {
    confirmation: ConfirmationVariant,
    num_dc_xor: usize,
    num_dc_add_secp251k1_scalar: usize,
}

impl Options {
    fn new_simple() -> Self {
        Self {
            confirmation: EcdsaSignatures,
            num_dc_xor: 1,
            num_dc_add_secp251k1_scalar: 0,
        }
    }

    fn new_valueshuffle() -> Self {
        Self {
            confirmation_variant: ValueShuffle,
            num_dc_xor: 1,
            num_dc_add_secp251k1_scalar: 1,
        }
    }

    fn confirmation(&self) -> ConfirmationVariant {
        self.confirmation
    }

    fn num_dc_xor(&self) -> usize {
        self.num_dc_xor
    }

    fn num_dc_add_secp251k1_scalar(&self) -> usize {
        self.num_dc_add_secp251k1_scalar
    }
}

lazy_static! {
    pub static ref SECP256K1: Secp256k1 = Secp256k1::new();
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
