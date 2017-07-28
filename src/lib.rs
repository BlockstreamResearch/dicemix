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
extern crate bit_set;

use secp256k1::Secp256k1;

mod solver;
mod rng;
mod field;
mod messages;
mod state;

lazy_static! {
    pub static ref SECP256K1: Secp256k1 = Secp256k1::new();
}

type SymmetricKey = [u8; 32];
type PeerIndex = u32;
type SequenceNum = u32;

// FIXME We store the peer ID in two [u8; 32], as this allows us to derive various traits.
// This can be resolved in the future using const generics, see the corresponding Rust RFC:
// https://github.com/rust-lang/rfcs/pull/2000/files
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PeerId([u8; 32], [u8; 32]);

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct SessionId([u8; 32]);

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Variant {
    PlainEcdsa,
    ValueShuffleElementsEcdsa,
    // TODO This requires support for early confirmation data, i.e., confirmation data before
    // the actual confirmation phase.
    // PlainSchnorrMulti,
    // ValueShuffleElementsSchnorrMulti.
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Options {
    variant: Variant,
    /// Indicates the requirement for a DC-net in the group of secp256k1 scalars
    dc_add_secp256k1_scalar: bool,
    // TODO This could be useful for MimbleWimble.
    // dc_add_secp256k1_point: bool
}

impl Options {
    fn new_simple(variant: Variant) -> Self {
        match variant {
            Variant::PlainEcdsa => {
                Self {
                    variant: Variant::PlainEcdsa,
                    dc_add_secp256k1_scalar: false,
                }
            },
            Variant::ValueShuffleElementsEcdsa => {
                Self {
                    variant: Variant::ValueShuffleElementsEcdsa,
                    dc_add_secp256k1_scalar: true,
                }
            },
        }
    }

    fn variant(&self) -> Variant {
        self.variant
    }

    fn dc_add_secp256k1_scalar(&self) -> bool {
        self.dc_add_secp256k1_scalar
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
