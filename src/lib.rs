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
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PeerId([u8; 32], [u8; 32]);

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SessionId([u8; 32]);

lazy_static! {
    pub static ref SECP256K1: Secp256k1 = Secp256k1::new();
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
