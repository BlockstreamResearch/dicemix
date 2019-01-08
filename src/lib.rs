extern crate byteorder;
extern crate bytes;
extern crate rand;
extern crate secp256k1;
extern crate serde;
extern crate tokio_io;
#[macro_use]
extern crate serde_derive;
extern crate bincode;
extern crate vec_map;
#[macro_use]
extern crate futures;
#[macro_use]
extern crate lazy_static;
extern crate bit_set;
extern crate blake2;

use secp256k1::Secp256k1;
use std::mem;

pub use messages::PublicKey;

mod messages;
mod rng;
mod solver;
// mod state;
mod dc;
mod io;

lazy_static! {
    pub static ref SECP256K1: Secp256k1 = Secp256k1::new();
}

type ExtensionVariant = mem::Discriminant<messages::Extension>;

// These types are sent over the wire, so there may be a need to change them easily.
type Commitment = [u8; 32];
type SymmetricKey = [u8; 32];
type SessionId = [u8; 32];
type PeerIndex = u32;
type SequenceNum = u32;

// FIXME We store the peer ID in two [u8; 32], as this allows us to derive various traits.
// This can be resolved in the future using const generics, see the corresponding Rust RFC:
// https://github.com/rust-lang/rfcs/pull/2000/files
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PeerId([u8; 32], [u8; 32]);

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Variant {
    PlainEcdsa,
    ValueShuffleElementsEcdsa,
    // TODO This requires support for early confirmation data, i.e., confirmation data before
    // the actual confirmation phase.
    // PlainSchnorrMulti,
    // ValueShuffleElementsSchnorrMulti.
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Options {
    variant: Variant,
    extension_variant: ExtensionVariant,
}

impl Options {
    fn new_simple(variant: Variant) -> Self {
        match variant {
            Variant::PlainEcdsa => Self {
                variant: Variant::PlainEcdsa,
                extension_variant: mem::discriminant(&messages::Extension::None),
            },
            Variant::ValueShuffleElementsEcdsa => Self {
                variant: Variant::ValueShuffleElementsEcdsa,
                extension_variant: mem::discriminant(&messages::Extension::DcAddSecp256k1Scalar()),
            },
        }
    }

    fn variant(&self) -> Variant {
        self.variant
    }

    fn extension_variant(&self) -> ExtensionVariant {
        self.extension_variant
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
