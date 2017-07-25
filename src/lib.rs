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

lazy_static! {
    pub static ref SECP256K1: Secp256k1 = Secp256k1::new();
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
