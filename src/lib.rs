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

mod solver;
mod rng;
mod field;
mod messages;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
