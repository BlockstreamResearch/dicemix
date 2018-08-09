use rand::{RngCore, SeedableRng, ChaChaRng, Error};
use std::io::Cursor;
use byteorder::{LittleEndian, ReadBytesExt};

// TODO Extend this to an RNG that produces the "sum" (in a DcGroup sense) of multiple RNGs

pub struct DiceMixRng {
    chacha : ChaChaRng
}

impl DiceMixRng {
    pub fn new(&key: &[u8; 32]) -> DiceMixRng {
        let mut dc_rng = DiceMixRng { chacha : ChaChaRng::from_seed(key) };
        dc_rng.prepare_round(0);
        dc_rng
    }

    pub fn prepare_round(&mut self, round: u32) {
        // This sets
        //   blockcount = 1 (We skip the first block because it's typically used for Poly1305)
        //   nonce = round
        self.chacha.set_word_pos(1 as u128);
        self.chacha.set_stream(round as u64);
    }
}

impl RngCore for DiceMixRng {
    fn next_u32(&mut self) -> u32 {
        self.chacha.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.chacha.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.chacha.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.chacha.try_fill_bytes(dest)
    }
}
