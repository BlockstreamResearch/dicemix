use rand::{Rng, SeedableRng, ChaChaRng};
use std::io::Cursor;
use byteorder::{LittleEndian, ReadBytesExt};

#[derive(Copy, Clone)]
pub struct DiceMixRng {
    chacha : ChaChaRng
}

impl DiceMixRng {
    pub fn new(&key: &[u8; 32]) -> DiceMixRng {
        let mut key32: [u32; 8] = [0; 8];
        let mut reader = Cursor::new(key);
        for x in &mut key32 {
            *x = reader.read_u32::<LittleEndian>().unwrap();
        }
        let mut dc_rng = DiceMixRng { chacha : ChaChaRng::from_seed(&key32) };
        dc_rng.prepare_round(0);
        dc_rng
    }

    pub fn prepare_round(&mut self, round: u32) {
        // This sets
        //   blockcount = 1 (We skip the first block because it's typically used for Poly1305)
        //   nonce = round
        self.chacha.set_counter(1u64, round as u64);
    }
}

impl Rng for DiceMixRng {
    fn next_u32(&mut self) -> u32 {
        self.chacha.next_u32()
    }
}
