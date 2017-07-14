use std::collections::VecDeque;
use secp256k1::key::PublicKey;

#[derive(Clone)]
struct Peer<'a> {
    ltvk: &'a PublicKey,
    kepks: VecDeque<PublicKey>,
}

impl<'a> Peer<'a> {
    pub fn new(ltvk: &'a PublicKey) -> Self {
        Peer {
            ltvk: ltvk,
            kepks: VecDeque::with_capacity(2),
        }
    }

    pub fn push_kepk(&mut self, kepk: PublicKey) {
        self.kepks.push_back(kepk);
        assert!(self.kepks.len() <= 2);
    }

    pub fn get_kepk(&self) -> &PublicKey {
        self.kepks.get(0).unwrap()
    }

    pub fn shift_keys(&mut self) {
        self.kepks.pop_front().unwrap();
    }
}
