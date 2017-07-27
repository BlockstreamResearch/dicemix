use super::*;

/// Public information about a peer
#[derive(Clone, Debug)]
pub struct Peer {
    peer_id: PeerId,
    ltvk: PublicKey,
    kepks: VecDeque<PublicKey>,
    history: RunHistory,
}

impl Peer {
    pub fn new(peer_id: PeerId, ltvk: PublicKey, num_peers: usize) -> Self {
        Peer {
            peer_id: peer_id,
            ltvk: ltvk,
            kepks: VecDeque::with_capacity(2),
            history: RunHistory::new(num_peers),
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
