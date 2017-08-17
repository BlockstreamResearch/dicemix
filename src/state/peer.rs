use super::*;

/// Public information about a peer
#[derive(Clone, Debug)]
pub struct Peer {
    peer_id: PeerId,
    ltvk: PublicKey,
    next_kepk: Option<PublicKey>,
    history: RunHistory,
}

impl Peer {
    pub fn new(peer_id: PeerId, ltvk: PublicKey, next_kepk: PublicKey, num_peers: usize) -> Self {
        Peer {
            peer_id: peer_id,
            ltvk: ltvk,
            next_kepk: Some(next_kepk),
            history: RunHistory::new(num_peers),
        }
    }

    pub fn push_kepk(&mut self, kepk: PublicKey) {
        assert!(self.next_kepk.is_none());
        self.next_kepk = Some(kepk);
    }

    pub fn pop_kepk(&mut self) -> PublicKey {
        let was = self.next_kepk.unwrap();
        self.next_kepk = None;
        was
    }

    pub fn ltvk(&self) -> &PublicKey {
        &self.ltvk
    }
}
