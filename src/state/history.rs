use super::*;

/// A history of the payloads sent by a peer in a single run
///
/// After a peer revealed the ephemeral secret key, this data is used to verify that the peer has
/// sent correct messages. The ephemeral public key is not stored here, because it is stored in the
/// Peer struct anyway.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct RunHistory {
    dc_exponential: Option<DcExponential>,
    dc_main: Option<DcMain>,

    revealed_symmetric_keys: VecMap<SymmetricKey>,
}

impl RunHistory {
    pub fn new(num_peers: usize) -> Self {
        RunHistory {
            dc_exponential: None,
            dc_main: None,

            revealed_symmetric_keys: VecMap::with_capacity(num_peers),
        }
    }

    pub fn record_payload(&mut self, payload: Payload) {
        match payload {
            Payload::DcExponential(inner) => { self.dc_exponential = Some(inner) },
            Payload::DcMain(inner) => { self.dc_main = Some(inner) },
            Payload::Reveal(Reveal { keys }) => {
                for (i, k) in keys {
                    // Record the key and assert that none has already been recorded for that peer.
                    // A "double-reveal" is supposed be rejected by the core logic.
                    let was = self.revealed_symmetric_keys.insert(i as usize, k);
                    assert!(was.is_none(), "Key for peer {} has already been recorded.", i)
                }
            },
            _ => { },
        };
        assert!(self.consistent());
    }

    pub fn dc_exponential(&self) -> &Option<DcExponential> {
        &self.dc_exponential
    }

    pub fn dc_main(&self) -> &Option<DcMain> {
        &self.dc_main
    }

    #[inline]
    fn consistent(&self) -> bool {
        if self.dc_exponential.is_some() && self.revealed_symmetric_keys.is_empty() {
            return false;
        }
        match (self.dc_exponential.is_some(),
               self.dc_main.is_some()) {
            (_, false) => true,
            (true,  _) => true,
            _ => false,
        }
    }
}

