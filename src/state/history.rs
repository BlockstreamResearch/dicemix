use super::*;

/// A history of the payloads sent by a peer in a single run
///
/// After a peer revealed the ephemeral secret key, this data is used to verify that the peer has
/// sent correct messages. The ephemeral public key is not stored here, because it is stored in the
/// Peer struct anyway.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct RunHistory {
    dc_exponential: Option<DcExponential>,
    dc_xor: Option<DcXor>,
    dc_add_secp256k1_scalar: Option<DcAddSecp256k1Scalar>,

    revealed_symmetric_keys: VecMap<SymmetricKey>,
}

impl RunHistory {
    pub fn new(num_peers: usize) -> Self {
        RunHistory {
            dc_exponential: None,
            dc_xor: None,
            dc_add_secp256k1_scalar: None,

            revealed_symmetric_keys: VecMap::with_capacity(num_peers),
        }
    }

    pub fn record_payload(&mut self, payload: Payload) {
        match payload {
            Payload::DcExponential(inner) => { self.dc_exponential = Some(inner) },
            Payload::DcXor(inner) => { self.dc_xor = Some(inner) },
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

    pub fn dc_xor(&self) -> &Option<DcXor> {
        &self.dc_xor
    }

    pub fn dc_add_secp256k1_scalar(&self) -> &Option<DcAddSecp256k1Scalar> {
        &self.dc_add_secp256k1_scalar
    }

    #[inline]
    fn consistent(&self) -> bool {
        if self.dc_exponential.is_some() && self.revealed_symmetric_keys.is_empty() {
            return false;
        }
        match (self.dc_exponential.is_some(),
               self.dc_xor.is_some(),
               self.dc_add_secp256k1_scalar.is_some()) {
            (_, false, false) => true,
            (true, true, _) => true,
            _ => false,
        }
    }
}

