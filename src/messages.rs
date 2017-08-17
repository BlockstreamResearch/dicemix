//! Protocol messages
//!
//! All protocol messages are serialized by serde according to the bincode data format. For
//! transmission on the wire, `tokio_io::codec::length_delimited` is used to prepend protocol
//! messages by an additional length header, thereby creating frames. It is crucial to
//!
//! The main type `Message` and the types in its fields are dump containers, which are not
//! responsible for any protocol logic (except for syntactic validation including validation of
//! `PublicKey` and `SecretKey` fields). Consequently, all fields of `Message` and all fields of
//! its contained types such as `Header` and `Payload` are public.

pub use secp256k1::key::{PublicKey, SecretKey};
use ::{SessionId, PeerIndex, SymmetricKey, SequenceNum};
use field::Fp;

/// A protocol message
///
/// Protocol messages consist of a header and a payload.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Message {
    pub header: Header,
    pub payload: Payload,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Header {
    pub session_id: SessionId, // just for consistency checks
    pub peer_index: PeerIndex,
    pub sequence_num: SequenceNum, // just for consistency checks
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Payload {
    KeyExchange(KeyExchange),
    DcExponential(DcExponential),
    DcMain(DcMain),
    Blame(Blame),
    Confirm(Confirm),
    Reveal(Reveal),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct KeyExchange {
    pub ke_pk: PublicKey,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DcExponential {
    pub commitment: [u8; 32],
    pub dc_exp: Vec<Fp>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DcMain {
    pub ok: bool,
    pub dc_xor: Vec<Vec<u8>>,
    pub ke_pk: PublicKey,
    pub extension: Extension,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Extension {
    None,
    DcAddSecp256k1Scalar(/* TODO */),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Blame {
    pub ke_sk: SecretKey,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Confirm {
    pub data: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Reveal {
    pub keys: Vec<(PeerIndex, SymmetricKey)>,
}

#[cfg(test)]
mod tests {
    use secp256k1::key::SecretKey;
    use bincode;

    use super::*;

    #[test]
    fn roundtrip_keyexchange() {
        let slice: [u8; 32] = [0x4f; 32];
        let sk = SecretKey::from_slice(&::SECP256K1, &slice).unwrap();
        let ke_pk = PublicKey::from_secret_key(&::SECP256K1, &sk).unwrap();
        assert!(ke_pk.is_valid());

        let payload = Payload::KeyExchange(KeyExchange {
            ke_pk: ke_pk,
        });

        roundtrip_serde_bincode(payload);
    }

    #[cfg(test)]
    fn roundtrip_serde_bincode(payload1: Payload) {
        let ser = bincode::serialize(&payload1, bincode::Infinite).unwrap();
        let payload2 : Payload = bincode::deserialize(&ser).unwrap();
        assert_eq!(payload1, payload2);
    }
}
