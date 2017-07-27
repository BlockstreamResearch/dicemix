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

use secp256k1::key::{PublicKey, SecretKey};
use secp256k1::Signature;
use ::{SessionId, PeerIndex, SymmetricKey, SequenceNum};

/// A protocol message
///
/// Protocol messages consist of a header and a payload.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub(crate) struct Message {
    pub header: Header,
    pub payload: Payload,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub(crate) struct Header {
    pub session_id: SessionId,
    pub peer_index: PeerIndex,
    pub sequence_num: SequenceNum,
    pub signature: Signature,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub(crate) enum Payload {
    KeyExchange(KeyExchange),
    DcExponential(DcExponential),
    DcXor(DcXor),
    DcAddSecp256k1Scalar(DcAddSecp256k1Scalar),
    Blame(Blame),
    Confirm(Confirm),
    Reveal(Reveal),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub(crate) struct KeyExchange {
    pub ke_pk: PublicKey,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub(crate) struct DcExponential {
    pub commitment: [u8; 32],
    pub dc_exp: Vec<[u8; 16]>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub(crate) struct DcXor {
    pub ok: bool,
    pub dc_xor: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub(crate) struct DcAddSecp256k1Scalar {
    // FIXME
    pub dc_add_secp256k1_scalar: (),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub(crate) struct Blame {
    pub ke_sk: SecretKey,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Confirm {
    pub data: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub(crate) struct Reveal {
    pub keys: Vec<(PeerIndex, SymmetricKey)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::key::SecretKey;

    use std::io::Cursor;
    use tokio_io::codec::length_delimited;
    use tokio_serde_bincode::{ReadBincode, WriteBincode};
    use futures::sink::Sink;
    use futures::{Future, Stream};

    #[test]
    fn roundtrip_serde_bincode() {
        // Create secret key, public key, message digest and signature
        let slice: [u8; 32] = [0xab; 32];
        let sk = SecretKey::from_slice(&::SECP256K1, &slice).unwrap();
        let ke_pk = PublicKey::from_secret_key(&::SECP256K1, &sk).unwrap();
        assert!(ke_pk.is_valid());
        let slice: [u8; 32] = [0x01; 32];
        let msg = ::secp256k1::Message::from_slice(&slice).unwrap();
        let sig = ::SECP256K1.sign(&msg, &sk).unwrap();

        // Create message
        let msg1 = Message {
            header: Header {
                peer_id: PeerId([17; 32], [7; 32]),
                session_id: SessionId([56; 32]),
                signature: sig,
            },
            payload: Payload::KeyExchange(KeyExchange {
                ke_pk: ke_pk,
            }),
        };

        // Write message
        let pipe = Cursor::new(Vec::new());
        let write = WriteBincode::new(length_delimited::FramedWrite::new(pipe));
        let write = write.send(msg1.clone()).wait().unwrap();

        // Read message again
        let pipe = Cursor::new(write.into_inner().into_inner().into_inner());
        let read = ReadBincode::<_ ,Message>::new(length_delimited::FramedRead::new(pipe));
        let msg2 = read.wait().next().unwrap().unwrap();

        assert_eq!(msg1, msg2);
    }
}
