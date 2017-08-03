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
use field::Fp;

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
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub(crate) struct SignedMessage {
    pub message: Message,
    pub signature: Signature,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub(crate) enum Payload {
    KeyExchange(KeyExchange),
    DcExponential(DcExponential),
    DcMain(DcMain),
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
    pub dc_exp: Vec<Fp>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub(crate) struct DcMain {
    pub ok: bool,
    pub dc_xor: Vec<Vec<u8>>,
    pub ke_pk: PublicKey,
    pub extension: Extension,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub(crate) enum Extension {
    None,
    DcAddSecp256k1Scalar(/* TODO */),
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
    use std::io::Cursor;
    use tokio_io::codec::length_delimited;
    use tokio_serde_bincode::{ReadBincode, WriteBincode};
    use futures::sink::Sink;
    use futures::{Future, Stream};

    use super::*;
    use secp256k1::key::SecretKey;

    #[cfg(test)]
    fn roundtrip_serde_bincode(payload: Payload) {
        let msg1 = Message {
            header: dummy_header(),
            payload: payload,
        }.add_signature();

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

    #[test]
    fn roundtrip_dcexponential() {
        let payload = Payload::DcExponential(DcExponential {
            commitment: [9; 32],
            dc_exp: vec![Fp::from_u127(Fp::prime()), Fp::from_u127(0), Fp::from_u127(656)],
        });

        roundtrip_serde_bincode(payload);
    }

    #[cfg(test)]
    fn dummy_header() -> Header {
        Header {
            peer_index: 2,
            session_id: SessionId([56; 32]),
            sequence_num: 14,
        }
    }

    #[cfg(test)]
    fn sign(msg: Message) -> SignedMessage {
        // Create secret key, public key, message digest and signature
        let slice: [u8; 32] = [0xab; 32];
        let sk = SecretKey::from_slice(&::SECP256K1, &slice).unwrap();
        let slice: [u8; 32] = [0x01; 32];
        let digest = ::secp256k1::Message::from_slice(&slice).unwrap();
        let sig = ::SECP256K1.sign(&digest, &sk).unwrap();
        SignedMessage {
            message: msg,
            signature: sig,
        }
    }
}
