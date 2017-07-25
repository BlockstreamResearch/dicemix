//! Protocol messages
//!
//! All protocol messages are serialized by serde according to the bincode data format. For
//! transmission on the wire, tokio_io::codec::length_delimited is used to prepend protocol
//! messages by an additional length header, thereby creating frames.

use secp256k1::key::{PublicKey, SecretKey};
use secp256k1::Signature;
use vec_map::VecMap;

/// A protocol message
///
/// Protocol messages consist of a header and a payload.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Message {
    header: Header,
    payload: Payload,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct Header {
    session_id: SessionId,
    peer_id: PeerId,
    signature: Signature,
}

// FIXME We store the peer ID in two [u8; 32], as this allows us to derive various traits.
// This can be resolved in the future using const generics, see the corresponding Rust RFC:
// https://github.com/rust-lang/rfcs/pull/2000/files
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct PeerId([u8; 32], [u8; 32]);

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct SessionId([u8; 32]);

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
enum Payload {
    KeyExchange(KeyExchange),
    DcExponential(DcExponential),
    DcXor(DcXor),
    // TODO: DcAddSecp256k1Scalar
    Blame(Blame),
    Confirm(Confirm),
    Reveal(Reveal),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct KeyExchange {
    ke_pk: PublicKey,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct DcExponential {
    commitment: [u8; 32],
    dc_exp: Vec<[u8; 16]>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct DcXor {
    ok: bool,
    dc_xor: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct Blame {
    ke_sk: SecretKey,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct Confirm {
    data: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct Reveal {
    keys: VecMap<[u8; 16]>,
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
