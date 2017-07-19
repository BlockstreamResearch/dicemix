use bytes::BytesMut;
use secp256k1::key::PublicKey;
use secp256k1::Secp256k1;
use secp256k1::Signature;
use std::io;
use tokio_io::codec::{Encoder, Decoder};

const MAGIC: [u8; 4] = [0x68, 0x1e, 0x58, 0x12];

/// Network messages take the following form:
///
/// | Field   | Length | Description                                                   |
/// |---------|--------|---------------------------------------------------------------|
/// | Magic   | 4      | Fixed magic bytes for identifying network messages            |
/// | header  | 1      | Message header                                                |
/// | payload | ...    | Message payload                                               |
///
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Message {
    header: Header,
    payload: Payload,
}

impl Message {
    fn new(header: Header, payload: Payload) -> Message {
        Message {
            header: header,
            payload: payload,
        }
    }
    /// Takes a byte slice and builds a Message. Returns same as MessageCodec::decode plus the
    /// remaining (unconsumed) buffer.
    fn decode<'a>(buf: &'a [u8], secp256k1: &Secp256k1) -> io::Result<Option<(Message, &'a [u8])>> {
        // Magic
        if buf.len() < 4 {
            return Ok(None);
        }
        let (magic, buf) = buf.split_at(4);
        if magic[..4] != MAGIC {
            return Err(io::Error::new(io::ErrorKind::Other, "Wrong magic bytes"));
        }
        let (header, buf) = match try!(Header::decode(buf)) {
            None => return Ok(None),
            Some((header, buf)) => (header, buf),
        };
        let (payload, buf) = match try!(Payload::decode(buf, secp256k1)) {
            None => return Ok(None),
            Some((payload, buf)) => (payload, buf),
        };
        return Ok(Some((
            Message {
                header: header,
                payload: payload,
            },
            buf,
        )));
    }
    fn encode(&self, buf: &mut BytesMut, secp256k1: &Secp256k1) -> io::Result<()> {
        buf.extend(MAGIC.iter());
        self.header.encode(buf)?;
        self.payload.encode(buf, secp256k1)?;
        Ok(())
    }
}

/// Headers take the following form:
///
/// | Field            | Length | Description                                            |
/// |------------------|--------|--------------------------------------------------------|
/// | protocol_version | 1      | Protocol version                                       |
///
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct Header {
    protocol_version: u8,
}

impl Header {
    fn new(protocol_version: u8) -> Header {
        Header { protocol_version: protocol_version }
    }
    /// Takes a byte slice and builds a Header. Returns same as MessageCodec::decode plus the
    /// remaining (unconsumed) buffer.
    fn decode<'a>(buf: &'a [u8]) -> io::Result<Option<(Header, &'a [u8])>> {
        if buf.len() < 1 {
            return Ok(None);
        }
        let (ver, buf) = buf.split_at(1);
        return Ok(Some((Header { protocol_version: ver[0] }, buf)));
    }
    fn encode(&self, buf: &mut BytesMut) -> io::Result<()> {
        buf.extend(vec![self.protocol_version]);
        Ok(())
    }
}

/// Payloads take the following form:
///
/// | Field   | Length | Description                                                   |
/// |---------|--------|---------------------------------------------------------------|
/// | Variant | 1      | Determines which payload variant this is                      |
/// |         |        |     0: KeyExchange                                            |
/// | Payload | ...    | The actual payload                                            |
///
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Payload {
    KeyExchange(KeyExchange),
}

impl Payload {
    /// Takes a byte slice and builds a Payload. Returns same as MessageCodec::decode plus the
    /// remaining (unconsumed) buffer.
    fn decode<'a>(buf: &'a [u8], secp256k1: &Secp256k1) -> io::Result<Option<(Payload, &'a [u8])>> {
        if buf.len() < 1 {
            return Ok(None);
        }
        let (variant, buf) = buf.split_at(1);
        match variant[0] {
            0 => return KeyExchange::decode(buf, secp256k1),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Unknown payload variant",
                ))
            }
        }
    }
    fn encode(&self, buf: &mut BytesMut, secp256k1: &Secp256k1) -> io::Result<()> {
        match self {
            &Payload::KeyExchange(key_exchange) => key_exchange.encode(buf, secp256k1),
        }
    }
}

/// KeyExchange take the following form:
///
/// | Field      | Length | Description                                                        |
/// |------------|--------|--------------------------------------------------------------------|
/// | signature  | 64     | Compressed ECDSA signature over ke_pk key using the long term      |
/// |            |        | public key                                                         |
/// | ke_pk      | 33     | Compressed ephemeral public key                                    |
///
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct KeyExchange {
    signature: Signature,
    ke_pk: PublicKey,
}

impl KeyExchange {
    fn new(signature: Signature, ke_pk: PublicKey) -> KeyExchange {
        KeyExchange {
            signature: signature,
            ke_pk: ke_pk,
        }
    }
    fn decode<'a>(buf: &'a [u8], secp256k1: &Secp256k1) -> io::Result<Option<(Payload, &'a [u8])>> {
        if buf.len() < 64 + 33 {
            return Ok(None);
        }
        let (signature, buf) = buf.split_at(64);
        let signature = {
            match Signature::from_compact(secp256k1, signature) {
                Ok(sig) => sig,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Signature parsing failed",
                    ))
                }
            }
        };
        let (ke_pk, buf) = buf.split_at(33);
        let ke_pk = {
            match PublicKey::from_slice(secp256k1, ke_pk) {
                Ok(pk) => pk,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Public key parsing failed",
                    ))
                }
            }
        };
        return Ok(Some((
            Payload::KeyExchange(KeyExchange::new(signature, ke_pk)),
            buf,
        )));
    }

    fn encode(&self, buf: &mut BytesMut, secp256k1: &Secp256k1) -> io::Result<()> {
        buf.extend(vec![0x00]);
        buf.extend(self.signature.serialize_compact(secp256k1).iter());
        buf.extend(self.ke_pk.serialize_vec(secp256k1, true));
        Ok(())
    }
}

/// Codec implementing the Encoder and Decoder trait for Messages.
pub struct MessageCodec {
    secp256k1: Secp256k1,
}

impl Decoder for MessageCodec {
    type Item = Message;
    type Error = io::Error;

    /// Takes a byte buffer and returns Ok(Some(Message)) if everything went ok.
    /// In that case `buf` is truncated by the bytes that have been read from it.
    /// If the `buf` isn't large enough for the full message to be read, `buf` is
    /// not mutated and Ok(None) is returned. If there's an error during parsing
    /// Err() is returned.
    fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<Message>> {
        let (msg, remaining_buf_len) = match try!(Message::decode(&buf[..], &self.secp256k1)) {
            None => return Ok(None),
            Some((msg, remaining_buf)) => (msg, remaining_buf.len()),
        };
        let consumed = buf.len() - remaining_buf_len;
        buf.split_to(consumed);
        return Ok(Some(msg));
    }
}

impl Encoder for MessageCodec {
    type Item = Message;
    type Error = io::Error;

    /// Writes a message to `buf`.
    fn encode(&mut self, msg: Message, buf: &mut BytesMut) -> io::Result<()> {
        msg.encode(buf, &self.secp256k1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1;
    use secp256k1::key::SecretKey;

    #[test]
    fn decode() {
        let mut codec = MessageCodec { secp256k1: Secp256k1::new() };
        let mut buf = BytesMut::new();

        // Not enough bytes available to determine if magic is correct
        buf.extend([0].iter());
        assert_eq!(codec.decode(&mut buf).unwrap(), None);
        assert_eq!(buf.len(), 1);

        // Wrong magic
        buf.clear();
        buf.extend([0, 0, 0, 0].iter());
        assert!(codec.decode(&mut buf).is_err());

        // Correct magic, but too short
        buf.clear();
        buf.extend(MAGIC.iter());
        assert_eq!(codec.decode(&mut buf).unwrap(), None);
        assert_eq!(buf.len(), 4);
    }
    #[test]
    fn decode_keyexchange() {
        let mut codec = MessageCodec { secp256k1: Secp256k1::new() };
        let mut buf = BytesMut::new();

        buf.clear();
        buf.extend(MAGIC.iter());
        let variant = 0;
        buf.extend([variant].iter());
        let protocol_version = 0;
        buf.extend([protocol_version].iter());
        let signature: [u8; 64] = [0xab; 64];
        buf.extend(signature.iter());
        let ke_pk: [u8; 33] = [0x02; 33];
        buf.extend(ke_pk.iter());
        let mut buf_copy = buf.clone();
        assert!(codec.decode(&mut buf).unwrap().is_some());

        // Verify that an invalid public key `ke_pk` results in an error.
        let buf_len = buf_copy.len();
        buf_copy.truncate(buf_len - 1);
        buf_copy.extend([0x04].iter());
        assert_eq!(
            codec
                .decode(&mut buf_copy)
                .unwrap_err()
                .get_ref()
                .unwrap()
                .description(),
            "Public key parsing failed"
        );
    }

    #[test]
    fn roundtrip() {
        // Create secret key, public key, message and signature
        let secp256k1 = Secp256k1::new();
        let slice: [u8; 32] = [0xab; 32];
        let sk = SecretKey::from_slice(&secp256k1, &slice).unwrap();
        let ke_pk = PublicKey::from_secret_key(&secp256k1, &sk).unwrap();
        assert!(ke_pk.is_valid());
        let slice: [u8; 32] = [0x01; 32];
        let msg = secp256k1::Message::from_slice(&slice).unwrap();
        let sig = secp256k1.sign(&msg, &sk).unwrap();

        // Create Message and encode and decode
        let msg = Message::new(
            Header::new(0),
            Payload::KeyExchange(KeyExchange::new(sig, ke_pk)),
        );
        let mut codec = MessageCodec { secp256k1: Secp256k1::new() };
        let mut buf = BytesMut::new();
        codec.encode(msg.clone(), &mut buf).unwrap();
        codec.encode(msg.clone(), &mut buf).unwrap();
        assert_eq!(codec.decode(&mut buf).unwrap().unwrap(), msg);
        assert_eq!(codec.decode(&mut buf).unwrap().unwrap(), msg);
        assert_eq!(buf.len(), 0);
    }
}
