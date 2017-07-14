use bytes::BytesMut;
use secp256k1::key::PublicKey;
use secp256k1::Secp256k1;
use secp256k1::Signature;
use std::io;
use tokio_io::codec::{Encoder, Decoder};

/// Network messages take the following form:
///
/// | Field   | Length | Description                                                   |
/// |---------|--------|---------------------------------------------------------------|
/// | Magic   | 4      | Fixed magic bytes for identifying network messages            |
/// | Header  | 1      | Message header                                                |
/// | Payload | ...    | Message payload                                               |
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
    fn from_bytes<'a>(
        buf: &'a [u8],
        secp256k1: &Secp256k1,
    ) -> io::Result<Option<(Message, &'a [u8])>> {
        // Magic
        if buf.len() < 4 {
            return Ok(None);
        }
        let (magic, buf) = buf.split_at(4);
        if !magic.starts_with(&[0x68, 0x1e, 0x58, 0x12]) {
            return Err(io::Error::new(io::ErrorKind::Other, "Wrong magic bytes"));
        }
        let (header, buf) = match try!(Header::from_bytes(buf)) {
            None => return Ok(None),
            Some((header, buf)) => (header, buf),
        };
        let (payload, buf) = match try!(Payload::from_bytes(buf, secp256k1)) {
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
    fn to_bytes(&self, buf: &mut BytesMut, secp256k1: &Secp256k1) -> io::Result<()> {
        buf.extend(vec![0x68, 0x1e, 0x58, 0x12]);
        self.header.to_bytes(buf)?;
        self.payload.to_bytes(buf, secp256k1)?;
        Ok(())
    }
}

/// Headers take the following form:
///
/// | Field   | Length | Description                                                   |
/// |---------|--------|---------------------------------------------------------------|
/// | Version | 1      | Protocol version                                              |
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
    fn from_bytes<'a>(buf: &'a [u8]) -> io::Result<Option<(Header, &'a [u8])>> {
        if buf.len() < 1 {
            return Ok(None);
        }
        let (ver, buf) = buf.split_at(1);
        return Ok(Some((Header { protocol_version: ver[0] }, buf)));
    }
    fn to_bytes(&self, buf: &mut BytesMut) -> io::Result<()> {
        buf.extend(vec![self.protocol_version]);
        Ok(())
    }
}

/// Payloads take the following form:
///
/// | Field   | Length | Description                                                   |
/// |---------|--------|---------------------------------------------------------------|
/// | Variant | 1      | Determines which payload variant this is                      |
/// | Variant | ...    | The actual variant                                            |
///
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Payload {
    /// KeyExchange take the following form:
    ///
    /// | Field      | Length | Description                                                        |
    /// |------------|--------|--------------------------------------------------------------------|
    /// | Signature  | 64     | Compressed ECDSA signature over the following public key using the |
    /// |            |        | long term  public key                                              |
    /// | Public Key | 33     | Compressed ephemeral public key                                    |
    ///
    KeyExchange {
        signature: Signature,
        public_key: PublicKey,
    },
}

fn from_bytes_keyexchange<'a>(
    buf: &'a [u8],
    secp256k1: &Secp256k1,
) -> io::Result<Option<(Payload, &'a [u8])>> {
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
    let (public_key, buf) = buf.split_at(33);
    let public_key = {
        match PublicKey::from_slice(secp256k1, public_key) {
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
        Payload::KeyExchange {
            signature: signature,
            public_key: public_key,
        },
        buf,
    )));
}


fn to_bytes_keyexchange(
    signature: &Signature,
    public_key: &PublicKey,
    buf: &mut BytesMut,
    secp256k1: &Secp256k1,
) -> io::Result<()> {
    buf.extend(vec![0x00]);
    buf.extend(signature.serialize_compact(secp256k1).iter());
    buf.extend(public_key.serialize_vec(secp256k1, true));
    Ok(())
}

impl Payload {
    /// Takes a byte slice and builds a Payload. Returns same as MessageCodec::decode plus the
    /// remaining (unconsumed) buffer.
    fn from_bytes<'a>(
        buf: &'a [u8],
        secp256k1: &Secp256k1,
    ) -> io::Result<Option<(Payload, &'a [u8])>> {
        if buf.len() < 1 {
            return Ok(None);
        }
        let (variant, buf) = buf.split_at(1);
        match variant[0] {
            0 => return from_bytes_keyexchange(buf, secp256k1),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Unknown payload variant",
                ))
            }
        }
    }
    fn to_bytes(&self, buf: &mut BytesMut, secp256k1: &Secp256k1) -> io::Result<()> {
        match self {
            &Payload::KeyExchange {
                signature,
                public_key,
            } => to_bytes_keyexchange(&signature, &public_key, buf, secp256k1),
        }
    }
}

/// Codec implementing the Encoder and Decoder trait for
/// Messages.
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
        let (msg, remaining_buf_len) = match try!(Message::from_bytes(&buf[..], &self.secp256k1)) {
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
        msg.to_bytes(buf, &self.secp256k1)
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
        buf.extend([0x68, 0x1e, 0x58, 0x12].iter());
        assert_eq!(codec.decode(&mut buf).unwrap(), None);
        assert_eq!(buf.len(), 4);
    }

    #[test]
    fn roundtrip() {
        // Create secret key, public key, message and signature
        let secp256k1 = Secp256k1::new();
        let slice: [u8; 32] = [0xab; 32];
        let sk = SecretKey::from_slice(&secp256k1, &slice).unwrap();
        let pk = PublicKey::from_secret_key(&secp256k1, &sk).unwrap();
        assert!(pk.is_valid());
        let slice: [u8; 32] = [0x01; 32];
        let msg = secp256k1::Message::from_slice(&slice).unwrap();
        let sig = secp256k1.sign(&msg, &sk).unwrap();

        // Create Message and encode and decode
        let msg = Message::new(
            Header::new(0),
            Payload::KeyExchange {
                signature: sig,
                public_key: pk,
            },
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
