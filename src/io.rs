///! There are two types of broadcast mechanisms.
///!
///! A simple broadcast mechanism just relays (sender, timestamp, message) triples,
///! possibly implementing rate limiting.
///!
///! A validating broadcast mechanism
///!   * relays (sender, message) pairs,
///!   * notifies the peers about timeout events (i.e., offline peers),
///!   * joins the protocol passively as an observer,
///!   * and excludes disruptive peers.
///!
///! Even a validating broadcast mechanism does not guarantee that it relays only valid messages.
///! For example, it may relay an invalid message before it processes it to avoid delays.
///! Moreover, a validating broadcast mechanism may replace messages by other equivalent,
///! e.g., it may replace an invalid message by a shorter invalid message or by a timeout
///! notification.
///!
///! How senders are identified depends on the broadcast mechanism, e.g., an IRC server could
///! use a nickname as a sender id. The peer-side implementation of the broadcast mechanism
///! is resposible for translating the sender id into a peer id by adding a header to the
///! incoming message (or equivalently, by rejecting messages with a wrong peer id in the
///! header, if the header is added by the by the sending peer).

use std::io;
use futures::{Stream, Poll, Async};
use bytes::Bytes;
use bincode;
use secp256k1;
use blake2::{Blake2s, Digest};

use messages::{Message, Payload, PublicKey};
use ::{SessionId, PeerIndex, SequenceNum};

const MAGIC_MESSAGE_PREFIX : &[u8; 32] = b"DICEMIX_SIGNED_MESSAGE__________";

pub enum IncomingPayload {
    Valid(Payload),
    Invalid,
}

/// Wrapper for FramedRead that parses and authenticates messages.
///
/// Errors in the stream indicate always I/O errors.
/// Invalid messages are indicated by a stream item with `IncomingPayload::Invalid`
/// as second component.
pub struct ReadAuthenticatedPayloads<'a, T: Stream<Item = (PeerIndex, Bytes)>> {
    inner: T,
    session_id: SessionId,
    ltvks: &'a Vec<PublicKey>,
    sequence_num: SequenceNum,
}

impl<'a, T> ReadAuthenticatedPayloads<'a, T>
    where T: Stream<Item = (PeerIndex, Bytes)>
{
    /// Creates a new `ReadAuthenticatedPayloads`.
    ///
    /// The underlying stream is responsible for handling messages
    ///   * from excluded peers and
    ///   * from peers that have sent a message already in this round,
    /// e.g., by returning an error or just ignoring the message.
    // TODO This means we need to forward the call to advance_round() to the underlying stream.
    // Also there should be an exclude() function, and we need to delegate calls to this function
    // to the underlying stream, too.
    fn new(inner: T, session_id: SessionId, ltvks: &'a Vec<PublicKey>) -> Self {
        Self {
            inner: inner,
            session_id: session_id,
            ltvks: ltvks,
            sequence_num: 0,
        }
    }

    // TODO We should export access to set_max_frame_length() of the underlying
    // length_delimited::FramedRead (and actually assume that it is of this type).
    // First, we need an adapter Stream<PeerIndex, T>, which relays a constant PeerIndex
    // and delegates every call to an inner Stream<T>.
    fn advance_round(&mut self, /* max_frame_length: usize */) {
        self.sequence_num += 1;
        // self.inner.set_max_frame_length(max_frame_length);
    }
}
impl<'a, T> Stream for ReadAuthenticatedPayloads<'a, T>
    where T: Stream<Item = (PeerIndex, Bytes), Error = io::Error>,
{
    type Item = (PeerIndex, IncomingPayload);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match try_ready!(self.inner.poll()) {
            None => Ok(Async::Ready(None)),
            Some((peer_index, bytes)) => {
                // Return value indicating an invalid message
                let invalid = Ok(Async::Ready(Some((peer_index, IncomingPayload::Invalid))));

                // Check size
                if bytes.len() < secp256k1::constants::COMPACT_SIGNATURE_SIZE {
                    // TODO log: format!("message too short to extract header and signature, only {} bytes", bytes.len()))
                    return invalid;
                }

                // Split bytes
                let split_pos = bytes.len() - secp256k1::constants::COMPACT_SIGNATURE_SIZE;
                let (msg_bytes, sig_bytes) = bytes.split_at(split_pos);

                // Try to deserialize
                let sig_result = secp256k1::Signature::from_compact(&::SECP256K1, &sig_bytes);
                let msg_result : bincode::Result<Message> = bincode::deserialize(&msg_bytes);

                // Create message digest
                let mut hasher = new_prefixed_hasher();
                hasher.input(&bytes);

                match (msg_result, sig_result) {
                    (Err(err), _) => {
                        // TODO log: cannot parse message
                        invalid
                    },
                    (_, Err(err)) => {
                        // TODO log: cannot deserialize signature
                        invalid
                    },
                    (Ok(Message { header: hdr, payload: pay }), Ok(sig)) => {
                        // Check session ID
                        if hdr.session_id != self.session_id {
                            // TODO log: format!("unexpected session ID {})", hdr.session_id)
                            return invalid;
                        }

                        // Check sequence number
                        if hdr.sequence_num != self.sequence_num {
                            // TODO log: format!("wrong sequence number (got {}, expected {})", hdr.sequence_num, expected);
                            return invalid;
                        }

                        // Check peer index
                        if hdr.peer_index != peer_index {
                            // TODO log: format!("unexpected peer index {})", hdr.peer_index)
                            return invalid;
                        }

                        // Verify signature
                        let digest = secp256k1::Message::from_slice(&hasher.result()).unwrap();
                        // TODO These "as" casts
                        //   * assume that usize is at least u32 and
                        //   * are ugly because they will be everywhere.
                        // The underlying stream should cast safely to usize (using From)
                        // as soon as it receives a message.
                        match ::SECP256K1.verify(&digest, &sig, &self.ltvks[peer_index as usize]) {
                            Err(err) => {
                                // TODO log
                                invalid
                            },
                            Ok(()) => {
                                Ok(Async::Ready(Some((peer_index, IncomingPayload::Valid(pay)))))
                            },
                        }
                    }
                }
            },
        }
    }
}

fn new_prefixed_hasher() -> Blake2s {
    let mut hasher = Blake2s::default();
    // We get exactly one block if we input the prefix twice (2 * 32 bytes).
    for _ in 0..1 {
        hasher.input(MAGIC_MESSAGE_PREFIX);
    }
    hasher
}

