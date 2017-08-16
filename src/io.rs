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
use vec_map::VecMap;

use messages::{Message, Header, Payload};
use ::{SessionId, PeerIndex, SequenceNum};
use state::peer::Peer;

const MAGIC_MESSAGE_PREFIX : &[u8; 32] = b"DICEMIX_SIGNED_MESSAGE__________";

pub enum IncomingMessage {
    Valid(Payload),
    Invalid,
}

// TODO We should export access to set_max_frame_length() of the underlying
// length_delimited::FramedRead (and actually assume that it is of this type).

/// Wrapper for FramedRead that parses and authenticates messages.
///
/// Errors in the stream indicate always I/O errors.
/// Invalid messages are indicated by a stream item with `IncomingMessage::Invalid`
/// as second component.
pub struct ReadAuthenticatedPayloads<'a, T: Stream<Item = (PeerIndex, Bytes)>> {
    inner: T,
    peers: &'a VecMap<Peer>,
    next_sequence_num: Vec<SequenceNum>,
}

impl<'a, T> ReadAuthenticatedPayloads<'a, T>
    where T: Stream<Item = (PeerIndex, Bytes)>
{
    /// Creates a new `ReadAuthenticatedPayloads`.
    fn new(inner: T, peers: &'a VecMap<Peer>) -> Self {
        Self {
            inner: inner,
            peers: peers,
            next_sequence_num: vec![0; peers.len()],
        }
    }
}

impl<'a, T> Stream for ReadAuthenticatedPayloads<'a, T>
    where T: Stream<Item = (PeerIndex, Bytes), Error = io::Error>,
{
    type Item = (PeerIndex, IncomingMessage);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match try_ready!(self.inner.poll()) {
            None => Ok(Async::Ready(None)),
            Some((peer_index, bytes)) => {
                // Return value indicating an invalid message
                let invalid = Ok(Async::Ready(Some((peer_index, IncomingMessage::Invalid))));

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

                // TODO These "as" casts
                //   * assume that usize is at least u32 and
                //   * are ugly because they are everywhere.
                // We should cast safely to usize (using From) as soon as we receive a message.
                let peer_opt = self.peers.get(peer_index as usize);
                match (msg_result, sig_result, peer_opt) {
                    (Err(err), _, _) => {
                        // TODO log: cannot parse message
                        invalid
                    },
                    (_, Err(err), _) => {
                        // TODO log: cannot deserialize signature
                        invalid
                    },
                    (_, _, None) => {
                        debug_assert!(peer_index as usize <= self.next_sequence_num.len());
                        // TODO log: format!("excluded peer index {})", peer_index)
                        invalid
                    },
                    (Ok(Message { header: hdr, payload: pay }), Ok(sig), Some(peer)) => {
                        // Check sequence number
                        let expected = self.next_sequence_num[peer_index as usize];
                        if hdr.sequence_num != expected {
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
                        match ::SECP256K1.verify(&digest, &sig, &peer.ltvk()) {
                            Err(err) => {
                                // TODO log
                                invalid
                            },
                            Ok(()) => {
                                self.next_sequence_num[peer_index as usize] += 1;
                                Ok(Async::Ready(Some((peer_index, IncomingMessage::Valid(pay)))))
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

