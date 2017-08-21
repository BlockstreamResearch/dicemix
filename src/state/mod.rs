use std::cmp::Ordering;
use std::iter;
use secp256k1::key::PublicKey;
use bit_set::BitSet;

use messages::*;
use super::*;
use io::IncomingPayload;

use self::history::RunHistory;

mod history;

type PeerVec<T> = Vec<Option<T>>;

/// Static public information about a peer
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    peer_id: PeerId,
    ltvk: PublicKey,
}

impl Peer {
    pub fn new(peer_id: PeerId, ltvk: PublicKey) -> Self {
        Peer {
            peer_id: peer_id,
            ltvk: ltvk,
        }
    }
}

/// An execution of the DiceMix Light protocol
pub struct Execution<'a> {
    peers: &'a Vec<Peer>,
    next_kepks: PeerVec<PublicKey>,
    rsm: RunStateMachine,
}

impl<'a> Execution<'a> {
    pub fn new(peers: &'a Vec<Peer>, initial_kepks: Vec<PublicKey>) -> Self {
        let num_peers = peers.len();

        Self {
            next_kepks: vec![None; num_peers],
            peers: peers,
            rsm: RunStateMachine::new(0, initial_kepks.into_iter().map(Some).collect()),
        }
    }

    #[inline]
    fn num_peers(&self) -> usize {
        self.peers.len()
    }

}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum DcPhase {
    Exponential,
    Main,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum RunState {
    DcProcess(DcPhase),
    DcReveal(DcPhase),
    Blame,
    Confirm,
}

impl PartialOrd for RunState {
    fn partial_cmp(&self, other: &RunState) -> Option<Ordering> {
        // This is ugly but not uglier than using std::intrinsics::discriminant_value,
        // which does not guarantee a proper ordering and consequently would force us to use
        // debug assertions to make sure that the compiler actually uses proper ordering
        // internally. Note that std::mem::Discriminant<T> does not implement PartialOrd either,
        // because it relies on std::intrinsics::discriminant_value.
        // If this changes in the future, we can replace this function.
        #[inline]
        fn discriminant(x: &RunState) -> u32 {
            match *x {
                RunState::DcProcess(DcPhase::Exponential) => 0,
                RunState::DcReveal(DcPhase::Exponential) => 1,
                RunState::DcProcess(DcPhase::Main) => 2,
                RunState::DcReveal(DcPhase::Main) => 3,
                RunState::Blame => 4,
                RunState::Confirm => 5,
            }
        }

        match (*self, *other) {
            (RunState::Blame, RunState::Confirm) => None,
            (RunState::Confirm, RunState::Blame) => None,
            _ => discriminant(self).partial_cmp(&discriminant(other)),
        }
    }
}

// State that is cleared after a run
#[derive(Clone, Debug)]
struct RunStateMachine {
    count: u32,
    state: RunState,
    kepks: PeerVec<PublicKey>,
    received: BitSet,

    // Blame data
    histories: PeerVec<RunHistory>,
    peers_before_dc_exponential: Option<BitSet>,
    peers_before_dc_main: Option<BitSet>,
}

impl RunStateMachine {
    fn new(count: u32, kepks: PeerVec<PublicKey>) -> Self {
        let num_peers = kepks.len();

        #[inline]
        fn new_peervec<T, U: Clone>(template: &PeerVec<T>, initial: U) -> PeerVec<U> {
            template.into_iter().map(|opt| match opt {
                &None => None,
                &Some(_) => Some(initial.clone()),
            }).collect()
        }

        let new = Self {
            count: count,
            state: RunState::DcProcess(DcPhase::Exponential),
            received: BitSet::with_capacity(num_peers),
            histories: new_peervec(&kepks, RunHistory::new(num_peers)),
            peers_before_dc_exponential: None,
            peers_before_dc_main: None,
            kepks: kepks,
        };

        debug_assert!(new.consistent());

        new
    }

    #[inline]
    fn set_state(&mut self, state: RunState) {
        assert!(self.state < state);
        self.state = state;
    }

    fn apply_incoming_message(&mut self, incoming: (PeerIndex, IncomingPayload)) {
        let (peer_index, incoming_payload) = incoming;

        // The message has a correct signature and is intended for this state of this session.
        // So we can record it.
        let first_from_peer = self.received.insert(peer_index as usize);
        // The stream should never send us two messages from the same peer in the same round.
        debug_assert!(first_from_peer);

        if let IncomingPayload::Valid(ref pay) = incoming_payload {
            self.histories[peer_index as usize].as_mut().unwrap().record_payload(pay.clone());
        }

        match (self.state, incoming_payload) {
            (RunState::DcProcess(DcPhase::Exponential), IncomingPayload::Valid(Payload::DcExponential(pay))) => {
                unimplemented!()
            },
            (RunState::DcProcess(DcPhase::Main), IncomingPayload::Valid(Payload::DcMain(pay))) => {
                unimplemented!()
            },
            (RunState::DcReveal(phase), IncomingPayload::Valid(Payload::Reveal(pay))) => {
                unimplemented!()
            },
            (RunState::Blame, IncomingPayload::Valid(Payload::Blame(pay))) => {
                unimplemented!()
            },
            (RunState::Confirm, IncomingPayload::Valid(Payload::Confirm(pay))) => {
                unimplemented!()
            },
            _ => {
                // TODO Kick the peer out
                unimplemented!()
            }
        }
        assert!(self.consistent());
    }

    fn apply_dc_exponential(&mut self, peer_index: PeerIndex, pay: DcExponential) {
        // Perform DC-net
        unimplemented!();
    }

    #[inline]
    fn consistent(&self) -> bool {
        unimplemented!()
    }
}

