use std::cmp::Ordering;
use std::collections::VecDeque;
use secp256k1::key::PublicKey;
use vec_map::VecMap;
use bit_set::BitSet;

use messages::*;
use super::*;
use self::history::*;

mod history;
mod peer;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum DcState {
    Process,
    Reveal,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum RunState {
    DcExponential(DcState),
    DcMain(DcState),
    Blame,
    Confirm,
}

impl PartialOrd for RunState {
    fn partial_cmp(&self, other: &RunState) -> Option<Ordering> {
        // This is ugly but not uglier than using std::intrinsics::discriminant_value,
        // which does guarantee a proper ordering and would force us to use debug assertions
        // anyway. Note that std::mem::Discriminant<T> does not implement PartialOrd either,
        // because it relies on std::intrinsics::discriminant_value.
        // If this changes in the future, we can replace this function.
        #[inline]
        fn discriminant(x: &RunState) -> u32 {
            match *x {
                RunState::DcExponential(_) => 0,
                RunState::DcMain(_) => 1,
                RunState::Blame => 2,
                RunState::Confirm => 3,
            }
        }

        match (*self, *other) {
            (RunState::Blame, RunState::Confirm) => None,
            (RunState::Confirm, RunState::Blame) => None,
            _ => discriminant(self).partial_cmp(&discriminant(other)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RunStateMachine {
    run: u32,
    state: RunState,
    kepks: VecMap<PublicKey>,
    received: BitSet,
    otvk_hashes: Option<Vec<[u8; 32]>>,
    peers_before_dc_exponential: Option<BitSet>,
    peers_before_dc_main: Option<BitSet>,
}

impl RunStateMachine {
    #[inline]
    fn set_state(&mut self, state: RunState) {
        assert!(self.state < state);
        self.state = state;
    }

    fn process(&self, payload: Payload) -> Option<Payload> {
        unimplemented!()
    }
}

