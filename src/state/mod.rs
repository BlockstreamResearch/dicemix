use std::collections::VecDeque;
use secp256k1::key::PublicKey;
use vec_map::VecMap;

use messages::*;
use super::*;
use self::history::*;

mod history;

/// Public information about a peer
#[derive(Clone, Debug)]
struct Peer<'a> {
    peer_id: PeerId,
    lt_vk: &'a PublicKey,
    ke_pks: VecDeque<PublicKey>,
    history: RunHistory,
}

