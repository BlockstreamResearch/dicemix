# DiceMix Light

DiceMix Light is a cryptographic P2P mixing protocol. It enables a group of mutually distrusting
peers, each of them holding an input message of identical size, to agree on the set of their input
messages anonymously, i.e., without revealing the which peer sends which input message. The
protocol provides this functionality without the help of a trusted proxy, and succeeds even in the
presence of malicious peers trying to prevent the honest peers from completing the protocol.

DiceMix Light is inspired by [DiceMix][dicemix], an P2P mixing protocol optimized for a minimal
number of communications rounds and require 4+2f communication rounds in the presence of f
disrupting peers. DiceMix Light needs 4+3f communication rounds but requires far less computation
and is simpler. We refer to the [DiceMix paper][dicemix] for background on P2P mixing protocols
and detailed definitions.

## Communication Model
Peers are connected via a broadcast mechanism, e.g., a server receiving protocol messages from each
peer and forwarding them to all other peers. The broadcast mechanism is also responsible for
notifiying the other peers when a peer has failed to send a protocol messages in time.

The communication between peers and the broadcast mechanism must be authenticated in both
directions to prevent a network attacker from interfering with the protocol.

## Security Goals
A P2P mixing protocol provides two security guarantees.

 * Sender Anonymity

 An attacker controlling the network (including the broadcast mechanism) and some peers is not able
 to tell which input message belongs to which honest peer. In more detail, the anonymity set of an
 individual honest peer is the set of all honest peers who have not been excluded for being
 offline.

 * Termination

 If the network (including the broadcast mechanism) is reliable and there are at least two honest
 peers, the protocol eventually terminates successfully for every honest peer.


## Protocol

### Setup Assumptions
TODO: Write

### Building Blocks

#### Pseudorandom Generator
 * `new_prg(seed)` initializes a PRG with seed `seed` and tweak `tweak`.
 * randomness can be obtained using calls such as `prg.get_bytes(n)` or `prg.get_field_element()`.

#### Deterministic One-time Signatures
We need a key-recoverable signature scheme which is weakly unforgeable under one-time chosen
message attacks.
 * `(otsk, otvk) := new_sig_keypair(rand)` generates a signing key and verification key.
 * `sign(otsk, msg)` creates a deterministic signature of message `msg` with signing key `otsk`.
 * `verify_recover(sig, msg)` outputs the verification key if `sig` is a valid signature on
 `msg` and nothing otherwise.

#### Non-interactive Key Exchange
We need a non-interactive key exchange protocol secure in the CRS model.
 * `(kesk, kepk) := new_ke_keypair(rand)` generates a secret key and a public key.
 We assume that for every valid public key there is a unique corresponding secret key.
 (Note: For ECDH, this implies that setting `kepk` to be just the x-coordinate without an
 additional bit is not sufficient; `kepk` must determine the full curve point.)
 * `validate_kepk(kepk)` outputs `true` iff `kepk` is a valid public key.
 * `shared_secret(kesk, kepk, my_id, their_id, tweak)` derives the shared secret between party
 `my_id` with secret key `kesk` and `their_id` with public key `kepk`, using the tweak `tweak`

#### Hash Functions
 * `hash` is a cryptographic hash function (modeled as a random oracle).
 * `hash_otvk` is a cryptographic hash function. If its output size is b bits, then the probability
 that a protocol run fails with an honest user being excluded is `n/2**b`, where `k` is the number
 of messages to be mixed. Values of `b` in the range of 64 are perfectly sufficient; note that the
 probability of an unexpected connection failure or hardware failure, which has the same
 consequences, is certainly higher.

### Pseudocode Conventions
 * The (non-excluded) peers are stored in set `P`.
 * `sgn(x)` is the signum function.
 * `**` denotes exponentiation.
 * `^` denotes bitwise XOR.
 * `(o)` denotes the arithmetic operator `o` in the finite field, e.g., `(+)` is addition in
 the finite field.
 * String constants such as `"KE"` are symbolic, their actual representation as bytes is
 defined below.

### Pseudocode
```
run := -1
P_exclude := {}
(my_kesk, my_kepk) := (undef, undef)
(my_next_kesk, my_next_kepk) := (undef, undef)

loop
    run := run + 1

    // In the first run, we perform a key exchange.
    // In later runs, we exclude peers who have been offline or malicious in the previous run.
    if run = 0 then
        // Key exchange
        (my_kesk, my_kepk) := new_sig_keypair()

        // FIXME sign the kepk with the long-term key
        broadcast "KEPK" || my_kepk
        receive "KEPK" || p.kepk from all p in P
            where validate_kepk(p.kepk)
            missing P_missing

        P := P \ P_missing
    else
        if P_exclude = {} then
            // Publish ephemeral secret and determine malicious peers
            broadcast "KESK" || my_kesk
            receive "KESK" || p.kesk from all p in P
            missing P_missing

            P := P \ P_missing

            // Exclude peers who have sent unexpected protocol messages
            for all p in P do
                // Given p.kesk, we can replay peer p's entire protocol execution, because the
                // protocol execution is deterministic except for the input messages to be mixed,
                // which we can recover from the DC(KE) round.
                replay peer p's expected protocol messages of the previous run by deriving them
                from p.kesk and recovering peer p's purported input messages,
                and set p.otvk_hashes[] to peer p's my_otvk_hashes[] variable on the way

                if p has sent an unexpected message then
                    P := P \ {p}

            // Exclude peers who are involved in a slot collision, i.e., an OTVK hash collision
            for all (p1, p2) in P^2 such that
            there is i and j with p1.otvk_hashes[i] = p2.otvk_hashes[j] and (p1 != p2 or i != j) do
                P_exclude := P_exclude U {p1, p2}

            // Rotate keys
            (my_kesk, my_kepk) := (my_next_kesk, my_next_kepk)
            (my_next_kesk, my_next_kepk) := (undef, undef)

        P := P \ P_exclude

    if |P| = 0 then
        fail "No peers left."

    P_exclude := {}

    // Build session ID
    ids[] := sort({p.id | p in P} U {my_id})

    if there are duplicate value in ids[] then
        fail "Duplicate peer IDs."

    sid := version || options || nonce || run || ids[0] || ... || ids[|P|]
    sid_hash := hash("SID" || sid)
    // FIXME more SIDs later?

    // Derive shared keys
    for all p in P do
        p.seed_dcexp := shared_secret(my_kesk, p.kepk, my_id, p.id, sid_hash || "DCEXP")
        p.prg_dcexp := new_prg(seed_dcexp)
        p.seed_dcsimple := shared_secret(my_kesk, p.kepk, my_id, p.id, sid_hash || "DC")
        p.prg_dcsimple := new_prg(seed_dcsimple)

    // Generate signature key pair
    otsk_seeds[] := array of my_num_msgs bitstrings
    otsks[] := array of my_num_msgs OTSKs
    my_otvks[] := array of my_num_msgs OTVKs
    for j := 0 to my_num_msgs do
        otsk_seeds[j] := hash("OTSK_SEED" || sid_hash || j || my_id || my_kesk)
        (otsks[j], my_otvks[j]) := new_ke_keypair(otsk_seeds[j])

    // Run a DC-net with exponential encoding
    sum_num_msgs := my_num_msgs
    for all p in P do
        sum_num_msgs := sum_num_msgs + p.num_msgs

    my_dc[] := array of sum_num_msgs finite field elements
    my_otvk_hashes[] := array of my_num_msgs bitstrings
    for j := 0 to my_num_msgs do
        my_otvk_hashes[j] := hash_otvk(my_otvks[j])
        for i := 0 to sum_num_msgs - 1 do
            my_dc[i] := my_otvk_hashes[j] ** (i + 1)

    for all p in P do
        for i := 0 to sum_num_msgs - 1 do
            my_dc[i] := my_dc[i] (+) (sgn(my_id - p.id) (*) p.prg_dcexp.get_field_element())

    broadcast "DCEXP" || my_dc[0] || ... || my_dc[sum_num_msgs - 1]
    receive "DCEXP" || p.dc[0] || ... || p.dc[sum_num_msgs - 1] from all p in P
        missing P_exclude

    if P_exclude != {} then
        continue

    dc_combined[] := my_dc[]
    for all p in P
        for i := 0 to sum_num_msgs - 1 do
            dc_combined[i] := dc_combined[i] (+) p.dc[i]

    solve the equation system
        "for all 0 <= i < sum_num_msgs ,
         dc_combined[i] = (sum)(j := 0 to sum_num_msgs - 1, roots[j] ** (i + 1))"
         for the array roots[]

    all_otvk_hashes[] := sort(roots[])

    // Run an ordinary DC-net with slot reservations
    my_msgs[] := fresh_msgs()
    for j := 0 to my_num_msgs do
        my_sigs[] := sign(otsk, my_msgs[])

    slot_size := |my_sigs[0]| + |my_msgs[0]|

    slots[] := array of my_num_msg integers, initialized with undef
    for j := 0 to my_num_msgs do
        slots[j] := undef
        if there is exactly one i
        with all_otvk_hashes[i] = my_otvk_hashes[j] then  // constant time in i
            slots[j] := i

    my_dc[] := array of |P| arrays of slot_size bytes, all initalized with 0
    for j := 0 to my_num_msgs do
        if slots[j] != undef then
            my_dc[slots[j]] := my_sigs[j] || my_msgs[j]  // constant time in slots[j] and my_msgs[j]

    for all p in P do
        for i := 0 to sum_num_msgs do
            my_dc[i] := my_dc[i] ^ p.prg_dcsimple.get_bytes(slot_size)

    if (my_next_kesk, my_next_kepk) = (undef, undef) and |P| > 1 then
        // Key exchange
        (my_next_kesk, my_next_kepk) := new_sig_keypair()
        // FIXME sign the kepk with the long-term key

        broadcast "DCKE" || my_next_kepk || my_dc[0] || ... || my_dc[sum_num_msgs - 1]
        receive "DCKE" || p.next_kepk || p.dc[0] || ... || p.dc[sum_num_msgs - 1] from all p in P
            where validate_kepk(p.next_kepk)
            missing P_exclude
    else
        broadcast "DC" || my_dc[0] || ... || my_dc[sum_num_msgs - 1]
        receive "DC" || p.dc[0] || ... || p.dc[sum_num_msgs - 1] from all p in P
            missing P_exclude

    if P_exclude != {} then
        continue

    dc_combined[] := my_dc[]
    for p in P do
        for i := 0 to sum_num_msgs do
            dc_combined[i] := dc_combined[i] ^ p.dc[i]

    // Check signatures
    msgs[] := array of sum_num_msgs messages

    for i := 0 to sum_num_msgs do
        sigi || msgs[i] := dc_combined[i]
        otvki := verify_recover(sigi, msgs[i])
        if not otvki then
            continue
        if hash_otvk(otvki) != all_otvk_hashes[i] then
            continue

    for all j := 0 to my_num_msgs do
        if my_msgs[j] != msgs[slots[j]] then  // constant time in slots[j] and in msgs[slots[j]]
            fail "One of my own messages is missing."

    // Confirmation
    my_confirmation := validate_and_confirm(msgs[])
    if my_confirmation != undef then
        continue

    broadcast "CF" || my_confirmation
    receive "CF" || p.confirmation from all p in P
        missing P_exclude

    if P_exclude != {} then
        continue

    // Check confirmation
    P_exclude := check_confirmations(msgs[], {(p.id, p.confirmation) | p in P})

    if P_exclude != {} then
        continue

    return successfully
```

### Security

#### Sender Anonymity
The security argument is similar to the one presented for the [original DiceMix protocol][dicemix].

#### Termination
For termination, we assume that the broadcast mechanism is honest, i.e., it delivers messages
correctly and it does not equivocate.

The honest peers, who are assumed to receive the same messages, hold by construction the same state
in their consensus-critical public variables and take the same consensus-critical control flow
decisions, unless an honest peer fails with "One of my own messages in missing". This failure
happens only with negligible probability for an honest peer, because this requires the attacker to
forge a signature under the OTVK of the honest peer.

By correctness of the protocol, a protocol run terminates if every peer sends expected messages and
there is no OTVK hash collision (and thus no slot collision). Consequently we can distinguish two
cases if the protocol fails.
  1. *There is a peer who has failed to send an expected message at least once.*

  The honest peers exclude this peer by construction.

  2. *There is an OTVK hash collision but no peer involved in the OTVK hash collision has failed to
  send an expected message.*

  We show that then all peers involved in the OTVK hash collision are malicious with overwhelming
  probability.

  First, if only one peer is involved in the OTVK hash collision (i.e., the peer sends the same
  OTVK hash for multiple slot reservations), then this peer is obviously malicious with
  overwhelming probaility.

  Second, we consider the case that multiple peers are involved in an OTVK hash collision. If one
  peer was honest, then the other peers involved in the collision could have derived the expected
  OTVK of the honest user in the DC(KE) round of the previous run only with negligible probability;
  observe that they have copied the honest peer's OTVK either, because the derivation of the OTVK
  depends on the peer ID and so the copied OTVK would be expected only with negligible probability.

  Thus all peers involved in the OTVK hash collision are malicious with overwhelming probability,
  and the honest peers exclude at least one such malicious peer.

In both cases, the honest peers exclude at least one disruptive, i.e., malicious or offline, peer.
Since all honest peers exclude the same disruptive peers, they all start the next run in the same
consensus-critical state. At some point, only honest peers will remain in the protocol execution
and the either protocol succeeds or fails expectly (in the case that only one peer remains).

[dicemix]: https://www.internetsociety.org/doc/p2p-mixing-and-unlinkable-bitcoin-transactions
  "P2P Mixing and Unlinkable Bitcoin Transactions. Tim Ruffing, Pedro Moreno-Sanchez, Aniket Kate. Network and Distributed System Security Symposium 2017 (NDSS'17)"
