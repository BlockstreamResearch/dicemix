**This document is a working draft. Substantial changes are possible.**

# DiceMix Light

DiceMix Light is a cryptographic P2P mixing protocol. It enables a group of mutually distrusting
peers, each of them holding an input message of identical size, to agree on the set of their input
messages anonymously, i.e., without revealing which peer sends which input message. The
protocol provides this functionality without the help of a trusted proxy, and succeeds even in the
presence of malicious peers trying to prevent the honest peers from completing the protocol.

DiceMix Light is inspired by [DiceMix][dicemix], an P2P mixing protocol optimized for a minimal
number of communications rounds and require 4+2f communication rounds in the presence of f
disrupting peers. DiceMix Light needs 4+3f communication rounds but requires far less computation
and is simpler. We refer to the [DiceMix paper][dicemix] for background on P2P mixing protocols
and detailed definitions.

## Communication Model
Peers are connected via a terminating reliable broadcast mechanism, e.g., a server receiving
protocol messages from each peer and forwarding them to all other peers. The broadcast mechanism is
responsible for ensuring that the same protocol message is forwarded to all other peers and for
notifying the other peers when a peer has failed to send a protocol message in time.

Even if not strictly necessary, it is recommended that the peers communicate to the broadcast
mechanism via a channel that provides confidentiality, authentication of the broadcast mechanism,
and anonymity on the network level (i.e., unlinkability of sender and network identifiers such as
IP addresses). This can be achieved by a broadcast mechanism reachable via a Tor Hidden Service.

## Security Goals
A P2P mixing protocol provides two security guarantees.

 * Sender-Message Unlinkability

 An attacker controlling the network (including the broadcast mechanism) and some peers is not able
 to tell which input message belongs to which honest peer. In more detail, define the anonymity set
 of an individual honest peer's message to be the set of all honest peers who have not been
 excluded for being offline. Then the case that peer `p1` has sent input message `m` is
 computationally indistinguishable from the case that peer `p2` has sent message `m` for all peers
 `p1` and `p2` in the anonymity set.

 * Termination

 If the network (including the broadcast mechanism) is reliable and there are at least two honest
 peers, the protocol eventually terminates successfully for every honest peer.

## Protocol

### Setup Assumptions
TODO: Write

### Building Blocks

#### Finite Field
We need a finite field F of size q which is large enough to ensure that the probability of a
collision is low when `sum_num_msgs` random field elements are sampled, where `sum_num_msgs` is the
number of messages sent by the peers altogether. If a collision occurs, the peers involved in the
collision will be excluded and cannot finish the protocol. Reasonable field size are for example
q ≈ 2³¹ or q ≈ 2⁴⁰, yielding probabilities of around 4.6E-8 and 9.0E-11 for a fixed honest peer to
be excluded in a run of the protocol, assuming this peer sends one message and there are 99 other
messages sent in the run.

#### Group
We need a group G where the discrete logarithm problem is hard.

#### Pseudorandom Generator
 * `new_prg(seed)` initializes a PRG with seed `seed` and tweak `tweak`.
 * Randomness can be obtained using calls such as `prg.get_bytes(n)` or `prg.get_field_element()`.

#### Non-interactive Key Exchange
We need a non-interactive key exchange protocol secure in the CKS model.
 * `(kesk, kepk) := new_ke_keypair(rand)` generates a secret key and a public key.
 We assume that for every valid public key there is a unique corresponding secret key.
 (Note: For ECDH, this implies that setting `kepk` to be just the x-coordinate without an
 additional bit is not sufficient; `kepk` must determine the full curve point.)
 * `validate_kepk(kepk)` outputs `true` iff `kepk` is a valid public key.
 * `shared_secret(kesk, kepk, my_id, their_id, tweak)` derives the shared secret between party
 `my_id` with secret key `kesk` and `their_id` with public key `kepk`, using the tweak `tweak`.

#### Hash Functions
 * `hash` is a cryptographic hash function whose output is long enough to ensure collision
 resistance.
 * `hash_into_group` is a cryptographic hash function into the group G.

Both hash functions are modeled as random oracles.

### Pseudocode Conventions
 * The (non-excluded) peers are stored in set `P`.
 * `sgn(x)` is the sign function.
 * `**` denotes exponentiation.
 * `^` denotes XOR.
 * `(+)` and `(*)` denote addition and multiplication in the finite field F.
 * `<+>` and `<*>` denote the group operation and scalar multiplication in the group G.
 * String constants such as `"KE"` are symbolic, their actual representation as bytes is
 defined below.
 * Every peer `p` signs all its messages using the respective long-term signing key `p.ltsk`.
 The signatures are omitted in the pseudocode for readability. A peer who receives an incorrectly
 signed message immediately treats the sending peer as offline and discards the message.

### Pseudocode
```
run := -1
P_exclude := {}
(my_kesk, my_kepk) := (undef, undef)
(my_next_kesk, my_next_kepk) := (undef, undef)
my_confirmation := undef

if there are duplicate value in ids[] then
    fail "Duplicate peer IDs."

loop
    run := run + 1

    if P_exclude = {} then
        // Key exchange
        // FIXME sign the kepk with the long-term key
        // (my_next_kesk, my_next_kepk) := new_ke_keypair()

        // In the first run, we perform a key exchange.
        // In later runs, we either confirm or exclude peers who have been offline or malicious in the
        // previous run.
        if run = 0 or my_confirmation != undef then
            broadcast "KECF" || my_next_kepk || my_confirmation
            receive "KECF" || p.next_kepk || p.confirmation from all p in P
                where validate_kepk(p.next_kepk)
                missing P_missing

            if my_confirmation != undef then
                // Check confirmation
                P_exclude := check_confirmations(msgs[], {p.id | p in P U {my_id})})

                assert P_exclude ⊂ P_missing

                if P_exclude = {} then
                    return successfully

                my_confirmation := undef

            P := P \ P_missing

        else
            // Publish ephemeral secret and determine malicious peers
            broadcast "KESK" || my_next_kepk || my_kesk
            receive "KESK" || p.next_kepk || p.kesk from all p in P
                where validate_kepk(p.next_kepk)
                missing P_missing

            P := P \ P_missing

            // Exclude peers who have sent unexpected protocol messages
            for all p in P do
                // Given p.seed, we can replay peer p's entire protocol execution, because the
                // protocol execution is deterministic except for the input messages to be mixed,
                // which we can recover from the DC round.
                replay peer p's expected protocol messages of the previous run by deriving them
                from p.seed and recovering peer p's purported input messages,
                and set p.slot_reservations[] to peer p's my_slot_reservations[] variable on the way

                if p has sent an unexpected message then
                    P := P \ {p}

            // Exclude pairs (p1, p2) of peers where both p1 and p2 have not sent unexpected
            // protocol messages but the slots of p1 and p2 collide
            for all (p1, p2) in P^2 for which there is i and j
            with p1.slot_reservations[i] = p2.slot_reservations[j] and (p1 != p2 or i != j) do
                P_exclude := P_exclude U {p1, p2}

            if P_exclude = {} then
                fail "Computationally unreachable"

        // Shift keys
        (my_kesk, my_kepk) := (my_next_kesk, my_next_kepk)
        (my_next_kesk, my_next_kepk) := (undef, undef)


    P := P \ P_exclude
    P_exclude := {}

    if |P| = 0 then
        fail "No peers left."

    // Build session ID
    ids[] := sort({p.id | p in P} U {my_id})

    sid := version || options || run || ids[0] || ... || ids[|P|]
    sid_hash := hash("SID" || sid)
    // FIXME more SIDs later?

    // Initialize private PRG for this run
    private_seed := hash("PRG" || sid_hash || my_id || kesk)
    private_prg = new_prg(private_seed)

    // Derive shared keys
    for all p in P do
        p.seed_dcexp := shared_secret(my_kesk, p.kepk, my_id, p.id, sid_hash || "DCEXP")
        p.prg_dcexp := new_prg(p.seed_dcexp)
        p.seed_dcsimple := shared_secret(my_kesk, p.kepk, my_id, p.id, sid_hash || "DC")
        p.prg_dcsimple := new_prg(p.seed_dcsimple)

    // Obtain messages
    my_msgs[] := fresh_msgs()
    my_num_msgs := |my_msgs[]|
    sum_num_msgs := my_num_msgs
    for all p in P do
        sum_num_msgs := sum_num_msgs + p.num_msgs

    // Run DC-net in group G
    my_dc_group := 0
    for i := 0 to my_num_msgs - 1 do
        my_dc_group := my_dc_group <+> hash_into_group("COMMIT" || my_kesk || sid_hash || my_id || i || my_msgs[i])

    for all p in P do
        my_dc_group := my_dc_group <+> (sgn(my_id - p.id) <*> p.prg_dcgroup.get_group_element())

    // Run a DC-net with exponential encoding for slot assignment
    my_dc[] := array of sum_num_msgs finite field elements, all initialized with 0
    my_slot_reservations[] := array of my_num_msgs finite field elements, all initialized with 0
    for j := 0 to my_num_msgs - 1 do
        my_slot_reservations[j] := private_prg.get_field_element()
        for i := 0 to sum_num_msgs - 1 do
            my_dc[i] := my_dc[i] (+) (my_slot_reservations[j] ** (i + 1))

    for all p in P do
        for i := 0 to sum_num_msgs - 1 do
            my_dc[i] := my_dc[i] (+) (sgn(my_id - p.id) (*) p.prg_dcexp.get_field_element())

    broadcast "SR" || my_dc_group || my_dc[0] || ... || my_dc[sum_num_msgs - 1]
    receive "SR" || p.dc_group || p.dc[0] || ... || p.dc[sum_num_msgs - 1] from all p in P
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

    all_slot_reservations[] := sort(roots[])

    // Run an XOR DC-net with slot assignment
    slot_size := |my_msgs[0]|

    slots[] := array of my_num_msg integers, initialized with undef
    ok := true
    for j := 0 to my_num_msgs - 1 do
        if there is exactly one i
        with all_slot_reservations[i] = my_slot_reservations[j] then  // constant time in i
            slots[j] := i
        else
            ok := false
            break

    if not ok then
        // Even though the run will be aborted, transmit the message in a deterministic slot.
        // This enables the peers to recompute our commitment.
        for j := 0 to my_num_msgs - 1 do
            slots[j] := j

    my_dc[] := array of |P| arrays of slot_size bytes, all initalized with 0
    for j := 0 to my_num_msgs - 1 do
        my_dc[slots[j]] := my_msgs[j]  // constant time in slots[j]

    for all p in P do
        for i := 0 to sum_num_msgs - 1 do
            my_dc[i] := my_dc[i] ^ p.prg_dcsimple.get_bytes(slot_size)

    if not ok then
        // Ensure that this DC-net will not be successful
        for i := 0 to sum_num_msgs - 1 do
            my_dc[i] := my_dc[i] ^ prg_private.get_bytes(slot_size)

    broadcast "DC" || my_dc[0] || ... || my_dc[sum_num_msgs - 1]
    receive "DC" || p.dc[0] || ... || p.dc[sum_num_msgs - 1] from all p in P
        missing P_exclude

    if P_exclude != {} then
        continue

    // Resolve the DC-net
    msgs[] := my_dc[]
    for all p in P do
        for i := 0 to sum_num_msgs - 1 do
            msgs[i] := msgs[i] ^ p.dc[i]
    msgs[] := sort(msgs[])

    // Resolve the DC-net in G and verify commitment
    commit1 := my_dc_group
    for all p in P do
        commit1 := commit1 <+> (sgn(my_id - p.id) <*> p.dc_group)

    commit2 := <0>
    for i := 0 to sum_num_msgs - 1 do
        commit2 := commit <+> hash_into_group(msgs[i])

    if commit1 != commit2 then
        continue

    for j := 0 to my_num_msgs - 1 do
        if there is no i with my_msgs[j] = msgs[i] then  // constant time in i and my_msgs[j]
            // One of our own messages is missing.
            continue  // (***)

    // Confirmation
    my_confirmation := confirm(msgs[], {p.id | p in P U {my_id})})
```

### Security

#### Sender-Message Unlinkability
The security argument is similar to the one presented for the [original DiceMix protocol][dicemix].

Note: It is crucial that for every run, every honest peer either enters the confirmation phase
or reveals the secret key of the key exchange. This holds true, because no honest peer will reveal
the secret key after it has started confirmation; in particular it will use a fresh key after
confirmation fails to ensure that the secret key will not be revealed in a further run.


#### Termination
For termination, we assume that the broadcast mechanism is honest, i.e., it delivers messages
correctly and it does not equivocate.

Ignoring line `(***)`, the honest peers, who are assumed to receive the same messages, hold by
construction the same state in their consensus-critical public variables and take the same
consensus-critical control flow decisions.
Assume that there is a run in which an honest peer p1 hits line `(***)` and an honest peer p2
does not hit line `(***)`. That implies that there is a message m1 of p1 that the attacker has
replaced in the XOR DC-net and there is a message m2 of p2 that the attacker has not replaced in
the XOR DC-net. Since the commitments verify, the attacker has either solved the generalized
birthday problem in G, which happens only with negligible probability because the discrete
logarithm problem is hard in G, or the attacker has replaced the sum of the messages hashes over
M = {m1, m2, ...} with the sum of messages hashes over some M' with m1 ∉ M' and m2 ∈ M', which
happens only with negligible probability because the attacker cannot predict m1 and m2 in the SR
round.

By correctness of the protocol, a protocol run terminates if every peer sends expected messages and
there is no collision of group elements in the slot reservation (and thus no slot collision).
Consequently we can distinguish two cases if the protocol fails.
  1. *There is a peer who has failed to send an expected message at least once.*

  The honest peers exclude this peer by construction.

  2. *There is a slot collision but no peer involved in the slot has failed to send an expected
  message.*

  We show that then all peers involved in the message hash collision are malicious with
  overwhelming probability.

  First, if only one peer is involved in the message hash collision, then this peer is obviously
  malicious with probability around 1/q.

  Second, we consider the case that multiple peers are involved in a collision. If one peer was
  honest, then the other peers involved in the collision could have derived the group element sent
  by the honest user the slot reservation only probability around 1/q; observe that they cannot
  have copied the honest peer's slot reservation message either, because then their DC-netpads
  in the DC-net in the group G would be expected only probability around 1/q, as the derivation of
  the shared keys includes the peer ID.

  Thus all peers involved in the slot collision are malicious with probability around 1/q, and the
  honest peers exclude at least one such malicious peer.

In both cases, the honest peers exclude at least one disruptive, i.e., malicious or offline, peer.
Since all honest peers exclude the same disruptive peers, they all start the next run in the same
consensus-critical state. At some point, only honest peers will remain in the protocol execution
and the protocol either succeeds or fails because only one peer remains.

[dicemix]: https://www.internetsociety.org/doc/p2p-mixing-and-unlinkable-bitcoin-transactions
  "P2P Mixing and Unlinkable Bitcoin Transactions. Tim Ruffing, Pedro Moreno-Sanchez, Aniket Kate. Network and Distributed System Security Symposium 2017 (NDSS'17)"

### Possible Improvements

#### Only Sign the Key Exchange
In principle, it suffices to sign the key exchange messages. All other protocol messages do not
need to be authenticated for sender-message unlinkability. So if signature verification is a
bottleneck, then it is possible to drop the other signatures, which however adds complexity to the
protocol as well as its analysis by giving the attacker much more possibility to fiddle with the
protocol messages and reach possibly overlooked cases.

---

#### License
To the extent possible under law, the DiceMix contributors who associated CC0 with this document
have waived all copyright and related or neighboring rights to this document.

[![CC0](http://i.creativecommons.org/p/zero/1.0/88x31.png)](http://creativecommons.org/publicdomain/zero/1.0/)
