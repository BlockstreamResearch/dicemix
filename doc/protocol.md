# Dicemix Light

## Primitives

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

#### Hash Function
 * `hash` is a cryptographic hash function (modeled as a random oracle).

## Protocol

### Pseudocode Conventions
 * The (non-excluded) peers are stored in set `P`.
 * `sgn(x)` is the signum function.
 * `**` denotes exponentiation.
 * `^` denotes bitwise XOR.
 * `(o)` denotes the arithmetic operator `o` in the finite field, e.g., `(+)` is addition in
 the finite field.
 * String constants such as `"KE"` are symbolic, their actual representation as bytes is
 defined below.

### Setup Assumptions
TODO: Write

### Authentication
All protocol messages are assumed to be authenticated. Unauthenticated messages must be ignored.
We note that authentication is only required for termination but not for anonymity.

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
        broadcast "KE" || my_kepk
        receive "KE" || p.kepk from all p in P
            where validate_kepk(p.kepk)
            missing P_missing

        P := P \ P_missing
    else
        if P_exclude != {} then
            P := P \ P_exclude
        else
            // Publish ephemeral secret and determine malicious peers
            broadcast "KESK" || my_kesk
            receive "KESK" || p.kesk from all p in P
            missing P_missing

            P := P \ P_missing

            for all p in P do
                replay all protocol messages of p using p.kesk
                // TODO Expand that part
                if p has sent an incorrect message then
                    P := P \ {p}

            if there is p in P with p.kepk = my_kepk then
                fail "No honest peers left."

            for all (p1, p2) in P^2 with p1 != p2 and p1.kepk = p2.kepk do
                P := P \ {p1, p2}

            // Rotate keys
            (my_kesk, my_kepk) := (my_next_kesk, my_next_kepk)
            (my_next_kesk, my_next_kepk) := (undef, undef)

    if |P| = 0 then
        fail "No peers left."
        break

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
        otsk_seeds[j] := hash("OTSK_SEED" || sid_hash || j || my_kesk)
        (otsks[j], my_otvks[j]) := new_ke_keypair(otsk_seeds[j])

    // Run a DC-net with exponential encoding
    sum_num_msgs := my_num_msgs
    for all p in P do
        sum_num_msgs := sum_num_msgs + p.num_msgs

    my_dc[] := array of sum_num_msgs finite field elements
    otvk_hashes[] := array of my_num_msgs bitstrings
    for j := 0 to my_num_msgs do
        otvk_hashes[j] := hash("OTVK" || my_otvks[j])
        for i := 0 to sum_num_msgs - 1 do
            my_dc[i] := otvk_hashes[j] ** (i + 1)

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

    otvk_hashes[] := sort(roots[])

    // Run an ordinary DC-net with slot reservations
    my_msgs[] := fresh_msgs()
    for j := 0 to my_num_msgs do
        my_sigs[] := sign(otsk, my_msgs[])

    slot_size := |my_sigs[0]| + |my_msgs[0]|
    padding_size := security_level_in_bits - (slot_size * sum_num_msgs * 8)

    slots[] := array of my_num_msg integers, initialized with undef
    for j := 0 to my_num_msgs do
        slots[j] := undef
        if there is exactly one i with otvk_hashes[i] = otvk_hash[j] then  // constant time in i
            slots[j] := i

    my_dc[] := array of |P| arrays of slot_size bytes, all initalized with 0
    for j := 0 to my_num_msgs do
        if slots[j] != undef then
            my_dc[slots[j]] := my_sigs[j] || my_msgs[j]  // constant time in slots[j] and my_msgs[j]

    for all p in P do
        for i := 0 to sum_num_msgs do
            my_dc[i] := my_dc[i] ^ p.prg_dcsimple.get_bytes(slot_size)
        if padding_size > 0 then
            my_padding := my_padding ^ p.prg_dcsimple.get_bytes(slot_size)

    if (my_next_kesk, my_next_kepk) = (undef, undef) and |P| > 1 then
        // Key exchange
        (my_next_kesk, my_next_kepk) := new_sig_keypair()
        // FIXME sign the kepk with the long-term key

        broadcast "DCKE" || my_next_kepk || my_dc[0] || ... || my_dc[sum_num_msgs - 1] || my_padding
        receive "DCKE" || p.next_kepk || p.dc[0] || ... || p.dc[sum_num_msgs - 1] || p.padding
            from all p in P
            where validate_kepk(p.next_kepk)
            missing P_exclude
    else
        broadcast "DC" || my_dc[0] || ... || my_dc[sum_num_msgs - 1] || my_padding
        receive "DC" || p.dc[0] || ... || p.dc[sum_num_msgs - 1] || p.padding
            from all p in P
            missing P_exclude

    if P_exclude != {} then
        continue

    dc_combined[] := my_dc[]
    for p in P do
        for i := 0 to sum_num_msgs do
            dc_combined[i] := dc_combined[i] ^ p.dc[i]

    // Check signatures
    msgs[] := array of sum_num_msgs messages

    found := false
    for i := 0 to sum_num_msgs do
        sigi || msgs[i] := dc_combined[i]
        otvki := verify_recover(sigi, msgs[i])
        if not otvki then
            continue
        if hash("OTVK", otvki) != otvk_hashes[i] then
            continue

    for all j := 0 to my_num_msgs do
        if my_msgs[j] != msgs[slots[j]] then  // constant time in slots[j] and in msgs[slots[j]]
            fail "This is probably a bug."

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
