#!/usr/bin/env sage

import sys

if len(sys.argv) != 3:
    print("Usage: %s <finite field size in bits> <number of messages>" % sys.argv[0])
    sys.exit(1)

secp256k1_prime = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
brainpoolP512r1_prime = 0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3

primes = {
    64: 2**64 - 59,
   128: 2**128 - 159,
   192: 2**192 - 237,
   256: secp256k1_prime,
   320: 2**320 - 197,
   384: 2**384 - 317,
   448: 2**448 - 2**224 - 1, # goldilocks
   512: brainpoolP512r1_prime,
  1024: 2**1024 - 105
}

prime = primes[int(sys.argv[1])]
n = int(sys.argv[2])

F = GF(prime, proof=False)
ms = [F.random_element() for _ in xrange(n)]
ss = [sum([m^i for m in ms]) for i in xrange(1,n+1)]
my = Integers(n).random_element()
print prime, n, ms[my], ' '.join(map(str,ss))

print >> sys.stderr, 'Original messages: ', sorted(ms)
test_coefficients = [F(0)] * n
# Calculate coefficients with a simple for
for i in xrange(1, n+1, 1): # for each i from 1 to n
    partial_sum = F(prime)
    pwsum_it = 0
    for j in xrange(i-1, 0, -1):
        # Calculate the sum from coefficient values calculated in previous loops
        partial_sum = partial_sum +  (ss[pwsum_it] * test_coefficients[j-1])
        pwsum_it += 1

    # The value of the current coeficient is (-Pi - partial_sum)/i
    inverse = F(1/i)
    test_coefficients[i-1] = F( (ss[i-1] * (-1)) + (partial_sum * (-1)) ) * inverse

print >> sys.stderr, 'Coefficients: ', test_coefficients
