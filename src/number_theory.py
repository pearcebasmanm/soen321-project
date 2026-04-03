"""
Number theory helpers for the SOEN 321 Course Project.
"""

import secrets


_SMALL_PRIMES = (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47)


def is_probable_prime(n: int, rounds: int = 16) -> bool:
    """Miller-Rabin primality test."""
    if n < 2:
        return False  # Numbers smaller than two are not primes
    if n in (2, 3):
        return True  # 2 and 3 are primes
    if n % 2 == 0:
        return False  # Even numbers are not primes
    for p in _SMALL_PRIMES:  # Quick check with small primes
        if n == p:
            return True
        if n % p == 0:
            return False

    # Write n - 1 = 2^s * d with d odd
    s = 0
    d = n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(rounds):  # round = 16 by default.
        # Possibility to misjudge: 0.25^16
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, mod=n)
        if x in (1, n - 1):
            continue
        witness_found = True  # Witness that n is a composite
        for _ in range(s - 1):
            x = pow(x, 2, mod=n)
            if x == n - 1:
                witness_found = False
                break
        else:
            witness_found = True
        if witness_found:  # If there's witness then n is not a prime
            return False
    return True


def generate_prime(bits: int) -> int:
    """Generate an odd probable prime with the requested bit size."""
    if bits < 16:
        raise ValueError("Use at least 16 bits")
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (
            1 << (bits - 1)
        ) | 1  # Turn the random number into an odd number with required num of bits/
        if is_probable_prime(candidate):
            return candidate
