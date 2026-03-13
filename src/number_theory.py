"""
Number theory helpers for the SOEN 321 Course Project.
"""

import secrets


_SMALL_PRIMES = (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47)


def gcd(a: int, b: int) -> int:
    """Return gcd(a, b) using the Euclidean algorithm."""
    while b != 0:
        a, b = b, a % b
    return abs(a)  # Avoid possible negative output


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Return (g, x, y) such that ax + by = g = gcd(a, b)."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r  # Compute gcd
        old_s, s = s, old_s - q * s  # Guarantee that old_s = old_s + qs
        old_t, t = t, old_t - q * t  # Guarantee that old_t = t + qt

    return old_r, old_s, old_t


def modinv(a: int, m: int) -> int:
    """Return the multiplicative inverse in mod m."""
    g, x, _ = extended_gcd(a, m)
    if g != 1:  # gcd must be 1 for multiplicative inverse to exist
        raise ValueError(f"No inverse exists for a={a} modulo m={m}")
    return x % m


def modexp(base: int, exponent: int, modulus: int) -> int:
    """Square-and-multiply modular exponentiation."""
    if modulus <= 0:
        raise ValueError("Modulus must be positive.")
    base %= modulus  # Project base to [0, moodulus - 1]
    result = 1
    while exponent > 0:
        if exponent & 1:  # If the lowest bit of exponent is 1, multiply
            result = (result * base) % modulus
        base = (base * base) % modulus  # Square
        exponent >>= 1  # Shift one bit rightward
    return result


def is_probable_prime(n: int, rounds: int = 16) -> bool:
    """Miller-Rabin primality test."""
    if n < 2:
        return False  # Numbers smaller than two are not primes
    if n in (2, 3):
        return True  # 2 and 3 are not primes
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
        x = modexp(a, d, n)
        if x in (1, n - 1):
            continue
        witness_found = True  # Witness that n is a composite
        for _ in range(s - 1):
            x = modexp(x, 2, n)
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
