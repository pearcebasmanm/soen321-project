"""Number theory helpers used by the SOEN 321 Option 2 prototype.

The implementation mirrors topics from the course:
- square-and-multiply modular exponentiation
- Euclidean algorithm
- Extended Euclidean algorithm
- multiplicative inverse
- basic primality testing (Miller-Rabin for prototype key generation)
"""

from __future__ import annotations

import secrets


def gcd(a: int, b: int) -> int:
    """Return gcd(a, b) using the Euclidean algorithm."""
    while b != 0:
        a, b = b, a % b
    return abs(a)


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Return (g, x, y) such that ax + by = g = gcd(a, b)."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    return old_r, old_s, old_t


def modinv(a: int, m: int) -> int:
    """Return the multiplicative inverse of a modulo m."""
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"No inverse exists for a={a} modulo m={m}")
    return x % m


def modexp(base: int, exponent: int, modulus: int) -> int:
    """Square-and-multiply modular exponentiation."""
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    base %= modulus
    result = 1
    while exponent > 0:
        if exponent & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent >>= 1
    return result


_SMALL_PRIMES = (
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47
)


def is_probable_prime(n: int, rounds: int = 16) -> bool:
    """Miller-Rabin primality test suitable for a classroom prototype."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # write n - 1 = 2^s * d with d odd
    s = 0
    d = n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = modexp(a, d, n)
        if x in (1, n - 1):
            continue
        witness_found = True
        for _ in range(s - 1):
            x = modexp(x, 2, n)
            if x == n - 1:
                witness_found = False
                break
        else:
            witness_found = True
        if witness_found:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Generate an odd probable prime with the requested bit size."""
    if bits < 16:
        raise ValueError("Use at least 16 bits")
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate
