import math


def generate_keys(p, q, e):
    """
    Precondition: p and q are primes
    """
    n = p * q
    totient = (p - 1) * (q - 1)

    if math.gcd(totient, e) != 1:
        print(f"Error: The value of e={e} is incompatible with n={n}")
        print("Hint: provide different values, or try again if they're being generated")
        exit()

    d = pow(e, -1, totient)

    assert (e * d) % totient == 1  # Just a sanity check, this shouldn't ever break

    # NOTE: make sure to never return p or q
    return {"n": n, "e": e, "d": d}


def encrypt(m, e, n):
    c = pow(m, e, n)
    return c


def decrypt(c, d, n):
    m = pow(c, d, n)
    return m
