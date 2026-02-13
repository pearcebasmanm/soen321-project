import click

import rsa
import utils


@click.group()
def _cli():
    """TODO: Project Name

    TODO: Command Description
    """


@_cli.group("rsa")
def _rsa():
    """TODO: rsa blurb"""


@_rsa.command("keygen")
@click.option("-p", type=click.INT)
@click.option("-q", type=click.INT)
@click.option("-e", type=click.INT, default=2**16 + 1)
def _rsa_keygen(p, q, e):
    """
    TODO: document
    """
    # Validation
    if p is not None and q is None:
        raise click.UsageError("If -p is provided, -q must also be provided")
    if p is None and q is not None:
        raise click.UsageError("If -q is provided, -p must also be provided")

    if (p and not utils.is_prime(p)) or (q and not utils.is_prime(q)):
        raise click.UsageError("Both -p and -q must be primes")

    # Defaults
    if p is None:
        p = utils.random_prime()
    if q is None:
        q = utils.random_prime()

    # Execution
    keys = rsa.generate_keys(p, q, e)
    n = keys["n"]
    e = keys["e"]
    d = keys["d"]
    print("Modular base (safe to share):", n)
    print("Encryption key (safe to share):", e)
    print("Decryption key (keep secure):", d)


@_rsa.command("encrypt")
@click.option("-n", type=click.INT, required=True)
@click.option("-e", type=click.INT, required=True)
@click.argument("message")
def _rsa_encrypt(n, e, message):
    """
    TODO: document
    """
    if message.isdigit():
        m = int(message)
    else:
        m = int.from_bytes(message.encode("utf-8"), byteorder="big")

    if m >= n:
        print("WARNING: this message is too large")

    c = rsa.encrypt(m, e, n)
    print("Encrypted message (safe to share):", c)


@_rsa.command("decrypt")
@click.option("-n", type=click.INT, required=True)
@click.option("-d", type=click.INT, required=True)
@click.argument("message")
def _rsa_decrypt(n, d, message):
    """
    TODO: document
    """
    c = int(message)

    if c >= n:
        print("WARNING: this message is too large")

    m = rsa.decrypt(c, d, n)
    print("Decrypted number:", m)
    try:
        num_bytes = (m.bit_length() + 7) // 8
        m = m.to_bytes(num_bytes, byteorder="big").decode("utf-8")
        print("Decrypted string:", m)
    except UnicodeError:
        pass


if __name__ == "__main__":
    _cli()
