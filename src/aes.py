from dataclasses import dataclass
import secrets

BLOCK_SIZE = 16
NUM_ROUNDS = 10

"""
AES-128 uses a 16-byte key.
Key expansion produces 44 words total.
Each word is 4 bytes.
44 words = 11 round keys * 4 words each.

Last roundkey is used as the first initializer round key for decryption
First key round 0 is used as the last roundkey of decryption

Final round just three transformations
(it is not completely opposite as it depends on the structure of the AES)
"""

"""
S-box is a lookup table.
It takes one byte and replaces it with another byte.
1 byte = 2 hex digits
"""
SBOX = [
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
]

MIX_MATRIX = [
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2]
]

INV_MIX_MATRIX = [
    [14, 11, 13, 9],
    [9, 14, 11, 13],
    [13, 9, 14, 11],
    [11, 13, 9, 14]
]


@dataclass
class AESKey:
    key_bytes: bytes


def generate_key() -> AESKey:
    return AESKey(secrets.token_bytes(BLOCK_SIZE))


"""
multiplies a byte by 2
"""
def xtime(x):
    x <<= 1
    if x & 0x100:
        x ^= 0x11B
    return x & 0xFF


"""
multiplies two bytes in GF(2^8)
"""
def gf_mul(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result


"""
inverse of S-box
"""
def build_inv_sbox():
    inv_sbox = [0] * 256

    for i in range(256):
        inv_sbox[SBOX[i]] = i

    return inv_sbox


def build_round_constant(num_values):
    round_constant = []
    value = 0x01
    for _ in range(num_values):
        round_constant.append(value)
        value = xtime(value)
    return round_constant

"""
Padding for strings length != 16
"""
def pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Invalid padded data.")

    pad_len = data[-1]

    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding.")

    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding.")

    return data[:-pad_len]

"""
4 transformations (encryption)
"""
def substitute_bytes(state):
    return [SBOX[x] for x in state]


"""
It moves each row of the AES state to the left,
with the first row unchanged, the second shifted by 1,
the third by 2, and the fourth by 3 left circular shift.
"""
def shift_rows(state):
    s = state[:]

    for row in range(4):
        row_values = [state[row], state[row + 4], state[row + 8], state[row + 12]]
        shifted = row_values[row:] + row_values[:row]

        s[row] = shifted[0]
        s[row + 4] = shifted[1]
        s[row + 8] = shifted[2]
        s[row + 12] = shifted[3]

    return s


"""
MixColumns multiplies each state column by a fixed AES matrix.
It mixes the 4 bytes in each column using matrix multiplication to create new values,
so each output byte depends on all 4 input bytes in that column.
"""
def mix_columns(state):
    s = state[:]

    for i in range(0, 16, 4):
        column = [state[i], state[i + 1], state[i + 2], state[i + 3]]

        new_column = [0, 0, 0, 0]
        for row in range(4):
            new_column[row] = (
                gf_mul(MIX_MATRIX[row][0], column[0]) ^
                gf_mul(MIX_MATRIX[row][1], column[1]) ^
                gf_mul(MIX_MATRIX[row][2], column[2]) ^
                gf_mul(MIX_MATRIX[row][3], column[3])
            )

        s[i], s[i + 1], s[i + 2], s[i + 3] = new_column

    return s


"""
XORs each byte of the state with the corresponding byte from the round key.
"""
def add_round_key(state, round_key):
    return [state[i] ^ round_key[i] for i in range(BLOCK_SIZE)]


"""
4 transformations (decryption, inv)
"""
INV_SBOX = build_inv_sbox()

def inv_substitute_bytes(state):
    return [INV_SBOX[x] for x in state]


def inv_shift_rows(state):
    s = state[:]

    for row in range(4):
        row_values = [state[row], state[row + 4], state[row + 8], state[row + 12]]
        shifted = row_values[-row:] + row_values[:-row] if row != 0 else row_values

        s[row] = shifted[0]
        s[row + 4] = shifted[1]
        s[row + 8] = shifted[2]
        s[row + 12] = shifted[3]

    return s


def inv_mix_columns(state):
    s = state[:]

    for i in range(0, 16, 4):
        column = [state[i], state[i + 1], state[i + 2], state[i + 3]]

        for row in range(4):
            s[i + row] = (
                gf_mul(column[0], INV_MIX_MATRIX[row][0]) ^
                gf_mul(column[1], INV_MIX_MATRIX[row][1]) ^
                gf_mul(column[2], INV_MIX_MATRIX[row][2]) ^
                gf_mul(column[3], INV_MIX_MATRIX[row][3])
            )

    return s


"""
Key Expansion: the method returns all AES round keys as a list.
XORs of round constant with g function output
"""
def g(word, rcon):
    word = word[1:] + word[:1]
    word = [SBOX[x] for x in word]
    word[0] ^= rcon
    return word


def expand_key(key: bytes):
    ROUND_CONSTANT = build_round_constant(NUM_ROUNDS)

    if len(key) != BLOCK_SIZE:
        raise ValueError("AES-128 key must be 16 bytes.")

    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]

    for i in range(4, 44):
        temp = words[i - 1][:]

        if i % 4 == 0:
            temp = g(temp, ROUND_CONSTANT[(i // 4) - 1])

        new_word = [words[i - 4][j] ^ temp[j] for j in range(4)]
        words.append(new_word)

    round_keys = []
    for r in range(NUM_ROUNDS + 1):
        round_key = []
        for j in range(4):
            round_key.extend(words[r * 4 + j])
        round_keys.append(bytes(round_key))

    return round_keys


def encrypt_block(plaintext: bytes, key: AESKey) -> bytes:
    if len(plaintext) != BLOCK_SIZE:
        raise ValueError("AES block must be 16 bytes.")
    if len(key.key_bytes) != BLOCK_SIZE:
        raise ValueError("AES-128 key must be 16 bytes.")

    round_keys = expand_key(key.key_bytes)
    state = list(plaintext)

    state = add_round_key(state, round_keys[0])

    for round_index in range(1, NUM_ROUNDS):
        state = substitute_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_index])

    state = substitute_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[NUM_ROUNDS])

    return bytes(state)


def decrypt_block(ciphertext: bytes, key: AESKey) -> bytes:
    if len(ciphertext) != BLOCK_SIZE:
        raise ValueError("AES block must be 16 bytes.")
    if len(key.key_bytes) != BLOCK_SIZE:
        raise ValueError("AES-128 key must be 16 bytes.")

    round_keys = expand_key(key.key_bytes)
    state = list(ciphertext)

    state = add_round_key(state, round_keys[NUM_ROUNDS])

    for round_index in range(NUM_ROUNDS - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_substitute_bytes(state)
        state = add_round_key(state, round_keys[round_index])
        state = inv_mix_columns(state)

    state = inv_shift_rows(state)
    state = inv_substitute_bytes(state)
    state = add_round_key(state, round_keys[0])

    return bytes(state)


def encrypt(plaintext: bytes, key: AESKey) -> bytes:
    plaintext = pad(plaintext)
    ciphertext = b""

    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i + BLOCK_SIZE]
        ciphertext += encrypt_block(block, key)

    return ciphertext


def decrypt(ciphertext: bytes, key: AESKey) -> bytes:
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext must be a multiple of 16 bytes.")

    plaintext = b""

    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        plaintext += decrypt_block(block, key)

    return unpad(plaintext)


def main():
    key = generate_key()
    print("Key       :", key)

    text = "no"
    plaintext = text.encode("utf-8")

    ciphertext = encrypt(plaintext, key)
    recovered = decrypt(ciphertext, key)

    print("Text      :", text)
    print("Plaintext :", plaintext)
    print("Ciphertext:", ciphertext.hex())
    print("Recovered :", recovered.decode("utf-8"))
    print("Match     :", recovered == plaintext)

if __name__ == "__main__": 
    main()