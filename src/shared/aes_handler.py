from utils import *
from secrets import randbelow
import hashlib
import os

# got substitution box from online (FIPS 197 standard)
sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

inv_sbox = [0] * 256
for i, j in enumerate(sbox):
    inv_sbox[j] = i

# 10 round constants for the 128 bit key
rcon = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

# multiplying the polynomials represented as bits of coefficients in the galois field xored with x^8 + x^4 + x^3 + x + 1
def xtime(b):
    return ((b << 1) ^ 0x1b) & 0xff if (b & 0x80) else (b << 1) & 0xff

def gmul(a, b):
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result

def key_expansion(key: bytes) -> list:
    w = [list(key[4*i: 4*i+4]) for i in range(4)]

    for i in range(4, 44):
        temp = w[i-1][:]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [sbox[b] for b in temp]
            temp[0] ^= rcon[i // 4 - 1]
        
        w.append([w[i-4][j] ^ temp[j] for j in range(4)])
    
    return [[b for word in w[rk*4: rk*4+4] for b in word] for rk in range(11)]

def add_round_key(state, rk):
    return [s ^ k for s, k in zip(state, rk)]

def sub_bytes(state):
    return [sbox[b] for b in state]

def inv_sub_bytes(state):
    return [inv_sbox[b] for b in state]

def shift_rows(state):
    return [
        state[0], state[5], state[10], state[15],
        state[4], state[9], state[14], state[3],
        state[8], state[13], state[2], state[7],
        state[12], state[1], state[6], state[11],
    ]

def inv_shift_rows(state):
    return [
        state[0],state[13], state[10], state[7],
        state[4], state[1], state[14], state[11],
        state[8], state[5], state[2], state[15],
        state[12], state[9], state[6], state[3],
    ]

def mix_column(s0, s1, s2, s3):
    return [
        gmul(2,s0) ^ gmul(3,s1) ^ s2 ^ s3,
        s0 ^ gmul(2,s1) ^ gmul(3,s2) ^ s3,
        s0 ^ s1 ^ gmul(2,s2) ^ gmul(3,s3),
        gmul(3,s0) ^ s1 ^ s2 ^ gmul(2,s3),
    ]

def inv_mix_column(s0, s1, s2, s3):
    return [
        gmul(14,s0) ^ gmul(11,s1) ^ gmul(13,s2) ^ gmul(9,s3),
        gmul(9,s0) ^ gmul(14,s1) ^ gmul(11,s2) ^ gmul(13,s3),
        gmul(13,s0) ^ gmul(9,s1) ^ gmul(14,s2) ^ gmul(11,s3),
        gmul(11,s0) ^ gmul(13,s1) ^ gmul(9,s2) ^ gmul(14,s3),
    ]

def mix_columns(state):
    result = []
    for c in range(4):
        result.extend(mix_column(state[4*c], state[4*c+1], state[4*c+2], state[4*c+3]))
    return result

def inv_mix_columns(state):
    result = []
    for c in range(4):
        result.extend(inv_mix_column(state[4*c], state[4*c+1], state[4*c+2], state[4*c+3]))
    return result

def aes_encrypt_block(block: bytes, round_keys: list) -> bytes:
    state = list(block)
    state = add_round_key(state, round_keys[0])

    # running the 9 rounds of sub, shift, mix, and xor round key
    for r in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[r])
    
    # no mixing on the last round b/c it's poitnless
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])

    return bytes(state)

# key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
# plain = bytes.fromhex("00112233445566778899aabbccddeeff")
# rks = key_expansion(key)
# print(aes_encrypt_block(plain, rks).hex())

def aes_decrypt_block(block: bytes, round_keys: list) -> bytes:
    state = list(block)
    state = add_round_key(state, round_keys[10])

    for r in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[r])
        state = inv_mix_columns(state)
    
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])

    return bytes(state)

# turning the 16 byte aes block cipher into a stream cipher for bigger text
def ctr_encrypt(data: bytes, round_keys: list, nonce: bytes) -> bytes:
    result = bytearray()

    for i in range(0, len(data), 16):
        counter_block = nonce + (i // 16).to_bytes(4, 'big')
        keystream = aes_encrypt_block(counter_block, round_keys)
        chunk = data[i:i+16]
        result.extend(ks ^ b for ks, b in zip(keystream, chunk))

    return bytes(result)

class AESHandler:
    @staticmethod
    def generate_key_exchange_data(first):
        if first:
            return SAFE_PRIME, GENERATOR, randbelow(SAFE_PRIME) | (1 << (2048 - 1))
        else:
            return randbelow(SAFE_PRIME) | (1 << (2048 - 1))

    @staticmethod
    def derive_key(shared_secret: int) -> bytes:
        return hashlib.sha256(shared_secret.to_bytes(256, 'big')).digest()[:16]

    @staticmethod
    def encrypt(data: bytes, key) -> bytes:
        if isinstance(key, int):
            key = AESHandler.derive_key(key)
        
        nonce = os.urandom(12)
        return nonce + ctr_encrypt(data, key_expansion(key), nonce)

    @staticmethod
    def decrypt(data: bytes, key) -> bytes:
        if isinstance(key, int):
            key = AESHandler.derive_key(key)
        
        nonce = data[:12]
        return ctr_encrypt(data[12:], key_expansion(key), nonce)
