# -*- coding: utf-8 -*-
"""
Created on Mon Jun  2 22:50:13 2025
@author: Admin
SR*(4, 2, 2, 4) Small scale AES 
"""

def sbox_substitution(nibble):
    # Precomputed S-box from the paper Small Scale Variants of the AES
    sbox = {
        0x0: 0x6, 0x1: 0xB, 0x2: 0x5, 0x3: 0x4,
        0x4: 0x2, 0x5: 0xE, 0x6: 0x7, 0x7: 0xA,
        0x8: 0x9, 0x9: 0xD, 0xA: 0xF, 0xB: 0xC,
        0xC: 0x3, 0xD: 0x1, 0xE: 0x0, 0xF: 0xF
    }
    return sbox[nibble]

def split_nibbles(word):
    # nibbles 0,1,2,3 go to state[0][0], state[1][0], state[0][1], state[1][1]
    return [
        [(word >> 12) & 0xF, (word >> 4) & 0xF],
        [(word >> 8) & 0xF, word & 0xF]
    ]

def join_nibbles(state):
    # Reconstruct 16-bit word from 2x2 matrix
    return (
        (state[0][0] << 12) |  # nibble 0
        (state[1][0] << 8)  |  # nibble 1
        (state[0][1] << 4)  |  # nibble 2
        (state[1][1])          # nibble 3
    )

def shift_rows(state):
    return [
        state[0],
        [state[1][1], state[1][0]]
    ]

def mix_columns(state):
    # MixColumns defined over GF(2^4), with fixed matrix multiplication
    def gf4_mul(a, b):
        IRR_POLY = 0b10011  # x^4 + x + 1 irreductible polynomial in GF(2^4)
        res = 0
        for i in range(4):
            if (b >> i) & 1:
                res ^= a << i
        for i in range(7, 3, -1): # reduce from degree 7 down to 4
            if (res >> i) & 1:
                res ^= IRR_POLY << (i - 4)
        return res & 0xF
    
    a, b = state[0]
    c, d = state[1]
    # MixColumns with matrix [[3, 2], [2, 3]]
    new0 = [gf4_mul(3, a) ^ gf4_mul(2, b), gf4_mul(2, a) ^ gf4_mul(3, b)]
    new1 = [gf4_mul(3, c) ^ gf4_mul(2, d), gf4_mul(2, c) ^ gf4_mul(3, d)]
    return [new0, new1]

def add_round_key(state, round_key):
    return [[state[i][j] ^ round_key[i][j] for j in range(2)] for i in range(2)]

def sr_aes_encrypt(plaintext, key):
    state = split_nibbles(plaintext)
    k = split_nibbles(key)

    state = add_round_key(state, k)

    for _ in range(3):
        state = [[sbox_substitution(n) for n in row] for row in state]
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, k)

    state = [[sbox_substitution(n) for n in row] for row in state]
    state = shift_rows(state)
    state = add_round_key(state, k)

    return join_nibbles(state)

# Example usage
plaintext = 0x2BA7
key = 0x90AE
ciphertext = sr_aes_encrypt(plaintext, key)

print(f"Plaintext:  0x{plaintext:04X}")
print(f"Ciphertext: 0x{ciphertext:04X}")