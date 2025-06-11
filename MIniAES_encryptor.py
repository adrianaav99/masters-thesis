# -*- coding: utf-8 -*-
"""
Created on Tue Apr 29 23:02:58 2025
@author: Admin
MINI-AES
"""
def sbox_substitution(nibble):
    sbox = {
        0x0: 0xE, 0x1: 0x3, 0x2: 0x4, 0x3: 0x8,
        0x4: 0x1, 0x5: 0xC, 0x6: 0xA, 0x7: 0xF,
        0x8: 0x7, 0x9: 0xD, 0xA: 0x9, 0xB: 0x6,
        0xC: 0xB, 0xD: 0x2, 0xE: 0x0, 0xF: 0x5
    }
    return sbox[nibble]

def split_nibbles(word):
    return [(word >> 12) & 0xF, (word >> 8) & 0xF, (word >> 4) & 0xF, word & 0xF]

def join_nibbles(nibbles):
    return (nibbles[0] << 12) | (nibbles[1] << 8) | (nibbles[2] << 4) | nibbles[3]

def shift_rows(state):
    # Input: [n0, n1, n2, n3]
    # Output after shift: [n0, n3, n2, n1]
    return [state[0], state[3], state[2], state[1]]

def mix_columns(state):
    # MixColumns defined over GF(2^4), with fixed matrix multiplication
    def gf_mult(a, b):
        IRR_POLY = 0b10011  # x^4 + x + 1 irreductible polynomial in GF(2^4)
        res = 0
        for i in range(4):
            if (b >> i) & 1:
                res ^= a << i
        for i in range(7, 3, -1):
            if (res >> i) & 1:
                res ^= IRR_POLY << (i - 4)
        return res & 0xF

    n0 = gf_mult(3, state[0]) ^ gf_mult(2, state[1])
    n1 = gf_mult(2, state[0]) ^ gf_mult(3, state[1])
    n2 = gf_mult(3, state[2]) ^ gf_mult(2, state[3])
    n3 = gf_mult(2, state[2]) ^ gf_mult(3, state[3])
    return [n0, n1, n2, n3]

def mini_aes_encrypt(plaintext, key):
    # Split into nibbles
    pt = split_nibbles(plaintext) # list of 4 nibbles, esch 4 bits
    k = split_nibbles(key) # list of 4 nibbles, esch 4 bits

    # Initial AddRoundKey
    state = [p ^ k[i] for i, p in enumerate(pt)]

    # Round 1
    state = [sbox_substitution(n) for n in state]
    state = shift_rows(state)
    state = mix_columns(state)
    state = [state[i] ^ k[i] for i in range(4)]

    # Round 2
    state = [sbox_substitution(n) for n in state]
    state = shift_rows(state)
    state = [state[i] ^ k[i] for i in range(4)]

    # Join nibbles back
    ciphertext = join_nibbles(state)
    return ciphertext


# Example usage
plaintext = 0x1234
key = 0xDBD1

ciphertext = mini_aes_encrypt(plaintext, key)

print(f"Plaintext:  0x{plaintext:04X}")
print(f"Ciphertext: 0x{ciphertext:04X}")