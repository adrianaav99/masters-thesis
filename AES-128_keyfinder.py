# -*- coding: utf-8 -*-
"""
Created on Mon Jun  2 23:18:39 2025
@author: Admin
SAT-based key recovery for AES-128
"""
import time
from pysat.formula import CNF
from pysat.solvers import Solver

# 1 word is 1 bytes 
sbox = [
    # 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,  # 0
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,  # 1
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,  # 2
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,  # 3
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,  # 4
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,  # 5
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,  # 6
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,  # 7
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,  # 8
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,  # 9
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,  # A
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,  # B
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,  # C
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,  # D
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,  # E
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16   # F
]

def xor_cnf(a, b, out):
    return [
        [-a, -b, -out],
        [-a,  b,  out],
        [ a, -b,  out],
        [ a,  b, -out],
    ]

# all 256 pairs
def encode_sbox_to_cnf(sbox, inputs, outputs):
    cnf = CNF()
    for in_val in range(256):
        out_val = sbox[in_val]
        cond = []
        for i in range(8):
            bit = (in_val >> (7 - i)) & 1
            lit = -inputs[i] if bit else inputs[i]
            cond.append(lit)
        for i in range(8):
            bit = (out_val >> (7 - i)) & 1
            cnf.append(cond + ([outputs[i]] if bit else [-outputs[i]]))
    return cnf

def gf_mult(a, b):
    IRR_POLY = 0b100011011  # AES uses x⁸ + x⁴ + x³ + x + 1
    res = 0
    for i in range(8):
        if (b >> i) & 1:
            res ^= a << i
    for i in range(15, 7, -1):
        if (res >> i) & 1:
            res ^= IRR_POLY << (i - 8)
    return res & 0xFF

def gf_mult_const_cnf(constant, input_bits, output_bits):
    """
    Encodes multiplication of an 8-bit input by a constant in GF(2⁸).
    input_bits: list of 8 variable IDs
    output_bits: list of 8 variable IDs
    """
    assert len(input_bits) == 8, f"Expected 8 input bits, got {len(input_bits)}"
    assert len(output_bits) == 8, f"Expected 8 output bits, got {len(output_bits)}"
    cnf = CNF()
    for x in range(256):  # All 8-bit inputs
        y = gf_mult(constant, x)
        clause = []
        for i in range(8):
            bit = (x >> (7 - i)) & 1
            clause.append(-input_bits[i] if bit else input_bits[i])
        for i in range(8):
            bit = (y >> (7 - i)) & 1
            cnf.append(clause + ([output_bits[i]] if bit else [-output_bits[i]]))
    return cnf

def xor_nbit(a_bits, b_bits, out_bits):
    clauses = CNF()
    for a, b, o in zip(a_bits, b_bits, out_bits):
        clauses.extend(xor_cnf(a, b, o))
    return clauses

def equals_cnf(a, b):
    cnf = CNF()
    cnf.append([a, -b])
    cnf.append([-a, b])
    return cnf

def encode_mixcolumns_to_cnf(in_bits, out_bits):
    assert len(in_bits) == 128, f"in_bits has {len(in_bits)} bits, expected 128"
    assert len(out_bits) == 128, f"out_bits has {len(out_bits)} bits, expected 128"

    cnf = CNF()

    for col in range(4):  # Process each column (4 bytes = 32 bits)
        a = in_bits[col * 32     : col * 32 + 8]
        b = in_bits[col * 32 + 8 : col * 32 + 16]
        c = in_bits[col * 32 + 16: col * 32 + 24]
        d = in_bits[col * 32 + 24: col * 32 + 32]

        # Intermediate GF multiplications
        a2, a3 = new_vars(8), new_vars(8)
        b2, b3 = new_vars(8), new_vars(8)
        c2, c3 = new_vars(8), new_vars(8)
        d2, d3 = new_vars(8), new_vars(8)

        cnf.extend(gf_mult_const_cnf(2, a, a2).clauses)
        cnf.extend(gf_mult_const_cnf(3, a, a3).clauses)
        cnf.extend(gf_mult_const_cnf(2, b, b2).clauses)
        cnf.extend(gf_mult_const_cnf(3, b, b3).clauses)
        cnf.extend(gf_mult_const_cnf(2, c, c2).clauses)
        cnf.extend(gf_mult_const_cnf(3, c, c3).clauses)
        cnf.extend(gf_mult_const_cnf(2, d, d2).clauses)
        cnf.extend(gf_mult_const_cnf(3, d, d3).clauses)

        # Compute s0 = 2a ^ 3b ^ c ^ d
        t1 = new_vars(8)
        t2 = new_vars(8)
        s0 = new_vars(8)
        cnf.extend(xor_nbit(a2, b3, t1).clauses)
        cnf.extend(xor_nbit(t1, c, t2).clauses)
        cnf.extend(xor_nbit(t2, d, s0).clauses)

        # Compute s1 = a ^ 2b ^ 3c ^ d
        t1 = new_vars(8)
        t2 = new_vars(8)
        s1 = new_vars(8)
        cnf.extend(xor_nbit(a, b2, t1).clauses)
        cnf.extend(xor_nbit(t1, c3, t2).clauses)
        cnf.extend(xor_nbit(t2, d, s1).clauses)

        # Compute s2 = a ^ b ^ 2c ^ 3d
        t1 = new_vars(8)
        t2 = new_vars(8)
        s2 = new_vars(8)
        cnf.extend(xor_nbit(a, b, t1).clauses)
        cnf.extend(xor_nbit(t1, c2, t2).clauses)
        cnf.extend(xor_nbit(t2, d3, s2).clauses)

        # Compute s3 = 3a ^ b ^ c ^ 2d
        t1 = new_vars(8)
        t2 = new_vars(8)
        s3 = new_vars(8)
        cnf.extend(xor_nbit(a3, b, t1).clauses)
        cnf.extend(xor_nbit(t1, c, t2).clauses)
        cnf.extend(xor_nbit(t2, d2, s3).clauses)

        # Assign s0, s1, s2, s3 to output bits
        out = out_bits[col * 32 : (col + 1) * 32]
        assert len(out) == 32, f"out_bits column {col} has {len(out)} bits, expected 32"

        for i in range(8):
            cnf.extend(equals_cnf(s0[i], out[i]).clauses)
            cnf.extend(equals_cnf(s1[i], out[i + 8]).clauses)
            cnf.extend(equals_cnf(s2[i], out[i + 16]).clauses)
            cnf.extend(equals_cnf(s3[i], out[i + 24]).clauses)
    return cnf

def set_bits(val, vars):
    bits = []
    for i in range(16):
        bit = (val >> (15 - i)) & 1
        bits.append(vars[i] if bit else -vars[i])
    return bits

# Global var counter
var_counter = 1
def new_vars(n):
    global var_counter
    vars = list(range(var_counter, var_counter + n))
    var_counter += n
    return vars

def build_cnf_model():
    global var_counter
    var_counter = 1
    cnf = CNF()

    # Initial variables
    pt = new_vars(128)
    key = new_vars(128)
    state = new_vars(128)
    # Initial AddRoundKey
    for i in range(128):
        cnf.extend(xor_cnf(pt[i], key[i], state[i]))

    # AES-128 10 rounds: 9 with MixColumns, 1 without
    for r in range(9):
        sboxed = new_vars(128)
        for i in range(0, 128, 8):
            cnf.extend(encode_sbox_to_cnf(sbox, state[i:i+8], sboxed[i:i+8]).clauses)

        shifted = [0]*128
        for row in range(4):
            for col in range(4):
                src_idx = (4 * col + row) * 8
                dst_col = (col + row) % 4
                dst_idx = (4 * dst_col + row) * 8
                shifted[dst_idx:dst_idx+8] = sboxed[src_idx:src_idx+8]

        mixed = new_vars(128)
        in_bits = []
        out_bits = []
        for col in range(4):
            for row in range(4):
                byte_start = (row * 32) + (col * 8)  # Correct position in row-major layout
                in_bits += shifted[byte_start : byte_start + 8]
                out_bits += mixed[byte_start : byte_start + 8]
        cnf.extend(encode_mixcolumns_to_cnf(in_bits, out_bits).clauses)

        after_add = new_vars(128)
        for i in range(128):
            cnf.extend(xor_cnf(mixed[i], key[i], after_add[i]))
        state = after_add

    # Final round (no MixColumns)
    sboxed = new_vars(128)
    for i in range(0, 128, 8):
        cnf.extend(encode_sbox_to_cnf(sbox, state[i:i+8], sboxed[i:i+8]).clauses)

    shifted = [0]*128
    for row in range(4):
        for col in range(4):
            src_idx = (4 * col + row) * 8
            dst_col = (col + row) % 4
            dst_idx = (4 * dst_col + row) * 8
            shifted[dst_idx:dst_idx+8] = sboxed[src_idx:src_idx+8]

    final = new_vars(128)
    for i in range(128):
        cnf.extend(xor_cnf(shifted[i], key[i], final[i]))

    return cnf, pt, final, key


# ------- Main Solver -------
start_time = time.time()
plaintext = 0x00112233445566778899AABBCCDDEEFF
ciphertext = 0x824F768A2B68C12A0791BFCE4036A49E

cnf, pt_vars, out_vars, key_vars = build_cnf_model()

# Fix plaintext and ciphertext bits
cnf.extend([[b] for b in set_bits(plaintext, pt_vars)])
cnf.extend([[b] for b in set_bits(ciphertext, out_vars)])

print(f"Generated {len(cnf.clauses)} clauses.")
end_time = time.time()
total_time = end_time - start_time
print(f"Execution time: {total_time:.4f} seconds")
"""
found_keys = set()
with Solver(bootstrap_with=cnf) as solver:
    while solver.solve():
        model = solver.get_model()
        key = 0
        block = []
        for i, k in enumerate(key_vars):
            val = 1 if k in model else 0
            key |= val << (127 - i)
            block.append(-k if val else k)
        print(f"Found key: 0x{key:032X}")
        found_keys.add(key)
        solver.add_clause(block)

    if not found_keys:
        print("No keys found.")
    else:
        print(f"Total keys found: {len(found_keys)}")
"""