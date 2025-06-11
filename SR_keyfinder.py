# -*- coding: utf-8 -*-
"""
Created on Mon Jun  2 23:18:39 2025
@author: Admin
SAT-based key recovery for SR*(4, 2, 2, 4)
"""
import time
from pysat.formula import CNF
from pysat.solvers import Solver

def xor_cnf(a, b, out):
    return [
        [-a, -b, -out],
        [-a,  b,  out],
        [ a, -b,  out],
        [ a,  b, -out],
    ]

# all 16 pairs
def encode_sbox_to_cnf(sbox, inputs, outputs):
    cnf = CNF()
    for in_val, out_val in sbox.items():
        cond = []
        for i in range(4):
            bit = (in_val >> (3 - i)) & 1
            lit = -inputs[i] if bit else inputs[i]
            cond.append(lit)
        for i in range(4):
            bit = (out_val >> (3 - i)) & 1
            lit = outputs[i] if bit else -outputs[i]
            cnf.append(cond + [lit])
    return cnf

IRR_POLY = 0b10011
def gf_mult(a, b):
    res = 0
    for i in range(4):
        if (b >> i) & 1:
            res ^= a << i
    for i in range(7, 3, -1):
        if (res >> i) & 1:
            res ^= IRR_POLY << (i - 4)
    return res & 0xF

def gf_mult_const_cnf(constant, input_bits, output_bits):
    cnf = CNF()
    for x in range(16):
        y = gf_mult(constant, x)
        clause = []
        for i in range(4):
            bit = (x >> (3 - i)) & 1
            clause.append(-input_bits[i] if bit else input_bits[i])
        for i in range(4):
            bit = (y >> (3 - i)) & 1
            cnf.append(clause + ([output_bits[i]] if bit else [-output_bits[i]]))
    return cnf

def xor_nbit(a_bits, b_bits, out_bits):
    clauses = CNF()
    for a, b, o in zip(a_bits, b_bits, out_bits):
        clauses.extend(xor_cnf(a, b, o))
    return clauses

def encode_mixcolumns_to_cnf(in_bits, out_bits):
    #modification -- change b with c
    cnf = CNF()
    a_bits, c_bits = in_bits[0:4], in_bits[4:8]
    b_bits, d_bits = in_bits[8:12], in_bits[12:16]

    a_out, c_out = out_bits[0:4], out_bits[4:8]
    b_out, d_out = out_bits[8:12], out_bits[12:16]

    a3 = new_vars(4)
    b2 = new_vars(4)
    a2 = new_vars(4)
    b3 = new_vars(4)
    c3 = new_vars(4)
    d2 = new_vars(4)
    c2 = new_vars(4)
    d3 = new_vars(4)

    cnf.extend(gf_mult_const_cnf(3, a_bits, a3).clauses)
    cnf.extend(gf_mult_const_cnf(2, b_bits, b2).clauses)
    cnf.extend(gf_mult_const_cnf(2, a_bits, a2).clauses)
    cnf.extend(gf_mult_const_cnf(3, b_bits, b3).clauses)
    cnf.extend(gf_mult_const_cnf(3, c_bits, c3).clauses)
    cnf.extend(gf_mult_const_cnf(2, d_bits, d2).clauses)
    cnf.extend(gf_mult_const_cnf(2, c_bits, c2).clauses)
    cnf.extend(gf_mult_const_cnf(3, d_bits, d3).clauses)

    cnf.extend(xor_nbit(a3, b2, a_out).clauses)
    cnf.extend(xor_nbit(a2, b3, b_out).clauses)
    cnf.extend(xor_nbit(c3, d2, c_out).clauses)
    cnf.extend(xor_nbit(c2, d3, d_out).clauses)
    return cnf

def set_bits(val, vars):
    bits = []
    for i in range(16):
        bit = (val >> (15 - i)) & 1
        bits.append(vars[i] if bit else -vars[i])
    return bits

# Correct S-box for SR*(4,2,2,4)
sbox = {
    0x0: 0x6, 0x1: 0xB, 0x2: 0x5, 0x3: 0x4,
    0x4: 0x2, 0x5: 0xE, 0x6: 0x7, 0x7: 0xA,
    0x8: 0x9, 0x9: 0xD, 0xA: 0xF, 0xB: 0xC,
    0xC: 0x3, 0xD: 0x1, 0xE: 0x0, 0xF: 0xF
}

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

    pt = new_vars(16)
    key = new_vars(16)
    state = new_vars(16)
    for i in range(16):
        cnf.extend(xor_cnf(pt[i], key[i], state[i]))

    # First 3 rounds
    for r in range(3):
        sboxed = new_vars(16)
        for i in range(0, 16, 4):
            cnf.extend(encode_sbox_to_cnf(sbox, state[i:i+4], sboxed[i:i+4]).clauses)
        shifted = sboxed[:]
        shifted[4:8], shifted[12:16] = sboxed[12:16], sboxed[4:8]
        mixed = new_vars(16)
        cnf.extend(encode_mixcolumns_to_cnf(shifted, mixed).clauses)
        after_add = new_vars(16)
        for i in range(16):
            cnf.extend(xor_cnf(mixed[i], key[i], after_add[i]))
        state = after_add

    # Final round (No MixColumns)
    sboxed = new_vars(16)
    for i in range(0, 16, 4):
        cnf.extend(encode_sbox_to_cnf(sbox, state[i:i+4], sboxed[i:i+4]).clauses)
    shifted = sboxed[:]
    shifted[4:8], shifted[12:16] = sboxed[12:16], sboxed[4:8]
    final = new_vars(16)
    for i in range(16):
        cnf.extend(xor_cnf(shifted[i], key[i], final[i]))

    return cnf, pt, final, key

# ------- Main Solver --------
start_time = time.time()
plaintext = 0xA9C7
ciphertext = 0x9089

cnf, pt_vars, out_vars, key_vars = build_cnf_model()

cnf.extend([[b] for b in set_bits(plaintext, pt_vars)])
cnf.extend([[b] for b in set_bits(ciphertext, out_vars)])

print(f"Generated {len(cnf.clauses)} clauses.")

found_keys = set()
with Solver(bootstrap_with=cnf) as solver:
    while solver.solve():
        model = solver.get_model()
        key = 0
        block = []
        for i, k in enumerate(key_vars):
            val = 1 if k in model else 0
            key |= val << (15 - i)
            block.append(-k if val else k)
        print(f"Found key: 0x{key:04X}")
        found_keys.add(key)
        solver.add_clause(block)

    if not found_keys:
        print("No keys found.")
    else:
        print(f"Total keys found: {len(found_keys)}")
end_time = time.time()
total_time = end_time - start_time
print(f"Execution time: {total_time:.4f} seconds")