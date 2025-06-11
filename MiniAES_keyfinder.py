# -*- coding: utf-8 -*-
"""
Created on Mon May  5 18:42:47 2025
@author: Admin
SAT based key recovery for MINI-AES
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
    cnf = CNF()
    a_bits, b_bits = in_bits[0:4], in_bits[4:8]
    c_bits, d_bits = in_bits[8:12], in_bits[12:16]

    a_out, b_out = out_bits[0:4], out_bits[4:8]
    c_out, d_out = out_bits[8:12], out_bits[12:16]

    # MixColumns matrix [[3, 2], [2, 3]]
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

sbox = {
    0x0: 0xE, 0x1: 0x3, 0x2: 0x4, 0x3: 0x8,
    0x4: 0x1, 0x5: 0xC, 0x6: 0xA, 0x7: 0xF,
    0x8: 0x7, 0x9: 0xD, 0xA: 0x9, 0xB: 0x6,
    0xC: 0xB, 0xD: 0x2, 0xE: 0x0, 0xF: 0x5
}

# Global variable counter
var_counter = 1
def new_vars(n):
    global var_counter
    vars = list(range(var_counter, var_counter + n))
    var_counter += n
    return vars

# ---- CNF Construction Function ----
def build_cnf_model():
    global var_counter
    var_counter = 1  # reset counter for fresh var IDs
    cnf = CNF()

    plaintext_vars = new_vars(16)
    key_vars = new_vars(16)
    after_xor1 = new_vars(16)

    for i in range(16):
        cnf.extend(xor_cnf(plaintext_vars[i], key_vars[i], after_xor1[i]))

    after_sbox1 = new_vars(16)
    for i in range(0, 16, 4):
        cnf.extend(encode_sbox_to_cnf(sbox, after_xor1[i:i+4], after_sbox1[i:i+4]).clauses)

    after_shift1 = [after_sbox1[0:4], after_sbox1[12:16], after_sbox1[8:12], after_sbox1[4:8]]
    after_shift1 = [b for group in after_shift1 for b in group]

    after_mix = new_vars(16)
    cnf.extend(encode_mixcolumns_to_cnf(after_shift1, after_mix).clauses)

    after_xor2 = new_vars(16)
    for i in range(16):
        cnf.extend(xor_cnf(after_mix[i], key_vars[i], after_xor2[i]))

    after_sbox2 = new_vars(16)
    for i in range(0, 16, 4):
        cnf.extend(encode_sbox_to_cnf(sbox, after_xor2[i:i+4], after_sbox2[i:i+4]).clauses)

    after_shift2 = [after_sbox2[0:4], after_sbox2[12:16], after_sbox2[8:12], after_sbox2[4:8]]
    after_shift2 = [b for group in after_shift2 for b in group]

    final_output = new_vars(16)
    for i in range(16):
        cnf.extend(xor_cnf(after_shift2[i], key_vars[i], final_output[i]))

    return cnf, plaintext_vars, final_output, key_vars


# ======= Main Solver Code =======
start_time = time.time()
plaintext = 0x6996 # example intercepted plaintext
ciphertext = 0x89AB  # example intercepted ciphertext

cnf, plaintext_bits, final_output, key_bits = build_cnf_model()

cnf.extend([[b] for b in set_bits(plaintext, plaintext_bits)])
cnf.extend([[b] for b in set_bits(ciphertext, final_output)])

print(f"Generated {len(cnf.clauses)} clauses.")

# --------------- Solve ---------------        
found_keys = set()
with Solver(bootstrap_with=cnf) as solver:
    while solver.solve():
        model = solver.get_model()
        key = 0
        block = []
        for i, k in enumerate(key_bits):
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