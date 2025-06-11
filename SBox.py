# -*- coding: utf-8 -*-
"""
Created on Sun Apr 27 19:03:57 2025
@author: Admin
Sbox
"""
from pysat.formula import CNF
from pysat.solvers import Solver

sbox_values = {
    0x0: 0xE, 0x1: 0x3, 0x2: 0x4, 0x3: 0x8,
    0x4: 0x1, 0x5: 0xC, 0x6: 0xA, 0x7: 0xF,
    0x8: 0x7, 0x9: 0xD, 0xA: 0x9, 0xB: 0x6,
    0xC: 0xB, 0xD: 0x2, 0xE: 0x0, 0xF: 0x5
}

def encode_sbox_to_cnf(sbox, inputs, outputs):
    """
    Encode a given S-box into CNF.
    Args:
    - sbox: dictionary mapping input integer to output integer.
    - inputs: list of variable numbers for input bits ([1,2,3,4])
    - outputs: list of variable numbers for output bits ([5,6,7,8])
    Returns:
    - cnf: pysat.formula.CNF objec
    """
    cnf = CNF()

    for input_value, output_value in sbox.items():
        cond_literals = []
        for i in range(4):
            # Get bits one by one, starting with most significant
            bit = (input_value >> (3 - i)) & 1
            lit = -inputs[i] if bit else inputs[i]
            cond_literals.append(lit)

        # For each output bit, build a clause
        for i in range(4):
            # Get bits one by one, starting with most significant
            bit = (output_value >> (3 - i)) & 1
            out_lit = outputs[i] if bit else -outputs[i]

            # Clause: (NOT condition) OR (output bit correct)
            clause = cond_literals + [out_lit]
            cnf.append(clause)

    return cnf

# Assign SAT variables
inputs = [1, 2, 3, 4]  # p0, p1, p2, p3
outputs = [5, 6, 7, 8] # q0, q1, q2, q3

# Encode S-box into CNF
cnf = encode_sbox_to_cnf(sbox_values, inputs, outputs)

print(f"Generated {len(cnf.clauses)} clauses.")
for clause in cnf.clauses[:8]:
    print(clause)

# Create a solver
with Solver(bootstrap_with=cnf) as solver:
    # Add assumption: here inputs are 0000
    solver.add_clause([-1])
    solver.add_clause([-2])
    solver.add_clause([-3])
    solver.add_clause([-4])
    
    # Check satisfiability
    satisfiable = solver.solve()
    model = solver.get_model()

    print("Is the model Satisfiable?:", satisfiable)
    if satisfiable:
        print("Model:", model)
        print("Input bits chosen:")
        for i, var in enumerate(inputs):
            value = 1 if var in model else 0
            print(f"p{i} = {value}")
        # Output bits need to be checked
        print("Outputs:")
        for i, var in enumerate(outputs):
            value = 1 if var in model else 0
            print(f"q{i} = {value}")