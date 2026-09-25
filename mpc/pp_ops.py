# Exported MP-SPDZ functions called by the computation parties
# (src/mpspdz_party.cpp via Machine::run_function).
#
# Compile (done by CMake): compile.py -E semi2k -R 128 mpc/pp_ops.py
#
# Domain: arithmetic modulo 2^128. Operands are unsigned integers below 2^66
# (see include/pps/ring.hpp). MP-SPDZ comparisons interpret operands as
# signed integers of `program.bit_length` bits and compare their difference;
# a bit length of 67 therefore covers [0, 2^66) exactly. With -E semi2k,
# MP-SPDZ implements the comparison and the truncation by splitting each
# additive share into binary shares and evaluating exact binary circuits
# (DEK20 techniques); there is no statistical error.

program.set_bit_length(67)

MAX_BATCH = 4096


@export
def leq(a, b):
    # [a <= b] as an arithmetic share of 0/1
    return a <= b


@export
def half(a):
    # Exact floor(a / 2) for 0 <= a < 2^66 (unsigned truncation).
    return a.__rshift__(1, bit_length=67, signed=False)


size = 1
while size <= MAX_BATCH:
    leq(sint(0, size=size), sint(0, size=size))
    half(sint(0, size=size))
    size *= 2
