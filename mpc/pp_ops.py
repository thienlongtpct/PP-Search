# Exported MP-SPDZ functions called by the computation parties
# (src/backend/mpspdz_party.cpp via Machine::run_function).
#
# Compile (done by CMake): compile.py -E semi2k -R 128 mpc/pp_ops.py
#
# Domain: arithmetic modulo 2^128. Operands are unsigned integers below 2^66
# (see src/common/ring.hpp). MP-SPDZ comparisons interpret operands as
# signed integers of `program.bit_length` bits and compare their difference;
# a bit length of 67 therefore covers [0, 2^66) exactly. With -E semi2k,
# MP-SPDZ implements the comparison by splitting each
# additive share into binary shares and evaluating exact binary circuits
# (DEK20 techniques); there is no statistical error.
#
# That comparison only reads the low bits of its operands. Inputs are chosen by
# their owners, so fits_u32 checks them over the whole ring first.

program.set_bit_length(67)

MAX_BATCH = 4096


@export
def leq(a, b):
    # [a <= b] as an arithmetic share of 0/1
    return a <= b


@export
def fits_u32(v):
    # [0 <= v < 2^32] as an arithmetic share of 0/1, exact for all v modulo
    # 2^128. less_than adds one to bit_length, so 127 reads all 128 bits. Read
    # as signed, v - 2^32 only wraps for v near -2^127, which the first test
    # already rejects.
    negative = v.less_than(0, bit_length=127, maybe_mixed=True)
    below = v.less_than(2**32, bit_length=127, maybe_mixed=True)
    return sintbit.conv(below & ~negative)


size = 1
while size <= MAX_BATCH:
    leq(sint(0, size=size), sint(0, size=size))
    fits_u32(sint(0, size=size))
    size *= 2
