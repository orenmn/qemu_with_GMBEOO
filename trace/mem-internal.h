/*
 * Helper functions for guest memory tracing
 *
 * Copyright (C) 2016 Lluís Vilanova <vilanova@ac.upc.edu>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef TRACE__MEM_INTERNAL_H
#define TRACE__MEM_INTERNAL_H

#define TRACE_MEM_SZ_SHIFT_MASK 0x7 /* size shift mask */
#define TRACE_MEM_SE (1ULL << 3)    /* sign extended (y/n) */
#define TRACE_MEM_BE (1ULL << 4)    /* big endian (y/n) */
#define TRACE_MEM_ST (1ULL << 5)    /* store (y/n) */
#define TRACE_MEM_CPL_MASK (0x3)
#define TRACE_MEM_CPL_SHIFT (6)

static inline uint8_t trace_mem_build_info(
    int size_shift, bool sign_extend, TCGMemOp endianness, bool store, int cpl)
{
    uint8_t res;

    res = size_shift & TRACE_MEM_SZ_SHIFT_MASK;
    if (sign_extend) {
        res |= TRACE_MEM_SE;
    }
    if (endianness == MO_BE) {
        res |= TRACE_MEM_BE;
    }
    if (store) {
        res |= TRACE_MEM_ST;
    }
    res |= (cpl & TRACE_MEM_CPL_MASK) << TRACE_MEM_CPL_SHIFT;
    return res;
}

static inline uint8_t trace_mem_get_info(TCGMemOp op, bool store, int cpl)
{
    return trace_mem_build_info(op & MO_SIZE, !!(op & MO_SIGN),
                                op & MO_BSWAP, store, cpl);
}

static inline
uint8_t trace_mem_build_info_no_se_be(int size_shift, bool store, int cpl)
{
    return trace_mem_build_info(size_shift, false, MO_BE, store, cpl);
}

static inline
uint8_t trace_mem_build_info_no_se_le(int size_shift, bool store, int cpl)
{
    return trace_mem_build_info(size_shift, false, MO_LE, store, cpl);
}

#endif /* TRACE__MEM_INTERNAL_H */
