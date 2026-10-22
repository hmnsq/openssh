/*	$OpenBSD: test_helper.h,v 1.13 2026/06/16 22:27:10 dtucker Exp $	*/
/*
 * Copyright (c) 2011 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Utility functions/framework for regress tests */

#ifndef _TEST_HELPER_H
#define _TEST_HELPER_H

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <stdint.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/err.h>
#endif

எண்ணிக்கை test_predicate {
	TEST_EQ, TEST_NE, TEST_LT, TEST_LE, TEST_GT, TEST_GE
};
வகைவரை வெறுமை (test_onerror_func_t)(வெறுமை *);

/* Supplied by test suite */
வெறுமை tests(வெறுமை);
வெறுமை benchmarks(வெறுமை);

வெறுமை hex2bin(uint8_t *, மாறிலி எழுத்து *, size_t);

மாறிலி எழுத்து *test_data_file(மாறிலி எழுத்து *name);
வெறுமை test_start(மாறிலி எழுத்து *n);
வெறுமை test_info(எழுத்து *s, size_t len);
வெறுமை set_onerror_func(test_onerror_func_t *f, வெறுமை *ctx);
வெறுமை test_done(வெறுமை);
முழு test_is_verbose(வெறுமை);
முழு test_is_quiet(வெறுமை);
முழு test_is_fast(வெறுமை);
முழு test_is_slow(வெறுமை);
முழு test_is_benchmark(வெறுமை);
வெறுமை test_subtest_info(மாறிலி எழுத்து *fmt, ...)
    __attribute__((format(printf, 1, 2)));
வெறுமை ssl_err_check(மாறிலி எழுத்து *file, முழு வரி);
#ifdef WITH_OPENSSL
வெறுமை assert_bignum(மாறிலி எழுத்து *file, முழு வரி,
    மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    மாறிலி BIGNUM *aa1, மாறிலி BIGNUM *aa2, எண்ணிக்கை test_predicate pred);
#endif
வெறுமை assert_string(மாறிலி எழுத்து *file, முழு வரி,
    மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    மாறிலி எழுத்து *aa1, மாறிலி எழுத்து *aa2, எண்ணிக்கை test_predicate pred);
வெறுமை assert_mem(மாறிலி எழுத்து *file, முழு வரி,
    மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    மாறிலி வெறுமை *aa1, மாறிலி வெறுமை *aa2, size_t l, எண்ணிக்கை test_predicate pred);
வெறுமை assert_mem_filled(மாறிலி எழுத்து *file, முழு வரி,
    மாறிலி எழுத்து *a1,
    மாறிலி வெறுமை *aa1, u_char v, size_t l, எண்ணிக்கை test_predicate pred);
வெறுமை assert_int(மாறிலி எழுத்து *file, முழு வரி,
    மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    முழு aa1, முழு aa2, எண்ணிக்கை test_predicate pred);
வெறுமை assert_size_t(மாறிலி எழுத்து *file, முழு வரி,
    மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    size_t aa1, size_t aa2, எண்ணிக்கை test_predicate pred);
வெறுமை assert_u_int(மாறிலி எழுத்து *file, முழு வரி,
    மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    u_int aa1, u_int aa2, எண்ணிக்கை test_predicate pred);
வெறுமை assert_long(மாறிலி எழுத்து *file, முழு வரி,
    மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    long aa1, long aa2, எண்ணிக்கை test_predicate pred);
வெறுமை assert_long_long(மாறிலி எழுத்து *file, முழு வரி,
    மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    long long aa1, long long aa2, எண்ணிக்கை test_predicate pred);
வெறுமை assert_char(மாறிலி எழுத்து *file, முழு வரி,
    மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    எழுத்து aa1, எழுத்து aa2, எண்ணிக்கை test_predicate pred);
வெறுமை assert_ptr(மாறிலி எழுத்து *file, முழு வரி,
    மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    மாறிலி வெறுமை *aa1, மாறிலி வெறுமை *aa2, எண்ணிக்கை test_predicate pred);
வெறுமை assert_u8(மாறிலி எழுத்து *file, முழு வரி,
    மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    uint8_t aa1, uint8_t aa2, எண்ணிக்கை test_predicate pred);
வெறுமை assert_u16(மாறிலி எழுத்து *file, முழு வரி,
    மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    uint16_t aa1, uint16_t aa2, எண்ணிக்கை test_predicate pred);
வெறுமை assert_u32(மாறிலி எழுத்து *file, முழு வரி,
    மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    uint32_t aa1, uint32_t aa2, எண்ணிக்கை test_predicate pred);
வெறுமை assert_u64(மாறிலி எழுத்து *file, முழு வரி,
    மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    uint64_t aa1, uint64_t aa2, எண்ணிக்கை test_predicate pred);
வெறுமை assert_double(மாறிலி எழுத்து *file, முழு வரி,
    மாறிலி எழுத்து *a1, மாறிலி எழுத்து *a2,
    இரட்டை aa1, இரட்டை aa2, எண்ணிக்கை test_predicate pred);

#define TEST_START(n)			test_start(n)
#define TEST_DONE()			test_done()
#define TEST_ONERROR(f, c)		set_onerror_func(f, c)
#define SSL_ERR_CHECK() 		ssl_err_check(__FILE__, __LINE__)

#define ASSERT_BIGNUM_EQ(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#define ASSERT_STRING_EQ(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#define ASSERT_MEM_EQ(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_EQ)
#define ASSERT_MEM_FILLED_EQ(a1, c, l) \
	assert_mem_filled(__FILE__, __LINE__, #a1, a1, c, l, TEST_EQ)
#define ASSERT_MEM_ZERO_EQ(a1, l) \
	assert_mem_filled(__FILE__, __LINE__, #a1, a1, '\0', l, TEST_EQ)
#define ASSERT_INT_EQ(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#define ASSERT_SIZE_T_EQ(a1, a2) \
	assert_size_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#define ASSERT_U_INT_EQ(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#define ASSERT_LONG_EQ(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#define ASSERT_LONG_LONG_EQ(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#define ASSERT_CHAR_EQ(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#define ASSERT_PTR_EQ(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#define ASSERT_U8_EQ(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#define ASSERT_U16_EQ(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#define ASSERT_U32_EQ(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#define ASSERT_U64_EQ(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)

#define ASSERT_BIGNUM_NE(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#define ASSERT_STRING_NE(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#define ASSERT_MEM_NE(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_NE)
#define ASSERT_MEM_ZERO_NE(a1, l) \
	assert_mem_filled(__FILE__, __LINE__, #a1, a1, '\0', l, TEST_NE)
#define ASSERT_INT_NE(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#define ASSERT_SIZE_T_NE(a1, a2) \
	assert_size_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#define ASSERT_U_INT_NE(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#define ASSERT_LONG_NE(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#define ASSERT_LONG_LONG_NE(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#define ASSERT_CHAR_NE(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#define ASSERT_PTR_NE(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#define ASSERT_U8_NE(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#define ASSERT_U16_NE(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#define ASSERT_U32_NE(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#define ASSERT_U64_NE(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)

#define ASSERT_BIGNUM_LT(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#define ASSERT_STRING_LT(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#define ASSERT_MEM_LT(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_LT)
#define ASSERT_INT_LT(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#define ASSERT_SIZE_T_LT(a1, a2) \
	assert_size_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#define ASSERT_U_INT_LT(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#define ASSERT_LONG_LT(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#define ASSERT_LONG_LONG_LT(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#define ASSERT_CHAR_LT(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#define ASSERT_PTR_LT(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#define ASSERT_U8_LT(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#define ASSERT_U16_LT(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#define ASSERT_U32_LT(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#define ASSERT_U64_LT(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)

#define ASSERT_BIGNUM_LE(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#define ASSERT_STRING_LE(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#define ASSERT_MEM_LE(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_LE)
#define ASSERT_INT_LE(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#define ASSERT_SIZE_T_LE(a1, a2) \
	assert_size_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#define ASSERT_U_INT_LE(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#define ASSERT_LONG_LE(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#define ASSERT_LONG_LONG_LE(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#define ASSERT_CHAR_LE(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#define ASSERT_PTR_LE(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#define ASSERT_U8_LE(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#define ASSERT_U16_LE(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#define ASSERT_U32_LE(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#define ASSERT_U64_LE(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)

#define ASSERT_BIGNUM_GT(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#define ASSERT_STRING_GT(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#define ASSERT_MEM_GT(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_GT)
#define ASSERT_INT_GT(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#define ASSERT_SIZE_T_GT(a1, a2) \
	assert_size_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#define ASSERT_U_INT_GT(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#define ASSERT_LONG_GT(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#define ASSERT_LONG_LONG_GT(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#define ASSERT_CHAR_GT(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#define ASSERT_PTR_GT(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#define ASSERT_U8_GT(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#define ASSERT_U16_GT(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#define ASSERT_U32_GT(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#define ASSERT_U64_GT(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)

#define ASSERT_BIGNUM_GE(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#define ASSERT_STRING_GE(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#define ASSERT_MEM_GE(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_GE)
#define ASSERT_INT_GE(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#define ASSERT_SIZE_T_GE(a1, a2) \
	assert_size_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#define ASSERT_U_INT_GE(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#define ASSERT_LONG_GE(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#define ASSERT_LONG_LONG_GE(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#define ASSERT_CHAR_GE(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#define ASSERT_PTR_GE(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#define ASSERT_U8_GE(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#define ASSERT_U16_GE(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#define ASSERT_U32_GE(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#define ASSERT_U64_GE(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)

#define ASSERT_DOUBLE_EQ(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#define ASSERT_DOUBLE_NE(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#define ASSERT_DOUBLE_LT(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#define ASSERT_DOUBLE_LE(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#define ASSERT_DOUBLE_GT(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#define ASSERT_DOUBLE_GE(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)

/* Benchmarking support */
#define BENCH_START(name)	\
	செய் { \
		bench_start(__FILE__, __LINE__, name); \
		போது (!bench_done()) { \
			bench_case_start(__FILE__, __LINE__); \
			செய் {
#define BENCH_FINISH(unit) \
			} போது (0); \
			bench_case_finish(__FILE__, __LINE__); \
		} \
		bench_finish(__FILE__, __LINE__, unit); \
	} போது (0)

வெறுமை bench_start(மாறிலி எழுத்து *file, முழு வரி, மாறிலி எழுத்து *name);
வெறுமை bench_case_start(மாறிலி எழுத்து *file, முழு வரி);
வெறுமை bench_case_finish(மாறிலி எழுத்து *file, முழு வரி);
வெறுமை bench_finish(மாறிலி எழுத்து *file, முழு வரி, மாறிலி எழுத்து *unit);
முழு bench_done(வெறுமை);

/* Fuzzing support */

கட்டமைப்பு fuzz;
#define FUZZ_1_BIT_FLIP		0x00000001	/* Flip one bit at a time */
#define FUZZ_2_BIT_FLIP		0x00000002	/* Flip two bits at a time */
#define FUZZ_1_BYTE_FLIP	0x00000004	/* Flip one byte at a time */
#define FUZZ_2_BYTE_FLIP	0x00000008	/* Flip two bytes at a time */
#define FUZZ_TRUNCATE_START	0x00000010	/* Truncate from beginning */
#define FUZZ_TRUNCATE_END	0x00000020	/* Truncate from end */
#define FUZZ_BASE64		0x00000040	/* Try all base64 chars */
#define FUZZ_MAX		FUZZ_BASE64

/* Start fuzzing a blob of data with selected strategies (bitmask) */
கட்டமைப்பு fuzz *fuzz_begin(u_int strategies, மாறிலி வெறுமை *p, size_t l);

/* Free a fuzz context */
வெறுமை fuzz_cleanup(கட்டமைப்பு fuzz *fuzz);

/* Prepare the next fuzz case in the series */
வெறுமை fuzz_next(கட்டமைப்பு fuzz *fuzz);

/*
 * Check whether this fuzz case is identical to the original
 * This is slow, but useful if the caller needs to ensure that all tests
 * generated change the input (e.g. when fuzzing signatures).
 */
முழு fuzz_matches_original(கட்டமைப்பு fuzz *fuzz);

/* Determine whether the current fuzz sequence is exhausted (nonzero = yes) */
முழு fuzz_done(கட்டமைப்பு fuzz *fuzz);

/* Return the length and a pointer to the current fuzzed case */
size_t fuzz_len(கட்டமைப்பு fuzz *fuzz);
u_char *fuzz_ptr(கட்டமைப்பு fuzz *fuzz);

/* Dump the current fuzz case to stderr */
வெறுமை fuzz_dump(கட்டமைப்பு fuzz *fuzz);

#endif /* _TEST_HELPER_H */
