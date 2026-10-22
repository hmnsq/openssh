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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <stdint.h>

#ifdef WITH_OPENSSL
#شامل <openssl/bn.h>
#شامل <openssl/err.h>
#endif

شمارش test_predicate {
	TEST_EQ, TEST_NE, TEST_LT, TEST_LE, TEST_GT, TEST_GE
};
تعریفنوع تهی (test_onerror_func_t)(تهی *);

/* Supplied by test suite */
تهی tests(تهی);
تهی benchmarks(تهی);

تهی hex2bin(uint8_t *, ثابت نویسه *, size_t);

ثابت نویسه *test_data_file(ثابت نویسه *name);
تهی test_start(ثابت نویسه *n);
تهی test_info(نویسه *s, size_t len);
تهی set_onerror_func(test_onerror_func_t *f, تهی *ctx);
تهی test_done(تهی);
صحیح test_is_verbose(تهی);
صحیح test_is_quiet(تهی);
صحیح test_is_fast(تهی);
صحیح test_is_slow(تهی);
صحیح test_is_benchmark(تهی);
تهی test_subtest_info(ثابت نویسه *fmt, ...)
    __attribute__((format(printf, 1, 2)));
تهی ssl_err_check(ثابت نویسه *file, صحیح سطر);
#ifdef WITH_OPENSSL
تهی assert_bignum(ثابت نویسه *file, صحیح سطر,
    ثابت نویسه *a1, ثابت نویسه *a2,
    ثابت BIGNUM *aa1, ثابت BIGNUM *aa2, شمارش test_predicate pred);
#endif
تهی assert_string(ثابت نویسه *file, صحیح سطر,
    ثابت نویسه *a1, ثابت نویسه *a2,
    ثابت نویسه *aa1, ثابت نویسه *aa2, شمارش test_predicate pred);
تهی assert_mem(ثابت نویسه *file, صحیح سطر,
    ثابت نویسه *a1, ثابت نویسه *a2,
    ثابت تهی *aa1, ثابت تهی *aa2, size_t l, شمارش test_predicate pred);
تهی assert_mem_filled(ثابت نویسه *file, صحیح سطر,
    ثابت نویسه *a1,
    ثابت تهی *aa1, u_char v, size_t l, شمارش test_predicate pred);
تهی assert_int(ثابت نویسه *file, صحیح سطر,
    ثابت نویسه *a1, ثابت نویسه *a2,
    صحیح aa1, صحیح aa2, شمارش test_predicate pred);
تهی assert_size_t(ثابت نویسه *file, صحیح سطر,
    ثابت نویسه *a1, ثابت نویسه *a2,
    size_t aa1, size_t aa2, شمارش test_predicate pred);
تهی assert_u_int(ثابت نویسه *file, صحیح سطر,
    ثابت نویسه *a1, ثابت نویسه *a2,
    u_int aa1, u_int aa2, شمارش test_predicate pred);
تهی assert_long(ثابت نویسه *file, صحیح سطر,
    ثابت نویسه *a1, ثابت نویسه *a2,
    long aa1, long aa2, شمارش test_predicate pred);
تهی assert_long_long(ثابت نویسه *file, صحیح سطر,
    ثابت نویسه *a1, ثابت نویسه *a2,
    long long aa1, long long aa2, شمارش test_predicate pred);
تهی assert_char(ثابت نویسه *file, صحیح سطر,
    ثابت نویسه *a1, ثابت نویسه *a2,
    نویسه aa1, نویسه aa2, شمارش test_predicate pred);
تهی assert_ptr(ثابت نویسه *file, صحیح سطر,
    ثابت نویسه *a1, ثابت نویسه *a2,
    ثابت تهی *aa1, ثابت تهی *aa2, شمارش test_predicate pred);
تهی assert_u8(ثابت نویسه *file, صحیح سطر,
    ثابت نویسه *a1, ثابت نویسه *a2,
    uint8_t aa1, uint8_t aa2, شمارش test_predicate pred);
تهی assert_u16(ثابت نویسه *file, صحیح سطر,
    ثابت نویسه *a1, ثابت نویسه *a2,
    uint16_t aa1, uint16_t aa2, شمارش test_predicate pred);
تهی assert_u32(ثابت نویسه *file, صحیح سطر,
    ثابت نویسه *a1, ثابت نویسه *a2,
    uint32_t aa1, uint32_t aa2, شمارش test_predicate pred);
تهی assert_u64(ثابت نویسه *file, صحیح سطر,
    ثابت نویسه *a1, ثابت نویسه *a2,
    uint64_t aa1, uint64_t aa2, شمارش test_predicate pred);
تهی assert_double(ثابت نویسه *file, صحیح سطر,
    ثابت نویسه *a1, ثابت نویسه *a2,
    دوگانه aa1, دوگانه aa2, شمارش test_predicate pred);

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
	انجامبده { \
		bench_start(__FILE__, __LINE__, name); \
		وقتی (!bench_done()) { \
			bench_case_start(__FILE__, __LINE__); \
			انجامبده {
#define BENCH_FINISH(unit) \
			} وقتی (0); \
			bench_case_finish(__FILE__, __LINE__); \
		} \
		bench_finish(__FILE__, __LINE__, unit); \
	} وقتی (0)

تهی bench_start(ثابت نویسه *file, صحیح سطر, ثابت نویسه *name);
تهی bench_case_start(ثابت نویسه *file, صحیح سطر);
تهی bench_case_finish(ثابت نویسه *file, صحیح سطر);
تهی bench_finish(ثابت نویسه *file, صحیح سطر, ثابت نویسه *unit);
صحیح bench_done(تهی);

/* Fuzzing support */

ساختار fuzz;
#define FUZZ_1_BIT_FLIP		0x00000001	/* Flip one bit at a time */
#define FUZZ_2_BIT_FLIP		0x00000002	/* Flip two bits at a time */
#define FUZZ_1_BYTE_FLIP	0x00000004	/* Flip one byte at a time */
#define FUZZ_2_BYTE_FLIP	0x00000008	/* Flip two bytes at a time */
#define FUZZ_TRUNCATE_START	0x00000010	/* Truncate from beginning */
#define FUZZ_TRUNCATE_END	0x00000020	/* Truncate from end */
#define FUZZ_BASE64		0x00000040	/* Try all base64 chars */
#define FUZZ_MAX		FUZZ_BASE64

/* Start fuzzing a blob of data with selected strategies (bitmask) */
ساختار fuzz *fuzz_begin(u_int strategies, ثابت تهی *p, size_t l);

/* Free a fuzz context */
تهی fuzz_cleanup(ساختار fuzz *fuzz);

/* Prepare the next fuzz case in the series */
تهی fuzz_next(ساختار fuzz *fuzz);

/*
 * Check whether this fuzz case is identical to the original
 * This is slow, but useful if the caller needs to ensure that all tests
 * generated change the input (e.g. when fuzzing signatures).
 */
صحیح fuzz_matches_original(ساختار fuzz *fuzz);

/* Determine whether the current fuzz sequence is exhausted (nonzero = yes) */
صحیح fuzz_done(ساختار fuzz *fuzz);

/* Return the length and a pointer to the current fuzzed case */
size_t fuzz_len(ساختار fuzz *fuzz);
u_char *fuzz_ptr(ساختار fuzz *fuzz);

/* Dump the current fuzz case to stderr */
تهی fuzz_dump(ساختار fuzz *fuzz);

#endif /* _TEST_HELPER_H */
