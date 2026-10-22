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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <stdint.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/bn.h>
#অন্তর্ভাব <openssl/err.h>
#endif

গণনা test_predicate {
	TEST_EQ, TEST_NE, TEST_LT, TEST_LE, TEST_GT, TEST_GE
};
প্রকারলেখ শূন্য (test_onerror_func_t)(শূন্য *);

/* Supplied by test suite */
শূন্য tests(শূন্য);
শূন্য benchmarks(শূন্য);

শূন্য hex2bin(uint8_t *, ধ্রুবক অক্ষর *, আকার_t);

ধ্রুবক অক্ষর *test_তথ্য_file(ধ্রুবক অক্ষর *name);
শূন্য test_start(ধ্রুবক অক্ষর *n);
শূন্য test_info(অক্ষর *s, আকার_t len);
শূন্য set_onerror_func(test_onerror_func_t *f, শূন্য *ctx);
শূন্য test_done(শূন্য);
পূর্ণসংখ্যা test_is_verbose(শূন্য);
পূর্ণসংখ্যা test_is_quiet(শূন্য);
পূর্ণসংখ্যা test_is_fast(শূন্য);
পূর্ণসংখ্যা test_is_slow(শূন্য);
পূর্ণসংখ্যা test_is_benchmark(শূন্য);
শূন্য test_subtest_info(ধ্রুবক অক্ষর *fmt, ...)
    __attribute__((format(printf, 1, 2)));
শূন্য ssl_err_check(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি);
#ifdef WITH_OPENSSL
শূন্য assert_bignum(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি,
    ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    ধ্রুবক BIGNUM *aa1, ধ্রুবক BIGNUM *aa2, গণনা test_predicate pred);
#endif
শূন্য assert_string(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি,
    ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    ধ্রুবক অক্ষর *aa1, ধ্রুবক অক্ষর *aa2, গণনা test_predicate pred);
শূন্য assert_mem(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি,
    ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    ধ্রুবক শূন্য *aa1, ধ্রুবক শূন্য *aa2, আকার_t l, গণনা test_predicate pred);
শূন্য assert_mem_filled(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি,
    ধ্রুবক অক্ষর *a1,
    ধ্রুবক শূন্য *aa1, u_char v, আকার_t l, গণনা test_predicate pred);
শূন্য assert_int(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি,
    ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    পূর্ণসংখ্যা aa1, পূর্ণসংখ্যা aa2, গণনা test_predicate pred);
শূন্য assert_আকার_t(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি,
    ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    আকার_t aa1, আকার_t aa2, গণনা test_predicate pred);
শূন্য assert_u_int(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি,
    ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    u_int aa1, u_int aa2, গণনা test_predicate pred);
শূন্য assert_long(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি,
    ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    long aa1, long aa2, গণনা test_predicate pred);
শূন্য assert_long_long(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি,
    ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    long long aa1, long long aa2, গণনা test_predicate pred);
শূন্য assert_char(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি,
    ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    অক্ষর aa1, অক্ষর aa2, গণনা test_predicate pred);
শূন্য assert_ptr(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি,
    ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    ধ্রুবক শূন্য *aa1, ধ্রুবক শূন্য *aa2, গণনা test_predicate pred);
শূন্য assert_u8(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি,
    ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    uint8_t aa1, uint8_t aa2, গণনা test_predicate pred);
শূন্য assert_u16(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি,
    ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    uint16_t aa1, uint16_t aa2, গণনা test_predicate pred);
শূন্য assert_u32(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি,
    ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    uint32_t aa1, uint32_t aa2, গণনা test_predicate pred);
শূন্য assert_u64(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি,
    ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    uint64_t aa1, uint64_t aa2, গণনা test_predicate pred);
শূন্য assert_double(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি,
    ধ্রুবক অক্ষর *a1, ধ্রুবক অক্ষর *a2,
    দ্বিগুণ aa1, দ্বিগুণ aa2, গণনা test_predicate pred);

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
#define ASSERT_আকার_T_EQ(a1, a2) \
	assert_আকার_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
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
#define ASSERT_আকার_T_NE(a1, a2) \
	assert_আকার_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
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
#define ASSERT_আকার_T_LT(a1, a2) \
	assert_আকার_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
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
#define ASSERT_আকার_T_LE(a1, a2) \
	assert_আকার_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
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
#define ASSERT_আকার_T_GT(a1, a2) \
	assert_আকার_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
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
#define ASSERT_আকার_T_GE(a1, a2) \
	assert_আকার_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
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
	করো { \
		bench_start(__FILE__, __LINE__, name); \
		যখন (!bench_done()) { \
			bench_case_start(__FILE__, __LINE__); \
			করো {
#define BENCH_FINISH(unit) \
			} যখন (0); \
			bench_case_finish(__FILE__, __LINE__); \
		} \
		bench_finish(__FILE__, __LINE__, unit); \
	} যখন (0)

শূন্য bench_start(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি, ধ্রুবক অক্ষর *name);
শূন্য bench_case_start(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি);
শূন্য bench_case_finish(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি);
শূন্য bench_finish(ধ্রুবক অক্ষর *file, পূর্ণসংখ্যা সারি, ধ্রুবক অক্ষর *unit);
পূর্ণসংখ্যা bench_done(শূন্য);

/* Fuzzing support */

কাঠামো fuzz;
#define FUZZ_1_BIT_FLIP		0x00000001	/* Flip one bit at a time */
#define FUZZ_2_BIT_FLIP		0x00000002	/* Flip two bits at a time */
#define FUZZ_1_BYTE_FLIP	0x00000004	/* Flip one byte at a time */
#define FUZZ_2_BYTE_FLIP	0x00000008	/* Flip two bytes at a time */
#define FUZZ_TRUNCATE_START	0x00000010	/* Truncate from beginning */
#define FUZZ_TRUNCATE_END	0x00000020	/* Truncate from end */
#define FUZZ_BASE64		0x00000040	/* Try all base64 chars */
#define FUZZ_MAX		FUZZ_BASE64

/* Start fuzzing a blob of data with selected strategies (bitmask) */
কাঠামো fuzz *fuzz_begin(u_int strategies, ধ্রুবক শূন্য *p, আকার_t l);

/* Free a fuzz context */
শূন্য fuzz_cleanup(কাঠামো fuzz *fuzz);

/* Prepare the next fuzz case in the series */
শূন্য fuzz_পরবর্তী(কাঠামো fuzz *fuzz);

/*
 * Check whether this fuzz case is identical to the original
 * This is slow, but useful if the caller needs to ensure that all tests
 * generated change the input (e.g. when fuzzing signatures).
 */
পূর্ণসংখ্যা fuzz_matches_original(কাঠামো fuzz *fuzz);

/* Determine whether the current fuzz sequence is exhausted (nonzero = yes) */
পূর্ণসংখ্যা fuzz_done(কাঠামো fuzz *fuzz);

/* Return the length and a pointer to the current fuzzed case */
আকার_t fuzz_len(কাঠামো fuzz *fuzz);
u_char *fuzz_ptr(কাঠামো fuzz *fuzz);

/* Dump the current fuzz case to stderr */
শূন্য fuzz_dump(কাঠামো fuzz *fuzz);

#endif /* _TEST_HELPER_H */
