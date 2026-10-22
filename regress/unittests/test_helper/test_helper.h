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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <stdint.h>

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/bn.h>
#અન્તર્ભાવ <openssl/err.h>
#endif

ગણના test_predicate {
	TEST_EQ, TEST_NE, TEST_LT, TEST_LE, TEST_GT, TEST_GE
};
પ્રકારવ્યાખ્યા શૂન્ય (test_onerror_func_t)(શૂન્ય *);

/* Supplied by test suite */
શૂન્ય tests(શૂન્ય);
શૂન્ય benchmarks(શૂન્ય);

શૂન્ય hex2bin(uint8_t *, અચલ અક્ષર *, size_t);

અચલ અક્ષર *test_data_file(અચલ અક્ષર *name);
શૂન્ય test_start(અચલ અક્ષર *n);
શૂન્ય test_info(અક્ષર *s, size_t len);
શૂન્ય set_onerror_func(test_onerror_func_t *f, શૂન્ય *ctx);
શૂન્ય test_done(શૂન્ય);
પૂર્ણાંક test_is_verbose(શૂન્ય);
પૂર્ણાંક test_is_quiet(શૂન્ય);
પૂર્ણાંક test_is_fast(શૂન્ય);
પૂર્ણાંક test_is_slow(શૂન્ય);
પૂર્ણાંક test_is_benchmark(શૂન્ય);
શૂન્ય test_subtest_info(અચલ અક્ષર *fmt, ...)
    __attribute__((format(printf, 1, 2)));
શૂન્ય ssl_err_check(અચલ અક્ષર *file, પૂર્ણાંક લીટી);
#ifdef WITH_OPENSSL
શૂન્ય assert_bignum(અચલ અક્ષર *file, પૂર્ણાંક લીટી,
    અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    અચલ BIGNUM *aa1, અચલ BIGNUM *aa2, ગણના test_predicate pred);
#endif
શૂન્ય assert_string(અચલ અક્ષર *file, પૂર્ણાંક લીટી,
    અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    અચલ અક્ષર *aa1, અચલ અક્ષર *aa2, ગણના test_predicate pred);
શૂન્ય assert_mem(અચલ અક્ષર *file, પૂર્ણાંક લીટી,
    અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    અચલ શૂન્ય *aa1, અચલ શૂન્ય *aa2, size_t l, ગણના test_predicate pred);
શૂન્ય assert_mem_filled(અચલ અક્ષર *file, પૂર્ણાંક લીટી,
    અચલ અક્ષર *a1,
    અચલ શૂન્ય *aa1, u_char v, size_t l, ગણના test_predicate pred);
શૂન્ય assert_int(અચલ અક્ષર *file, પૂર્ણાંક લીટી,
    અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    પૂર્ણાંક aa1, પૂર્ણાંક aa2, ગણના test_predicate pred);
શૂન્ય assert_size_t(અચલ અક્ષર *file, પૂર્ણાંક લીટી,
    અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    size_t aa1, size_t aa2, ગણના test_predicate pred);
શૂન્ય assert_u_int(અચલ અક્ષર *file, પૂર્ણાંક લીટી,
    અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    u_int aa1, u_int aa2, ગણના test_predicate pred);
શૂન્ય assert_long(અચલ અક્ષર *file, પૂર્ણાંક લીટી,
    અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    long aa1, long aa2, ગણના test_predicate pred);
શૂન્ય assert_long_long(અચલ અક્ષર *file, પૂર્ણાંક લીટી,
    અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    long long aa1, long long aa2, ગણના test_predicate pred);
શૂન્ય assert_char(અચલ અક્ષર *file, પૂર્ણાંક લીટી,
    અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    અક્ષર aa1, અક્ષર aa2, ગણના test_predicate pred);
શૂન્ય assert_ptr(અચલ અક્ષર *file, પૂર્ણાંક લીટી,
    અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    અચલ શૂન્ય *aa1, અચલ શૂન્ય *aa2, ગણના test_predicate pred);
શૂન્ય assert_u8(અચલ અક્ષર *file, પૂર્ણાંક લીટી,
    અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    uint8_t aa1, uint8_t aa2, ગણના test_predicate pred);
શૂન્ય assert_u16(અચલ અક્ષર *file, પૂર્ણાંક લીટી,
    અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    uint16_t aa1, uint16_t aa2, ગણના test_predicate pred);
શૂન્ય assert_u32(અચલ અક્ષર *file, પૂર્ણાંક લીટી,
    અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    uint32_t aa1, uint32_t aa2, ગણના test_predicate pred);
શૂન્ય assert_u64(અચલ અક્ષર *file, પૂર્ણાંક લીટી,
    અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    uint64_t aa1, uint64_t aa2, ગણના test_predicate pred);
શૂન્ય assert_double(અચલ અક્ષર *file, પૂર્ણાંક લીટી,
    અચલ અક્ષર *a1, અચલ અક્ષર *a2,
    દ્વિગુણ aa1, દ્વિગુણ aa2, ગણના test_predicate pred);

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
	કરો { \
		bench_start(__FILE__, __LINE__, name); \
		જ્યારે (!bench_done()) { \
			bench_case_start(__FILE__, __LINE__); \
			કરો {
#define BENCH_FINISH(unit) \
			} જ્યારે (0); \
			bench_case_finish(__FILE__, __LINE__); \
		} \
		bench_finish(__FILE__, __LINE__, unit); \
	} જ્યારે (0)

શૂન્ય bench_start(અચલ અક્ષર *file, પૂર્ણાંક લીટી, અચલ અક્ષર *name);
શૂન્ય bench_case_start(અચલ અક્ષર *file, પૂર્ણાંક લીટી);
શૂન્ય bench_case_finish(અચલ અક્ષર *file, પૂર્ણાંક લીટી);
શૂન્ય bench_finish(અચલ અક્ષર *file, પૂર્ણાંક લીટી, અચલ અક્ષર *unit);
પૂર્ણાંક bench_done(શૂન્ય);

/* Fuzzing support */

સંરચના fuzz;
#define FUZZ_1_BIT_FLIP		0x00000001	/* Flip one bit at a time */
#define FUZZ_2_BIT_FLIP		0x00000002	/* Flip two bits at a time */
#define FUZZ_1_BYTE_FLIP	0x00000004	/* Flip one byte at a time */
#define FUZZ_2_BYTE_FLIP	0x00000008	/* Flip two bytes at a time */
#define FUZZ_TRUNCATE_START	0x00000010	/* Truncate from beginning */
#define FUZZ_TRUNCATE_END	0x00000020	/* Truncate from end */
#define FUZZ_BASE64		0x00000040	/* Try all base64 chars */
#define FUZZ_MAX		FUZZ_BASE64

/* Start fuzzing a blob of data with selected strategies (bitmask) */
સંરચના fuzz *fuzz_begin(u_int strategies, અચલ શૂન્ય *p, size_t l);

/* Free a fuzz context */
શૂન્ય fuzz_cleanup(સંરચના fuzz *fuzz);

/* Prepare the next fuzz case in the series */
શૂન્ય fuzz_next(સંરચના fuzz *fuzz);

/*
 * Check whether this fuzz case is identical to the original
 * This is slow, but useful if the caller needs to ensure that all tests
 * generated change the input (e.g. when fuzzing signatures).
 */
પૂર્ણાંક fuzz_matches_original(સંરચના fuzz *fuzz);

/* Determine whether the current fuzz sequence is exhausted (nonzero = yes) */
પૂર્ણાંક fuzz_done(સંરચના fuzz *fuzz);

/* Return the length and a pointer to the current fuzzed case */
size_t fuzz_len(સંરચના fuzz *fuzz);
u_char *fuzz_ptr(સંરચના fuzz *fuzz);

/* Dump the current fuzz case to stderr */
શૂન્ય fuzz_dump(સંરચના fuzz *fuzz);

#endif /* _TEST_HELPER_H */
