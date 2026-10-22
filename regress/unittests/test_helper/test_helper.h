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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <stdint.h>

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/bn.h>
#അന്തര്ഭാവ <openssl/err.h>
#endif

എണ്ണൽ test_predicate {
	TEST_EQ, TEST_NE, TEST_LT, TEST_LE, TEST_GT, TEST_GE
};
തരനിർവചനം ശൂന്യം (test_onerror_func_t)(ശൂന്യം *);

/* Supplied by test suite */
ശൂന്യം tests(ശൂന്യം);
ശൂന്യം benchmarks(ശൂന്യം);

ശൂന്യം hex2bin(uint8_t *, സ്ഥിരം അക്ഷരം *, size_t);

സ്ഥിരം അക്ഷരം *test_data_file(സ്ഥിരം അക്ഷരം *name);
ശൂന്യം test_start(സ്ഥിരം അക്ഷരം *n);
ശൂന്യം test_info(അക്ഷരം *s, size_t len);
ശൂന്യം set_onerror_func(test_onerror_func_t *f, ശൂന്യം *ctx);
ശൂന്യം test_done(ശൂന്യം);
പൂർണ്ണസംഖ്യ test_is_verbose(ശൂന്യം);
പൂർണ്ണസംഖ്യ test_is_quiet(ശൂന്യം);
പൂർണ്ണസംഖ്യ test_is_fast(ശൂന്യം);
പൂർണ്ണസംഖ്യ test_is_slow(ശൂന്യം);
പൂർണ്ണസംഖ്യ test_is_benchmark(ശൂന്യം);
ശൂന്യം test_subtest_info(സ്ഥിരം അക്ഷരം *fmt, ...)
    __attribute__((format(printf, 1, 2)));
ശൂന്യം ssl_err_check(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി);
#ifdef WITH_OPENSSL
ശൂന്യം assert_bignum(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി,
    സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    സ്ഥിരം BIGNUM *aa1, സ്ഥിരം BIGNUM *aa2, എണ്ണൽ test_predicate pred);
#endif
ശൂന്യം assert_string(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി,
    സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    സ്ഥിരം അക്ഷരം *aa1, സ്ഥിരം അക്ഷരം *aa2, എണ്ണൽ test_predicate pred);
ശൂന്യം assert_mem(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി,
    സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    സ്ഥിരം ശൂന്യം *aa1, സ്ഥിരം ശൂന്യം *aa2, size_t l, എണ്ണൽ test_predicate pred);
ശൂന്യം assert_mem_filled(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി,
    സ്ഥിരം അക്ഷരം *a1,
    സ്ഥിരം ശൂന്യം *aa1, u_char v, size_t l, എണ്ണൽ test_predicate pred);
ശൂന്യം assert_int(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി,
    സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    പൂർണ്ണസംഖ്യ aa1, പൂർണ്ണസംഖ്യ aa2, എണ്ണൽ test_predicate pred);
ശൂന്യം assert_size_t(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി,
    സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    size_t aa1, size_t aa2, എണ്ണൽ test_predicate pred);
ശൂന്യം assert_u_int(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി,
    സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    u_int aa1, u_int aa2, എണ്ണൽ test_predicate pred);
ശൂന്യം assert_long(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി,
    സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    long aa1, long aa2, എണ്ണൽ test_predicate pred);
ശൂന്യം assert_long_long(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി,
    സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    long long aa1, long long aa2, എണ്ണൽ test_predicate pred);
ശൂന്യം assert_char(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി,
    സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    അക്ഷരം aa1, അക്ഷരം aa2, എണ്ണൽ test_predicate pred);
ശൂന്യം assert_ptr(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി,
    സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    സ്ഥിരം ശൂന്യം *aa1, സ്ഥിരം ശൂന്യം *aa2, എണ്ണൽ test_predicate pred);
ശൂന്യം assert_u8(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി,
    സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    uint8_t aa1, uint8_t aa2, എണ്ണൽ test_predicate pred);
ശൂന്യം assert_u16(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി,
    സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    uint16_t aa1, uint16_t aa2, എണ്ണൽ test_predicate pred);
ശൂന്യം assert_u32(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി,
    സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    uint32_t aa1, uint32_t aa2, എണ്ണൽ test_predicate pred);
ശൂന്യം assert_u64(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി,
    സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    uint64_t aa1, uint64_t aa2, എണ്ണൽ test_predicate pred);
ശൂന്യം assert_double(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി,
    സ്ഥിരം അക്ഷരം *a1, സ്ഥിരം അക്ഷരം *a2,
    ഇരട്ട aa1, ഇരട്ട aa2, എണ്ണൽ test_predicate pred);

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
	ചെയ്യുക { \
		bench_start(__FILE__, __LINE__, name); \
		ആകുമ്പോൾ (!bench_done()) { \
			bench_case_start(__FILE__, __LINE__); \
			ചെയ്യുക {
#define BENCH_FINISH(unit) \
			} ആകുമ്പോൾ (0); \
			bench_case_finish(__FILE__, __LINE__); \
		} \
		bench_finish(__FILE__, __LINE__, unit); \
	} ആകുമ്പോൾ (0)

ശൂന്യം bench_start(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി, സ്ഥിരം അക്ഷരം *name);
ശൂന്യം bench_case_start(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി);
ശൂന്യം bench_case_finish(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി);
ശൂന്യം bench_finish(സ്ഥിരം അക്ഷരം *file, പൂർണ്ണസംഖ്യ വരി, സ്ഥിരം അക്ഷരം *unit);
പൂർണ്ണസംഖ്യ bench_done(ശൂന്യം);

/* Fuzzing support */

ഘടന fuzz;
#define FUZZ_1_BIT_FLIP		0x00000001	/* Flip one bit at a time */
#define FUZZ_2_BIT_FLIP		0x00000002	/* Flip two bits at a time */
#define FUZZ_1_BYTE_FLIP	0x00000004	/* Flip one byte at a time */
#define FUZZ_2_BYTE_FLIP	0x00000008	/* Flip two bytes at a time */
#define FUZZ_TRUNCATE_START	0x00000010	/* Truncate from beginning */
#define FUZZ_TRUNCATE_END	0x00000020	/* Truncate from end */
#define FUZZ_BASE64		0x00000040	/* Try all base64 chars */
#define FUZZ_MAX		FUZZ_BASE64

/* Start fuzzing a blob of data with selected strategies (bitmask) */
ഘടന fuzz *fuzz_begin(u_int strategies, സ്ഥിരം ശൂന്യം *p, size_t l);

/* Free a fuzz context */
ശൂന്യം fuzz_cleanup(ഘടന fuzz *fuzz);

/* Prepare the next fuzz case in the series */
ശൂന്യം fuzz_next(ഘടന fuzz *fuzz);

/*
 * Check whether this fuzz case is identical to the original
 * This is slow, but useful if the caller needs to ensure that all tests
 * generated change the input (e.g. when fuzzing signatures).
 */
പൂർണ്ണസംഖ്യ fuzz_matches_original(ഘടന fuzz *fuzz);

/* Determine whether the current fuzz sequence is exhausted (nonzero = yes) */
പൂർണ്ണസംഖ്യ fuzz_done(ഘടന fuzz *fuzz);

/* Return the length and a pointer to the current fuzzed case */
size_t fuzz_len(ഘടന fuzz *fuzz);
u_char *fuzz_ptr(ഘടന fuzz *fuzz);

/* Dump the current fuzz case to stderr */
ശൂന്യം fuzz_dump(ഘടന fuzz *fuzz);

#endif /* _TEST_HELPER_H */
