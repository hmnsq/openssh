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

#اگر_غیر_تعریف_شدہ _TEST_HELPER_H
#تعریف_کرو _TEST_HELPER_H

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <stdint.h>

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/bn.h>
#شامل <openssl/err.h>
#اگر_ختم

شمار test_predicate {
	TEST_EQ, TEST_NE, TEST_LT, TEST_LE, TEST_GT, TEST_GE
};
قسمتعریف خالی (test_onerror_func_t)(خالی *);

/* Supplied by test suite */
خالی tests(خالی);
خالی benchmarks(خالی);

خالی hex2bin(uint8_t *, ثابت حرف *, سائز_t);

ثابت حرف *test_ڈیٹا_file(ثابت حرف *name);
خالی test_آغاز(ثابت حرف *n);
خالی test_info(حرف *s, سائز_t len);
خالی سیٹ_onerror_func(test_onerror_func_t *f, خالی *ctx);
خالی test_مکمل(خالی);
صحیح test_is_verbose(خالی);
صحیح test_is_quiet(خالی);
صحیح test_is_fast(خالی);
صحیح test_is_slow(خالی);
صحیح test_is_benchmark(خالی);
خالی test_subtest_info(ثابت حرف *fmt, ...)
    __attribute__((format(لکھو, 1, 2)));
خالی ssl_err_check(ثابت حرف *file, صحیح سطر);
#اگر_تعریف_شدہ WITH_OPENSSL
خالی assert_bignum(ثابت حرف *file, صحیح سطر,
    ثابت حرف *a1, ثابت حرف *a2,
    ثابت BIGNUM *aa1, ثابت BIGNUM *aa2, شمار test_predicate pred);
#اگر_ختم
خالی assert_string(ثابت حرف *file, صحیح سطر,
    ثابت حرف *a1, ثابت حرف *a2,
    ثابت حرف *aa1, ثابت حرف *aa2, شمار test_predicate pred);
خالی assert_mem(ثابت حرف *file, صحیح سطر,
    ثابت حرف *a1, ثابت حرف *a2,
    ثابت خالی *aa1, ثابت خالی *aa2, سائز_t l, شمار test_predicate pred);
خالی assert_mem_filled(ثابت حرف *file, صحیح سطر,
    ثابت حرف *a1,
    ثابت خالی *aa1, u_char v, سائز_t l, شمار test_predicate pred);
خالی assert_int(ثابت حرف *file, صحیح سطر,
    ثابت حرف *a1, ثابت حرف *a2,
    صحیح aa1, صحیح aa2, شمار test_predicate pred);
خالی assert_سائز_t(ثابت حرف *file, صحیح سطر,
    ثابت حرف *a1, ثابت حرف *a2,
    سائز_t aa1, سائز_t aa2, شمار test_predicate pred);
خالی assert_u_int(ثابت حرف *file, صحیح سطر,
    ثابت حرف *a1, ثابت حرف *a2,
    u_int aa1, u_int aa2, شمار test_predicate pred);
خالی assert_long(ثابت حرف *file, صحیح سطر,
    ثابت حرف *a1, ثابت حرف *a2,
    طویل aa1, طویل aa2, شمار test_predicate pred);
خالی assert_long_long(ثابت حرف *file, صحیح سطر,
    ثابت حرف *a1, ثابت حرف *a2,
    طویل طویل aa1, طویل طویل aa2, شمار test_predicate pred);
خالی assert_char(ثابت حرف *file, صحیح سطر,
    ثابت حرف *a1, ثابت حرف *a2,
    حرف aa1, حرف aa2, شمار test_predicate pred);
خالی assert_ptr(ثابت حرف *file, صحیح سطر,
    ثابت حرف *a1, ثابت حرف *a2,
    ثابت خالی *aa1, ثابت خالی *aa2, شمار test_predicate pred);
خالی assert_u8(ثابت حرف *file, صحیح سطر,
    ثابت حرف *a1, ثابت حرف *a2,
    uint8_t aa1, uint8_t aa2, شمار test_predicate pred);
خالی assert_u16(ثابت حرف *file, صحیح سطر,
    ثابت حرف *a1, ثابت حرف *a2,
    uint16_t aa1, uint16_t aa2, شمار test_predicate pred);
خالی assert_u32(ثابت حرف *file, صحیح سطر,
    ثابت حرف *a1, ثابت حرف *a2,
    uint32_t aa1, uint32_t aa2, شمار test_predicate pred);
خالی assert_u64(ثابت حرف *file, صحیح سطر,
    ثابت حرف *a1, ثابت حرف *a2,
    uint64_t aa1, uint64_t aa2, شمار test_predicate pred);
خالی assert_double(ثابت حرف *file, صحیح سطر,
    ثابت حرف *a1, ثابت حرف *a2,
    دوہرا aa1, دوہرا aa2, شمار test_predicate pred);

#تعریف_کرو TEST_آغاز(n)			test_آغاز(n)
#تعریف_کرو TEST_مکمل()			test_مکمل()
#تعریف_کرو TEST_ONERROR(f, c)		سیٹ_onerror_func(f, c)
#تعریف_کرو SSL_ERR_CHECK() 		ssl_err_check(__FILE__, __LINE__)

#تعریف_کرو ASSERT_BIGNUM_EQ(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کرو ASSERT_STRING_EQ(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کرو ASSERT_MEM_EQ(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_EQ)
#تعریف_کرو ASSERT_MEM_FILLED_EQ(a1, c, l) \
	assert_mem_filled(__FILE__, __LINE__, #a1, a1, c, l, TEST_EQ)
#تعریف_کرو ASSERT_MEM_ZERO_EQ(a1, l) \
	assert_mem_filled(__FILE__, __LINE__, #a1, a1, '\0', l, TEST_EQ)
#تعریف_کرو ASSERT_INT_EQ(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کرو ASSERT_سائز_T_EQ(a1, a2) \
	assert_سائز_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کرو ASSERT_U_INT_EQ(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کرو ASSERT_LONG_EQ(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کرو ASSERT_LONG_LONG_EQ(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کرو ASSERT_CHAR_EQ(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کرو ASSERT_PTR_EQ(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کرو ASSERT_U8_EQ(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کرو ASSERT_U16_EQ(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کرو ASSERT_U32_EQ(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کرو ASSERT_U64_EQ(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)

#تعریف_کرو ASSERT_BIGNUM_NE(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کرو ASSERT_STRING_NE(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کرو ASSERT_MEM_NE(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_NE)
#تعریف_کرو ASSERT_MEM_ZERO_NE(a1, l) \
	assert_mem_filled(__FILE__, __LINE__, #a1, a1, '\0', l, TEST_NE)
#تعریف_کرو ASSERT_INT_NE(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کرو ASSERT_سائز_T_NE(a1, a2) \
	assert_سائز_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کرو ASSERT_U_INT_NE(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کرو ASSERT_LONG_NE(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کرو ASSERT_LONG_LONG_NE(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کرو ASSERT_CHAR_NE(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کرو ASSERT_PTR_NE(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کرو ASSERT_U8_NE(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کرو ASSERT_U16_NE(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کرو ASSERT_U32_NE(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کرو ASSERT_U64_NE(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)

#تعریف_کرو ASSERT_BIGNUM_LT(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کرو ASSERT_STRING_LT(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کرو ASSERT_MEM_LT(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_LT)
#تعریف_کرو ASSERT_INT_LT(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کرو ASSERT_سائز_T_LT(a1, a2) \
	assert_سائز_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کرو ASSERT_U_INT_LT(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کرو ASSERT_LONG_LT(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کرو ASSERT_LONG_LONG_LT(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کرو ASSERT_CHAR_LT(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کرو ASSERT_PTR_LT(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کرو ASSERT_U8_LT(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کرو ASSERT_U16_LT(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کرو ASSERT_U32_LT(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کرو ASSERT_U64_LT(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)

#تعریف_کرو ASSERT_BIGNUM_LE(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کرو ASSERT_STRING_LE(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کرو ASSERT_MEM_LE(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_LE)
#تعریف_کرو ASSERT_INT_LE(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کرو ASSERT_سائز_T_LE(a1, a2) \
	assert_سائز_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کرو ASSERT_U_INT_LE(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کرو ASSERT_LONG_LE(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کرو ASSERT_LONG_LONG_LE(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کرو ASSERT_CHAR_LE(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کرو ASSERT_PTR_LE(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کرو ASSERT_U8_LE(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کرو ASSERT_U16_LE(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کرو ASSERT_U32_LE(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کرو ASSERT_U64_LE(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)

#تعریف_کرو ASSERT_BIGNUM_GT(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کرو ASSERT_STRING_GT(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کرو ASSERT_MEM_GT(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_GT)
#تعریف_کرو ASSERT_INT_GT(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کرو ASSERT_سائز_T_GT(a1, a2) \
	assert_سائز_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کرو ASSERT_U_INT_GT(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کرو ASSERT_LONG_GT(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کرو ASSERT_LONG_LONG_GT(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کرو ASSERT_CHAR_GT(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کرو ASSERT_PTR_GT(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کرو ASSERT_U8_GT(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کرو ASSERT_U16_GT(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کرو ASSERT_U32_GT(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کرو ASSERT_U64_GT(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)

#تعریف_کرو ASSERT_BIGNUM_GE(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#تعریف_کرو ASSERT_STRING_GE(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#تعریف_کرو ASSERT_MEM_GE(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_GE)
#تعریف_کرو ASSERT_INT_GE(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#تعریف_کرو ASSERT_سائز_T_GE(a1, a2) \
	assert_سائز_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#تعریف_کرو ASSERT_U_INT_GE(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#تعریف_کرو ASSERT_LONG_GE(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#تعریف_کرو ASSERT_LONG_LONG_GE(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#تعریف_کرو ASSERT_CHAR_GE(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#تعریف_کرو ASSERT_PTR_GE(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#تعریف_کرو ASSERT_U8_GE(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#تعریف_کرو ASSERT_U16_GE(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#تعریف_کرو ASSERT_U32_GE(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#تعریف_کرو ASSERT_U64_GE(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)

#تعریف_کرو ASSERT_DOUBLE_EQ(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کرو ASSERT_DOUBLE_NE(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کرو ASSERT_DOUBLE_LT(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کرو ASSERT_DOUBLE_LE(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کرو ASSERT_DOUBLE_GT(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کرو ASSERT_DOUBLE_GE(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)

/* Benchmarking support */
#تعریف_کرو BENCH_آغاز(name)	\
	کرو { \
		bench_آغاز(__FILE__, __LINE__, name); \
		جب (!bench_مکمل()) { \
			bench_case_آغاز(__FILE__, __LINE__); \
			کرو {
#تعریف_کرو BENCH_اختتام(unit) \
			} جب (0); \
			bench_case_اختتام(__FILE__, __LINE__); \
		} \
		bench_اختتام(__FILE__, __LINE__, unit); \
	} جب (0)

خالی bench_آغاز(ثابت حرف *file, صحیح سطر, ثابت حرف *name);
خالی bench_case_آغاز(ثابت حرف *file, صحیح سطر);
خالی bench_case_اختتام(ثابت حرف *file, صحیح سطر);
خالی bench_اختتام(ثابت حرف *file, صحیح سطر, ثابت حرف *unit);
صحیح bench_مکمل(خالی);

/* Fuzzing support */

ساخت fuzz;
#تعریف_کرو FUZZ_1_ثنائی_ہندسہ_FLIP		0x00000001	/* Flip one bit at a time */
#تعریف_کرو FUZZ_2_ثنائی_ہندسہ_FLIP		0x00000002	/* Flip two bits at a time */
#تعریف_کرو FUZZ_1_BYTE_FLIP	0x00000004	/* Flip one byte at a time */
#تعریف_کرو FUZZ_2_BYTE_FLIP	0x00000008	/* Flip two bytes at a time */
#تعریف_کرو FUZZ_TRUNCATE_آغاز	0x00000010	/* Truncate from beginning */
#تعریف_کرو FUZZ_TRUNCATE_انتہا	0x00000020	/* Truncate from end */
#تعریف_کرو FUZZ_BASE64		0x00000040	/* Try all base64 chars */
#تعریف_کرو FUZZ_MAX		FUZZ_BASE64

/* Start fuzzing a blob of data with selected strategies (bitmask) */
ساخت fuzz *fuzz_begin(u_int strategies, ثابت خالی *p, سائز_t l);

/* Free a fuzz context */
خالی fuzz_cleanup(ساخت fuzz *fuzz);

/* Prepare the next fuzz case in the series */
خالی fuzz_اگلا(ساخت fuzz *fuzz);

/*
 * Check whether this fuzz case is identical to the original
 * This is slow, but useful if the caller needs to ensure that all tests
 * generated change the input (e.g. when fuzzing signatures).
 */
صحیح fuzz_matches_original(ساخت fuzz *fuzz);

/* Determine whether the current fuzz sequence is exhausted (nonzero = yes) */
صحیح fuzz_مکمل(ساخت fuzz *fuzz);

/* Return the length and a pointer to the current fuzzed case */
سائز_t fuzz_len(ساخت fuzz *fuzz);
u_char *fuzz_ptr(ساخت fuzz *fuzz);

/* Dump the current fuzz case to stderr */
خالی fuzz_dump(ساخت fuzz *fuzz);

#اگر_ختم /* _TEST_HELPER_H */
