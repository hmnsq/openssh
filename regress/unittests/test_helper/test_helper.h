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

#که_نه_تعریف_شوی _TEST_HELPER_H
#تعریف_کړه _TEST_HELPER_H

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <stdint.h>

#که_تعریف_شوی WITH_OPENSSL
#ضمن <openssl/bn.h>
#ضمن <openssl/err.h>
#د_که_پای

تعداد test_predicate {
	TEST_EQ, TEST_NE, TEST_LT, TEST_LE, TEST_GT, TEST_GE
};
تعريفنوع فراغ (test_onerror_func_t)(فراغ *);

/* Supplied by test suite */
فراغ tests(فراغ);
فراغ benchmarks(فراغ);

فراغ hex2bin(uint8_t *, ثابت حرف *, اندازه_t);

ثابت حرف *test_معلومات_file(ثابت حرف *name);
فراغ test_پیل(ثابت حرف *n);
فراغ test_info(حرف *s, اندازه_t len);
فراغ سېټ_onerror_func(test_onerror_func_t *f, فراغ *ctx);
فراغ test_بشپړ(فراغ);
صحيح test_is_verbose(فراغ);
صحيح test_is_quiet(فراغ);
صحيح test_is_fast(فراغ);
صحيح test_is_slow(فراغ);
صحيح test_is_benchmark(فراغ);
فراغ test_subtest_info(ثابت حرف *fmt, ...)
    __attribute__((format(چاپ_کړه, 1, 2)));
فراغ ssl_err_check(ثابت حرف *file, صحيح کرښه);
#که_تعریف_شوی WITH_OPENSSL
فراغ assert_bignum(ثابت حرف *file, صحيح کرښه,
    ثابت حرف *a1, ثابت حرف *a2,
    ثابت BIGNUM *aa1, ثابت BIGNUM *aa2, تعداد test_predicate pred);
#د_که_پای
فراغ assert_string(ثابت حرف *file, صحيح کرښه,
    ثابت حرف *a1, ثابت حرف *a2,
    ثابت حرف *aa1, ثابت حرف *aa2, تعداد test_predicate pred);
فراغ assert_mem(ثابت حرف *file, صحيح کرښه,
    ثابت حرف *a1, ثابت حرف *a2,
    ثابت فراغ *aa1, ثابت فراغ *aa2, اندازه_t l, تعداد test_predicate pred);
فراغ assert_mem_filled(ثابت حرف *file, صحيح کرښه,
    ثابت حرف *a1,
    ثابت فراغ *aa1, u_char v, اندازه_t l, تعداد test_predicate pred);
فراغ assert_int(ثابت حرف *file, صحيح کرښه,
    ثابت حرف *a1, ثابت حرف *a2,
    صحيح aa1, صحيح aa2, تعداد test_predicate pred);
فراغ assert_اندازه_t(ثابت حرف *file, صحيح کرښه,
    ثابت حرف *a1, ثابت حرف *a2,
    اندازه_t aa1, اندازه_t aa2, تعداد test_predicate pred);
فراغ assert_u_int(ثابت حرف *file, صحيح کرښه,
    ثابت حرف *a1, ثابت حرف *a2,
    u_int aa1, u_int aa2, تعداد test_predicate pred);
فراغ assert_long(ثابت حرف *file, صحيح کرښه,
    ثابت حرف *a1, ثابت حرف *a2,
    اوږد aa1, اوږد aa2, تعداد test_predicate pred);
فراغ assert_long_long(ثابت حرف *file, صحيح کرښه,
    ثابت حرف *a1, ثابت حرف *a2,
    اوږد اوږد aa1, اوږد اوږد aa2, تعداد test_predicate pred);
فراغ assert_char(ثابت حرف *file, صحيح کرښه,
    ثابت حرف *a1, ثابت حرف *a2,
    حرف aa1, حرف aa2, تعداد test_predicate pred);
فراغ assert_ptr(ثابت حرف *file, صحيح کرښه,
    ثابت حرف *a1, ثابت حرف *a2,
    ثابت فراغ *aa1, ثابت فراغ *aa2, تعداد test_predicate pred);
فراغ assert_u8(ثابت حرف *file, صحيح کرښه,
    ثابت حرف *a1, ثابت حرف *a2,
    uint8_t aa1, uint8_t aa2, تعداد test_predicate pred);
فراغ assert_u16(ثابت حرف *file, صحيح کرښه,
    ثابت حرف *a1, ثابت حرف *a2,
    uint16_t aa1, uint16_t aa2, تعداد test_predicate pred);
فراغ assert_u32(ثابت حرف *file, صحيح کرښه,
    ثابت حرف *a1, ثابت حرف *a2,
    uint32_t aa1, uint32_t aa2, تعداد test_predicate pred);
فراغ assert_u64(ثابت حرف *file, صحيح کرښه,
    ثابت حرف *a1, ثابت حرف *a2,
    uint64_t aa1, uint64_t aa2, تعداد test_predicate pred);
فراغ assert_double(ثابت حرف *file, صحيح کرښه,
    ثابت حرف *a1, ثابت حرف *a2,
    مزدوج aa1, مزدوج aa2, تعداد test_predicate pred);

#تعریف_کړه TEST_پیل(n)			test_پیل(n)
#تعریف_کړه TEST_بشپړ()			test_بشپړ()
#تعریف_کړه TEST_ONERROR(f, c)		سېټ_onerror_func(f, c)
#تعریف_کړه SSL_ERR_CHECK() 		ssl_err_check(__FILE__, __LINE__)

#تعریف_کړه ASSERT_BIGNUM_EQ(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کړه ASSERT_STRING_EQ(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کړه ASSERT_MEM_EQ(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_EQ)
#تعریف_کړه ASSERT_MEM_FILLED_EQ(a1, c, l) \
	assert_mem_filled(__FILE__, __LINE__, #a1, a1, c, l, TEST_EQ)
#تعریف_کړه ASSERT_MEM_ZERO_EQ(a1, l) \
	assert_mem_filled(__FILE__, __LINE__, #a1, a1, '\0', l, TEST_EQ)
#تعریف_کړه ASSERT_INT_EQ(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کړه ASSERT_اندازه_T_EQ(a1, a2) \
	assert_اندازه_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کړه ASSERT_U_INT_EQ(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کړه ASSERT_LONG_EQ(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کړه ASSERT_LONG_LONG_EQ(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کړه ASSERT_CHAR_EQ(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کړه ASSERT_PTR_EQ(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کړه ASSERT_U8_EQ(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کړه ASSERT_U16_EQ(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کړه ASSERT_U32_EQ(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کړه ASSERT_U64_EQ(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)

#تعریف_کړه ASSERT_BIGNUM_NE(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کړه ASSERT_STRING_NE(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کړه ASSERT_MEM_NE(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_NE)
#تعریف_کړه ASSERT_MEM_ZERO_NE(a1, l) \
	assert_mem_filled(__FILE__, __LINE__, #a1, a1, '\0', l, TEST_NE)
#تعریف_کړه ASSERT_INT_NE(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کړه ASSERT_اندازه_T_NE(a1, a2) \
	assert_اندازه_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کړه ASSERT_U_INT_NE(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کړه ASSERT_LONG_NE(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کړه ASSERT_LONG_LONG_NE(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کړه ASSERT_CHAR_NE(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کړه ASSERT_PTR_NE(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کړه ASSERT_U8_NE(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کړه ASSERT_U16_NE(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کړه ASSERT_U32_NE(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کړه ASSERT_U64_NE(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)

#تعریف_کړه ASSERT_BIGNUM_LT(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کړه ASSERT_STRING_LT(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کړه ASSERT_MEM_LT(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_LT)
#تعریف_کړه ASSERT_INT_LT(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کړه ASSERT_اندازه_T_LT(a1, a2) \
	assert_اندازه_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کړه ASSERT_U_INT_LT(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کړه ASSERT_LONG_LT(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کړه ASSERT_LONG_LONG_LT(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کړه ASSERT_CHAR_LT(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کړه ASSERT_PTR_LT(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کړه ASSERT_U8_LT(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کړه ASSERT_U16_LT(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کړه ASSERT_U32_LT(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کړه ASSERT_U64_LT(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)

#تعریف_کړه ASSERT_BIGNUM_LE(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کړه ASSERT_STRING_LE(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کړه ASSERT_MEM_LE(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_LE)
#تعریف_کړه ASSERT_INT_LE(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کړه ASSERT_اندازه_T_LE(a1, a2) \
	assert_اندازه_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کړه ASSERT_U_INT_LE(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کړه ASSERT_LONG_LE(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کړه ASSERT_LONG_LONG_LE(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کړه ASSERT_CHAR_LE(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کړه ASSERT_PTR_LE(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کړه ASSERT_U8_LE(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کړه ASSERT_U16_LE(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کړه ASSERT_U32_LE(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کړه ASSERT_U64_LE(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)

#تعریف_کړه ASSERT_BIGNUM_GT(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کړه ASSERT_STRING_GT(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کړه ASSERT_MEM_GT(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_GT)
#تعریف_کړه ASSERT_INT_GT(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کړه ASSERT_اندازه_T_GT(a1, a2) \
	assert_اندازه_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کړه ASSERT_U_INT_GT(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کړه ASSERT_LONG_GT(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کړه ASSERT_LONG_LONG_GT(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کړه ASSERT_CHAR_GT(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کړه ASSERT_PTR_GT(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کړه ASSERT_U8_GT(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کړه ASSERT_U16_GT(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کړه ASSERT_U32_GT(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کړه ASSERT_U64_GT(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)

#تعریف_کړه ASSERT_BIGNUM_GE(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#تعریف_کړه ASSERT_STRING_GE(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#تعریف_کړه ASSERT_MEM_GE(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_GE)
#تعریف_کړه ASSERT_INT_GE(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#تعریف_کړه ASSERT_اندازه_T_GE(a1, a2) \
	assert_اندازه_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#تعریف_کړه ASSERT_U_INT_GE(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#تعریف_کړه ASSERT_LONG_GE(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#تعریف_کړه ASSERT_LONG_LONG_GE(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#تعریف_کړه ASSERT_CHAR_GE(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#تعریف_کړه ASSERT_PTR_GE(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#تعریف_کړه ASSERT_U8_GE(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#تعریف_کړه ASSERT_U16_GE(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#تعریف_کړه ASSERT_U32_GE(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#تعریف_کړه ASSERT_U64_GE(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)

#تعریف_کړه ASSERT_DOUBLE_EQ(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#تعریف_کړه ASSERT_DOUBLE_NE(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#تعریف_کړه ASSERT_DOUBLE_LT(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#تعریف_کړه ASSERT_DOUBLE_LE(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#تعریف_کړه ASSERT_DOUBLE_GT(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#تعریف_کړه ASSERT_DOUBLE_GE(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)

/* Benchmarking support */
#تعریف_کړه BENCH_پیل(name)	\
	افعل { \
		bench_پیل(__FILE__, __LINE__, name); \
		طالما (!bench_بشپړ()) { \
			bench_case_پیل(__FILE__, __LINE__); \
			افعل {
#تعریف_کړه BENCH_پای(unit) \
			} طالما (0); \
			bench_case_پای(__FILE__, __LINE__); \
		} \
		bench_پای(__FILE__, __LINE__, unit); \
	} طالما (0)

فراغ bench_پیل(ثابت حرف *file, صحيح کرښه, ثابت حرف *name);
فراغ bench_case_پیل(ثابت حرف *file, صحيح کرښه);
فراغ bench_case_پای(ثابت حرف *file, صحيح کرښه);
فراغ bench_پای(ثابت حرف *file, صحيح کرښه, ثابت حرف *unit);
صحيح bench_بشپړ(فراغ);

/* Fuzzing support */

بنية fuzz;
#تعریف_کړه FUZZ_1_بټ_FLIP		0x00000001	/* Flip one bit at a time */
#تعریف_کړه FUZZ_2_بټ_FLIP		0x00000002	/* Flip two bits at a time */
#تعریف_کړه FUZZ_1_BYTE_FLIP	0x00000004	/* Flip one byte at a time */
#تعریف_کړه FUZZ_2_BYTE_FLIP	0x00000008	/* Flip two bytes at a time */
#تعریف_کړه FUZZ_TRUNCATE_پیل	0x00000010	/* Truncate from beginning */
#تعریف_کړه FUZZ_TRUNCATE_پای_ټکی	0x00000020	/* Truncate from end */
#تعریف_کړه FUZZ_BASE64		0x00000040	/* Try all base64 chars */
#تعریف_کړه FUZZ_MAX		FUZZ_BASE64

/* Start fuzzing a blob of data with selected strategies (bitmask) */
بنية fuzz *fuzz_begin(u_int strategies, ثابت فراغ *p, اندازه_t l);

/* Free a fuzz context */
فراغ fuzz_cleanup(بنية fuzz *fuzz);

/* Prepare the next fuzz case in the series */
فراغ fuzz_بل(بنية fuzz *fuzz);

/*
 * Check whether this fuzz case is identical to the original
 * This is slow, but useful if the caller needs to ensure that all tests
 * generated change the input (e.g. when fuzzing signatures).
 */
صحيح fuzz_matches_original(بنية fuzz *fuzz);

/* Determine whether the current fuzz sequence is exhausted (nonzero = yes) */
صحيح fuzz_بشپړ(بنية fuzz *fuzz);

/* Return the length and a pointer to the current fuzzed case */
اندازه_t fuzz_len(بنية fuzz *fuzz);
u_char *fuzz_ptr(بنية fuzz *fuzz);

/* Dump the current fuzz case to stderr */
فراغ fuzz_dump(بنية fuzz *fuzz);

#د_که_پای /* _TEST_HELPER_H */
