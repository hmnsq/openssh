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

#جيڪڏهن_وصف_نه_ٿيل _TEST_HELPER_H
#وصف_ڪريو _TEST_HELPER_H

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <stdint.h>

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
#ضمن <openssl/bn.h>
#ضمن <openssl/err.h>
#جيڪڏهن_پورو

تعداد test_predicate {
	TEST_EQ, TEST_NE, TEST_LT, TEST_LE, TEST_GT, TEST_GE
};
تعريفنوع فراغ (test_onerror_func_t)(فراغ *);

/* Supplied by test suite */
فراغ tests(فراغ);
فراغ benchmarks(فراغ);

فراغ hex2bin(uint8_t *, ثابت حرف *, سائيز_t);

ثابت حرف *test_معلومات_file(ثابت حرف *name);
فراغ test_شروعات(ثابت حرف *n);
فراغ test_info(حرف *s, سائيز_t len);
فراغ سيٽ_onerror_func(test_onerror_func_t *f, فراغ *ctx);
فراغ test_پورو(فراغ);
صحيح test_is_verbose(فراغ);
صحيح test_is_quiet(فراغ);
صحيح test_is_fast(فراغ);
صحيح test_is_slow(فراغ);
صحيح test_is_benchmark(فراغ);
فراغ test_subtest_info(ثابت حرف *fmt, ...)
    __attribute__((format(لکو, 1, 2)));
فراغ ssl_err_check(ثابت حرف *file, صحيح سٽ);
#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
فراغ assert_bignum(ثابت حرف *file, صحيح سٽ,
    ثابت حرف *a1, ثابت حرف *a2,
    ثابت BIGNUM *aa1, ثابت BIGNUM *aa2, تعداد test_predicate pred);
#جيڪڏهن_پورو
فراغ assert_string(ثابت حرف *file, صحيح سٽ,
    ثابت حرف *a1, ثابت حرف *a2,
    ثابت حرف *aa1, ثابت حرف *aa2, تعداد test_predicate pred);
فراغ assert_mem(ثابت حرف *file, صحيح سٽ,
    ثابت حرف *a1, ثابت حرف *a2,
    ثابت فراغ *aa1, ثابت فراغ *aa2, سائيز_t l, تعداد test_predicate pred);
فراغ assert_mem_filled(ثابت حرف *file, صحيح سٽ,
    ثابت حرف *a1,
    ثابت فراغ *aa1, u_char v, سائيز_t l, تعداد test_predicate pred);
فراغ assert_int(ثابت حرف *file, صحيح سٽ,
    ثابت حرف *a1, ثابت حرف *a2,
    صحيح aa1, صحيح aa2, تعداد test_predicate pred);
فراغ assert_سائيز_t(ثابت حرف *file, صحيح سٽ,
    ثابت حرف *a1, ثابت حرف *a2,
    سائيز_t aa1, سائيز_t aa2, تعداد test_predicate pred);
فراغ assert_u_int(ثابت حرف *file, صحيح سٽ,
    ثابت حرف *a1, ثابت حرف *a2,
    u_int aa1, u_int aa2, تعداد test_predicate pred);
فراغ assert_long(ثابت حرف *file, صحيح سٽ,
    ثابت حرف *a1, ثابت حرف *a2,
    ڊگهو aa1, ڊگهو aa2, تعداد test_predicate pred);
فراغ assert_long_long(ثابت حرف *file, صحيح سٽ,
    ثابت حرف *a1, ثابت حرف *a2,
    ڊگهو ڊگهو aa1, ڊگهو ڊگهو aa2, تعداد test_predicate pred);
فراغ assert_char(ثابت حرف *file, صحيح سٽ,
    ثابت حرف *a1, ثابت حرف *a2,
    حرف aa1, حرف aa2, تعداد test_predicate pred);
فراغ assert_ptr(ثابت حرف *file, صحيح سٽ,
    ثابت حرف *a1, ثابت حرف *a2,
    ثابت فراغ *aa1, ثابت فراغ *aa2, تعداد test_predicate pred);
فراغ assert_u8(ثابت حرف *file, صحيح سٽ,
    ثابت حرف *a1, ثابت حرف *a2,
    uint8_t aa1, uint8_t aa2, تعداد test_predicate pred);
فراغ assert_u16(ثابت حرف *file, صحيح سٽ,
    ثابت حرف *a1, ثابت حرف *a2,
    uint16_t aa1, uint16_t aa2, تعداد test_predicate pred);
فراغ assert_u32(ثابت حرف *file, صحيح سٽ,
    ثابت حرف *a1, ثابت حرف *a2,
    uint32_t aa1, uint32_t aa2, تعداد test_predicate pred);
فراغ assert_u64(ثابت حرف *file, صحيح سٽ,
    ثابت حرف *a1, ثابت حرف *a2,
    uint64_t aa1, uint64_t aa2, تعداد test_predicate pred);
فراغ assert_double(ثابت حرف *file, صحيح سٽ,
    ثابت حرف *a1, ثابت حرف *a2,
    مزدوج aa1, مزدوج aa2, تعداد test_predicate pred);

#وصف_ڪريو TEST_شروعات(n)			test_شروعات(n)
#وصف_ڪريو TEST_پورو()			test_پورو()
#وصف_ڪريو TEST_ONERROR(f, c)		سيٽ_onerror_func(f, c)
#وصف_ڪريو SSL_ERR_CHECK() 		ssl_err_check(__FILE__, __LINE__)

#وصف_ڪريو ASSERT_BIGNUM_EQ(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#وصف_ڪريو ASSERT_STRING_EQ(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#وصف_ڪريو ASSERT_MEM_EQ(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_EQ)
#وصف_ڪريو ASSERT_MEM_FILLED_EQ(a1, c, l) \
	assert_mem_filled(__FILE__, __LINE__, #a1, a1, c, l, TEST_EQ)
#وصف_ڪريو ASSERT_MEM_ZERO_EQ(a1, l) \
	assert_mem_filled(__FILE__, __LINE__, #a1, a1, '\0', l, TEST_EQ)
#وصف_ڪريو ASSERT_INT_EQ(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#وصف_ڪريو ASSERT_سائيز_T_EQ(a1, a2) \
	assert_سائيز_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#وصف_ڪريو ASSERT_U_INT_EQ(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#وصف_ڪريو ASSERT_LONG_EQ(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#وصف_ڪريو ASSERT_LONG_LONG_EQ(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#وصف_ڪريو ASSERT_CHAR_EQ(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#وصف_ڪريو ASSERT_PTR_EQ(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#وصف_ڪريو ASSERT_U8_EQ(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#وصف_ڪريو ASSERT_U16_EQ(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#وصف_ڪريو ASSERT_U32_EQ(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#وصف_ڪريو ASSERT_U64_EQ(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)

#وصف_ڪريو ASSERT_BIGNUM_NE(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#وصف_ڪريو ASSERT_STRING_NE(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#وصف_ڪريو ASSERT_MEM_NE(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_NE)
#وصف_ڪريو ASSERT_MEM_ZERO_NE(a1, l) \
	assert_mem_filled(__FILE__, __LINE__, #a1, a1, '\0', l, TEST_NE)
#وصف_ڪريو ASSERT_INT_NE(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#وصف_ڪريو ASSERT_سائيز_T_NE(a1, a2) \
	assert_سائيز_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#وصف_ڪريو ASSERT_U_INT_NE(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#وصف_ڪريو ASSERT_LONG_NE(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#وصف_ڪريو ASSERT_LONG_LONG_NE(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#وصف_ڪريو ASSERT_CHAR_NE(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#وصف_ڪريو ASSERT_PTR_NE(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#وصف_ڪريو ASSERT_U8_NE(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#وصف_ڪريو ASSERT_U16_NE(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#وصف_ڪريو ASSERT_U32_NE(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#وصف_ڪريو ASSERT_U64_NE(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)

#وصف_ڪريو ASSERT_BIGNUM_LT(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#وصف_ڪريو ASSERT_STRING_LT(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#وصف_ڪريو ASSERT_MEM_LT(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_LT)
#وصف_ڪريو ASSERT_INT_LT(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#وصف_ڪريو ASSERT_سائيز_T_LT(a1, a2) \
	assert_سائيز_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#وصف_ڪريو ASSERT_U_INT_LT(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#وصف_ڪريو ASSERT_LONG_LT(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#وصف_ڪريو ASSERT_LONG_LONG_LT(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#وصف_ڪريو ASSERT_CHAR_LT(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#وصف_ڪريو ASSERT_PTR_LT(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#وصف_ڪريو ASSERT_U8_LT(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#وصف_ڪريو ASSERT_U16_LT(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#وصف_ڪريو ASSERT_U32_LT(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#وصف_ڪريو ASSERT_U64_LT(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)

#وصف_ڪريو ASSERT_BIGNUM_LE(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#وصف_ڪريو ASSERT_STRING_LE(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#وصف_ڪريو ASSERT_MEM_LE(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_LE)
#وصف_ڪريو ASSERT_INT_LE(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#وصف_ڪريو ASSERT_سائيز_T_LE(a1, a2) \
	assert_سائيز_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#وصف_ڪريو ASSERT_U_INT_LE(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#وصف_ڪريو ASSERT_LONG_LE(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#وصف_ڪريو ASSERT_LONG_LONG_LE(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#وصف_ڪريو ASSERT_CHAR_LE(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#وصف_ڪريو ASSERT_PTR_LE(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#وصف_ڪريو ASSERT_U8_LE(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#وصف_ڪريو ASSERT_U16_LE(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#وصف_ڪريو ASSERT_U32_LE(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#وصف_ڪريو ASSERT_U64_LE(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)

#وصف_ڪريو ASSERT_BIGNUM_GT(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#وصف_ڪريو ASSERT_STRING_GT(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#وصف_ڪريو ASSERT_MEM_GT(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_GT)
#وصف_ڪريو ASSERT_INT_GT(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#وصف_ڪريو ASSERT_سائيز_T_GT(a1, a2) \
	assert_سائيز_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#وصف_ڪريو ASSERT_U_INT_GT(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#وصف_ڪريو ASSERT_LONG_GT(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#وصف_ڪريو ASSERT_LONG_LONG_GT(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#وصف_ڪريو ASSERT_CHAR_GT(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#وصف_ڪريو ASSERT_PTR_GT(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#وصف_ڪريو ASSERT_U8_GT(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#وصف_ڪريو ASSERT_U16_GT(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#وصف_ڪريو ASSERT_U32_GT(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#وصف_ڪريو ASSERT_U64_GT(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)

#وصف_ڪريو ASSERT_BIGNUM_GE(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#وصف_ڪريو ASSERT_STRING_GE(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#وصف_ڪريو ASSERT_MEM_GE(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_GE)
#وصف_ڪريو ASSERT_INT_GE(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#وصف_ڪريو ASSERT_سائيز_T_GE(a1, a2) \
	assert_سائيز_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#وصف_ڪريو ASSERT_U_INT_GE(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#وصف_ڪريو ASSERT_LONG_GE(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#وصف_ڪريو ASSERT_LONG_LONG_GE(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#وصف_ڪريو ASSERT_CHAR_GE(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#وصف_ڪريو ASSERT_PTR_GE(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#وصف_ڪريو ASSERT_U8_GE(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#وصف_ڪريو ASSERT_U16_GE(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#وصف_ڪريو ASSERT_U32_GE(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#وصف_ڪريو ASSERT_U64_GE(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)

#وصف_ڪريو ASSERT_DOUBLE_EQ(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#وصف_ڪريو ASSERT_DOUBLE_NE(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#وصف_ڪريو ASSERT_DOUBLE_LT(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#وصف_ڪريو ASSERT_DOUBLE_LE(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#وصف_ڪريو ASSERT_DOUBLE_GT(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#وصف_ڪريو ASSERT_DOUBLE_GE(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)

/* Benchmarking support */
#وصف_ڪريو BENCH_شروعات(name)	\
	افعل { \
		bench_شروعات(__FILE__, __LINE__, name); \
		طالما (!bench_پورو()) { \
			bench_case_شروعات(__FILE__, __LINE__); \
			افعل {
#وصف_ڪريو BENCH_پڄاڻي(unit) \
			} طالما (0); \
			bench_case_پڄاڻي(__FILE__, __LINE__); \
		} \
		bench_پڄاڻي(__FILE__, __LINE__, unit); \
	} طالما (0)

فراغ bench_شروعات(ثابت حرف *file, صحيح سٽ, ثابت حرف *name);
فراغ bench_case_شروعات(ثابت حرف *file, صحيح سٽ);
فراغ bench_case_پڄاڻي(ثابت حرف *file, صحيح سٽ);
فراغ bench_پڄاڻي(ثابت حرف *file, صحيح سٽ, ثابت حرف *unit);
صحيح bench_پورو(فراغ);

/* Fuzzing support */

بنية fuzz;
#وصف_ڪريو FUZZ_1_ٻٽو_انگ_FLIP		0x00000001	/* Flip one bit at a time */
#وصف_ڪريو FUZZ_2_ٻٽو_انگ_FLIP		0x00000002	/* Flip two bits at a time */
#وصف_ڪريو FUZZ_1_BYTE_FLIP	0x00000004	/* Flip one byte at a time */
#وصف_ڪريو FUZZ_2_BYTE_FLIP	0x00000008	/* Flip two bytes at a time */
#وصف_ڪريو FUZZ_TRUNCATE_شروعات	0x00000010	/* Truncate from beginning */
#وصف_ڪريو FUZZ_TRUNCATE_پڇاڙي	0x00000020	/* Truncate from end */
#وصف_ڪريو FUZZ_BASE64		0x00000040	/* Try all base64 chars */
#وصف_ڪريو FUZZ_MAX		FUZZ_BASE64

/* Start fuzzing a blob of data with selected strategies (bitmask) */
بنية fuzz *fuzz_begin(u_int strategies, ثابت فراغ *p, سائيز_t l);

/* Free a fuzz context */
فراغ fuzz_cleanup(بنية fuzz *fuzz);

/* Prepare the next fuzz case in the series */
فراغ fuzz_ايندڙ(بنية fuzz *fuzz);

/*
 * Check whether this fuzz case is identical to the original
 * This is slow, but useful if the caller needs to ensure that all tests
 * generated change the input (e.g. when fuzzing signatures).
 */
صحيح fuzz_matches_original(بنية fuzz *fuzz);

/* Determine whether the current fuzz sequence is exhausted (nonzero = yes) */
صحيح fuzz_پورو(بنية fuzz *fuzz);

/* Return the length and a pointer to the current fuzzed case */
سائيز_t fuzz_len(بنية fuzz *fuzz);
u_char *fuzz_ptr(بنية fuzz *fuzz);

/* Dump the current fuzz case to stderr */
فراغ fuzz_dump(بنية fuzz *fuzz);

#جيڪڏهن_پورو /* _TEST_HELPER_H */
