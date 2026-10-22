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

#यदि_अपरिभाषितम् _TEST_HELPER_H
#परिभाषय _TEST_HELPER_H

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <stdint.h>

#यदि_परिभाषितम् WITH_OPENSSL
#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/err.h>
#यदि_अन्तः

गणना test_predicate {
	TEST_EQ, TEST_NE, TEST_LT, TEST_LE, TEST_GT, TEST_GE
};
प्रकारनिर्देश शून्य (test_onerror_func_t)(शून्य *);

/* Supplied by test suite */
शून्य tests(शून्य);
शून्य benchmarks(शून्य);

शून्य hex2bin(uint8_t *, ध्रुव वर्ण *, आकार_t);

ध्रुव वर्ण *test_दत्त_file(ध्रुव वर्ण *name);
शून्य test_start(ध्रुव वर्ण *n);
शून्य test_info(वर्ण *s, आकार_t len);
शून्य समुच्चयः_onerror_func(test_onerror_func_t *f, शून्य *ctx);
शून्य test_समाप्तम्(शून्य);
पूर्णाङ्क test_is_verbose(शून्य);
पूर्णाङ्क test_is_quiet(शून्य);
पूर्णाङ्क test_is_fast(शून्य);
पूर्णाङ्क test_is_slow(शून्य);
पूर्णाङ्क test_is_benchmark(शून्य);
शून्य test_subtest_info(ध्रुव वर्ण *fmt, ...)
    __attribute__((format(प्रारूप_लिख, 1, 2)));
शून्य ssl_err_check(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः);
#यदि_परिभाषितम् WITH_OPENSSL
शून्य assert_bignum(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः,
    ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    ध्रुव BIGNUM *aa1, ध्रुव BIGNUM *aa2, गणना test_predicate pred);
#यदि_अन्तः
शून्य assert_string(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः,
    ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    ध्रुव वर्ण *aa1, ध्रुव वर्ण *aa2, गणना test_predicate pred);
शून्य assert_mem(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः,
    ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    ध्रुव शून्य *aa1, ध्रुव शून्य *aa2, आकार_t l, गणना test_predicate pred);
शून्य assert_mem_filled(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः,
    ध्रुव वर्ण *a1,
    ध्रुव शून्य *aa1, u_char v, आकार_t l, गणना test_predicate pred);
शून्य assert_int(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः,
    ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    पूर्णाङ्क aa1, पूर्णाङ्क aa2, गणना test_predicate pred);
शून्य assert_आकार_t(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः,
    ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    आकार_t aa1, आकार_t aa2, गणना test_predicate pred);
शून्य assert_u_int(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः,
    ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    u_int aa1, u_int aa2, गणना test_predicate pred);
शून्य assert_long(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः,
    ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    दीर्घ aa1, दीर्घ aa2, गणना test_predicate pred);
शून्य assert_long_long(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः,
    ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    दीर्घ दीर्घ aa1, दीर्घ दीर्घ aa2, गणना test_predicate pred);
शून्य assert_char(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः,
    ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    वर्ण aa1, वर्ण aa2, गणना test_predicate pred);
शून्य assert_ptr(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः,
    ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    ध्रुव शून्य *aa1, ध्रुव शून्य *aa2, गणना test_predicate pred);
शून्य assert_u8(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः,
    ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    uint8_t aa1, uint8_t aa2, गणना test_predicate pred);
शून्य assert_u16(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः,
    ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    uint16_t aa1, uint16_t aa2, गणना test_predicate pred);
शून्य assert_u32(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः,
    ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    uint32_t aa1, uint32_t aa2, गणना test_predicate pred);
शून्य assert_u64(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः,
    ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    uint64_t aa1, uint64_t aa2, गणना test_predicate pred);
शून्य assert_double(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः,
    ध्रुव वर्ण *a1, ध्रुव वर्ण *a2,
    द्विगुण aa1, द्विगुण aa2, गणना test_predicate pred);

#परिभाषय TEST_START(n)			test_start(n)
#परिभाषय TEST_समाप्तम्()			test_समाप्तम्()
#परिभाषय TEST_ONERROR(f, c)		समुच्चयः_onerror_func(f, c)
#परिभाषय SSL_ERR_CHECK() 		ssl_err_check(__FILE__, __LINE__)

#परिभाषय ASSERT_BIGNUM_EQ(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#परिभाषय ASSERT_STRING_EQ(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#परिभाषय ASSERT_MEM_EQ(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_EQ)
#परिभाषय ASSERT_MEM_FILLED_EQ(a1, c, l) \
	assert_mem_filled(__FILE__, __LINE__, #a1, a1, c, l, TEST_EQ)
#परिभाषय ASSERT_MEM_ZERO_EQ(a1, l) \
	assert_mem_filled(__FILE__, __LINE__, #a1, a1, '\0', l, TEST_EQ)
#परिभाषय ASSERT_INT_EQ(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#परिभाषय ASSERT_आकार_T_EQ(a1, a2) \
	assert_आकार_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#परिभाषय ASSERT_U_INT_EQ(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#परिभाषय ASSERT_LONG_EQ(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#परिभाषय ASSERT_LONG_LONG_EQ(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#परिभाषय ASSERT_CHAR_EQ(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#परिभाषय ASSERT_PTR_EQ(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#परिभाषय ASSERT_U8_EQ(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#परिभाषय ASSERT_U16_EQ(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#परिभाषय ASSERT_U32_EQ(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#परिभाषय ASSERT_U64_EQ(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)

#परिभाषय ASSERT_BIGNUM_NE(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#परिभाषय ASSERT_STRING_NE(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#परिभाषय ASSERT_MEM_NE(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_NE)
#परिभाषय ASSERT_MEM_ZERO_NE(a1, l) \
	assert_mem_filled(__FILE__, __LINE__, #a1, a1, '\0', l, TEST_NE)
#परिभाषय ASSERT_INT_NE(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#परिभाषय ASSERT_आकार_T_NE(a1, a2) \
	assert_आकार_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#परिभाषय ASSERT_U_INT_NE(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#परिभाषय ASSERT_LONG_NE(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#परिभाषय ASSERT_LONG_LONG_NE(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#परिभाषय ASSERT_CHAR_NE(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#परिभाषय ASSERT_PTR_NE(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#परिभाषय ASSERT_U8_NE(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#परिभाषय ASSERT_U16_NE(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#परिभाषय ASSERT_U32_NE(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#परिभाषय ASSERT_U64_NE(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)

#परिभाषय ASSERT_BIGNUM_LT(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#परिभाषय ASSERT_STRING_LT(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#परिभाषय ASSERT_MEM_LT(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_LT)
#परिभाषय ASSERT_INT_LT(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#परिभाषय ASSERT_आकार_T_LT(a1, a2) \
	assert_आकार_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#परिभाषय ASSERT_U_INT_LT(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#परिभाषय ASSERT_LONG_LT(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#परिभाषय ASSERT_LONG_LONG_LT(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#परिभाषय ASSERT_CHAR_LT(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#परिभाषय ASSERT_PTR_LT(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#परिभाषय ASSERT_U8_LT(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#परिभाषय ASSERT_U16_LT(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#परिभाषय ASSERT_U32_LT(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#परिभाषय ASSERT_U64_LT(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)

#परिभाषय ASSERT_BIGNUM_LE(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#परिभाषय ASSERT_STRING_LE(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#परिभाषय ASSERT_MEM_LE(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_LE)
#परिभाषय ASSERT_INT_LE(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#परिभाषय ASSERT_आकार_T_LE(a1, a2) \
	assert_आकार_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#परिभाषय ASSERT_U_INT_LE(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#परिभाषय ASSERT_LONG_LE(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#परिभाषय ASSERT_LONG_LONG_LE(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#परिभाषय ASSERT_CHAR_LE(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#परिभाषय ASSERT_PTR_LE(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#परिभाषय ASSERT_U8_LE(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#परिभाषय ASSERT_U16_LE(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#परिभाषय ASSERT_U32_LE(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#परिभाषय ASSERT_U64_LE(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)

#परिभाषय ASSERT_BIGNUM_GT(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#परिभाषय ASSERT_STRING_GT(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#परिभाषय ASSERT_MEM_GT(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_GT)
#परिभाषय ASSERT_INT_GT(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#परिभाषय ASSERT_आकार_T_GT(a1, a2) \
	assert_आकार_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#परिभाषय ASSERT_U_INT_GT(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#परिभाषय ASSERT_LONG_GT(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#परिभाषय ASSERT_LONG_LONG_GT(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#परिभाषय ASSERT_CHAR_GT(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#परिभाषय ASSERT_PTR_GT(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#परिभाषय ASSERT_U8_GT(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#परिभाषय ASSERT_U16_GT(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#परिभाषय ASSERT_U32_GT(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#परिभाषय ASSERT_U64_GT(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)

#परिभाषय ASSERT_BIGNUM_GE(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#परिभाषय ASSERT_STRING_GE(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#परिभाषय ASSERT_MEM_GE(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_GE)
#परिभाषय ASSERT_INT_GE(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#परिभाषय ASSERT_आकार_T_GE(a1, a2) \
	assert_आकार_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#परिभाषय ASSERT_U_INT_GE(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#परिभाषय ASSERT_LONG_GE(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#परिभाषय ASSERT_LONG_LONG_GE(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#परिभाषय ASSERT_CHAR_GE(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#परिभाषय ASSERT_PTR_GE(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#परिभाषय ASSERT_U8_GE(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#परिभाषय ASSERT_U16_GE(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#परिभाषय ASSERT_U32_GE(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#परिभाषय ASSERT_U64_GE(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)

#परिभाषय ASSERT_DOUBLE_EQ(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#परिभाषय ASSERT_DOUBLE_NE(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#परिभाषय ASSERT_DOUBLE_LT(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#परिभाषय ASSERT_DOUBLE_LE(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#परिभाषय ASSERT_DOUBLE_GT(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#परिभाषय ASSERT_DOUBLE_GE(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)

/* Benchmarking support */
#परिभाषय BENCH_START(name)	\
	कुरु { \
		bench_start(__FILE__, __LINE__, name); \
		यावत् (!bench_समाप्तम्()) { \
			bench_case_start(__FILE__, __LINE__); \
			कुरु {
#परिभाषय BENCH_FINISH(unit) \
			} यावत् (0); \
			bench_case_finish(__FILE__, __LINE__); \
		} \
		bench_finish(__FILE__, __LINE__, unit); \
	} यावत् (0)

शून्य bench_start(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *name);
शून्य bench_case_start(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः);
शून्य bench_case_finish(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः);
शून्य bench_finish(ध्रुव वर्ण *file, पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *unit);
पूर्णाङ्क bench_समाप्तम्(शून्य);

/* Fuzzing support */

संरचना fuzz;
#परिभाषय FUZZ_1_BIT_FLIP		0x00000001	/* Flip one bit at a time */
#परिभाषय FUZZ_2_BIT_FLIP		0x00000002	/* Flip two bits at a time */
#परिभाषय FUZZ_1_BYTE_FLIP	0x00000004	/* Flip one byte at a time */
#परिभाषय FUZZ_2_BYTE_FLIP	0x00000008	/* Flip two bytes at a time */
#परिभाषय FUZZ_TRUNCATE_START	0x00000010	/* Truncate from beginning */
#परिभाषय FUZZ_TRUNCATE_अन्तः	0x00000020	/* Truncate from end */
#परिभाषय FUZZ_BASE64		0x00000040	/* Try all base64 chars */
#परिभाषय FUZZ_MAX		FUZZ_BASE64

/* Start fuzzing a blob of data with selected strategies (bitmask) */
संरचना fuzz *fuzz_begin(u_int strategies, ध्रुव शून्य *p, आकार_t l);

/* Free a fuzz context */
शून्य fuzz_cleanup(संरचना fuzz *fuzz);

/* Prepare the next fuzz case in the series */
शून्य fuzz_अग्र(संरचना fuzz *fuzz);

/*
 * Check whether this fuzz case is identical to the original
 * This is slow, but useful if the caller needs to ensure that all tests
 * generated change the input (e.g. when fuzzing signatures).
 */
पूर्णाङ्क fuzz_matches_original(संरचना fuzz *fuzz);

/* Determine whether the current fuzz sequence is exhausted (nonzero = yes) */
पूर्णाङ्क fuzz_समाप्तम्(संरचना fuzz *fuzz);

/* Return the length and a pointer to the current fuzzed case */
आकार_t fuzz_len(संरचना fuzz *fuzz);
u_char *fuzz_ptr(संरचना fuzz *fuzz);

/* Dump the current fuzz case to stderr */
शून्य fuzz_dump(संरचना fuzz *fuzz);

#यदि_अन्तः /* _TEST_HELPER_H */
