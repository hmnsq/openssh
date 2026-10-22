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

#నిర్వచితం_కాకపోతే _TEST_HELPER_H
#నిర్వచించు _TEST_HELPER_H

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdint.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/err.h>
#అయితే_ముగింపు

గణన test_predicate {
	TEST_EQ, TEST_NE, TEST_LT, TEST_LE, TEST_GT, TEST_GE
};
రకనిర్వచనం శూన్య (test_onerror_func_t)(శూన్య *);

/* Supplied by test suite */
శూన్య tests(శూన్య);
శూన్య benchmarks(శూన్య);

శూన్య hex2bin(uint8_t *, స్థిరరాశి అక్షరం *, కొలత_t);

స్థిరరాశి అక్షరం *test_దత్తాంశం_file(స్థిరరాశి అక్షరం *name);
శూన్య test_ప్రారంభం(స్థిరరాశి అక్షరం *n);
శూన్య test_info(అక్షరం *s, కొలత_t len);
శూన్య సమితి_onerror_func(test_onerror_func_t *f, శూన్య *ctx);
శూన్య test_పూర్తి(శూన్య);
పూర్ణాంకం test_is_verbose(శూన్య);
పూర్ణాంకం test_is_quiet(శూన్య);
పూర్ణాంకం test_is_fast(శూన్య);
పూర్ణాంకం test_is_slow(శూన్య);
పూర్ణాంకం test_is_benchmark(శూన్య);
శూన్య test_subtest_info(స్థిరరాశి అక్షరం *fmt, ...)
    __attribute__((format(రాయి, 1, 2)));
శూన్య ssl_err_check(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి);
#నిర్వచితమైతే WITH_OPENSSL
శూన్య assert_bignum(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి,
    స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    స్థిరరాశి BIGNUM *aa1, స్థిరరాశి BIGNUM *aa2, గణన test_predicate pred);
#అయితే_ముగింపు
శూన్య assert_string(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి,
    స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    స్థిరరాశి అక్షరం *aa1, స్థిరరాశి అక్షరం *aa2, గణన test_predicate pred);
శూన్య assert_mem(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి,
    స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    స్థిరరాశి శూన్య *aa1, స్థిరరాశి శూన్య *aa2, కొలత_t l, గణన test_predicate pred);
శూన్య assert_mem_filled(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి,
    స్థిరరాశి అక్షరం *a1,
    స్థిరరాశి శూన్య *aa1, u_char v, కొలత_t l, గణన test_predicate pred);
శూన్య assert_int(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి,
    స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    పూర్ణాంకం aa1, పూర్ణాంకం aa2, గణన test_predicate pred);
శూన్య assert_కొలత_t(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి,
    స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    కొలత_t aa1, కొలత_t aa2, గణన test_predicate pred);
శూన్య assert_u_int(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి,
    స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    u_int aa1, u_int aa2, గణన test_predicate pred);
శూన్య assert_long(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి,
    స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    దీర్ఘ aa1, దీర్ఘ aa2, గణన test_predicate pred);
శూన్య assert_long_long(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి,
    స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    దీర్ఘ దీర్ఘ aa1, దీర్ఘ దీర్ఘ aa2, గణన test_predicate pred);
శూన్య assert_char(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి,
    స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    అక్షరం aa1, అక్షరం aa2, గణన test_predicate pred);
శూన్య assert_ptr(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి,
    స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    స్థిరరాశి శూన్య *aa1, స్థిరరాశి శూన్య *aa2, గణన test_predicate pred);
శూన్య assert_u8(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి,
    స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    uint8_t aa1, uint8_t aa2, గణన test_predicate pred);
శూన్య assert_u16(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి,
    స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    uint16_t aa1, uint16_t aa2, గణన test_predicate pred);
శూన్య assert_u32(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి,
    స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    uint32_t aa1, uint32_t aa2, గణన test_predicate pred);
శూన్య assert_u64(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి,
    స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    uint64_t aa1, uint64_t aa2, గణన test_predicate pred);
శూన్య assert_double(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి,
    స్థిరరాశి అక్షరం *a1, స్థిరరాశి అక్షరం *a2,
    ద్విగుణ aa1, ద్విగుణ aa2, గణన test_predicate pred);

#నిర్వచించు TEST_ప్రారంభం(n)			test_ప్రారంభం(n)
#నిర్వచించు TEST_పూర్తి()			test_పూర్తి()
#నిర్వచించు TEST_ONERROR(f, c)		సమితి_onerror_func(f, c)
#నిర్వచించు SSL_ERR_CHECK() 		ssl_err_check(__FILE__, __LINE__)

#నిర్వచించు ASSERT_BIGNUM_EQ(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#నిర్వచించు ASSERT_STRING_EQ(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#నిర్వచించు ASSERT_MEM_EQ(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_EQ)
#నిర్వచించు ASSERT_MEM_FILLED_EQ(a1, c, l) \
	assert_mem_filled(__FILE__, __LINE__, #a1, a1, c, l, TEST_EQ)
#నిర్వచించు ASSERT_MEM_ZERO_EQ(a1, l) \
	assert_mem_filled(__FILE__, __LINE__, #a1, a1, '\0', l, TEST_EQ)
#నిర్వచించు ASSERT_INT_EQ(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#నిర్వచించు ASSERT_కొలత_T_EQ(a1, a2) \
	assert_కొలత_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#నిర్వచించు ASSERT_U_INT_EQ(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#నిర్వచించు ASSERT_LONG_EQ(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#నిర్వచించు ASSERT_LONG_LONG_EQ(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#నిర్వచించు ASSERT_CHAR_EQ(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#నిర్వచించు ASSERT_PTR_EQ(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#నిర్వచించు ASSERT_U8_EQ(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#నిర్వచించు ASSERT_U16_EQ(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#నిర్వచించు ASSERT_U32_EQ(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#నిర్వచించు ASSERT_U64_EQ(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)

#నిర్వచించు ASSERT_BIGNUM_NE(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#నిర్వచించు ASSERT_STRING_NE(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#నిర్వచించు ASSERT_MEM_NE(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_NE)
#నిర్వచించు ASSERT_MEM_ZERO_NE(a1, l) \
	assert_mem_filled(__FILE__, __LINE__, #a1, a1, '\0', l, TEST_NE)
#నిర్వచించు ASSERT_INT_NE(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#నిర్వచించు ASSERT_కొలత_T_NE(a1, a2) \
	assert_కొలత_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#నిర్వచించు ASSERT_U_INT_NE(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#నిర్వచించు ASSERT_LONG_NE(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#నిర్వచించు ASSERT_LONG_LONG_NE(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#నిర్వచించు ASSERT_CHAR_NE(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#నిర్వచించు ASSERT_PTR_NE(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#నిర్వచించు ASSERT_U8_NE(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#నిర్వచించు ASSERT_U16_NE(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#నిర్వచించు ASSERT_U32_NE(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#నిర్వచించు ASSERT_U64_NE(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)

#నిర్వచించు ASSERT_BIGNUM_LT(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#నిర్వచించు ASSERT_STRING_LT(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#నిర్వచించు ASSERT_MEM_LT(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_LT)
#నిర్వచించు ASSERT_INT_LT(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#నిర్వచించు ASSERT_కొలత_T_LT(a1, a2) \
	assert_కొలత_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#నిర్వచించు ASSERT_U_INT_LT(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#నిర్వచించు ASSERT_LONG_LT(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#నిర్వచించు ASSERT_LONG_LONG_LT(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#నిర్వచించు ASSERT_CHAR_LT(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#నిర్వచించు ASSERT_PTR_LT(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#నిర్వచించు ASSERT_U8_LT(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#నిర్వచించు ASSERT_U16_LT(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#నిర్వచించు ASSERT_U32_LT(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#నిర్వచించు ASSERT_U64_LT(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)

#నిర్వచించు ASSERT_BIGNUM_LE(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#నిర్వచించు ASSERT_STRING_LE(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#నిర్వచించు ASSERT_MEM_LE(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_LE)
#నిర్వచించు ASSERT_INT_LE(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#నిర్వచించు ASSERT_కొలత_T_LE(a1, a2) \
	assert_కొలత_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#నిర్వచించు ASSERT_U_INT_LE(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#నిర్వచించు ASSERT_LONG_LE(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#నిర్వచించు ASSERT_LONG_LONG_LE(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#నిర్వచించు ASSERT_CHAR_LE(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#నిర్వచించు ASSERT_PTR_LE(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#నిర్వచించు ASSERT_U8_LE(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#నిర్వచించు ASSERT_U16_LE(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#నిర్వచించు ASSERT_U32_LE(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#నిర్వచించు ASSERT_U64_LE(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)

#నిర్వచించు ASSERT_BIGNUM_GT(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#నిర్వచించు ASSERT_STRING_GT(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#నిర్వచించు ASSERT_MEM_GT(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_GT)
#నిర్వచించు ASSERT_INT_GT(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#నిర్వచించు ASSERT_కొలత_T_GT(a1, a2) \
	assert_కొలత_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#నిర్వచించు ASSERT_U_INT_GT(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#నిర్వచించు ASSERT_LONG_GT(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#నిర్వచించు ASSERT_LONG_LONG_GT(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#నిర్వచించు ASSERT_CHAR_GT(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#నిర్వచించు ASSERT_PTR_GT(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#నిర్వచించు ASSERT_U8_GT(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#నిర్వచించు ASSERT_U16_GT(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#నిర్వచించు ASSERT_U32_GT(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#నిర్వచించు ASSERT_U64_GT(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)

#నిర్వచించు ASSERT_BIGNUM_GE(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#నిర్వచించు ASSERT_STRING_GE(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#నిర్వచించు ASSERT_MEM_GE(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_GE)
#నిర్వచించు ASSERT_INT_GE(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#నిర్వచించు ASSERT_కొలత_T_GE(a1, a2) \
	assert_కొలత_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#నిర్వచించు ASSERT_U_INT_GE(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#నిర్వచించు ASSERT_LONG_GE(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#నిర్వచించు ASSERT_LONG_LONG_GE(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#నిర్వచించు ASSERT_CHAR_GE(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#నిర్వచించు ASSERT_PTR_GE(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#నిర్వచించు ASSERT_U8_GE(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#నిర్వచించు ASSERT_U16_GE(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#నిర్వచించు ASSERT_U32_GE(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#నిర్వచించు ASSERT_U64_GE(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)

#నిర్వచించు ASSERT_DOUBLE_EQ(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#నిర్వచించు ASSERT_DOUBLE_NE(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#నిర్వచించు ASSERT_DOUBLE_LT(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#నిర్వచించు ASSERT_DOUBLE_LE(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#నిర్వచించు ASSERT_DOUBLE_GT(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#నిర్వచించు ASSERT_DOUBLE_GE(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)

/* Benchmarking support */
#నిర్వచించు BENCH_ప్రారంభం(name)	\
	చేయి { \
		bench_ప్రారంభం(__FILE__, __LINE__, name); \
		అయితే (!bench_పూర్తి()) { \
			bench_case_ప్రారంభం(__FILE__, __LINE__); \
			చేయి {
#నిర్వచించు BENCH_ముగింపు(unit) \
			} అయితే (0); \
			bench_case_ముగింపు(__FILE__, __LINE__); \
		} \
		bench_ముగింపు(__FILE__, __LINE__, unit); \
	} అయితే (0)

శూన్య bench_ప్రారంభం(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి, స్థిరరాశి అక్షరం *name);
శూన్య bench_case_ప్రారంభం(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి);
శూన్య bench_case_ముగింపు(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి);
శూన్య bench_ముగింపు(స్థిరరాశి అక్షరం *file, పూర్ణాంకం పంక్తి, స్థిరరాశి అక్షరం *unit);
పూర్ణాంకం bench_పూర్తి(శూన్య);

/* Fuzzing support */

నిర్మాణం fuzz;
#నిర్వచించు FUZZ_1_బిట్టు_FLIP		0x00000001	/* Flip one bit at a time */
#నిర్వచించు FUZZ_2_బిట్టు_FLIP		0x00000002	/* Flip two bits at a time */
#నిర్వచించు FUZZ_1_BYTE_FLIP	0x00000004	/* Flip one byte at a time */
#నిర్వచించు FUZZ_2_BYTE_FLIP	0x00000008	/* Flip two bytes at a time */
#నిర్వచించు FUZZ_TRUNCATE_ప్రారంభం	0x00000010	/* Truncate from beginning */
#నిర్వచించు FUZZ_TRUNCATE_చివర	0x00000020	/* Truncate from end */
#నిర్వచించు FUZZ_BASE64		0x00000040	/* Try all base64 chars */
#నిర్వచించు FUZZ_MAX		FUZZ_BASE64

/* Start fuzzing a blob of data with selected strategies (bitmask) */
నిర్మాణం fuzz *fuzz_begin(u_int strategies, స్థిరరాశి శూన్య *p, కొలత_t l);

/* Free a fuzz context */
శూన్య fuzz_cleanup(నిర్మాణం fuzz *fuzz);

/* Prepare the next fuzz case in the series */
శూన్య fuzz_తదుపరి(నిర్మాణం fuzz *fuzz);

/*
 * Check whether this fuzz case is identical to the original
 * This is slow, but useful if the caller needs to ensure that all tests
 * generated change the input (e.g. when fuzzing signatures).
 */
పూర్ణాంకం fuzz_matches_original(నిర్మాణం fuzz *fuzz);

/* Determine whether the current fuzz sequence is exhausted (nonzero = yes) */
పూర్ణాంకం fuzz_పూర్తి(నిర్మాణం fuzz *fuzz);

/* Return the length and a pointer to the current fuzzed case */
కొలత_t fuzz_len(నిర్మాణం fuzz *fuzz);
u_char *fuzz_ptr(నిర్మాణం fuzz *fuzz);

/* Dump the current fuzz case to stderr */
శూన్య fuzz_dump(నిర్మాణం fuzz *fuzz);

#అయితే_ముగింపు /* _TEST_HELPER_H */
