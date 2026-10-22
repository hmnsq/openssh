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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _TEST_HELPER_H
#ವ್ಯಾಖ್ಯಾನಿಸು _TEST_HELPER_H

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/err.h>
#ಆದರೆ_ಅಂತ್ಯ

ಎಣಿಕೆ test_predicate {
	TEST_EQ, TEST_NE, TEST_LT, TEST_LE, TEST_GT, TEST_GE
};
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಶೂನ್ಯ (test_onerror_func_t)(ಶೂನ್ಯ *);

/* Supplied by test suite */
ಶೂನ್ಯ tests(ಶೂನ್ಯ);
ಶೂನ್ಯ benchmarks(ಶೂನ್ಯ);

ಶೂನ್ಯ hex2bin(uint8_t *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಗಾತ್ರ_t);

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *test_ದತ್ತಾಂಶ_file(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name);
ಶೂನ್ಯ test_ಆರಂಭ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *n);
ಶೂನ್ಯ test_info(ಅಕ್ಷರ *s, ಗಾತ್ರ_t len);
ಶೂನ್ಯ ಗಣ_onerror_func(test_onerror_func_t *f, ಶೂನ್ಯ *ctx);
ಶೂನ್ಯ test_ಮುಗಿದ(ಶೂನ್ಯ);
ಪೂರ್ಣಾಂಕ test_is_verbose(ಶೂನ್ಯ);
ಪೂರ್ಣಾಂಕ test_is_quiet(ಶೂನ್ಯ);
ಪೂರ್ಣಾಂಕ test_is_fast(ಶೂನ್ಯ);
ಪೂರ್ಣಾಂಕ test_is_slow(ಶೂನ್ಯ);
ಪೂರ್ಣಾಂಕ test_is_benchmark(ಶೂನ್ಯ);
ಶೂನ್ಯ test_subtest_info(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
    __attribute__((format(ಬರೆ, 1, 2)));
ಶೂನ್ಯ ssl_err_check(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
ಶೂನ್ಯ assert_bignum(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    ಸ್ಥಿರಾಂಕ BIGNUM *aa1, ಸ್ಥಿರಾಂಕ BIGNUM *aa2, ಎಣಿಕೆ test_predicate pred);
#ಆದರೆ_ಅಂತ್ಯ
ಶೂನ್ಯ assert_string(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *aa1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *aa2, ಎಣಿಕೆ test_predicate pred);
ಶೂನ್ಯ assert_mem(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *aa1, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *aa2, ಗಾತ್ರ_t l, ಎಣಿಕೆ test_predicate pred);
ಶೂನ್ಯ assert_mem_filled(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1,
    ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *aa1, u_char v, ಗಾತ್ರ_t l, ಎಣಿಕೆ test_predicate pred);
ಶೂನ್ಯ assert_int(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    ಪೂರ್ಣಾಂಕ aa1, ಪೂರ್ಣಾಂಕ aa2, ಎಣಿಕೆ test_predicate pred);
ಶೂನ್ಯ assert_ಗಾತ್ರ_t(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    ಗಾತ್ರ_t aa1, ಗಾತ್ರ_t aa2, ಎಣಿಕೆ test_predicate pred);
ಶೂನ್ಯ assert_u_int(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    u_int aa1, u_int aa2, ಎಣಿಕೆ test_predicate pred);
ಶೂನ್ಯ assert_long(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    ದೀರ್ಘ aa1, ದೀರ್ಘ aa2, ಎಣಿಕೆ test_predicate pred);
ಶೂನ್ಯ assert_long_long(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    ದೀರ್ಘ ದೀರ್ಘ aa1, ದೀರ್ಘ ದೀರ್ಘ aa2, ಎಣಿಕೆ test_predicate pred);
ಶೂನ್ಯ assert_char(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    ಅಕ್ಷರ aa1, ಅಕ್ಷರ aa2, ಎಣಿಕೆ test_predicate pred);
ಶೂನ್ಯ assert_ptr(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *aa1, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *aa2, ಎಣಿಕೆ test_predicate pred);
ಶೂನ್ಯ assert_u8(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    uint8_t aa1, uint8_t aa2, ಎಣಿಕೆ test_predicate pred);
ಶೂನ್ಯ assert_u16(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    uint16_t aa1, uint16_t aa2, ಎಣಿಕೆ test_predicate pred);
ಶೂನ್ಯ assert_u32(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    uint32_t aa1, uint32_t aa2, ಎಣಿಕೆ test_predicate pred);
ಶೂನ್ಯ assert_u64(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    uint64_t aa1, uint64_t aa2, ಎಣಿಕೆ test_predicate pred);
ಶೂನ್ಯ assert_double(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a1, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a2,
    ದ್ವಿಗುಣ aa1, ದ್ವಿಗುಣ aa2, ಎಣಿಕೆ test_predicate pred);

#ವ್ಯಾಖ್ಯಾನಿಸು TEST_ಆರಂಭ(n)			test_ಆರಂಭ(n)
#ವ್ಯಾಖ್ಯಾನಿಸು TEST_ಮುಗಿದ()			test_ಮುಗಿದ()
#ವ್ಯಾಖ್ಯಾನಿಸು TEST_ONERROR(f, c)		ಗಣ_onerror_func(f, c)
#ವ್ಯಾಖ್ಯಾನಿಸು SSL_ERR_CHECK() 		ssl_err_check(__FILE__, __LINE__)

#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_BIGNUM_EQ(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_STRING_EQ(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_MEM_EQ(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_EQ)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_MEM_FILLED_EQ(a1, c, l) \
	assert_mem_filled(__FILE__, __LINE__, #a1, a1, c, l, TEST_EQ)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_MEM_ZERO_EQ(a1, l) \
	assert_mem_filled(__FILE__, __LINE__, #a1, a1, '\0', l, TEST_EQ)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_INT_EQ(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_ಗಾತ್ರ_T_EQ(a1, a2) \
	assert_ಗಾತ್ರ_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U_INT_EQ(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_LONG_EQ(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_LONG_LONG_EQ(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_CHAR_EQ(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_PTR_EQ(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U8_EQ(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U16_EQ(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U32_EQ(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U64_EQ(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)

#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_BIGNUM_NE(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_STRING_NE(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_MEM_NE(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_NE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_MEM_ZERO_NE(a1, l) \
	assert_mem_filled(__FILE__, __LINE__, #a1, a1, '\0', l, TEST_NE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_INT_NE(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_ಗಾತ್ರ_T_NE(a1, a2) \
	assert_ಗಾತ್ರ_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U_INT_NE(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_LONG_NE(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_LONG_LONG_NE(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_CHAR_NE(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_PTR_NE(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U8_NE(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U16_NE(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U32_NE(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U64_NE(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)

#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_BIGNUM_LT(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_STRING_LT(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_MEM_LT(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_LT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_INT_LT(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_ಗಾತ್ರ_T_LT(a1, a2) \
	assert_ಗಾತ್ರ_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U_INT_LT(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_LONG_LT(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_LONG_LONG_LT(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_CHAR_LT(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_PTR_LT(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U8_LT(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U16_LT(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U32_LT(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U64_LT(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)

#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_BIGNUM_LE(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_STRING_LE(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_MEM_LE(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_LE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_INT_LE(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_ಗಾತ್ರ_T_LE(a1, a2) \
	assert_ಗಾತ್ರ_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U_INT_LE(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_LONG_LE(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_LONG_LONG_LE(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_CHAR_LE(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_PTR_LE(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U8_LE(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U16_LE(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U32_LE(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U64_LE(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)

#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_BIGNUM_GT(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_STRING_GT(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_MEM_GT(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_GT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_INT_GT(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_ಗಾತ್ರ_T_GT(a1, a2) \
	assert_ಗಾತ್ರ_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U_INT_GT(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_LONG_GT(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_LONG_LONG_GT(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_CHAR_GT(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_PTR_GT(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U8_GT(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U16_GT(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U32_GT(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U64_GT(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)

#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_BIGNUM_GE(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_STRING_GE(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_MEM_GE(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_GE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_INT_GE(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_ಗಾತ್ರ_T_GE(a1, a2) \
	assert_ಗಾತ್ರ_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U_INT_GE(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_LONG_GE(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_LONG_LONG_GE(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_CHAR_GE(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_PTR_GE(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U8_GE(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U16_GE(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U32_GE(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_U64_GE(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)

#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_DOUBLE_EQ(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_DOUBLE_NE(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_DOUBLE_LT(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_DOUBLE_LE(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_DOUBLE_GT(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ವ್ಯಾಖ್ಯಾನಿಸು ASSERT_DOUBLE_GE(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)

/* Benchmarking support */
#ವ್ಯಾಖ್ಯಾನಿಸು BENCH_ಆರಂಭ(name)	\
	ಮಾಡು { \
		bench_ಆರಂಭ(__FILE__, __LINE__, name); \
		ಆಗ (!bench_ಮುಗಿದ()) { \
			bench_case_ಆರಂಭ(__FILE__, __LINE__); \
			ಮಾಡು {
#ವ್ಯಾಖ್ಯಾನಿಸು BENCH_ಮುಕ್ತಾಯ(unit) \
			} ಆಗ (0); \
			bench_case_ಮುಕ್ತಾಯ(__FILE__, __LINE__); \
		} \
		bench_ಮುಕ್ತಾಯ(__FILE__, __LINE__, unit); \
	} ಆಗ (0)

ಶೂನ್ಯ bench_ಆರಂಭ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name);
ಶೂನ್ಯ bench_case_ಆರಂಭ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು);
ಶೂನ್ಯ bench_case_ಮುಕ್ತಾಯ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು);
ಶೂನ್ಯ bench_ಮುಕ್ತಾಯ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *file, ಪೂರ್ಣಾಂಕ ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *unit);
ಪೂರ್ಣಾಂಕ bench_ಮುಗಿದ(ಶೂನ್ಯ);

/* Fuzzing support */

ರಚನೆ fuzz;
#ವ್ಯಾಖ್ಯಾನಿಸು FUZZ_1_ಬಿಟ್_FLIP		0x00000001	/* Flip one bit at a time */
#ವ್ಯಾಖ್ಯಾನಿಸು FUZZ_2_ಬಿಟ್_FLIP		0x00000002	/* Flip two bits at a time */
#ವ್ಯಾಖ್ಯಾನಿಸು FUZZ_1_BYTE_FLIP	0x00000004	/* Flip one byte at a time */
#ವ್ಯಾಖ್ಯಾನಿಸು FUZZ_2_BYTE_FLIP	0x00000008	/* Flip two bytes at a time */
#ವ್ಯಾಖ್ಯಾನಿಸು FUZZ_TRUNCATE_ಆರಂಭ	0x00000010	/* Truncate from beginning */
#ವ್ಯಾಖ್ಯಾನಿಸು FUZZ_TRUNCATE_ಕೊನೆ	0x00000020	/* Truncate from end */
#ವ್ಯಾಖ್ಯಾನಿಸು FUZZ_BASE64		0x00000040	/* Try all base64 chars */
#ವ್ಯಾಖ್ಯಾನಿಸು FUZZ_MAX		FUZZ_BASE64

/* Start fuzzing a blob of data with selected strategies (bitmask) */
ರಚನೆ fuzz *fuzz_begin(u_int strategies, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *p, ಗಾತ್ರ_t l);

/* Free a fuzz context */
ಶೂನ್ಯ fuzz_cleanup(ರಚನೆ fuzz *fuzz);

/* Prepare the next fuzz case in the series */
ಶೂನ್ಯ fuzz_ಮುಂದಿನ(ರಚನೆ fuzz *fuzz);

/*
 * Check whether this fuzz case is identical to the original
 * This is slow, but useful if the caller needs to ensure that all tests
 * generated change the input (e.g. when fuzzing signatures).
 */
ಪೂರ್ಣಾಂಕ fuzz_matches_original(ರಚನೆ fuzz *fuzz);

/* Determine whether the current fuzz sequence is exhausted (nonzero = yes) */
ಪೂರ್ಣಾಂಕ fuzz_ಮುಗಿದ(ರಚನೆ fuzz *fuzz);

/* Return the length and a pointer to the current fuzzed case */
ಗಾತ್ರ_t fuzz_len(ರಚನೆ fuzz *fuzz);
u_char *fuzz_ptr(ರಚನೆ fuzz *fuzz);

/* Dump the current fuzz case to stderr */
ಶೂನ್ಯ fuzz_dump(ರಚನೆ fuzz *fuzz);

#ಆದರೆ_ಅಂತ್ಯ /* _TEST_HELPER_H */
