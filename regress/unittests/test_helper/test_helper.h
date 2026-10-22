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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _TEST_HELPER_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _TEST_HELPER_H

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/err.h>
#ਜੇ_ਅੰਤ

ਗਿਣਤੀ test_predicate {
	TEST_EQ, TEST_NE, TEST_LT, TEST_LE, TEST_GT, TEST_GE
};
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਖਾਲੀ (test_onerror_func_t)(ਖਾਲੀ *);

/* Supplied by test suite */
ਖਾਲੀ tests(ਖਾਲੀ);
ਖਾਲੀ benchmarks(ਖਾਲੀ);

ਖਾਲੀ hex2bin(uint8_t *, ਅਚਲ ਅੱਖਰ *, ਮਾਪ_t);

ਅਚਲ ਅੱਖਰ *test_ਅੰਕੜੇ_file(ਅਚਲ ਅੱਖਰ *name);
ਖਾਲੀ test_ਸ਼ੁਰੂ(ਅਚਲ ਅੱਖਰ *n);
ਖਾਲੀ test_info(ਅੱਖਰ *s, ਮਾਪ_t len);
ਖਾਲੀ ਸੈੱਟ_onerror_func(test_onerror_func_t *f, ਖਾਲੀ *ctx);
ਖਾਲੀ test_ਪੂਰਾ(ਖਾਲੀ);
ਪੂਰਨ test_is_verbose(ਖਾਲੀ);
ਪੂਰਨ test_is_quiet(ਖਾਲੀ);
ਪੂਰਨ test_is_fast(ਖਾਲੀ);
ਪੂਰਨ test_is_slow(ਖਾਲੀ);
ਪੂਰਨ test_is_benchmark(ਖਾਲੀ);
ਖਾਲੀ test_subtest_info(ਅਚਲ ਅੱਖਰ *fmt, ...)
    __attribute__((format(ਲਿਖੋ, 1, 2)));
ਖਾਲੀ ssl_err_check(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
ਖਾਲੀ assert_bignum(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ,
    ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    ਅਚਲ BIGNUM *aa1, ਅਚਲ BIGNUM *aa2, ਗਿਣਤੀ test_predicate pred);
#ਜੇ_ਅੰਤ
ਖਾਲੀ assert_string(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ,
    ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    ਅਚਲ ਅੱਖਰ *aa1, ਅਚਲ ਅੱਖਰ *aa2, ਗਿਣਤੀ test_predicate pred);
ਖਾਲੀ assert_mem(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ,
    ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    ਅਚਲ ਖਾਲੀ *aa1, ਅਚਲ ਖਾਲੀ *aa2, ਮਾਪ_t l, ਗਿਣਤੀ test_predicate pred);
ਖਾਲੀ assert_mem_filled(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ,
    ਅਚਲ ਅੱਖਰ *a1,
    ਅਚਲ ਖਾਲੀ *aa1, u_char v, ਮਾਪ_t l, ਗਿਣਤੀ test_predicate pred);
ਖਾਲੀ assert_int(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ,
    ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    ਪੂਰਨ aa1, ਪੂਰਨ aa2, ਗਿਣਤੀ test_predicate pred);
ਖਾਲੀ assert_ਮਾਪ_t(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ,
    ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    ਮਾਪ_t aa1, ਮਾਪ_t aa2, ਗਿਣਤੀ test_predicate pred);
ਖਾਲੀ assert_u_int(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ,
    ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    u_int aa1, u_int aa2, ਗਿਣਤੀ test_predicate pred);
ਖਾਲੀ assert_long(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ,
    ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    ਲੰਮਾ aa1, ਲੰਮਾ aa2, ਗਿਣਤੀ test_predicate pred);
ਖਾਲੀ assert_long_long(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ,
    ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    ਲੰਮਾ ਲੰਮਾ aa1, ਲੰਮਾ ਲੰਮਾ aa2, ਗਿਣਤੀ test_predicate pred);
ਖਾਲੀ assert_char(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ,
    ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    ਅੱਖਰ aa1, ਅੱਖਰ aa2, ਗਿਣਤੀ test_predicate pred);
ਖਾਲੀ assert_ptr(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ,
    ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    ਅਚਲ ਖਾਲੀ *aa1, ਅਚਲ ਖਾਲੀ *aa2, ਗਿਣਤੀ test_predicate pred);
ਖਾਲੀ assert_u8(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ,
    ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    uint8_t aa1, uint8_t aa2, ਗਿਣਤੀ test_predicate pred);
ਖਾਲੀ assert_u16(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ,
    ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    uint16_t aa1, uint16_t aa2, ਗਿਣਤੀ test_predicate pred);
ਖਾਲੀ assert_u32(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ,
    ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    uint32_t aa1, uint32_t aa2, ਗਿਣਤੀ test_predicate pred);
ਖਾਲੀ assert_u64(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ,
    ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    uint64_t aa1, uint64_t aa2, ਗਿਣਤੀ test_predicate pred);
ਖਾਲੀ assert_double(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ,
    ਅਚਲ ਅੱਖਰ *a1, ਅਚਲ ਅੱਖਰ *a2,
    ਦੁੱਗਣਾ aa1, ਦੁੱਗਣਾ aa2, ਗਿਣਤੀ test_predicate pred);

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TEST_ਸ਼ੁਰੂ(n)			test_ਸ਼ੁਰੂ(n)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TEST_ਪੂਰਾ()			test_ਪੂਰਾ()
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TEST_ONERROR(f, c)		ਸੈੱਟ_onerror_func(f, c)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSL_ERR_CHECK() 		ssl_err_check(__FILE__, __LINE__)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_BIGNUM_EQ(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_STRING_EQ(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_MEM_EQ(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_EQ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_MEM_FILLED_EQ(a1, c, l) \
	assert_mem_filled(__FILE__, __LINE__, #a1, a1, c, l, TEST_EQ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_MEM_ZERO_EQ(a1, l) \
	assert_mem_filled(__FILE__, __LINE__, #a1, a1, '\0', l, TEST_EQ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_INT_EQ(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_ਮਾਪ_T_EQ(a1, a2) \
	assert_ਮਾਪ_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U_INT_EQ(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_LONG_EQ(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_LONG_LONG_EQ(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_CHAR_EQ(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_PTR_EQ(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U8_EQ(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U16_EQ(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U32_EQ(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U64_EQ(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_BIGNUM_NE(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_STRING_NE(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_MEM_NE(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_NE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_MEM_ZERO_NE(a1, l) \
	assert_mem_filled(__FILE__, __LINE__, #a1, a1, '\0', l, TEST_NE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_INT_NE(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_ਮਾਪ_T_NE(a1, a2) \
	assert_ਮਾਪ_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U_INT_NE(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_LONG_NE(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_LONG_LONG_NE(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_CHAR_NE(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_PTR_NE(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U8_NE(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U16_NE(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U32_NE(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U64_NE(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_BIGNUM_LT(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_STRING_LT(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_MEM_LT(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_LT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_INT_LT(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_ਮਾਪ_T_LT(a1, a2) \
	assert_ਮਾਪ_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U_INT_LT(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_LONG_LT(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_LONG_LONG_LT(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_CHAR_LT(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_PTR_LT(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U8_LT(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U16_LT(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U32_LT(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U64_LT(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_BIGNUM_LE(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_STRING_LE(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_MEM_LE(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_LE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_INT_LE(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_ਮਾਪ_T_LE(a1, a2) \
	assert_ਮਾਪ_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U_INT_LE(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_LONG_LE(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_LONG_LONG_LE(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_CHAR_LE(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_PTR_LE(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U8_LE(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U16_LE(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U32_LE(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U64_LE(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_BIGNUM_GT(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_STRING_GT(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_MEM_GT(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_GT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_INT_GT(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_ਮਾਪ_T_GT(a1, a2) \
	assert_ਮਾਪ_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U_INT_GT(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_LONG_GT(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_LONG_LONG_GT(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_CHAR_GT(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_PTR_GT(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U8_GT(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U16_GT(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U32_GT(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U64_GT(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_BIGNUM_GE(a1, a2) \
	assert_bignum(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_STRING_GE(a1, a2) \
	assert_string(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_MEM_GE(a1, a2, l) \
	assert_mem(__FILE__, __LINE__, #a1, #a2, a1, a2, l, TEST_GE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_INT_GE(a1, a2) \
	assert_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_ਮਾਪ_T_GE(a1, a2) \
	assert_ਮਾਪ_t(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U_INT_GE(a1, a2) \
	assert_u_int(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_LONG_GE(a1, a2) \
	assert_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_LONG_LONG_GE(a1, a2) \
	assert_long_long(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_CHAR_GE(a1, a2) \
	assert_char(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_PTR_GE(a1, a2) \
	assert_ptr(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U8_GE(a1, a2) \
	assert_u8(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U16_GE(a1, a2) \
	assert_u16(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U32_GE(a1, a2) \
	assert_u32(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_U64_GE(a1, a2) \
	assert_u64(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_DOUBLE_EQ(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_DOUBLE_NE(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_DOUBLE_LT(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_DOUBLE_LE(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_DOUBLE_GT(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSERT_DOUBLE_GE(a1, a2) \
	assert_double(__FILE__, __LINE__, #a1, #a2, a1, a2, TEST_GE)

/* Benchmarking support */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ BENCH_ਸ਼ੁਰੂ(name)	\
	ਕਰੋ { \
		bench_ਸ਼ੁਰੂ(__FILE__, __LINE__, name); \
		ਜਦੋਂ (!bench_ਪੂਰਾ()) { \
			bench_case_ਸ਼ੁਰੂ(__FILE__, __LINE__); \
			ਕਰੋ {
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ BENCH_ਅੰਤ(unit) \
			} ਜਦੋਂ (0); \
			bench_case_ਅੰਤ(__FILE__, __LINE__); \
		} \
		bench_ਅੰਤ(__FILE__, __LINE__, unit); \
	} ਜਦੋਂ (0)

ਖਾਲੀ bench_ਸ਼ੁਰੂ(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ, ਅਚਲ ਅੱਖਰ *name);
ਖਾਲੀ bench_case_ਸ਼ੁਰੂ(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ);
ਖਾਲੀ bench_case_ਅੰਤ(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ);
ਖਾਲੀ bench_ਅੰਤ(ਅਚਲ ਅੱਖਰ *file, ਪੂਰਨ ਸਤਰ, ਅਚਲ ਅੱਖਰ *unit);
ਪੂਰਨ bench_ਪੂਰਾ(ਖਾਲੀ);

/* Fuzzing support */

ਬਣਤਰ fuzz;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FUZZ_1_ਦੋਆਧਾਰੀ_ਅੰਕ_FLIP		0x00000001	/* Flip one bit at a time */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FUZZ_2_ਦੋਆਧਾਰੀ_ਅੰਕ_FLIP		0x00000002	/* Flip two bits at a time */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FUZZ_1_BYTE_FLIP	0x00000004	/* Flip one byte at a time */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FUZZ_2_BYTE_FLIP	0x00000008	/* Flip two bytes at a time */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FUZZ_TRUNCATE_ਸ਼ੁਰੂ	0x00000010	/* Truncate from beginning */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FUZZ_TRUNCATE_ਸਿਰਾ	0x00000020	/* Truncate from end */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FUZZ_BASE64		0x00000040	/* Try all base64 chars */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FUZZ_MAX		FUZZ_BASE64

/* Start fuzzing a blob of data with selected strategies (bitmask) */
ਬਣਤਰ fuzz *fuzz_begin(u_int strategies, ਅਚਲ ਖਾਲੀ *p, ਮਾਪ_t l);

/* Free a fuzz context */
ਖਾਲੀ fuzz_cleanup(ਬਣਤਰ fuzz *fuzz);

/* Prepare the next fuzz case in the series */
ਖਾਲੀ fuzz_ਅਗਲਾ(ਬਣਤਰ fuzz *fuzz);

/*
 * Check whether this fuzz case is identical to the original
 * This is slow, but useful if the caller needs to ensure that all tests
 * generated change the input (e.g. when fuzzing signatures).
 */
ਪੂਰਨ fuzz_matches_original(ਬਣਤਰ fuzz *fuzz);

/* Determine whether the current fuzz sequence is exhausted (nonzero = yes) */
ਪੂਰਨ fuzz_ਪੂਰਾ(ਬਣਤਰ fuzz *fuzz);

/* Return the length and a pointer to the current fuzzed case */
ਮਾਪ_t fuzz_len(ਬਣਤਰ fuzz *fuzz);
u_char *fuzz_ptr(ਬਣਤਰ fuzz *fuzz);

/* Dump the current fuzz case to stderr */
ਖਾਲੀ fuzz_dump(ਬਣਤਰ fuzz *fuzz);

#ਜੇ_ਅੰਤ /* _TEST_HELPER_H */
