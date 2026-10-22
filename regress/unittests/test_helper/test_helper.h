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

#अगर_अघोषित _TEST_HELPER_H
#घोषणा _TEST_HELPER_H

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <stdint.h>

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/bn.h>
#समावेश <openssl/err.h>
#पूर्ण_अगर

क्रमागत test_predicate {
	TEST_EQ, TEST_NE, TEST_LT, TEST_LE, TEST_GT, TEST_GE
};
प्रकार व्योम (test_onerror_func_t)(व्योम *);

/* Supplied by test suite */
व्योम tests(व्योम);
व्योम benchmarks(व्योम);

व्योम hex2bin(uint8_t *, स्थिर अक्षर *, माप_प्रकार);

स्थिर अक्षर *test_तथ्य_file(स्थिर अक्षर *name);
व्योम test_start(स्थिर अक्षर *n);
व्योम test_info(अक्षर *s, माप_प्रकार len);
व्योम set_onerror_func(test_onerror_func_t *f, व्योम *ctx);
व्योम test_done(व्योम);
पूर्णांक test_is_verbose(व्योम);
पूर्णांक test_is_quiet(व्योम);
पूर्णांक test_is_fast(व्योम);
पूर्णांक test_is_slow(व्योम);
पूर्णांक test_is_benchmark(व्योम);
व्योम test_subtest_info(स्थिर अक्षर *fmt, ...)
    __attribute__((format(म_लिखो, 1, 2)));
व्योम ssl_err_check(स्थिर अक्षर *file, पूर्णांक पंक्ति);
#अगर_घोषित WITH_OPENSSL
व्योम assert_bignum(स्थिर अक्षर *file, पूर्णांक पंक्ति,
    स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    स्थिर BIGNUM *aa1, स्थिर BIGNUM *aa2, क्रमागत test_predicate pred);
#पूर्ण_अगर
व्योम assert_string(स्थिर अक्षर *file, पूर्णांक पंक्ति,
    स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    स्थिर अक्षर *aa1, स्थिर अक्षर *aa2, क्रमागत test_predicate pred);
व्योम assert_mem(स्थिर अक्षर *file, पूर्णांक पंक्ति,
    स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    स्थिर व्योम *aa1, स्थिर व्योम *aa2, माप_प्रकार l, क्रमागत test_predicate pred);
व्योम assert_mem_filled(स्थिर अक्षर *file, पूर्णांक पंक्ति,
    स्थिर अक्षर *a1,
    स्थिर व्योम *aa1, u_char v, माप_प्रकार l, क्रमागत test_predicate pred);
व्योम assert_int(स्थिर अक्षर *file, पूर्णांक पंक्ति,
    स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    पूर्णांक aa1, पूर्णांक aa2, क्रमागत test_predicate pred);
व्योम assert_आकार_t(स्थिर अक्षर *file, पूर्णांक पंक्ति,
    स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    माप_प्रकार aa1, माप_प्रकार aa2, क्रमागत test_predicate pred);
व्योम assert_u_int(स्थिर अक्षर *file, पूर्णांक पंक्ति,
    स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    u_int aa1, u_int aa2, क्रमागत test_predicate pred);
व्योम assert_long(स्थिर अक्षर *file, पूर्णांक पंक्ति,
    स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    दीर्घ aa1, दीर्घ aa2, क्रमागत test_predicate pred);
व्योम assert_long_long(स्थिर अक्षर *file, पूर्णांक पंक्ति,
    स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    दीर्घ दीर्घ aa1, दीर्घ दीर्घ aa2, क्रमागत test_predicate pred);
व्योम assert_char(स्थिर अक्षर *file, पूर्णांक पंक्ति,
    स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    अक्षर aa1, अक्षर aa2, क्रमागत test_predicate pred);
व्योम assert_ptr(स्थिर अक्षर *file, पूर्णांक पंक्ति,
    स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    स्थिर व्योम *aa1, स्थिर व्योम *aa2, क्रमागत test_predicate pred);
व्योम assert_u8(स्थिर अक्षर *file, पूर्णांक पंक्ति,
    स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    uint8_t aa1, uint8_t aa2, क्रमागत test_predicate pred);
व्योम assert_u16(स्थिर अक्षर *file, पूर्णांक पंक्ति,
    स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    uint16_t aa1, uint16_t aa2, क्रमागत test_predicate pred);
व्योम assert_u32(स्थिर अक्षर *file, पूर्णांक पंक्ति,
    स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    uint32_t aa1, uint32_t aa2, क्रमागत test_predicate pred);
व्योम assert_u64(स्थिर अक्षर *file, पूर्णांक पंक्ति,
    स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    uint64_t aa1, uint64_t aa2, क्रमागत test_predicate pred);
व्योम assert_double(स्थिर अक्षर *file, पूर्णांक पंक्ति,
    स्थिर अक्षर *a1, स्थिर अक्षर *a2,
    द्विगुन aa1, द्विगुन aa2, क्रमागत test_predicate pred);

#घोषणा TEST_START(n)			test_start(n)
#घोषणा TEST_DONE()			test_done()
#घोषणा TEST_ONERROR(f, c)		set_onerror_func(f, c)
#घोषणा SSL_ERR_CHECK() 		ssl_err_check(__खाता__, __LINE__)

#घोषणा ASSERT_BIGNUM_EQ(a1, a2) \
	assert_bignum(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#घोषणा ASSERT_STRING_EQ(a1, a2) \
	assert_string(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#घोषणा ASSERT_MEM_EQ(a1, a2, l) \
	assert_mem(__खाता__, __LINE__, #a1, #a2, a1, a2, l, TEST_EQ)
#घोषणा ASSERT_MEM_FILLED_EQ(a1, c, l) \
	assert_mem_filled(__खाता__, __LINE__, #a1, a1, c, l, TEST_EQ)
#घोषणा ASSERT_MEM_ZERO_EQ(a1, l) \
	assert_mem_filled(__खाता__, __LINE__, #a1, a1, '\0', l, TEST_EQ)
#घोषणा ASSERT_INT_EQ(a1, a2) \
	assert_int(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#घोषणा ASSERT_आकार_T_EQ(a1, a2) \
	assert_आकार_t(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#घोषणा ASSERT_U_INT_EQ(a1, a2) \
	assert_u_int(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#घोषणा ASSERT_LONG_EQ(a1, a2) \
	assert_long(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#घोषणा ASSERT_LONG_LONG_EQ(a1, a2) \
	assert_long_long(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#घोषणा ASSERT_CHAR_EQ(a1, a2) \
	assert_char(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#घोषणा ASSERT_PTR_EQ(a1, a2) \
	assert_ptr(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#घोषणा ASSERT_U8_EQ(a1, a2) \
	assert_u8(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#घोषणा ASSERT_U16_EQ(a1, a2) \
	assert_u16(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#घोषणा ASSERT_U32_EQ(a1, a2) \
	assert_u32(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#घोषणा ASSERT_U64_EQ(a1, a2) \
	assert_u64(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)

#घोषणा ASSERT_BIGNUM_NE(a1, a2) \
	assert_bignum(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#घोषणा ASSERT_STRING_NE(a1, a2) \
	assert_string(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#घोषणा ASSERT_MEM_NE(a1, a2, l) \
	assert_mem(__खाता__, __LINE__, #a1, #a2, a1, a2, l, TEST_NE)
#घोषणा ASSERT_MEM_ZERO_NE(a1, l) \
	assert_mem_filled(__खाता__, __LINE__, #a1, a1, '\0', l, TEST_NE)
#घोषणा ASSERT_INT_NE(a1, a2) \
	assert_int(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#घोषणा ASSERT_आकार_T_NE(a1, a2) \
	assert_आकार_t(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#घोषणा ASSERT_U_INT_NE(a1, a2) \
	assert_u_int(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#घोषणा ASSERT_LONG_NE(a1, a2) \
	assert_long(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#घोषणा ASSERT_LONG_LONG_NE(a1, a2) \
	assert_long_long(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#घोषणा ASSERT_CHAR_NE(a1, a2) \
	assert_char(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#घोषणा ASSERT_PTR_NE(a1, a2) \
	assert_ptr(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#घोषणा ASSERT_U8_NE(a1, a2) \
	assert_u8(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#घोषणा ASSERT_U16_NE(a1, a2) \
	assert_u16(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#घोषणा ASSERT_U32_NE(a1, a2) \
	assert_u32(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#घोषणा ASSERT_U64_NE(a1, a2) \
	assert_u64(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_NE)

#घोषणा ASSERT_BIGNUM_LT(a1, a2) \
	assert_bignum(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#घोषणा ASSERT_STRING_LT(a1, a2) \
	assert_string(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#घोषणा ASSERT_MEM_LT(a1, a2, l) \
	assert_mem(__खाता__, __LINE__, #a1, #a2, a1, a2, l, TEST_LT)
#घोषणा ASSERT_INT_LT(a1, a2) \
	assert_int(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#घोषणा ASSERT_आकार_T_LT(a1, a2) \
	assert_आकार_t(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#घोषणा ASSERT_U_INT_LT(a1, a2) \
	assert_u_int(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#घोषणा ASSERT_LONG_LT(a1, a2) \
	assert_long(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#घोषणा ASSERT_LONG_LONG_LT(a1, a2) \
	assert_long_long(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#घोषणा ASSERT_CHAR_LT(a1, a2) \
	assert_char(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#घोषणा ASSERT_PTR_LT(a1, a2) \
	assert_ptr(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#घोषणा ASSERT_U8_LT(a1, a2) \
	assert_u8(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#घोषणा ASSERT_U16_LT(a1, a2) \
	assert_u16(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#घोषणा ASSERT_U32_LT(a1, a2) \
	assert_u32(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#घोषणा ASSERT_U64_LT(a1, a2) \
	assert_u64(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LT)

#घोषणा ASSERT_BIGNUM_LE(a1, a2) \
	assert_bignum(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#घोषणा ASSERT_STRING_LE(a1, a2) \
	assert_string(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#घोषणा ASSERT_MEM_LE(a1, a2, l) \
	assert_mem(__खाता__, __LINE__, #a1, #a2, a1, a2, l, TEST_LE)
#घोषणा ASSERT_INT_LE(a1, a2) \
	assert_int(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#घोषणा ASSERT_आकार_T_LE(a1, a2) \
	assert_आकार_t(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#घोषणा ASSERT_U_INT_LE(a1, a2) \
	assert_u_int(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#घोषणा ASSERT_LONG_LE(a1, a2) \
	assert_long(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#घोषणा ASSERT_LONG_LONG_LE(a1, a2) \
	assert_long_long(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#घोषणा ASSERT_CHAR_LE(a1, a2) \
	assert_char(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#घोषणा ASSERT_PTR_LE(a1, a2) \
	assert_ptr(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#घोषणा ASSERT_U8_LE(a1, a2) \
	assert_u8(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#घोषणा ASSERT_U16_LE(a1, a2) \
	assert_u16(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#घोषणा ASSERT_U32_LE(a1, a2) \
	assert_u32(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#घोषणा ASSERT_U64_LE(a1, a2) \
	assert_u64(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LE)

#घोषणा ASSERT_BIGNUM_GT(a1, a2) \
	assert_bignum(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#घोषणा ASSERT_STRING_GT(a1, a2) \
	assert_string(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#घोषणा ASSERT_MEM_GT(a1, a2, l) \
	assert_mem(__खाता__, __LINE__, #a1, #a2, a1, a2, l, TEST_GT)
#घोषणा ASSERT_INT_GT(a1, a2) \
	assert_int(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#घोषणा ASSERT_आकार_T_GT(a1, a2) \
	assert_आकार_t(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#घोषणा ASSERT_U_INT_GT(a1, a2) \
	assert_u_int(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#घोषणा ASSERT_LONG_GT(a1, a2) \
	assert_long(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#घोषणा ASSERT_LONG_LONG_GT(a1, a2) \
	assert_long_long(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#घोषणा ASSERT_CHAR_GT(a1, a2) \
	assert_char(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#घोषणा ASSERT_PTR_GT(a1, a2) \
	assert_ptr(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#घोषणा ASSERT_U8_GT(a1, a2) \
	assert_u8(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#घोषणा ASSERT_U16_GT(a1, a2) \
	assert_u16(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#घोषणा ASSERT_U32_GT(a1, a2) \
	assert_u32(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#घोषणा ASSERT_U64_GT(a1, a2) \
	assert_u64(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GT)

#घोषणा ASSERT_BIGNUM_GE(a1, a2) \
	assert_bignum(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#घोषणा ASSERT_STRING_GE(a1, a2) \
	assert_string(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#घोषणा ASSERT_MEM_GE(a1, a2, l) \
	assert_mem(__खाता__, __LINE__, #a1, #a2, a1, a2, l, TEST_GE)
#घोषणा ASSERT_INT_GE(a1, a2) \
	assert_int(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#घोषणा ASSERT_आकार_T_GE(a1, a2) \
	assert_आकार_t(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#घोषणा ASSERT_U_INT_GE(a1, a2) \
	assert_u_int(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#घोषणा ASSERT_LONG_GE(a1, a2) \
	assert_long(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#घोषणा ASSERT_LONG_LONG_GE(a1, a2) \
	assert_long_long(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#घोषणा ASSERT_CHAR_GE(a1, a2) \
	assert_char(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#घोषणा ASSERT_PTR_GE(a1, a2) \
	assert_ptr(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#घोषणा ASSERT_U8_GE(a1, a2) \
	assert_u8(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#घोषणा ASSERT_U16_GE(a1, a2) \
	assert_u16(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#घोषणा ASSERT_U32_GE(a1, a2) \
	assert_u32(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GE)
#घोषणा ASSERT_U64_GE(a1, a2) \
	assert_u64(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GE)

#घोषणा ASSERT_DOUBLE_EQ(a1, a2) \
	assert_double(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_EQ)
#घोषणा ASSERT_DOUBLE_NE(a1, a2) \
	assert_double(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_NE)
#घोषणा ASSERT_DOUBLE_LT(a1, a2) \
	assert_double(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LT)
#घोषणा ASSERT_DOUBLE_LE(a1, a2) \
	assert_double(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_LE)
#घोषणा ASSERT_DOUBLE_GT(a1, a2) \
	assert_double(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GT)
#घोषणा ASSERT_DOUBLE_GE(a1, a2) \
	assert_double(__खाता__, __LINE__, #a1, #a2, a1, a2, TEST_GE)

/* Benchmarking support */
#घोषणा BENCH_START(name)	\
	करो { \
		bench_start(__खाता__, __LINE__, name); \
		जबतक (!bench_done()) { \
			bench_case_start(__खाता__, __LINE__); \
			करो {
#घोषणा BENCH_FINISH(unit) \
			} जबतक (0); \
			bench_case_finish(__खाता__, __LINE__); \
		} \
		bench_finish(__खाता__, __LINE__, unit); \
	} जबतक (0)

व्योम bench_start(स्थिर अक्षर *file, पूर्णांक पंक्ति, स्थिर अक्षर *name);
व्योम bench_case_start(स्थिर अक्षर *file, पूर्णांक पंक्ति);
व्योम bench_case_finish(स्थिर अक्षर *file, पूर्णांक पंक्ति);
व्योम bench_finish(स्थिर अक्षर *file, पूर्णांक पंक्ति, स्थिर अक्षर *unit);
पूर्णांक bench_done(व्योम);

/* Fuzzing support */

काष्ठा fuzz;
#घोषणा FUZZ_1_BIT_FLIP		0x00000001	/* Flip one bit at a time */
#घोषणा FUZZ_2_BIT_FLIP		0x00000002	/* Flip two bits at a time */
#घोषणा FUZZ_1_BYTE_FLIP	0x00000004	/* Flip one byte at a time */
#घोषणा FUZZ_2_BYTE_FLIP	0x00000008	/* Flip two bytes at a time */
#घोषणा FUZZ_TRUNCATE_START	0x00000010	/* Truncate from beginning */
#घोषणा FUZZ_TRUNCATE_END	0x00000020	/* Truncate from end */
#घोषणा FUZZ_BASE64		0x00000040	/* Try all base64 chars */
#घोषणा FUZZ_MAX		FUZZ_BASE64

/* Start fuzzing a blob of data with selected strategies (bitmask) */
काष्ठा fuzz *fuzz_begin(u_int strategies, स्थिर व्योम *p, माप_प्रकार l);

/* Free a fuzz context */
व्योम fuzz_cleanup(काष्ठा fuzz *fuzz);

/* Prepare the next fuzz case in the series */
व्योम fuzz_अग्र(काष्ठा fuzz *fuzz);

/*
 * Check whether this fuzz case is identical to the original
 * This is slow, but useful if the caller needs to ensure that all tests
 * generated change the input (e.g. when fuzzing signatures).
 */
पूर्णांक fuzz_matches_original(काष्ठा fuzz *fuzz);

/* Determine whether the current fuzz sequence is exhausted (nonzero = yes) */
पूर्णांक fuzz_done(काष्ठा fuzz *fuzz);

/* Return the length and a pointer to the current fuzzed case */
माप_प्रकार fuzz_len(काष्ठा fuzz *fuzz);
u_char *fuzz_ptr(काष्ठा fuzz *fuzz);

/* Dump the current fuzz case to stderr */
व्योम fuzz_dump(काष्ठा fuzz *fuzz);

#पूर्ण_अगर /* _TEST_HELPER_H */
