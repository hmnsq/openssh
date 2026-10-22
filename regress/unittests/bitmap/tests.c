/* 	$OpenBSD: tests.c,v 1.3 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for bitmap.h bitmap API
 *
 * Placed in the public domain
 */

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/bn.h>
#पूर्ण_अगर

#समावेश "../test_helper/test_helper.h"

#समावेश "bitmap.h"

#घोषणा DEFAULT_NTESTS 131

व्योम
tests(व्योम)
{
#अगर_घोषित WITH_OPENSSL
	काष्ठा bitmap *b;
	BIGNUM *bn;
	माप_प्रकार len;
	पूर्णांक i, j, k, n, ntests = DEFAULT_NTESTS;
	u_char bbuf[1024], bnbuf[1024];
	पूर्णांक r;

	अगर (test_is_fast())
		ntests /= 4;
	अन्यथा अगर (test_is_slow())
		ntests *= 2;

	TEST_START("bitmap_new");
	b = bitmap_new();
	ASSERT_PTR_NE(b, शून्य);
	bn = BN_new();
	ASSERT_PTR_NE(bn, शून्य);
	TEST_DONE();

	TEST_START("bitmap_set_bit / bitmap_test_bit");
	क्रम (i = -1; i < ntests; i++) {
		क्रम (j = -1; j < ntests; j++) {
			क्रम (k = -1; k < ntests; k++) {
				bitmap_zero(b);
				BN_clear(bn);

				test_subtest_info("set %d/%d/%d", i, j, k);
				/* Set bits */
				अगर (i >= 0) {
					ASSERT_INT_EQ(bitmap_set_bit(b, i), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, i), 1);
				}
				अगर (j >= 0) {
					ASSERT_INT_EQ(bitmap_set_bit(b, j), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, j), 1);
				}
				अगर (k >= 0) {
					ASSERT_INT_EQ(bitmap_set_bit(b, k), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, k), 1);
				}

				/* Check perfect match between bitmap and bn */
				test_subtest_info("match %d/%d/%d", i, j, k);
				क्रम (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_bit_set(bn, n),
					    bitmap_test_bit(b, n));
				}

				/* Test length calculations */
				test_subtest_info("length %d/%d/%d", i, j, k);
				ASSERT_INT_EQ(BN_अंक_bits(bn),
				    (पूर्णांक)bitmap_nbits(b));
				ASSERT_INT_EQ(BN_अंक_bytes(bn),
				    (पूर्णांक)bitmap_nbytes(b));

				/* Test serialisation */
				test_subtest_info("serialise %d/%d/%d",
				    i, j, k);
				len = bitmap_nbytes(b);
				स_रखो(bbuf, 0xfc, माप(bbuf));
				ASSERT_INT_EQ(bitmap_to_string(b, bbuf,
				    माप(bbuf)), 0);
				क्रम (n = len; n < (पूर्णांक)माप(bbuf); n++)
					ASSERT_U8_EQ(bbuf[n], 0xfc);
				r = BN_bn2bin(bn, bnbuf);
				ASSERT_INT_GE(r, 0);
				ASSERT_INT_EQ(r, (पूर्णांक)len);
				ASSERT_MEM_EQ(bbuf, bnbuf, len);

				/* Test deserialisation */
				test_subtest_info("deserialise %d/%d/%d",
				    i, j, k);
				bitmap_zero(b);
				ASSERT_INT_EQ(bitmap_from_string(b, bnbuf,
				    len), 0);
				क्रम (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_bit_set(bn, n),
					    bitmap_test_bit(b, n));
				}

				/* Test clearing bits */
				test_subtest_info("clear %d/%d/%d",
				    i, j, k);
				क्रम (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(bitmap_set_bit(b, n), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, n), 1);
				}
				अगर (i >= 0) {
					bitmap_clear_bit(b, i);
					BN_clear_bit(bn, i);
				}
				अगर (j >= 0) {
					bitmap_clear_bit(b, j);
					BN_clear_bit(bn, j);
				}
				अगर (k >= 0) {
					bitmap_clear_bit(b, k);
					BN_clear_bit(bn, k);
				}
				क्रम (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_bit_set(bn, n),
					    bitmap_test_bit(b, n));
				}
			}
		}
	}
	bitmap_free(b);
	BN_free(bn);
	TEST_DONE();
#पूर्ण_अगर
}

व्योम
benchmarks(व्योम)
{
	म_लिखो("no benchmarks\n");
}
