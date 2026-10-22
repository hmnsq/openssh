/* 	$OpenBSD: tests.c,v 1.3 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for bitmap.h bitmap API
 *
 * Placed in the public domain
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#यदि_परिभाषितम् WITH_OPENSSL
#अन्तर्भाव <openssl/bn.h>
#यदि_अन्तः

#अन्तर्भाव "../test_helper/test_helper.h"

#अन्तर्भाव "bitmap.h"

#परिभाषय DEFAULT_NTESTS 131

शून्य
tests(शून्य)
{
#यदि_परिभाषितम् WITH_OPENSSL
	संरचना bitmap *b;
	BIGNUM *bn;
	आकार_t len;
	पूर्णाङ्क i, j, k, n, ntests = DEFAULT_NTESTS;
	u_char bbuf[1024], bnbuf[1024];
	पूर्णाङ्क r;

	यदि (test_is_fast())
		ntests /= 4;
	अन्यथा यदि (test_is_slow())
		ntests *= 2;

	TEST_START("bitmap_new");
	b = bitmap_new();
	ASSERT_PTR_NE(b, रिक्त);
	bn = BN_new();
	ASSERT_PTR_NE(bn, रिक्त);
	TEST_समाप्तम्();

	TEST_START("bitmap_set_bit / bitmap_test_bit");
	प्रति (i = -1; i < ntests; i++) {
		प्रति (j = -1; j < ntests; j++) {
			प्रति (k = -1; k < ntests; k++) {
				bitmap_zero(b);
				BN_clear(bn);

				test_subtest_info("set %d/%d/%d", i, j, k);
				/* Set bits */
				यदि (i >= 0) {
					ASSERT_INT_EQ(bitmap_समुच्चयः_bit(b, i), 0);
					ASSERT_INT_EQ(BN_समुच्चयः_bit(bn, i), 1);
				}
				यदि (j >= 0) {
					ASSERT_INT_EQ(bitmap_समुच्चयः_bit(b, j), 0);
					ASSERT_INT_EQ(BN_समुच्चयः_bit(bn, j), 1);
				}
				यदि (k >= 0) {
					ASSERT_INT_EQ(bitmap_समुच्चयः_bit(b, k), 0);
					ASSERT_INT_EQ(BN_समुच्चयः_bit(bn, k), 1);
				}

				/* Check perfect match between bitmap and bn */
				test_subtest_info("match %d/%d/%d", i, j, k);
				प्रति (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_bit_समुच्चयः(bn, n),
					    bitmap_test_bit(b, n));
				}

				/* Test length calculations */
				test_subtest_info("length %d/%d/%d", i, j, k);
				ASSERT_INT_EQ(BN_अङ्कः_द्वयङ्काः(bn),
				    (पूर्णाङ्क)bitmap_nbits(b));
				ASSERT_INT_EQ(BN_अङ्कः_अष्टकानि(bn),
				    (पूर्णाङ्क)bitmap_nbytes(b));

				/* Test serialisation */
				test_subtest_info("serialise %d/%d/%d",
				    i, j, k);
				len = bitmap_nbytes(b);
				स्मृतिं_पूरय(bbuf, 0xfc, परिमाण(bbuf));
				ASSERT_INT_EQ(bitmap_गन्तव्यम्_string(b, bbuf,
				    परिमाण(bbuf)), 0);
				प्रति (n = len; n < (पूर्णाङ्क)परिमाण(bbuf); n++)
					ASSERT_U8_EQ(bbuf[n], 0xfc);
				r = BN_bn2bin(bn, bnbuf);
				ASSERT_INT_GE(r, 0);
				ASSERT_INT_EQ(r, (पूर्णाङ्क)len);
				ASSERT_MEM_EQ(bbuf, bnbuf, len);

				/* Test deserialisation */
				test_subtest_info("deserialise %d/%d/%d",
				    i, j, k);
				bitmap_zero(b);
				ASSERT_INT_EQ(bitmap_from_string(b, bnbuf,
				    len), 0);
				प्रति (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_bit_समुच्चयः(bn, n),
					    bitmap_test_bit(b, n));
				}

				/* Test clearing bits */
				test_subtest_info("clear %d/%d/%d",
				    i, j, k);
				प्रति (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(bitmap_समुच्चयः_bit(b, n), 0);
					ASSERT_INT_EQ(BN_समुच्चयः_bit(bn, n), 1);
				}
				यदि (i >= 0) {
					bitmap_clear_bit(b, i);
					BN_clear_bit(bn, i);
				}
				यदि (j >= 0) {
					bitmap_clear_bit(b, j);
					BN_clear_bit(bn, j);
				}
				यदि (k >= 0) {
					bitmap_clear_bit(b, k);
					BN_clear_bit(bn, k);
				}
				प्रति (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_bit_समुच्चयः(bn, n),
					    bitmap_test_bit(b, n));
				}
			}
		}
	}
	bitmap_free(b);
	BN_free(bn);
	TEST_समाप्तम्();
#यदि_अन्तः
}

शून्य
benchmarks(शून्य)
{
	प्रारूप_लिख("no benchmarks\n");
}
