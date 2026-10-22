/* 	$OpenBSD: tests.c,v 1.3 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for bitmap.h bitmap API
 *
 * Placed in the public domain
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/bn.h>
#అయితే_ముగింపు

#అన్తర్భావ "../test_helper/test_helper.h"

#అన్తర్భావ "bitmap.h"

#నిర్వచించు DEFAULT_NTESTS 131

శూన్య
tests(శూన్య)
{
#నిర్వచితమైతే WITH_OPENSSL
	నిర్మాణం bitmap *b;
	BIGNUM *bn;
	కొలత_t len;
	పూర్ణాంకం i, j, k, n, ntests = DEFAULT_NTESTS;
	u_char bbuf[1024], bnbuf[1024];
	పూర్ణాంకం r;

	ఒకవేళ (test_is_fast())
		ntests /= 4;
	లేకపోతే ఒకవేళ (test_is_slow())
		ntests *= 2;

	TEST_ప్రారంభం("bitmap_new");
	b = bitmap_new();
	ASSERT_PTR_NE(b, ఖాళీ);
	bn = BN_new();
	ASSERT_PTR_NE(bn, ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("bitmap_set_bit / bitmap_test_bit");
	కొరకు (i = -1; i < ntests; i++) {
		కొరకు (j = -1; j < ntests; j++) {
			కొరకు (k = -1; k < ntests; k++) {
				bitmap_zero(b);
				BN_clear(bn);

				test_subtest_info("set %d/%d/%d", i, j, k);
				/* Set bits */
				ఒకవేళ (i >= 0) {
					ASSERT_INT_EQ(bitmap_సమితి_బిట్టు(b, i), 0);
					ASSERT_INT_EQ(BN_సమితి_బిట్టు(bn, i), 1);
				}
				ఒకవేళ (j >= 0) {
					ASSERT_INT_EQ(bitmap_సమితి_బిట్టు(b, j), 0);
					ASSERT_INT_EQ(BN_సమితి_బిట్టు(bn, j), 1);
				}
				ఒకవేళ (k >= 0) {
					ASSERT_INT_EQ(bitmap_సమితి_బిట్టు(b, k), 0);
					ASSERT_INT_EQ(BN_సమితి_బిట్టు(bn, k), 1);
				}

				/* Check perfect match between bitmap and bn */
				test_subtest_info("match %d/%d/%d", i, j, k);
				కొరకు (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_బిట్టు_సమితి(bn, n),
					    bitmap_test_బిట్టు(b, n));
				}

				/* Test length calculations */
				test_subtest_info("length %d/%d/%d", i, j, k);
				ASSERT_INT_EQ(BN_అంకె_బిట్లు(bn),
				    (పూర్ణాంకం)bitmap_nbits(b));
				ASSERT_INT_EQ(BN_అంకె_బైట్లు(bn),
				    (పూర్ణాంకం)bitmap_nbytes(b));

				/* Test serialisation */
				test_subtest_info("serialise %d/%d/%d",
				    i, j, k);
				len = bitmap_nbytes(b);
				memset(bbuf, 0xfc, పరిమాణం(bbuf));
				ASSERT_INT_EQ(bitmap_గమ్యం_string(b, bbuf,
				    పరిమాణం(bbuf)), 0);
				కొరకు (n = len; n < (పూర్ణాంకం)పరిమాణం(bbuf); n++)
					ASSERT_U8_EQ(bbuf[n], 0xfc);
				r = BN_bn2bin(bn, bnbuf);
				ASSERT_INT_GE(r, 0);
				ASSERT_INT_EQ(r, (పూర్ణాంకం)len);
				ASSERT_MEM_EQ(bbuf, bnbuf, len);

				/* Test deserialisation */
				test_subtest_info("deserialise %d/%d/%d",
				    i, j, k);
				bitmap_zero(b);
				ASSERT_INT_EQ(bitmap_from_string(b, bnbuf,
				    len), 0);
				కొరకు (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_బిట్టు_సమితి(bn, n),
					    bitmap_test_బిట్టు(b, n));
				}

				/* Test clearing bits */
				test_subtest_info("clear %d/%d/%d",
				    i, j, k);
				కొరకు (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(bitmap_సమితి_బిట్టు(b, n), 0);
					ASSERT_INT_EQ(BN_సమితి_బిట్టు(bn, n), 1);
				}
				ఒకవేళ (i >= 0) {
					bitmap_clear_బిట్టు(b, i);
					BN_clear_బిట్టు(bn, i);
				}
				ఒకవేళ (j >= 0) {
					bitmap_clear_బిట్టు(b, j);
					BN_clear_బిట్టు(bn, j);
				}
				ఒకవేళ (k >= 0) {
					bitmap_clear_బిట్టు(b, k);
					BN_clear_బిట్టు(bn, k);
				}
				కొరకు (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_బిట్టు_సమితి(bn, n),
					    bitmap_test_బిట్టు(b, n));
				}
			}
		}
	}
	bitmap_free(b);
	BN_free(bn);
	TEST_పూర్తి();
#అయితే_ముగింపు
}

శూన్య
benchmarks(శూన్య)
{
	రాయి("no benchmarks\n");
}
