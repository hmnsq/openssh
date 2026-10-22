/* 	$OpenBSD: tests.c,v 1.3 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for bitmap.h bitmap API
 *
 * Placed in the public domain
 */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ <openssl/bn.h>
#endif

#ଅନ୍ତର୍ଭାଵ "../test_helper/test_helper.h"

#ଅନ୍ତର୍ଭାଵ "bitmap.h"

#define DEFAULT_NTESTS 131

ଶୂନ୍ୟ
tests(ଶୂନ୍ୟ)
{
#ifdef WITH_OPENSSL
	ସଂରଚନା bitmap *b;
	BIGNUM *bn;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, j, k, n, ntests = DEFAULT_NTESTS;
	u_char bbuf[1024], bnbuf[1024];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (test_is_fast())
		ntests /= 4;
	ଅନ୍ୟଥା ଯଦି (test_is_slow())
		ntests *= 2;

	TEST_START("bitmap_new");
	b = bitmap_new();
	ASSERT_PTR_NE(b, ଖାଲି);
	bn = BN_new();
	ASSERT_PTR_NE(bn, ଖାଲି);
	TEST_DONE();

	TEST_START("bitmap_set_bit / bitmap_test_bit");
	ପାଇଁ (i = -1; i < ntests; i++) {
		ପାଇଁ (j = -1; j < ntests; j++) {
			ପାଇଁ (k = -1; k < ntests; k++) {
				bitmap_zero(b);
				BN_clear(bn);

				test_subtest_info("set %d/%d/%d", i, j, k);
				/* Set bits */
				ଯଦି (i >= 0) {
					ASSERT_INT_EQ(bitmap_set_bit(b, i), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, i), 1);
				}
				ଯଦି (j >= 0) {
					ASSERT_INT_EQ(bitmap_set_bit(b, j), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, j), 1);
				}
				ଯଦି (k >= 0) {
					ASSERT_INT_EQ(bitmap_set_bit(b, k), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, k), 1);
				}

				/* Check perfect match between bitmap and bn */
				test_subtest_info("match %d/%d/%d", i, j, k);
				ପାଇଁ (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_bit_set(bn, n),
					    bitmap_test_bit(b, n));
				}

				/* Test length calculations */
				test_subtest_info("length %d/%d/%d", i, j, k);
				ASSERT_INT_EQ(BN_ଅଙ୍କ_bits(bn),
				    (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)bitmap_nbits(b));
				ASSERT_INT_EQ(BN_ଅଙ୍କ_bytes(bn),
				    (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)bitmap_nbytes(b));

				/* Test serialisation */
				test_subtest_info("serialise %d/%d/%d",
				    i, j, k);
				len = bitmap_nbytes(b);
				memset(bbuf, 0xfc, ଆକାର(bbuf));
				ASSERT_INT_EQ(bitmap_to_string(b, bbuf,
				    ଆକାର(bbuf)), 0);
				ପାଇଁ (n = len; n < (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)ଆକାର(bbuf); n++)
					ASSERT_U8_EQ(bbuf[n], 0xfc);
				r = BN_bn2bin(bn, bnbuf);
				ASSERT_INT_GE(r, 0);
				ASSERT_INT_EQ(r, (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)len);
				ASSERT_MEM_EQ(bbuf, bnbuf, len);

				/* Test deserialisation */
				test_subtest_info("deserialise %d/%d/%d",
				    i, j, k);
				bitmap_zero(b);
				ASSERT_INT_EQ(bitmap_from_string(b, bnbuf,
				    len), 0);
				ପାଇଁ (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_bit_set(bn, n),
					    bitmap_test_bit(b, n));
				}

				/* Test clearing bits */
				test_subtest_info("clear %d/%d/%d",
				    i, j, k);
				ପାଇଁ (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(bitmap_set_bit(b, n), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, n), 1);
				}
				ଯଦି (i >= 0) {
					bitmap_clear_bit(b, i);
					BN_clear_bit(bn, i);
				}
				ଯଦି (j >= 0) {
					bitmap_clear_bit(b, j);
					BN_clear_bit(bn, j);
				}
				ଯଦି (k >= 0) {
					bitmap_clear_bit(b, k);
					BN_clear_bit(bn, k);
				}
				ପାଇଁ (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_bit_set(bn, n),
					    bitmap_test_bit(b, n));
				}
			}
		}
	}
	bitmap_free(b);
	BN_free(bn);
	TEST_DONE();
#endif
}

ଶୂନ୍ୟ
benchmarks(ଶୂନ୍ୟ)
{
	printf("no benchmarks\n");
}
