/* 	$OpenBSD: tests.c,v 1.3 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for bitmap.h bitmap API
 *
 * Placed in the public domain
 */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/bn.h>
#endif

#அந்தர்பாவ "../test_helper/test_helper.h"

#அந்தர்பாவ "bitmap.h"

#define DEFAULT_NTESTS 131

வெறுமை
tests(வெறுமை)
{
#ifdef WITH_OPENSSL
	கட்டமைப்பு bitmap *b;
	BIGNUM *bn;
	size_t len;
	முழு i, j, k, n, ntests = DEFAULT_NTESTS;
	u_char bbuf[1024], bnbuf[1024];
	முழு r;

	எனில் (test_is_fast())
		ntests /= 4;
	இல்லையெனில் எனில் (test_is_slow())
		ntests *= 2;

	TEST_START("bitmap_new");
	b = bitmap_new();
	ASSERT_PTR_NE(b, வெற்று);
	bn = BN_new();
	ASSERT_PTR_NE(bn, வெற்று);
	TEST_DONE();

	TEST_START("bitmap_set_bit / bitmap_test_bit");
	க்கு (i = -1; i < ntests; i++) {
		க்கு (j = -1; j < ntests; j++) {
			க்கு (k = -1; k < ntests; k++) {
				bitmap_zero(b);
				BN_clear(bn);

				test_subtest_info("set %d/%d/%d", i, j, k);
				/* Set bits */
				எனில் (i >= 0) {
					ASSERT_INT_EQ(bitmap_set_bit(b, i), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, i), 1);
				}
				எனில் (j >= 0) {
					ASSERT_INT_EQ(bitmap_set_bit(b, j), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, j), 1);
				}
				எனில் (k >= 0) {
					ASSERT_INT_EQ(bitmap_set_bit(b, k), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, k), 1);
				}

				/* Check perfect match between bitmap and bn */
				test_subtest_info("match %d/%d/%d", i, j, k);
				க்கு (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_bit_set(bn, n),
					    bitmap_test_bit(b, n));
				}

				/* Test length calculations */
				test_subtest_info("length %d/%d/%d", i, j, k);
				ASSERT_INT_EQ(BN_இலக்கம்_bits(bn),
				    (முழு)bitmap_nbits(b));
				ASSERT_INT_EQ(BN_இலக்கம்_bytes(bn),
				    (முழு)bitmap_nbytes(b));

				/* Test serialisation */
				test_subtest_info("serialise %d/%d/%d",
				    i, j, k);
				len = bitmap_nbytes(b);
				memset(bbuf, 0xfc, அளவு(bbuf));
				ASSERT_INT_EQ(bitmap_to_string(b, bbuf,
				    அளவு(bbuf)), 0);
				க்கு (n = len; n < (முழு)அளவு(bbuf); n++)
					ASSERT_U8_EQ(bbuf[n], 0xfc);
				r = BN_bn2bin(bn, bnbuf);
				ASSERT_INT_GE(r, 0);
				ASSERT_INT_EQ(r, (முழு)len);
				ASSERT_MEM_EQ(bbuf, bnbuf, len);

				/* Test deserialisation */
				test_subtest_info("deserialise %d/%d/%d",
				    i, j, k);
				bitmap_zero(b);
				ASSERT_INT_EQ(bitmap_from_string(b, bnbuf,
				    len), 0);
				க்கு (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_bit_set(bn, n),
					    bitmap_test_bit(b, n));
				}

				/* Test clearing bits */
				test_subtest_info("clear %d/%d/%d",
				    i, j, k);
				க்கு (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(bitmap_set_bit(b, n), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, n), 1);
				}
				எனில் (i >= 0) {
					bitmap_clear_bit(b, i);
					BN_clear_bit(bn, i);
				}
				எனில் (j >= 0) {
					bitmap_clear_bit(b, j);
					BN_clear_bit(bn, j);
				}
				எனில் (k >= 0) {
					bitmap_clear_bit(b, k);
					BN_clear_bit(bn, k);
				}
				க்கு (n = 0; n < ntests; n++) {
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

வெறுமை
benchmarks(வெறுமை)
{
	printf("no benchmarks\n");
}
