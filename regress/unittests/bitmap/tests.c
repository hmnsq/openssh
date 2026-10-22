/* 	$OpenBSD: tests.c,v 1.3 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for bitmap.h bitmap API
 *
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#endif

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

#ಅನ್ತರ್ಭಾವ "bitmap.h"

#define DEFAULT_NTESTS 131

ಶೂನ್ಯ
tests(ಶೂನ್ಯ)
{
#ifdef WITH_OPENSSL
	ಸಂರಚನಾ bitmap *b;
	BIGNUM *bn;
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ i, j, k, n, ntests = DEFAULT_NTESTS;
	u_char bbuf[1024], bnbuf[1024];
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (test_is_fast())
		ntests /= 4;
	ಅನ್ಯಥಾ ಯದಿ (test_is_slow())
		ntests *= 2;

	TEST_START("bitmap_new");
	b = bitmap_new();
	ASSERT_PTR_NE(b, ರಿಕ್ತ);
	bn = BN_new();
	ASSERT_PTR_NE(bn, ರಿಕ್ತ);
	TEST_DONE();

	TEST_START("bitmap_set_bit / bitmap_test_bit");
	ಪ್ರತಿ (i = -1; i < ntests; i++) {
		ಪ್ರತಿ (j = -1; j < ntests; j++) {
			ಪ್ರತಿ (k = -1; k < ntests; k++) {
				bitmap_zero(b);
				BN_clear(bn);

				test_subtest_info("set %d/%d/%d", i, j, k);
				/* Set bits */
				ಯದಿ (i >= 0) {
					ASSERT_INT_EQ(bitmap_set_bit(b, i), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, i), 1);
				}
				ಯದಿ (j >= 0) {
					ASSERT_INT_EQ(bitmap_set_bit(b, j), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, j), 1);
				}
				ಯದಿ (k >= 0) {
					ASSERT_INT_EQ(bitmap_set_bit(b, k), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, k), 1);
				}

				/* Check perfect match between bitmap and bn */
				test_subtest_info("match %d/%d/%d", i, j, k);
				ಪ್ರತಿ (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_bit_set(bn, n),
					    bitmap_test_bit(b, n));
				}

				/* Test length calculations */
				test_subtest_info("length %d/%d/%d", i, j, k);
				ASSERT_INT_EQ(BN_ಅಂಕೆ_bits(bn),
				    (ಪೂರ್ಣಾಙ್ಕ)bitmap_nbits(b));
				ASSERT_INT_EQ(BN_ಅಂಕೆ_bytes(bn),
				    (ಪೂರ್ಣಾಙ್ಕ)bitmap_nbytes(b));

				/* Test serialisation */
				test_subtest_info("serialise %d/%d/%d",
				    i, j, k);
				len = bitmap_nbytes(b);
				memset(bbuf, 0xfc, ಪರಿಮಾಣ(bbuf));
				ASSERT_INT_EQ(bitmap_to_string(b, bbuf,
				    ಪರಿಮಾಣ(bbuf)), 0);
				ಪ್ರತಿ (n = len; n < (ಪೂರ್ಣಾಙ್ಕ)ಪರಿಮಾಣ(bbuf); n++)
					ASSERT_U8_EQ(bbuf[n], 0xfc);
				r = BN_bn2bin(bn, bnbuf);
				ASSERT_INT_GE(r, 0);
				ASSERT_INT_EQ(r, (ಪೂರ್ಣಾಙ್ಕ)len);
				ASSERT_MEM_EQ(bbuf, bnbuf, len);

				/* Test deserialisation */
				test_subtest_info("deserialise %d/%d/%d",
				    i, j, k);
				bitmap_zero(b);
				ASSERT_INT_EQ(bitmap_from_string(b, bnbuf,
				    len), 0);
				ಪ್ರತಿ (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_bit_set(bn, n),
					    bitmap_test_bit(b, n));
				}

				/* Test clearing bits */
				test_subtest_info("clear %d/%d/%d",
				    i, j, k);
				ಪ್ರತಿ (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(bitmap_set_bit(b, n), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, n), 1);
				}
				ಯದಿ (i >= 0) {
					bitmap_clear_bit(b, i);
					BN_clear_bit(bn, i);
				}
				ಯದಿ (j >= 0) {
					bitmap_clear_bit(b, j);
					BN_clear_bit(bn, j);
				}
				ಯದಿ (k >= 0) {
					bitmap_clear_bit(b, k);
					BN_clear_bit(bn, k);
				}
				ಪ್ರತಿ (n = 0; n < ntests; n++) {
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

ಶೂನ್ಯ
benchmarks(ಶೂನ್ಯ)
{
	printf("no benchmarks\n");
}
