/* 	$OpenBSD: tests.c,v 1.3 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for bitmap.h bitmap API
 *
 * Placed in the public domain
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "bitmap.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DEFAULT_NTESTS 131

ਖਾਲੀ
tests(ਖਾਲੀ)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਬਣਤਰ bitmap *b;
	BIGNUM *bn;
	ਮਾਪ_t len;
	ਪੂਰਨ i, j, k, n, ntests = DEFAULT_NTESTS;
	u_char bbuf[1024], bnbuf[1024];
	ਪੂਰਨ r;

	ਜੇ (test_is_fast())
		ntests /= 4;
	ਨਹੀਂਤਾਂ ਜੇ (test_is_slow())
		ntests *= 2;

	TEST_ਸ਼ੁਰੂ("bitmap_new");
	b = bitmap_new();
	ASSERT_PTR_NE(b, ਨਿਰਾ);
	bn = BN_new();
	ASSERT_PTR_NE(bn, ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("bitmap_set_bit / bitmap_test_bit");
	ਲਈ (i = -1; i < ntests; i++) {
		ਲਈ (j = -1; j < ntests; j++) {
			ਲਈ (k = -1; k < ntests; k++) {
				bitmap_zero(b);
				BN_clear(bn);

				test_subtest_info("set %d/%d/%d", i, j, k);
				/* Set bits */
				ਜੇ (i >= 0) {
					ASSERT_INT_EQ(bitmap_ਸੈੱਟ_ਦੋਆਧਾਰੀ_ਅੰਕ(b, i), 0);
					ASSERT_INT_EQ(BN_ਸੈੱਟ_ਦੋਆਧਾਰੀ_ਅੰਕ(bn, i), 1);
				}
				ਜੇ (j >= 0) {
					ASSERT_INT_EQ(bitmap_ਸੈੱਟ_ਦੋਆਧਾਰੀ_ਅੰਕ(b, j), 0);
					ASSERT_INT_EQ(BN_ਸੈੱਟ_ਦੋਆਧਾਰੀ_ਅੰਕ(bn, j), 1);
				}
				ਜੇ (k >= 0) {
					ASSERT_INT_EQ(bitmap_ਸੈੱਟ_ਦੋਆਧਾਰੀ_ਅੰਕ(b, k), 0);
					ASSERT_INT_EQ(BN_ਸੈੱਟ_ਦੋਆਧਾਰੀ_ਅੰਕ(bn, k), 1);
				}

				/* Check perfect match between bitmap and bn */
				test_subtest_info("match %d/%d/%d", i, j, k);
				ਲਈ (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_ਦੋਆਧਾਰੀ_ਅੰਕ_ਸੈੱਟ(bn, n),
					    bitmap_test_ਦੋਆਧਾਰੀ_ਅੰਕ(b, n));
				}

				/* Test length calculations */
				test_subtest_info("length %d/%d/%d", i, j, k);
				ASSERT_INT_EQ(BN_ਅੰਕ_ਬਿੱਟ(bn),
				    (ਪੂਰਨ)bitmap_nbits(b));
				ASSERT_INT_EQ(BN_ਅੰਕ_ਬਾਈਟਾਂ(bn),
				    (ਪੂਰਨ)bitmap_nbytes(b));

				/* Test serialisation */
				test_subtest_info("serialise %d/%d/%d",
				    i, j, k);
				len = bitmap_nbytes(b);
				memset(bbuf, 0xfc, ਆਕਾਰ(bbuf));
				ASSERT_INT_EQ(bitmap_ਮੰਜ਼ਿਲ_string(b, bbuf,
				    ਆਕਾਰ(bbuf)), 0);
				ਲਈ (n = len; n < (ਪੂਰਨ)ਆਕਾਰ(bbuf); n++)
					ASSERT_U8_EQ(bbuf[n], 0xfc);
				r = BN_bn2bin(bn, bnbuf);
				ASSERT_INT_GE(r, 0);
				ASSERT_INT_EQ(r, (ਪੂਰਨ)len);
				ASSERT_MEM_EQ(bbuf, bnbuf, len);

				/* Test deserialisation */
				test_subtest_info("deserialise %d/%d/%d",
				    i, j, k);
				bitmap_zero(b);
				ASSERT_INT_EQ(bitmap_from_string(b, bnbuf,
				    len), 0);
				ਲਈ (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_ਦੋਆਧਾਰੀ_ਅੰਕ_ਸੈੱਟ(bn, n),
					    bitmap_test_ਦੋਆਧਾਰੀ_ਅੰਕ(b, n));
				}

				/* Test clearing bits */
				test_subtest_info("clear %d/%d/%d",
				    i, j, k);
				ਲਈ (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(bitmap_ਸੈੱਟ_ਦੋਆਧਾਰੀ_ਅੰਕ(b, n), 0);
					ASSERT_INT_EQ(BN_ਸੈੱਟ_ਦੋਆਧਾਰੀ_ਅੰਕ(bn, n), 1);
				}
				ਜੇ (i >= 0) {
					bitmap_clear_ਦੋਆਧਾਰੀ_ਅੰਕ(b, i);
					BN_clear_ਦੋਆਧਾਰੀ_ਅੰਕ(bn, i);
				}
				ਜੇ (j >= 0) {
					bitmap_clear_ਦੋਆਧਾਰੀ_ਅੰਕ(b, j);
					BN_clear_ਦੋਆਧਾਰੀ_ਅੰਕ(bn, j);
				}
				ਜੇ (k >= 0) {
					bitmap_clear_ਦੋਆਧਾਰੀ_ਅੰਕ(b, k);
					BN_clear_ਦੋਆਧਾਰੀ_ਅੰਕ(bn, k);
				}
				ਲਈ (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_ਦੋਆਧਾਰੀ_ਅੰਕ_ਸੈੱਟ(bn, n),
					    bitmap_test_ਦੋਆਧਾਰੀ_ਅੰਕ(b, n));
				}
			}
		}
	}
	bitmap_free(b);
	BN_free(bn);
	TEST_ਪੂਰਾ();
#ਜੇ_ਅੰਤ
}

ਖਾਲੀ
benchmarks(ਖਾਲੀ)
{
	ਲਿਖੋ("no benchmarks\n");
}
