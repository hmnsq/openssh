/* 	$OpenBSD: tests.c,v 1.3 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for bitmap.h bitmap API
 *
 * Placed in the public domain
 */

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

#ifdef WITH_OPENSSL
#شامل <openssl/bn.h>
#endif

#شامل "../test_helper/test_helper.h"

#شامل "bitmap.h"

#define DEFAULT_NTESTS 131

تهی
tests(تهی)
{
#ifdef WITH_OPENSSL
	ساختار bitmap *b;
	BIGNUM *bn;
	size_t len;
	صحیح i, j, k, n, ntests = DEFAULT_NTESTS;
	u_char bbuf[1024], bnbuf[1024];
	صحیح r;

	اگر (test_is_fast())
		ntests /= 4;
	وگرنه اگر (test_is_slow())
		ntests *= 2;

	TEST_START("bitmap_new");
	b = bitmap_new();
	ASSERT_PTR_NE(b, پوچ);
	bn = BN_new();
	ASSERT_PTR_NE(bn, پوچ);
	TEST_DONE();

	TEST_START("bitmap_set_bit / bitmap_test_bit");
	برای (i = -1; i < ntests; i++) {
		برای (j = -1; j < ntests; j++) {
			برای (k = -1; k < ntests; k++) {
				bitmap_zero(b);
				BN_clear(bn);

				test_subtest_info("set %d/%d/%d", i, j, k);
				/* Set bits */
				اگر (i >= 0) {
					ASSERT_INT_EQ(bitmap_set_bit(b, i), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, i), 1);
				}
				اگر (j >= 0) {
					ASSERT_INT_EQ(bitmap_set_bit(b, j), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, j), 1);
				}
				اگر (k >= 0) {
					ASSERT_INT_EQ(bitmap_set_bit(b, k), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, k), 1);
				}

				/* Check perfect match between bitmap and bn */
				test_subtest_info("match %d/%d/%d", i, j, k);
				برای (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_bit_set(bn, n),
					    bitmap_test_bit(b, n));
				}

				/* Test length calculations */
				test_subtest_info("length %d/%d/%d", i, j, k);
				ASSERT_INT_EQ(BN_رقم_bits(bn),
				    (صحیح)bitmap_nbits(b));
				ASSERT_INT_EQ(BN_رقم_bytes(bn),
				    (صحیح)bitmap_nbytes(b));

				/* Test serialisation */
				test_subtest_info("serialise %d/%d/%d",
				    i, j, k);
				len = bitmap_nbytes(b);
				memset(bbuf, 0xfc, اندازه(bbuf));
				ASSERT_INT_EQ(bitmap_to_string(b, bbuf,
				    اندازه(bbuf)), 0);
				برای (n = len; n < (صحیح)اندازه(bbuf); n++)
					ASSERT_U8_EQ(bbuf[n], 0xfc);
				r = BN_bn2bin(bn, bnbuf);
				ASSERT_INT_GE(r, 0);
				ASSERT_INT_EQ(r, (صحیح)len);
				ASSERT_MEM_EQ(bbuf, bnbuf, len);

				/* Test deserialisation */
				test_subtest_info("deserialise %d/%d/%d",
				    i, j, k);
				bitmap_zero(b);
				ASSERT_INT_EQ(bitmap_from_string(b, bnbuf,
				    len), 0);
				برای (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_bit_set(bn, n),
					    bitmap_test_bit(b, n));
				}

				/* Test clearing bits */
				test_subtest_info("clear %d/%d/%d",
				    i, j, k);
				برای (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(bitmap_set_bit(b, n), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, n), 1);
				}
				اگر (i >= 0) {
					bitmap_clear_bit(b, i);
					BN_clear_bit(bn, i);
				}
				اگر (j >= 0) {
					bitmap_clear_bit(b, j);
					BN_clear_bit(bn, j);
				}
				اگر (k >= 0) {
					bitmap_clear_bit(b, k);
					BN_clear_bit(bn, k);
				}
				برای (n = 0; n < ntests; n++) {
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

تهی
benchmarks(تهی)
{
	printf("no benchmarks\n");
}
