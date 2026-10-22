/* 	$OpenBSD: tests.c,v 1.3 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for bitmap.h bitmap API
 *
 * Placed in the public domain
 */

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/bn.h>
#endif

#અન્તર્ભાવ "../test_helper/test_helper.h"

#અન્તર્ભાવ "bitmap.h"

#define DEFAULT_NTESTS 131

શૂન્ય
tests(શૂન્ય)
{
#ifdef WITH_OPENSSL
	સંરચના bitmap *b;
	BIGNUM *bn;
	size_t len;
	પૂર્ણાંક i, j, k, n, ntests = DEFAULT_NTESTS;
	u_char bbuf[1024], bnbuf[1024];
	પૂર્ણાંક r;

	જો (test_is_fast())
		ntests /= 4;
	નહીંતર જો (test_is_slow())
		ntests *= 2;

	TEST_START("bitmap_new");
	b = bitmap_new();
	ASSERT_PTR_NE(b, ખાલી);
	bn = BN_new();
	ASSERT_PTR_NE(bn, ખાલી);
	TEST_DONE();

	TEST_START("bitmap_set_bit / bitmap_test_bit");
	માટે (i = -1; i < ntests; i++) {
		માટે (j = -1; j < ntests; j++) {
			માટે (k = -1; k < ntests; k++) {
				bitmap_zero(b);
				BN_clear(bn);

				test_subtest_info("set %d/%d/%d", i, j, k);
				/* Set bits */
				જો (i >= 0) {
					ASSERT_INT_EQ(bitmap_set_bit(b, i), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, i), 1);
				}
				જો (j >= 0) {
					ASSERT_INT_EQ(bitmap_set_bit(b, j), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, j), 1);
				}
				જો (k >= 0) {
					ASSERT_INT_EQ(bitmap_set_bit(b, k), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, k), 1);
				}

				/* Check perfect match between bitmap and bn */
				test_subtest_info("match %d/%d/%d", i, j, k);
				માટે (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_bit_set(bn, n),
					    bitmap_test_bit(b, n));
				}

				/* Test length calculations */
				test_subtest_info("length %d/%d/%d", i, j, k);
				ASSERT_INT_EQ(BN_અંક_bits(bn),
				    (પૂર્ણાંક)bitmap_nbits(b));
				ASSERT_INT_EQ(BN_અંક_bytes(bn),
				    (પૂર્ણાંક)bitmap_nbytes(b));

				/* Test serialisation */
				test_subtest_info("serialise %d/%d/%d",
				    i, j, k);
				len = bitmap_nbytes(b);
				memset(bbuf, 0xfc, કદ(bbuf));
				ASSERT_INT_EQ(bitmap_to_string(b, bbuf,
				    કદ(bbuf)), 0);
				માટે (n = len; n < (પૂર્ણાંક)કદ(bbuf); n++)
					ASSERT_U8_EQ(bbuf[n], 0xfc);
				r = BN_bn2bin(bn, bnbuf);
				ASSERT_INT_GE(r, 0);
				ASSERT_INT_EQ(r, (પૂર્ણાંક)len);
				ASSERT_MEM_EQ(bbuf, bnbuf, len);

				/* Test deserialisation */
				test_subtest_info("deserialise %d/%d/%d",
				    i, j, k);
				bitmap_zero(b);
				ASSERT_INT_EQ(bitmap_from_string(b, bnbuf,
				    len), 0);
				માટે (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_bit_set(bn, n),
					    bitmap_test_bit(b, n));
				}

				/* Test clearing bits */
				test_subtest_info("clear %d/%d/%d",
				    i, j, k);
				માટે (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(bitmap_set_bit(b, n), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, n), 1);
				}
				જો (i >= 0) {
					bitmap_clear_bit(b, i);
					BN_clear_bit(bn, i);
				}
				જો (j >= 0) {
					bitmap_clear_bit(b, j);
					BN_clear_bit(bn, j);
				}
				જો (k >= 0) {
					bitmap_clear_bit(b, k);
					BN_clear_bit(bn, k);
				}
				માટે (n = 0; n < ntests; n++) {
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

શૂન્ય
benchmarks(શૂન્ય)
{
	printf("no benchmarks\n");
}
