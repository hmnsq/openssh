/* 	$OpenBSD: tests.c,v 1.3 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for bitmap.h bitmap API
 *
 * Placed in the public domain
 */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/bn.h>
#endif

#അന്തര്ഭാവ "../test_helper/test_helper.h"

#അന്തര്ഭാവ "bitmap.h"

#define DEFAULT_NTESTS 131

ശൂന്യം
tests(ശൂന്യം)
{
#ifdef WITH_OPENSSL
	ഘടന bitmap *b;
	BIGNUM *bn;
	size_t len;
	പൂർണ്ണസംഖ്യ i, j, k, n, ntests = DEFAULT_NTESTS;
	u_char bbuf[1024], bnbuf[1024];
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (test_is_fast())
		ntests /= 4;
	അല്ലെങ്കിൽ എങ്കിൽ (test_is_slow())
		ntests *= 2;

	TEST_START("bitmap_new");
	b = bitmap_new();
	ASSERT_PTR_NE(b, ശൂന്യ);
	bn = BN_new();
	ASSERT_PTR_NE(bn, ശൂന്യ);
	TEST_DONE();

	TEST_START("bitmap_set_bit / bitmap_test_bit");
	വേണ്ടി (i = -1; i < ntests; i++) {
		വേണ്ടി (j = -1; j < ntests; j++) {
			വേണ്ടി (k = -1; k < ntests; k++) {
				bitmap_zero(b);
				BN_clear(bn);

				test_subtest_info("set %d/%d/%d", i, j, k);
				/* Set bits */
				എങ്കിൽ (i >= 0) {
					ASSERT_INT_EQ(bitmap_set_bit(b, i), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, i), 1);
				}
				എങ്കിൽ (j >= 0) {
					ASSERT_INT_EQ(bitmap_set_bit(b, j), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, j), 1);
				}
				എങ്കിൽ (k >= 0) {
					ASSERT_INT_EQ(bitmap_set_bit(b, k), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, k), 1);
				}

				/* Check perfect match between bitmap and bn */
				test_subtest_info("match %d/%d/%d", i, j, k);
				വേണ്ടി (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_bit_set(bn, n),
					    bitmap_test_bit(b, n));
				}

				/* Test length calculations */
				test_subtest_info("length %d/%d/%d", i, j, k);
				ASSERT_INT_EQ(BN_അക്കം_bits(bn),
				    (പൂർണ്ണസംഖ്യ)bitmap_nbits(b));
				ASSERT_INT_EQ(BN_അക്കം_bytes(bn),
				    (പൂർണ്ണസംഖ്യ)bitmap_nbytes(b));

				/* Test serialisation */
				test_subtest_info("serialise %d/%d/%d",
				    i, j, k);
				len = bitmap_nbytes(b);
				memset(bbuf, 0xfc, വലുപ്പം(bbuf));
				ASSERT_INT_EQ(bitmap_to_string(b, bbuf,
				    വലുപ്പം(bbuf)), 0);
				വേണ്ടി (n = len; n < (പൂർണ്ണസംഖ്യ)വലുപ്പം(bbuf); n++)
					ASSERT_U8_EQ(bbuf[n], 0xfc);
				r = BN_bn2bin(bn, bnbuf);
				ASSERT_INT_GE(r, 0);
				ASSERT_INT_EQ(r, (പൂർണ്ണസംഖ്യ)len);
				ASSERT_MEM_EQ(bbuf, bnbuf, len);

				/* Test deserialisation */
				test_subtest_info("deserialise %d/%d/%d",
				    i, j, k);
				bitmap_zero(b);
				ASSERT_INT_EQ(bitmap_from_string(b, bnbuf,
				    len), 0);
				വേണ്ടി (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_bit_set(bn, n),
					    bitmap_test_bit(b, n));
				}

				/* Test clearing bits */
				test_subtest_info("clear %d/%d/%d",
				    i, j, k);
				വേണ്ടി (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(bitmap_set_bit(b, n), 0);
					ASSERT_INT_EQ(BN_set_bit(bn, n), 1);
				}
				എങ്കിൽ (i >= 0) {
					bitmap_clear_bit(b, i);
					BN_clear_bit(bn, i);
				}
				എങ്കിൽ (j >= 0) {
					bitmap_clear_bit(b, j);
					BN_clear_bit(bn, j);
				}
				എങ്കിൽ (k >= 0) {
					bitmap_clear_bit(b, k);
					BN_clear_bit(bn, k);
				}
				വേണ്ടി (n = 0; n < ntests; n++) {
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

ശൂന്യം
benchmarks(ശൂന്യം)
{
	printf("no benchmarks\n");
}
