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

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/bn.h>
#اگر_ختم

#شامل "../test_helper/test_helper.h"

#شامل "bitmap.h"

#تعریف_کرو DEFAULT_NTESTS 131

خالی
tests(خالی)
{
#اگر_تعریف_شدہ WITH_OPENSSL
	ساخت bitmap *b;
	BIGNUM *bn;
	سائز_t len;
	صحیح i, j, k, n, ntests = DEFAULT_NTESTS;
	u_char bbuf[1024], bnbuf[1024];
	صحیح r;

	اگر (test_is_fast())
		ntests /= 4;
	ورنہ اگر (test_is_slow())
		ntests *= 2;

	TEST_آغاز("bitmap_new");
	b = bitmap_new();
	ASSERT_PTR_NE(b, تہی);
	bn = BN_new();
	ASSERT_PTR_NE(bn, تہی);
	TEST_مکمل();

	TEST_آغاز("bitmap_set_bit / bitmap_test_bit");
	برائے (i = -1; i < ntests; i++) {
		برائے (j = -1; j < ntests; j++) {
			برائے (k = -1; k < ntests; k++) {
				bitmap_zero(b);
				BN_clear(bn);

				test_subtest_info("set %d/%d/%d", i, j, k);
				/* Set bits */
				اگر (i >= 0) {
					ASSERT_INT_EQ(bitmap_سیٹ_ثنائی_ہندسہ(b, i), 0);
					ASSERT_INT_EQ(BN_سیٹ_ثنائی_ہندسہ(bn, i), 1);
				}
				اگر (j >= 0) {
					ASSERT_INT_EQ(bitmap_سیٹ_ثنائی_ہندسہ(b, j), 0);
					ASSERT_INT_EQ(BN_سیٹ_ثنائی_ہندسہ(bn, j), 1);
				}
				اگر (k >= 0) {
					ASSERT_INT_EQ(bitmap_سیٹ_ثنائی_ہندسہ(b, k), 0);
					ASSERT_INT_EQ(BN_سیٹ_ثنائی_ہندسہ(bn, k), 1);
				}

				/* Check perfect match between bitmap and bn */
				test_subtest_info("match %d/%d/%d", i, j, k);
				برائے (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_ثنائی_ہندسہ_سیٹ(bn, n),
					    bitmap_test_ثنائی_ہندسہ(b, n));
				}

				/* Test length calculations */
				test_subtest_info("length %d/%d/%d", i, j, k);
				ASSERT_INT_EQ(BN_عدد_بٹ(bn),
				    (صحیح)bitmap_nbits(b));
				ASSERT_INT_EQ(BN_عدد_بائٹیں(bn),
				    (صحیح)bitmap_nbytes(b));

				/* Test serialisation */
				test_subtest_info("serialise %d/%d/%d",
				    i, j, k);
				len = bitmap_nbytes(b);
				memset(bbuf, 0xfc, حجم(bbuf));
				ASSERT_INT_EQ(bitmap_مقصد_string(b, bbuf,
				    حجم(bbuf)), 0);
				برائے (n = len; n < (صحیح)حجم(bbuf); n++)
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
				برائے (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_ثنائی_ہندسہ_سیٹ(bn, n),
					    bitmap_test_ثنائی_ہندسہ(b, n));
				}

				/* Test clearing bits */
				test_subtest_info("clear %d/%d/%d",
				    i, j, k);
				برائے (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(bitmap_سیٹ_ثنائی_ہندسہ(b, n), 0);
					ASSERT_INT_EQ(BN_سیٹ_ثنائی_ہندسہ(bn, n), 1);
				}
				اگر (i >= 0) {
					bitmap_clear_ثنائی_ہندسہ(b, i);
					BN_clear_ثنائی_ہندسہ(bn, i);
				}
				اگر (j >= 0) {
					bitmap_clear_ثنائی_ہندسہ(b, j);
					BN_clear_ثنائی_ہندسہ(bn, j);
				}
				اگر (k >= 0) {
					bitmap_clear_ثنائی_ہندسہ(b, k);
					BN_clear_ثنائی_ہندسہ(bn, k);
				}
				برائے (n = 0; n < ntests; n++) {
					ASSERT_INT_EQ(BN_is_ثنائی_ہندسہ_سیٹ(bn, n),
					    bitmap_test_ثنائی_ہندسہ(b, n));
				}
			}
		}
	}
	bitmap_free(b);
	BN_free(bn);
	TEST_مکمل();
#اگر_ختم
}

خالی
benchmarks(خالی)
{
	لکھو("no benchmarks\n");
}
