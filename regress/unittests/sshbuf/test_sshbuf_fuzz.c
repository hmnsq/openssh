/* 	$OpenBSD: test_sshbuf_fuzz.c,v 1.5 2026/03/06 06:57:33 dtucker Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

#شامل "../test_helper/test_helper.h"

#شامل "ssherr.h"
#شامل "sshbuf.h"

#تعریف_کرو عدد_FUZZ_TESTS (1 << 18)

خالی sshbuf_fuzz_tests(خالی);

خالی
sshbuf_fuzz_tests(خالی)
{
	ساخت sshbuf *p1;
	u_char *dp;
	سائز_t sz, sz2, i, ntests = عدد_FUZZ_TESTS;
	uint32_t r;
	صحیح ret;

	اگر (test_is_fast())
		ntests >>= 2;
	اگر (test_is_slow())
		ntests <<= 2;

	/* NB. uses sshbuf internals */
	TEST_آغاز("fuzz alloc/dealloc");
	p1 = sshbuf_new();
	ASSERT_INT_EQ(sshbuf_سیٹ_max_سائز(p1, 16 * 1024), 0);
	ASSERT_PTR_NE(p1, تہی);
	ASSERT_PTR_NE(sshbuf_ptr(p1), تہی);
	ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
	برائے (i = 0; i < ntests; i++) {
		r = arc4random_یکساں(10);
		اگر (r == 0) {
			/* 10% chance: small reserve */
			r = arc4random_یکساں(10);
 fuzz_reserve:
			sz = sshbuf_avail(p1);
			sz2 = sshbuf_len(p1);
			ret = sshbuf_reserve(p1, r, &dp);
			اگر (ret < 0) {
				ASSERT_PTR_EQ(dp, تہی);
				ASSERT_سائز_T_LT(sz, r);
				ASSERT_سائز_T_EQ(sshbuf_avail(p1), sz);
				ASSERT_سائز_T_EQ(sshbuf_len(p1), sz2);
			} ورنہ {
				ASSERT_PTR_NE(dp, تہی);
				ASSERT_سائز_T_GE(sz, r);
				ASSERT_سائز_T_EQ(sshbuf_avail(p1), sz - r);
				ASSERT_سائز_T_EQ(sshbuf_len(p1), sz2 + r);
				memset(dp, arc4random_یکساں(255) + 1, r);
			}
		} ورنہ اگر (r < 3) {
			/* 20% chance: big reserve */
			r = arc4random_یکساں(8 * 1024);
			جاؤ fuzz_reserve;
		} ورنہ اگر (r == 3) {
			/* 10% chance: small consume */
			r = arc4random_یکساں(10);
 fuzz_consume:
			sz = sshbuf_avail(p1);
			sz2 = sshbuf_len(p1);
			/* 50% change consume from end, otherwise start */
			ret = ((arc4random() & 1) ?
			    sshbuf_consume : sshbuf_consume_انتہا)(p1, r);
			اگر (ret < 0) {
				ASSERT_سائز_T_LT(sz2, r);
				ASSERT_سائز_T_EQ(sshbuf_avail(p1), sz);
				ASSERT_سائز_T_EQ(sshbuf_len(p1), sz2);
			} ورنہ {
				ASSERT_سائز_T_GE(sz2, r);
				ASSERT_سائز_T_EQ(sshbuf_avail(p1), sz + r);
				ASSERT_سائز_T_EQ(sshbuf_len(p1), sz2 - r);
			}
		} ورنہ اگر (r < 8) {
			/* 40% chance: big consume */
			r = arc4random_یکساں(2 * 1024);
			جاؤ fuzz_consume;
		} ورنہ اگر (r == 8) {
			/* 10% chance: reset max size */
			r = arc4random_یکساں(16 * 1024);
			sz = sshbuf_max_سائز(p1);
			اگر (sshbuf_سیٹ_max_سائز(p1, r) < 0)
				ASSERT_سائز_T_EQ(sshbuf_max_سائز(p1), sz);
			ورنہ
				ASSERT_سائز_T_EQ(sshbuf_max_سائز(p1), r);
		} ورنہ {
			اگر (arc4random_یکساں(8192) == 0) {
				/* tiny chance: new buffer */
				ASSERT_PTR_NE(sshbuf_ptr(p1), تہی);
				ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
				sshbuf_free(p1);
				p1 = sshbuf_new();
				ASSERT_PTR_NE(p1, تہی);
				ASSERT_INT_EQ(sshbuf_سیٹ_max_سائز(p1,
				    16 * 1024), 0);
			} ورنہ {
				/* Almost 10%: giant reserve */
				/* use arc4random_buf for r > 2^32 on 64 bit */
				arc4random_buf(&r, حجم(r));
				جب (r < SSHBUF_سائز_MAX / 2) {
					r <<= 1;
					r |= arc4random() & 1;
				}
				جاؤ fuzz_reserve;
			}
		}
		ASSERT_PTR_NE(sshbuf_ptr(p1), تہی);
		ASSERT_سائز_T_LE(sshbuf_max_سائز(p1), 16 * 1024);
	}
	ASSERT_PTR_NE(sshbuf_ptr(p1), تہی);
	ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
	sshbuf_free(p1);
	TEST_مکمل();
}
