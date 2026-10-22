/* 	$OpenBSD: test_sshbuf_fuzz.c,v 1.5 2026/03/06 06:57:33 dtucker Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਅੰਕ_FUZZ_TESTS (1 << 18)

ਖਾਲੀ sshbuf_fuzz_tests(ਖਾਲੀ);

ਖਾਲੀ
sshbuf_fuzz_tests(ਖਾਲੀ)
{
	ਬਣਤਰ sshbuf *p1;
	u_char *dp;
	ਮਾਪ_t sz, sz2, i, ntests = ਅੰਕ_FUZZ_TESTS;
	uint32_t r;
	ਪੂਰਨ ret;

	ਜੇ (test_is_fast())
		ntests >>= 2;
	ਜੇ (test_is_slow())
		ntests <<= 2;

	/* NB. uses sshbuf internals */
	TEST_ਸ਼ੁਰੂ("fuzz alloc/dealloc");
	p1 = sshbuf_new();
	ASSERT_INT_EQ(sshbuf_ਸੈੱਟ_max_ਮਾਪ(p1, 16 * 1024), 0);
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_PTR_NE(sshbuf_ptr(p1), ਨਿਰਾ);
	ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
	ਲਈ (i = 0; i < ntests; i++) {
		r = arc4random_ਇਕਸਾਰ(10);
		ਜੇ (r == 0) {
			/* 10% chance: small reserve */
			r = arc4random_ਇਕਸਾਰ(10);
 fuzz_reserve:
			sz = sshbuf_avail(p1);
			sz2 = sshbuf_len(p1);
			ret = sshbuf_reserve(p1, r, &dp);
			ਜੇ (ret < 0) {
				ASSERT_PTR_EQ(dp, ਨਿਰਾ);
				ASSERT_ਮਾਪ_T_LT(sz, r);
				ASSERT_ਮਾਪ_T_EQ(sshbuf_avail(p1), sz);
				ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), sz2);
			} ਨਹੀਂਤਾਂ {
				ASSERT_PTR_NE(dp, ਨਿਰਾ);
				ASSERT_ਮਾਪ_T_GE(sz, r);
				ASSERT_ਮਾਪ_T_EQ(sshbuf_avail(p1), sz - r);
				ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), sz2 + r);
				memset(dp, arc4random_ਇਕਸਾਰ(255) + 1, r);
			}
		} ਨਹੀਂਤਾਂ ਜੇ (r < 3) {
			/* 20% chance: big reserve */
			r = arc4random_ਇਕਸਾਰ(8 * 1024);
			ਜਾਓ fuzz_reserve;
		} ਨਹੀਂਤਾਂ ਜੇ (r == 3) {
			/* 10% chance: small consume */
			r = arc4random_ਇਕਸਾਰ(10);
 fuzz_consume:
			sz = sshbuf_avail(p1);
			sz2 = sshbuf_len(p1);
			/* 50% change consume from end, otherwise start */
			ret = ((arc4random() & 1) ?
			    sshbuf_consume : sshbuf_consume_ਸਿਰਾ)(p1, r);
			ਜੇ (ret < 0) {
				ASSERT_ਮਾਪ_T_LT(sz2, r);
				ASSERT_ਮਾਪ_T_EQ(sshbuf_avail(p1), sz);
				ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), sz2);
			} ਨਹੀਂਤਾਂ {
				ASSERT_ਮਾਪ_T_GE(sz2, r);
				ASSERT_ਮਾਪ_T_EQ(sshbuf_avail(p1), sz + r);
				ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), sz2 - r);
			}
		} ਨਹੀਂਤਾਂ ਜੇ (r < 8) {
			/* 40% chance: big consume */
			r = arc4random_ਇਕਸਾਰ(2 * 1024);
			ਜਾਓ fuzz_consume;
		} ਨਹੀਂਤਾਂ ਜੇ (r == 8) {
			/* 10% chance: reset max size */
			r = arc4random_ਇਕਸਾਰ(16 * 1024);
			sz = sshbuf_max_ਮਾਪ(p1);
			ਜੇ (sshbuf_ਸੈੱਟ_max_ਮਾਪ(p1, r) < 0)
				ASSERT_ਮਾਪ_T_EQ(sshbuf_max_ਮਾਪ(p1), sz);
			ਨਹੀਂਤਾਂ
				ASSERT_ਮਾਪ_T_EQ(sshbuf_max_ਮਾਪ(p1), r);
		} ਨਹੀਂਤਾਂ {
			ਜੇ (arc4random_ਇਕਸਾਰ(8192) == 0) {
				/* tiny chance: new buffer */
				ASSERT_PTR_NE(sshbuf_ptr(p1), ਨਿਰਾ);
				ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
				sshbuf_free(p1);
				p1 = sshbuf_new();
				ASSERT_PTR_NE(p1, ਨਿਰਾ);
				ASSERT_INT_EQ(sshbuf_ਸੈੱਟ_max_ਮਾਪ(p1,
				    16 * 1024), 0);
			} ਨਹੀਂਤਾਂ {
				/* Almost 10%: giant reserve */
				/* use arc4random_buf for r > 2^32 on 64 bit */
				arc4random_buf(&r, ਆਕਾਰ(r));
				ਜਦੋਂ (r < SSHBUF_ਮਾਪ_MAX / 2) {
					r <<= 1;
					r |= arc4random() & 1;
				}
				ਜਾਓ fuzz_reserve;
			}
		}
		ASSERT_PTR_NE(sshbuf_ptr(p1), ਨਿਰਾ);
		ASSERT_ਮਾਪ_T_LE(sshbuf_max_ਮਾਪ(p1), 16 * 1024);
	}
	ASSERT_PTR_NE(sshbuf_ptr(p1), ਨਿਰਾ);
	ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();
}
