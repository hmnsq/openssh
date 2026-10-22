/* 	$OpenBSD: test_sshbuf_fuzz.c,v 1.5 2026/03/06 06:57:33 dtucker Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "../test_helper/test_helper.h"

#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sshbuf.h"

#define இலக்கம்_FUZZ_TESTS (1 << 18)

வெறுமை sshbuf_fuzz_tests(வெறுமை);

வெறுமை
sshbuf_fuzz_tests(வெறுமை)
{
	கட்டமைப்பு sshbuf *p1;
	u_char *dp;
	size_t sz, sz2, i, ntests = இலக்கம்_FUZZ_TESTS;
	uint32_t r;
	முழு ret;

	எனில் (test_is_fast())
		ntests >>= 2;
	எனில் (test_is_slow())
		ntests <<= 2;

	/* NB. uses sshbuf internals */
	TEST_START("fuzz alloc/dealloc");
	p1 = sshbuf_new();
	ASSERT_INT_EQ(sshbuf_set_max_size(p1, 16 * 1024), 0);
	ASSERT_PTR_NE(p1, வெற்று);
	ASSERT_PTR_NE(sshbuf_ptr(p1), வெற்று);
	ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
	க்கு (i = 0; i < ntests; i++) {
		r = arc4random_uniform(10);
		எனில் (r == 0) {
			/* 10% chance: small reserve */
			r = arc4random_uniform(10);
 fuzz_reserve:
			sz = sshbuf_avail(p1);
			sz2 = sshbuf_len(p1);
			ret = sshbuf_reserve(p1, r, &dp);
			எனில் (ret < 0) {
				ASSERT_PTR_EQ(dp, வெற்று);
				ASSERT_SIZE_T_LT(sz, r);
				ASSERT_SIZE_T_EQ(sshbuf_avail(p1), sz);
				ASSERT_SIZE_T_EQ(sshbuf_len(p1), sz2);
			} இல்லையெனில் {
				ASSERT_PTR_NE(dp, வெற்று);
				ASSERT_SIZE_T_GE(sz, r);
				ASSERT_SIZE_T_EQ(sshbuf_avail(p1), sz - r);
				ASSERT_SIZE_T_EQ(sshbuf_len(p1), sz2 + r);
				memset(dp, arc4random_uniform(255) + 1, r);
			}
		} இல்லையெனில் எனில் (r < 3) {
			/* 20% chance: big reserve */
			r = arc4random_uniform(8 * 1024);
			செல் fuzz_reserve;
		} இல்லையெனில் எனில் (r == 3) {
			/* 10% chance: small consume */
			r = arc4random_uniform(10);
 fuzz_consume:
			sz = sshbuf_avail(p1);
			sz2 = sshbuf_len(p1);
			/* 50% change consume from end, otherwise start */
			ret = ((arc4random() & 1) ?
			    sshbuf_consume : sshbuf_consume_end)(p1, r);
			எனில் (ret < 0) {
				ASSERT_SIZE_T_LT(sz2, r);
				ASSERT_SIZE_T_EQ(sshbuf_avail(p1), sz);
				ASSERT_SIZE_T_EQ(sshbuf_len(p1), sz2);
			} இல்லையெனில் {
				ASSERT_SIZE_T_GE(sz2, r);
				ASSERT_SIZE_T_EQ(sshbuf_avail(p1), sz + r);
				ASSERT_SIZE_T_EQ(sshbuf_len(p1), sz2 - r);
			}
		} இல்லையெனில் எனில் (r < 8) {
			/* 40% chance: big consume */
			r = arc4random_uniform(2 * 1024);
			செல் fuzz_consume;
		} இல்லையெனில் எனில் (r == 8) {
			/* 10% chance: reset max size */
			r = arc4random_uniform(16 * 1024);
			sz = sshbuf_max_size(p1);
			எனில் (sshbuf_set_max_size(p1, r) < 0)
				ASSERT_SIZE_T_EQ(sshbuf_max_size(p1), sz);
			இல்லையெனில்
				ASSERT_SIZE_T_EQ(sshbuf_max_size(p1), r);
		} இல்லையெனில் {
			எனில் (arc4random_uniform(8192) == 0) {
				/* tiny chance: new buffer */
				ASSERT_PTR_NE(sshbuf_ptr(p1), வெற்று);
				ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
				sshbuf_free(p1);
				p1 = sshbuf_new();
				ASSERT_PTR_NE(p1, வெற்று);
				ASSERT_INT_EQ(sshbuf_set_max_size(p1,
				    16 * 1024), 0);
			} இல்லையெனில் {
				/* Almost 10%: giant reserve */
				/* use arc4random_buf for r > 2^32 on 64 bit */
				arc4random_buf(&r, அளவு(r));
				போது (r < SSHBUF_SIZE_MAX / 2) {
					r <<= 1;
					r |= arc4random() & 1;
				}
				செல் fuzz_reserve;
			}
		}
		ASSERT_PTR_NE(sshbuf_ptr(p1), வெற்று);
		ASSERT_SIZE_T_LE(sshbuf_max_size(p1), 16 * 1024);
	}
	ASSERT_PTR_NE(sshbuf_ptr(p1), வெற்று);
	ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
	sshbuf_free(p1);
	TEST_DONE();
}
