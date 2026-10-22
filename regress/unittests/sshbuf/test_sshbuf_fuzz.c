/* 	$OpenBSD: test_sshbuf_fuzz.c,v 1.5 2026/03/06 06:57:33 dtucker Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ "../test_helper/test_helper.h"

#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"

#define ଅଙ୍କ_FUZZ_TESTS (1 << 18)

ଶୂନ୍ୟ sshbuf_fuzz_tests(ଶୂନ୍ୟ);

ଶୂନ୍ୟ
sshbuf_fuzz_tests(ଶୂନ୍ୟ)
{
	ସଂରଚନା sshbuf *p1;
	u_char *dp;
	size_t sz, sz2, i, ntests = ଅଙ୍କ_FUZZ_TESTS;
	uint32_t r;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret;

	ଯଦି (test_is_fast())
		ntests >>= 2;
	ଯଦି (test_is_slow())
		ntests <<= 2;

	/* NB. uses sshbuf internals */
	TEST_START("fuzz alloc/dealloc");
	p1 = sshbuf_new();
	ASSERT_INT_EQ(sshbuf_set_max_size(p1, 16 * 1024), 0);
	ASSERT_PTR_NE(p1, ଖାଲି);
	ASSERT_PTR_NE(sshbuf_ptr(p1), ଖାଲି);
	ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
	ପାଇଁ (i = 0; i < ntests; i++) {
		r = arc4random_uniform(10);
		ଯଦି (r == 0) {
			/* 10% chance: small reserve */
			r = arc4random_uniform(10);
 fuzz_reserve:
			sz = sshbuf_avail(p1);
			sz2 = sshbuf_len(p1);
			ret = sshbuf_reserve(p1, r, &dp);
			ଯଦି (ret < 0) {
				ASSERT_PTR_EQ(dp, ଖାଲି);
				ASSERT_SIZE_T_LT(sz, r);
				ASSERT_SIZE_T_EQ(sshbuf_avail(p1), sz);
				ASSERT_SIZE_T_EQ(sshbuf_len(p1), sz2);
			} ଅନ୍ୟଥା {
				ASSERT_PTR_NE(dp, ଖାଲି);
				ASSERT_SIZE_T_GE(sz, r);
				ASSERT_SIZE_T_EQ(sshbuf_avail(p1), sz - r);
				ASSERT_SIZE_T_EQ(sshbuf_len(p1), sz2 + r);
				memset(dp, arc4random_uniform(255) + 1, r);
			}
		} ଅନ୍ୟଥା ଯଦି (r < 3) {
			/* 20% chance: big reserve */
			r = arc4random_uniform(8 * 1024);
			ଯାଅ fuzz_reserve;
		} ଅନ୍ୟଥା ଯଦି (r == 3) {
			/* 10% chance: small consume */
			r = arc4random_uniform(10);
 fuzz_consume:
			sz = sshbuf_avail(p1);
			sz2 = sshbuf_len(p1);
			/* 50% change consume from end, otherwise start */
			ret = ((arc4random() & 1) ?
			    sshbuf_consume : sshbuf_consume_end)(p1, r);
			ଯଦି (ret < 0) {
				ASSERT_SIZE_T_LT(sz2, r);
				ASSERT_SIZE_T_EQ(sshbuf_avail(p1), sz);
				ASSERT_SIZE_T_EQ(sshbuf_len(p1), sz2);
			} ଅନ୍ୟଥା {
				ASSERT_SIZE_T_GE(sz2, r);
				ASSERT_SIZE_T_EQ(sshbuf_avail(p1), sz + r);
				ASSERT_SIZE_T_EQ(sshbuf_len(p1), sz2 - r);
			}
		} ଅନ୍ୟଥା ଯଦି (r < 8) {
			/* 40% chance: big consume */
			r = arc4random_uniform(2 * 1024);
			ଯାଅ fuzz_consume;
		} ଅନ୍ୟଥା ଯଦି (r == 8) {
			/* 10% chance: reset max size */
			r = arc4random_uniform(16 * 1024);
			sz = sshbuf_max_size(p1);
			ଯଦି (sshbuf_set_max_size(p1, r) < 0)
				ASSERT_SIZE_T_EQ(sshbuf_max_size(p1), sz);
			ଅନ୍ୟଥା
				ASSERT_SIZE_T_EQ(sshbuf_max_size(p1), r);
		} ଅନ୍ୟଥା {
			ଯଦି (arc4random_uniform(8192) == 0) {
				/* tiny chance: new buffer */
				ASSERT_PTR_NE(sshbuf_ptr(p1), ଖାଲି);
				ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
				sshbuf_free(p1);
				p1 = sshbuf_new();
				ASSERT_PTR_NE(p1, ଖାଲି);
				ASSERT_INT_EQ(sshbuf_set_max_size(p1,
				    16 * 1024), 0);
			} ଅନ୍ୟଥା {
				/* Almost 10%: giant reserve */
				/* use arc4random_buf for r > 2^32 on 64 bit */
				arc4random_buf(&r, ଆକାର(r));
				ଯେତେବେଳେ (r < SSHBUF_SIZE_MAX / 2) {
					r <<= 1;
					r |= arc4random() & 1;
				}
				ଯାଅ fuzz_reserve;
			}
		}
		ASSERT_PTR_NE(sshbuf_ptr(p1), ଖାଲି);
		ASSERT_SIZE_T_LE(sshbuf_max_size(p1), 16 * 1024);
	}
	ASSERT_PTR_NE(sshbuf_ptr(p1), ଖାଲି);
	ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
	sshbuf_free(p1);
	TEST_DONE();
}
