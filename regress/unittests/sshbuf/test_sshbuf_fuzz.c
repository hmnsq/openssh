/* 	$OpenBSD: test_sshbuf_fuzz.c,v 1.5 2026/03/06 06:57:33 dtucker Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"

#define ಅಂಕೆ_FUZZ_TESTS (1 << 18)

ಶೂನ್ಯ sshbuf_fuzz_tests(ಶೂನ್ಯ);

ಶೂನ್ಯ
sshbuf_fuzz_tests(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshbuf *p1;
	u_char *dp;
	size_t sz, sz2, i, ntests = ಅಂಕೆ_FUZZ_TESTS;
	uint32_t r;
	ಪೂರ್ಣಾಙ್ಕ ret;

	ಯದಿ (test_is_fast())
		ntests >>= 2;
	ಯದಿ (test_is_slow())
		ntests <<= 2;

	/* NB. uses sshbuf internals */
	TEST_START("fuzz alloc/dealloc");
	p1 = sshbuf_new();
	ASSERT_INT_EQ(sshbuf_set_max_size(p1, 16 * 1024), 0);
	ASSERT_PTR_NE(p1, ರಿಕ್ತ);
	ASSERT_PTR_NE(sshbuf_ptr(p1), ರಿಕ್ತ);
	ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
	ಪ್ರತಿ (i = 0; i < ntests; i++) {
		r = arc4random_uniform(10);
		ಯದಿ (r == 0) {
			/* 10% chance: small reserve */
			r = arc4random_uniform(10);
 fuzz_reserve:
			sz = sshbuf_avail(p1);
			sz2 = sshbuf_len(p1);
			ret = sshbuf_reserve(p1, r, &dp);
			ಯದಿ (ret < 0) {
				ASSERT_PTR_EQ(dp, ರಿಕ್ತ);
				ASSERT_SIZE_T_LT(sz, r);
				ASSERT_SIZE_T_EQ(sshbuf_avail(p1), sz);
				ASSERT_SIZE_T_EQ(sshbuf_len(p1), sz2);
			} ಅನ್ಯಥಾ {
				ASSERT_PTR_NE(dp, ರಿಕ್ತ);
				ASSERT_SIZE_T_GE(sz, r);
				ASSERT_SIZE_T_EQ(sshbuf_avail(p1), sz - r);
				ASSERT_SIZE_T_EQ(sshbuf_len(p1), sz2 + r);
				memset(dp, arc4random_uniform(255) + 1, r);
			}
		} ಅನ್ಯಥಾ ಯದಿ (r < 3) {
			/* 20% chance: big reserve */
			r = arc4random_uniform(8 * 1024);
			ಗಚ್ಛ fuzz_reserve;
		} ಅನ್ಯಥಾ ಯದಿ (r == 3) {
			/* 10% chance: small consume */
			r = arc4random_uniform(10);
 fuzz_consume:
			sz = sshbuf_avail(p1);
			sz2 = sshbuf_len(p1);
			/* 50% change consume from end, otherwise start */
			ret = ((arc4random() & 1) ?
			    sshbuf_consume : sshbuf_consume_end)(p1, r);
			ಯದಿ (ret < 0) {
				ASSERT_SIZE_T_LT(sz2, r);
				ASSERT_SIZE_T_EQ(sshbuf_avail(p1), sz);
				ASSERT_SIZE_T_EQ(sshbuf_len(p1), sz2);
			} ಅನ್ಯಥಾ {
				ASSERT_SIZE_T_GE(sz2, r);
				ASSERT_SIZE_T_EQ(sshbuf_avail(p1), sz + r);
				ASSERT_SIZE_T_EQ(sshbuf_len(p1), sz2 - r);
			}
		} ಅನ್ಯಥಾ ಯದಿ (r < 8) {
			/* 40% chance: big consume */
			r = arc4random_uniform(2 * 1024);
			ಗಚ್ಛ fuzz_consume;
		} ಅನ್ಯಥಾ ಯದಿ (r == 8) {
			/* 10% chance: reset max size */
			r = arc4random_uniform(16 * 1024);
			sz = sshbuf_max_size(p1);
			ಯದಿ (sshbuf_set_max_size(p1, r) < 0)
				ASSERT_SIZE_T_EQ(sshbuf_max_size(p1), sz);
			ಅನ್ಯಥಾ
				ASSERT_SIZE_T_EQ(sshbuf_max_size(p1), r);
		} ಅನ್ಯಥಾ {
			ಯದಿ (arc4random_uniform(8192) == 0) {
				/* tiny chance: new buffer */
				ASSERT_PTR_NE(sshbuf_ptr(p1), ರಿಕ್ತ);
				ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
				sshbuf_free(p1);
				p1 = sshbuf_new();
				ASSERT_PTR_NE(p1, ರಿಕ್ತ);
				ASSERT_INT_EQ(sshbuf_set_max_size(p1,
				    16 * 1024), 0);
			} ಅನ್ಯಥಾ {
				/* Almost 10%: giant reserve */
				/* use arc4random_buf for r > 2^32 on 64 bit */
				arc4random_buf(&r, ಪರಿಮಾಣ(r));
				ಯಾವತ್ (r < SSHBUF_SIZE_MAX / 2) {
					r <<= 1;
					r |= arc4random() & 1;
				}
				ಗಚ್ಛ fuzz_reserve;
			}
		}
		ASSERT_PTR_NE(sshbuf_ptr(p1), ರಿಕ್ತ);
		ASSERT_SIZE_T_LE(sshbuf_max_size(p1), 16 * 1024);
	}
	ASSERT_PTR_NE(sshbuf_ptr(p1), ರಿಕ್ತ);
	ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
	sshbuf_free(p1);
	TEST_DONE();
}
