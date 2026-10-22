/* 	$OpenBSD: test_sshbuf_fuzz.c,v 1.5 2026/03/06 06:57:33 dtucker Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "../test_helper/test_helper.h"

#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshbuf.h"

#నిర్వచించు అంకె_FUZZ_TESTS (1 << 18)

శూన్య sshbuf_fuzz_tests(శూన్య);

శూన్య
sshbuf_fuzz_tests(శూన్య)
{
	నిర్మాణం sshbuf *p1;
	u_char *dp;
	కొలత_t sz, sz2, i, ntests = అంకె_FUZZ_TESTS;
	uint32_t r;
	పూర్ణాంకం ret;

	ఒకవేళ (test_is_fast())
		ntests >>= 2;
	ఒకవేళ (test_is_slow())
		ntests <<= 2;

	/* NB. uses sshbuf internals */
	TEST_ప్రారంభం("fuzz alloc/dealloc");
	p1 = sshbuf_new();
	ASSERT_INT_EQ(sshbuf_సమితి_max_కొలత(p1, 16 * 1024), 0);
	ASSERT_PTR_NE(p1, ఖాళీ);
	ASSERT_PTR_NE(sshbuf_ptr(p1), ఖాళీ);
	ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
	కొరకు (i = 0; i < ntests; i++) {
		r = arc4random_ఏకరీతి(10);
		ఒకవేళ (r == 0) {
			/* 10% chance: small reserve */
			r = arc4random_ఏకరీతి(10);
 fuzz_reserve:
			sz = sshbuf_avail(p1);
			sz2 = sshbuf_len(p1);
			ret = sshbuf_reserve(p1, r, &dp);
			ఒకవేళ (ret < 0) {
				ASSERT_PTR_EQ(dp, ఖాళీ);
				ASSERT_కొలత_T_LT(sz, r);
				ASSERT_కొలత_T_EQ(sshbuf_avail(p1), sz);
				ASSERT_కొలత_T_EQ(sshbuf_len(p1), sz2);
			} లేకపోతే {
				ASSERT_PTR_NE(dp, ఖాళీ);
				ASSERT_కొలత_T_GE(sz, r);
				ASSERT_కొలత_T_EQ(sshbuf_avail(p1), sz - r);
				ASSERT_కొలత_T_EQ(sshbuf_len(p1), sz2 + r);
				memset(dp, arc4random_ఏకరీతి(255) + 1, r);
			}
		} లేకపోతే ఒకవేళ (r < 3) {
			/* 20% chance: big reserve */
			r = arc4random_ఏకరీతి(8 * 1024);
			వెళ్ళు fuzz_reserve;
		} లేకపోతే ఒకవేళ (r == 3) {
			/* 10% chance: small consume */
			r = arc4random_ఏకరీతి(10);
 fuzz_consume:
			sz = sshbuf_avail(p1);
			sz2 = sshbuf_len(p1);
			/* 50% change consume from end, otherwise start */
			ret = ((arc4random() & 1) ?
			    sshbuf_consume : sshbuf_consume_చివర)(p1, r);
			ఒకవేళ (ret < 0) {
				ASSERT_కొలత_T_LT(sz2, r);
				ASSERT_కొలత_T_EQ(sshbuf_avail(p1), sz);
				ASSERT_కొలత_T_EQ(sshbuf_len(p1), sz2);
			} లేకపోతే {
				ASSERT_కొలత_T_GE(sz2, r);
				ASSERT_కొలత_T_EQ(sshbuf_avail(p1), sz + r);
				ASSERT_కొలత_T_EQ(sshbuf_len(p1), sz2 - r);
			}
		} లేకపోతే ఒకవేళ (r < 8) {
			/* 40% chance: big consume */
			r = arc4random_ఏకరీతి(2 * 1024);
			వెళ్ళు fuzz_consume;
		} లేకపోతే ఒకవేళ (r == 8) {
			/* 10% chance: reset max size */
			r = arc4random_ఏకరీతి(16 * 1024);
			sz = sshbuf_max_కొలత(p1);
			ఒకవేళ (sshbuf_సమితి_max_కొలత(p1, r) < 0)
				ASSERT_కొలత_T_EQ(sshbuf_max_కొలత(p1), sz);
			లేకపోతే
				ASSERT_కొలత_T_EQ(sshbuf_max_కొలత(p1), r);
		} లేకపోతే {
			ఒకవేళ (arc4random_ఏకరీతి(8192) == 0) {
				/* tiny chance: new buffer */
				ASSERT_PTR_NE(sshbuf_ptr(p1), ఖాళీ);
				ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
				sshbuf_free(p1);
				p1 = sshbuf_new();
				ASSERT_PTR_NE(p1, ఖాళీ);
				ASSERT_INT_EQ(sshbuf_సమితి_max_కొలత(p1,
				    16 * 1024), 0);
			} లేకపోతే {
				/* Almost 10%: giant reserve */
				/* use arc4random_buf for r > 2^32 on 64 bit */
				arc4random_buf(&r, పరిమాణం(r));
				అయితే (r < SSHBUF_కొలత_MAX / 2) {
					r <<= 1;
					r |= arc4random() & 1;
				}
				వెళ్ళు fuzz_reserve;
			}
		}
		ASSERT_PTR_NE(sshbuf_ptr(p1), ఖాళీ);
		ASSERT_కొలత_T_LE(sshbuf_max_కొలత(p1), 16 * 1024);
	}
	ASSERT_PTR_NE(sshbuf_ptr(p1), ఖాళీ);
	ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
	sshbuf_free(p1);
	TEST_పూర్తి();
}
