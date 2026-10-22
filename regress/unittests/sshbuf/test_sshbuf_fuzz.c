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

#ವ್ಯಾಖ್ಯಾನಿಸು ಅಂಕೆ_FUZZ_TESTS (1 << 18)

ಶೂನ್ಯ sshbuf_fuzz_tests(ಶೂನ್ಯ);

ಶೂನ್ಯ
sshbuf_fuzz_tests(ಶೂನ್ಯ)
{
	ರಚನೆ sshbuf *p1;
	u_char *dp;
	ಗಾತ್ರ_t sz, sz2, i, ntests = ಅಂಕೆ_FUZZ_TESTS;
	uint32_t r;
	ಪೂರ್ಣಾಂಕ ret;

	ಆದರೆ (test_is_fast())
		ntests >>= 2;
	ಆದರೆ (test_is_slow())
		ntests <<= 2;

	/* NB. uses sshbuf internals */
	TEST_ಆರಂಭ("fuzz alloc/dealloc");
	p1 = sshbuf_new();
	ASSERT_INT_EQ(sshbuf_ಗಣ_max_ಗಾತ್ರ(p1, 16 * 1024), 0);
	ASSERT_PTR_NE(p1, ಖಾಲಿ);
	ASSERT_PTR_NE(sshbuf_ptr(p1), ಖಾಲಿ);
	ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
	ಗಾಗಿ (i = 0; i < ntests; i++) {
		r = arc4random_ಏಕರೂಪ(10);
		ಆದರೆ (r == 0) {
			/* 10% chance: small reserve */
			r = arc4random_ಏಕರೂಪ(10);
 fuzz_reserve:
			sz = sshbuf_avail(p1);
			sz2 = sshbuf_len(p1);
			ret = sshbuf_reserve(p1, r, &dp);
			ಆದರೆ (ret < 0) {
				ASSERT_PTR_EQ(dp, ಖಾಲಿ);
				ASSERT_ಗಾತ್ರ_T_LT(sz, r);
				ASSERT_ಗಾತ್ರ_T_EQ(sshbuf_avail(p1), sz);
				ASSERT_ಗಾತ್ರ_T_EQ(sshbuf_len(p1), sz2);
			} ಇಲ್ಲದಿದ್ದರೆ {
				ASSERT_PTR_NE(dp, ಖಾಲಿ);
				ASSERT_ಗಾತ್ರ_T_GE(sz, r);
				ASSERT_ಗಾತ್ರ_T_EQ(sshbuf_avail(p1), sz - r);
				ASSERT_ಗಾತ್ರ_T_EQ(sshbuf_len(p1), sz2 + r);
				memset(dp, arc4random_ಏಕರೂಪ(255) + 1, r);
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r < 3) {
			/* 20% chance: big reserve */
			r = arc4random_ಏಕರೂಪ(8 * 1024);
			ಹೋಗು fuzz_reserve;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r == 3) {
			/* 10% chance: small consume */
			r = arc4random_ಏಕರೂಪ(10);
 fuzz_consume:
			sz = sshbuf_avail(p1);
			sz2 = sshbuf_len(p1);
			/* 50% change consume from end, otherwise start */
			ret = ((arc4random() & 1) ?
			    sshbuf_consume : sshbuf_consume_ಕೊನೆ)(p1, r);
			ಆದರೆ (ret < 0) {
				ASSERT_ಗಾತ್ರ_T_LT(sz2, r);
				ASSERT_ಗಾತ್ರ_T_EQ(sshbuf_avail(p1), sz);
				ASSERT_ಗಾತ್ರ_T_EQ(sshbuf_len(p1), sz2);
			} ಇಲ್ಲದಿದ್ದರೆ {
				ASSERT_ಗಾತ್ರ_T_GE(sz2, r);
				ASSERT_ಗಾತ್ರ_T_EQ(sshbuf_avail(p1), sz + r);
				ASSERT_ಗಾತ್ರ_T_EQ(sshbuf_len(p1), sz2 - r);
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r < 8) {
			/* 40% chance: big consume */
			r = arc4random_ಏಕರೂಪ(2 * 1024);
			ಹೋಗು fuzz_consume;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r == 8) {
			/* 10% chance: reset max size */
			r = arc4random_ಏಕರೂಪ(16 * 1024);
			sz = sshbuf_max_ಗಾತ್ರ(p1);
			ಆದರೆ (sshbuf_ಗಣ_max_ಗಾತ್ರ(p1, r) < 0)
				ASSERT_ಗಾತ್ರ_T_EQ(sshbuf_max_ಗಾತ್ರ(p1), sz);
			ಇಲ್ಲದಿದ್ದರೆ
				ASSERT_ಗಾತ್ರ_T_EQ(sshbuf_max_ಗಾತ್ರ(p1), r);
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (arc4random_ಏಕರೂಪ(8192) == 0) {
				/* tiny chance: new buffer */
				ASSERT_PTR_NE(sshbuf_ptr(p1), ಖಾಲಿ);
				ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
				sshbuf_free(p1);
				p1 = sshbuf_new();
				ASSERT_PTR_NE(p1, ಖಾಲಿ);
				ASSERT_INT_EQ(sshbuf_ಗಣ_max_ಗಾತ್ರ(p1,
				    16 * 1024), 0);
			} ಇಲ್ಲದಿದ್ದರೆ {
				/* Almost 10%: giant reserve */
				/* use arc4random_buf for r > 2^32 on 64 bit */
				arc4random_buf(&r, ಗಾತ್ರ(r));
				ಆಗ (r < SSHBUF_ಗಾತ್ರ_MAX / 2) {
					r <<= 1;
					r |= arc4random() & 1;
				}
				ಹೋಗು fuzz_reserve;
			}
		}
		ASSERT_PTR_NE(sshbuf_ptr(p1), ಖಾಲಿ);
		ASSERT_ಗಾತ್ರ_T_LE(sshbuf_max_ಗಾತ್ರ(p1), 16 * 1024);
	}
	ASSERT_PTR_NE(sshbuf_ptr(p1), ಖಾಲಿ);
	ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
	sshbuf_free(p1);
	TEST_ಮುಗಿದ();
}
