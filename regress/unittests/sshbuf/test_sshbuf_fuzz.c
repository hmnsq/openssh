/* 	$OpenBSD: test_sshbuf_fuzz.c,v 1.5 2026/03/06 06:57:33 dtucker Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "../test_helper/test_helper.h"

#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sshbuf.h"

#define അക്കം_FUZZ_TESTS (1 << 18)

ശൂന്യം sshbuf_fuzz_tests(ശൂന്യം);

ശൂന്യം
sshbuf_fuzz_tests(ശൂന്യം)
{
	ഘടന sshbuf *p1;
	u_char *dp;
	size_t sz, sz2, i, ntests = അക്കം_FUZZ_TESTS;
	uint32_t r;
	പൂർണ്ണസംഖ്യ ret;

	എങ്കിൽ (test_is_fast())
		ntests >>= 2;
	എങ്കിൽ (test_is_slow())
		ntests <<= 2;

	/* NB. uses sshbuf internals */
	TEST_START("fuzz alloc/dealloc");
	p1 = sshbuf_new();
	ASSERT_INT_EQ(sshbuf_set_max_size(p1, 16 * 1024), 0);
	ASSERT_PTR_NE(p1, ശൂന്യ);
	ASSERT_PTR_NE(sshbuf_ptr(p1), ശൂന്യ);
	ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
	വേണ്ടി (i = 0; i < ntests; i++) {
		r = arc4random_uniform(10);
		എങ്കിൽ (r == 0) {
			/* 10% chance: small reserve */
			r = arc4random_uniform(10);
 fuzz_reserve:
			sz = sshbuf_avail(p1);
			sz2 = sshbuf_len(p1);
			ret = sshbuf_reserve(p1, r, &dp);
			എങ്കിൽ (ret < 0) {
				ASSERT_PTR_EQ(dp, ശൂന്യ);
				ASSERT_SIZE_T_LT(sz, r);
				ASSERT_SIZE_T_EQ(sshbuf_avail(p1), sz);
				ASSERT_SIZE_T_EQ(sshbuf_len(p1), sz2);
			} അല്ലെങ്കിൽ {
				ASSERT_PTR_NE(dp, ശൂന്യ);
				ASSERT_SIZE_T_GE(sz, r);
				ASSERT_SIZE_T_EQ(sshbuf_avail(p1), sz - r);
				ASSERT_SIZE_T_EQ(sshbuf_len(p1), sz2 + r);
				memset(dp, arc4random_uniform(255) + 1, r);
			}
		} അല്ലെങ്കിൽ എങ്കിൽ (r < 3) {
			/* 20% chance: big reserve */
			r = arc4random_uniform(8 * 1024);
			പോകുക fuzz_reserve;
		} അല്ലെങ്കിൽ എങ്കിൽ (r == 3) {
			/* 10% chance: small consume */
			r = arc4random_uniform(10);
 fuzz_consume:
			sz = sshbuf_avail(p1);
			sz2 = sshbuf_len(p1);
			/* 50% change consume from end, otherwise start */
			ret = ((arc4random() & 1) ?
			    sshbuf_consume : sshbuf_consume_end)(p1, r);
			എങ്കിൽ (ret < 0) {
				ASSERT_SIZE_T_LT(sz2, r);
				ASSERT_SIZE_T_EQ(sshbuf_avail(p1), sz);
				ASSERT_SIZE_T_EQ(sshbuf_len(p1), sz2);
			} അല്ലെങ്കിൽ {
				ASSERT_SIZE_T_GE(sz2, r);
				ASSERT_SIZE_T_EQ(sshbuf_avail(p1), sz + r);
				ASSERT_SIZE_T_EQ(sshbuf_len(p1), sz2 - r);
			}
		} അല്ലെങ്കിൽ എങ്കിൽ (r < 8) {
			/* 40% chance: big consume */
			r = arc4random_uniform(2 * 1024);
			പോകുക fuzz_consume;
		} അല്ലെങ്കിൽ എങ്കിൽ (r == 8) {
			/* 10% chance: reset max size */
			r = arc4random_uniform(16 * 1024);
			sz = sshbuf_max_size(p1);
			എങ്കിൽ (sshbuf_set_max_size(p1, r) < 0)
				ASSERT_SIZE_T_EQ(sshbuf_max_size(p1), sz);
			അല്ലെങ്കിൽ
				ASSERT_SIZE_T_EQ(sshbuf_max_size(p1), r);
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (arc4random_uniform(8192) == 0) {
				/* tiny chance: new buffer */
				ASSERT_PTR_NE(sshbuf_ptr(p1), ശൂന്യ);
				ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
				sshbuf_free(p1);
				p1 = sshbuf_new();
				ASSERT_PTR_NE(p1, ശൂന്യ);
				ASSERT_INT_EQ(sshbuf_set_max_size(p1,
				    16 * 1024), 0);
			} അല്ലെങ്കിൽ {
				/* Almost 10%: giant reserve */
				/* use arc4random_buf for r > 2^32 on 64 bit */
				arc4random_buf(&r, വലുപ്പം(r));
				ആകുമ്പോൾ (r < SSHBUF_SIZE_MAX / 2) {
					r <<= 1;
					r |= arc4random() & 1;
				}
				പോകുക fuzz_reserve;
			}
		}
		ASSERT_PTR_NE(sshbuf_ptr(p1), ശൂന്യ);
		ASSERT_SIZE_T_LE(sshbuf_max_size(p1), 16 * 1024);
	}
	ASSERT_PTR_NE(sshbuf_ptr(p1), ശൂന്യ);
	ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
	sshbuf_free(p1);
	TEST_DONE();
}
