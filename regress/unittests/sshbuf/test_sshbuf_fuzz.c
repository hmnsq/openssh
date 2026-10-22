/* 	$OpenBSD: test_sshbuf_fuzz.c,v 1.5 2026/03/06 06:57:33 dtucker Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>

#समावेश "../test_helper/test_helper.h"

#समावेश "ssherr.h"
#समावेश "sshbuf.h"

#घोषणा अंक_FUZZ_TESTS (1 << 18)

व्योम sshbuf_fuzz_tests(व्योम);

व्योम
sshbuf_fuzz_tests(व्योम)
{
	काष्ठा sshbuf *p1;
	u_char *dp;
	माप_प्रकार sz, sz2, i, ntests = अंक_FUZZ_TESTS;
	uint32_t r;
	पूर्णांक ret;

	अगर (test_is_fast())
		ntests >>= 2;
	अगर (test_is_slow())
		ntests <<= 2;

	/* NB. uses sshbuf internals */
	TEST_START("fuzz alloc/dealloc");
	p1 = sshbuf_new();
	ASSERT_INT_EQ(sshbuf_set_max_आकार(p1, 16 * 1024), 0);
	ASSERT_PTR_NE(p1, शून्य);
	ASSERT_PTR_NE(sshbuf_ptr(p1), शून्य);
	ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
	क्रम (i = 0; i < ntests; i++) {
		r = arc4random_uniform(10);
		अगर (r == 0) {
			/* 10% chance: small reserve */
			r = arc4random_uniform(10);
 fuzz_reserve:
			sz = sshbuf_avail(p1);
			sz2 = sshbuf_len(p1);
			ret = sshbuf_reserve(p1, r, &dp);
			अगर (ret < 0) {
				ASSERT_PTR_EQ(dp, शून्य);
				ASSERT_आकार_T_LT(sz, r);
				ASSERT_आकार_T_EQ(sshbuf_avail(p1), sz);
				ASSERT_आकार_T_EQ(sshbuf_len(p1), sz2);
			} अन्यथा {
				ASSERT_PTR_NE(dp, शून्य);
				ASSERT_आकार_T_GE(sz, r);
				ASSERT_आकार_T_EQ(sshbuf_avail(p1), sz - r);
				ASSERT_आकार_T_EQ(sshbuf_len(p1), sz2 + r);
				स_रखो(dp, arc4random_uniform(255) + 1, r);
			}
		} अन्यथा अगर (r < 3) {
			/* 20% chance: big reserve */
			r = arc4random_uniform(8 * 1024);
			जाओ fuzz_reserve;
		} अन्यथा अगर (r == 3) {
			/* 10% chance: small consume */
			r = arc4random_uniform(10);
 fuzz_consume:
			sz = sshbuf_avail(p1);
			sz2 = sshbuf_len(p1);
			/* 50% change consume from end, otherwise start */
			ret = ((arc4random() & 1) ?
			    sshbuf_consume : sshbuf_consume_end)(p1, r);
			अगर (ret < 0) {
				ASSERT_आकार_T_LT(sz2, r);
				ASSERT_आकार_T_EQ(sshbuf_avail(p1), sz);
				ASSERT_आकार_T_EQ(sshbuf_len(p1), sz2);
			} अन्यथा {
				ASSERT_आकार_T_GE(sz2, r);
				ASSERT_आकार_T_EQ(sshbuf_avail(p1), sz + r);
				ASSERT_आकार_T_EQ(sshbuf_len(p1), sz2 - r);
			}
		} अन्यथा अगर (r < 8) {
			/* 40% chance: big consume */
			r = arc4random_uniform(2 * 1024);
			जाओ fuzz_consume;
		} अन्यथा अगर (r == 8) {
			/* 10% chance: reset max size */
			r = arc4random_uniform(16 * 1024);
			sz = sshbuf_max_आकार(p1);
			अगर (sshbuf_set_max_आकार(p1, r) < 0)
				ASSERT_आकार_T_EQ(sshbuf_max_आकार(p1), sz);
			अन्यथा
				ASSERT_आकार_T_EQ(sshbuf_max_आकार(p1), r);
		} अन्यथा {
			अगर (arc4random_uniform(8192) == 0) {
				/* tiny chance: new buffer */
				ASSERT_PTR_NE(sshbuf_ptr(p1), शून्य);
				ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
				sshbuf_free(p1);
				p1 = sshbuf_new();
				ASSERT_PTR_NE(p1, शून्य);
				ASSERT_INT_EQ(sshbuf_set_max_आकार(p1,
				    16 * 1024), 0);
			} अन्यथा {
				/* Almost 10%: giant reserve */
				/* use arc4random_buf for r > 2^32 on 64 bit */
				arc4random_buf(&r, माप(r));
				जबतक (r < SSHBUF_आकार_MAX / 2) {
					r <<= 1;
					r |= arc4random() & 1;
				}
				जाओ fuzz_reserve;
			}
		}
		ASSERT_PTR_NE(sshbuf_ptr(p1), शून्य);
		ASSERT_आकार_T_LE(sshbuf_max_आकार(p1), 16 * 1024);
	}
	ASSERT_PTR_NE(sshbuf_ptr(p1), शून्य);
	ASSERT_MEM_ZERO_NE(sshbuf_ptr(p1), sshbuf_len(p1));
	sshbuf_free(p1);
	TEST_DONE();
}
