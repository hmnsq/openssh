/* 	$OpenBSD: test_sshbuf.c,v 1.3 2025/12/30 00:12:58 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#परिभाषय SSHBUF_आन्तरिकम् 1	/* access internals for testing */
#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "../test_helper/test_helper.h"

#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshbuf.h"

शून्य sshbuf_tests(शून्य);

#यदि_अपरिभाषितम् roundup
#परिभाषय roundup(x, y)   ((((x)+((y)-1))/(y))*(y))
#यदि_अन्तः

शून्य
sshbuf_tests(शून्य)
{
	संरचना sshbuf *p1, *p2, *p3;
	u_int v32;
	ध्रुव u_char *cdp;
	u_char *dp;
	आकार_t sz;
	पूर्णाङ्क r;

	TEST_START("allocate sshbuf");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, रिक्त);
	TEST_समाप्तम्();

	TEST_START("max size on fresh buffer");
	ASSERT_आकार_T_GT(sshbuf_max_आकार(p1), 0);
	TEST_समाप्तम्();

	TEST_START("available on fresh buffer");
	ASSERT_आकार_T_GT(sshbuf_avail(p1), 0);
	TEST_समाप्तम्();

	TEST_START("len = 0 on empty buffer");
	ASSERT_आकार_T_EQ(sshbuf_len(p1), 0);
	TEST_समाप्तम्();

	TEST_START("set valid max size");
	ASSERT_INT_EQ(sshbuf_समुच्चयः_max_आकार(p1, 65536), 0);
	ASSERT_आकार_T_EQ(sshbuf_max_आकार(p1), 65536);
	TEST_समाप्तम्();

	TEST_START("available on limited buffer");
	ASSERT_आकार_T_EQ(sshbuf_avail(p1), 65536);
	TEST_समाप्तम्();

	TEST_START("free");
	sshbuf_free(p1);
	TEST_समाप्तम्();

	TEST_START("consume on empty buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, रिक्त);
	ASSERT_INT_EQ(sshbuf_consume(p1, 0), 0);
	ASSERT_INT_EQ(sshbuf_consume(p1, 1), SSH_ERR_सन्देशः_INCOMPLETE);
	sshbuf_free(p1);
	TEST_समाप्तम्();

	TEST_START("consume_end on empty buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, रिक्त);
	ASSERT_INT_EQ(sshbuf_consume_अन्तः(p1, 0), 0);
	ASSERT_INT_EQ(sshbuf_consume_अन्तः(p1, 1), SSH_ERR_सन्देशः_INCOMPLETE);
	sshbuf_free(p1);
	TEST_समाप्तम्();

	TEST_START("reserve space");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, रिक्त);
	r = sshbuf_reserve(p1, 1, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, रिक्त);
	*dp = 0x11;
	r = sshbuf_reserve(p1, 3, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, रिक्त);
	*dp++ = 0x22;
	*dp++ = 0x33;
	*dp++ = 0x44;
	TEST_समाप्तम्();

	TEST_START("sshbuf_len on filled buffer");
	ASSERT_आकार_T_EQ(sshbuf_len(p1), 4);
	TEST_समाप्तम्();

	TEST_START("sshbuf_ptr on filled buffer");
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(cdp, रिक्त);
	ASSERT_U8_EQ(cdp[0], 0x11);
	ASSERT_U8_EQ(cdp[1], 0x22);
	ASSERT_U8_EQ(cdp[2], 0x33);
	ASSERT_U8_EQ(cdp[3], 0x44);
	TEST_समाप्तम्();

	TEST_START("consume on filled buffer");
	ASSERT_आकार_T_EQ(sshbuf_len(p1), 4);
	ASSERT_INT_EQ(sshbuf_consume(p1, 0), 0);
	ASSERT_आकार_T_EQ(sshbuf_len(p1), 4);
	r = sshbuf_consume(p1, 64);
	ASSERT_INT_EQ(r, SSH_ERR_सन्देशः_INCOMPLETE);
	ASSERT_आकार_T_EQ(sshbuf_len(p1), 4);
	ASSERT_INT_EQ(sshbuf_consume(p1, 1), 0);
	ASSERT_आकार_T_EQ(sshbuf_len(p1), 3);
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(p1, रिक्त);
	ASSERT_U8_EQ(cdp[0], 0x22);
	ASSERT_INT_EQ(sshbuf_consume(p1, 2), 0);
	ASSERT_आकार_T_EQ(sshbuf_len(p1), 1);
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(p1, रिक्त);
	ASSERT_U8_EQ(cdp[0], 0x44);
	r = sshbuf_consume(p1, 2);
	ASSERT_INT_EQ(r, SSH_ERR_सन्देशः_INCOMPLETE);
	ASSERT_आकार_T_EQ(sshbuf_len(p1), 1);
	ASSERT_INT_EQ(sshbuf_consume(p1, 1), 0);
	ASSERT_आकार_T_EQ(sshbuf_len(p1), 0);
	r = sshbuf_consume(p1, 1);
	ASSERT_INT_EQ(r, SSH_ERR_सन्देशः_INCOMPLETE);
	sshbuf_free(p1);
	TEST_समाप्तम्();

	TEST_START("consume_end on filled buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, रिक्त);
	r = sshbuf_reserve(p1, 4, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, रिक्त);
	*dp++ = 0x11;
	*dp++ = 0x22;
	*dp++ = 0x33;
	*dp++ = 0x44;
	ASSERT_आकार_T_EQ(sshbuf_len(p1), 4);
	r = sshbuf_consume_अन्तः(p1, 5);
	ASSERT_INT_EQ(r, SSH_ERR_सन्देशः_INCOMPLETE);
	ASSERT_आकार_T_EQ(sshbuf_len(p1), 4);
	ASSERT_INT_EQ(sshbuf_consume_अन्तः(p1, 3), 0);
	ASSERT_आकार_T_EQ(sshbuf_len(p1), 1);
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(cdp, रिक्त);
	ASSERT_U8_EQ(*cdp, 0x11);
	r = sshbuf_consume_अन्तः(p1, 2);
	ASSERT_INT_EQ(r, SSH_ERR_सन्देशः_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_consume_अन्तः(p1, 1), 0);
	ASSERT_आकार_T_EQ(sshbuf_len(p1), 0);
	sshbuf_free(p1);
	TEST_समाप्तम्();

	TEST_START("fill limited buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, रिक्त);
	ASSERT_INT_EQ(sshbuf_समुच्चयः_max_आकार(p1, 1223), 0);
	ASSERT_आकार_T_EQ(sshbuf_max_आकार(p1), 1223);
	ASSERT_आकार_T_EQ(sshbuf_avail(p1), 1223);
	r = sshbuf_reserve(p1, 1223, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, रिक्त);
	स्मृतिं_पूरय(dp, 0xd7, 1223);
	ASSERT_आकार_T_EQ(sshbuf_len(p1), 1223);
	ASSERT_आकार_T_EQ(sshbuf_avail(p1), 0);
	r = sshbuf_reserve(p1, 1, &dp);
	ASSERT_INT_EQ(r, SSH_ERR_NO_बफर_SPACE);
	ASSERT_PTR_EQ(dp, रिक्त);
	TEST_समाप्तम्();

	TEST_START("consume and force compaction");
	ASSERT_INT_EQ(sshbuf_consume(p1, 223), 0);
	ASSERT_आकार_T_EQ(sshbuf_len(p1), 1000);
	ASSERT_आकार_T_EQ(sshbuf_avail(p1), 223);
	r = sshbuf_reserve(p1, 224, &dp);
	ASSERT_INT_EQ(r, SSH_ERR_NO_बफर_SPACE);
	ASSERT_PTR_EQ(dp, रिक्त);
	ASSERT_आकार_T_EQ(sshbuf_len(p1), 1000);
	ASSERT_आकार_T_EQ(sshbuf_avail(p1), 223);
	r = sshbuf_reserve(p1, 223, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, रिक्त);
	स्मृतिं_पूरय(dp, 0x7d, 223);
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(cdp, रिक्त);
	ASSERT_MEM_FILLED_EQ(cdp, 0xd7, 1000);
	ASSERT_MEM_FILLED_EQ(cdp + 1000, 0x7d, 223);
	TEST_समाप्तम्();

	TEST_START("resize full buffer");
	r = sshbuf_समुच्चयः_max_आकार(p1, 1000);
	ASSERT_INT_EQ(r, SSH_ERR_NO_बफर_SPACE);
	sz = roundup(1223 + SSHBUF_आकार_INC * 3, SSHBUF_आकार_INC);
	ASSERT_INT_EQ(sshbuf_समुच्चयः_max_आकार(p1, sz), 0);
	ASSERT_आकार_T_EQ(sshbuf_max_आकार(p1), sz);
	ASSERT_आकार_T_EQ(sshbuf_avail(p1), sz - 1223);
	ASSERT_INT_EQ(sshbuf_len(p1), 1223);
	TEST_समाप्तम्();

	/* NB. uses sshbuf internals */
	TEST_START("alloc chunking");
	r = sshbuf_reserve(p1, 1, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, रिक्त);
	*dp = 0xff;
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(cdp, रिक्त);
	ASSERT_MEM_FILLED_EQ(cdp, 0xd7, 1000);
	ASSERT_MEM_FILLED_EQ(cdp + 1000, 0x7d, 223);
	ASSERT_MEM_FILLED_EQ(cdp + 1223, 0xff, 1);
	ASSERT_आकार_T_EQ(sshbuf_alloc(p1) % SSHBUF_आकार_INC, 0);
	sshbuf_free(p1);
	TEST_समाप्तम्();

	TEST_START("reset buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, रिक्त);
	ASSERT_INT_EQ(sshbuf_समुच्चयः_max_आकार(p1, 1223), 0);
	ASSERT_आकार_T_EQ(sshbuf_max_आकार(p1), 1223);
	r = sshbuf_reserve(p1, 1223, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, रिक्त);
	स्मृतिं_पूरय(dp, 0xd7, 1223);
	ASSERT_आकार_T_EQ(sshbuf_len(p1), 1223);
	sshbuf_reset(p1);
	ASSERT_आकार_T_EQ(sshbuf_max_आकार(p1), 1223);
	ASSERT_आकार_T_EQ(sshbuf_len(p1), 0);
	ASSERT_आकार_T_EQ(sshbuf_avail(p1), 1223);
	sshbuf_free(p1);
	TEST_समाप्तम्();

	TEST_START("sshbuf_consume_upto_child");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, रिक्त);
	p2 = sshbuf_new();
	ASSERT_PTR_NE(p2, रिक्त);
	/* Unrelated buffers */
	ASSERT_INT_EQ(sshbuf_consume_upto_child(p1, p2),
	    SSH_ERR_INVALID_तर्कः);
	/* Simple success case */
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0xdeadbeef), 0);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x01020304), 0);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0xfeedface), 0);
	ASSERT_आकार_T_EQ(sshbuf_len(p1), 12);
	p3 = sshbuf_fromb(p1);
	ASSERT_PTR_NE(p3, रिक्त);
	ASSERT_INT_EQ(sshbuf_get_u32(p3, &v32), 0);
	ASSERT_U32_EQ(v32, 0xdeadbeef);
	ASSERT_आकार_T_EQ(sshbuf_len(p3), 8);
	ASSERT_INT_EQ(sshbuf_consume_upto_child(p1, p3), 0);
	ASSERT_आकार_T_EQ(sshbuf_len(p1), sshbuf_len(p3));
	ASSERT_PTR_EQ(sshbuf_ptr(p1), sshbuf_ptr(p3));
	sshbuf_free(p3);
	/* Parent already consumed past child */
	p3 = sshbuf_fromb(p1);
	ASSERT_PTR_NE(p3, रिक्त);
	ASSERT_INT_EQ(sshbuf_get_u32(p1, &v32), 0);
	ASSERT_U32_EQ(v32, 0x01020304);
	ASSERT_INT_EQ(sshbuf_consume_upto_child(p1, p3),
	    SSH_ERR_INVALID_तर्कः);
	sshbuf_free(p1);
	sshbuf_free(p2);
	sshbuf_free(p3);
	TEST_समाप्तम्();
}
