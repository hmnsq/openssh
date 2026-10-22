/* 	$OpenBSD: test_sshbuf.c,v 1.3 2025/12/30 00:12:58 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#నిర్వచించు SSHBUF_అంతర్గత 1	/* access internals for testing */
#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "../test_helper/test_helper.h"

#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshbuf.h"

శూన్య sshbuf_tests(శూన్య);

#నిర్వచితం_కాకపోతే roundup
#నిర్వచించు roundup(x, y)   ((((x)+((y)-1))/(y))*(y))
#అయితే_ముగింపు

శూన్య
sshbuf_tests(శూన్య)
{
	నిర్మాణం sshbuf *p1, *p2, *p3;
	u_int v32;
	స్థిరరాశి u_char *cdp;
	u_char *dp;
	కొలత_t sz;
	పూర్ణాంకం r;

	TEST_ప్రారంభం("allocate sshbuf");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("max size on fresh buffer");
	ASSERT_కొలత_T_GT(sshbuf_max_కొలత(p1), 0);
	TEST_పూర్తి();

	TEST_ప్రారంభం("available on fresh buffer");
	ASSERT_కొలత_T_GT(sshbuf_avail(p1), 0);
	TEST_పూర్తి();

	TEST_ప్రారంభం("len = 0 on empty buffer");
	ASSERT_కొలత_T_EQ(sshbuf_len(p1), 0);
	TEST_పూర్తి();

	TEST_ప్రారంభం("set valid max size");
	ASSERT_INT_EQ(sshbuf_సమితి_max_కొలత(p1, 65536), 0);
	ASSERT_కొలత_T_EQ(sshbuf_max_కొలత(p1), 65536);
	TEST_పూర్తి();

	TEST_ప్రారంభం("available on limited buffer");
	ASSERT_కొలత_T_EQ(sshbuf_avail(p1), 65536);
	TEST_పూర్తి();

	TEST_ప్రారంభం("free");
	sshbuf_free(p1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("consume on empty buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_consume(p1, 0), 0);
	ASSERT_INT_EQ(sshbuf_consume(p1, 1), SSH_ERR_సందేశం_INCOMPLETE);
	sshbuf_free(p1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("consume_end on empty buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_consume_చివర(p1, 0), 0);
	ASSERT_INT_EQ(sshbuf_consume_చివర(p1, 1), SSH_ERR_సందేశం_INCOMPLETE);
	sshbuf_free(p1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("reserve space");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ఖాళీ);
	r = sshbuf_reserve(p1, 1, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, ఖాళీ);
	*dp = 0x11;
	r = sshbuf_reserve(p1, 3, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, ఖాళీ);
	*dp++ = 0x22;
	*dp++ = 0x33;
	*dp++ = 0x44;
	TEST_పూర్తి();

	TEST_ప్రారంభం("sshbuf_len on filled buffer");
	ASSERT_కొలత_T_EQ(sshbuf_len(p1), 4);
	TEST_పూర్తి();

	TEST_ప్రారంభం("sshbuf_ptr on filled buffer");
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(cdp, ఖాళీ);
	ASSERT_U8_EQ(cdp[0], 0x11);
	ASSERT_U8_EQ(cdp[1], 0x22);
	ASSERT_U8_EQ(cdp[2], 0x33);
	ASSERT_U8_EQ(cdp[3], 0x44);
	TEST_పూర్తి();

	TEST_ప్రారంభం("consume on filled buffer");
	ASSERT_కొలత_T_EQ(sshbuf_len(p1), 4);
	ASSERT_INT_EQ(sshbuf_consume(p1, 0), 0);
	ASSERT_కొలత_T_EQ(sshbuf_len(p1), 4);
	r = sshbuf_consume(p1, 64);
	ASSERT_INT_EQ(r, SSH_ERR_సందేశం_INCOMPLETE);
	ASSERT_కొలత_T_EQ(sshbuf_len(p1), 4);
	ASSERT_INT_EQ(sshbuf_consume(p1, 1), 0);
	ASSERT_కొలత_T_EQ(sshbuf_len(p1), 3);
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(p1, ఖాళీ);
	ASSERT_U8_EQ(cdp[0], 0x22);
	ASSERT_INT_EQ(sshbuf_consume(p1, 2), 0);
	ASSERT_కొలత_T_EQ(sshbuf_len(p1), 1);
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(p1, ఖాళీ);
	ASSERT_U8_EQ(cdp[0], 0x44);
	r = sshbuf_consume(p1, 2);
	ASSERT_INT_EQ(r, SSH_ERR_సందేశం_INCOMPLETE);
	ASSERT_కొలత_T_EQ(sshbuf_len(p1), 1);
	ASSERT_INT_EQ(sshbuf_consume(p1, 1), 0);
	ASSERT_కొలత_T_EQ(sshbuf_len(p1), 0);
	r = sshbuf_consume(p1, 1);
	ASSERT_INT_EQ(r, SSH_ERR_సందేశం_INCOMPLETE);
	sshbuf_free(p1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("consume_end on filled buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ఖాళీ);
	r = sshbuf_reserve(p1, 4, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, ఖాళీ);
	*dp++ = 0x11;
	*dp++ = 0x22;
	*dp++ = 0x33;
	*dp++ = 0x44;
	ASSERT_కొలత_T_EQ(sshbuf_len(p1), 4);
	r = sshbuf_consume_చివర(p1, 5);
	ASSERT_INT_EQ(r, SSH_ERR_సందేశం_INCOMPLETE);
	ASSERT_కొలత_T_EQ(sshbuf_len(p1), 4);
	ASSERT_INT_EQ(sshbuf_consume_చివర(p1, 3), 0);
	ASSERT_కొలత_T_EQ(sshbuf_len(p1), 1);
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(cdp, ఖాళీ);
	ASSERT_U8_EQ(*cdp, 0x11);
	r = sshbuf_consume_చివర(p1, 2);
	ASSERT_INT_EQ(r, SSH_ERR_సందేశం_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_consume_చివర(p1, 1), 0);
	ASSERT_కొలత_T_EQ(sshbuf_len(p1), 0);
	sshbuf_free(p1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("fill limited buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_సమితి_max_కొలత(p1, 1223), 0);
	ASSERT_కొలత_T_EQ(sshbuf_max_కొలత(p1), 1223);
	ASSERT_కొలత_T_EQ(sshbuf_avail(p1), 1223);
	r = sshbuf_reserve(p1, 1223, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, ఖాళీ);
	memset(dp, 0xd7, 1223);
	ASSERT_కొలత_T_EQ(sshbuf_len(p1), 1223);
	ASSERT_కొలత_T_EQ(sshbuf_avail(p1), 0);
	r = sshbuf_reserve(p1, 1, &dp);
	ASSERT_INT_EQ(r, SSH_ERR_NO_బఫరు_SPACE);
	ASSERT_PTR_EQ(dp, ఖాళీ);
	TEST_పూర్తి();

	TEST_ప్రారంభం("consume and force compaction");
	ASSERT_INT_EQ(sshbuf_consume(p1, 223), 0);
	ASSERT_కొలత_T_EQ(sshbuf_len(p1), 1000);
	ASSERT_కొలత_T_EQ(sshbuf_avail(p1), 223);
	r = sshbuf_reserve(p1, 224, &dp);
	ASSERT_INT_EQ(r, SSH_ERR_NO_బఫరు_SPACE);
	ASSERT_PTR_EQ(dp, ఖాళీ);
	ASSERT_కొలత_T_EQ(sshbuf_len(p1), 1000);
	ASSERT_కొలత_T_EQ(sshbuf_avail(p1), 223);
	r = sshbuf_reserve(p1, 223, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, ఖాళీ);
	memset(dp, 0x7d, 223);
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(cdp, ఖాళీ);
	ASSERT_MEM_FILLED_EQ(cdp, 0xd7, 1000);
	ASSERT_MEM_FILLED_EQ(cdp + 1000, 0x7d, 223);
	TEST_పూర్తి();

	TEST_ప్రారంభం("resize full buffer");
	r = sshbuf_సమితి_max_కొలత(p1, 1000);
	ASSERT_INT_EQ(r, SSH_ERR_NO_బఫరు_SPACE);
	sz = roundup(1223 + SSHBUF_కొలత_INC * 3, SSHBUF_కొలత_INC);
	ASSERT_INT_EQ(sshbuf_సమితి_max_కొలత(p1, sz), 0);
	ASSERT_కొలత_T_EQ(sshbuf_max_కొలత(p1), sz);
	ASSERT_కొలత_T_EQ(sshbuf_avail(p1), sz - 1223);
	ASSERT_INT_EQ(sshbuf_len(p1), 1223);
	TEST_పూర్తి();

	/* NB. uses sshbuf internals */
	TEST_ప్రారంభం("alloc chunking");
	r = sshbuf_reserve(p1, 1, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, ఖాళీ);
	*dp = 0xff;
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(cdp, ఖాళీ);
	ASSERT_MEM_FILLED_EQ(cdp, 0xd7, 1000);
	ASSERT_MEM_FILLED_EQ(cdp + 1000, 0x7d, 223);
	ASSERT_MEM_FILLED_EQ(cdp + 1223, 0xff, 1);
	ASSERT_కొలత_T_EQ(sshbuf_alloc(p1) % SSHBUF_కొలత_INC, 0);
	sshbuf_free(p1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("reset buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_సమితి_max_కొలత(p1, 1223), 0);
	ASSERT_కొలత_T_EQ(sshbuf_max_కొలత(p1), 1223);
	r = sshbuf_reserve(p1, 1223, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, ఖాళీ);
	memset(dp, 0xd7, 1223);
	ASSERT_కొలత_T_EQ(sshbuf_len(p1), 1223);
	sshbuf_reset(p1);
	ASSERT_కొలత_T_EQ(sshbuf_max_కొలత(p1), 1223);
	ASSERT_కొలత_T_EQ(sshbuf_len(p1), 0);
	ASSERT_కొలత_T_EQ(sshbuf_avail(p1), 1223);
	sshbuf_free(p1);
	TEST_పూర్తి();

	TEST_ప్రారంభం("sshbuf_consume_upto_child");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ఖాళీ);
	p2 = sshbuf_new();
	ASSERT_PTR_NE(p2, ఖాళీ);
	/* Unrelated buffers */
	ASSERT_INT_EQ(sshbuf_consume_upto_బిడ్డ(p1, p2),
	    SSH_ERR_INVALID_వాదం);
	/* Simple success case */
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0xdeadbeef), 0);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x01020304), 0);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0xfeedface), 0);
	ASSERT_కొలత_T_EQ(sshbuf_len(p1), 12);
	p3 = sshbuf_fromb(p1);
	ASSERT_PTR_NE(p3, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_get_u32(p3, &v32), 0);
	ASSERT_U32_EQ(v32, 0xdeadbeef);
	ASSERT_కొలత_T_EQ(sshbuf_len(p3), 8);
	ASSERT_INT_EQ(sshbuf_consume_upto_బిడ్డ(p1, p3), 0);
	ASSERT_కొలత_T_EQ(sshbuf_len(p1), sshbuf_len(p3));
	ASSERT_PTR_EQ(sshbuf_ptr(p1), sshbuf_ptr(p3));
	sshbuf_free(p3);
	/* Parent already consumed past child */
	p3 = sshbuf_fromb(p1);
	ASSERT_PTR_NE(p3, ఖాళీ);
	ASSERT_INT_EQ(sshbuf_get_u32(p1, &v32), 0);
	ASSERT_U32_EQ(v32, 0x01020304);
	ASSERT_INT_EQ(sshbuf_consume_upto_బిడ్డ(p1, p3),
	    SSH_ERR_INVALID_వాదం);
	sshbuf_free(p1);
	sshbuf_free(p2);
	sshbuf_free(p3);
	TEST_పూర్తి();
}
