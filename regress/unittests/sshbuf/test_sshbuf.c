/* 	$OpenBSD: test_sshbuf.c,v 1.3 2025/12/30 00:12:58 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#تعریف_کرو SSHBUF_اندرونی 1	/* access internals for testing */
#شامل "includes.h"

#شامل <sys/types.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>

#شامل "../test_helper/test_helper.h"

#شامل "ssherr.h"
#شامل "sshbuf.h"

خالی sshbuf_tests(خالی);

#اگر_غیر_تعریف_شدہ roundup
#تعریف_کرو roundup(x, y)   ((((x)+((y)-1))/(y))*(y))
#اگر_ختم

خالی
sshbuf_tests(خالی)
{
	ساخت sshbuf *p1, *p2, *p3;
	u_int v32;
	ثابت u_char *cdp;
	u_char *dp;
	سائز_t sz;
	صحیح r;

	TEST_آغاز("allocate sshbuf");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, تہی);
	TEST_مکمل();

	TEST_آغاز("max size on fresh buffer");
	ASSERT_سائز_T_GT(sshbuf_max_سائز(p1), 0);
	TEST_مکمل();

	TEST_آغاز("available on fresh buffer");
	ASSERT_سائز_T_GT(sshbuf_avail(p1), 0);
	TEST_مکمل();

	TEST_آغاز("len = 0 on empty buffer");
	ASSERT_سائز_T_EQ(sshbuf_len(p1), 0);
	TEST_مکمل();

	TEST_آغاز("set valid max size");
	ASSERT_INT_EQ(sshbuf_سیٹ_max_سائز(p1, 65536), 0);
	ASSERT_سائز_T_EQ(sshbuf_max_سائز(p1), 65536);
	TEST_مکمل();

	TEST_آغاز("available on limited buffer");
	ASSERT_سائز_T_EQ(sshbuf_avail(p1), 65536);
	TEST_مکمل();

	TEST_آغاز("free");
	sshbuf_free(p1);
	TEST_مکمل();

	TEST_آغاز("consume on empty buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, تہی);
	ASSERT_INT_EQ(sshbuf_consume(p1, 0), 0);
	ASSERT_INT_EQ(sshbuf_consume(p1, 1), SSH_ERR_پیغام_INCOMPLETE);
	sshbuf_free(p1);
	TEST_مکمل();

	TEST_آغاز("consume_end on empty buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, تہی);
	ASSERT_INT_EQ(sshbuf_consume_انتہا(p1, 0), 0);
	ASSERT_INT_EQ(sshbuf_consume_انتہا(p1, 1), SSH_ERR_پیغام_INCOMPLETE);
	sshbuf_free(p1);
	TEST_مکمل();

	TEST_آغاز("reserve space");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, تہی);
	r = sshbuf_reserve(p1, 1, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, تہی);
	*dp = 0x11;
	r = sshbuf_reserve(p1, 3, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, تہی);
	*dp++ = 0x22;
	*dp++ = 0x33;
	*dp++ = 0x44;
	TEST_مکمل();

	TEST_آغاز("sshbuf_len on filled buffer");
	ASSERT_سائز_T_EQ(sshbuf_len(p1), 4);
	TEST_مکمل();

	TEST_آغاز("sshbuf_ptr on filled buffer");
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(cdp, تہی);
	ASSERT_U8_EQ(cdp[0], 0x11);
	ASSERT_U8_EQ(cdp[1], 0x22);
	ASSERT_U8_EQ(cdp[2], 0x33);
	ASSERT_U8_EQ(cdp[3], 0x44);
	TEST_مکمل();

	TEST_آغاز("consume on filled buffer");
	ASSERT_سائز_T_EQ(sshbuf_len(p1), 4);
	ASSERT_INT_EQ(sshbuf_consume(p1, 0), 0);
	ASSERT_سائز_T_EQ(sshbuf_len(p1), 4);
	r = sshbuf_consume(p1, 64);
	ASSERT_INT_EQ(r, SSH_ERR_پیغام_INCOMPLETE);
	ASSERT_سائز_T_EQ(sshbuf_len(p1), 4);
	ASSERT_INT_EQ(sshbuf_consume(p1, 1), 0);
	ASSERT_سائز_T_EQ(sshbuf_len(p1), 3);
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(p1, تہی);
	ASSERT_U8_EQ(cdp[0], 0x22);
	ASSERT_INT_EQ(sshbuf_consume(p1, 2), 0);
	ASSERT_سائز_T_EQ(sshbuf_len(p1), 1);
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(p1, تہی);
	ASSERT_U8_EQ(cdp[0], 0x44);
	r = sshbuf_consume(p1, 2);
	ASSERT_INT_EQ(r, SSH_ERR_پیغام_INCOMPLETE);
	ASSERT_سائز_T_EQ(sshbuf_len(p1), 1);
	ASSERT_INT_EQ(sshbuf_consume(p1, 1), 0);
	ASSERT_سائز_T_EQ(sshbuf_len(p1), 0);
	r = sshbuf_consume(p1, 1);
	ASSERT_INT_EQ(r, SSH_ERR_پیغام_INCOMPLETE);
	sshbuf_free(p1);
	TEST_مکمل();

	TEST_آغاز("consume_end on filled buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, تہی);
	r = sshbuf_reserve(p1, 4, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, تہی);
	*dp++ = 0x11;
	*dp++ = 0x22;
	*dp++ = 0x33;
	*dp++ = 0x44;
	ASSERT_سائز_T_EQ(sshbuf_len(p1), 4);
	r = sshbuf_consume_انتہا(p1, 5);
	ASSERT_INT_EQ(r, SSH_ERR_پیغام_INCOMPLETE);
	ASSERT_سائز_T_EQ(sshbuf_len(p1), 4);
	ASSERT_INT_EQ(sshbuf_consume_انتہا(p1, 3), 0);
	ASSERT_سائز_T_EQ(sshbuf_len(p1), 1);
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(cdp, تہی);
	ASSERT_U8_EQ(*cdp, 0x11);
	r = sshbuf_consume_انتہا(p1, 2);
	ASSERT_INT_EQ(r, SSH_ERR_پیغام_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_consume_انتہا(p1, 1), 0);
	ASSERT_سائز_T_EQ(sshbuf_len(p1), 0);
	sshbuf_free(p1);
	TEST_مکمل();

	TEST_آغاز("fill limited buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, تہی);
	ASSERT_INT_EQ(sshbuf_سیٹ_max_سائز(p1, 1223), 0);
	ASSERT_سائز_T_EQ(sshbuf_max_سائز(p1), 1223);
	ASSERT_سائز_T_EQ(sshbuf_avail(p1), 1223);
	r = sshbuf_reserve(p1, 1223, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, تہی);
	memset(dp, 0xd7, 1223);
	ASSERT_سائز_T_EQ(sshbuf_len(p1), 1223);
	ASSERT_سائز_T_EQ(sshbuf_avail(p1), 0);
	r = sshbuf_reserve(p1, 1, &dp);
	ASSERT_INT_EQ(r, SSH_ERR_NO_بفر_SPACE);
	ASSERT_PTR_EQ(dp, تہی);
	TEST_مکمل();

	TEST_آغاز("consume and force compaction");
	ASSERT_INT_EQ(sshbuf_consume(p1, 223), 0);
	ASSERT_سائز_T_EQ(sshbuf_len(p1), 1000);
	ASSERT_سائز_T_EQ(sshbuf_avail(p1), 223);
	r = sshbuf_reserve(p1, 224, &dp);
	ASSERT_INT_EQ(r, SSH_ERR_NO_بفر_SPACE);
	ASSERT_PTR_EQ(dp, تہی);
	ASSERT_سائز_T_EQ(sshbuf_len(p1), 1000);
	ASSERT_سائز_T_EQ(sshbuf_avail(p1), 223);
	r = sshbuf_reserve(p1, 223, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, تہی);
	memset(dp, 0x7d, 223);
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(cdp, تہی);
	ASSERT_MEM_FILLED_EQ(cdp, 0xd7, 1000);
	ASSERT_MEM_FILLED_EQ(cdp + 1000, 0x7d, 223);
	TEST_مکمل();

	TEST_آغاز("resize full buffer");
	r = sshbuf_سیٹ_max_سائز(p1, 1000);
	ASSERT_INT_EQ(r, SSH_ERR_NO_بفر_SPACE);
	sz = roundup(1223 + SSHBUF_سائز_INC * 3, SSHBUF_سائز_INC);
	ASSERT_INT_EQ(sshbuf_سیٹ_max_سائز(p1, sz), 0);
	ASSERT_سائز_T_EQ(sshbuf_max_سائز(p1), sz);
	ASSERT_سائز_T_EQ(sshbuf_avail(p1), sz - 1223);
	ASSERT_INT_EQ(sshbuf_len(p1), 1223);
	TEST_مکمل();

	/* NB. uses sshbuf internals */
	TEST_آغاز("alloc chunking");
	r = sshbuf_reserve(p1, 1, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, تہی);
	*dp = 0xff;
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(cdp, تہی);
	ASSERT_MEM_FILLED_EQ(cdp, 0xd7, 1000);
	ASSERT_MEM_FILLED_EQ(cdp + 1000, 0x7d, 223);
	ASSERT_MEM_FILLED_EQ(cdp + 1223, 0xff, 1);
	ASSERT_سائز_T_EQ(sshbuf_alloc(p1) % SSHBUF_سائز_INC, 0);
	sshbuf_free(p1);
	TEST_مکمل();

	TEST_آغاز("reset buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, تہی);
	ASSERT_INT_EQ(sshbuf_سیٹ_max_سائز(p1, 1223), 0);
	ASSERT_سائز_T_EQ(sshbuf_max_سائز(p1), 1223);
	r = sshbuf_reserve(p1, 1223, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, تہی);
	memset(dp, 0xd7, 1223);
	ASSERT_سائز_T_EQ(sshbuf_len(p1), 1223);
	sshbuf_reset(p1);
	ASSERT_سائز_T_EQ(sshbuf_max_سائز(p1), 1223);
	ASSERT_سائز_T_EQ(sshbuf_len(p1), 0);
	ASSERT_سائز_T_EQ(sshbuf_avail(p1), 1223);
	sshbuf_free(p1);
	TEST_مکمل();

	TEST_آغاز("sshbuf_consume_upto_child");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, تہی);
	p2 = sshbuf_new();
	ASSERT_PTR_NE(p2, تہی);
	/* Unrelated buffers */
	ASSERT_INT_EQ(sshbuf_consume_upto_بچہ(p1, p2),
	    SSH_ERR_INVALID_دلیل);
	/* Simple success case */
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0xdeadbeef), 0);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x01020304), 0);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0xfeedface), 0);
	ASSERT_سائز_T_EQ(sshbuf_len(p1), 12);
	p3 = sshbuf_fromb(p1);
	ASSERT_PTR_NE(p3, تہی);
	ASSERT_INT_EQ(sshbuf_get_u32(p3, &v32), 0);
	ASSERT_U32_EQ(v32, 0xdeadbeef);
	ASSERT_سائز_T_EQ(sshbuf_len(p3), 8);
	ASSERT_INT_EQ(sshbuf_consume_upto_بچہ(p1, p3), 0);
	ASSERT_سائز_T_EQ(sshbuf_len(p1), sshbuf_len(p3));
	ASSERT_PTR_EQ(sshbuf_ptr(p1), sshbuf_ptr(p3));
	sshbuf_free(p3);
	/* Parent already consumed past child */
	p3 = sshbuf_fromb(p1);
	ASSERT_PTR_NE(p3, تہی);
	ASSERT_INT_EQ(sshbuf_get_u32(p1, &v32), 0);
	ASSERT_U32_EQ(v32, 0x01020304);
	ASSERT_INT_EQ(sshbuf_consume_upto_بچہ(p1, p3),
	    SSH_ERR_INVALID_دلیل);
	sshbuf_free(p1);
	sshbuf_free(p2);
	sshbuf_free(p3);
	TEST_مکمل();
}
