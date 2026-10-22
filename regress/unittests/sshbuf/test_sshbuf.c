/* 	$OpenBSD: test_sshbuf.c,v 1.3 2025/12/30 00:12:58 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#تعریف_کن SSHBUF_داخلی 1	/* access internals for testing */
#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن "../test_helper/test_helper.h"

#ضمن "ssherr.h"
#ضمن "sshbuf.h"

فراغ sshbuf_tests(فراغ);

#اگر_تعریف_نشده roundup
#تعریف_کن roundup(x, y)   ((((x)+((y)-1))/(y))*(y))
#پایان_اگر

فراغ
sshbuf_tests(فراغ)
{
	بنية sshbuf *p1, *p2, *p3;
	u_int v32;
	ثابت u_char *cdp;
	u_char *dp;
	اندازه_t sz;
	صحيح r;

	TEST_شروع("allocate sshbuf");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, عدم);
	TEST_انجامشده();

	TEST_شروع("max size on fresh buffer");
	ASSERT_اندازه_T_GT(sshbuf_max_اندازه(p1), 0);
	TEST_انجامشده();

	TEST_شروع("available on fresh buffer");
	ASSERT_اندازه_T_GT(sshbuf_avail(p1), 0);
	TEST_انجامشده();

	TEST_شروع("len = 0 on empty buffer");
	ASSERT_اندازه_T_EQ(sshbuf_len(p1), 0);
	TEST_انجامشده();

	TEST_شروع("set valid max size");
	ASSERT_INT_EQ(sshbuf_مجموعه_max_اندازه(p1, 65536), 0);
	ASSERT_اندازه_T_EQ(sshbuf_max_اندازه(p1), 65536);
	TEST_انجامشده();

	TEST_شروع("available on limited buffer");
	ASSERT_اندازه_T_EQ(sshbuf_avail(p1), 65536);
	TEST_انجامشده();

	TEST_شروع("free");
	sshbuf_free(p1);
	TEST_انجامشده();

	TEST_شروع("consume on empty buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, عدم);
	ASSERT_INT_EQ(sshbuf_consume(p1, 0), 0);
	ASSERT_INT_EQ(sshbuf_consume(p1, 1), SSH_ERR_پیام_INCOMPLETE);
	sshbuf_free(p1);
	TEST_انجامشده();

	TEST_شروع("consume_end on empty buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, عدم);
	ASSERT_INT_EQ(sshbuf_consume_انتها(p1, 0), 0);
	ASSERT_INT_EQ(sshbuf_consume_انتها(p1, 1), SSH_ERR_پیام_INCOMPLETE);
	sshbuf_free(p1);
	TEST_انجامشده();

	TEST_شروع("reserve space");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, عدم);
	r = sshbuf_reserve(p1, 1, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, عدم);
	*dp = 0x11;
	r = sshbuf_reserve(p1, 3, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, عدم);
	*dp++ = 0x22;
	*dp++ = 0x33;
	*dp++ = 0x44;
	TEST_انجامشده();

	TEST_شروع("sshbuf_len on filled buffer");
	ASSERT_اندازه_T_EQ(sshbuf_len(p1), 4);
	TEST_انجامشده();

	TEST_شروع("sshbuf_ptr on filled buffer");
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(cdp, عدم);
	ASSERT_U8_EQ(cdp[0], 0x11);
	ASSERT_U8_EQ(cdp[1], 0x22);
	ASSERT_U8_EQ(cdp[2], 0x33);
	ASSERT_U8_EQ(cdp[3], 0x44);
	TEST_انجامشده();

	TEST_شروع("consume on filled buffer");
	ASSERT_اندازه_T_EQ(sshbuf_len(p1), 4);
	ASSERT_INT_EQ(sshbuf_consume(p1, 0), 0);
	ASSERT_اندازه_T_EQ(sshbuf_len(p1), 4);
	r = sshbuf_consume(p1, 64);
	ASSERT_INT_EQ(r, SSH_ERR_پیام_INCOMPLETE);
	ASSERT_اندازه_T_EQ(sshbuf_len(p1), 4);
	ASSERT_INT_EQ(sshbuf_consume(p1, 1), 0);
	ASSERT_اندازه_T_EQ(sshbuf_len(p1), 3);
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(p1, عدم);
	ASSERT_U8_EQ(cdp[0], 0x22);
	ASSERT_INT_EQ(sshbuf_consume(p1, 2), 0);
	ASSERT_اندازه_T_EQ(sshbuf_len(p1), 1);
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(p1, عدم);
	ASSERT_U8_EQ(cdp[0], 0x44);
	r = sshbuf_consume(p1, 2);
	ASSERT_INT_EQ(r, SSH_ERR_پیام_INCOMPLETE);
	ASSERT_اندازه_T_EQ(sshbuf_len(p1), 1);
	ASSERT_INT_EQ(sshbuf_consume(p1, 1), 0);
	ASSERT_اندازه_T_EQ(sshbuf_len(p1), 0);
	r = sshbuf_consume(p1, 1);
	ASSERT_INT_EQ(r, SSH_ERR_پیام_INCOMPLETE);
	sshbuf_free(p1);
	TEST_انجامشده();

	TEST_شروع("consume_end on filled buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, عدم);
	r = sshbuf_reserve(p1, 4, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, عدم);
	*dp++ = 0x11;
	*dp++ = 0x22;
	*dp++ = 0x33;
	*dp++ = 0x44;
	ASSERT_اندازه_T_EQ(sshbuf_len(p1), 4);
	r = sshbuf_consume_انتها(p1, 5);
	ASSERT_INT_EQ(r, SSH_ERR_پیام_INCOMPLETE);
	ASSERT_اندازه_T_EQ(sshbuf_len(p1), 4);
	ASSERT_INT_EQ(sshbuf_consume_انتها(p1, 3), 0);
	ASSERT_اندازه_T_EQ(sshbuf_len(p1), 1);
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(cdp, عدم);
	ASSERT_U8_EQ(*cdp, 0x11);
	r = sshbuf_consume_انتها(p1, 2);
	ASSERT_INT_EQ(r, SSH_ERR_پیام_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_consume_انتها(p1, 1), 0);
	ASSERT_اندازه_T_EQ(sshbuf_len(p1), 0);
	sshbuf_free(p1);
	TEST_انجامشده();

	TEST_شروع("fill limited buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, عدم);
	ASSERT_INT_EQ(sshbuf_مجموعه_max_اندازه(p1, 1223), 0);
	ASSERT_اندازه_T_EQ(sshbuf_max_اندازه(p1), 1223);
	ASSERT_اندازه_T_EQ(sshbuf_avail(p1), 1223);
	r = sshbuf_reserve(p1, 1223, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, عدم);
	memset(dp, 0xd7, 1223);
	ASSERT_اندازه_T_EQ(sshbuf_len(p1), 1223);
	ASSERT_اندازه_T_EQ(sshbuf_avail(p1), 0);
	r = sshbuf_reserve(p1, 1, &dp);
	ASSERT_INT_EQ(r, SSH_ERR_NO_میانگیر_SPACE);
	ASSERT_PTR_EQ(dp, عدم);
	TEST_انجامشده();

	TEST_شروع("consume and force compaction");
	ASSERT_INT_EQ(sshbuf_consume(p1, 223), 0);
	ASSERT_اندازه_T_EQ(sshbuf_len(p1), 1000);
	ASSERT_اندازه_T_EQ(sshbuf_avail(p1), 223);
	r = sshbuf_reserve(p1, 224, &dp);
	ASSERT_INT_EQ(r, SSH_ERR_NO_میانگیر_SPACE);
	ASSERT_PTR_EQ(dp, عدم);
	ASSERT_اندازه_T_EQ(sshbuf_len(p1), 1000);
	ASSERT_اندازه_T_EQ(sshbuf_avail(p1), 223);
	r = sshbuf_reserve(p1, 223, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, عدم);
	memset(dp, 0x7d, 223);
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(cdp, عدم);
	ASSERT_MEM_FILLED_EQ(cdp, 0xd7, 1000);
	ASSERT_MEM_FILLED_EQ(cdp + 1000, 0x7d, 223);
	TEST_انجامشده();

	TEST_شروع("resize full buffer");
	r = sshbuf_مجموعه_max_اندازه(p1, 1000);
	ASSERT_INT_EQ(r, SSH_ERR_NO_میانگیر_SPACE);
	sz = roundup(1223 + SSHBUF_اندازه_INC * 3, SSHBUF_اندازه_INC);
	ASSERT_INT_EQ(sshbuf_مجموعه_max_اندازه(p1, sz), 0);
	ASSERT_اندازه_T_EQ(sshbuf_max_اندازه(p1), sz);
	ASSERT_اندازه_T_EQ(sshbuf_avail(p1), sz - 1223);
	ASSERT_INT_EQ(sshbuf_len(p1), 1223);
	TEST_انجامشده();

	/* NB. uses sshbuf internals */
	TEST_شروع("alloc chunking");
	r = sshbuf_reserve(p1, 1, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, عدم);
	*dp = 0xff;
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(cdp, عدم);
	ASSERT_MEM_FILLED_EQ(cdp, 0xd7, 1000);
	ASSERT_MEM_FILLED_EQ(cdp + 1000, 0x7d, 223);
	ASSERT_MEM_FILLED_EQ(cdp + 1223, 0xff, 1);
	ASSERT_اندازه_T_EQ(sshbuf_alloc(p1) % SSHBUF_اندازه_INC, 0);
	sshbuf_free(p1);
	TEST_انجامشده();

	TEST_شروع("reset buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, عدم);
	ASSERT_INT_EQ(sshbuf_مجموعه_max_اندازه(p1, 1223), 0);
	ASSERT_اندازه_T_EQ(sshbuf_max_اندازه(p1), 1223);
	r = sshbuf_reserve(p1, 1223, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, عدم);
	memset(dp, 0xd7, 1223);
	ASSERT_اندازه_T_EQ(sshbuf_len(p1), 1223);
	sshbuf_reset(p1);
	ASSERT_اندازه_T_EQ(sshbuf_max_اندازه(p1), 1223);
	ASSERT_اندازه_T_EQ(sshbuf_len(p1), 0);
	ASSERT_اندازه_T_EQ(sshbuf_avail(p1), 1223);
	sshbuf_free(p1);
	TEST_انجامشده();

	TEST_شروع("sshbuf_consume_upto_child");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, عدم);
	p2 = sshbuf_new();
	ASSERT_PTR_NE(p2, عدم);
	/* Unrelated buffers */
	ASSERT_INT_EQ(sshbuf_consume_upto_فرزند(p1, p2),
	    SSH_ERR_INVALID_آرگومان);
	/* Simple success case */
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0xdeadbeef), 0);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x01020304), 0);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0xfeedface), 0);
	ASSERT_اندازه_T_EQ(sshbuf_len(p1), 12);
	p3 = sshbuf_fromb(p1);
	ASSERT_PTR_NE(p3, عدم);
	ASSERT_INT_EQ(sshbuf_get_u32(p3, &v32), 0);
	ASSERT_U32_EQ(v32, 0xdeadbeef);
	ASSERT_اندازه_T_EQ(sshbuf_len(p3), 8);
	ASSERT_INT_EQ(sshbuf_consume_upto_فرزند(p1, p3), 0);
	ASSERT_اندازه_T_EQ(sshbuf_len(p1), sshbuf_len(p3));
	ASSERT_PTR_EQ(sshbuf_ptr(p1), sshbuf_ptr(p3));
	sshbuf_free(p3);
	/* Parent already consumed past child */
	p3 = sshbuf_fromb(p1);
	ASSERT_PTR_NE(p3, عدم);
	ASSERT_INT_EQ(sshbuf_get_u32(p1, &v32), 0);
	ASSERT_U32_EQ(v32, 0x01020304);
	ASSERT_INT_EQ(sshbuf_consume_upto_فرزند(p1, p3),
	    SSH_ERR_INVALID_آرگومان);
	sshbuf_free(p1);
	sshbuf_free(p2);
	sshbuf_free(p3);
	TEST_انجامشده();
}
