/* 	$OpenBSD: test_sshbuf.c,v 1.3 2025/12/30 00:12:58 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHBUF_ਅੰਦਰੂਨੀ 1	/* access internals for testing */
#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"

ਖਾਲੀ sshbuf_tests(ਖਾਲੀ);

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ roundup
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ roundup(x, y)   ((((x)+((y)-1))/(y))*(y))
#ਜੇ_ਅੰਤ

ਖਾਲੀ
sshbuf_tests(ਖਾਲੀ)
{
	ਬਣਤਰ sshbuf *p1, *p2, *p3;
	u_int v32;
	ਅਚਲ u_char *cdp;
	u_char *dp;
	ਮਾਪ_t sz;
	ਪੂਰਨ r;

	TEST_ਸ਼ੁਰੂ("allocate sshbuf");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("max size on fresh buffer");
	ASSERT_ਮਾਪ_T_GT(sshbuf_max_ਮਾਪ(p1), 0);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("available on fresh buffer");
	ASSERT_ਮਾਪ_T_GT(sshbuf_avail(p1), 0);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("len = 0 on empty buffer");
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 0);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("set valid max size");
	ASSERT_INT_EQ(sshbuf_ਸੈੱਟ_max_ਮਾਪ(p1, 65536), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_max_ਮਾਪ(p1), 65536);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("available on limited buffer");
	ASSERT_ਮਾਪ_T_EQ(sshbuf_avail(p1), 65536);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("free");
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("consume on empty buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_consume(p1, 0), 0);
	ASSERT_INT_EQ(sshbuf_consume(p1, 1), SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("consume_end on empty buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_consume_ਸਿਰਾ(p1, 0), 0);
	ASSERT_INT_EQ(sshbuf_consume_ਸਿਰਾ(p1, 1), SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("reserve space");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	r = sshbuf_reserve(p1, 1, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, ਨਿਰਾ);
	*dp = 0x11;
	r = sshbuf_reserve(p1, 3, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, ਨਿਰਾ);
	*dp++ = 0x22;
	*dp++ = 0x33;
	*dp++ = 0x44;
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_len on filled buffer");
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 4);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_ptr on filled buffer");
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(cdp, ਨਿਰਾ);
	ASSERT_U8_EQ(cdp[0], 0x11);
	ASSERT_U8_EQ(cdp[1], 0x22);
	ASSERT_U8_EQ(cdp[2], 0x33);
	ASSERT_U8_EQ(cdp[3], 0x44);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("consume on filled buffer");
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 4);
	ASSERT_INT_EQ(sshbuf_consume(p1, 0), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 4);
	r = sshbuf_consume(p1, 64);
	ASSERT_INT_EQ(r, SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 4);
	ASSERT_INT_EQ(sshbuf_consume(p1, 1), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 3);
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_U8_EQ(cdp[0], 0x22);
	ASSERT_INT_EQ(sshbuf_consume(p1, 2), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 1);
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_U8_EQ(cdp[0], 0x44);
	r = sshbuf_consume(p1, 2);
	ASSERT_INT_EQ(r, SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 1);
	ASSERT_INT_EQ(sshbuf_consume(p1, 1), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 0);
	r = sshbuf_consume(p1, 1);
	ASSERT_INT_EQ(r, SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("consume_end on filled buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	r = sshbuf_reserve(p1, 4, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, ਨਿਰਾ);
	*dp++ = 0x11;
	*dp++ = 0x22;
	*dp++ = 0x33;
	*dp++ = 0x44;
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 4);
	r = sshbuf_consume_ਸਿਰਾ(p1, 5);
	ASSERT_INT_EQ(r, SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 4);
	ASSERT_INT_EQ(sshbuf_consume_ਸਿਰਾ(p1, 3), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 1);
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(cdp, ਨਿਰਾ);
	ASSERT_U8_EQ(*cdp, 0x11);
	r = sshbuf_consume_ਸਿਰਾ(p1, 2);
	ASSERT_INT_EQ(r, SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE);
	ASSERT_INT_EQ(sshbuf_consume_ਸਿਰਾ(p1, 1), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 0);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("fill limited buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_ਸੈੱਟ_max_ਮਾਪ(p1, 1223), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_max_ਮਾਪ(p1), 1223);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_avail(p1), 1223);
	r = sshbuf_reserve(p1, 1223, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, ਨਿਰਾ);
	memset(dp, 0xd7, 1223);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 1223);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_avail(p1), 0);
	r = sshbuf_reserve(p1, 1, &dp);
	ASSERT_INT_EQ(r, SSH_ERR_NO_ਬਫਰ_SPACE);
	ASSERT_PTR_EQ(dp, ਨਿਰਾ);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("consume and force compaction");
	ASSERT_INT_EQ(sshbuf_consume(p1, 223), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 1000);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_avail(p1), 223);
	r = sshbuf_reserve(p1, 224, &dp);
	ASSERT_INT_EQ(r, SSH_ERR_NO_ਬਫਰ_SPACE);
	ASSERT_PTR_EQ(dp, ਨਿਰਾ);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 1000);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_avail(p1), 223);
	r = sshbuf_reserve(p1, 223, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, ਨਿਰਾ);
	memset(dp, 0x7d, 223);
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(cdp, ਨਿਰਾ);
	ASSERT_MEM_FILLED_EQ(cdp, 0xd7, 1000);
	ASSERT_MEM_FILLED_EQ(cdp + 1000, 0x7d, 223);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("resize full buffer");
	r = sshbuf_ਸੈੱਟ_max_ਮਾਪ(p1, 1000);
	ASSERT_INT_EQ(r, SSH_ERR_NO_ਬਫਰ_SPACE);
	sz = roundup(1223 + SSHBUF_ਮਾਪ_INC * 3, SSHBUF_ਮਾਪ_INC);
	ASSERT_INT_EQ(sshbuf_ਸੈੱਟ_max_ਮਾਪ(p1, sz), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_max_ਮਾਪ(p1), sz);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_avail(p1), sz - 1223);
	ASSERT_INT_EQ(sshbuf_len(p1), 1223);
	TEST_ਪੂਰਾ();

	/* NB. uses sshbuf internals */
	TEST_ਸ਼ੁਰੂ("alloc chunking");
	r = sshbuf_reserve(p1, 1, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, ਨਿਰਾ);
	*dp = 0xff;
	cdp = sshbuf_ptr(p1);
	ASSERT_PTR_NE(cdp, ਨਿਰਾ);
	ASSERT_MEM_FILLED_EQ(cdp, 0xd7, 1000);
	ASSERT_MEM_FILLED_EQ(cdp + 1000, 0x7d, 223);
	ASSERT_MEM_FILLED_EQ(cdp + 1223, 0xff, 1);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_alloc(p1) % SSHBUF_ਮਾਪ_INC, 0);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("reset buffer");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_ਸੈੱਟ_max_ਮਾਪ(p1, 1223), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_max_ਮਾਪ(p1), 1223);
	r = sshbuf_reserve(p1, 1223, &dp);
	ASSERT_INT_EQ(r, 0);
	ASSERT_PTR_NE(dp, ਨਿਰਾ);
	memset(dp, 0xd7, 1223);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 1223);
	sshbuf_reset(p1);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_max_ਮਾਪ(p1), 1223);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_avail(p1), 1223);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_consume_upto_child");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	p2 = sshbuf_new();
	ASSERT_PTR_NE(p2, ਨਿਰਾ);
	/* Unrelated buffers */
	ASSERT_INT_EQ(sshbuf_consume_upto_ਬੱਚਾ(p1, p2),
	    SSH_ERR_INVALID_ਦਲੀਲ);
	/* Simple success case */
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0xdeadbeef), 0);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x01020304), 0);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0xfeedface), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 12);
	p3 = sshbuf_fromb(p1);
	ASSERT_PTR_NE(p3, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_get_u32(p3, &v32), 0);
	ASSERT_U32_EQ(v32, 0xdeadbeef);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p3), 8);
	ASSERT_INT_EQ(sshbuf_consume_upto_ਬੱਚਾ(p1, p3), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), sshbuf_len(p3));
	ASSERT_PTR_EQ(sshbuf_ptr(p1), sshbuf_ptr(p3));
	sshbuf_free(p3);
	/* Parent already consumed past child */
	p3 = sshbuf_fromb(p1);
	ASSERT_PTR_NE(p3, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_get_u32(p1, &v32), 0);
	ASSERT_U32_EQ(v32, 0x01020304);
	ASSERT_INT_EQ(sshbuf_consume_upto_ਬੱਚਾ(p1, p3),
	    SSH_ERR_INVALID_ਦਲੀਲ);
	sshbuf_free(p1);
	sshbuf_free(p2);
	sshbuf_free(p3);
	TEST_ਪੂਰਾ();
}
