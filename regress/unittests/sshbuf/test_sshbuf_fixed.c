/* 	$OpenBSD: test_sshbuf_fixed.c,v 1.2 2021/12/14 21:25:27 deraadt Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#define SSHBUF_INTERNAL 1  /* access internals for testing */
#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

#অন্তর্ভাব "../test_helper/test_helper.h"

#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssherr.h"

শূন্য sshbuf_fixed(শূন্য);

ধ্রুবক u_char test_buf[] = "\x01\x12\x34\x56\x78\x00\x00\x00\x05hello";

শূন্য
sshbuf_fixed(শূন্য)
{
	কাঠামো sshbuf *p1, *p2, *p3;
	u_char c;
	অক্ষর *s;
	u_int i;
	আকার_t l;

	TEST_START("sshbuf_from");
	p1 = sshbuf_from(test_buf, আকার(test_buf));
	ASSERT_PTR_NE(p1, ফাঁকা);
	ASSERT_PTR_EQ(sshbuf_mutable_ptr(p1), ফাঁকা);
	ASSERT_INT_EQ(sshbuf_check_reserve(p1, 1), SSH_ERR_বাফার_READ_ONLY);
	ASSERT_INT_EQ(sshbuf_reserve(p1, 1, ফাঁকা), SSH_ERR_বাফার_READ_ONLY);
	ASSERT_INT_EQ(sshbuf_set_max_আকার(p1, 200), SSH_ERR_বাফার_READ_ONLY);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x12345678), SSH_ERR_বাফার_READ_ONLY);
	ASSERT_আকার_T_EQ(sshbuf_avail(p1), 0);
	ASSERT_PTR_EQ(sshbuf_ptr(p1), test_buf);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_from data");
	p1 = sshbuf_from(test_buf, আকার(test_buf) - 1);
	ASSERT_PTR_NE(p1, ফাঁকা);
	ASSERT_PTR_EQ(sshbuf_ptr(p1), test_buf);
	ASSERT_INT_EQ(sshbuf_get_u8(p1, &c), 0);
	ASSERT_PTR_EQ(sshbuf_ptr(p1), test_buf + 1);
	ASSERT_U8_EQ(c, 1);
	ASSERT_INT_EQ(sshbuf_get_u32(p1, &i), 0);
	ASSERT_PTR_EQ(sshbuf_ptr(p1), test_buf + 5);
	ASSERT_U32_EQ(i, 0x12345678);
	ASSERT_INT_EQ(sshbuf_get_cstring(p1, &s, &l), 0);
	ASSERT_আকার_T_EQ(sshbuf_len(p1), 0);
	ASSERT_STRING_EQ(s, "hello");
	ASSERT_আকার_T_EQ(l, 5);
	sshbuf_free(p1);
	মুক্ত(s);
	TEST_DONE();

	TEST_START("sshbuf_fromb ");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ফাঁকা);
	ASSERT_U_INT_EQ(sshbuf_refcount(p1), 1);
	ASSERT_PTR_EQ(sshbuf_parent(p1), ফাঁকা);
	ASSERT_INT_EQ(sshbuf_put(p1, test_buf, আকার(test_buf) - 1), 0);
	p2 = sshbuf_fromb(p1);
	ASSERT_PTR_NE(p2, ফাঁকা);
	ASSERT_U_INT_EQ(sshbuf_refcount(p1), 2);
	ASSERT_PTR_EQ(sshbuf_parent(p1), ফাঁকা);
	ASSERT_PTR_EQ(sshbuf_parent(p2), p1);
	ASSERT_PTR_EQ(sshbuf_ptr(p2), sshbuf_ptr(p1));
	ASSERT_PTR_NE(sshbuf_ptr(p1), ফাঁকা);
	ASSERT_PTR_NE(sshbuf_ptr(p2), ফাঁকা);
	ASSERT_PTR_EQ(sshbuf_mutable_ptr(p1), ফাঁকা);
	ASSERT_PTR_EQ(sshbuf_mutable_ptr(p2), ফাঁকা);
	ASSERT_আকার_T_EQ(sshbuf_len(p1), sshbuf_len(p2));
	ASSERT_INT_EQ(sshbuf_get_u8(p2, &c), 0);
	ASSERT_PTR_EQ(sshbuf_ptr(p2), sshbuf_ptr(p1) + 1);
	ASSERT_U8_EQ(c, 1);
	ASSERT_INT_EQ(sshbuf_get_u32(p2, &i), 0);
	ASSERT_PTR_EQ(sshbuf_ptr(p2), sshbuf_ptr(p1) + 5);
	ASSERT_U32_EQ(i, 0x12345678);
	ASSERT_INT_EQ(sshbuf_get_cstring(p2, &s, &l), 0);
	ASSERT_আকার_T_EQ(sshbuf_len(p2), 0);
	ASSERT_STRING_EQ(s, "hello");
	ASSERT_আকার_T_EQ(l, 5);
	sshbuf_free(p1);
	ASSERT_U_INT_EQ(sshbuf_refcount(p1), 1);
	sshbuf_free(p2);
	মুক্ত(s);
	TEST_DONE();

	TEST_START("sshbuf_froms");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ফাঁকা);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x01), 0);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x12345678), 0);
	ASSERT_INT_EQ(sshbuf_put_cstring(p1, "hello"), 0);
	p2 = sshbuf_new();
	ASSERT_PTR_NE(p2, ফাঁকা);
	ASSERT_আকার_T_EQ(sshbuf_len(p1), আকার(test_buf) - 1);
	ASSERT_INT_EQ(sshbuf_put_stringb(p2, p1), 0);
	ASSERT_আকার_T_EQ(sshbuf_len(p2), আকার(test_buf) + 4 - 1);
	ASSERT_INT_EQ(sshbuf_froms(p2, &p3), 0);
	ASSERT_আকার_T_EQ(sshbuf_len(p2), 0);
	ASSERT_PTR_NE(p3, ফাঁকা);
	ASSERT_PTR_NE(sshbuf_ptr(p3), ফাঁকা);
	ASSERT_আকার_T_EQ(sshbuf_len(p3), আকার(test_buf) - 1);
	ASSERT_MEM_EQ(sshbuf_ptr(p3), test_buf, আকার(test_buf) - 1);
	sshbuf_free(p3);
	ASSERT_INT_EQ(sshbuf_put_stringb(p2, p1), 0);
	ASSERT_INT_EQ(sshbuf_consume_end(p2, 1), 0);
	ASSERT_INT_EQ(sshbuf_froms(p2, &p3), SSH_ERR_MESSAGE_INCOMPLETE);
	ASSERT_PTR_EQ(p3, ফাঁকা);
	sshbuf_free(p2);
	sshbuf_free(p1);
}
