/* 	$OpenBSD: test_sshbuf_fixed.c,v 1.2 2021/12/14 21:25:27 deraadt Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#define SSHBUF_INTERNAL 1  /* access internals for testing */
#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "../test_helper/test_helper.h"

#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "ssherr.h"

வெறுமை sshbuf_fixed(வெறுமை);

மாறிலி u_char test_buf[] = "\x01\x12\x34\x56\x78\x00\x00\x00\x05hello";

வெறுமை
sshbuf_fixed(வெறுமை)
{
	கட்டமைப்பு sshbuf *p1, *p2, *p3;
	u_char c;
	எழுத்து *s;
	u_int i;
	size_t l;

	TEST_START("sshbuf_from");
	p1 = sshbuf_from(test_buf, அளவு(test_buf));
	ASSERT_PTR_NE(p1, வெற்று);
	ASSERT_PTR_EQ(sshbuf_mutable_ptr(p1), வெற்று);
	ASSERT_INT_EQ(sshbuf_check_reserve(p1, 1), SSH_ERR_BUFFER_READ_ONLY);
	ASSERT_INT_EQ(sshbuf_reserve(p1, 1, வெற்று), SSH_ERR_BUFFER_READ_ONLY);
	ASSERT_INT_EQ(sshbuf_set_max_size(p1, 200), SSH_ERR_BUFFER_READ_ONLY);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x12345678), SSH_ERR_BUFFER_READ_ONLY);
	ASSERT_SIZE_T_EQ(sshbuf_avail(p1), 0);
	ASSERT_PTR_EQ(sshbuf_ptr(p1), test_buf);
	sshbuf_free(p1);
	TEST_DONE();

	TEST_START("sshbuf_from data");
	p1 = sshbuf_from(test_buf, அளவு(test_buf) - 1);
	ASSERT_PTR_NE(p1, வெற்று);
	ASSERT_PTR_EQ(sshbuf_ptr(p1), test_buf);
	ASSERT_INT_EQ(sshbuf_get_u8(p1, &c), 0);
	ASSERT_PTR_EQ(sshbuf_ptr(p1), test_buf + 1);
	ASSERT_U8_EQ(c, 1);
	ASSERT_INT_EQ(sshbuf_get_u32(p1, &i), 0);
	ASSERT_PTR_EQ(sshbuf_ptr(p1), test_buf + 5);
	ASSERT_U32_EQ(i, 0x12345678);
	ASSERT_INT_EQ(sshbuf_get_cstring(p1, &s, &l), 0);
	ASSERT_SIZE_T_EQ(sshbuf_len(p1), 0);
	ASSERT_STRING_EQ(s, "hello");
	ASSERT_SIZE_T_EQ(l, 5);
	sshbuf_free(p1);
	விடுவி(s);
	TEST_DONE();

	TEST_START("sshbuf_fromb ");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, வெற்று);
	ASSERT_U_INT_EQ(sshbuf_refcount(p1), 1);
	ASSERT_PTR_EQ(sshbuf_parent(p1), வெற்று);
	ASSERT_INT_EQ(sshbuf_put(p1, test_buf, அளவு(test_buf) - 1), 0);
	p2 = sshbuf_fromb(p1);
	ASSERT_PTR_NE(p2, வெற்று);
	ASSERT_U_INT_EQ(sshbuf_refcount(p1), 2);
	ASSERT_PTR_EQ(sshbuf_parent(p1), வெற்று);
	ASSERT_PTR_EQ(sshbuf_parent(p2), p1);
	ASSERT_PTR_EQ(sshbuf_ptr(p2), sshbuf_ptr(p1));
	ASSERT_PTR_NE(sshbuf_ptr(p1), வெற்று);
	ASSERT_PTR_NE(sshbuf_ptr(p2), வெற்று);
	ASSERT_PTR_EQ(sshbuf_mutable_ptr(p1), வெற்று);
	ASSERT_PTR_EQ(sshbuf_mutable_ptr(p2), வெற்று);
	ASSERT_SIZE_T_EQ(sshbuf_len(p1), sshbuf_len(p2));
	ASSERT_INT_EQ(sshbuf_get_u8(p2, &c), 0);
	ASSERT_PTR_EQ(sshbuf_ptr(p2), sshbuf_ptr(p1) + 1);
	ASSERT_U8_EQ(c, 1);
	ASSERT_INT_EQ(sshbuf_get_u32(p2, &i), 0);
	ASSERT_PTR_EQ(sshbuf_ptr(p2), sshbuf_ptr(p1) + 5);
	ASSERT_U32_EQ(i, 0x12345678);
	ASSERT_INT_EQ(sshbuf_get_cstring(p2, &s, &l), 0);
	ASSERT_SIZE_T_EQ(sshbuf_len(p2), 0);
	ASSERT_STRING_EQ(s, "hello");
	ASSERT_SIZE_T_EQ(l, 5);
	sshbuf_free(p1);
	ASSERT_U_INT_EQ(sshbuf_refcount(p1), 1);
	sshbuf_free(p2);
	விடுவி(s);
	TEST_DONE();

	TEST_START("sshbuf_froms");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, வெற்று);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x01), 0);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x12345678), 0);
	ASSERT_INT_EQ(sshbuf_put_cstring(p1, "hello"), 0);
	p2 = sshbuf_new();
	ASSERT_PTR_NE(p2, வெற்று);
	ASSERT_SIZE_T_EQ(sshbuf_len(p1), அளவு(test_buf) - 1);
	ASSERT_INT_EQ(sshbuf_put_stringb(p2, p1), 0);
	ASSERT_SIZE_T_EQ(sshbuf_len(p2), அளவு(test_buf) + 4 - 1);
	ASSERT_INT_EQ(sshbuf_froms(p2, &p3), 0);
	ASSERT_SIZE_T_EQ(sshbuf_len(p2), 0);
	ASSERT_PTR_NE(p3, வெற்று);
	ASSERT_PTR_NE(sshbuf_ptr(p3), வெற்று);
	ASSERT_SIZE_T_EQ(sshbuf_len(p3), அளவு(test_buf) - 1);
	ASSERT_MEM_EQ(sshbuf_ptr(p3), test_buf, அளவு(test_buf) - 1);
	sshbuf_free(p3);
	ASSERT_INT_EQ(sshbuf_put_stringb(p2, p1), 0);
	ASSERT_INT_EQ(sshbuf_consume_end(p2, 1), 0);
	ASSERT_INT_EQ(sshbuf_froms(p2, &p3), SSH_ERR_MESSAGE_INCOMPLETE);
	ASSERT_PTR_EQ(p3, வெற்று);
	sshbuf_free(p2);
	sshbuf_free(p1);
}
