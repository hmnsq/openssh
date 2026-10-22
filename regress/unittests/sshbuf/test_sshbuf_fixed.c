/* 	$OpenBSD: test_sshbuf_fixed.c,v 1.2 2021/12/14 21:25:27 deraadt Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#ವ್ಯಾಖ್ಯಾನಿಸು SSHBUF_ಆಂತರಿಕ 1  /* access internals for testing */
#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"

ಶೂನ್ಯ sshbuf_fixed(ಶೂನ್ಯ);

ಸ್ಥಿರಾಂಕ u_char test_buf[] = "\x01\x12\x34\x56\x78\x00\x00\x00\x05hello";

ಶೂನ್ಯ
sshbuf_fixed(ಶೂನ್ಯ)
{
	ರಚನೆ sshbuf *p1, *p2, *p3;
	u_char c;
	ಅಕ್ಷರ *s;
	u_int i;
	ಗಾತ್ರ_t l;

	TEST_ಆರಂಭ("sshbuf_from");
	p1 = sshbuf_from(test_buf, ಗಾತ್ರ(test_buf));
	ASSERT_PTR_NE(p1, ಖಾಲಿ);
	ASSERT_PTR_EQ(sshbuf_mutable_ptr(p1), ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_check_reserve(p1, 1), SSH_ERR_ಬಫರ್_READ_ONLY);
	ASSERT_INT_EQ(sshbuf_reserve(p1, 1, ಖಾಲಿ), SSH_ERR_ಬಫರ್_READ_ONLY);
	ASSERT_INT_EQ(sshbuf_ಗಣ_max_ಗಾತ್ರ(p1, 200), SSH_ERR_ಬಫರ್_READ_ONLY);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x12345678), SSH_ERR_ಬಫರ್_READ_ONLY);
	ASSERT_ಗಾತ್ರ_T_EQ(sshbuf_avail(p1), 0);
	ASSERT_PTR_EQ(sshbuf_ptr(p1), test_buf);
	sshbuf_free(p1);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("sshbuf_from data");
	p1 = sshbuf_from(test_buf, ಗಾತ್ರ(test_buf) - 1);
	ASSERT_PTR_NE(p1, ಖಾಲಿ);
	ASSERT_PTR_EQ(sshbuf_ptr(p1), test_buf);
	ASSERT_INT_EQ(sshbuf_get_u8(p1, &c), 0);
	ASSERT_PTR_EQ(sshbuf_ptr(p1), test_buf + 1);
	ASSERT_U8_EQ(c, 1);
	ASSERT_INT_EQ(sshbuf_get_u32(p1, &i), 0);
	ASSERT_PTR_EQ(sshbuf_ptr(p1), test_buf + 5);
	ASSERT_U32_EQ(i, 0x12345678);
	ASSERT_INT_EQ(sshbuf_get_cstring(p1, &s, &l), 0);
	ASSERT_ಗಾತ್ರ_T_EQ(sshbuf_len(p1), 0);
	ASSERT_STRING_EQ(s, "hello");
	ASSERT_ಗಾತ್ರ_T_EQ(l, 5);
	sshbuf_free(p1);
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("sshbuf_fromb ");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ಖಾಲಿ);
	ASSERT_U_INT_EQ(sshbuf_refcount(p1), 1);
	ASSERT_PTR_EQ(sshbuf_ಪೋಷಕ(p1), ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_put(p1, test_buf, ಗಾತ್ರ(test_buf) - 1), 0);
	p2 = sshbuf_fromb(p1);
	ASSERT_PTR_NE(p2, ಖಾಲಿ);
	ASSERT_U_INT_EQ(sshbuf_refcount(p1), 2);
	ASSERT_PTR_EQ(sshbuf_ಪೋಷಕ(p1), ಖಾಲಿ);
	ASSERT_PTR_EQ(sshbuf_ಪೋಷಕ(p2), p1);
	ASSERT_PTR_EQ(sshbuf_ptr(p2), sshbuf_ptr(p1));
	ASSERT_PTR_NE(sshbuf_ptr(p1), ಖಾಲಿ);
	ASSERT_PTR_NE(sshbuf_ptr(p2), ಖಾಲಿ);
	ASSERT_PTR_EQ(sshbuf_mutable_ptr(p1), ಖಾಲಿ);
	ASSERT_PTR_EQ(sshbuf_mutable_ptr(p2), ಖಾಲಿ);
	ASSERT_ಗಾತ್ರ_T_EQ(sshbuf_len(p1), sshbuf_len(p2));
	ASSERT_INT_EQ(sshbuf_get_u8(p2, &c), 0);
	ASSERT_PTR_EQ(sshbuf_ptr(p2), sshbuf_ptr(p1) + 1);
	ASSERT_U8_EQ(c, 1);
	ASSERT_INT_EQ(sshbuf_get_u32(p2, &i), 0);
	ASSERT_PTR_EQ(sshbuf_ptr(p2), sshbuf_ptr(p1) + 5);
	ASSERT_U32_EQ(i, 0x12345678);
	ASSERT_INT_EQ(sshbuf_get_cstring(p2, &s, &l), 0);
	ASSERT_ಗಾತ್ರ_T_EQ(sshbuf_len(p2), 0);
	ASSERT_STRING_EQ(s, "hello");
	ASSERT_ಗಾತ್ರ_T_EQ(l, 5);
	sshbuf_free(p1);
	ASSERT_U_INT_EQ(sshbuf_refcount(p1), 1);
	sshbuf_free(p2);
	ಬಿಡುಗಡೆ(s);
	TEST_ಮುಗಿದ();

	TEST_ಆರಂಭ("sshbuf_froms");
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ಖಾಲಿ);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x01), 0);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 0x12345678), 0);
	ASSERT_INT_EQ(sshbuf_put_cstring(p1, "hello"), 0);
	p2 = sshbuf_new();
	ASSERT_PTR_NE(p2, ಖಾಲಿ);
	ASSERT_ಗಾತ್ರ_T_EQ(sshbuf_len(p1), ಗಾತ್ರ(test_buf) - 1);
	ASSERT_INT_EQ(sshbuf_put_stringb(p2, p1), 0);
	ASSERT_ಗಾತ್ರ_T_EQ(sshbuf_len(p2), ಗಾತ್ರ(test_buf) + 4 - 1);
	ASSERT_INT_EQ(sshbuf_froms(p2, &p3), 0);
	ASSERT_ಗಾತ್ರ_T_EQ(sshbuf_len(p2), 0);
	ASSERT_PTR_NE(p3, ಖಾಲಿ);
	ASSERT_PTR_NE(sshbuf_ptr(p3), ಖಾಲಿ);
	ASSERT_ಗಾತ್ರ_T_EQ(sshbuf_len(p3), ಗಾತ್ರ(test_buf) - 1);
	ASSERT_MEM_EQ(sshbuf_ptr(p3), test_buf, ಗಾತ್ರ(test_buf) - 1);
	sshbuf_free(p3);
	ASSERT_INT_EQ(sshbuf_put_stringb(p2, p1), 0);
	ASSERT_INT_EQ(sshbuf_consume_ಕೊನೆ(p2, 1), 0);
	ASSERT_INT_EQ(sshbuf_froms(p2, &p3), SSH_ERR_ಸಂದೇಶ_INCOMPLETE);
	ASSERT_PTR_EQ(p3, ಖಾಲಿ);
	sshbuf_free(p2);
	sshbuf_free(p1);
}
