/* 	$OpenBSD: test_sshbuf_getput_crypto.c,v 1.5 2026/03/06 06:57:33 dtucker Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ec.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/objects.h>
#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"

ਖਾਲੀ sshbuf_getput_crypto_tests(ਖਾਲੀ);

ਖਾਲੀ
sshbuf_getput_crypto_tests(ਖਾਲੀ)
{
	ਬਣਤਰ sshbuf *p1;
	ਅਚਲ u_char *d;
	ਮਾਪ_t s;
	BIGNUM *bn, *bn2, *bn_x, *bn_y;
	ਅਚਲ ਅੱਖਰ *hexbn1 = "0102030405060708090a0b0c0d0e0f10";
	/* This one has MSB set to test bignum2 encoding negative-avoidance */
	ਅਚਲ ਅੱਖਰ *hexbn2 = "f0e0d0c0b0a0908070605040302010007fff11";
	u_char expbn1[] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	};
	u_char expbn2[] = {
		0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80,
		0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00,
		0x7f, 0xff, 0x11
	};
	ਪੂਰਨ ec256_nid = NID_X9_62_prime256v1;
	ਅੱਖਰ *ec256_x = "0C828004839D0106AA59575216191357"
		        "34B451459DADB586677EF9DF55784999";
	ਅੱਖਰ *ec256_y = "4D196B50F0B4E94B3C73E3A9D4CD9DF2"
	                "C8F9A35E42BDD047550F69D80EC23CD4";
	u_char expec256[] = {
		0x04,
		0x0c, 0x82, 0x80, 0x04, 0x83, 0x9d, 0x01, 0x06,
		0xaa, 0x59, 0x57, 0x52, 0x16, 0x19, 0x13, 0x57,
		0x34, 0xb4, 0x51, 0x45, 0x9d, 0xad, 0xb5, 0x86,
		0x67, 0x7e, 0xf9, 0xdf, 0x55, 0x78, 0x49, 0x99,
		0x4d, 0x19, 0x6b, 0x50, 0xf0, 0xb4, 0xe9, 0x4b,
		0x3c, 0x73, 0xe3, 0xa9, 0xd4, 0xcd, 0x9d, 0xf2,
		0xc8, 0xf9, 0xa3, 0x5e, 0x42, 0xbd, 0xd0, 0x47,
		0x55, 0x0f, 0x69, 0xd8, 0x0e, 0xc2, 0x3c, 0xd4
	};
	EC_ਕੁੰਜੀ *eck;
	EC_ਬਿੰਦੂ *ecp;
	ਪੂਰਨ r;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MKBN(b, bnn) \
	ਕਰੋ { \
		bnn = ਨਿਰਾ; \
		ASSERT_INT_GT(BN_hex2bn(&bnn, b), 0); \
	} ਜਦੋਂ (0)

	TEST_ਸ਼ੁਰੂ("sshbuf_put_bignum2");
	MKBN(hexbn1, bn);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put_bignum2(p1, bn), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), ਆਕਾਰ(expbn1) + 4);
	ASSERT_U32_EQ(PEEK_U32(sshbuf_ptr(p1)), (uint32_t)BN_ਅੰਕ_ਬਾਈਟਾਂ(bn));
	ASSERT_MEM_EQ(sshbuf_ptr(p1) + 4, expbn1, ਆਕਾਰ(expbn1));
	BN_free(bn);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_put_bignum2 limited");
	MKBN(hexbn1, bn);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_ਸੈੱਟ_max_ਮਾਪ(p1, ਆਕਾਰ(expbn1) + 3), 0);
	r = sshbuf_put_bignum2(p1, bn);
	ASSERT_INT_EQ(r, SSH_ERR_NO_ਬਫਰ_SPACE);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 0);
	BN_free(bn);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_put_bignum2 bn2");
	MKBN(hexbn2, bn);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put_bignum2(p1, bn), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), ਆਕਾਰ(expbn2) + 4 + 1); /* MSB */
	ASSERT_U32_EQ(PEEK_U32(sshbuf_ptr(p1)), (uint32_t)BN_ਅੰਕ_ਬਾਈਟਾਂ(bn) + 1);
	ASSERT_U8_EQ(*(sshbuf_ptr(p1) + 4), 0x00);
	ASSERT_MEM_EQ(sshbuf_ptr(p1) + 5, expbn2, ਆਕਾਰ(expbn2));
	BN_free(bn);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_put_bignum2 bn2 limited");
	MKBN(hexbn2, bn);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_ਸੈੱਟ_max_ਮਾਪ(p1, ਆਕਾਰ(expbn2) + 3), 0);
	r = sshbuf_put_bignum2(p1, bn);
	ASSERT_INT_EQ(r, SSH_ERR_NO_ਬਫਰ_SPACE);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 0);
	BN_free(bn);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_get_bignum2");
	MKBN(hexbn1, bn);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, BN_ਅੰਕ_ਬਾਈਟਾਂ(bn)), 0);
	ASSERT_INT_EQ(sshbuf_put(p1, expbn1, ਆਕਾਰ(expbn1)), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 4 + ਆਕਾਰ(expbn1));
	ASSERT_INT_EQ(sshbuf_put_u16(p1, 0xd00f), 0);
	bn2 = ਨਿਰਾ;
	ASSERT_INT_EQ(sshbuf_get_bignum2(p1, &bn2), 0);
	ASSERT_BIGNUM_EQ(bn, bn2);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 2);
	BN_free(bn);
	BN_free(bn2);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_get_bignum2 truncated");
	MKBN(hexbn1, bn);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, BN_ਅੰਕ_ਬਾਈਟਾਂ(bn)), 0);
	ASSERT_INT_EQ(sshbuf_put(p1, expbn1, ਆਕਾਰ(expbn1) - 1), 0);
	bn2 = ਨਿਰਾ;
	r = sshbuf_get_bignum2(p1, &bn2);
	ASSERT_INT_EQ(r, SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), ਆਕਾਰ(expbn1) + 3);
	BN_free(bn);
	BN_free(bn2);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_get_bignum2 giant");
	MKBN(hexbn1, bn);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, 65536), 0);
	ASSERT_INT_EQ(sshbuf_reserve(p1, 65536, ਨਿਰਾ), 0);
	bn2 = ਨਿਰਾ;
	r = sshbuf_get_bignum2(p1, &bn2);
	ASSERT_INT_EQ(r, SSH_ERR_BIGNUM_TOO_LARGE);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 65536 + 4);
	BN_free(bn);
	BN_free(bn2);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_get_bignum2 bn2");
	MKBN(hexbn2, bn);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, BN_ਅੰਕ_ਬਾਈਟਾਂ(bn) + 1), 0); /* MSB */
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x00), 0);
	ASSERT_INT_EQ(sshbuf_put(p1, expbn2, ਆਕਾਰ(expbn2)), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 4 + 1 + ਆਕਾਰ(expbn2));
	ASSERT_INT_EQ(sshbuf_put_u16(p1, 0xd00f), 0);
	bn2 = ਨਿਰਾ;
	ASSERT_INT_EQ(sshbuf_get_bignum2(p1, &bn2), 0);
	ASSERT_BIGNUM_EQ(bn, bn2);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 2);
	BN_free(bn);
	BN_free(bn2);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_get_bignum2 bn2 truncated");
	MKBN(hexbn2, bn);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, BN_ਅੰਕ_ਬਾਈਟਾਂ(bn) + 1), 0);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x00), 0);
	ASSERT_INT_EQ(sshbuf_put(p1, expbn2, ਆਕਾਰ(expbn2) - 1), 0);
	bn2 = ਨਿਰਾ;
	r = sshbuf_get_bignum2(p1, &bn2);
	ASSERT_INT_EQ(r, SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), ਆਕਾਰ(expbn2) + 1 + 4 - 1);
	BN_free(bn);
	BN_free(bn2);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_get_bignum2 bn2 negative");
	MKBN(hexbn2, bn);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put_u32(p1, BN_ਅੰਕ_ਬਾਈਟਾਂ(bn)), 0);
	ASSERT_INT_EQ(sshbuf_put(p1, expbn2, ਆਕਾਰ(expbn2)), 0);
	bn2 = ਨਿਰਾ;
	r = sshbuf_get_bignum2(p1, &bn2);
	ASSERT_INT_EQ(r, SSH_ERR_BIGNUM_IS_NEGATIVE);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), ਆਕਾਰ(expbn2) + 4);
	BN_free(bn);
	BN_free(bn2);
	sshbuf_free(p1);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_put_ec");
	eck = EC_ਕੁੰਜੀ_new_by_ਵਕਰ_name(ec256_nid);
	ASSERT_PTR_NE(eck, ਨਿਰਾ);
	ecp = EC_ਬਿੰਦੂ_new(EC_ਕੁੰਜੀ_get0_ਸਮੂਹ(eck));
	ASSERT_PTR_NE(ecp, ਨਿਰਾ);
	MKBN(ec256_x, bn_x);
	MKBN(ec256_y, bn_y);
	ASSERT_INT_EQ(EC_ਬਿੰਦੂ_ਸੈੱਟ_affine_coordinates(
	    EC_ਕੁੰਜੀ_get0_ਸਮੂਹ(eck), ecp, bn_x, bn_y, ਨਿਰਾ), 1);
	ASSERT_INT_EQ(EC_ਕੁੰਜੀ_ਸੈੱਟ_ਜਨਤਕ_ਕੁੰਜੀ(eck, ecp), 1);
	BN_free(bn_x);
	BN_free(bn_y);
	EC_ਬਿੰਦੂ_free(ecp);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put_eckey(p1, eck), 0);
	ASSERT_INT_EQ(sshbuf_get_string_ਸਿੱਧਾ(p1, &d, &s), 0);
	ASSERT_ਮਾਪ_T_EQ(s, ਆਕਾਰ(expec256));
	ASSERT_MEM_EQ(d, expec256, ਆਕਾਰ(expec256));
	sshbuf_free(p1);
	EC_ਕੁੰਜੀ_free(eck);
	TEST_ਪੂਰਾ();

	TEST_ਸ਼ੁਰੂ("sshbuf_get_ec");
	eck = EC_ਕੁੰਜੀ_new_by_ਵਕਰ_name(ec256_nid);
	ASSERT_PTR_NE(eck, ਨਿਰਾ);
	p1 = sshbuf_new();
	ASSERT_PTR_NE(p1, ਨਿਰਾ);
	ASSERT_INT_EQ(sshbuf_put_string(p1, expec256, ਆਕਾਰ(expec256)), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), ਆਕਾਰ(expec256) + 4);
	ASSERT_INT_EQ(sshbuf_put_u8(p1, 0x00), 0);
	ASSERT_INT_EQ(sshbuf_get_eckey(p1, eck), 0);
	bn_x = BN_new();
	bn_y = BN_new();
	ASSERT_PTR_NE(bn_x, ਨਿਰਾ);
	ASSERT_PTR_NE(bn_y, ਨਿਰਾ);
	ASSERT_INT_EQ(EC_ਬਿੰਦੂ_get_affine_coordinates(
	    EC_ਕੁੰਜੀ_get0_ਸਮੂਹ(eck), EC_ਕੁੰਜੀ_get0_ਜਨਤਕ_ਕੁੰਜੀ(eck),
	    bn_x, bn_y, ਨਿਰਾ), 1);
	MKBN(ec256_x, bn);
	MKBN(ec256_y, bn2);
	ASSERT_INT_EQ(BN_cmp(bn_x, bn), 0);
	ASSERT_INT_EQ(BN_cmp(bn_y, bn2), 0);
	ASSERT_ਮਾਪ_T_EQ(sshbuf_len(p1), 1);
	sshbuf_free(p1);
	EC_ਕੁੰਜੀ_free(eck);
	BN_free(bn_x);
	BN_free(bn_y);
	BN_free(bn);
	BN_free(bn2);
	TEST_ਪੂਰਾ();
}

#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
