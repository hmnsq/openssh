/* 	$OpenBSD: common.c,v 1.8 2025/06/16 08:49:27 dtucker Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ec.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/rsa.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/objects.h>
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "../test_helper/test_helper.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "common.h"

ਬਣਤਰ sshbuf *
ਲੱਦੋ_file(ਅਚਲ ਅੱਖਰ *name)
{
	ਬਣਤਰ sshbuf *ret = ਨਿਰਾ;

	ASSERT_INT_EQ(sshbuf_ਲੱਦੋ_file(test_ਅੰਕੜੇ_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, ਨਿਰਾ);
	ਵਾਪਸ ret;
}

ਬਣਤਰ sshbuf *
ਲੱਦੋ_ਪਾਠ_file(ਅਚਲ ਅੱਖਰ *name)
{
	ਬਣਤਰ sshbuf *ret = ਲੱਦੋ_file(name);
	ਅਚਲ u_char *p;
	ਮਾਪ_t len;

	/* Trim whitespace at EOL */
	ਲਈ (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		ਜੇ (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_ਸਿਰਾ(ret, 1), 0);
		ਨਹੀਂਤਾਂ
			ਰੋਕੋ;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	ਵਾਪਸ ret;
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
BIGNUM *
ਲੱਦੋ_bignum(ਅਚਲ ਅੱਖਰ *name)
{
	BIGNUM *ret = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *buf;

	buf = ਲੱਦੋ_ਪਾਠ_file(name);
	ASSERT_INT_NE(BN_hex2bn(&ret, (ਅਚਲ ਅੱਖਰ *)sshbuf_ptr(buf)), 0);
	sshbuf_free(buf);
	ਵਾਪਸ ret;
}

ਅਚਲ BIGNUM *
rsa_n(ਬਣਤਰ sshkey *k)
{
	ਅਚਲ BIGNUM *n = ਨਿਰਾ;

	ASSERT_PTR_NE(k, ਨਿਰਾ);
	ASSERT_PTR_NE(k->pkey, ਨਿਰਾ);
	RSA_get0_ਕੁੰਜੀ(EVP_PKEY_get0_RSA(k->pkey), &n, ਨਿਰਾ, ਨਿਰਾ);
	ਵਾਪਸ n;
}

ਅਚਲ BIGNUM *
rsa_e(ਬਣਤਰ sshkey *k)
{
	ਅਚਲ BIGNUM *e = ਨਿਰਾ;

	ASSERT_PTR_NE(k, ਨਿਰਾ);
	ASSERT_PTR_NE(k->pkey, ਨਿਰਾ);
	RSA_get0_ਕੁੰਜੀ(EVP_PKEY_get0_RSA(k->pkey), ਨਿਰਾ, &e, ਨਿਰਾ);
	ਵਾਪਸ e;
}

ਅਚਲ BIGNUM *
rsa_p(ਬਣਤਰ sshkey *k)
{
	ਅਚਲ BIGNUM *p = ਨਿਰਾ;

	ASSERT_PTR_NE(k, ਨਿਰਾ);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), ਨਿਰਾ);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), &p, ਨਿਰਾ);
	ਵਾਪਸ p;
}

ਅਚਲ BIGNUM *
rsa_q(ਬਣਤਰ sshkey *k)
{
	ਅਚਲ BIGNUM *q = ਨਿਰਾ;

	ASSERT_PTR_NE(k, ਨਿਰਾ);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), ਨਿਰਾ);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), ਨਿਰਾ, &q);
	ਵਾਪਸ q;
}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
