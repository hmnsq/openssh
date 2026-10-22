/* 	$OpenBSD: common.c,v 1.8 2025/06/16 08:49:27 dtucker Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/stat.h>
#شامل <fcntl.h>
#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/bn.h>
#شامل <openssl/ec.h>
#شامل <openssl/rsa.h>
#شامل <openssl/objects.h>
#اگر_ختم /* WITH_OPENSSL */

#شامل "openbsd-compat/openssl-compat.h"

#شامل "../test_helper/test_helper.h"

#شامل "ssherr.h"
#شامل "authfile.h"
#شامل "sshkey.h"
#شامل "sshbuf.h"

#شامل "common.h"

ساخت sshbuf *
بھرو_file(ثابت حرف *name)
{
	ساخت sshbuf *ret = تہی;

	ASSERT_INT_EQ(sshbuf_بھرو_file(test_ڈیٹا_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, تہی);
	واپس ret;
}

ساخت sshbuf *
بھرو_متن_file(ثابت حرف *name)
{
	ساخت sshbuf *ret = بھرو_file(name);
	ثابت u_char *p;
	سائز_t len;

	/* Trim whitespace at EOL */
	برائے (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		اگر (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_انتہا(ret, 1), 0);
		ورنہ
			توڑو;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	واپس ret;
}

#اگر_تعریف_شدہ WITH_OPENSSL
BIGNUM *
بھرو_bignum(ثابت حرف *name)
{
	BIGNUM *ret = تہی;
	ساخت sshbuf *buf;

	buf = بھرو_متن_file(name);
	ASSERT_INT_NE(BN_hex2bn(&ret, (ثابت حرف *)sshbuf_ptr(buf)), 0);
	sshbuf_free(buf);
	واپس ret;
}

ثابت BIGNUM *
rsa_n(ساخت sshkey *k)
{
	ثابت BIGNUM *n = تہی;

	ASSERT_PTR_NE(k, تہی);
	ASSERT_PTR_NE(k->pkey, تہی);
	RSA_get0_کلید(EVP_PKEY_get0_RSA(k->pkey), &n, تہی, تہی);
	واپس n;
}

ثابت BIGNUM *
rsa_e(ساخت sshkey *k)
{
	ثابت BIGNUM *e = تہی;

	ASSERT_PTR_NE(k, تہی);
	ASSERT_PTR_NE(k->pkey, تہی);
	RSA_get0_کلید(EVP_PKEY_get0_RSA(k->pkey), تہی, &e, تہی);
	واپس e;
}

ثابت BIGNUM *
rsa_p(ساخت sshkey *k)
{
	ثابت BIGNUM *p = تہی;

	ASSERT_PTR_NE(k, تہی);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), تہی);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), &p, تہی);
	واپس p;
}

ثابت BIGNUM *
rsa_q(ساخت sshkey *k)
{
	ثابت BIGNUM *q = تہی;

	ASSERT_PTR_NE(k, تہی);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), تہی);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), تہی, &q);
	واپس q;
}
#اگر_ختم /* WITH_OPENSSL */
