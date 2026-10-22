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

#ifdef WITH_OPENSSL
#شامل <openssl/bn.h>
#شامل <openssl/ec.h>
#شامل <openssl/rsa.h>
#شامل <openssl/objects.h>
#endif /* WITH_OPENSSL */

#شامل "openbsd-compat/openssl-compat.h"

#شامل "../test_helper/test_helper.h"

#شامل "ssherr.h"
#شامل "authfile.h"
#شامل "sshkey.h"
#شامل "sshbuf.h"

#شامل "common.h"

ساختار sshbuf *
load_file(ثابت نویسه *name)
{
	ساختار sshbuf *ret = پوچ;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, پوچ);
	بازگشت ret;
}

ساختار sshbuf *
load_text_file(ثابت نویسه *name)
{
	ساختار sshbuf *ret = load_file(name);
	ثابت u_char *p;
	size_t len;

	/* Trim whitespace at EOL */
	برای (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		اگر (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		وگرنه
			بشکن;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	بازگشت ret;
}

#ifdef WITH_OPENSSL
BIGNUM *
load_bignum(ثابت نویسه *name)
{
	BIGNUM *ret = پوچ;
	ساختار sshbuf *buf;

	buf = load_text_file(name);
	ASSERT_INT_NE(BN_hex2bn(&ret, (ثابت نویسه *)sshbuf_ptr(buf)), 0);
	sshbuf_free(buf);
	بازگشت ret;
}

ثابت BIGNUM *
rsa_n(ساختار sshkey *k)
{
	ثابت BIGNUM *n = پوچ;

	ASSERT_PTR_NE(k, پوچ);
	ASSERT_PTR_NE(k->pkey, پوچ);
	RSA_get0_کلید(EVP_PKEY_get0_RSA(k->pkey), &n, پوچ, پوچ);
	بازگشت n;
}

ثابت BIGNUM *
rsa_e(ساختار sshkey *k)
{
	ثابت BIGNUM *e = پوچ;

	ASSERT_PTR_NE(k, پوچ);
	ASSERT_PTR_NE(k->pkey, پوچ);
	RSA_get0_کلید(EVP_PKEY_get0_RSA(k->pkey), پوچ, &e, پوچ);
	بازگشت e;
}

ثابت BIGNUM *
rsa_p(ساختار sshkey *k)
{
	ثابت BIGNUM *p = پوچ;

	ASSERT_PTR_NE(k, پوچ);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), پوچ);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), &p, پوچ);
	بازگشت p;
}

ثابت BIGNUM *
rsa_q(ساختار sshkey *k)
{
	ثابت BIGNUM *q = پوچ;

	ASSERT_PTR_NE(k, پوچ);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), پوچ);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), پوچ, &q);
	بازگشت q;
}
#endif /* WITH_OPENSSL */
