/* 	$OpenBSD: common.c,v 1.8 2025/06/16 08:49:27 dtucker Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/stat.h>
#ضمن <fcntl.h>
#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
#ضمن <openssl/bn.h>
#ضمن <openssl/ec.h>
#ضمن <openssl/rsa.h>
#ضمن <openssl/objects.h>
#جيڪڏهن_پورو /* WITH_OPENSSL */

#ضمن "openbsd-compat/openssl-compat.h"

#ضمن "../test_helper/test_helper.h"

#ضمن "ssherr.h"
#ضمن "authfile.h"
#ضمن "sshkey.h"
#ضمن "sshbuf.h"

#ضمن "common.h"

بنية sshbuf *
ڀريو_file(ثابت حرف *name)
{
	بنية sshbuf *ret = عدم;

	ASSERT_INT_EQ(sshbuf_ڀريو_file(test_معلومات_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, عدم);
	أرجع ret;
}

بنية sshbuf *
ڀريو_متن_file(ثابت حرف *name)
{
	بنية sshbuf *ret = ڀريو_file(name);
	ثابت u_char *p;
	سائيز_t len;

	/* Trim whitespace at EOL */
	لكل (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		إذا (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_پڇاڙي(ret, 1), 0);
		وإلا
			اكسر;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	أرجع ret;
}

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
BIGNUM *
ڀريو_bignum(ثابت حرف *name)
{
	BIGNUM *ret = عدم;
	بنية sshbuf *buf;

	buf = ڀريو_متن_file(name);
	ASSERT_INT_NE(BN_hex2bn(&ret, (ثابت حرف *)sshbuf_ptr(buf)), 0);
	sshbuf_free(buf);
	أرجع ret;
}

ثابت BIGNUM *
rsa_n(بنية sshkey *k)
{
	ثابت BIGNUM *n = عدم;

	ASSERT_PTR_NE(k, عدم);
	ASSERT_PTR_NE(k->pkey, عدم);
	RSA_get0_ڪنجي(EVP_PKEY_get0_RSA(k->pkey), &n, عدم, عدم);
	أرجع n;
}

ثابت BIGNUM *
rsa_e(بنية sshkey *k)
{
	ثابت BIGNUM *e = عدم;

	ASSERT_PTR_NE(k, عدم);
	ASSERT_PTR_NE(k->pkey, عدم);
	RSA_get0_ڪنجي(EVP_PKEY_get0_RSA(k->pkey), عدم, &e, عدم);
	أرجع e;
}

ثابت BIGNUM *
rsa_p(بنية sshkey *k)
{
	ثابت BIGNUM *p = عدم;

	ASSERT_PTR_NE(k, عدم);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), عدم);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), &p, عدم);
	أرجع p;
}

ثابت BIGNUM *
rsa_q(بنية sshkey *k)
{
	ثابت BIGNUM *q = عدم;

	ASSERT_PTR_NE(k, عدم);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), عدم);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), عدم, &q);
	أرجع q;
}
#جيڪڏهن_پورو /* WITH_OPENSSL */
