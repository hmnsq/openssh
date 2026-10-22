/* 	$OpenBSD: common.c,v 1.8 2025/06/16 08:49:27 dtucker Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/stat.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/bn.h>
#অন্তর্ভাব <openssl/ec.h>
#অন্তর্ভাব <openssl/rsa.h>
#অন্তর্ভাব <openssl/objects.h>
#endif /* WITH_OPENSSL */

#অন্তর্ভাব "openbsd-compat/openssl-compat.h"

#অন্তর্ভাব "../test_helper/test_helper.h"

#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "sshbuf.h"

#অন্তর্ভাব "common.h"

সংরচনা sshbuf *
load_file(ধ্রুব বর্ণ *name)
{
	সংরচনা sshbuf *ret = রিক্ত;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, রিক্ত);
	প্রত্যাগম ret;
}

সংরচনা sshbuf *
load_text_file(ধ্রুব বর্ণ *name)
{
	সংরচনা sshbuf *ret = load_file(name);
	ধ্রুব u_char *p;
	size_t len;

	/* Trim whitespace at EOL */
	প্রতি (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		যদি (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		অন্যথা
			ভঙ্গ;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	প্রত্যাগম ret;
}

#ifdef WITH_OPENSSL
BIGNUM *
load_bignum(ধ্রুব বর্ণ *name)
{
	BIGNUM *ret = রিক্ত;
	সংরচনা sshbuf *buf;

	buf = load_text_file(name);
	ASSERT_INT_NE(BN_hex2bn(&ret, (ধ্রুব বর্ণ *)sshbuf_ptr(buf)), 0);
	sshbuf_free(buf);
	প্রত্যাগম ret;
}

ধ্রুব BIGNUM *
rsa_n(সংরচনা sshkey *k)
{
	ধ্রুব BIGNUM *n = রিক্ত;

	ASSERT_PTR_NE(k, রিক্ত);
	ASSERT_PTR_NE(k->pkey, রিক্ত);
	RSA_get0_চাবি(EVP_PKEY_get0_RSA(k->pkey), &n, রিক্ত, রিক্ত);
	প্রত্যাগম n;
}

ধ্রুব BIGNUM *
rsa_e(সংরচনা sshkey *k)
{
	ধ্রুব BIGNUM *e = রিক্ত;

	ASSERT_PTR_NE(k, রিক্ত);
	ASSERT_PTR_NE(k->pkey, রিক্ত);
	RSA_get0_চাবি(EVP_PKEY_get0_RSA(k->pkey), রিক্ত, &e, রিক্ত);
	প্রত্যাগম e;
}

ধ্রুব BIGNUM *
rsa_p(সংরচনা sshkey *k)
{
	ধ্রুব BIGNUM *p = রিক্ত;

	ASSERT_PTR_NE(k, রিক্ত);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), রিক্ত);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), &p, রিক্ত);
	প্রত্যাগম p;
}

ধ্রুব BIGNUM *
rsa_q(সংরচনা sshkey *k)
{
	ধ্রুব BIGNUM *q = রিক্ত;

	ASSERT_PTR_NE(k, রিক্ত);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), রিক্ত);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), রিক্ত, &q);
	প্রত্যাগম q;
}
#endif /* WITH_OPENSSL */
