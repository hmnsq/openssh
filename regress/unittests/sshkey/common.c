/* 	$OpenBSD: common.c,v 1.8 2025/06/16 08:49:27 dtucker Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/stat.h>
#অন্তর্ভাৱ <fcntl.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <unistd.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাৱ <openssl/bn.h>
#অন্তর্ভাৱ <openssl/ec.h>
#অন্তর্ভাৱ <openssl/rsa.h>
#অন্তর্ভাৱ <openssl/objects.h>
#endif /* WITH_OPENSSL */

#অন্তর্ভাৱ "openbsd-compat/openssl-compat.h"

#অন্তর্ভাৱ "../test_helper/test_helper.h"

#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "authfile.h"
#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "sshbuf.h"

#অন্তর্ভাৱ "common.h"

সংরচনা sshbuf *
load_file(ধ্রুৱ ৱর্ণ *name)
{
	সংরচনা sshbuf *ret = রিক্ত;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, রিক্ত);
	ঘূৰাই ret;
}

সংরচনা sshbuf *
load_text_file(ধ্রুৱ ৱর্ণ *name)
{
	সংরচনা sshbuf *ret = load_file(name);
	ধ্রুৱ u_char *p;
	size_t len;

	/* Trim whitespace at EOL */
	বাবে (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		যদি (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		অন্যথা
			ভঙ্গ;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	ঘূৰাই ret;
}

#ifdef WITH_OPENSSL
BIGNUM *
load_bignum(ধ্রুৱ ৱর্ণ *name)
{
	BIGNUM *ret = রিক্ত;
	সংরচনা sshbuf *buf;

	buf = load_text_file(name);
	ASSERT_INT_NE(BN_hex2bn(&ret, (ধ্রুৱ ৱর্ণ *)sshbuf_ptr(buf)), 0);
	sshbuf_free(buf);
	ঘূৰাই ret;
}

ধ্রুৱ BIGNUM *
rsa_n(সংরচনা sshkey *k)
{
	ধ্রুৱ BIGNUM *n = রিক্ত;

	ASSERT_PTR_NE(k, রিক্ত);
	ASSERT_PTR_NE(k->pkey, রিক্ত);
	RSA_get0_চাবি(EVP_PKEY_get0_RSA(k->pkey), &n, রিক্ত, রিক্ত);
	ঘূৰাই n;
}

ধ্রুৱ BIGNUM *
rsa_e(সংরচনা sshkey *k)
{
	ধ্রুৱ BIGNUM *e = রিক্ত;

	ASSERT_PTR_NE(k, রিক্ত);
	ASSERT_PTR_NE(k->pkey, রিক্ত);
	RSA_get0_চাবি(EVP_PKEY_get0_RSA(k->pkey), রিক্ত, &e, রিক্ত);
	ঘূৰাই e;
}

ধ্রুৱ BIGNUM *
rsa_p(সংরচনা sshkey *k)
{
	ধ্রুৱ BIGNUM *p = রিক্ত;

	ASSERT_PTR_NE(k, রিক্ত);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), রিক্ত);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), &p, রিক্ত);
	ঘূৰাই p;
}

ধ্রুৱ BIGNUM *
rsa_q(সংরচনা sshkey *k)
{
	ধ্রুৱ BIGNUM *q = রিক্ত;

	ASSERT_PTR_NE(k, রিক্ত);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), রিক্ত);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), রিক্ত, &q);
	ঘূৰাই q;
}
#endif /* WITH_OPENSSL */
