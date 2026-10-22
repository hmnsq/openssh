/* 	$OpenBSD: common.c,v 1.8 2025/06/16 08:49:27 dtucker Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ <openssl/bn.h>
#ଅନ୍ତର୍ଭାଵ <openssl/ec.h>
#ଅନ୍ତର୍ଭାଵ <openssl/rsa.h>
#ଅନ୍ତର୍ଭାଵ <openssl/objects.h>
#endif /* WITH_OPENSSL */

#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openssl-compat.h"

#ଅନ୍ତର୍ଭାଵ "../test_helper/test_helper.h"

#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "authfile.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"

#ଅନ୍ତର୍ଭାଵ "common.h"

ସଂରଚନା sshbuf *
load_file(ଅଚଳ ଅକ୍ଷର *name)
{
	ସଂରଚନା sshbuf *ret = ଖାଲି;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, ଖାଲି);
	ଫେରନ୍ତୁ ret;
}

ସଂରଚନା sshbuf *
load_text_file(ଅଚଳ ଅକ୍ଷର *name)
{
	ସଂରଚନା sshbuf *ret = load_file(name);
	ଅଚଳ u_char *p;
	size_t len;

	/* Trim whitespace at EOL */
	ପାଇଁ (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		ଯଦି (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		ଅନ୍ୟଥା
			ଭାଙ୍ଗ;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	ଫେରନ୍ତୁ ret;
}

#ifdef WITH_OPENSSL
BIGNUM *
load_bignum(ଅଚଳ ଅକ୍ଷର *name)
{
	BIGNUM *ret = ଖାଲି;
	ସଂରଚନା sshbuf *buf;

	buf = load_text_file(name);
	ASSERT_INT_NE(BN_hex2bn(&ret, (ଅଚଳ ଅକ୍ଷର *)sshbuf_ptr(buf)), 0);
	sshbuf_free(buf);
	ଫେରନ୍ତୁ ret;
}

ଅଚଳ BIGNUM *
rsa_n(ସଂରଚନା sshkey *k)
{
	ଅଚଳ BIGNUM *n = ଖାଲି;

	ASSERT_PTR_NE(k, ଖାଲି);
	ASSERT_PTR_NE(k->pkey, ଖାଲି);
	RSA_get0_ଚାବି(EVP_PKEY_get0_RSA(k->pkey), &n, ଖାଲି, ଖାଲି);
	ଫେରନ୍ତୁ n;
}

ଅଚଳ BIGNUM *
rsa_e(ସଂରଚନା sshkey *k)
{
	ଅଚଳ BIGNUM *e = ଖାଲି;

	ASSERT_PTR_NE(k, ଖାଲି);
	ASSERT_PTR_NE(k->pkey, ଖାଲି);
	RSA_get0_ଚାବି(EVP_PKEY_get0_RSA(k->pkey), ଖାଲି, &e, ଖାଲି);
	ଫେରନ୍ତୁ e;
}

ଅଚଳ BIGNUM *
rsa_p(ସଂରଚନା sshkey *k)
{
	ଅଚଳ BIGNUM *p = ଖାଲି;

	ASSERT_PTR_NE(k, ଖାଲି);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), ଖାଲି);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), &p, ଖାଲି);
	ଫେରନ୍ତୁ p;
}

ଅଚଳ BIGNUM *
rsa_q(ସଂରଚନା sshkey *k)
{
	ଅଚଳ BIGNUM *q = ଖାଲି;

	ASSERT_PTR_NE(k, ଖାଲି);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), ଖାଲି);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), ଖାଲି, &q);
	ଫେରନ୍ତୁ q;
}
#endif /* WITH_OPENSSL */
