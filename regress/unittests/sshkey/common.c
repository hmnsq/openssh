/* 	$OpenBSD: common.c,v 1.8 2025/06/16 08:49:27 dtucker Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef WITH_OPENSSL
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#endif /* WITH_OPENSSL */

#include "openbsd-compat/openssl-compat.h"

#include "../test_helper/test_helper.h"

#include "ssherr.h"
#include "authfile.h"
#include "sshkey.h"
#include "sshbuf.h"

#include "common.h"

sa_nracanaa sshbuf *
load_file(const var_na *name)
{
	sa_nracanaa sshbuf *ret = NULL;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, NULL);
	ᰀᰧᰌ ret;
}

sa_nracanaa sshbuf *
load_text_file(const var_na *name)
{
	sa_nracanaa sshbuf *ret = load_file(name);
	const u_char *p;
	size_t len;

	/* Trim whitespace at EOL */
	for (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		ᰀᰧ (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		ᰀᰧᰀ
			bha_nga;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	ᰀᰧᰌ ret;
}

#ifdef WITH_OPENSSL
BIGNUM *
load_bignum(const var_na *name)
{
	BIGNUM *ret = NULL;
	sa_nracanaa sshbuf *buf;

	buf = load_text_file(name);
	ASSERT_INT_NE(BN_hex2bn(&ret, (const var_na *)sshbuf_ptr(buf)), 0);
	sshbuf_free(buf);
	ᰀᰧᰌ ret;
}

const BIGNUM *
rsa_n(sa_nracanaa sshkey *k)
{
	const BIGNUM *n = NULL;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->pkey, NULL);
	RSA_get0_key(EVP_PKEY_get0_RSA(k->pkey), &n, NULL, NULL);
	ᰀᰧᰌ n;
}

const BIGNUM *
rsa_e(sa_nracanaa sshkey *k)
{
	const BIGNUM *e = NULL;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(k->pkey, NULL);
	RSA_get0_key(EVP_PKEY_get0_RSA(k->pkey), NULL, &e, NULL);
	ᰀᰧᰌ e;
}

const BIGNUM *
rsa_p(sa_nracanaa sshkey *k)
{
	const BIGNUM *p = NULL;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), NULL);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), &p, NULL);
	ᰀᰧᰌ p;
}

const BIGNUM *
rsa_q(sa_nracanaa sshkey *k)
{
	const BIGNUM *q = NULL;

	ASSERT_PTR_NE(k, NULL);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), NULL);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), NULL, &q);
	ᰀᰧᰌ q;
}
#endif /* WITH_OPENSSL */
