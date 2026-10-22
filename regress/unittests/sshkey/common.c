/* 	$OpenBSD: common.c,v 1.8 2025/06/16 08:49:27 dtucker Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/stat.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/bn.h>
#અન્તર્ભાવ <openssl/ec.h>
#અન્તર્ભાવ <openssl/rsa.h>
#અન્તર્ભાવ <openssl/objects.h>
#endif /* WITH_OPENSSL */

#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"

#અન્તર્ભાવ "../test_helper/test_helper.h"

#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "sshbuf.h"

#અન્તર્ભાવ "common.h"

સંરચના sshbuf *
load_file(અચલ અક્ષર *name)
{
	સંરચના sshbuf *ret = ખાલી;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, ખાલી);
	પાછા ret;
}

સંરચના sshbuf *
load_text_file(અચલ અક્ષર *name)
{
	સંરચના sshbuf *ret = load_file(name);
	અચલ u_char *p;
	size_t len;

	/* Trim whitespace at EOL */
	માટે (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		જો (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		નહીંતર
			તોડો;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	પાછા ret;
}

#ifdef WITH_OPENSSL
BIGNUM *
load_bignum(અચલ અક્ષર *name)
{
	BIGNUM *ret = ખાલી;
	સંરચના sshbuf *buf;

	buf = load_text_file(name);
	ASSERT_INT_NE(BN_hex2bn(&ret, (અચલ અક્ષર *)sshbuf_ptr(buf)), 0);
	sshbuf_free(buf);
	પાછા ret;
}

અચલ BIGNUM *
rsa_n(સંરચના sshkey *k)
{
	અચલ BIGNUM *n = ખાલી;

	ASSERT_PTR_NE(k, ખાલી);
	ASSERT_PTR_NE(k->pkey, ખાલી);
	RSA_get0_ચાવી(EVP_PKEY_get0_RSA(k->pkey), &n, ખાલી, ખાલી);
	પાછા n;
}

અચલ BIGNUM *
rsa_e(સંરચના sshkey *k)
{
	અચલ BIGNUM *e = ખાલી;

	ASSERT_PTR_NE(k, ખાલી);
	ASSERT_PTR_NE(k->pkey, ખાલી);
	RSA_get0_ચાવી(EVP_PKEY_get0_RSA(k->pkey), ખાલી, &e, ખાલી);
	પાછા e;
}

અચલ BIGNUM *
rsa_p(સંરચના sshkey *k)
{
	અચલ BIGNUM *p = ખાલી;

	ASSERT_PTR_NE(k, ખાલી);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), ખાલી);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), &p, ખાલી);
	પાછા p;
}

અચલ BIGNUM *
rsa_q(સંરચના sshkey *k)
{
	અચલ BIGNUM *q = ખાલી;

	ASSERT_PTR_NE(k, ખાલી);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), ખાલી);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), ખાલી, &q);
	પાછા q;
}
#endif /* WITH_OPENSSL */
