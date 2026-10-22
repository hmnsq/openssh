/* 	$OpenBSD: common.c,v 1.8 2025/06/16 08:49:27 dtucker Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/ec.h>
#ಅನ್ತರ್ಭಾವ <openssl/rsa.h>
#ಅನ್ತರ್ಭಾವ <openssl/objects.h>
#endif /* WITH_OPENSSL */

#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"

#ಅನ್ತರ್ಭಾವ "common.h"

ಸಂರಚನಾ sshbuf *
load_file(ಧ್ರುವ ವರ್ಣ *name)
{
	ಸಂರಚನಾ sshbuf *ret = ರಿಕ್ತ;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, ರಿಕ್ತ);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸಂರಚನಾ sshbuf *
load_text_file(ಧ್ರುವ ವರ್ಣ *name)
{
	ಸಂರಚನಾ sshbuf *ret = load_file(name);
	ಧ್ರುವ u_char *p;
	size_t len;

	/* Trim whitespace at EOL */
	ಪ್ರತಿ (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		ಯದಿ (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		ಅನ್ಯಥಾ
			ಭಙ್ಗ;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	ಪ್ರತ್ಯಾಗಮ ret;
}

#ifdef WITH_OPENSSL
BIGNUM *
load_bignum(ಧ್ರುವ ವರ್ಣ *name)
{
	BIGNUM *ret = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *buf;

	buf = load_text_file(name);
	ASSERT_INT_NE(BN_hex2bn(&ret, (ಧ್ರುವ ವರ್ಣ *)sshbuf_ptr(buf)), 0);
	sshbuf_free(buf);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಧ್ರುವ BIGNUM *
rsa_n(ಸಂರಚನಾ sshkey *k)
{
	ಧ್ರುವ BIGNUM *n = ರಿಕ್ತ;

	ASSERT_PTR_NE(k, ರಿಕ್ತ);
	ASSERT_PTR_NE(k->pkey, ರಿಕ್ತ);
	RSA_get0_ಕೀಲಿ(EVP_PKEY_get0_RSA(k->pkey), &n, ರಿಕ್ತ, ರಿಕ್ತ);
	ಪ್ರತ್ಯಾಗಮ n;
}

ಧ್ರುವ BIGNUM *
rsa_e(ಸಂರಚನಾ sshkey *k)
{
	ಧ್ರುವ BIGNUM *e = ರಿಕ್ತ;

	ASSERT_PTR_NE(k, ರಿಕ್ತ);
	ASSERT_PTR_NE(k->pkey, ರಿಕ್ತ);
	RSA_get0_ಕೀಲಿ(EVP_PKEY_get0_RSA(k->pkey), ರಿಕ್ತ, &e, ರಿಕ್ತ);
	ಪ್ರತ್ಯಾಗಮ e;
}

ಧ್ರುವ BIGNUM *
rsa_p(ಸಂರಚನಾ sshkey *k)
{
	ಧ್ರುವ BIGNUM *p = ರಿಕ್ತ;

	ASSERT_PTR_NE(k, ರಿಕ್ತ);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), ರಿಕ್ತ);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), &p, ರಿಕ್ತ);
	ಪ್ರತ್ಯಾಗಮ p;
}

ಧ್ರುವ BIGNUM *
rsa_q(ಸಂರಚನಾ sshkey *k)
{
	ಧ್ರುವ BIGNUM *q = ರಿಕ್ತ;

	ASSERT_PTR_NE(k, ರಿಕ್ತ);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), ರಿಕ್ತ);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), ರಿಕ್ತ, &q);
	ಪ್ರತ್ಯಾಗಮ q;
}
#endif /* WITH_OPENSSL */
