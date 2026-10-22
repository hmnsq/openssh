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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/ec.h>
#ಅನ್ತರ್ಭಾವ <openssl/rsa.h>
#ಅನ್ತರ್ಭಾವ <openssl/objects.h>
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"

#ಅನ್ತರ್ಭಾವ "../test_helper/test_helper.h"

#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"

#ಅನ್ತರ್ಭಾವ "common.h"

ರಚನೆ sshbuf *
ತುಂಬು_file(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ರಚನೆ sshbuf *ret = ಖಾಲಿ;

	ASSERT_INT_EQ(sshbuf_ತುಂಬು_file(test_ದತ್ತಾಂಶ_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, ಖಾಲಿ);
	ಹಿಂತಿರುಗಿ ret;
}

ರಚನೆ sshbuf *
ತುಂಬು_ಪಠ್ಯ_file(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ರಚನೆ sshbuf *ret = ತುಂಬು_file(name);
	ಸ್ಥಿರಾಂಕ u_char *p;
	ಗಾತ್ರ_t len;

	/* Trim whitespace at EOL */
	ಗಾಗಿ (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		ಆದರೆ (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_ಕೊನೆ(ret, 1), 0);
		ಇಲ್ಲದಿದ್ದರೆ
			ನಿಲ್ಲಿಸು;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	ಹಿಂತಿರುಗಿ ret;
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
BIGNUM *
ತುಂಬು_bignum(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	BIGNUM *ret = ಖಾಲಿ;
	ರಚನೆ sshbuf *buf;

	buf = ತುಂಬು_ಪಠ್ಯ_file(name);
	ASSERT_INT_NE(BN_hex2bn(&ret, (ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *)sshbuf_ptr(buf)), 0);
	sshbuf_free(buf);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರಾಂಕ BIGNUM *
rsa_n(ರಚನೆ sshkey *k)
{
	ಸ್ಥಿರಾಂಕ BIGNUM *n = ಖಾಲಿ;

	ASSERT_PTR_NE(k, ಖಾಲಿ);
	ASSERT_PTR_NE(k->pkey, ಖಾಲಿ);
	RSA_get0_ಕೀಲಿ(EVP_PKEY_get0_RSA(k->pkey), &n, ಖಾಲಿ, ಖಾಲಿ);
	ಹಿಂತಿರುಗಿ n;
}

ಸ್ಥಿರಾಂಕ BIGNUM *
rsa_e(ರಚನೆ sshkey *k)
{
	ಸ್ಥಿರಾಂಕ BIGNUM *e = ಖಾಲಿ;

	ASSERT_PTR_NE(k, ಖಾಲಿ);
	ASSERT_PTR_NE(k->pkey, ಖಾಲಿ);
	RSA_get0_ಕೀಲಿ(EVP_PKEY_get0_RSA(k->pkey), ಖಾಲಿ, &e, ಖಾಲಿ);
	ಹಿಂತಿರುಗಿ e;
}

ಸ್ಥಿರಾಂಕ BIGNUM *
rsa_p(ರಚನೆ sshkey *k)
{
	ಸ್ಥಿರಾಂಕ BIGNUM *p = ಖಾಲಿ;

	ASSERT_PTR_NE(k, ಖಾಲಿ);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), ಖಾಲಿ);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), &p, ಖಾಲಿ);
	ಹಿಂತಿರುಗಿ p;
}

ಸ್ಥಿರಾಂಕ BIGNUM *
rsa_q(ರಚನೆ sshkey *k)
{
	ಸ್ಥಿರಾಂಕ BIGNUM *q = ಖಾಲಿ;

	ASSERT_PTR_NE(k, ಖಾಲಿ);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), ಖಾಲಿ);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), ಖಾಲಿ, &q);
	ಹಿಂತಿರುಗಿ q;
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
