/* 	$OpenBSD: common.c,v 1.8 2025/06/16 08:49:27 dtucker Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/bn.h>
#അന്തര്ഭാവ <openssl/ec.h>
#അന്തര്ഭാവ <openssl/rsa.h>
#അന്തര്ഭാവ <openssl/objects.h>
#endif /* WITH_OPENSSL */

#അന്തര്ഭാവ "openbsd-compat/openssl-compat.h"

#അന്തര്ഭാവ "../test_helper/test_helper.h"

#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "sshbuf.h"

#അന്തര്ഭാവ "common.h"

ഘടന sshbuf *
load_file(സ്ഥിരം അക്ഷരം *name)
{
	ഘടന sshbuf *ret = ശൂന്യ;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, ശൂന്യ);
	തിരികെ ret;
}

ഘടന sshbuf *
load_text_file(സ്ഥിരം അക്ഷരം *name)
{
	ഘടന sshbuf *ret = load_file(name);
	സ്ഥിരം u_char *p;
	size_t len;

	/* Trim whitespace at EOL */
	വേണ്ടി (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		എങ്കിൽ (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		അല്ലെങ്കിൽ
			നിർത്തുക;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	തിരികെ ret;
}

#ifdef WITH_OPENSSL
BIGNUM *
load_bignum(സ്ഥിരം അക്ഷരം *name)
{
	BIGNUM *ret = ശൂന്യ;
	ഘടന sshbuf *buf;

	buf = load_text_file(name);
	ASSERT_INT_NE(BN_hex2bn(&ret, (സ്ഥിരം അക്ഷരം *)sshbuf_ptr(buf)), 0);
	sshbuf_free(buf);
	തിരികെ ret;
}

സ്ഥിരം BIGNUM *
rsa_n(ഘടന sshkey *k)
{
	സ്ഥിരം BIGNUM *n = ശൂന്യ;

	ASSERT_PTR_NE(k, ശൂന്യ);
	ASSERT_PTR_NE(k->pkey, ശൂന്യ);
	RSA_get0_താക്കോൽ(EVP_PKEY_get0_RSA(k->pkey), &n, ശൂന്യ, ശൂന്യ);
	തിരികെ n;
}

സ്ഥിരം BIGNUM *
rsa_e(ഘടന sshkey *k)
{
	സ്ഥിരം BIGNUM *e = ശൂന്യ;

	ASSERT_PTR_NE(k, ശൂന്യ);
	ASSERT_PTR_NE(k->pkey, ശൂന്യ);
	RSA_get0_താക്കോൽ(EVP_PKEY_get0_RSA(k->pkey), ശൂന്യ, &e, ശൂന്യ);
	തിരികെ e;
}

സ്ഥിരം BIGNUM *
rsa_p(ഘടന sshkey *k)
{
	സ്ഥിരം BIGNUM *p = ശൂന്യ;

	ASSERT_PTR_NE(k, ശൂന്യ);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), ശൂന്യ);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), &p, ശൂന്യ);
	തിരികെ p;
}

സ്ഥിരം BIGNUM *
rsa_q(ഘടന sshkey *k)
{
	സ്ഥിരം BIGNUM *q = ശൂന്യ;

	ASSERT_PTR_NE(k, ശൂന്യ);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), ശൂന്യ);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), ശൂന്യ, &q);
	തിരികെ q;
}
#endif /* WITH_OPENSSL */
