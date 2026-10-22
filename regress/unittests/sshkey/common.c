/* 	$OpenBSD: common.c,v 1.8 2025/06/16 08:49:27 dtucker Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/ec.h>
#அந்தர்பாவ <openssl/rsa.h>
#அந்தர்பாவ <openssl/objects.h>
#endif /* WITH_OPENSSL */

#அந்தர்பாவ "openbsd-compat/openssl-compat.h"

#அந்தர்பாவ "../test_helper/test_helper.h"

#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "sshbuf.h"

#அந்தர்பாவ "common.h"

கட்டமைப்பு sshbuf *
load_file(மாறிலி எழுத்து *name)
{
	கட்டமைப்பு sshbuf *ret = வெற்று;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, வெற்று);
	திரும்பு ret;
}

கட்டமைப்பு sshbuf *
load_text_file(மாறிலி எழுத்து *name)
{
	கட்டமைப்பு sshbuf *ret = load_file(name);
	மாறிலி u_char *p;
	size_t len;

	/* Trim whitespace at EOL */
	க்கு (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		எனில் (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		இல்லையெனில்
			நிறுத்து;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	திரும்பு ret;
}

#ifdef WITH_OPENSSL
BIGNUM *
load_bignum(மாறிலி எழுத்து *name)
{
	BIGNUM *ret = வெற்று;
	கட்டமைப்பு sshbuf *buf;

	buf = load_text_file(name);
	ASSERT_INT_NE(BN_hex2bn(&ret, (மாறிலி எழுத்து *)sshbuf_ptr(buf)), 0);
	sshbuf_free(buf);
	திரும்பு ret;
}

மாறிலி BIGNUM *
rsa_n(கட்டமைப்பு sshkey *k)
{
	மாறிலி BIGNUM *n = வெற்று;

	ASSERT_PTR_NE(k, வெற்று);
	ASSERT_PTR_NE(k->pkey, வெற்று);
	RSA_get0_சாவி(EVP_PKEY_get0_RSA(k->pkey), &n, வெற்று, வெற்று);
	திரும்பு n;
}

மாறிலி BIGNUM *
rsa_e(கட்டமைப்பு sshkey *k)
{
	மாறிலி BIGNUM *e = வெற்று;

	ASSERT_PTR_NE(k, வெற்று);
	ASSERT_PTR_NE(k->pkey, வெற்று);
	RSA_get0_சாவி(EVP_PKEY_get0_RSA(k->pkey), வெற்று, &e, வெற்று);
	திரும்பு e;
}

மாறிலி BIGNUM *
rsa_p(கட்டமைப்பு sshkey *k)
{
	மாறிலி BIGNUM *p = வெற்று;

	ASSERT_PTR_NE(k, வெற்று);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), வெற்று);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), &p, வெற்று);
	திரும்பு p;
}

மாறிலி BIGNUM *
rsa_q(கட்டமைப்பு sshkey *k)
{
	மாறிலி BIGNUM *q = வெற்று;

	ASSERT_PTR_NE(k, வெற்று);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), வெற்று);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), வெற்று, &q);
	திரும்பு q;
}
#endif /* WITH_OPENSSL */
