/* 	$OpenBSD: common.c,v 1.8 2025/06/16 08:49:27 dtucker Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/stat.h>
#समावेश <fcntl.h>
#समावेश <stdio.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/bn.h>
#समावेश <openssl/ec.h>
#समावेश <openssl/rsa.h>
#समावेश <openssl/objects.h>
#पूर्ण_अगर /* WITH_OPENSSL */

#समावेश "openbsd-compat/openssl-compat.h"

#समावेश "../test_helper/test_helper.h"

#समावेश "ssherr.h"
#समावेश "authfile.h"
#समावेश "sshkey.h"
#समावेश "sshbuf.h"

#समावेश "common.h"

काष्ठा sshbuf *
load_file(स्थिर अक्षर *name)
{
	काष्ठा sshbuf *ret = शून्य;

	ASSERT_INT_EQ(sshbuf_load_file(test_तथ्य_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, शून्य);
	वापस ret;
}

काष्ठा sshbuf *
load_text_file(स्थिर अक्षर *name)
{
	काष्ठा sshbuf *ret = load_file(name);
	स्थिर u_char *p;
	माप_प्रकार len;

	/* Trim whitespace at EOL */
	क्रम (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		अगर (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		अन्यथा
			अवरोध;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	वापस ret;
}

#अगर_घोषित WITH_OPENSSL
BIGNUM *
load_bignum(स्थिर अक्षर *name)
{
	BIGNUM *ret = शून्य;
	काष्ठा sshbuf *buf;

	buf = load_text_file(name);
	ASSERT_INT_NE(BN_hex2bn(&ret, (स्थिर अक्षर *)sshbuf_ptr(buf)), 0);
	sshbuf_free(buf);
	वापस ret;
}

स्थिर BIGNUM *
rsa_n(काष्ठा sshkey *k)
{
	स्थिर BIGNUM *n = शून्य;

	ASSERT_PTR_NE(k, शून्य);
	ASSERT_PTR_NE(k->pkey, शून्य);
	RSA_get0_कुंजी(EVP_PKEY_get0_RSA(k->pkey), &n, शून्य, शून्य);
	वापस n;
}

स्थिर BIGNUM *
rsa_e(काष्ठा sshkey *k)
{
	स्थिर BIGNUM *e = शून्य;

	ASSERT_PTR_NE(k, शून्य);
	ASSERT_PTR_NE(k->pkey, शून्य);
	RSA_get0_कुंजी(EVP_PKEY_get0_RSA(k->pkey), शून्य, &e, शून्य);
	वापस e;
}

स्थिर BIGNUM *
rsa_p(काष्ठा sshkey *k)
{
	स्थिर BIGNUM *p = शून्य;

	ASSERT_PTR_NE(k, शून्य);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), शून्य);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), &p, शून्य);
	वापस p;
}

स्थिर BIGNUM *
rsa_q(काष्ठा sshkey *k)
{
	स्थिर BIGNUM *q = शून्य;

	ASSERT_PTR_NE(k, शून्य);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), शून्य);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), शून्य, &q);
	वापस q;
}
#पूर्ण_अगर /* WITH_OPENSSL */
