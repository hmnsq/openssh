/* 	$OpenBSD: common.c,v 1.8 2025/06/16 08:49:27 dtucker Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#यदि_परिभाषितम् WITH_OPENSSL
#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/ec.h>
#अन्तर्भाव <openssl/rsa.h>
#अन्तर्भाव <openssl/objects.h>
#यदि_अन्तः /* WITH_OPENSSL */

#अन्तर्भाव "openbsd-compat/openssl-compat.h"

#अन्तर्भाव "../test_helper/test_helper.h"

#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "sshbuf.h"

#अन्तर्भाव "common.h"

संरचना sshbuf *
आरोपय_file(ध्रुव वर्ण *name)
{
	संरचना sshbuf *ret = रिक्त;

	ASSERT_INT_EQ(sshbuf_आरोपय_file(test_दत्त_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, रिक्त);
	प्रत्यागम ret;
}

संरचना sshbuf *
आरोपय_text_file(ध्रुव वर्ण *name)
{
	संरचना sshbuf *ret = आरोपय_file(name);
	ध्रुव u_char *p;
	आकार_t len;

	/* Trim whitespace at EOL */
	प्रति (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		यदि (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_अन्तः(ret, 1), 0);
		अन्यथा
			भङ्ग;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	प्रत्यागम ret;
}

#यदि_परिभाषितम् WITH_OPENSSL
BIGNUM *
आरोपय_bignum(ध्रुव वर्ण *name)
{
	BIGNUM *ret = रिक्त;
	संरचना sshbuf *buf;

	buf = आरोपय_text_file(name);
	ASSERT_INT_NE(BN_hex2bn(&ret, (ध्रुव वर्ण *)sshbuf_ptr(buf)), 0);
	sshbuf_free(buf);
	प्रत्यागम ret;
}

ध्रुव BIGNUM *
rsa_n(संरचना sshkey *k)
{
	ध्रुव BIGNUM *n = रिक्त;

	ASSERT_PTR_NE(k, रिक्त);
	ASSERT_PTR_NE(k->pkey, रिक्त);
	RSA_get0_कुञ्चिका(EVP_PKEY_get0_RSA(k->pkey), &n, रिक्त, रिक्त);
	प्रत्यागम n;
}

ध्रुव BIGNUM *
rsa_e(संरचना sshkey *k)
{
	ध्रुव BIGNUM *e = रिक्त;

	ASSERT_PTR_NE(k, रिक्त);
	ASSERT_PTR_NE(k->pkey, रिक्त);
	RSA_get0_कुञ्चिका(EVP_PKEY_get0_RSA(k->pkey), रिक्त, &e, रिक्त);
	प्रत्यागम e;
}

ध्रुव BIGNUM *
rsa_p(संरचना sshkey *k)
{
	ध्रुव BIGNUM *p = रिक्त;

	ASSERT_PTR_NE(k, रिक्त);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), रिक्त);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), &p, रिक्त);
	प्रत्यागम p;
}

ध्रुव BIGNUM *
rsa_q(संरचना sshkey *k)
{
	ध्रुव BIGNUM *q = रिक्त;

	ASSERT_PTR_NE(k, रिक्त);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), रिक्त);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), रिक्त, &q);
	प्रत्यागम q;
}
#यदि_अन्तः /* WITH_OPENSSL */
