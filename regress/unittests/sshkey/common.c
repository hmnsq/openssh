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

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/ec.h>
#अन्तर्भाव <openssl/rsa.h>
#अन्तर्भाव <openssl/objects.h>
#endif /* WITH_OPENSSL */

#अन्तर्भाव "openbsd-compat/openssl-compat.h"

#अन्तर्भाव "../test_helper/test_helper.h"

#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "sshbuf.h"

#अन्तर्भाव "common.h"

संरचना sshbuf *
load_file(स्थिरांक अक्षर *name)
{
	संरचना sshbuf *ret = रिक्त;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, रिक्त);
	परत ret;
}

संरचना sshbuf *
load_text_file(स्थिरांक अक्षर *name)
{
	संरचना sshbuf *ret = load_file(name);
	स्थिरांक u_char *p;
	माप_प्रकार len;

	/* Trim whitespace at EOL */
	साठी (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		जर (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		अन्यथा
			थांबा;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	परत ret;
}

#ifdef WITH_OPENSSL
BIGNUM *
load_bignum(स्थिरांक अक्षर *name)
{
	BIGNUM *ret = रिक्त;
	संरचना sshbuf *buf;

	buf = load_text_file(name);
	ASSERT_INT_NE(BN_hex2bn(&ret, (स्थिरांक अक्षर *)sshbuf_ptr(buf)), 0);
	sshbuf_free(buf);
	परत ret;
}

स्थिरांक BIGNUM *
rsa_n(संरचना sshkey *k)
{
	स्थिरांक BIGNUM *n = रिक्त;

	ASSERT_PTR_NE(k, रिक्त);
	ASSERT_PTR_NE(k->pkey, रिक्त);
	RSA_get0_किल्ली(EVP_PKEY_get0_RSA(k->pkey), &n, रिक्त, रिक्त);
	परत n;
}

स्थिरांक BIGNUM *
rsa_e(संरचना sshkey *k)
{
	स्थिरांक BIGNUM *e = रिक्त;

	ASSERT_PTR_NE(k, रिक्त);
	ASSERT_PTR_NE(k->pkey, रिक्त);
	RSA_get0_किल्ली(EVP_PKEY_get0_RSA(k->pkey), रिक्त, &e, रिक्त);
	परत e;
}

स्थिरांक BIGNUM *
rsa_p(संरचना sshkey *k)
{
	स्थिरांक BIGNUM *p = रिक्त;

	ASSERT_PTR_NE(k, रिक्त);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), रिक्त);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), &p, रिक्त);
	परत p;
}

स्थिरांक BIGNUM *
rsa_q(संरचना sshkey *k)
{
	स्थिरांक BIGNUM *q = रिक्त;

	ASSERT_PTR_NE(k, रिक्त);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), रिक्त);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), रिक्त, &q);
	परत q;
}
#endif /* WITH_OPENSSL */
