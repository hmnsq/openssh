/* 	$OpenBSD: common.c,v 1.8 2025/06/16 08:49:27 dtucker Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/stat.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/bn.h>
#অন্তর্ভাব <openssl/ec.h>
#অন্তর্ভাব <openssl/rsa.h>
#অন্তর্ভাব <openssl/objects.h>
#endif /* WITH_OPENSSL */

#অন্তর্ভাব "openbsd-compat/openssl-compat.h"

#অন্তর্ভাব "../test_helper/test_helper.h"

#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "sshbuf.h"

#অন্তর্ভাব "common.h"

কাঠামো sshbuf *
load_file(ধ্রুবক অক্ষর *name)
{
	কাঠামো sshbuf *ret = ফাঁকা;

	ASSERT_INT_EQ(sshbuf_load_file(test_তথ্য_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, ফাঁকা);
	ফেরত ret;
}

কাঠামো sshbuf *
load_text_file(ধ্রুবক অক্ষর *name)
{
	কাঠামো sshbuf *ret = load_file(name);
	ধ্রুবক u_char *p;
	আকার_t len;

	/* Trim whitespace at EOL */
	জন্য (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		যদি (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		অন্যথা
			বিরতি;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	ফেরত ret;
}

#ifdef WITH_OPENSSL
BIGNUM *
load_bignum(ধ্রুবক অক্ষর *name)
{
	BIGNUM *ret = ফাঁকা;
	কাঠামো sshbuf *buf;

	buf = load_text_file(name);
	ASSERT_INT_NE(BN_hex2bn(&ret, (ধ্রুবক অক্ষর *)sshbuf_ptr(buf)), 0);
	sshbuf_free(buf);
	ফেরত ret;
}

ধ্রুবক BIGNUM *
rsa_n(কাঠামো sshkey *k)
{
	ধ্রুবক BIGNUM *n = ফাঁকা;

	ASSERT_PTR_NE(k, ফাঁকা);
	ASSERT_PTR_NE(k->pkey, ফাঁকা);
	RSA_get0_চাবি(EVP_PKEY_get0_RSA(k->pkey), &n, ফাঁকা, ফাঁকা);
	ফেরত n;
}

ধ্রুবক BIGNUM *
rsa_e(কাঠামো sshkey *k)
{
	ধ্রুবক BIGNUM *e = ফাঁকা;

	ASSERT_PTR_NE(k, ফাঁকা);
	ASSERT_PTR_NE(k->pkey, ফাঁকা);
	RSA_get0_চাবি(EVP_PKEY_get0_RSA(k->pkey), ফাঁকা, &e, ফাঁকা);
	ফেরত e;
}

ধ্রুবক BIGNUM *
rsa_p(কাঠামো sshkey *k)
{
	ধ্রুবক BIGNUM *p = ফাঁকা;

	ASSERT_PTR_NE(k, ফাঁকা);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), ফাঁকা);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), &p, ফাঁকা);
	ফেরত p;
}

ধ্রুবক BIGNUM *
rsa_q(কাঠামো sshkey *k)
{
	ধ্রুবক BIGNUM *q = ফাঁকা;

	ASSERT_PTR_NE(k, ফাঁকা);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), ফাঁকা);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), ফাঁকা, &q);
	ফেরত q;
}
#endif /* WITH_OPENSSL */
