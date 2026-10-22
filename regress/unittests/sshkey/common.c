/* 	$OpenBSD: common.c,v 1.8 2025/06/16 08:49:27 dtucker Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/stat.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/ec.h>
#అన్తర్భావ <openssl/rsa.h>
#అన్తర్భావ <openssl/objects.h>
#అయితే_ముగింపు /* WITH_OPENSSL */

#అన్తర్భావ "openbsd-compat/openssl-compat.h"

#అన్తర్భావ "../test_helper/test_helper.h"

#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "sshbuf.h"

#అన్తర్భావ "common.h"

నిర్మాణం sshbuf *
ఎక్కించు_file(స్థిరరాశి అక్షరం *name)
{
	నిర్మాణం sshbuf *ret = ఖాళీ;

	ASSERT_INT_EQ(sshbuf_ఎక్కించు_file(test_దత్తాంశం_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, ఖాళీ);
	తిరిగి ret;
}

నిర్మాణం sshbuf *
ఎక్కించు_పాఠ్యం_file(స్థిరరాశి అక్షరం *name)
{
	నిర్మాణం sshbuf *ret = ఎక్కించు_file(name);
	స్థిరరాశి u_char *p;
	కొలత_t len;

	/* Trim whitespace at EOL */
	కొరకు (p = sshbuf_ptr(ret); (len = sshbuf_len(ret)) > 0;) {
		len--;
		ఒకవేళ (p[len] == '\r' || p[len] == '\t' ||
		    p[len] == ' ' || p[len] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_చివర(ret, 1), 0);
		లేకపోతే
			ఆపు;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	తిరిగి ret;
}

#నిర్వచితమైతే WITH_OPENSSL
BIGNUM *
ఎక్కించు_bignum(స్థిరరాశి అక్షరం *name)
{
	BIGNUM *ret = ఖాళీ;
	నిర్మాణం sshbuf *buf;

	buf = ఎక్కించు_పాఠ్యం_file(name);
	ASSERT_INT_NE(BN_hex2bn(&ret, (స్థిరరాశి అక్షరం *)sshbuf_ptr(buf)), 0);
	sshbuf_free(buf);
	తిరిగి ret;
}

స్థిరరాశి BIGNUM *
rsa_n(నిర్మాణం sshkey *k)
{
	స్థిరరాశి BIGNUM *n = ఖాళీ;

	ASSERT_PTR_NE(k, ఖాళీ);
	ASSERT_PTR_NE(k->pkey, ఖాళీ);
	RSA_get0_కీలకం(EVP_PKEY_get0_RSA(k->pkey), &n, ఖాళీ, ఖాళీ);
	తిరిగి n;
}

స్థిరరాశి BIGNUM *
rsa_e(నిర్మాణం sshkey *k)
{
	స్థిరరాశి BIGNUM *e = ఖాళీ;

	ASSERT_PTR_NE(k, ఖాళీ);
	ASSERT_PTR_NE(k->pkey, ఖాళీ);
	RSA_get0_కీలకం(EVP_PKEY_get0_RSA(k->pkey), ఖాళీ, &e, ఖాళీ);
	తిరిగి e;
}

స్థిరరాశి BIGNUM *
rsa_p(నిర్మాణం sshkey *k)
{
	స్థిరరాశి BIGNUM *p = ఖాళీ;

	ASSERT_PTR_NE(k, ఖాళీ);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), ఖాళీ);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), &p, ఖాళీ);
	తిరిగి p;
}

స్థిరరాశి BIGNUM *
rsa_q(నిర్మాణం sshkey *k)
{
	స్థిరరాశి BIGNUM *q = ఖాళీ;

	ASSERT_PTR_NE(k, ఖాళీ);
	ASSERT_PTR_NE(EVP_PKEY_get0_RSA(k->pkey), ఖాళీ);
	RSA_get0_factors(EVP_PKEY_get0_RSA(k->pkey), ఖాళీ, &q);
	తిరిగి q;
}
#అయితే_ముగింపు /* WITH_OPENSSL */
