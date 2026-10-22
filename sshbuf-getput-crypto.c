/*	$OpenBSD: sshbuf-getput-crypto.c,v 1.12 2024/08/15 00:51:51 djm Exp $	*/
/*
 * Copyright (c) 2011 Damien Miller
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>

#यदि_परिभाषितम् WITH_OPENSSL
#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/ec.h>

#अन्तर्भाव "ssherr.h"
#परिभाषय SSHBUF_आन्तरिकम्
#अन्तर्भाव "sshbuf.h"

पूर्णाङ्क
sshbuf_get_bignum2(संरचना sshbuf *buf, BIGNUM **valp)
{
	BIGNUM *v;
	ध्रुव u_char *d;
	आकार_t len;
	पूर्णाङ्क r;

	यदि (valp != रिक्त)
		*valp = रिक्त;
	यदि ((r = sshbuf_get_bignum2_अष्टकानि_प्रत्यक्षम्(buf, &d, &len)) != 0)
		प्रत्यागम r;
	यदि (valp != रिक्त) {
		यदि ((v = BN_new()) == रिक्त ||
		    BN_bin2bn(d, len, v) == रिक्त) {
			BN_clear_free(v);
			प्रत्यागम SSH_ERR_ALLOC_FAIL;
		}
		*valp = v;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
get_ec(ध्रुव u_char *d, आकार_t len, EC_POINT *v, ध्रुव EC_गणः *g)
{
	/* Refuse overlong bignums */
	यदि (len == 0 || len > SSHBUF_MAX_ECPOINT)
		प्रत्यागम SSH_ERR_ECPOINT_TOO_LARGE;
	/* Only handle uncompressed points */
	यदि (*d != POINT_CONVERSION_UNCOMPRESSED)
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	यदि (v != रिक्त && EC_POINT_oct2point(g, v, d, len, रिक्त) != 1)
		प्रत्यागम SSH_ERR_INVALID_FORMAT; /* XXX assumption */
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_get_ec(संरचना sshbuf *buf, EC_POINT *v, ध्रुव EC_गणः *g)
{
	ध्रुव u_char *d;
	आकार_t len;
	पूर्णाङ्क r;

	यदि ((r = sshbuf_peek_string_प्रत्यक्षम्(buf, &d, &len)) < 0)
		प्रत्यागम r;
	यदि ((r = get_ec(d, len, v, g)) != 0)
		प्रत्यागम r;
	/* Skip string */
	यदि (sshbuf_get_string_प्रत्यक्षम्(buf, रिक्त, रिक्त) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_get_eckey(संरचना sshbuf *buf, EC_कुञ्चिका *v)
{
	EC_POINT *pt = EC_POINT_new(EC_कुञ्चिका_get0_गणः(v));
	पूर्णाङ्क r;
	ध्रुव u_char *d;
	आकार_t len;

	यदि (pt == रिक्त) {
		SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	}
	यदि ((r = sshbuf_peek_string_प्रत्यक्षम्(buf, &d, &len)) < 0) {
		EC_POINT_free(pt);
		प्रत्यागम r;
	}
	यदि ((r = get_ec(d, len, pt, EC_कुञ्चिका_get0_गणः(v))) != 0) {
		EC_POINT_free(pt);
		प्रत्यागम r;
	}
	यदि (EC_कुञ्चिका_समुच्चयः_लौकिकम्_कुञ्चिका(v, pt) != 1) {
		EC_POINT_free(pt);
		प्रत्यागम SSH_ERR_ALLOC_FAIL; /* XXX assumption */
	}
	EC_POINT_free(pt);
	/* Skip string */
	यदि (sshbuf_get_string_प्रत्यक्षम्(buf, रिक्त, रिक्त) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_put_bignum2(संरचना sshbuf *buf, ध्रुव BIGNUM *v)
{
	u_char d[SSHBUF_MAX_BIGNUM + 1];
	पूर्णाङ्क len = BN_अङ्कः_अष्टकानि(v), prepend = 0, r;

	यदि (len < 0 || len > SSHBUF_MAX_BIGNUM)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	*d = '\0';
	यदि (BN_bn2bin(v, d + 1) != len)
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR; /* Shouldn't happen */
	/* If MSB is set, prepend a \0 */
	यदि (len > 0 && (d[1] & 0x80) != 0)
		prepend = 1;
	यदि ((r = sshbuf_put_string(buf, d + 1 - prepend, len + prepend)) < 0) {
		explicit_bzero(d, परिमाण(d));
		प्रत्यागम r;
	}
	explicit_bzero(d, परिमाण(d));
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_put_ec(संरचना sshbuf *buf, ध्रुव EC_POINT *v, ध्रुव EC_गणः *g)
{
	u_char d[SSHBUF_MAX_ECPOINT];
	आकार_t len;
	पूर्णाङ्क ret;

	यदि ((len = EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    रिक्त, 0, रिक्त)) > SSHBUF_MAX_ECPOINT) {
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	}
	यदि (EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    d, len, रिक्त) != len) {
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR; /* Shouldn't happen */
	}
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	प्रत्यागम ret;
}

पूर्णाङ्क
sshbuf_put_eckey(संरचना sshbuf *buf, ध्रुव EC_कुञ्चिका *v)
{
	प्रत्यागम sshbuf_put_ec(buf, EC_कुञ्चिका_get0_लौकिकम्_कुञ्चिका(v),
	    EC_कुञ्चिका_get0_गणः(v));
}

पूर्णाङ्क
sshbuf_put_ec_pkey(संरचना sshbuf *buf, EVP_PKEY *pkey)
{
	ध्रुव EC_कुञ्चिका *ec;

	यदि ((ec = EVP_PKEY_get0_EC_कुञ्चिका(pkey)) == रिक्त)
		प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;
	प्रत्यागम sshbuf_put_eckey(buf, ec);
}
#यदि_अन्तः /* WITH_OPENSSL */
