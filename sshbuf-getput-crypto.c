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

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/ec.h>

#अन्तर्भाव "ssherr.h"
#define SSHBUF_INTERNAL
#अन्तर्भाव "sshbuf.h"

पूर्णाङ्क
sshbuf_get_bignum2(संरचना sshbuf *buf, BIGNUM **valp)
{
	BIGNUM *v;
	ध्रुव u_char *d;
	size_t len;
	पूर्णाङ्क r;

	सचे (valp != रिक्त)
		*valp = रिक्त;
	सचे ((r = sshbuf_get_bignum2_bytes_direct(buf, &d, &len)) != 0)
		पटिनिवत्त r;
	सचे (valp != रिक्त) {
		सचे ((v = BN_new()) == रिक्त ||
		    BN_bin2bn(d, len, v) == रिक्त) {
			BN_clear_free(v);
			पटिनिवत्त SSH_ERR_ALLOC_FAIL;
		}
		*valp = v;
	}
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
get_ec(ध्रुव u_char *d, size_t len, EC_POINT *v, ध्रुव EC_GROUP *g)
{
	/* Refuse overlong bignums */
	सचे (len == 0 || len > SSHBUF_MAX_ECPOINT)
		पटिनिवत्त SSH_ERR_ECPOINT_TOO_LARGE;
	/* Only handle uncompressed points */
	सचे (*d != POINT_CONVERSION_UNCOMPRESSED)
		पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	सचे (v != रिक्त && EC_POINT_oct2point(g, v, d, len, रिक्त) != 1)
		पटिनिवत्त SSH_ERR_INVALID_FORMAT; /* XXX assumption */
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_get_ec(संरचना sshbuf *buf, EC_POINT *v, ध्रुव EC_GROUP *g)
{
	ध्रुव u_char *d;
	size_t len;
	पूर्णाङ्क r;

	सचे ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0)
		पटिनिवत्त r;
	सचे ((r = get_ec(d, len, v, g)) != 0)
		पटिनिवत्त r;
	/* Skip string */
	सचे (sshbuf_get_string_direct(buf, रिक्त, रिक्त) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		पटिनिवत्त SSH_ERR_INTERNAL_ERROR;
	}
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_get_eckey(संरचना sshbuf *buf, EC_कुञ्चिका *v)
{
	EC_POINT *pt = EC_POINT_new(EC_कुञ्चिका_get0_group(v));
	पूर्णाङ्क r;
	ध्रुव u_char *d;
	size_t len;

	सचे (pt == रिक्त) {
		SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	}
	सचे ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0) {
		EC_POINT_free(pt);
		पटिनिवत्त r;
	}
	सचे ((r = get_ec(d, len, pt, EC_कुञ्चिका_get0_group(v))) != 0) {
		EC_POINT_free(pt);
		पटिनिवत्त r;
	}
	सचे (EC_कुञ्चिका_set_public_कुञ्चिका(v, pt) != 1) {
		EC_POINT_free(pt);
		पटिनिवत्त SSH_ERR_ALLOC_FAIL; /* XXX assumption */
	}
	EC_POINT_free(pt);
	/* Skip string */
	सचे (sshbuf_get_string_direct(buf, रिक्त, रिक्त) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		पटिनिवत्त SSH_ERR_INTERNAL_ERROR;
	}
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_put_bignum2(संरचना sshbuf *buf, ध्रुव BIGNUM *v)
{
	u_char d[SSHBUF_MAX_BIGNUM + 1];
	पूर्णाङ्क len = BN_अङ्कः_bytes(v), prepend = 0, r;

	सचे (len < 0 || len > SSHBUF_MAX_BIGNUM)
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;
	*d = '\0';
	सचे (BN_bn2bin(v, d + 1) != len)
		पटिनिवत्त SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	/* If MSB is set, prepend a \0 */
	सचे (len > 0 && (d[1] & 0x80) != 0)
		prepend = 1;
	सचे ((r = sshbuf_put_string(buf, d + 1 - prepend, len + prepend)) < 0) {
		explicit_bzero(d, परिमाण(d));
		पटिनिवत्त r;
	}
	explicit_bzero(d, परिमाण(d));
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_put_ec(संरचना sshbuf *buf, ध्रुव EC_POINT *v, ध्रुव EC_GROUP *g)
{
	u_char d[SSHBUF_MAX_ECPOINT];
	size_t len;
	पूर्णाङ्क ret;

	सचे ((len = EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    रिक्त, 0, रिक्त)) > SSHBUF_MAX_ECPOINT) {
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;
	}
	सचे (EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    d, len, रिक्त) != len) {
		पटिनिवत्त SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	}
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	पटिनिवत्त ret;
}

पूर्णाङ्क
sshbuf_put_eckey(संरचना sshbuf *buf, ध्रुव EC_कुञ्चिका *v)
{
	पटिनिवत्त sshbuf_put_ec(buf, EC_कुञ्चिका_get0_public_कुञ्चिका(v),
	    EC_कुञ्चिका_get0_group(v));
}

पूर्णाङ्क
sshbuf_put_ec_pkey(संरचना sshbuf *buf, EVP_PKEY *pkey)
{
	ध्रुव EC_कुञ्चिका *ec;

	सचे ((ec = EVP_PKEY_get0_EC_कुञ्चिका(pkey)) == रिक्त)
		पटिनिवत्त SSH_ERR_LIBCRYPTO_ERROR;
	पटिनिवत्त sshbuf_put_eckey(buf, ec);
}
#endif /* WITH_OPENSSL */
