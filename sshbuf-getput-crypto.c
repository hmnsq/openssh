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

पूर्णांक
sshbuf_get_bignum2(संरचना sshbuf *buf, BIGNUM **valp)
{
	BIGNUM *v;
	स्थिरांक u_char *d;
	माप_प्रकार len;
	पूर्णांक r;

	जर (valp != रिक्त)
		*valp = रिक्त;
	जर ((r = sshbuf_get_bignum2_bytes_direct(buf, &d, &len)) != 0)
		परत r;
	जर (valp != रिक्त) {
		जर ((v = BN_new()) == रिक्त ||
		    BN_bin2bn(d, len, v) == रिक्त) {
			BN_clear_free(v);
			परत SSH_ERR_ALLOC_FAIL;
		}
		*valp = v;
	}
	परत 0;
}

स्थिर पूर्णांक
get_ec(स्थिरांक u_char *d, माप_प्रकार len, EC_POINT *v, स्थिरांक EC_GROUP *g)
{
	/* Refuse overlong bignums */
	जर (len == 0 || len > SSHBUF_MAX_ECPOINT)
		परत SSH_ERR_ECPOINT_TOO_LARGE;
	/* Only handle uncompressed points */
	जर (*d != POINT_CONVERSION_UNCOMPRESSED)
		परत SSH_ERR_INVALID_FORMAT;
	जर (v != रिक्त && EC_POINT_oct2point(g, v, d, len, रिक्त) != 1)
		परत SSH_ERR_INVALID_FORMAT; /* XXX assumption */
	परत 0;
}

पूर्णांक
sshbuf_get_ec(संरचना sshbuf *buf, EC_POINT *v, स्थिरांक EC_GROUP *g)
{
	स्थिरांक u_char *d;
	माप_प्रकार len;
	पूर्णांक r;

	जर ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0)
		परत r;
	जर ((r = get_ec(d, len, v, g)) != 0)
		परत r;
	/* Skip string */
	जर (sshbuf_get_string_direct(buf, रिक्त, रिक्त) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		परत SSH_ERR_INTERNAL_ERROR;
	}
	परत 0;
}

पूर्णांक
sshbuf_get_eckey(संरचना sshbuf *buf, EC_किल्ली *v)
{
	EC_POINT *pt = EC_POINT_new(EC_किल्ली_get0_group(v));
	पूर्णांक r;
	स्थिरांक u_char *d;
	माप_प्रकार len;

	जर (pt == रिक्त) {
		SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
		परत SSH_ERR_ALLOC_FAIL;
	}
	जर ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0) {
		EC_POINT_free(pt);
		परत r;
	}
	जर ((r = get_ec(d, len, pt, EC_किल्ली_get0_group(v))) != 0) {
		EC_POINT_free(pt);
		परत r;
	}
	जर (EC_किल्ली_set_public_किल्ली(v, pt) != 1) {
		EC_POINT_free(pt);
		परत SSH_ERR_ALLOC_FAIL; /* XXX assumption */
	}
	EC_POINT_free(pt);
	/* Skip string */
	जर (sshbuf_get_string_direct(buf, रिक्त, रिक्त) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		परत SSH_ERR_INTERNAL_ERROR;
	}
	परत 0;
}

पूर्णांक
sshbuf_put_bignum2(संरचना sshbuf *buf, स्थिरांक BIGNUM *v)
{
	u_char d[SSHBUF_MAX_BIGNUM + 1];
	पूर्णांक len = BN_अंक_bytes(v), prepend = 0, r;

	जर (len < 0 || len > SSHBUF_MAX_BIGNUM)
		परत SSH_ERR_INVALID_ARGUMENT;
	*d = '\0';
	जर (BN_bn2bin(v, d + 1) != len)
		परत SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	/* If MSB is set, prepend a \0 */
	जर (len > 0 && (d[1] & 0x80) != 0)
		prepend = 1;
	जर ((r = sshbuf_put_string(buf, d + 1 - prepend, len + prepend)) < 0) {
		explicit_bzero(d, आकार(d));
		परत r;
	}
	explicit_bzero(d, आकार(d));
	परत 0;
}

पूर्णांक
sshbuf_put_ec(संरचना sshbuf *buf, स्थिरांक EC_POINT *v, स्थिरांक EC_GROUP *g)
{
	u_char d[SSHBUF_MAX_ECPOINT];
	माप_प्रकार len;
	पूर्णांक ret;

	जर ((len = EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    रिक्त, 0, रिक्त)) > SSHBUF_MAX_ECPOINT) {
		परत SSH_ERR_INVALID_ARGUMENT;
	}
	जर (EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    d, len, रिक्त) != len) {
		परत SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	}
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	परत ret;
}

पूर्णांक
sshbuf_put_eckey(संरचना sshbuf *buf, स्थिरांक EC_किल्ली *v)
{
	परत sshbuf_put_ec(buf, EC_किल्ली_get0_public_किल्ली(v),
	    EC_किल्ली_get0_group(v));
}

पूर्णांक
sshbuf_put_ec_pkey(संरचना sshbuf *buf, EVP_PKEY *pkey)
{
	स्थिरांक EC_किल्ली *ec;

	जर ((ec = EVP_PKEY_get0_EC_किल्ली(pkey)) == रिक्त)
		परत SSH_ERR_LIBCRYPTO_ERROR;
	परत sshbuf_put_eckey(buf, ec);
}
#endif /* WITH_OPENSSL */
