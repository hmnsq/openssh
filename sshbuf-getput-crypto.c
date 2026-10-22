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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <string.h>

#ifdef WITH_OPENSSL
#شامل <openssl/bn.h>
#شامل <openssl/ec.h>

#شامل "ssherr.h"
#define SSHBUF_INTERNAL
#شامل "sshbuf.h"

صحیح
sshbuf_get_bignum2(ساختار sshbuf *buf, BIGNUM **valp)
{
	BIGNUM *v;
	ثابت u_char *d;
	size_t len;
	صحیح r;

	اگر (valp != پوچ)
		*valp = پوچ;
	اگر ((r = sshbuf_get_bignum2_bytes_direct(buf, &d, &len)) != 0)
		بازگشت r;
	اگر (valp != پوچ) {
		اگر ((v = BN_new()) == پوچ ||
		    BN_bin2bn(d, len, v) == پوچ) {
			BN_clear_free(v);
			بازگشت SSH_ERR_ALLOC_FAIL;
		}
		*valp = v;
	}
	بازگشت 0;
}

ایستا صحیح
get_ec(ثابت u_char *d, size_t len, EC_POINT *v, ثابت EC_GROUP *g)
{
	/* Refuse overlong bignums */
	اگر (len == 0 || len > SSHBUF_MAX_ECPOINT)
		بازگشت SSH_ERR_ECPOINT_TOO_LARGE;
	/* Only handle uncompressed points */
	اگر (*d != POINT_CONVERSION_UNCOMPRESSED)
		بازگشت SSH_ERR_INVALID_FORMAT;
	اگر (v != پوچ && EC_POINT_oct2point(g, v, d, len, پوچ) != 1)
		بازگشت SSH_ERR_INVALID_FORMAT; /* XXX assumption */
	بازگشت 0;
}

صحیح
sshbuf_get_ec(ساختار sshbuf *buf, EC_POINT *v, ثابت EC_GROUP *g)
{
	ثابت u_char *d;
	size_t len;
	صحیح r;

	اگر ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0)
		بازگشت r;
	اگر ((r = get_ec(d, len, v, g)) != 0)
		بازگشت r;
	/* Skip string */
	اگر (sshbuf_get_string_direct(buf, پوچ, پوچ) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		بازگشت SSH_ERR_INTERNAL_ERROR;
	}
	بازگشت 0;
}

صحیح
sshbuf_get_eckey(ساختار sshbuf *buf, EC_کلید *v)
{
	EC_POINT *pt = EC_POINT_new(EC_کلید_get0_group(v));
	صحیح r;
	ثابت u_char *d;
	size_t len;

	اگر (pt == پوچ) {
		SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
		بازگشت SSH_ERR_ALLOC_FAIL;
	}
	اگر ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0) {
		EC_POINT_free(pt);
		بازگشت r;
	}
	اگر ((r = get_ec(d, len, pt, EC_کلید_get0_group(v))) != 0) {
		EC_POINT_free(pt);
		بازگشت r;
	}
	اگر (EC_کلید_set_public_کلید(v, pt) != 1) {
		EC_POINT_free(pt);
		بازگشت SSH_ERR_ALLOC_FAIL; /* XXX assumption */
	}
	EC_POINT_free(pt);
	/* Skip string */
	اگر (sshbuf_get_string_direct(buf, پوچ, پوچ) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		بازگشت SSH_ERR_INTERNAL_ERROR;
	}
	بازگشت 0;
}

صحیح
sshbuf_put_bignum2(ساختار sshbuf *buf, ثابت BIGNUM *v)
{
	u_char d[SSHBUF_MAX_BIGNUM + 1];
	صحیح len = BN_رقم_bytes(v), prepend = 0, r;

	اگر (len < 0 || len > SSHBUF_MAX_BIGNUM)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	*d = '\0';
	اگر (BN_bn2bin(v, d + 1) != len)
		بازگشت SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	/* If MSB is set, prepend a \0 */
	اگر (len > 0 && (d[1] & 0x80) != 0)
		prepend = 1;
	اگر ((r = sshbuf_put_string(buf, d + 1 - prepend, len + prepend)) < 0) {
		explicit_bzero(d, اندازه(d));
		بازگشت r;
	}
	explicit_bzero(d, اندازه(d));
	بازگشت 0;
}

صحیح
sshbuf_put_ec(ساختار sshbuf *buf, ثابت EC_POINT *v, ثابت EC_GROUP *g)
{
	u_char d[SSHBUF_MAX_ECPOINT];
	size_t len;
	صحیح ret;

	اگر ((len = EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    پوچ, 0, پوچ)) > SSHBUF_MAX_ECPOINT) {
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	}
	اگر (EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    d, len, پوچ) != len) {
		بازگشت SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	}
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	بازگشت ret;
}

صحیح
sshbuf_put_eckey(ساختار sshbuf *buf, ثابت EC_کلید *v)
{
	بازگشت sshbuf_put_ec(buf, EC_کلید_get0_public_کلید(v),
	    EC_کلید_get0_group(v));
}

صحیح
sshbuf_put_ec_pkey(ساختار sshbuf *buf, EVP_PKEY *pkey)
{
	ثابت EC_کلید *ec;

	اگر ((ec = EVP_PKEY_get0_EC_کلید(pkey)) == پوچ)
		بازگشت SSH_ERR_LIBCRYPTO_ERROR;
	بازگشت sshbuf_put_eckey(buf, ec);
}
#endif /* WITH_OPENSSL */
