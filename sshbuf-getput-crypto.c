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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <string.h>

#ifdef WITH_OPENSSL
#ضمن <openssl/bn.h>
#ضمن <openssl/ec.h>

#ضمن "ssherr.h"
#define SSHBUF_INTERNAL
#ضمن "sshbuf.h"

صحيح
sshbuf_get_bignum2(بنية sshbuf *buf, BIGNUM **valp)
{
	BIGNUM *v;
	ثابت u_char *d;
	size_t len;
	صحيح r;

	إذا (valp != عدم)
		*valp = عدم;
	إذا ((r = sshbuf_get_bignum2_bytes_direct(buf, &d, &len)) != 0)
		أرجع r;
	إذا (valp != عدم) {
		إذا ((v = BN_new()) == عدم ||
		    BN_bin2bn(d, len, v) == عدم) {
			BN_clear_free(v);
			أرجع SSH_ERR_ALLOC_FAIL;
		}
		*valp = v;
	}
	أرجع 0;
}

ساكن صحيح
get_ec(ثابت u_char *d, size_t len, EC_POINT *v, ثابت EC_GROUP *g)
{
	/* Refuse overlong bignums */
	إذا (len == 0 || len > SSHBUF_MAX_ECPOINT)
		أرجع SSH_ERR_ECPOINT_TOO_LARGE;
	/* Only handle uncompressed points */
	إذا (*d != POINT_CONVERSION_UNCOMPRESSED)
		أرجع SSH_ERR_INVALID_FORMAT;
	إذا (v != عدم && EC_POINT_oct2point(g, v, d, len, عدم) != 1)
		أرجع SSH_ERR_INVALID_FORMAT; /* XXX assumption */
	أرجع 0;
}

صحيح
sshbuf_get_ec(بنية sshbuf *buf, EC_POINT *v, ثابت EC_GROUP *g)
{
	ثابت u_char *d;
	size_t len;
	صحيح r;

	إذا ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0)
		أرجع r;
	إذا ((r = get_ec(d, len, v, g)) != 0)
		أرجع r;
	/* Skip string */
	إذا (sshbuf_get_string_direct(buf, عدم, عدم) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		أرجع SSH_ERR_INTERNAL_ERROR;
	}
	أرجع 0;
}

صحيح
sshbuf_get_eckey(بنية sshbuf *buf, EC_مبودي *v)
{
	EC_POINT *pt = EC_POINT_new(EC_مبودي_get0_group(v));
	صحيح r;
	ثابت u_char *d;
	size_t len;

	إذا (pt == عدم) {
		SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
		أرجع SSH_ERR_ALLOC_FAIL;
	}
	إذا ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0) {
		EC_POINT_free(pt);
		أرجع r;
	}
	إذا ((r = get_ec(d, len, pt, EC_مبودي_get0_group(v))) != 0) {
		EC_POINT_free(pt);
		أرجع r;
	}
	إذا (EC_مبودي_set_public_مبودي(v, pt) != 1) {
		EC_POINT_free(pt);
		أرجع SSH_ERR_ALLOC_FAIL; /* XXX assumption */
	}
	EC_POINT_free(pt);
	/* Skip string */
	إذا (sshbuf_get_string_direct(buf, عدم, عدم) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		أرجع SSH_ERR_INTERNAL_ERROR;
	}
	أرجع 0;
}

صحيح
sshbuf_put_bignum2(بنية sshbuf *buf, ثابت BIGNUM *v)
{
	u_char d[SSHBUF_MAX_BIGNUM + 1];
	صحيح len = BN_لمب_bytes(v), prepend = 0, r;

	إذا (len < 0 || len > SSHBUF_MAX_BIGNUM)
		أرجع SSH_ERR_INVALID_ARGUMENT;
	*d = '\0';
	إذا (BN_bn2bin(v, d + 1) != len)
		أرجع SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	/* If MSB is set, prepend a \0 */
	إذا (len > 0 && (d[1] & 0x80) != 0)
		prepend = 1;
	إذا ((r = sshbuf_put_string(buf, d + 1 - prepend, len + prepend)) < 0) {
		explicit_bzero(d, حجم(d));
		أرجع r;
	}
	explicit_bzero(d, حجم(d));
	أرجع 0;
}

صحيح
sshbuf_put_ec(بنية sshbuf *buf, ثابت EC_POINT *v, ثابت EC_GROUP *g)
{
	u_char d[SSHBUF_MAX_ECPOINT];
	size_t len;
	صحيح ret;

	إذا ((len = EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    عدم, 0, عدم)) > SSHBUF_MAX_ECPOINT) {
		أرجع SSH_ERR_INVALID_ARGUMENT;
	}
	إذا (EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    d, len, عدم) != len) {
		أرجع SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	}
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	أرجع ret;
}

صحيح
sshbuf_put_eckey(بنية sshbuf *buf, ثابت EC_مبودي *v)
{
	أرجع sshbuf_put_ec(buf, EC_مبودي_get0_public_مبودي(v),
	    EC_مبودي_get0_group(v));
}

صحيح
sshbuf_put_ec_pkey(بنية sshbuf *buf, EVP_PKEY *pkey)
{
	ثابت EC_مبودي *ec;

	إذا ((ec = EVP_PKEY_get0_EC_مبودي(pkey)) == عدم)
		أرجع SSH_ERR_LIBCRYPTO_ERROR;
	أرجع sshbuf_put_eckey(buf, ec);
}
#endif /* WITH_OPENSSL */
