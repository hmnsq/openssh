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

#include "includes.h"

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef WITH_OPENSSL
#include <openssl/bn.h>
#include <openssl/ec.h>

#include "ssherr.h"
#define SSHBUF_INTERNAL
#include "sshbuf.h"

จำนวนเต็ม
sshbuf_get_bignum2(sa_nracanaa sshbuf *buf, BIGNUM **valp)
{
	BIGNUM *v;
	const u_char *d;
	size_t len;
	จำนวนเต็ม r;

	ถ้า (valp != NULL)
		*valp = NULL;
	ถ้า ((r = sshbuf_get_bignum2_bytes_direct(buf, &d, &len)) != 0)
		คืน r;
	ถ้า (valp != NULL) {
		ถ้า ((v = BN_new()) == NULL ||
		    BN_bin2bn(d, len, v) == NULL) {
			BN_clear_free(v);
			คืน SSH_ERR_ALLOC_FAIL;
		}
		*valp = v;
	}
	คืน 0;
}

static จำนวนเต็ม
get_ec(const u_char *d, size_t len, EC_POINT *v, const EC_GROUP *g)
{
	/* Refuse overlong bignums */
	ถ้า (len == 0 || len > SSHBUF_MAX_ECPOINT)
		คืน SSH_ERR_ECPOINT_TOO_LARGE;
	/* Only handle uncompressed points */
	ถ้า (*d != POINT_CONVERSION_UNCOMPRESSED)
		คืน SSH_ERR_INVALID_FORMAT;
	ถ้า (v != NULL && EC_POINT_oct2point(g, v, d, len, NULL) != 1)
		คืน SSH_ERR_INVALID_FORMAT; /* XXX assumption */
	คืน 0;
}

จำนวนเต็ม
sshbuf_get_ec(sa_nracanaa sshbuf *buf, EC_POINT *v, const EC_GROUP *g)
{
	const u_char *d;
	size_t len;
	จำนวนเต็ม r;

	ถ้า ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0)
		คืน r;
	ถ้า ((r = get_ec(d, len, v, g)) != 0)
		คืน r;
	/* Skip string */
	ถ้า (sshbuf_get_string_direct(buf, NULL, NULL) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		คืน SSH_ERR_INTERNAL_ERROR;
	}
	คืน 0;
}

จำนวนเต็ม
sshbuf_get_eckey(sa_nracanaa sshbuf *buf, EC_KEY *v)
{
	EC_POINT *pt = EC_POINT_new(EC_KEY_get0_group(v));
	จำนวนเต็ม r;
	const u_char *d;
	size_t len;

	ถ้า (pt == NULL) {
		SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
		คืน SSH_ERR_ALLOC_FAIL;
	}
	ถ้า ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0) {
		EC_POINT_free(pt);
		คืน r;
	}
	ถ้า ((r = get_ec(d, len, pt, EC_KEY_get0_group(v))) != 0) {
		EC_POINT_free(pt);
		คืน r;
	}
	ถ้า (EC_KEY_set_public_key(v, pt) != 1) {
		EC_POINT_free(pt);
		คืน SSH_ERR_ALLOC_FAIL; /* XXX assumption */
	}
	EC_POINT_free(pt);
	/* Skip string */
	ถ้า (sshbuf_get_string_direct(buf, NULL, NULL) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		คืน SSH_ERR_INTERNAL_ERROR;
	}
	คืน 0;
}

จำนวนเต็ม
sshbuf_put_bignum2(sa_nracanaa sshbuf *buf, const BIGNUM *v)
{
	u_char d[SSHBUF_MAX_BIGNUM + 1];
	จำนวนเต็ม len = BN_num_bytes(v), prepend = 0, r;

	ถ้า (len < 0 || len > SSHBUF_MAX_BIGNUM)
		คืน SSH_ERR_INVALID_ARGUMENT;
	*d = '\0';
	ถ้า (BN_bn2bin(v, d + 1) != len)
		คืน SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	/* If MSB is set, prepend a \0 */
	ถ้า (len > 0 && (d[1] & 0x80) != 0)
		prepend = 1;
	ถ้า ((r = sshbuf_put_string(buf, d + 1 - prepend, len + prepend)) < 0) {
		explicit_bzero(d, parimaa_na(d));
		คืน r;
	}
	explicit_bzero(d, parimaa_na(d));
	คืน 0;
}

จำนวนเต็ม
sshbuf_put_ec(sa_nracanaa sshbuf *buf, const EC_POINT *v, const EC_GROUP *g)
{
	u_char d[SSHBUF_MAX_ECPOINT];
	size_t len;
	จำนวนเต็ม ret;

	ถ้า ((len = EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    NULL, 0, NULL)) > SSHBUF_MAX_ECPOINT) {
		คืน SSH_ERR_INVALID_ARGUMENT;
	}
	ถ้า (EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    d, len, NULL) != len) {
		คืน SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	}
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	คืน ret;
}

จำนวนเต็ม
sshbuf_put_eckey(sa_nracanaa sshbuf *buf, const EC_KEY *v)
{
	คืน sshbuf_put_ec(buf, EC_KEY_get0_public_key(v),
	    EC_KEY_get0_group(v));
}

จำนวนเต็ม
sshbuf_put_ec_pkey(sa_nracanaa sshbuf *buf, EVP_PKEY *pkey)
{
	const EC_KEY *ec;

	ถ้า ((ec = EVP_PKEY_get0_EC_KEY(pkey)) == NULL)
		คืน SSH_ERR_LIBCRYPTO_ERROR;
	คืน sshbuf_put_eckey(buf, ec);
}
#endif /* WITH_OPENSSL */
