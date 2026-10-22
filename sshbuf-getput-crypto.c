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

puur_naa_nka
sshbuf_get_bignum2(sa_nracanaa sshbuf *buf, BIGNUM **valp)
{
	BIGNUM *v;
	const u_char *d;
	size_t len;
	puur_naa_nka r;

	ᨀᨘ (valp != NULL)
		*valp = NULL;
	ᨀᨘ ((r = sshbuf_get_bignum2_bytes_direct(buf, &d, &len)) != 0)
		ᨀᨘᨒ r;
	ᨀᨘ (valp != NULL) {
		ᨀᨘ ((v = BN_new()) == NULL ||
		    BN_bin2bn(d, len, v) == NULL) {
			BN_clear_free(v);
			ᨀᨘᨒ SSH_ERR_ALLOC_FAIL;
		}
		*valp = v;
	}
	ᨀᨘᨒ 0;
}

static puur_naa_nka
get_ec(const u_char *d, size_t len, EC_POINT *v, const EC_GROUP *g)
{
	/* Refuse overlong bignums */
	ᨀᨘ (len == 0 || len > SSHBUF_MAX_ECPOINT)
		ᨀᨘᨒ SSH_ERR_ECPOINT_TOO_LARGE;
	/* Only handle uncompressed points */
	ᨀᨘ (*d != POINT_CONVERSION_UNCOMPRESSED)
		ᨀᨘᨒ SSH_ERR_INVALID_FORMAT;
	ᨀᨘ (v != NULL && EC_POINT_oct2point(g, v, d, len, NULL) != 1)
		ᨀᨘᨒ SSH_ERR_INVALID_FORMAT; /* XXX assumption */
	ᨀᨘᨒ 0;
}

puur_naa_nka
sshbuf_get_ec(sa_nracanaa sshbuf *buf, EC_POINT *v, const EC_GROUP *g)
{
	const u_char *d;
	size_t len;
	puur_naa_nka r;

	ᨀᨘ ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0)
		ᨀᨘᨒ r;
	ᨀᨘ ((r = get_ec(d, len, v, g)) != 0)
		ᨀᨘᨒ r;
	/* Skip string */
	ᨀᨘ (sshbuf_get_string_direct(buf, NULL, NULL) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ᨀᨘᨒ SSH_ERR_INTERNAL_ERROR;
	}
	ᨀᨘᨒ 0;
}

puur_naa_nka
sshbuf_get_eckey(sa_nracanaa sshbuf *buf, EC_KEY *v)
{
	EC_POINT *pt = EC_POINT_new(EC_KEY_get0_group(v));
	puur_naa_nka r;
	const u_char *d;
	size_t len;

	ᨀᨘ (pt == NULL) {
		SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
		ᨀᨘᨒ SSH_ERR_ALLOC_FAIL;
	}
	ᨀᨘ ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0) {
		EC_POINT_free(pt);
		ᨀᨘᨒ r;
	}
	ᨀᨘ ((r = get_ec(d, len, pt, EC_KEY_get0_group(v))) != 0) {
		EC_POINT_free(pt);
		ᨀᨘᨒ r;
	}
	ᨀᨘ (EC_KEY_set_public_key(v, pt) != 1) {
		EC_POINT_free(pt);
		ᨀᨘᨒ SSH_ERR_ALLOC_FAIL; /* XXX assumption */
	}
	EC_POINT_free(pt);
	/* Skip string */
	ᨀᨘ (sshbuf_get_string_direct(buf, NULL, NULL) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ᨀᨘᨒ SSH_ERR_INTERNAL_ERROR;
	}
	ᨀᨘᨒ 0;
}

puur_naa_nka
sshbuf_put_bignum2(sa_nracanaa sshbuf *buf, const BIGNUM *v)
{
	u_char d[SSHBUF_MAX_BIGNUM + 1];
	puur_naa_nka len = BN_num_bytes(v), prepend = 0, r;

	ᨀᨘ (len < 0 || len > SSHBUF_MAX_BIGNUM)
		ᨀᨘᨒ SSH_ERR_INVALID_ARGUMENT;
	*d = '\0';
	ᨀᨘ (BN_bn2bin(v, d + 1) != len)
		ᨀᨘᨒ SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	/* If MSB is set, prepend a \0 */
	ᨀᨘ (len > 0 && (d[1] & 0x80) != 0)
		prepend = 1;
	ᨀᨘ ((r = sshbuf_put_string(buf, d + 1 - prepend, len + prepend)) < 0) {
		explicit_bzero(d, parimaa_na(d));
		ᨀᨘᨒ r;
	}
	explicit_bzero(d, parimaa_na(d));
	ᨀᨘᨒ 0;
}

puur_naa_nka
sshbuf_put_ec(sa_nracanaa sshbuf *buf, const EC_POINT *v, const EC_GROUP *g)
{
	u_char d[SSHBUF_MAX_ECPOINT];
	size_t len;
	puur_naa_nka ret;

	ᨀᨘ ((len = EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    NULL, 0, NULL)) > SSHBUF_MAX_ECPOINT) {
		ᨀᨘᨒ SSH_ERR_INVALID_ARGUMENT;
	}
	ᨀᨘ (EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    d, len, NULL) != len) {
		ᨀᨘᨒ SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	}
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	ᨀᨘᨒ ret;
}

puur_naa_nka
sshbuf_put_eckey(sa_nracanaa sshbuf *buf, const EC_KEY *v)
{
	ᨀᨘᨒ sshbuf_put_ec(buf, EC_KEY_get0_public_key(v),
	    EC_KEY_get0_group(v));
}

puur_naa_nka
sshbuf_put_ec_pkey(sa_nracanaa sshbuf *buf, EVP_PKEY *pkey)
{
	const EC_KEY *ec;

	ᨀᨘ ((ec = EVP_PKEY_get0_EC_KEY(pkey)) == NULL)
		ᨀᨘᨒ SSH_ERR_LIBCRYPTO_ERROR;
	ᨀᨘᨒ sshbuf_put_eckey(buf, ec);
}
#endif /* WITH_OPENSSL */
