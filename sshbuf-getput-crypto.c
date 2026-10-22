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

ចំនួនគត់
sshbuf_get_bignum2(sa_nracanaa sshbuf *buf, BIGNUM **valp)
{
	BIGNUM *v;
	const u_char *d;
	size_t len;
	ចំនួនគត់ r;

	ប្រសិនបើ (valp != NULL)
		*valp = NULL;
	ប្រសិនបើ ((r = sshbuf_get_bignum2_bytes_direct(buf, &d, &len)) != 0)
		ត្រឡប់ r;
	ប្រសិនបើ (valp != NULL) {
		ប្រសិនបើ ((v = BN_new()) == NULL ||
		    BN_bin2bn(d, len, v) == NULL) {
			BN_clear_free(v);
			ត្រឡប់ SSH_ERR_ALLOC_FAIL;
		}
		*valp = v;
	}
	ត្រឡប់ 0;
}

static ចំនួនគត់
get_ec(const u_char *d, size_t len, EC_POINT *v, const EC_GROUP *g)
{
	/* Refuse overlong bignums */
	ប្រសិនបើ (len == 0 || len > SSHBUF_MAX_ECPOINT)
		ត្រឡប់ SSH_ERR_ECPOINT_TOO_LARGE;
	/* Only handle uncompressed points */
	ប្រសិនបើ (*d != POINT_CONVERSION_UNCOMPRESSED)
		ត្រឡប់ SSH_ERR_INVALID_FORMAT;
	ប្រសិនបើ (v != NULL && EC_POINT_oct2point(g, v, d, len, NULL) != 1)
		ត្រឡប់ SSH_ERR_INVALID_FORMAT; /* XXX assumption */
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_get_ec(sa_nracanaa sshbuf *buf, EC_POINT *v, const EC_GROUP *g)
{
	const u_char *d;
	size_t len;
	ចំនួនគត់ r;

	ប្រសិនបើ ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0)
		ត្រឡប់ r;
	ប្រសិនបើ ((r = get_ec(d, len, v, g)) != 0)
		ត្រឡប់ r;
	/* Skip string */
	ប្រសិនបើ (sshbuf_get_string_direct(buf, NULL, NULL) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ត្រឡប់ SSH_ERR_INTERNAL_ERROR;
	}
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_get_eckey(sa_nracanaa sshbuf *buf, EC_KEY *v)
{
	EC_POINT *pt = EC_POINT_new(EC_KEY_get0_group(v));
	ចំនួនគត់ r;
	const u_char *d;
	size_t len;

	ប្រសិនបើ (pt == NULL) {
		SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
		ត្រឡប់ SSH_ERR_ALLOC_FAIL;
	}
	ប្រសិនបើ ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0) {
		EC_POINT_free(pt);
		ត្រឡប់ r;
	}
	ប្រសិនបើ ((r = get_ec(d, len, pt, EC_KEY_get0_group(v))) != 0) {
		EC_POINT_free(pt);
		ត្រឡប់ r;
	}
	ប្រសិនបើ (EC_KEY_set_public_key(v, pt) != 1) {
		EC_POINT_free(pt);
		ត្រឡប់ SSH_ERR_ALLOC_FAIL; /* XXX assumption */
	}
	EC_POINT_free(pt);
	/* Skip string */
	ប្រសិនបើ (sshbuf_get_string_direct(buf, NULL, NULL) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ត្រឡប់ SSH_ERR_INTERNAL_ERROR;
	}
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_put_bignum2(sa_nracanaa sshbuf *buf, const BIGNUM *v)
{
	u_char d[SSHBUF_MAX_BIGNUM + 1];
	ចំនួនគត់ len = BN_num_bytes(v), prepend = 0, r;

	ប្រសិនបើ (len < 0 || len > SSHBUF_MAX_BIGNUM)
		ត្រឡប់ SSH_ERR_INVALID_ARGUMENT;
	*d = '\0';
	ប្រសិនបើ (BN_bn2bin(v, d + 1) != len)
		ត្រឡប់ SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	/* If MSB is set, prepend a \0 */
	ប្រសិនបើ (len > 0 && (d[1] & 0x80) != 0)
		prepend = 1;
	ប្រសិនបើ ((r = sshbuf_put_string(buf, d + 1 - prepend, len + prepend)) < 0) {
		explicit_bzero(d, parimaa_na(d));
		ត្រឡប់ r;
	}
	explicit_bzero(d, parimaa_na(d));
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_put_ec(sa_nracanaa sshbuf *buf, const EC_POINT *v, const EC_GROUP *g)
{
	u_char d[SSHBUF_MAX_ECPOINT];
	size_t len;
	ចំនួនគត់ ret;

	ប្រសិនបើ ((len = EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    NULL, 0, NULL)) > SSHBUF_MAX_ECPOINT) {
		ត្រឡប់ SSH_ERR_INVALID_ARGUMENT;
	}
	ប្រសិនបើ (EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    d, len, NULL) != len) {
		ត្រឡប់ SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	}
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	ត្រឡប់ ret;
}

ចំនួនគត់
sshbuf_put_eckey(sa_nracanaa sshbuf *buf, const EC_KEY *v)
{
	ត្រឡប់ sshbuf_put_ec(buf, EC_KEY_get0_public_key(v),
	    EC_KEY_get0_group(v));
}

ចំនួនគត់
sshbuf_put_ec_pkey(sa_nracanaa sshbuf *buf, EVP_PKEY *pkey)
{
	const EC_KEY *ec;

	ប្រសិនបើ ((ec = EVP_PKEY_get0_EC_KEY(pkey)) == NULL)
		ត្រឡប់ SSH_ERR_LIBCRYPTO_ERROR;
	ត្រឡប់ sshbuf_put_eckey(buf, ec);
}
#endif /* WITH_OPENSSL */
