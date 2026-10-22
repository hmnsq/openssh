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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/ec.h>

#ಅನ್ತರ್ಭಾವ "ssherr.h"
#define SSHBUF_INTERNAL
#ಅನ್ತರ್ಭಾವ "sshbuf.h"

ಪೂರ್ಣಾಙ್ಕ
sshbuf_get_bignum2(ಸಂರಚನಾ sshbuf *buf, BIGNUM **valp)
{
	BIGNUM *v;
	ಧ್ರುವ u_char *d;
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (valp != ರಿಕ್ತ)
		*valp = ರಿಕ್ತ;
	ಯದಿ ((r = sshbuf_get_bignum2_bytes_direct(buf, &d, &len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (valp != ರಿಕ್ತ) {
		ಯದಿ ((v = BN_new()) == ರಿಕ್ತ ||
		    BN_bin2bn(d, len, v) == ರಿಕ್ತ) {
			BN_clear_free(v);
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
		}
		*valp = v;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
get_ec(ಧ್ರುವ u_char *d, size_t len, EC_POINT *v, ಧ್ರುವ EC_GROUP *g)
{
	/* Refuse overlong bignums */
	ಯದಿ (len == 0 || len > SSHBUF_MAX_ECPOINT)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ECPOINT_TOO_LARGE;
	/* Only handle uncompressed points */
	ಯದಿ (*d != POINT_CONVERSION_UNCOMPRESSED)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	ಯದಿ (v != ರಿಕ್ತ && EC_POINT_oct2point(g, v, d, len, ರಿಕ್ತ) != 1)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT; /* XXX assumption */
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_get_ec(ಸಂರಚನಾ sshbuf *buf, EC_POINT *v, ಧ್ರುವ EC_GROUP *g)
{
	ಧ್ರುವ u_char *d;
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((r = get_ec(d, len, v, g)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	/* Skip string */
	ಯದಿ (sshbuf_get_string_direct(buf, ರಿಕ್ತ, ರಿಕ್ತ) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_get_eckey(ಸಂರಚನಾ sshbuf *buf, EC_ಕೀಲಿ *v)
{
	EC_POINT *pt = EC_POINT_new(EC_ಕೀಲಿ_get0_group(v));
	ಪೂರ್ಣಾಙ್ಕ r;
	ಧ್ರುವ u_char *d;
	size_t len;

	ಯದಿ (pt == ರಿಕ್ತ) {
		SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	}
	ಯದಿ ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0) {
		EC_POINT_free(pt);
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಯದಿ ((r = get_ec(d, len, pt, EC_ಕೀಲಿ_get0_group(v))) != 0) {
		EC_POINT_free(pt);
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಯದಿ (EC_ಕೀಲಿ_set_public_ಕೀಲಿ(v, pt) != 1) {
		EC_POINT_free(pt);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL; /* XXX assumption */
	}
	EC_POINT_free(pt);
	/* Skip string */
	ಯದಿ (sshbuf_get_string_direct(buf, ರಿಕ್ತ, ರಿಕ್ತ) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_put_bignum2(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ BIGNUM *v)
{
	u_char d[SSHBUF_MAX_BIGNUM + 1];
	ಪೂರ್ಣಾಙ್ಕ len = BN_ಅಂಕೆ_bytes(v), prepend = 0, r;

	ಯದಿ (len < 0 || len > SSHBUF_MAX_BIGNUM)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	*d = '\0';
	ಯದಿ (BN_bn2bin(v, d + 1) != len)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	/* If MSB is set, prepend a \0 */
	ಯದಿ (len > 0 && (d[1] & 0x80) != 0)
		prepend = 1;
	ಯದಿ ((r = sshbuf_put_string(buf, d + 1 - prepend, len + prepend)) < 0) {
		explicit_bzero(d, ಪರಿಮಾಣ(d));
		ಪ್ರತ್ಯಾಗಮ r;
	}
	explicit_bzero(d, ಪರಿಮಾಣ(d));
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_put_ec(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ EC_POINT *v, ಧ್ರುವ EC_GROUP *g)
{
	u_char d[SSHBUF_MAX_ECPOINT];
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ ret;

	ಯದಿ ((len = EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    ರಿಕ್ತ, 0, ರಿಕ್ತ)) > SSHBUF_MAX_ECPOINT) {
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	}
	ಯದಿ (EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    d, len, ರಿಕ್ತ) != len) {
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	}
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_put_eckey(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ EC_ಕೀಲಿ *v)
{
	ಪ್ರತ್ಯಾಗಮ sshbuf_put_ec(buf, EC_ಕೀಲಿ_get0_public_ಕೀಲಿ(v),
	    EC_ಕೀಲಿ_get0_group(v));
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_put_ec_pkey(ಸಂರಚನಾ sshbuf *buf, EVP_PKEY *pkey)
{
	ಧ್ರುವ EC_ಕೀಲಿ *ec;

	ಯದಿ ((ec = EVP_PKEY_get0_EC_ಕೀಲಿ(pkey)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_LIBCRYPTO_ERROR;
	ಪ್ರತ್ಯಾಗಮ sshbuf_put_eckey(buf, ec);
}
#endif /* WITH_OPENSSL */
