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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/ec.h>

#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ವ್ಯಾಖ್ಯಾನಿಸು SSHBUF_ಆಂತರಿಕ
#ಅನ್ತರ್ಭಾವ "sshbuf.h"

ಪೂರ್ಣಾಂಕ
sshbuf_get_bignum2(ರಚನೆ sshbuf *buf, BIGNUM **valp)
{
	BIGNUM *v;
	ಸ್ಥಿರಾಂಕ u_char *d;
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (valp != ಖಾಲಿ)
		*valp = ಖಾಲಿ;
	ಆದರೆ ((r = sshbuf_get_bignum2_ಬೈಟುಗಳು_ನೇರ(buf, &d, &len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (valp != ಖಾಲಿ) {
		ಆದರೆ ((v = BN_new()) == ಖಾಲಿ ||
		    BN_bin2bn(d, len, v) == ಖಾಲಿ) {
			BN_clear_free(v);
			ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
		}
		*valp = v;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
get_ec(ಸ್ಥಿರಾಂಕ u_char *d, ಗಾತ್ರ_t len, EC_ಬಿಂದು *v, ಸ್ಥಿರಾಂಕ EC_ಗುಂಪು *g)
{
	/* Refuse overlong bignums */
	ಆದರೆ (len == 0 || len > SSHBUF_MAX_ECPOINT)
		ಹಿಂತಿರುಗಿ SSH_ERR_ECPOINT_TOO_LARGE;
	/* Only handle uncompressed points */
	ಆದರೆ (*d != ಬಿಂದು_CONVERSION_UNCOMPRESSED)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	ಆದರೆ (v != ಖಾಲಿ && EC_ಬಿಂದು_oct2point(g, v, d, len, ಖಾಲಿ) != 1)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT; /* XXX assumption */
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_get_ec(ರಚನೆ sshbuf *buf, EC_ಬಿಂದು *v, ಸ್ಥಿರಾಂಕ EC_ಗುಂಪು *g)
{
	ಸ್ಥಿರಾಂಕ u_char *d;
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_peek_string_ನೇರ(buf, &d, &len)) < 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((r = get_ec(d, len, v, g)) != 0)
		ಹಿಂತಿರುಗಿ r;
	/* Skip string */
	ಆದರೆ (sshbuf_get_string_ನೇರ(buf, ಖಾಲಿ, ಖಾಲಿ) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_get_eckey(ರಚನೆ sshbuf *buf, EC_ಕೀಲಿ *v)
{
	EC_ಬಿಂದು *pt = EC_ಬಿಂದು_new(EC_ಕೀಲಿ_get0_ಗುಂಪು(v));
	ಪೂರ್ಣಾಂಕ r;
	ಸ್ಥಿರಾಂಕ u_char *d;
	ಗಾತ್ರ_t len;

	ಆದರೆ (pt == ಖಾಲಿ) {
		SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	}
	ಆದರೆ ((r = sshbuf_peek_string_ನೇರ(buf, &d, &len)) < 0) {
		EC_ಬಿಂದು_free(pt);
		ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ ((r = get_ec(d, len, pt, EC_ಕೀಲಿ_get0_ಗುಂಪು(v))) != 0) {
		EC_ಬಿಂದು_free(pt);
		ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ (EC_ಕೀಲಿ_ಗಣ_ಬಹಿರಂಗ_ಕೀಲಿ(v, pt) != 1) {
		EC_ಬಿಂದು_free(pt);
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL; /* XXX assumption */
	}
	EC_ಬಿಂದು_free(pt);
	/* Skip string */
	ಆದರೆ (sshbuf_get_string_ನೇರ(buf, ಖಾಲಿ, ಖಾಲಿ) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_put_bignum2(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ BIGNUM *v)
{
	u_char d[SSHBUF_MAX_BIGNUM + 1];
	ಪೂರ್ಣಾಂಕ len = BN_ಅಂಕೆ_ಬೈಟುಗಳು(v), prepend = 0, r;

	ಆದರೆ (len < 0 || len > SSHBUF_MAX_BIGNUM)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	*d = '\0';
	ಆದರೆ (BN_bn2bin(v, d + 1) != len)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR; /* Shouldn't happen */
	/* If MSB is set, prepend a \0 */
	ಆದರೆ (len > 0 && (d[1] & 0x80) != 0)
		prepend = 1;
	ಆದರೆ ((r = sshbuf_put_string(buf, d + 1 - prepend, len + prepend)) < 0) {
		explicit_bzero(d, ಗಾತ್ರ(d));
		ಹಿಂತಿರುಗಿ r;
	}
	explicit_bzero(d, ಗಾತ್ರ(d));
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_put_ec(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ EC_ಬಿಂದು *v, ಸ್ಥಿರಾಂಕ EC_ಗುಂಪು *g)
{
	u_char d[SSHBUF_MAX_ECPOINT];
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ ret;

	ಆದರೆ ((len = EC_ಬಿಂದು_point2oct(g, v, ಬಿಂದು_CONVERSION_UNCOMPRESSED,
	    ಖಾಲಿ, 0, ಖಾಲಿ)) > SSHBUF_MAX_ECPOINT) {
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	}
	ಆದರೆ (EC_ಬಿಂದು_point2oct(g, v, ಬಿಂದು_CONVERSION_UNCOMPRESSED,
	    d, len, ಖಾಲಿ) != len) {
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR; /* Shouldn't happen */
	}
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
sshbuf_put_eckey(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ EC_ಕೀಲಿ *v)
{
	ಹಿಂತಿರುಗಿ sshbuf_put_ec(buf, EC_ಕೀಲಿ_get0_ಬಹಿರಂಗ_ಕೀಲಿ(v),
	    EC_ಕೀಲಿ_get0_ಗುಂಪು(v));
}

ಪೂರ್ಣಾಂಕ
sshbuf_put_ec_pkey(ರಚನೆ sshbuf *buf, EVP_PKEY *pkey)
{
	ಸ್ಥಿರಾಂಕ EC_ಕೀಲಿ *ec;

	ಆದರೆ ((ec = EVP_PKEY_get0_EC_ಕೀಲಿ(pkey)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;
	ಹಿಂತಿರುಗಿ sshbuf_put_eckey(buf, ec);
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
