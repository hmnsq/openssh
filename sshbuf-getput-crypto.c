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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/ec.h>

#அந்தர்பாவ "ssherr.h"
#define SSHBUF_INTERNAL
#அந்தர்பாவ "sshbuf.h"

முழு
sshbuf_get_bignum2(கட்டமைப்பு sshbuf *buf, BIGNUM **valp)
{
	BIGNUM *v;
	மாறிலி u_char *d;
	size_t len;
	முழு r;

	எனில் (valp != வெற்று)
		*valp = வெற்று;
	எனில் ((r = sshbuf_get_bignum2_bytes_direct(buf, &d, &len)) != 0)
		திரும்பு r;
	எனில் (valp != வெற்று) {
		எனில் ((v = BN_new()) == வெற்று ||
		    BN_bin2bn(d, len, v) == வெற்று) {
			BN_clear_free(v);
			திரும்பு SSH_ERR_ALLOC_FAIL;
		}
		*valp = v;
	}
	திரும்பு 0;
}

நிலையான முழு
get_ec(மாறிலி u_char *d, size_t len, EC_POINT *v, மாறிலி EC_GROUP *g)
{
	/* Refuse overlong bignums */
	எனில் (len == 0 || len > SSHBUF_MAX_ECPOINT)
		திரும்பு SSH_ERR_ECPOINT_TOO_LARGE;
	/* Only handle uncompressed points */
	எனில் (*d != POINT_CONVERSION_UNCOMPRESSED)
		திரும்பு SSH_ERR_INVALID_FORMAT;
	எனில் (v != வெற்று && EC_POINT_oct2point(g, v, d, len, வெற்று) != 1)
		திரும்பு SSH_ERR_INVALID_FORMAT; /* XXX assumption */
	திரும்பு 0;
}

முழு
sshbuf_get_ec(கட்டமைப்பு sshbuf *buf, EC_POINT *v, மாறிலி EC_GROUP *g)
{
	மாறிலி u_char *d;
	size_t len;
	முழு r;

	எனில் ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0)
		திரும்பு r;
	எனில் ((r = get_ec(d, len, v, g)) != 0)
		திரும்பு r;
	/* Skip string */
	எனில் (sshbuf_get_string_direct(buf, வெற்று, வெற்று) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	}
	திரும்பு 0;
}

முழு
sshbuf_get_eckey(கட்டமைப்பு sshbuf *buf, EC_சாவி *v)
{
	EC_POINT *pt = EC_POINT_new(EC_சாவி_get0_group(v));
	முழு r;
	மாறிலி u_char *d;
	size_t len;

	எனில் (pt == வெற்று) {
		SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
		திரும்பு SSH_ERR_ALLOC_FAIL;
	}
	எனில் ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0) {
		EC_POINT_free(pt);
		திரும்பு r;
	}
	எனில் ((r = get_ec(d, len, pt, EC_சாவி_get0_group(v))) != 0) {
		EC_POINT_free(pt);
		திரும்பு r;
	}
	எனில் (EC_சாவி_set_public_சாவி(v, pt) != 1) {
		EC_POINT_free(pt);
		திரும்பு SSH_ERR_ALLOC_FAIL; /* XXX assumption */
	}
	EC_POINT_free(pt);
	/* Skip string */
	எனில் (sshbuf_get_string_direct(buf, வெற்று, வெற்று) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	}
	திரும்பு 0;
}

முழு
sshbuf_put_bignum2(கட்டமைப்பு sshbuf *buf, மாறிலி BIGNUM *v)
{
	u_char d[SSHBUF_MAX_BIGNUM + 1];
	முழு len = BN_இலக்கம்_bytes(v), prepend = 0, r;

	எனில் (len < 0 || len > SSHBUF_MAX_BIGNUM)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	*d = '\0';
	எனில் (BN_bn2bin(v, d + 1) != len)
		திரும்பு SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	/* If MSB is set, prepend a \0 */
	எனில் (len > 0 && (d[1] & 0x80) != 0)
		prepend = 1;
	எனில் ((r = sshbuf_put_string(buf, d + 1 - prepend, len + prepend)) < 0) {
		explicit_bzero(d, அளவு(d));
		திரும்பு r;
	}
	explicit_bzero(d, அளவு(d));
	திரும்பு 0;
}

முழு
sshbuf_put_ec(கட்டமைப்பு sshbuf *buf, மாறிலி EC_POINT *v, மாறிலி EC_GROUP *g)
{
	u_char d[SSHBUF_MAX_ECPOINT];
	size_t len;
	முழு ret;

	எனில் ((len = EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    வெற்று, 0, வெற்று)) > SSHBUF_MAX_ECPOINT) {
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	}
	எனில் (EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    d, len, வெற்று) != len) {
		திரும்பு SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	}
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	திரும்பு ret;
}

முழு
sshbuf_put_eckey(கட்டமைப்பு sshbuf *buf, மாறிலி EC_சாவி *v)
{
	திரும்பு sshbuf_put_ec(buf, EC_சாவி_get0_public_சாவி(v),
	    EC_சாவி_get0_group(v));
}

முழு
sshbuf_put_ec_pkey(கட்டமைப்பு sshbuf *buf, EVP_PKEY *pkey)
{
	மாறிலி EC_சாவி *ec;

	எனில் ((ec = EVP_PKEY_get0_EC_சாவி(pkey)) == வெற்று)
		திரும்பு SSH_ERR_LIBCRYPTO_ERROR;
	திரும்பு sshbuf_put_eckey(buf, ec);
}
#endif /* WITH_OPENSSL */
