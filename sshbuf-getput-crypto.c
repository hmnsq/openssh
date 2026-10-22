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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ec.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHBUF_ਅੰਦਰੂਨੀ
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"

ਪੂਰਨ
sshbuf_get_bignum2(ਬਣਤਰ sshbuf *buf, BIGNUM **valp)
{
	BIGNUM *v;
	ਅਚਲ u_char *d;
	ਮਾਪ_t len;
	ਪੂਰਨ r;

	ਜੇ (valp != ਨਿਰਾ)
		*valp = ਨਿਰਾ;
	ਜੇ ((r = sshbuf_get_bignum2_ਬਾਈਟਾਂ_ਸਿੱਧਾ(buf, &d, &len)) != 0)
		ਵਾਪਸ r;
	ਜੇ (valp != ਨਿਰਾ) {
		ਜੇ ((v = BN_new()) == ਨਿਰਾ ||
		    BN_bin2bn(d, len, v) == ਨਿਰਾ) {
			BN_clear_free(v);
			ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
		}
		*valp = v;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
get_ec(ਅਚਲ u_char *d, ਮਾਪ_t len, EC_ਬਿੰਦੂ *v, ਅਚਲ EC_ਸਮੂਹ *g)
{
	/* Refuse overlong bignums */
	ਜੇ (len == 0 || len > SSHBUF_MAX_ECPOINT)
		ਵਾਪਸ SSH_ERR_ECPOINT_TOO_LARGE;
	/* Only handle uncompressed points */
	ਜੇ (*d != ਬਿੰਦੂ_CONVERSION_UNCOMPRESSED)
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	ਜੇ (v != ਨਿਰਾ && EC_ਬਿੰਦੂ_oct2point(g, v, d, len, ਨਿਰਾ) != 1)
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT; /* XXX assumption */
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_get_ec(ਬਣਤਰ sshbuf *buf, EC_ਬਿੰਦੂ *v, ਅਚਲ EC_ਸਮੂਹ *g)
{
	ਅਚਲ u_char *d;
	ਮਾਪ_t len;
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_peek_string_ਸਿੱਧਾ(buf, &d, &len)) < 0)
		ਵਾਪਸ r;
	ਜੇ ((r = get_ec(d, len, v, g)) != 0)
		ਵਾਪਸ r;
	/* Skip string */
	ਜੇ (sshbuf_get_string_ਸਿੱਧਾ(buf, ਨਿਰਾ, ਨਿਰਾ) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	}
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_get_eckey(ਬਣਤਰ sshbuf *buf, EC_ਕੁੰਜੀ *v)
{
	EC_ਬਿੰਦੂ *pt = EC_ਬਿੰਦੂ_new(EC_ਕੁੰਜੀ_get0_ਸਮੂਹ(v));
	ਪੂਰਨ r;
	ਅਚਲ u_char *d;
	ਮਾਪ_t len;

	ਜੇ (pt == ਨਿਰਾ) {
		SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	}
	ਜੇ ((r = sshbuf_peek_string_ਸਿੱਧਾ(buf, &d, &len)) < 0) {
		EC_ਬਿੰਦੂ_free(pt);
		ਵਾਪਸ r;
	}
	ਜੇ ((r = get_ec(d, len, pt, EC_ਕੁੰਜੀ_get0_ਸਮੂਹ(v))) != 0) {
		EC_ਬਿੰਦੂ_free(pt);
		ਵਾਪਸ r;
	}
	ਜੇ (EC_ਕੁੰਜੀ_ਸੈੱਟ_ਜਨਤਕ_ਕੁੰਜੀ(v, pt) != 1) {
		EC_ਬਿੰਦੂ_free(pt);
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL; /* XXX assumption */
	}
	EC_ਬਿੰਦੂ_free(pt);
	/* Skip string */
	ਜੇ (sshbuf_get_string_ਸਿੱਧਾ(buf, ਨਿਰਾ, ਨਿਰਾ) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	}
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_put_bignum2(ਬਣਤਰ sshbuf *buf, ਅਚਲ BIGNUM *v)
{
	u_char d[SSHBUF_MAX_BIGNUM + 1];
	ਪੂਰਨ len = BN_ਅੰਕ_ਬਾਈਟਾਂ(v), prepend = 0, r;

	ਜੇ (len < 0 || len > SSHBUF_MAX_BIGNUM)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	*d = '\0';
	ਜੇ (BN_bn2bin(v, d + 1) != len)
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR; /* Shouldn't happen */
	/* If MSB is set, prepend a \0 */
	ਜੇ (len > 0 && (d[1] & 0x80) != 0)
		prepend = 1;
	ਜੇ ((r = sshbuf_put_string(buf, d + 1 - prepend, len + prepend)) < 0) {
		explicit_bzero(d, ਆਕਾਰ(d));
		ਵਾਪਸ r;
	}
	explicit_bzero(d, ਆਕਾਰ(d));
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_put_ec(ਬਣਤਰ sshbuf *buf, ਅਚਲ EC_ਬਿੰਦੂ *v, ਅਚਲ EC_ਸਮੂਹ *g)
{
	u_char d[SSHBUF_MAX_ECPOINT];
	ਮਾਪ_t len;
	ਪੂਰਨ ret;

	ਜੇ ((len = EC_ਬਿੰਦੂ_point2oct(g, v, ਬਿੰਦੂ_CONVERSION_UNCOMPRESSED,
	    ਨਿਰਾ, 0, ਨਿਰਾ)) > SSHBUF_MAX_ECPOINT) {
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	}
	ਜੇ (EC_ਬਿੰਦੂ_point2oct(g, v, ਬਿੰਦੂ_CONVERSION_UNCOMPRESSED,
	    d, len, ਨਿਰਾ) != len) {
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR; /* Shouldn't happen */
	}
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	ਵਾਪਸ ret;
}

ਪੂਰਨ
sshbuf_put_eckey(ਬਣਤਰ sshbuf *buf, ਅਚਲ EC_ਕੁੰਜੀ *v)
{
	ਵਾਪਸ sshbuf_put_ec(buf, EC_ਕੁੰਜੀ_get0_ਜਨਤਕ_ਕੁੰਜੀ(v),
	    EC_ਕੁੰਜੀ_get0_ਸਮੂਹ(v));
}

ਪੂਰਨ
sshbuf_put_ec_pkey(ਬਣਤਰ sshbuf *buf, EVP_PKEY *pkey)
{
	ਅਚਲ EC_ਕੁੰਜੀ *ec;

	ਜੇ ((ec = EVP_PKEY_get0_EC_ਕੁੰਜੀ(pkey)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_LIBCRYPTO_ERROR;
	ਵਾਪਸ sshbuf_put_eckey(buf, ec);
}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
