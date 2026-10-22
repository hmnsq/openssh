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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/bn.h>
#અન્તર્ભાવ <openssl/ec.h>

#અન્તર્ભાવ "ssherr.h"
#define SSHBUF_INTERNAL
#અન્તર્ભાવ "sshbuf.h"

પૂર્ણાંક
sshbuf_get_bignum2(સંરચના sshbuf *buf, BIGNUM **valp)
{
	BIGNUM *v;
	અચલ u_char *d;
	size_t len;
	પૂર્ણાંક r;

	જો (valp != ખાલી)
		*valp = ખાલી;
	જો ((r = sshbuf_get_bignum2_bytes_direct(buf, &d, &len)) != 0)
		પાછા r;
	જો (valp != ખાલી) {
		જો ((v = BN_new()) == ખાલી ||
		    BN_bin2bn(d, len, v) == ખાલી) {
			BN_clear_free(v);
			પાછા SSH_ERR_ALLOC_FAIL;
		}
		*valp = v;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
get_ec(અચલ u_char *d, size_t len, EC_POINT *v, અચલ EC_GROUP *g)
{
	/* Refuse overlong bignums */
	જો (len == 0 || len > SSHBUF_MAX_ECPOINT)
		પાછા SSH_ERR_ECPOINT_TOO_LARGE;
	/* Only handle uncompressed points */
	જો (*d != POINT_CONVERSION_UNCOMPRESSED)
		પાછા SSH_ERR_INVALID_FORMAT;
	જો (v != ખાલી && EC_POINT_oct2point(g, v, d, len, ખાલી) != 1)
		પાછા SSH_ERR_INVALID_FORMAT; /* XXX assumption */
	પાછા 0;
}

પૂર્ણાંક
sshbuf_get_ec(સંરચના sshbuf *buf, EC_POINT *v, અચલ EC_GROUP *g)
{
	અચલ u_char *d;
	size_t len;
	પૂર્ણાંક r;

	જો ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0)
		પાછા r;
	જો ((r = get_ec(d, len, v, g)) != 0)
		પાછા r;
	/* Skip string */
	જો (sshbuf_get_string_direct(buf, ખાલી, ખાલી) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		પાછા SSH_ERR_INTERNAL_ERROR;
	}
	પાછા 0;
}

પૂર્ણાંક
sshbuf_get_eckey(સંરચના sshbuf *buf, EC_ચાવી *v)
{
	EC_POINT *pt = EC_POINT_new(EC_ચાવી_get0_group(v));
	પૂર્ણાંક r;
	અચલ u_char *d;
	size_t len;

	જો (pt == ખાલી) {
		SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
		પાછા SSH_ERR_ALLOC_FAIL;
	}
	જો ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0) {
		EC_POINT_free(pt);
		પાછા r;
	}
	જો ((r = get_ec(d, len, pt, EC_ચાવી_get0_group(v))) != 0) {
		EC_POINT_free(pt);
		પાછા r;
	}
	જો (EC_ચાવી_set_public_ચાવી(v, pt) != 1) {
		EC_POINT_free(pt);
		પાછા SSH_ERR_ALLOC_FAIL; /* XXX assumption */
	}
	EC_POINT_free(pt);
	/* Skip string */
	જો (sshbuf_get_string_direct(buf, ખાલી, ખાલી) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		પાછા SSH_ERR_INTERNAL_ERROR;
	}
	પાછા 0;
}

પૂર્ણાંક
sshbuf_put_bignum2(સંરચના sshbuf *buf, અચલ BIGNUM *v)
{
	u_char d[SSHBUF_MAX_BIGNUM + 1];
	પૂર્ણાંક len = BN_અંક_bytes(v), prepend = 0, r;

	જો (len < 0 || len > SSHBUF_MAX_BIGNUM)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	*d = '\0';
	જો (BN_bn2bin(v, d + 1) != len)
		પાછા SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	/* If MSB is set, prepend a \0 */
	જો (len > 0 && (d[1] & 0x80) != 0)
		prepend = 1;
	જો ((r = sshbuf_put_string(buf, d + 1 - prepend, len + prepend)) < 0) {
		explicit_bzero(d, કદ(d));
		પાછા r;
	}
	explicit_bzero(d, કદ(d));
	પાછા 0;
}

પૂર્ણાંક
sshbuf_put_ec(સંરચના sshbuf *buf, અચલ EC_POINT *v, અચલ EC_GROUP *g)
{
	u_char d[SSHBUF_MAX_ECPOINT];
	size_t len;
	પૂર્ણાંક ret;

	જો ((len = EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    ખાલી, 0, ખાલી)) > SSHBUF_MAX_ECPOINT) {
		પાછા SSH_ERR_INVALID_ARGUMENT;
	}
	જો (EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    d, len, ખાલી) != len) {
		પાછા SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	}
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	પાછા ret;
}

પૂર્ણાંક
sshbuf_put_eckey(સંરચના sshbuf *buf, અચલ EC_ચાવી *v)
{
	પાછા sshbuf_put_ec(buf, EC_ચાવી_get0_public_ચાવી(v),
	    EC_ચાવી_get0_group(v));
}

પૂર્ણાંક
sshbuf_put_ec_pkey(સંરચના sshbuf *buf, EVP_PKEY *pkey)
{
	અચલ EC_ચાવી *ec;

	જો ((ec = EVP_PKEY_get0_EC_ચાવી(pkey)) == ખાલી)
		પાછા SSH_ERR_LIBCRYPTO_ERROR;
	પાછા sshbuf_put_eckey(buf, ec);
}
#endif /* WITH_OPENSSL */
