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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/bn.h>
#അന്തര്ഭാവ <openssl/ec.h>

#അന്തര്ഭാവ "ssherr.h"
#define SSHBUF_INTERNAL
#അന്തര്ഭാവ "sshbuf.h"

പൂർണ്ണസംഖ്യ
sshbuf_get_bignum2(ഘടന sshbuf *buf, BIGNUM **valp)
{
	BIGNUM *v;
	സ്ഥിരം u_char *d;
	size_t len;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (valp != ശൂന്യ)
		*valp = ശൂന്യ;
	എങ്കിൽ ((r = sshbuf_get_bignum2_bytes_direct(buf, &d, &len)) != 0)
		തിരികെ r;
	എങ്കിൽ (valp != ശൂന്യ) {
		എങ്കിൽ ((v = BN_new()) == ശൂന്യ ||
		    BN_bin2bn(d, len, v) == ശൂന്യ) {
			BN_clear_free(v);
			തിരികെ SSH_ERR_ALLOC_FAIL;
		}
		*valp = v;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
get_ec(സ്ഥിരം u_char *d, size_t len, EC_POINT *v, സ്ഥിരം EC_GROUP *g)
{
	/* Refuse overlong bignums */
	എങ്കിൽ (len == 0 || len > SSHBUF_MAX_ECPOINT)
		തിരികെ SSH_ERR_ECPOINT_TOO_LARGE;
	/* Only handle uncompressed points */
	എങ്കിൽ (*d != POINT_CONVERSION_UNCOMPRESSED)
		തിരികെ SSH_ERR_INVALID_FORMAT;
	എങ്കിൽ (v != ശൂന്യ && EC_POINT_oct2point(g, v, d, len, ശൂന്യ) != 1)
		തിരികെ SSH_ERR_INVALID_FORMAT; /* XXX assumption */
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_get_ec(ഘടന sshbuf *buf, EC_POINT *v, സ്ഥിരം EC_GROUP *g)
{
	സ്ഥിരം u_char *d;
	size_t len;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0)
		തിരികെ r;
	എങ്കിൽ ((r = get_ec(d, len, v, g)) != 0)
		തിരികെ r;
	/* Skip string */
	എങ്കിൽ (sshbuf_get_string_direct(buf, ശൂന്യ, ശൂന്യ) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	}
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_get_eckey(ഘടന sshbuf *buf, EC_താക്കോൽ *v)
{
	EC_POINT *pt = EC_POINT_new(EC_താക്കോൽ_get0_group(v));
	പൂർണ്ണസംഖ്യ r;
	സ്ഥിരം u_char *d;
	size_t len;

	എങ്കിൽ (pt == ശൂന്യ) {
		SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
		തിരികെ SSH_ERR_ALLOC_FAIL;
	}
	എങ്കിൽ ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0) {
		EC_POINT_free(pt);
		തിരികെ r;
	}
	എങ്കിൽ ((r = get_ec(d, len, pt, EC_താക്കോൽ_get0_group(v))) != 0) {
		EC_POINT_free(pt);
		തിരികെ r;
	}
	എങ്കിൽ (EC_താക്കോൽ_set_public_താക്കോൽ(v, pt) != 1) {
		EC_POINT_free(pt);
		തിരികെ SSH_ERR_ALLOC_FAIL; /* XXX assumption */
	}
	EC_POINT_free(pt);
	/* Skip string */
	എങ്കിൽ (sshbuf_get_string_direct(buf, ശൂന്യ, ശൂന്യ) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	}
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_put_bignum2(ഘടന sshbuf *buf, സ്ഥിരം BIGNUM *v)
{
	u_char d[SSHBUF_MAX_BIGNUM + 1];
	പൂർണ്ണസംഖ്യ len = BN_അക്കം_bytes(v), prepend = 0, r;

	എങ്കിൽ (len < 0 || len > SSHBUF_MAX_BIGNUM)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	*d = '\0';
	എങ്കിൽ (BN_bn2bin(v, d + 1) != len)
		തിരികെ SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	/* If MSB is set, prepend a \0 */
	എങ്കിൽ (len > 0 && (d[1] & 0x80) != 0)
		prepend = 1;
	എങ്കിൽ ((r = sshbuf_put_string(buf, d + 1 - prepend, len + prepend)) < 0) {
		explicit_bzero(d, വലുപ്പം(d));
		തിരികെ r;
	}
	explicit_bzero(d, വലുപ്പം(d));
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_put_ec(ഘടന sshbuf *buf, സ്ഥിരം EC_POINT *v, സ്ഥിരം EC_GROUP *g)
{
	u_char d[SSHBUF_MAX_ECPOINT];
	size_t len;
	പൂർണ്ണസംഖ്യ ret;

	എങ്കിൽ ((len = EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    ശൂന്യ, 0, ശൂന്യ)) > SSHBUF_MAX_ECPOINT) {
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	}
	എങ്കിൽ (EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    d, len, ശൂന്യ) != len) {
		തിരികെ SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	}
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
sshbuf_put_eckey(ഘടന sshbuf *buf, സ്ഥിരം EC_താക്കോൽ *v)
{
	തിരികെ sshbuf_put_ec(buf, EC_താക്കോൽ_get0_public_താക്കോൽ(v),
	    EC_താക്കോൽ_get0_group(v));
}

പൂർണ്ണസംഖ്യ
sshbuf_put_ec_pkey(ഘടന sshbuf *buf, EVP_PKEY *pkey)
{
	സ്ഥിരം EC_താക്കോൽ *ec;

	എങ്കിൽ ((ec = EVP_PKEY_get0_EC_താക്കോൽ(pkey)) == ശൂന്യ)
		തിരികെ SSH_ERR_LIBCRYPTO_ERROR;
	തിരികെ sshbuf_put_eckey(buf, ec);
}
#endif /* WITH_OPENSSL */
