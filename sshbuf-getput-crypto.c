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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/bn.h>
#অন্তর্ভাব <openssl/ec.h>

#অন্তর্ভাব "ssherr.h"
#define SSHBUF_INTERNAL
#অন্তর্ভাব "sshbuf.h"

পূর্ণাঙ্ক
sshbuf_get_bignum2(সংরচনা sshbuf *buf, BIGNUM **valp)
{
	BIGNUM *v;
	ধ্রুব u_char *d;
	size_t len;
	পূর্ণাঙ্ক r;

	যদি (valp != রিক্ত)
		*valp = রিক্ত;
	যদি ((r = sshbuf_get_bignum2_bytes_direct(buf, &d, &len)) != 0)
		প্রত্যাগম r;
	যদি (valp != রিক্ত) {
		যদি ((v = BN_new()) == রিক্ত ||
		    BN_bin2bn(d, len, v) == রিক্ত) {
			BN_clear_free(v);
			প্রত্যাগম SSH_ERR_ALLOC_FAIL;
		}
		*valp = v;
	}
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
get_ec(ধ্রুব u_char *d, size_t len, EC_POINT *v, ধ্রুব EC_GROUP *g)
{
	/* Refuse overlong bignums */
	যদি (len == 0 || len > SSHBUF_MAX_ECPOINT)
		প্রত্যাগম SSH_ERR_ECPOINT_TOO_LARGE;
	/* Only handle uncompressed points */
	যদি (*d != POINT_CONVERSION_UNCOMPRESSED)
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	যদি (v != রিক্ত && EC_POINT_oct2point(g, v, d, len, রিক্ত) != 1)
		প্রত্যাগম SSH_ERR_INVALID_FORMAT; /* XXX assumption */
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
sshbuf_get_ec(সংরচনা sshbuf *buf, EC_POINT *v, ধ্রুব EC_GROUP *g)
{
	ধ্রুব u_char *d;
	size_t len;
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0)
		প্রত্যাগম r;
	যদি ((r = get_ec(d, len, v, g)) != 0)
		প্রত্যাগম r;
	/* Skip string */
	যদি (sshbuf_get_string_direct(buf, রিক্ত, রিক্ত) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		প্রত্যাগম SSH_ERR_INTERNAL_ERROR;
	}
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
sshbuf_get_eckey(সংরচনা sshbuf *buf, EC_চাবি *v)
{
	EC_POINT *pt = EC_POINT_new(EC_চাবি_get0_group(v));
	পূর্ণাঙ্ক r;
	ধ্রুব u_char *d;
	size_t len;

	যদি (pt == রিক্ত) {
		SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	}
	যদি ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0) {
		EC_POINT_free(pt);
		প্রত্যাগম r;
	}
	যদি ((r = get_ec(d, len, pt, EC_চাবি_get0_group(v))) != 0) {
		EC_POINT_free(pt);
		প্রত্যাগম r;
	}
	যদি (EC_চাবি_set_public_চাবি(v, pt) != 1) {
		EC_POINT_free(pt);
		প্রত্যাগম SSH_ERR_ALLOC_FAIL; /* XXX assumption */
	}
	EC_POINT_free(pt);
	/* Skip string */
	যদি (sshbuf_get_string_direct(buf, রিক্ত, রিক্ত) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		প্রত্যাগম SSH_ERR_INTERNAL_ERROR;
	}
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
sshbuf_put_bignum2(সংরচনা sshbuf *buf, ধ্রুব BIGNUM *v)
{
	u_char d[SSHBUF_MAX_BIGNUM + 1];
	পূর্ণাঙ্ক len = BN_অঙ্ক_bytes(v), prepend = 0, r;

	যদি (len < 0 || len > SSHBUF_MAX_BIGNUM)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	*d = '\0';
	যদি (BN_bn2bin(v, d + 1) != len)
		প্রত্যাগম SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	/* If MSB is set, prepend a \0 */
	যদি (len > 0 && (d[1] & 0x80) != 0)
		prepend = 1;
	যদি ((r = sshbuf_put_string(buf, d + 1 - prepend, len + prepend)) < 0) {
		explicit_bzero(d, পরিমাণ(d));
		প্রত্যাগম r;
	}
	explicit_bzero(d, পরিমাণ(d));
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
sshbuf_put_ec(সংরচনা sshbuf *buf, ধ্রুব EC_POINT *v, ধ্রুব EC_GROUP *g)
{
	u_char d[SSHBUF_MAX_ECPOINT];
	size_t len;
	পূর্ণাঙ্ক ret;

	যদি ((len = EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    রিক্ত, 0, রিক্ত)) > SSHBUF_MAX_ECPOINT) {
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	}
	যদি (EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    d, len, রিক্ত) != len) {
		প্রত্যাগম SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	}
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	প্রত্যাগম ret;
}

পূর্ণাঙ্ক
sshbuf_put_eckey(সংরচনা sshbuf *buf, ধ্রুব EC_চাবি *v)
{
	প্রত্যাগম sshbuf_put_ec(buf, EC_চাবি_get0_public_চাবি(v),
	    EC_চাবি_get0_group(v));
}

পূর্ণাঙ্ক
sshbuf_put_ec_pkey(সংরচনা sshbuf *buf, EVP_PKEY *pkey)
{
	ধ্রুব EC_চাবি *ec;

	যদি ((ec = EVP_PKEY_get0_EC_চাবি(pkey)) == রিক্ত)
		প্রত্যাগম SSH_ERR_LIBCRYPTO_ERROR;
	প্রত্যাগম sshbuf_put_eckey(buf, ec);
}
#endif /* WITH_OPENSSL */
