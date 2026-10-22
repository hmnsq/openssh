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

পূর্ণসংখ্যা
sshbuf_get_bignum2(কাঠামো sshbuf *buf, BIGNUM **valp)
{
	BIGNUM *v;
	ধ্রুবক u_char *d;
	আকার_t len;
	পূর্ণসংখ্যা r;

	যদি (valp != ফাঁকা)
		*valp = ফাঁকা;
	যদি ((r = sshbuf_get_bignum2_bytes_direct(buf, &d, &len)) != 0)
		ফেরত r;
	যদি (valp != ফাঁকা) {
		যদি ((v = BN_new()) == ফাঁকা ||
		    BN_bin2bn(d, len, v) == ফাঁকা) {
			BN_clear_free(v);
			ফেরত SSH_ERR_ALLOC_FAIL;
		}
		*valp = v;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
get_ec(ধ্রুবক u_char *d, আকার_t len, EC_POINT *v, ধ্রুবক EC_GROUP *g)
{
	/* Refuse overlong bignums */
	যদি (len == 0 || len > SSHBUF_MAX_ECPOINT)
		ফেরত SSH_ERR_ECPOINT_TOO_LARGE;
	/* Only handle uncompressed points */
	যদি (*d != POINT_CONVERSION_UNCOMPRESSED)
		ফেরত SSH_ERR_INVALID_FORMAT;
	যদি (v != ফাঁকা && EC_POINT_oct2point(g, v, d, len, ফাঁকা) != 1)
		ফেরত SSH_ERR_INVALID_FORMAT; /* XXX assumption */
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_get_ec(কাঠামো sshbuf *buf, EC_POINT *v, ধ্রুবক EC_GROUP *g)
{
	ধ্রুবক u_char *d;
	আকার_t len;
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0)
		ফেরত r;
	যদি ((r = get_ec(d, len, v, g)) != 0)
		ফেরত r;
	/* Skip string */
	যদি (sshbuf_get_string_direct(buf, ফাঁকা, ফাঁকা) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ফেরত SSH_ERR_INTERNAL_ERROR;
	}
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_get_eckey(কাঠামো sshbuf *buf, EC_চাবি *v)
{
	EC_POINT *pt = EC_POINT_new(EC_চাবি_get0_group(v));
	পূর্ণসংখ্যা r;
	ধ্রুবক u_char *d;
	আকার_t len;

	যদি (pt == ফাঁকা) {
		SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
		ফেরত SSH_ERR_ALLOC_FAIL;
	}
	যদি ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0) {
		EC_POINT_free(pt);
		ফেরত r;
	}
	যদি ((r = get_ec(d, len, pt, EC_চাবি_get0_group(v))) != 0) {
		EC_POINT_free(pt);
		ফেরত r;
	}
	যদি (EC_চাবি_set_public_চাবি(v, pt) != 1) {
		EC_POINT_free(pt);
		ফেরত SSH_ERR_ALLOC_FAIL; /* XXX assumption */
	}
	EC_POINT_free(pt);
	/* Skip string */
	যদি (sshbuf_get_string_direct(buf, ফাঁকা, ফাঁকা) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ফেরত SSH_ERR_INTERNAL_ERROR;
	}
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_put_bignum2(কাঠামো sshbuf *buf, ধ্রুবক BIGNUM *v)
{
	u_char d[SSHBUF_MAX_BIGNUM + 1];
	পূর্ণসংখ্যা len = BN_অঙ্ক_bytes(v), prepend = 0, r;

	যদি (len < 0 || len > SSHBUF_MAX_BIGNUM)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	*d = '\0';
	যদি (BN_bn2bin(v, d + 1) != len)
		ফেরত SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	/* If MSB is set, prepend a \0 */
	যদি (len > 0 && (d[1] & 0x80) != 0)
		prepend = 1;
	যদি ((r = sshbuf_put_string(buf, d + 1 - prepend, len + prepend)) < 0) {
		explicit_bzero(d, আকার(d));
		ফেরত r;
	}
	explicit_bzero(d, আকার(d));
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_put_ec(কাঠামো sshbuf *buf, ধ্রুবক EC_POINT *v, ধ্রুবক EC_GROUP *g)
{
	u_char d[SSHBUF_MAX_ECPOINT];
	আকার_t len;
	পূর্ণসংখ্যা ret;

	যদি ((len = EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    ফাঁকা, 0, ফাঁকা)) > SSHBUF_MAX_ECPOINT) {
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	}
	যদি (EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    d, len, ফাঁকা) != len) {
		ফেরত SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	}
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	ফেরত ret;
}

পূর্ণসংখ্যা
sshbuf_put_eckey(কাঠামো sshbuf *buf, ধ্রুবক EC_চাবি *v)
{
	ফেরত sshbuf_put_ec(buf, EC_চাবি_get0_public_চাবি(v),
	    EC_চাবি_get0_group(v));
}

পূর্ণসংখ্যা
sshbuf_put_ec_pkey(কাঠামো sshbuf *buf, EVP_PKEY *pkey)
{
	ধ্রুবক EC_চাবি *ec;

	যদি ((ec = EVP_PKEY_get0_EC_চাবি(pkey)) == ফাঁকা)
		ফেরত SSH_ERR_LIBCRYPTO_ERROR;
	ফেরত sshbuf_put_eckey(buf, ec);
}
#endif /* WITH_OPENSSL */
