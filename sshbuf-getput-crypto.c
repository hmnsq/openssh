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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ <openssl/bn.h>
#ଅନ୍ତର୍ଭାଵ <openssl/ec.h>

#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#define SSHBUF_INTERNAL
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_get_bignum2(ସଂରଚନା sshbuf *buf, BIGNUM **valp)
{
	BIGNUM *v;
	ଅଚଳ u_char *d;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (valp != ଖାଲି)
		*valp = ଖାଲି;
	ଯଦି ((r = sshbuf_get_bignum2_bytes_direct(buf, &d, &len)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (valp != ଖାଲି) {
		ଯଦି ((v = BN_new()) == ଖାଲି ||
		    BN_bin2bn(d, len, v) == ଖାଲି) {
			BN_clear_free(v);
			ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
		}
		*valp = v;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
get_ec(ଅଚଳ u_char *d, size_t len, EC_POINT *v, ଅଚଳ EC_GROUP *g)
{
	/* Refuse overlong bignums */
	ଯଦି (len == 0 || len > SSHBUF_MAX_ECPOINT)
		ଫେରନ୍ତୁ SSH_ERR_ECPOINT_TOO_LARGE;
	/* Only handle uncompressed points */
	ଯଦି (*d != POINT_CONVERSION_UNCOMPRESSED)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	ଯଦି (v != ଖାଲି && EC_POINT_oct2point(g, v, d, len, ଖାଲି) != 1)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT; /* XXX assumption */
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_get_ec(ସଂରଚନା sshbuf *buf, EC_POINT *v, ଅଚଳ EC_GROUP *g)
{
	ଅଚଳ u_char *d;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((r = get_ec(d, len, v, g)) != 0)
		ଫେରନ୍ତୁ r;
	/* Skip string */
	ଯଦି (sshbuf_get_string_direct(buf, ଖାଲି, ଖାଲି) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	}
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_get_eckey(ସଂରଚନା sshbuf *buf, EC_ଚାବି *v)
{
	EC_POINT *pt = EC_POINT_new(EC_ଚାବି_get0_group(v));
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଅଚଳ u_char *d;
	size_t len;

	ଯଦି (pt == ଖାଲି) {
		SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	}
	ଯଦି ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0) {
		EC_POINT_free(pt);
		ଫେରନ୍ତୁ r;
	}
	ଯଦି ((r = get_ec(d, len, pt, EC_ଚାବି_get0_group(v))) != 0) {
		EC_POINT_free(pt);
		ଫେରନ୍ତୁ r;
	}
	ଯଦି (EC_ଚାବି_set_public_ଚାବି(v, pt) != 1) {
		EC_POINT_free(pt);
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL; /* XXX assumption */
	}
	EC_POINT_free(pt);
	/* Skip string */
	ଯଦି (sshbuf_get_string_direct(buf, ଖାଲି, ଖାଲି) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	}
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_put_bignum2(ସଂରଚନା sshbuf *buf, ଅଚଳ BIGNUM *v)
{
	u_char d[SSHBUF_MAX_BIGNUM + 1];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା len = BN_ଅଙ୍କ_bytes(v), prepend = 0, r;

	ଯଦି (len < 0 || len > SSHBUF_MAX_BIGNUM)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	*d = '\0';
	ଯଦି (BN_bn2bin(v, d + 1) != len)
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	/* If MSB is set, prepend a \0 */
	ଯଦି (len > 0 && (d[1] & 0x80) != 0)
		prepend = 1;
	ଯଦି ((r = sshbuf_put_string(buf, d + 1 - prepend, len + prepend)) < 0) {
		explicit_bzero(d, ଆକାର(d));
		ଫେରନ୍ତୁ r;
	}
	explicit_bzero(d, ଆକାର(d));
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_put_ec(ସଂରଚନା sshbuf *buf, ଅଚଳ EC_POINT *v, ଅଚଳ EC_GROUP *g)
{
	u_char d[SSHBUF_MAX_ECPOINT];
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret;

	ଯଦି ((len = EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    ଖାଲି, 0, ଖାଲି)) > SSHBUF_MAX_ECPOINT) {
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	}
	ଯଦି (EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    d, len, ଖାଲି) != len) {
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	}
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_put_eckey(ସଂରଚନା sshbuf *buf, ଅଚଳ EC_ଚାବି *v)
{
	ଫେରନ୍ତୁ sshbuf_put_ec(buf, EC_ଚାବି_get0_public_ଚାବି(v),
	    EC_ଚାବି_get0_group(v));
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_put_ec_pkey(ସଂରଚନା sshbuf *buf, EVP_PKEY *pkey)
{
	ଅଚଳ EC_ଚାବି *ec;

	ଯଦି ((ec = EVP_PKEY_get0_EC_ଚାବି(pkey)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_LIBCRYPTO_ERROR;
	ଫେରନ୍ତୁ sshbuf_put_eckey(buf, ec);
}
#endif /* WITH_OPENSSL */
