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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/ec.h>

#అన్తర్భావ "ssherr.h"
#నిర్వచించు SSHBUF_అంతర్గత
#అన్తర్భావ "sshbuf.h"

పూర్ణాంకం
sshbuf_get_bignum2(నిర్మాణం sshbuf *buf, BIGNUM **valp)
{
	BIGNUM *v;
	స్థిరరాశి u_char *d;
	కొలత_t len;
	పూర్ణాంకం r;

	ఒకవేళ (valp != ఖాళీ)
		*valp = ఖాళీ;
	ఒకవేళ ((r = sshbuf_get_bignum2_బైట్లు_ప్రత్యక్ష(buf, &d, &len)) != 0)
		తిరిగి r;
	ఒకవేళ (valp != ఖాళీ) {
		ఒకవేళ ((v = BN_new()) == ఖాళీ ||
		    BN_bin2bn(d, len, v) == ఖాళీ) {
			BN_clear_free(v);
			తిరిగి SSH_ERR_ALLOC_FAIL;
		}
		*valp = v;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
get_ec(స్థిరరాశి u_char *d, కొలత_t len, EC_బిందువు *v, స్థిరరాశి EC_సమూహం *g)
{
	/* Refuse overlong bignums */
	ఒకవేళ (len == 0 || len > SSHBUF_MAX_ECPOINT)
		తిరిగి SSH_ERR_ECPOINT_TOO_LARGE;
	/* Only handle uncompressed points */
	ఒకవేళ (*d != బిందువు_CONVERSION_UNCOMPRESSED)
		తిరిగి SSH_ERR_INVALID_FORMAT;
	ఒకవేళ (v != ఖాళీ && EC_బిందువు_oct2point(g, v, d, len, ఖాళీ) != 1)
		తిరిగి SSH_ERR_INVALID_FORMAT; /* XXX assumption */
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_get_ec(నిర్మాణం sshbuf *buf, EC_బిందువు *v, స్థిరరాశి EC_సమూహం *g)
{
	స్థిరరాశి u_char *d;
	కొలత_t len;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_peek_string_ప్రత్యక్ష(buf, &d, &len)) < 0)
		తిరిగి r;
	ఒకవేళ ((r = get_ec(d, len, v, g)) != 0)
		తిరిగి r;
	/* Skip string */
	ఒకవేళ (sshbuf_get_string_ప్రత్యక్ష(buf, ఖాళీ, ఖాళీ) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	}
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_get_eckey(నిర్మాణం sshbuf *buf, EC_కీలకం *v)
{
	EC_బిందువు *pt = EC_బిందువు_new(EC_కీలకం_get0_సమూహం(v));
	పూర్ణాంకం r;
	స్థిరరాశి u_char *d;
	కొలత_t len;

	ఒకవేళ (pt == ఖాళీ) {
		SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
		తిరిగి SSH_ERR_ALLOC_FAIL;
	}
	ఒకవేళ ((r = sshbuf_peek_string_ప్రత్యక్ష(buf, &d, &len)) < 0) {
		EC_బిందువు_free(pt);
		తిరిగి r;
	}
	ఒకవేళ ((r = get_ec(d, len, pt, EC_కీలకం_get0_సమూహం(v))) != 0) {
		EC_బిందువు_free(pt);
		తిరిగి r;
	}
	ఒకవేళ (EC_కీలకం_సమితి_ప్రజా_కీలకం(v, pt) != 1) {
		EC_బిందువు_free(pt);
		తిరిగి SSH_ERR_ALLOC_FAIL; /* XXX assumption */
	}
	EC_బిందువు_free(pt);
	/* Skip string */
	ఒకవేళ (sshbuf_get_string_ప్రత్యక్ష(buf, ఖాళీ, ఖాళీ) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	}
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_put_bignum2(నిర్మాణం sshbuf *buf, స్థిరరాశి BIGNUM *v)
{
	u_char d[SSHBUF_MAX_BIGNUM + 1];
	పూర్ణాంకం len = BN_అంకె_బైట్లు(v), prepend = 0, r;

	ఒకవేళ (len < 0 || len > SSHBUF_MAX_BIGNUM)
		తిరిగి SSH_ERR_INVALID_వాదం;
	*d = '\0';
	ఒకవేళ (BN_bn2bin(v, d + 1) != len)
		తిరిగి SSH_ERR_అంతర్గత_ERROR; /* Shouldn't happen */
	/* If MSB is set, prepend a \0 */
	ఒకవేళ (len > 0 && (d[1] & 0x80) != 0)
		prepend = 1;
	ఒకవేళ ((r = sshbuf_put_string(buf, d + 1 - prepend, len + prepend)) < 0) {
		explicit_bzero(d, పరిమాణం(d));
		తిరిగి r;
	}
	explicit_bzero(d, పరిమాణం(d));
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_put_ec(నిర్మాణం sshbuf *buf, స్థిరరాశి EC_బిందువు *v, స్థిరరాశి EC_సమూహం *g)
{
	u_char d[SSHBUF_MAX_ECPOINT];
	కొలత_t len;
	పూర్ణాంకం ret;

	ఒకవేళ ((len = EC_బిందువు_point2oct(g, v, బిందువు_CONVERSION_UNCOMPRESSED,
	    ఖాళీ, 0, ఖాళీ)) > SSHBUF_MAX_ECPOINT) {
		తిరిగి SSH_ERR_INVALID_వాదం;
	}
	ఒకవేళ (EC_బిందువు_point2oct(g, v, బిందువు_CONVERSION_UNCOMPRESSED,
	    d, len, ఖాళీ) != len) {
		తిరిగి SSH_ERR_అంతర్గత_ERROR; /* Shouldn't happen */
	}
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	తిరిగి ret;
}

పూర్ణాంకం
sshbuf_put_eckey(నిర్మాణం sshbuf *buf, స్థిరరాశి EC_కీలకం *v)
{
	తిరిగి sshbuf_put_ec(buf, EC_కీలకం_get0_ప్రజా_కీలకం(v),
	    EC_కీలకం_get0_సమూహం(v));
}

పూర్ణాంకం
sshbuf_put_ec_pkey(నిర్మాణం sshbuf *buf, EVP_PKEY *pkey)
{
	స్థిరరాశి EC_కీలకం *ec;

	ఒకవేళ ((ec = EVP_PKEY_get0_EC_కీలకం(pkey)) == ఖాళీ)
		తిరిగి SSH_ERR_LIBCRYPTO_ERROR;
	తిరిగి sshbuf_put_eckey(buf, ec);
}
#అయితే_ముగింపు /* WITH_OPENSSL */
