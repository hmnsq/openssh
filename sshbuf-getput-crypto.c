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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <string.h>

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/bn.h>
#شامل <openssl/ec.h>

#شامل "ssherr.h"
#تعریف_کرو SSHBUF_اندرونی
#شامل "sshbuf.h"

صحیح
sshbuf_get_bignum2(ساخت sshbuf *buf, BIGNUM **valp)
{
	BIGNUM *v;
	ثابت u_char *d;
	سائز_t len;
	صحیح r;

	اگر (valp != تہی)
		*valp = تہی;
	اگر ((r = sshbuf_get_bignum2_بائٹیں_براہ_راست(buf, &d, &len)) != 0)
		واپس r;
	اگر (valp != تہی) {
		اگر ((v = BN_new()) == تہی ||
		    BN_bin2bn(d, len, v) == تہی) {
			BN_clear_free(v);
			واپس SSH_ERR_ALLOC_FAIL;
		}
		*valp = v;
	}
	واپس 0;
}

ساکن صحیح
get_ec(ثابت u_char *d, سائز_t len, EC_نقطہ *v, ثابت EC_گروہ *g)
{
	/* Refuse overlong bignums */
	اگر (len == 0 || len > SSHBUF_MAX_ECPOINT)
		واپس SSH_ERR_ECPOINT_TOO_LARGE;
	/* Only handle uncompressed points */
	اگر (*d != نقطہ_CONVERSION_UNCOMPRESSED)
		واپس SSH_ERR_INVALID_FORMAT;
	اگر (v != تہی && EC_نقطہ_oct2point(g, v, d, len, تہی) != 1)
		واپس SSH_ERR_INVALID_FORMAT; /* XXX assumption */
	واپس 0;
}

صحیح
sshbuf_get_ec(ساخت sshbuf *buf, EC_نقطہ *v, ثابت EC_گروہ *g)
{
	ثابت u_char *d;
	سائز_t len;
	صحیح r;

	اگر ((r = sshbuf_peek_string_براہ_راست(buf, &d, &len)) < 0)
		واپس r;
	اگر ((r = get_ec(d, len, v, g)) != 0)
		واپس r;
	/* Skip string */
	اگر (sshbuf_get_string_براہ_راست(buf, تہی, تہی) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		واپس SSH_ERR_اندرونی_ERROR;
	}
	واپس 0;
}

صحیح
sshbuf_get_eckey(ساخت sshbuf *buf, EC_کلید *v)
{
	EC_نقطہ *pt = EC_نقطہ_new(EC_کلید_get0_گروہ(v));
	صحیح r;
	ثابت u_char *d;
	سائز_t len;

	اگر (pt == تہی) {
		SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
		واپس SSH_ERR_ALLOC_FAIL;
	}
	اگر ((r = sshbuf_peek_string_براہ_راست(buf, &d, &len)) < 0) {
		EC_نقطہ_free(pt);
		واپس r;
	}
	اگر ((r = get_ec(d, len, pt, EC_کلید_get0_گروہ(v))) != 0) {
		EC_نقطہ_free(pt);
		واپس r;
	}
	اگر (EC_کلید_سیٹ_عوامی_کلید(v, pt) != 1) {
		EC_نقطہ_free(pt);
		واپس SSH_ERR_ALLOC_FAIL; /* XXX assumption */
	}
	EC_نقطہ_free(pt);
	/* Skip string */
	اگر (sshbuf_get_string_براہ_راست(buf, تہی, تہی) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		واپس SSH_ERR_اندرونی_ERROR;
	}
	واپس 0;
}

صحیح
sshbuf_put_bignum2(ساخت sshbuf *buf, ثابت BIGNUM *v)
{
	u_char d[SSHBUF_MAX_BIGNUM + 1];
	صحیح len = BN_عدد_بائٹیں(v), prepend = 0, r;

	اگر (len < 0 || len > SSHBUF_MAX_BIGNUM)
		واپس SSH_ERR_INVALID_دلیل;
	*d = '\0';
	اگر (BN_bn2bin(v, d + 1) != len)
		واپس SSH_ERR_اندرونی_ERROR; /* Shouldn't happen */
	/* If MSB is set, prepend a \0 */
	اگر (len > 0 && (d[1] & 0x80) != 0)
		prepend = 1;
	اگر ((r = sshbuf_put_string(buf, d + 1 - prepend, len + prepend)) < 0) {
		explicit_bzero(d, حجم(d));
		واپس r;
	}
	explicit_bzero(d, حجم(d));
	واپس 0;
}

صحیح
sshbuf_put_ec(ساخت sshbuf *buf, ثابت EC_نقطہ *v, ثابت EC_گروہ *g)
{
	u_char d[SSHBUF_MAX_ECPOINT];
	سائز_t len;
	صحیح ret;

	اگر ((len = EC_نقطہ_point2oct(g, v, نقطہ_CONVERSION_UNCOMPRESSED,
	    تہی, 0, تہی)) > SSHBUF_MAX_ECPOINT) {
		واپس SSH_ERR_INVALID_دلیل;
	}
	اگر (EC_نقطہ_point2oct(g, v, نقطہ_CONVERSION_UNCOMPRESSED,
	    d, len, تہی) != len) {
		واپس SSH_ERR_اندرونی_ERROR; /* Shouldn't happen */
	}
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	واپس ret;
}

صحیح
sshbuf_put_eckey(ساخت sshbuf *buf, ثابت EC_کلید *v)
{
	واپس sshbuf_put_ec(buf, EC_کلید_get0_عوامی_کلید(v),
	    EC_کلید_get0_گروہ(v));
}

صحیح
sshbuf_put_ec_pkey(ساخت sshbuf *buf, EVP_PKEY *pkey)
{
	ثابت EC_کلید *ec;

	اگر ((ec = EVP_PKEY_get0_EC_کلید(pkey)) == تہی)
		واپس SSH_ERR_LIBCRYPTO_ERROR;
	واپس sshbuf_put_eckey(buf, ec);
}
#اگر_ختم /* WITH_OPENSSL */
