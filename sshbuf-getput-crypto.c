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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <stdlib.h>
#समावेश <stdio.h>
#समावेश <string.h>

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/bn.h>
#समावेश <openssl/ec.h>

#समावेश "ssherr.h"
#घोषणा SSHBUF_INTERNAL
#समावेश "sshbuf.h"

पूर्णांक
sshbuf_get_bignum2(काष्ठा sshbuf *buf, BIGNUM **valp)
{
	BIGNUM *v;
	स्थिर u_char *d;
	माप_प्रकार len;
	पूर्णांक r;

	अगर (valp != शून्य)
		*valp = शून्य;
	अगर ((r = sshbuf_get_bignum2_bytes_direct(buf, &d, &len)) != 0)
		वापस r;
	अगर (valp != शून्य) {
		अगर ((v = BN_new()) == शून्य ||
		    BN_bin2bn(d, len, v) == शून्य) {
			BN_clear_free(v);
			वापस SSH_ERR_ALLOC_FAIL;
		}
		*valp = v;
	}
	वापस 0;
}

अटल पूर्णांक
get_ec(स्थिर u_char *d, माप_प्रकार len, EC_POINT *v, स्थिर EC_GROUP *g)
{
	/* Refuse overlong bignums */
	अगर (len == 0 || len > SSHBUF_MAX_ECPOINT)
		वापस SSH_ERR_ECPOINT_TOO_LARGE;
	/* Only handle uncompressed points */
	अगर (*d != POINT_CONVERSION_UNCOMPRESSED)
		वापस SSH_ERR_INVALID_FORMAT;
	अगर (v != शून्य && EC_POINT_oct2point(g, v, d, len, शून्य) != 1)
		वापस SSH_ERR_INVALID_FORMAT; /* XXX assumption */
	वापस 0;
}

पूर्णांक
sshbuf_get_ec(काष्ठा sshbuf *buf, EC_POINT *v, स्थिर EC_GROUP *g)
{
	स्थिर u_char *d;
	माप_प्रकार len;
	पूर्णांक r;

	अगर ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0)
		वापस r;
	अगर ((r = get_ec(d, len, v, g)) != 0)
		वापस r;
	/* Skip string */
	अगर (sshbuf_get_string_direct(buf, शून्य, शून्य) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		वापस SSH_ERR_INTERNAL_ERROR;
	}
	वापस 0;
}

पूर्णांक
sshbuf_get_eckey(काष्ठा sshbuf *buf, EC_कुंजी *v)
{
	EC_POINT *pt = EC_POINT_new(EC_कुंजी_get0_group(v));
	पूर्णांक r;
	स्थिर u_char *d;
	माप_प्रकार len;

	अगर (pt == शून्य) {
		SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
		वापस SSH_ERR_ALLOC_FAIL;
	}
	अगर ((r = sshbuf_peek_string_direct(buf, &d, &len)) < 0) {
		EC_POINT_free(pt);
		वापस r;
	}
	अगर ((r = get_ec(d, len, pt, EC_कुंजी_get0_group(v))) != 0) {
		EC_POINT_free(pt);
		वापस r;
	}
	अगर (EC_कुंजी_set_public_कुंजी(v, pt) != 1) {
		EC_POINT_free(pt);
		वापस SSH_ERR_ALLOC_FAIL; /* XXX assumption */
	}
	EC_POINT_free(pt);
	/* Skip string */
	अगर (sshbuf_get_string_direct(buf, शून्य, शून्य) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		वापस SSH_ERR_INTERNAL_ERROR;
	}
	वापस 0;
}

पूर्णांक
sshbuf_put_bignum2(काष्ठा sshbuf *buf, स्थिर BIGNUM *v)
{
	u_char d[SSHBUF_MAX_BIGNUM + 1];
	पूर्णांक len = BN_अंक_bytes(v), prepend = 0, r;

	अगर (len < 0 || len > SSHBUF_MAX_BIGNUM)
		वापस SSH_ERR_INVALID_ARGUMENT;
	*d = '\0';
	अगर (BN_bn2bin(v, d + 1) != len)
		वापस SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	/* If MSB is set, prepend a \0 */
	अगर (len > 0 && (d[1] & 0x80) != 0)
		prepend = 1;
	अगर ((r = sshbuf_put_string(buf, d + 1 - prepend, len + prepend)) < 0) {
		explicit_bzero(d, माप(d));
		वापस r;
	}
	explicit_bzero(d, माप(d));
	वापस 0;
}

पूर्णांक
sshbuf_put_ec(काष्ठा sshbuf *buf, स्थिर EC_POINT *v, स्थिर EC_GROUP *g)
{
	u_char d[SSHBUF_MAX_ECPOINT];
	माप_प्रकार len;
	पूर्णांक ret;

	अगर ((len = EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    शून्य, 0, शून्य)) > SSHBUF_MAX_ECPOINT) {
		वापस SSH_ERR_INVALID_ARGUMENT;
	}
	अगर (EC_POINT_point2oct(g, v, POINT_CONVERSION_UNCOMPRESSED,
	    d, len, शून्य) != len) {
		वापस SSH_ERR_INTERNAL_ERROR; /* Shouldn't happen */
	}
	ret = sshbuf_put_string(buf, d, len);
	explicit_bzero(d, len);
	वापस ret;
}

पूर्णांक
sshbuf_put_eckey(काष्ठा sshbuf *buf, स्थिर EC_कुंजी *v)
{
	वापस sshbuf_put_ec(buf, EC_कुंजी_get0_public_कुंजी(v),
	    EC_कुंजी_get0_group(v));
}

पूर्णांक
sshbuf_put_ec_pkey(काष्ठा sshbuf *buf, EVP_PKEY *pkey)
{
	स्थिर EC_कुंजी *ec;

	अगर ((ec = EVP_PKEY_get0_EC_कुंजी(pkey)) == शून्य)
		वापस SSH_ERR_LIBCRYPTO_ERROR;
	वापस sshbuf_put_eckey(buf, ec);
}
#पूर्ण_अगर /* WITH_OPENSSL */
