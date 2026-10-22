/*
 * Copyright (c) 2005 Darren Tucker <dtucker@zip.com.au>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _OPENSSL_COMPAT_H
#define _OPENSSL_COMPAT_H

#அந்தர்பாவ "includes.h"
#ifdef WITH_OPENSSL

#அந்தர்பாவ <openssl/opensslv.h>
#அந்தர்பாவ <openssl/crypto.h>
#அந்தர்பாவ <openssl/evp.h>
#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/rsa.h>
#அந்தர்பாவ <openssl/ecdsa.h>
#அந்தர்பாவ <openssl/dh.h>

முழு ssh_compatible_openssl(long, long);
முழு ssh_libcrypto_init(வெறுமை);

#எனில் (OPENSSL_VERSION_எண் < 0x10100000L)
# error OpenSSL 1.1.0 or greater is required
#endif
#ifdef LIBRESSL_VERSION_எண்
# எனில் LIBRESSL_VERSION_எண் < 0x3010000fL
#  error LibreSSL 3.1.0 or greater is required
# endif
#endif

#ifndef OPENSSL_RSA_MAX_MODULUS_BITS
# define OPENSSL_RSA_MAX_MODULUS_BITS	16384
#endif

#ifdef LIBRESSL_VERSION_எண்
# எனில் LIBRESSL_VERSION_எண் < 0x3010000fL
#  define HAVE_BROKEN_CHACHA20
# endif
#endif

#எனில் defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
/*
 * BoringSSL and AWS-LC (rightly) got rid of the BN_FLG_CONSTTIME flag, along with
 * the entire BN_set_flags() interface.
 * https://boringssl.googlesource.com/boringssl/+/0a211dfe9
 */
# define BN_set_flags(a, b)
#endif

/* LibreSSL <3.4 has the _GFp variants but not the equivalent modern ones. */
#ifndef HAVE_EC_POINT_GET_AFFINE_COORDINATES
# ifdef HAVE_EC_POINT_GET_AFFINE_COORDINATES_GFP
#  define EC_POINT_get_affine_coordinates(a, b, c, d, e) \
	(EC_POINT_get_affine_coordinates_GFp(a, b, c, d, e))
# endif
#endif
#ifndef HAVE_EC_POINT_SET_AFFINE_COORDINATES
# ifdef HAVE_EC_POINT_SET_AFFINE_COORDINATES_GFP
#  define EC_POINT_set_affine_coordinates(a, b, c, d, e) \
	(EC_POINT_set_affine_coordinates_GFp(a, b, c, d, e))
# endif
#endif

#ifndef HAVE_EVP_CIPHER_CTX_GET_IV
# ifdef HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV
#  define EVP_CIPHER_CTX_get_iv EVP_CIPHER_CTX_get_updated_iv
# இல்லையெனில் /* HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV */
முழு EVP_CIPHER_CTX_get_iv(மாறிலி EVP_CIPHER_CTX *ctx,
    unsigned எழுத்து *iv, size_t len);
# endif /* HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV */
#endif /* HAVE_EVP_CIPHER_CTX_GET_IV */

#ifndef HAVE_EVP_CIPHER_CTX_SET_IV
முழு EVP_CIPHER_CTX_set_iv(EVP_CIPHER_CTX *ctx,
    மாறிலி unsigned எழுத்து *iv, size_t len);
#endif /* HAVE_EVP_CIPHER_CTX_SET_IV */

#ifndef HAVE_EVP_DIGESTSIGN
முழு EVP_DigestSign(EVP_MD_CTX *, unsigned எழுத்து *, size_t *,
    மாறிலி unsigned எழுத்து *, size_t);
#endif

#ifndef HAVE_EVP_DIGESTVERIFY
முழு EVP_DigestVerify(EVP_MD_CTX *, மாறிலி unsigned எழுத்து *, size_t,
    மாறிலி unsigned எழுத்து *, size_t);
#endif

#endif /* WITH_OPENSSL */
#endif /* _OPENSSL_COMPAT_H */
