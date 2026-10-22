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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _OPENSSL_COMPAT_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _OPENSSL_COMPAT_H

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL

#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/opensslv.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/crypto.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/rsa.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ecdsa.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/dh.h>

ਪੂਰਨ ssh_compatible_openssl(ਲੰਮਾ, ਲੰਮਾ);
ਪੂਰਨ ssh_libcrypto_init(ਖਾਲੀ);

#ਜੇ (OPENSSL_ਸੰਸਕਰਣ_ਸੰਖਿਆ < 0x10100000L)
# error OpenSSL 1.1.0 or greater is required
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ LIBRESSL_ਸੰਸਕਰਣ_ਸੰਖਿਆ
# ਜੇ LIBRESSL_ਸੰਸਕਰਣ_ਸੰਖਿਆ < 0x3010000fL
#  error LibreSSL 3.1.0 or greater is required
# endif
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ OPENSSL_RSA_MAX_MODULUS_ਬਿੱਟ
# define OPENSSL_RSA_MAX_MODULUS_ਬਿੱਟ	16384
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ LIBRESSL_ਸੰਸਕਰਣ_ਸੰਖਿਆ
# ਜੇ LIBRESSL_ਸੰਸਕਰਣ_ਸੰਖਿਆ < 0x3010000fL
#  define HAVE_BROKEN_CHACHA20
# endif
#ਜੇ_ਅੰਤ

#ਜੇ defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
/*
 * BoringSSL and AWS-LC (rightly) got rid of the BN_FLG_CONSTTIME flag, along with
 * the entire BN_set_flags() interface.
 * https://boringssl.googlesource.com/boringssl/+/0a211dfe9
 */
# define BN_ਸੈੱਟ_flags(a, b)
#ਜੇ_ਅੰਤ

/* LibreSSL <3.4 has the _GFp variants but not the equivalent modern ones. */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_EC_ਬਿੰਦੂ_GET_AFFINE_COORDINATES
# ifdef HAVE_EC_ਬਿੰਦੂ_GET_AFFINE_COORDINATES_GFP
#  define EC_ਬਿੰਦੂ_get_affine_coordinates(a, b, c, d, e) \
	(EC_ਬਿੰਦੂ_get_affine_coordinates_GFp(a, b, c, d, e))
# endif
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_EC_ਬਿੰਦੂ_ਸੈੱਟ_AFFINE_COORDINATES
# ifdef HAVE_EC_ਬਿੰਦੂ_ਸੈੱਟ_AFFINE_COORDINATES_GFP
#  define EC_ਬਿੰਦੂ_ਸੈੱਟ_affine_coordinates(a, b, c, d, e) \
	(EC_ਬਿੰਦੂ_ਸੈੱਟ_affine_coordinates_GFp(a, b, c, d, e))
# endif
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_EVP_CIPHER_CTX_GET_IV
# ifdef HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV
#  define EVP_CIPHER_CTX_get_iv EVP_CIPHER_CTX_get_updated_iv
# ਨਹੀਂਤਾਂ /* HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV */
ਪੂਰਨ EVP_CIPHER_CTX_get_iv(ਅਚਲ EVP_CIPHER_CTX *ctx,
    ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *iv, ਮਾਪ_t len);
# endif /* HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV */
#ਜੇ_ਅੰਤ /* HAVE_EVP_CIPHER_CTX_GET_IV */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_EVP_CIPHER_CTX_ਸੈੱਟ_IV
ਪੂਰਨ EVP_CIPHER_CTX_ਸੈੱਟ_iv(EVP_CIPHER_CTX *ctx,
    ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *iv, ਮਾਪ_t len);
#ਜੇ_ਅੰਤ /* HAVE_EVP_CIPHER_CTX_SET_IV */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_EVP_DIGESTSIGN
ਪੂਰਨ EVP_DigestSign(EVP_MD_CTX *, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *, ਮਾਪ_t *,
    ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *, ਮਾਪ_t);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_EVP_DIGESTVERIFY
ਪੂਰਨ EVP_DigestVerify(EVP_MD_CTX *, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *, ਮਾਪ_t,
    ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *, ਮਾਪ_t);
#ਜੇ_ਅੰਤ

#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
#ਜੇ_ਅੰਤ /* _OPENSSL_COMPAT_H */
