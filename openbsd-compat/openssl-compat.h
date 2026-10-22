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

#جے_بنا_تعریف _OPENSSL_COMPAT_H
#تعریف_کرو _OPENSSL_COMPAT_H

#ضمن "includes.h"
#جے_تعریف_شدہ WITH_OPENSSL

#ضمن <openssl/opensslv.h>
#ضمن <openssl/crypto.h>
#ضمن <openssl/evp.h>
#ضمن <openssl/bn.h>
#ضمن <openssl/rsa.h>
#ضمن <openssl/ecdsa.h>
#ضمن <openssl/dh.h>

صحيح ssh_compatible_openssl(لما, لما);
صحيح ssh_libcrypto_init(فراغ);

#إذا (OPENSSL_نسخہ_نمبر < 0x10100000L)
# error OpenSSL 1.1.0 or greater is required
#جے_انت
#جے_تعریف_شدہ LIBRESSL_نسخہ_نمبر
# إذا LIBRESSL_نسخہ_نمبر < 0x3010000fL
#  error LibreSSL 3.1.0 or greater is required
# endif
#جے_انت

#جے_بنا_تعریف OPENSSL_RSA_MAX_MODULUS_بٹ
# define OPENSSL_RSA_MAX_MODULUS_بٹ	16384
#جے_انت

#جے_تعریف_شدہ LIBRESSL_نسخہ_نمبر
# إذا LIBRESSL_نسخہ_نمبر < 0x3010000fL
#  define HAVE_BROKEN_CHACHA20
# endif
#جے_انت

#إذا defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
/*
 * BoringSSL and AWS-LC (rightly) got rid of the BN_FLG_CONSTTIME flag, along with
 * the entire BN_set_flags() interface.
 * https://boringssl.googlesource.com/boringssl/+/0a211dfe9
 */
# define BN_سیٹ_flags(a, b)
#جے_انت

/* LibreSSL <3.4 has the _GFp variants but not the equivalent modern ones. */
#جے_بنا_تعریف HAVE_EC_نقطہ_GET_AFFINE_COORDINATES
# ifdef HAVE_EC_نقطہ_GET_AFFINE_COORDINATES_GFP
#  define EC_نقطہ_get_affine_coordinates(a, b, c, d, e) \
	(EC_نقطہ_get_affine_coordinates_GFp(a, b, c, d, e))
# endif
#جے_انت
#جے_بنا_تعریف HAVE_EC_نقطہ_سیٹ_AFFINE_COORDINATES
# ifdef HAVE_EC_نقطہ_سیٹ_AFFINE_COORDINATES_GFP
#  define EC_نقطہ_سیٹ_affine_coordinates(a, b, c, d, e) \
	(EC_نقطہ_سیٹ_affine_coordinates_GFp(a, b, c, d, e))
# endif
#جے_انت

#جے_بنا_تعریف HAVE_EVP_CIPHER_CTX_GET_IV
# ifdef HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV
#  define EVP_CIPHER_CTX_get_iv EVP_CIPHER_CTX_get_updated_iv
# وإلا /* HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV */
صحيح EVP_CIPHER_CTX_get_iv(ثابت EVP_CIPHER_CTX *ctx,
    بنانشانی حرف *iv, ناپ_t len);
# endif /* HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV */
#جے_انت /* HAVE_EVP_CIPHER_CTX_GET_IV */

#جے_بنا_تعریف HAVE_EVP_CIPHER_CTX_سیٹ_IV
صحيح EVP_CIPHER_CTX_سیٹ_iv(EVP_CIPHER_CTX *ctx,
    ثابت بنانشانی حرف *iv, ناپ_t len);
#جے_انت /* HAVE_EVP_CIPHER_CTX_SET_IV */

#جے_بنا_تعریف HAVE_EVP_DIGESTSIGN
صحيح EVP_DigestSign(EVP_MD_CTX *, بنانشانی حرف *, ناپ_t *,
    ثابت بنانشانی حرف *, ناپ_t);
#جے_انت

#جے_بنا_تعریف HAVE_EVP_DIGESTVERIFY
صحيح EVP_DigestVerify(EVP_MD_CTX *, ثابت بنانشانی حرف *, ناپ_t,
    ثابت بنانشانی حرف *, ناپ_t);
#جے_انت

#جے_انت /* WITH_OPENSSL */
#جے_انت /* _OPENSSL_COMPAT_H */
