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

#اگر_تعریف_نشده _OPENSSL_COMPAT_H
#تعریف_کن _OPENSSL_COMPAT_H

#ضمن "includes.h"
#اگر_تعریف_شده WITH_OPENSSL

#ضمن <openssl/opensslv.h>
#ضمن <openssl/crypto.h>
#ضمن <openssl/evp.h>
#ضمن <openssl/bn.h>
#ضمن <openssl/rsa.h>
#ضمن <openssl/ecdsa.h>
#ضمن <openssl/dh.h>

صحيح ssh_compatible_openssl(دراز, دراز);
صحيح ssh_libcrypto_init(فراغ);

#إذا (OPENSSL_نسخه_عدد < 0x10100000L)
# error OpenSSL 1.1.0 or greater is required
#پایان_اگر
#اگر_تعریف_شده LIBRESSL_نسخه_عدد
# إذا LIBRESSL_نسخه_عدد < 0x3010000fL
#  error LibreSSL 3.1.0 or greater is required
# endif
#پایان_اگر

#اگر_تعریف_نشده OPENSSL_RSA_MAX_MODULUS_بیتها
# define OPENSSL_RSA_MAX_MODULUS_بیتها	16384
#پایان_اگر

#اگر_تعریف_شده LIBRESSL_نسخه_عدد
# إذا LIBRESSL_نسخه_عدد < 0x3010000fL
#  define HAVE_BROKEN_CHACHA20
# endif
#پایان_اگر

#إذا defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
/*
 * BoringSSL and AWS-LC (rightly) got rid of the BN_FLG_CONSTTIME flag, along with
 * the entire BN_set_flags() interface.
 * https://boringssl.googlesource.com/boringssl/+/0a211dfe9
 */
# define BN_مجموعه_flags(a, b)
#پایان_اگر

/* LibreSSL <3.4 has the _GFp variants but not the equivalent modern ones. */
#اگر_تعریف_نشده HAVE_EC_نقطه_GET_AFFINE_COORDINATES
# ifdef HAVE_EC_نقطه_GET_AFFINE_COORDINATES_GFP
#  define EC_نقطه_get_affine_coordinates(a, b, c, d, e) \
	(EC_نقطه_get_affine_coordinates_GFp(a, b, c, d, e))
# endif
#پایان_اگر
#اگر_تعریف_نشده HAVE_EC_نقطه_مجموعه_AFFINE_COORDINATES
# ifdef HAVE_EC_نقطه_مجموعه_AFFINE_COORDINATES_GFP
#  define EC_نقطه_مجموعه_affine_coordinates(a, b, c, d, e) \
	(EC_نقطه_مجموعه_affine_coordinates_GFp(a, b, c, d, e))
# endif
#پایان_اگر

#اگر_تعریف_نشده HAVE_EVP_CIPHER_CTX_GET_IV
# ifdef HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV
#  define EVP_CIPHER_CTX_get_iv EVP_CIPHER_CTX_get_updated_iv
# وإلا /* HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV */
صحيح EVP_CIPHER_CTX_get_iv(ثابت EVP_CIPHER_CTX *ctx,
    بیعلامت حرف *iv, اندازه_t len);
# endif /* HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV */
#پایان_اگر /* HAVE_EVP_CIPHER_CTX_GET_IV */

#اگر_تعریف_نشده HAVE_EVP_CIPHER_CTX_مجموعه_IV
صحيح EVP_CIPHER_CTX_مجموعه_iv(EVP_CIPHER_CTX *ctx,
    ثابت بیعلامت حرف *iv, اندازه_t len);
#پایان_اگر /* HAVE_EVP_CIPHER_CTX_SET_IV */

#اگر_تعریف_نشده HAVE_EVP_DIGESTSIGN
صحيح EVP_DigestSign(EVP_MD_CTX *, بیعلامت حرف *, اندازه_t *,
    ثابت بیعلامت حرف *, اندازه_t);
#پایان_اگر

#اگر_تعریف_نشده HAVE_EVP_DIGESTVERIFY
صحيح EVP_DigestVerify(EVP_MD_CTX *, ثابت بیعلامت حرف *, اندازه_t,
    ثابت بیعلامت حرف *, اندازه_t);
#پایان_اگر

#پایان_اگر /* WITH_OPENSSL */
#پایان_اگر /* _OPENSSL_COMPAT_H */
