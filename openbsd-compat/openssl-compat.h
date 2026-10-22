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

#اگر_غیر_تعریف_شدہ _OPENSSL_COMPAT_H
#تعریف_کرو _OPENSSL_COMPAT_H

#شامل "includes.h"
#اگر_تعریف_شدہ WITH_OPENSSL

#شامل <openssl/opensslv.h>
#شامل <openssl/crypto.h>
#شامل <openssl/evp.h>
#شامل <openssl/bn.h>
#شامل <openssl/rsa.h>
#شامل <openssl/ecdsa.h>
#شامل <openssl/dh.h>

صحیح ssh_compatible_openssl(طویل, طویل);
صحیح ssh_libcrypto_init(خالی);

#اگر (OPENSSL_نسخہ_نمبر < 0x10100000L)
# error OpenSSL 1.1.0 or greater is required
#اگر_ختم
#اگر_تعریف_شدہ LIBRESSL_نسخہ_نمبر
# اگر LIBRESSL_نسخہ_نمبر < 0x3010000fL
#  error LibreSSL 3.1.0 or greater is required
# endif
#اگر_ختم

#اگر_غیر_تعریف_شدہ OPENSSL_RSA_MAX_MODULUS_بٹ
# define OPENSSL_RSA_MAX_MODULUS_بٹ	16384
#اگر_ختم

#اگر_تعریف_شدہ LIBRESSL_نسخہ_نمبر
# اگر LIBRESSL_نسخہ_نمبر < 0x3010000fL
#  define HAVE_BROKEN_CHACHA20
# endif
#اگر_ختم

#اگر defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
/*
 * BoringSSL and AWS-LC (rightly) got rid of the BN_FLG_CONSTTIME flag, along with
 * the entire BN_set_flags() interface.
 * https://boringssl.googlesource.com/boringssl/+/0a211dfe9
 */
# define BN_سیٹ_flags(a, b)
#اگر_ختم

/* LibreSSL <3.4 has the _GFp variants but not the equivalent modern ones. */
#اگر_غیر_تعریف_شدہ HAVE_EC_نقطہ_GET_AFFINE_COORDINATES
# ifdef HAVE_EC_نقطہ_GET_AFFINE_COORDINATES_GFP
#  define EC_نقطہ_get_affine_coordinates(a, b, c, d, e) \
	(EC_نقطہ_get_affine_coordinates_GFp(a, b, c, d, e))
# endif
#اگر_ختم
#اگر_غیر_تعریف_شدہ HAVE_EC_نقطہ_سیٹ_AFFINE_COORDINATES
# ifdef HAVE_EC_نقطہ_سیٹ_AFFINE_COORDINATES_GFP
#  define EC_نقطہ_سیٹ_affine_coordinates(a, b, c, d, e) \
	(EC_نقطہ_سیٹ_affine_coordinates_GFp(a, b, c, d, e))
# endif
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_EVP_CIPHER_CTX_GET_IV
# ifdef HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV
#  define EVP_CIPHER_CTX_get_iv EVP_CIPHER_CTX_get_updated_iv
# ورنہ /* HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV */
صحیح EVP_CIPHER_CTX_get_iv(ثابت EVP_CIPHER_CTX *ctx,
    غیرعلامتی حرف *iv, سائز_t len);
# endif /* HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV */
#اگر_ختم /* HAVE_EVP_CIPHER_CTX_GET_IV */

#اگر_غیر_تعریف_شدہ HAVE_EVP_CIPHER_CTX_سیٹ_IV
صحیح EVP_CIPHER_CTX_سیٹ_iv(EVP_CIPHER_CTX *ctx,
    ثابت غیرعلامتی حرف *iv, سائز_t len);
#اگر_ختم /* HAVE_EVP_CIPHER_CTX_SET_IV */

#اگر_غیر_تعریف_شدہ HAVE_EVP_DIGESTSIGN
صحیح EVP_DigestSign(EVP_MD_CTX *, غیرعلامتی حرف *, سائز_t *,
    ثابت غیرعلامتی حرف *, سائز_t);
#اگر_ختم

#اگر_غیر_تعریف_شدہ HAVE_EVP_DIGESTVERIFY
صحیح EVP_DigestVerify(EVP_MD_CTX *, ثابت غیرعلامتی حرف *, سائز_t,
    ثابت غیرعلامتی حرف *, سائز_t);
#اگر_ختم

#اگر_ختم /* WITH_OPENSSL */
#اگر_ختم /* _OPENSSL_COMPAT_H */
