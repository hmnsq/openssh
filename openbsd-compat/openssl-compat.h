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

#که_نه_تعریف_شوی _OPENSSL_COMPAT_H
#تعریف_کړه _OPENSSL_COMPAT_H

#ضمن "includes.h"
#که_تعریف_شوی WITH_OPENSSL

#ضمن <openssl/opensslv.h>
#ضمن <openssl/crypto.h>
#ضمن <openssl/evp.h>
#ضمن <openssl/bn.h>
#ضمن <openssl/rsa.h>
#ضمن <openssl/ecdsa.h>
#ضمن <openssl/dh.h>

صحيح ssh_compatible_openssl(اوږد, اوږد);
صحيح ssh_libcrypto_init(فراغ);

#إذا (OPENSSL_نسخه_شمېره < 0x10100000L)
# error OpenSSL 1.1.0 or greater is required
#د_که_پای
#که_تعریف_شوی LIBRESSL_نسخه_شمېره
# إذا LIBRESSL_نسخه_شمېره < 0x3010000fL
#  error LibreSSL 3.1.0 or greater is required
# endif
#د_که_پای

#که_نه_تعریف_شوی OPENSSL_RSA_MAX_MODULUS_بټونه
# define OPENSSL_RSA_MAX_MODULUS_بټونه	16384
#د_که_پای

#که_تعریف_شوی LIBRESSL_نسخه_شمېره
# إذا LIBRESSL_نسخه_شمېره < 0x3010000fL
#  define HAVE_BROKEN_CHACHA20
# endif
#د_که_پای

#إذا defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
/*
 * BoringSSL and AWS-LC (rightly) got rid of the BN_FLG_CONSTTIME flag, along with
 * the entire BN_set_flags() interface.
 * https://boringssl.googlesource.com/boringssl/+/0a211dfe9
 */
# define BN_سېټ_flags(a, b)
#د_که_پای

/* LibreSSL <3.4 has the _GFp variants but not the equivalent modern ones. */
#که_نه_تعریف_شوی HAVE_EC_ټکی_GET_AFFINE_COORDINATES
# ifdef HAVE_EC_ټکی_GET_AFFINE_COORDINATES_GFP
#  define EC_ټکی_get_affine_coordinates(a, b, c, d, e) \
	(EC_ټکی_get_affine_coordinates_GFp(a, b, c, d, e))
# endif
#د_که_پای
#که_نه_تعریف_شوی HAVE_EC_ټکی_سېټ_AFFINE_COORDINATES
# ifdef HAVE_EC_ټکی_سېټ_AFFINE_COORDINATES_GFP
#  define EC_ټکی_سېټ_affine_coordinates(a, b, c, d, e) \
	(EC_ټکی_سېټ_affine_coordinates_GFp(a, b, c, d, e))
# endif
#د_که_پای

#که_نه_تعریف_شوی HAVE_EVP_CIPHER_CTX_GET_IV
# ifdef HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV
#  define EVP_CIPHER_CTX_get_iv EVP_CIPHER_CTX_get_updated_iv
# وإلا /* HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV */
صحيح EVP_CIPHER_CTX_get_iv(ثابت EVP_CIPHER_CTX *ctx,
    بینښه حرف *iv, اندازه_t len);
# endif /* HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV */
#د_که_پای /* HAVE_EVP_CIPHER_CTX_GET_IV */

#که_نه_تعریف_شوی HAVE_EVP_CIPHER_CTX_سېټ_IV
صحيح EVP_CIPHER_CTX_سېټ_iv(EVP_CIPHER_CTX *ctx,
    ثابت بینښه حرف *iv, اندازه_t len);
#د_که_پای /* HAVE_EVP_CIPHER_CTX_SET_IV */

#که_نه_تعریف_شوی HAVE_EVP_DIGESTSIGN
صحيح EVP_DigestSign(EVP_MD_CTX *, بینښه حرف *, اندازه_t *,
    ثابت بینښه حرف *, اندازه_t);
#د_که_پای

#که_نه_تعریف_شوی HAVE_EVP_DIGESTVERIFY
صحيح EVP_DigestVerify(EVP_MD_CTX *, ثابت بینښه حرف *, اندازه_t,
    ثابت بینښه حرف *, اندازه_t);
#د_که_پای

#د_که_پای /* WITH_OPENSSL */
#د_که_پای /* _OPENSSL_COMPAT_H */
