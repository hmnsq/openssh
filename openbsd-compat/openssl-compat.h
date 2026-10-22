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

#جيڪڏهن_وصف_نه_ٿيل _OPENSSL_COMPAT_H
#وصف_ڪريو _OPENSSL_COMPAT_H

#ضمن "includes.h"
#جيڪڏهن_وصف_ٿيل WITH_OPENSSL

#ضمن <openssl/opensslv.h>
#ضمن <openssl/crypto.h>
#ضمن <openssl/evp.h>
#ضمن <openssl/bn.h>
#ضمن <openssl/rsa.h>
#ضمن <openssl/ecdsa.h>
#ضمن <openssl/dh.h>

صحيح ssh_compatible_openssl(ڊگهو, ڊگهو);
صحيح ssh_libcrypto_init(فراغ);

#إذا (OPENSSL_نسخو_عدد < 0x10100000L)
# error OpenSSL 1.1.0 or greater is required
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل LIBRESSL_نسخو_عدد
# إذا LIBRESSL_نسخو_عدد < 0x3010000fL
#  error LibreSSL 3.1.0 or greater is required
# endif
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل OPENSSL_RSA_MAX_MODULUS_بٽ
# define OPENSSL_RSA_MAX_MODULUS_بٽ	16384
#جيڪڏهن_پورو

#جيڪڏهن_وصف_ٿيل LIBRESSL_نسخو_عدد
# إذا LIBRESSL_نسخو_عدد < 0x3010000fL
#  define HAVE_BROKEN_CHACHA20
# endif
#جيڪڏهن_پورو

#إذا defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
/*
 * BoringSSL and AWS-LC (rightly) got rid of the BN_FLG_CONSTTIME flag, along with
 * the entire BN_set_flags() interface.
 * https://boringssl.googlesource.com/boringssl/+/0a211dfe9
 */
# define BN_سيٽ_flags(a, b)
#جيڪڏهن_پورو

/* LibreSSL <3.4 has the _GFp variants but not the equivalent modern ones. */
#جيڪڏهن_وصف_نه_ٿيل HAVE_EC_نقطو_GET_AFFINE_COORDINATES
# ifdef HAVE_EC_نقطو_GET_AFFINE_COORDINATES_GFP
#  define EC_نقطو_get_affine_coordinates(a, b, c, d, e) \
	(EC_نقطو_get_affine_coordinates_GFp(a, b, c, d, e))
# endif
#جيڪڏهن_پورو
#جيڪڏهن_وصف_نه_ٿيل HAVE_EC_نقطو_سيٽ_AFFINE_COORDINATES
# ifdef HAVE_EC_نقطو_سيٽ_AFFINE_COORDINATES_GFP
#  define EC_نقطو_سيٽ_affine_coordinates(a, b, c, d, e) \
	(EC_نقطو_سيٽ_affine_coordinates_GFp(a, b, c, d, e))
# endif
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_EVP_CIPHER_CTX_GET_IV
# ifdef HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV
#  define EVP_CIPHER_CTX_get_iv EVP_CIPHER_CTX_get_updated_iv
# وإلا /* HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV */
صحيح EVP_CIPHER_CTX_get_iv(ثابت EVP_CIPHER_CTX *ctx,
    بنانشان حرف *iv, سائيز_t len);
# endif /* HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV */
#جيڪڏهن_پورو /* HAVE_EVP_CIPHER_CTX_GET_IV */

#جيڪڏهن_وصف_نه_ٿيل HAVE_EVP_CIPHER_CTX_سيٽ_IV
صحيح EVP_CIPHER_CTX_سيٽ_iv(EVP_CIPHER_CTX *ctx,
    ثابت بنانشان حرف *iv, سائيز_t len);
#جيڪڏهن_پورو /* HAVE_EVP_CIPHER_CTX_SET_IV */

#جيڪڏهن_وصف_نه_ٿيل HAVE_EVP_DIGESTSIGN
صحيح EVP_DigestSign(EVP_MD_CTX *, بنانشان حرف *, سائيز_t *,
    ثابت بنانشان حرف *, سائيز_t);
#جيڪڏهن_پورو

#جيڪڏهن_وصف_نه_ٿيل HAVE_EVP_DIGESTVERIFY
صحيح EVP_DigestVerify(EVP_MD_CTX *, ثابت بنانشان حرف *, سائيز_t,
    ثابت بنانشان حرف *, سائيز_t);
#جيڪڏهن_پورو

#جيڪڏهن_پورو /* WITH_OPENSSL */
#جيڪڏهن_پورو /* _OPENSSL_COMPAT_H */
