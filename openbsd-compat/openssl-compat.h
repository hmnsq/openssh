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

#अगर_अघोषित _OPENSSL_COMPAT_H
#घोषणा _OPENSSL_COMPAT_H

#समावेश "includes.h"
#अगर_घोषित WITH_OPENSSL

#समावेश <openssl/opensslv.h>
#समावेश <openssl/crypto.h>
#समावेश <openssl/evp.h>
#समावेश <openssl/bn.h>
#समावेश <openssl/rsa.h>
#समावेश <openssl/ecdsa.h>
#समावेश <openssl/dh.h>

पूर्णांक ssh_compatible_openssl(दीर्घ, दीर्घ);
पूर्णांक ssh_libcrypto_init(व्योम);

#अगर (OPENSSL_VERSION_संख्या < 0x10100000L)
# error OpenSSL 1.1.0 or greater is required
#पूर्ण_अगर
#अगर_घोषित LIBRESSL_VERSION_संख्या
# अगर LIBRESSL_VERSION_संख्या < 0x3010000fL
#  error LibreSSL 3.1.0 or greater is required
# endif
#पूर्ण_अगर

#अगर_अघोषित OPENSSL_RSA_MAX_MODULUS_BITS
# define OPENSSL_RSA_MAX_MODULUS_BITS	16384
#पूर्ण_अगर

#अगर_घोषित LIBRESSL_VERSION_संख्या
# अगर LIBRESSL_VERSION_संख्या < 0x3010000fL
#  define HAVE_BROKEN_CHACHA20
# endif
#पूर्ण_अगर

#अगर defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
/*
 * BoringSSL and AWS-LC (rightly) got rid of the BN_FLG_CONSTTIME flag, along with
 * the entire BN_set_flags() interface.
 * https://boringssl.googlesource.com/boringssl/+/0a211dfe9
 */
# define BN_set_flags(a, b)
#पूर्ण_अगर

/* LibreSSL <3.4 has the _GFp variants but not the equivalent modern ones. */
#अगर_अघोषित HAVE_EC_POINT_GET_AFFINE_COORDINATES
# ifdef HAVE_EC_POINT_GET_AFFINE_COORDINATES_GFP
#  define EC_POINT_get_affine_coordinates(a, b, c, d, e) \
	(EC_POINT_get_affine_coordinates_GFp(a, b, c, d, e))
# endif
#पूर्ण_अगर
#अगर_अघोषित HAVE_EC_POINT_SET_AFFINE_COORDINATES
# ifdef HAVE_EC_POINT_SET_AFFINE_COORDINATES_GFP
#  define EC_POINT_set_affine_coordinates(a, b, c, d, e) \
	(EC_POINT_set_affine_coordinates_GFp(a, b, c, d, e))
# endif
#पूर्ण_अगर

#अगर_अघोषित HAVE_EVP_CIPHER_CTX_GET_IV
# ifdef HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV
#  define EVP_CIPHER_CTX_get_iv EVP_CIPHER_CTX_get_updated_iv
# अन्यथा /* HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV */
पूर्णांक EVP_CIPHER_CTX_get_iv(स्थिर EVP_CIPHER_CTX *ctx,
    अचिन्हित अक्षर *iv, माप_प्रकार len);
# endif /* HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV */
#पूर्ण_अगर /* HAVE_EVP_CIPHER_CTX_GET_IV */

#अगर_अघोषित HAVE_EVP_CIPHER_CTX_SET_IV
पूर्णांक EVP_CIPHER_CTX_set_iv(EVP_CIPHER_CTX *ctx,
    स्थिर अचिन्हित अक्षर *iv, माप_प्रकार len);
#पूर्ण_अगर /* HAVE_EVP_CIPHER_CTX_SET_IV */

#अगर_अघोषित HAVE_EVP_DIGESTSIGN
पूर्णांक EVP_DigestSign(EVP_MD_CTX *, अचिन्हित अक्षर *, माप_प्रकार *,
    स्थिर अचिन्हित अक्षर *, माप_प्रकार);
#पूर्ण_अगर

#अगर_अघोषित HAVE_EVP_DIGESTVERIFY
पूर्णांक EVP_DigestVerify(EVP_MD_CTX *, स्थिर अचिन्हित अक्षर *, माप_प्रकार,
    स्थिर अचिन्हित अक्षर *, माप_प्रकार);
#पूर्ण_अगर

#पूर्ण_अगर /* WITH_OPENSSL */
#पूर्ण_अगर /* _OPENSSL_COMPAT_H */
