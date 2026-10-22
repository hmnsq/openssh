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

#यदि_अपरिभाषितम् _OPENSSL_COMPAT_H
#परिभाषय _OPENSSL_COMPAT_H

#अन्तर्भाव "includes.h"
#यदि_परिभाषितम् WITH_OPENSSL

#अन्तर्भाव <openssl/opensslv.h>
#अन्तर्भाव <openssl/crypto.h>
#अन्तर्भाव <openssl/evp.h>
#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/rsa.h>
#अन्तर्भाव <openssl/ecdsa.h>
#अन्तर्भाव <openssl/dh.h>

पूर्णाङ्क ssh_compatible_openssl(दीर्घ, दीर्घ);
पूर्णाङ्क ssh_libcrypto_init(शून्य);

#यदि (OPENSSL_संस्करणम्_सङ्ख्या < 0x10100000L)
# error OpenSSL 1.1.0 or greater is required
#यदि_अन्तः
#यदि_परिभाषितम् LIBRESSL_संस्करणम्_सङ्ख्या
# यदि LIBRESSL_संस्करणम्_सङ्ख्या < 0x3010000fL
#  error LibreSSL 3.1.0 or greater is required
# endif
#यदि_अन्तः

#यदि_अपरिभाषितम् OPENSSL_RSA_MAX_MODULUS_द्वयङ्काः
# define OPENSSL_RSA_MAX_MODULUS_द्वयङ्काः	16384
#यदि_अन्तः

#यदि_परिभाषितम् LIBRESSL_संस्करणम्_सङ्ख्या
# यदि LIBRESSL_संस्करणम्_सङ्ख्या < 0x3010000fL
#  define HAVE_BROKEN_CHACHA20
# endif
#यदि_अन्तः

#यदि defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
/*
 * BoringSSL and AWS-LC (rightly) got rid of the BN_FLG_CONSTTIME flag, along with
 * the entire BN_set_flags() interface.
 * https://boringssl.googlesource.com/boringssl/+/0a211dfe9
 */
# define BN_समुच्चयः_flags(a, b)
#यदि_अन्तः

/* LibreSSL <3.4 has the _GFp variants but not the equivalent modern ones. */
#यदि_अपरिभाषितम् HAVE_EC_POINT_GET_AFFINE_COORDINATES
# ifdef HAVE_EC_POINT_GET_AFFINE_COORDINATES_GFP
#  define EC_POINT_get_affine_coordinates(a, b, c, d, e) \
	(EC_POINT_get_affine_coordinates_GFp(a, b, c, d, e))
# endif
#यदि_अन्तः
#यदि_अपरिभाषितम् HAVE_EC_POINT_समुच्चयः_AFFINE_COORDINATES
# ifdef HAVE_EC_POINT_समुच्चयः_AFFINE_COORDINATES_GFP
#  define EC_POINT_समुच्चयः_affine_coordinates(a, b, c, d, e) \
	(EC_POINT_समुच्चयः_affine_coordinates_GFp(a, b, c, d, e))
# endif
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_EVP_CIPHER_CTX_GET_IV
# ifdef HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV
#  define EVP_CIPHER_CTX_get_iv EVP_CIPHER_CTX_get_updated_iv
# अन्यथा /* HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV */
पूर्णाङ्क EVP_CIPHER_CTX_get_iv(ध्रुव EVP_CIPHER_CTX *ctx,
    अचिह्नित वर्ण *iv, आकार_t len);
# endif /* HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV */
#यदि_अन्तः /* HAVE_EVP_CIPHER_CTX_GET_IV */

#यदि_अपरिभाषितम् HAVE_EVP_CIPHER_CTX_समुच्चयः_IV
पूर्णाङ्क EVP_CIPHER_CTX_समुच्चयः_iv(EVP_CIPHER_CTX *ctx,
    ध्रुव अचिह्नित वर्ण *iv, आकार_t len);
#यदि_अन्तः /* HAVE_EVP_CIPHER_CTX_SET_IV */

#यदि_अपरिभाषितम् HAVE_EVP_DIGESTSIGN
पूर्णाङ्क EVP_DigestSign(EVP_MD_CTX *, अचिह्नित वर्ण *, आकार_t *,
    ध्रुव अचिह्नित वर्ण *, आकार_t);
#यदि_अन्तः

#यदि_अपरिभाषितम् HAVE_EVP_DIGESTVERIFY
पूर्णाङ्क EVP_DigestVerify(EVP_MD_CTX *, ध्रुव अचिह्नित वर्ण *, आकार_t,
    ध्रुव अचिह्नित वर्ण *, आकार_t);
#यदि_अन्तः

#यदि_अन्तः /* WITH_OPENSSL */
#यदि_अन्तः /* _OPENSSL_COMPAT_H */
