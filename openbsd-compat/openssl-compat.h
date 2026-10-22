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

#నిర్వచితం_కాకపోతే _OPENSSL_COMPAT_H
#నిర్వచించు _OPENSSL_COMPAT_H

#అన్తర్భావ "includes.h"
#నిర్వచితమైతే WITH_OPENSSL

#అన్తర్భావ <openssl/opensslv.h>
#అన్తర్భావ <openssl/crypto.h>
#అన్తర్భావ <openssl/evp.h>
#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/rsa.h>
#అన్తర్భావ <openssl/ecdsa.h>
#అన్తర్భావ <openssl/dh.h>

పూర్ణాంకం ssh_compatible_openssl(దీర్ఘ, దీర్ఘ);
పూర్ణాంకం ssh_libcrypto_init(శూన్య);

#ఒకవేళ (OPENSSL_సంస్కరణ_సంఖ్య < 0x10100000L)
# error OpenSSL 1.1.0 or greater is required
#అయితే_ముగింపు
#నిర్వచితమైతే LIBRESSL_సంస్కరణ_సంఖ్య
# ఒకవేళ LIBRESSL_సంస్కరణ_సంఖ్య < 0x3010000fL
#  error LibreSSL 3.1.0 or greater is required
# endif
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే OPENSSL_RSA_MAX_MODULUS_బిట్లు
# define OPENSSL_RSA_MAX_MODULUS_బిట్లు	16384
#అయితే_ముగింపు

#నిర్వచితమైతే LIBRESSL_సంస్కరణ_సంఖ్య
# ఒకవేళ LIBRESSL_సంస్కరణ_సంఖ్య < 0x3010000fL
#  define HAVE_BROKEN_CHACHA20
# endif
#అయితే_ముగింపు

#ఒకవేళ defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
/*
 * BoringSSL and AWS-LC (rightly) got rid of the BN_FLG_CONSTTIME flag, along with
 * the entire BN_set_flags() interface.
 * https://boringssl.googlesource.com/boringssl/+/0a211dfe9
 */
# define BN_సమితి_flags(a, b)
#అయితే_ముగింపు

/* LibreSSL <3.4 has the _GFp variants but not the equivalent modern ones. */
#నిర్వచితం_కాకపోతే HAVE_EC_బిందువు_GET_AFFINE_COORDINATES
# ifdef HAVE_EC_బిందువు_GET_AFFINE_COORDINATES_GFP
#  define EC_బిందువు_get_affine_coordinates(a, b, c, d, e) \
	(EC_బిందువు_get_affine_coordinates_GFp(a, b, c, d, e))
# endif
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే HAVE_EC_బిందువు_సమితి_AFFINE_COORDINATES
# ifdef HAVE_EC_బిందువు_సమితి_AFFINE_COORDINATES_GFP
#  define EC_బిందువు_సమితి_affine_coordinates(a, b, c, d, e) \
	(EC_బిందువు_సమితి_affine_coordinates_GFp(a, b, c, d, e))
# endif
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_EVP_CIPHER_CTX_GET_IV
# ifdef HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV
#  define EVP_CIPHER_CTX_get_iv EVP_CIPHER_CTX_get_updated_iv
# లేకపోతే /* HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV */
పూర్ణాంకం EVP_CIPHER_CTX_get_iv(స్థిరరాశి EVP_CIPHER_CTX *ctx,
    గుర్తులేని అక్షరం *iv, కొలత_t len);
# endif /* HAVE_EVP_CIPHER_CTX_GET_UPDATED_IV */
#అయితే_ముగింపు /* HAVE_EVP_CIPHER_CTX_GET_IV */

#నిర్వచితం_కాకపోతే HAVE_EVP_CIPHER_CTX_సమితి_IV
పూర్ణాంకం EVP_CIPHER_CTX_సమితి_iv(EVP_CIPHER_CTX *ctx,
    స్థిరరాశి గుర్తులేని అక్షరం *iv, కొలత_t len);
#అయితే_ముగింపు /* HAVE_EVP_CIPHER_CTX_SET_IV */

#నిర్వచితం_కాకపోతే HAVE_EVP_DIGESTSIGN
పూర్ణాంకం EVP_DigestSign(EVP_MD_CTX *, గుర్తులేని అక్షరం *, కొలత_t *,
    స్థిరరాశి గుర్తులేని అక్షరం *, కొలత_t);
#అయితే_ముగింపు

#నిర్వచితం_కాకపోతే HAVE_EVP_DIGESTVERIFY
పూర్ణాంకం EVP_DigestVerify(EVP_MD_CTX *, స్థిరరాశి గుర్తులేని అక్షరం *, కొలత_t,
    స్థిరరాశి గుర్తులేని అక్షరం *, కొలత_t);
#అయితే_ముగింపు

#అయితే_ముగింపు /* WITH_OPENSSL */
#అయితే_ముగింపు /* _OPENSSL_COMPAT_H */
