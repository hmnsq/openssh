/* $OpenBSD: sk-dummy.c,v 1.17 2026/09/16 00:45:03 djm Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>

#ಅನ್ತರ್ಭಾವ "crypto_api.h"
#ಅನ್ತರ್ಭಾವ "sk-api.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/opensslv.h>
#ಅನ್ತರ್ಭಾವ <openssl/sha.h>
#ಅನ್ತರ್ಭಾವ <openssl/crypto.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/ec.h>
#ಅನ್ತರ್ಭಾವ <openssl/ecdsa.h>
#ಅನ್ತರ್ಭಾವ <openssl/pem.h>

/* Use OpenSSL SHA256 instead of libc */
#ವ್ಯಾಖ್ಯಾನಿಸು SHA256Init(x)		SHA256_Init(x)
#ವ್ಯಾಖ್ಯಾನಿಸು SHA256Update(x, y, z)	SHA256_Update(x, y, z)
#ವ್ಯಾಖ್ಯಾನಿಸು SHA256Final(x, y)	SHA256_Final(x, y)
#ವ್ಯಾಖ್ಯಾನಿಸು SHA2_CTX		SHA256_CTX

#ಅಥವಾಆದರೆ defined(HAVE_SHA2_H)
#ಅನ್ತರ್ಭಾವ <sha2.h>
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

/* #define SK_DEBUG 1 */

#ಆದರೆ SSH_SK_ಆವೃತ್ತಿ_MAJOR != 0x000a0000
# error SK API has ಬದಲಾಯಿತು, sk-dummy.c needs an update
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SK_DUMMY_INTEGRATE
# define sk_api_ಆವೃತ್ತಿ		ssh_sk_api_ಆವೃತ್ತಿ
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_ತುಂಬು_resident_ಕೀಲಿಗಳು	ssh_sk_ತುಂಬು_resident_ಕೀಲಿಗಳು
#ಆದರೆ_ಅಂತ್ಯ /* !SK_STANDALONE */

ಸ್ಥಿರ ಶೂನ್ಯ skdebug(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *func, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
    __attribute__((__format__ (ಬರೆ, 2, 3)));

ಸ್ಥಿರ ಶೂನ್ಯ
skdebug(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *func, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
#ಆದರೆ defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "sk-dummy %s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#ಇಲ್ಲದಿದ್ದರೆ
	(ಶೂನ್ಯ)func; /* XXX */
	(ಶೂನ್ಯ)fmt; /* XXX */
#ಆದರೆ_ಅಂತ್ಯ
}

uint32_t
sk_api_ಆವೃತ್ತಿ(ಶೂನ್ಯ)
{
	ಹಿಂತಿರುಗಿ SSH_SK_ಆವೃತ್ತಿ_MAJOR;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pack_ಕೀಲಿ_ecdsa(ರಚನೆ sk_enroll_response *response)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	EC_ಕೀಲಿ *ಕೀಲಿ = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ EC_ಗುಂಪು *g;
	ಸ್ಥಿರಾಂಕ EC_ಬಿಂದು *q;
	ಪೂರ್ಣಾಂಕ ret = -1;
	ದೀರ್ಘ privlen;
	BIO *bio = ಖಾಲಿ;
	ಅಕ್ಷರ *privptr;

	response->ಬಹಿರಂಗ_ಕೀಲಿ = ಖಾಲಿ;
	response->ಬಹಿರಂಗ_ಕೀಲಿ_len = 0;
	response->ಕೀಲಿ_handle = ಖಾಲಿ;
	response->ಕೀಲಿ_handle_len = 0;

	ಆದರೆ ((ಕೀಲಿ = EC_ಕೀಲಿ_new_by_ವಕ್ರ_name(NID_X9_62_prime256v1)) == ಖಾಲಿ) {
		skdebug(__func__, "EC_KEY_new_by_curve_name");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EC_ಕೀಲಿ_generate_ಕೀಲಿ(ಕೀಲಿ) != 1) {
		skdebug(__func__, "EC_KEY_generate_key");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	EC_ಕೀಲಿ_ಗಣ_asn1_flag(ಕೀಲಿ, OPENSSL_EC_NAMED_ವಕ್ರ);
	ಆದರೆ ((bio = BIO_new(BIO_s_mem())) == ಖಾಲಿ ||
	    (g = EC_ಕೀಲಿ_get0_ಗುಂಪು(ಕೀಲಿ)) == ಖಾಲಿ ||
	    (q = EC_ಕೀಲಿ_get0_ಬಹಿರಂಗ_ಕೀಲಿ(ಕೀಲಿ)) == ಖಾಲಿ) {
		skdebug(__func__, "couldn't get key parameters");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	response->ಬಹಿರಂಗ_ಕೀಲಿ_len = EC_ಬಿಂದು_point2oct(g, q,
	    ಬಿಂದು_CONVERSION_UNCOMPRESSED, ಖಾಲಿ, 0, ಖಾಲಿ);
	ಆದರೆ (response->ಬಹಿರಂಗ_ಕೀಲಿ_len == 0 || response->ಬಹಿರಂಗ_ಕೀಲಿ_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->ಬಹಿರಂಗ_ಕೀಲಿ_len);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((response->ಬಹಿರಂಗ_ಕೀಲಿ = ಸ್ಮರಣೆ_ಕೊಡು(response->ಬಹಿರಂಗ_ಕೀಲಿ_len)) == ಖಾಲಿ) {
		skdebug(__func__, "malloc pubkey failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EC_ಬಿಂದು_point2oct(g, q, ಬಿಂದು_CONVERSION_UNCOMPRESSED,
	    response->ಬಹಿರಂಗ_ಕೀಲಿ, response->ಬಹಿರಂಗ_ಕೀಲಿ_len, ಖಾಲಿ) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* Key handle contains PEM encoded private key */
	ಆದರೆ (!PEM_write_bio_ECPrivate_ಕೀಲಿ(bio, ಕೀಲಿ, ಖಾಲಿ, ಖಾಲಿ, 0, ಖಾಲಿ, ಖಾಲಿ)) {
		skdebug(__func__, "PEM_write_bio_ECPrivateKey failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((privlen = BIO_get_mem_ದತ್ತಾಂಶ(bio, &privptr)) <= 0) {
		skdebug(__func__, "BIO_get_mem_data failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((response->ಕೀಲಿ_handle = ಸ್ಮರಣೆ_ಕೊಡು(privlen)) == ಖಾಲಿ) {
		skdebug(__func__, "malloc key_handle failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	response->ಕೀಲಿ_handle_len = (ಗಾತ್ರ_t)privlen;
	ಸ್ಮರಣೆ_ನಕಲು(response->ಕೀಲಿ_handle, privptr, response->ಕೀಲಿ_handle_len);
	/* success */
	ret = 0;
 ಹೊರಹೋಗು:
	ಆದರೆ (ret != 0) {
		ಆದರೆ (response->ಬಹಿರಂಗ_ಕೀಲಿ != ಖಾಲಿ) {
			memset(response->ಬಹಿರಂಗ_ಕೀಲಿ, 0,
			    response->ಬಹಿರಂಗ_ಕೀಲಿ_len);
			ಬಿಡುಗಡೆ(response->ಬಹಿರಂಗ_ಕೀಲಿ);
			response->ಬಹಿರಂಗ_ಕೀಲಿ = ಖಾಲಿ;
		}
		ಆದರೆ (response->ಕೀಲಿ_handle != ಖಾಲಿ) {
			memset(response->ಕೀಲಿ_handle, 0,
			    response->ಕೀಲಿ_handle_len);
			ಬಿಡುಗಡೆ(response->ಕೀಲಿ_handle);
			response->ಕೀಲಿ_handle = ಖಾಲಿ;
		}
	}
	BIO_free(bio);
	EC_ಕೀಲಿ_free(ಕೀಲಿ);
	ಹಿಂತಿರುಗಿ ret;
#ಇಲ್ಲದಿದ್ದರೆ
	ಹಿಂತಿರುಗಿ -1;
#ಆದರೆ_ಅಂತ್ಯ
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pack_ಕೀಲಿ_ed25519(ರಚನೆ sk_enroll_response *response)
{
	ಪೂರ್ಣಾಂಕ ret = -1;
	u_char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	u_char sk[crypto_sign_ed25519_SECRETKEYBYTES];

	response->ಬಹಿರಂಗ_ಕೀಲಿ = ಖಾಲಿ;
	response->ಬಹಿರಂಗ_ಕೀಲಿ_len = 0;
	response->ಕೀಲಿ_handle = ಖಾಲಿ;
	response->ಕೀಲಿ_handle_len = 0;

	memset(pk, 0, ಗಾತ್ರ(pk));
	memset(sk, 0, ಗಾತ್ರ(sk));
	crypto_sign_ed25519_keypair(pk, sk);

	response->ಬಹಿರಂಗ_ಕೀಲಿ_len = ಗಾತ್ರ(pk);
	ಆದರೆ ((response->ಬಹಿರಂಗ_ಕೀಲಿ = ಸ್ಮರಣೆ_ಕೊಡು(response->ಬಹಿರಂಗ_ಕೀಲಿ_len)) == ಖಾಲಿ) {
		skdebug(__func__, "malloc pubkey failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಸ್ಮರಣೆ_ನಕಲು(response->ಬಹಿರಂಗ_ಕೀಲಿ, pk, ಗಾತ್ರ(pk));
	/* Key handle contains sk */
	response->ಕೀಲಿ_handle_len = ಗಾತ್ರ(sk);
	ಆದರೆ ((response->ಕೀಲಿ_handle = ಸ್ಮರಣೆ_ಕೊಡು(response->ಕೀಲಿ_handle_len)) == ಖಾಲಿ) {
		skdebug(__func__, "malloc key_handle failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಸ್ಮರಣೆ_ನಕಲು(response->ಕೀಲಿ_handle, sk, ಗಾತ್ರ(sk));
	/* success */
	ret = 0;
 ಹೊರಹೋಗು:
	ಆದರೆ (ret != 0)
		ಬಿಡುಗಡೆ(response->ಬಹಿರಂಗ_ಕೀಲಿ);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
check_options(ರಚನೆ sk_option **options)
{
	ಗಾತ್ರ_t i;

	ಆದರೆ (options == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಗಾಗಿ (i = 0; options[i] != ಖಾಲಿ; i++) {
		skdebug(__func__, "requested unsupported option %s",
		    options[i]->name);
		ಆದರೆ (options[i]->required) {
			skdebug(__func__, "unknown required option");
			ಹಿಂತಿರುಗಿ -1;
		}
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sk_enroll(uint32_t alg, ಸ್ಥಿರಾಂಕ uint8_t *challenge, ಗಾತ್ರ_t challenge_len,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application, uint8_t flags, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin,
    ರಚನೆ sk_option **options, ರಚನೆ sk_enroll_response **enroll_response)
{
	ರಚನೆ sk_enroll_response *response = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ret = SSH_SK_ERR_GENERAL;

	(ಶೂನ್ಯ)flags; /* XXX; unused */

	ಆದರೆ (enroll_response == ಖಾಲಿ) {
		skdebug(__func__, "enroll_response == NULL");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	*enroll_response = ಖಾಲಿ;
	ಆದರೆ (check_options(options) != 0)
		ಹೋಗು ಹೊರಹೋಗು; /* error already logged */
	ಆದರೆ ((response = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*response))) == ಖಾಲಿ) {
		skdebug(__func__, "calloc response failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	response->flags = flags;
	ಆಯ್ಕೆ(alg) {
	ಸ್ಥಿತಿ SSH_SK_ECDSA:
		ಆದರೆ (pack_ಕೀಲಿ_ecdsa(response) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH_SK_ED25519:
		ಆದರೆ (pack_ಕೀಲಿ_ed25519(response) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		skdebug(__func__, "unsupported key type %d", alg);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* Have to return something here */
	ಆದರೆ ((response->signature = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, 1)) == ಖಾಲಿ) {
		skdebug(__func__, "calloc signature failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	response->signature_len = 0;

	*enroll_response = response;
	response = ಖಾಲಿ;
	ret = 0;
 ಹೊರಹೋಗು:
	ಆದರೆ (response != ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(response->ಬಹಿರಂಗ_ಕೀಲಿ);
		ಬಿಡುಗಡೆ(response->ಕೀಲಿ_handle);
		ಬಿಡುಗಡೆ(response->signature);
		ಬಿಡುಗಡೆ(response->attestation_cert);
		ಬಿಡುಗಡೆ(response);
	}
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *preamble, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *sv, ಗಾತ್ರ_t l)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SK_DEBUG
	ಸ್ಥಿರಾಂಕ u_char *s = (ಸ್ಥಿರಾಂಕ u_char *)sv;
	ಗಾತ್ರ_t i;

	fprintf(stderr, "%s (len %zu):\n", preamble, l);
	ಗಾಗಿ (i = 0; i < l; i++) {
		ಆದರೆ (i % 16 == 0)
			fprintf(stderr, "%04zu: ", i);
		fprintf(stderr, "%02x", s[i]);
		ಆದರೆ (i % 16 == 15 || i == l - 1)
			fprintf(stderr, "\n");
	}
#ಆದರೆ_ಅಂತ್ಯ
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sig_ecdsa(ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ_2, ಗಾತ್ರ_t ಸಂದೇಶ_len_2,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application, uint32_t counter, uint8_t flags,
    ಸ್ಥಿರಾಂಕ uint8_t *ಕೀಲಿ_handle, ಗಾತ್ರ_t ಕೀಲಿ_handle_len,
    ರಚನೆ sk_sign_response *response)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ECDSA_SIG *sig = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ BIGNUM *sig_r, *sig_s;
	ಪೂರ್ಣಾಂಕ ret = -1;
	BIO *bio = ಖಾಲಿ;
	EVP_PKEY *pk = ಖಾಲಿ;
	EC_ಕೀಲಿ *ec = ಖಾಲಿ;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_ಉದ್ದಳತೆ];
	uint8_t	sighash[SHA256_DIGEST_ಉದ್ದಳತೆ];
	uint8_t countbuf[4];

	/* Decode EC_KEY from key handle */
	ಆದರೆ ((bio = BIO_new(BIO_s_mem())) == ಖಾಲಿ ||
	    BIO_write(bio, ಕೀಲಿ_handle, ಕೀಲಿ_handle_len) != (ಪೂರ್ಣಾಂಕ)ಕೀಲಿ_handle_len) {
		skdebug(__func__, "BIO setup failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((pk = PEM_read_bio_ಖಾಸಗಿ_ಕೀಲಿ(bio, ಖಾಲಿ, ಖಾಲಿ, "")) == ಖಾಲಿ) {
		skdebug(__func__, "PEM_read_bio_PrivateKey failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EVP_PKEY_ತಳ_id(pk) != EVP_PKEY_EC) {
		skdebug(__func__, "Not an EC key: %d", EVP_PKEY_ತಳ_id(pk));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((ec = EVP_PKEY_get1_EC_ಕೀಲಿ(pk)) == ಖಾಲಿ) {
		skdebug(__func__, "EVP_PKEY_get1_EC_KEY failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* Expect message to be pre-hashed */
	ಆದರೆ (ಸಂದೇಶ_len_2 != SHA256_DIGEST_ಉದ್ದಳತೆ) {
		skdebug(__func__, "bad message len %zu", ಸಂದೇಶ_len_2);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* Prepare data to be signed */
	dump("message", ಸಂದೇಶ_2, ಸಂದೇಶ_len_2);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ಸ್ಥಿರಾಂಕ u_char *)application, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, ಗಾತ್ರ(apphash));
	countbuf[0] = (counter >> 24) & 0xff;
	countbuf[1] = (counter >> 16) & 0xff;
	countbuf[2] = (counter >> 8) & 0xff;
	countbuf[3] = counter & 0xff;
	dump("countbuf", countbuf, ಗಾತ್ರ(countbuf));
	dump("flags", &flags, ಗಾತ್ರ(flags));
	SHA256Init(&ctx);
	SHA256Update(&ctx, apphash, ಗಾತ್ರ(apphash));
	SHA256Update(&ctx, &flags, ಗಾತ್ರ(flags));
	SHA256Update(&ctx, countbuf, ಗಾತ್ರ(countbuf));
	SHA256Update(&ctx, ಸಂದೇಶ_2, ಸಂದೇಶ_len_2);
	SHA256Final(sighash, &ctx);
	dump("sighash", sighash, ಗಾತ್ರ(sighash));
	/* create and encode signature */
	ಆದರೆ ((sig = ECDSA_do_sign(sighash, ಗಾತ್ರ(sighash), ec)) == ಖಾಲಿ) {
		skdebug(__func__, "ECDSA_do_sign failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_ಅಂಕೆ_ಬೈಟುಗಳು(sig_r);
	response->sig_s_len = BN_ಅಂಕೆ_ಬೈಟುಗಳು(sig_s);
	ಆದರೆ ((response->sig_r = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, response->sig_r_len)) == ಖಾಲಿ ||
	    (response->sig_s = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, response->sig_s_len)) == ಖಾಲಿ) {
		skdebug(__func__, "calloc signature failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 ಹೊರಹೋಗು:
	explicit_bzero(&ctx, ಗಾತ್ರ(ctx));
	explicit_bzero(&apphash, ಗಾತ್ರ(apphash));
	explicit_bzero(&sighash, ಗಾತ್ರ(sighash));
	ECDSA_SIG_free(sig);
	ಆದರೆ (ret != 0) {
		ಬಿಡುಗಡೆ(response->sig_r);
		ಬಿಡುಗಡೆ(response->sig_s);
		response->sig_r = ಖಾಲಿ;
		response->sig_s = ಖಾಲಿ;
	}
	BIO_free(bio);
	EC_ಕೀಲಿ_free(ec);
	EVP_PKEY_free(pk);
	ಹಿಂತಿರುಗಿ ret;
#ಇಲ್ಲದಿದ್ದರೆ
	ಹಿಂತಿರುಗಿ -1;
#ಆದರೆ_ಅಂತ್ಯ
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sig_ed25519(ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ_2, ಗಾತ್ರ_t ಸಂದೇಶ_len_2,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application, uint32_t counter, uint8_t flags,
    ಸ್ಥಿರಾಂಕ uint8_t *ಕೀಲಿ_handle, ಗಾತ್ರ_t ಕೀಲಿ_handle_len,
    ರಚನೆ sk_sign_response *response)
{
	ಗಾತ್ರ_t o;
	ಪೂರ್ಣಾಂಕ ret = -1;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_ಉದ್ದಳತೆ];
	uint8_t signbuf[ಗಾತ್ರ(apphash) + ಗಾತ್ರ(flags) +
	    ಗಾತ್ರ(counter) + SHA256_DIGEST_ಉದ್ದಳತೆ];
	uint8_t sig[crypto_sign_ed25519_ಬೈಟುಗಳು];
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ siglen = 0;

	ಆದರೆ (ಕೀಲಿ_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		skdebug(__func__, "bad key handle length %zu", ಕೀಲಿ_handle_len);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* Expect message to be pre-hashed */
	ಆದರೆ (ಸಂದೇಶ_len_2 != SHA256_DIGEST_ಉದ್ದಳತೆ) {
		skdebug(__func__, "bad message len %zu", ಸಂದೇಶ_len_2);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* Prepare data to be signed */
	dump("message", ಸಂದೇಶ_2, ಸಂದೇಶ_len_2);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ಸ್ಥಿರಾಂಕ u_char *)application, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, ಗಾತ್ರ(apphash));

	ಸ್ಮರಣೆ_ನಕಲು(signbuf, apphash, ಗಾತ್ರ(apphash));
	o = ಗಾತ್ರ(apphash);
	signbuf[o++] = flags;
	signbuf[o++] = (counter >> 24) & 0xff;
	signbuf[o++] = (counter >> 16) & 0xff;
	signbuf[o++] = (counter >> 8) & 0xff;
	signbuf[o++] = counter & 0xff;
	ಸ್ಮರಣೆ_ನಕಲು(signbuf + o, ಸಂದೇಶ_2, ಸಂದೇಶ_len_2);
	o += ಸಂದೇಶ_len_2;
	ಆದರೆ (o != ಗಾತ್ರ(signbuf)) {
		skdebug(__func__, "bad sign buf len %zu, expected %zu",
		    o, ಗಾತ್ರ(signbuf));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	dump("signbuf", signbuf, ಗಾತ್ರ(signbuf));
	/* create and encode signature */
	ಆದರೆ (crypto_sign_ed25519_detached(sig, &siglen, signbuf, ಗಾತ್ರ(signbuf),
	    ಕೀಲಿ_handle) != 0) {
		skdebug(__func__, "crypto_sign_ed25519_detached failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (siglen != ಗಾತ್ರ(sig)) {
		skdebug(__func__, "bad signature length %llu", siglen);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	response->sig_r_len = ಗಾತ್ರ(sig);
	ಆದರೆ ((response->sig_r = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, response->sig_r_len)) == ಖಾಲಿ) {
		skdebug(__func__, "calloc signature failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಸ್ಮರಣೆ_ನಕಲು(response->sig_r, sig, response->sig_r_len);
	dump("sig_r", response->sig_r, response->sig_r_len);
	ret = 0;
 ಹೊರಹೋಗು:
	explicit_bzero(&ctx, ಗಾತ್ರ(ctx));
	explicit_bzero(&apphash, ಗಾತ್ರ(apphash));
	explicit_bzero(&signbuf, ಗಾತ್ರ(signbuf));
	explicit_bzero(&sig, ಗಾತ್ರ(sig));
	ಆದರೆ (ret != 0) {
		ಬಿಡುಗಡೆ(response->sig_r);
		response->sig_r = ಖಾಲಿ;
	}
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
sk_sign(uint32_t alg, ಸ್ಥಿರಾಂಕ uint8_t *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application, ಸ್ಥಿರಾಂಕ uint8_t *ಕೀಲಿ_handle, ಗಾತ್ರ_t ಕೀಲಿ_handle_len,
    uint8_t flags, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin, ರಚನೆ sk_option **options,
    ರಚನೆ sk_sign_response **sign_response)
{
	ರಚನೆ sk_sign_response *response = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ret = SSH_SK_ERR_GENERAL;
	SHA2_CTX ctx;
	uint8_t ಸಂದೇಶ_2[32];

	ಆದರೆ (sign_response == ಖಾಲಿ) {
		skdebug(__func__, "sign_response == NULL");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	*sign_response = ಖಾಲಿ;
	ಆದರೆ (check_options(options) != 0)
		ಹೋಗು ಹೊರಹೋಗು; /* error already logged */
	ಆದರೆ ((response = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*response))) == ಖಾಲಿ) {
		skdebug(__func__, "calloc response failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	SHA256Init(&ctx);
	SHA256Update(&ctx, ದತ್ತಾಂಶ, datalen);
	SHA256Final(ಸಂದೇಶ_2, &ctx);
	response->flags = flags;
	response->counter = 0x12345678;
	ಆಯ್ಕೆ(alg) {
	ಸ್ಥಿತಿ SSH_SK_ECDSA:
		ಆದರೆ (sig_ecdsa(ಸಂದೇಶ_2, ಗಾತ್ರ(ಸಂದೇಶ_2), application,
		    response->counter, flags, ಕೀಲಿ_handle, ಕೀಲಿ_handle_len,
		    response) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH_SK_ED25519:
		ಆದರೆ (sig_ed25519(ಸಂದೇಶ_2, ಗಾತ್ರ(ಸಂದೇಶ_2), application,
		    response->counter, flags, ಕೀಲಿ_handle, ಕೀಲಿ_handle_len,
		    response) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		skdebug(__func__, "unsupported key type %d", alg);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	*sign_response = response;
	response = ಖಾಲಿ;
	ret = 0;
 ಹೊರಹೋಗು:
	explicit_bzero(ಸಂದೇಶ_2, ಗಾತ್ರ(ಸಂದೇಶ_2));
	ಆದರೆ (response != ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(response->sig_r);
		ಬಿಡುಗಡೆ(response->sig_s);
		ಬಿಡುಗಡೆ(response);
	}
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
sk_ತುಂಬು_resident_ಕೀಲಿಗಳು(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin, ರಚನೆ sk_option **options,
    ರಚನೆ sk_resident_ಕೀಲಿ ***rks, ಗಾತ್ರ_t *nrks)
{
	ಹಿಂತಿರುಗಿ SSH_SK_ERR_UNSUPPORTED;
}
