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

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/opensslv.h>
#ಅನ್ತರ್ಭಾವ <openssl/sha.h>
#ಅನ್ತರ್ಭಾವ <openssl/crypto.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/ec.h>
#ಅನ್ತರ್ಭಾವ <openssl/ecdsa.h>
#ಅನ್ತರ್ಭಾವ <openssl/pem.h>

/* Use OpenSSL SHA256 instead of libc */
#define SHA256Init(x)		SHA256_Init(x)
#define SHA256Update(x, y, z)	SHA256_Update(x, y, z)
#define SHA256Final(x, y)	SHA256_Final(x, y)
#define SHA2_CTX		SHA256_CTX

#ನೋಚೇದ್ಯದಿ defined(HAVE_SHA2_H)
#ಅನ್ತರ್ಭಾವ <sha2.h>
#endif /* WITH_OPENSSL */

/* #define SK_DEBUG 1 */

#ಯದಿ SSH_SK_VERSION_MAJOR != 0x000a0000
# error SK API has changed, sk-dummy.c needs an update
#endif

#ifdef SK_DUMMY_INTEGRATE
# define sk_api_version		ssh_sk_api_version
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_load_resident_ಕೀಲಿಗಳು	ssh_sk_load_resident_ಕೀಲಿಗಳು
#endif /* !SK_STANDALONE */

ಸ್ಥಿರ ಶೂನ್ಯ skdebug(ಧ್ರುವ ವರ್ಣ *func, ಧ್ರುವ ವರ್ಣ *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

ಸ್ಥಿರ ಶೂನ್ಯ
skdebug(ಧ್ರುವ ವರ್ಣ *func, ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
#ಯದಿ defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "sk-dummy %s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#ಅನ್ಯಥಾ
	(ಶೂನ್ಯ)func; /* XXX */
	(ಶೂನ್ಯ)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(ಶೂನ್ಯ)
{
	ಪ್ರತ್ಯಾಗಮ SSH_SK_VERSION_MAJOR;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pack_ಕೀಲಿ_ecdsa(ಸಂರಚನಾ sk_enroll_response *response)
{
#ifdef WITH_OPENSSL
	EC_ಕೀಲಿ *ಕೀಲಿ = ರಿಕ್ತ;
	ಧ್ರುವ EC_GROUP *g;
	ಧ್ರುವ EC_POINT *q;
	ಪೂರ್ಣಾಙ್ಕ ret = -1;
	long privlen;
	BIO *bio = ರಿಕ್ತ;
	ವರ್ಣ *privptr;

	response->public_ಕೀಲಿ = ರಿಕ್ತ;
	response->public_ಕೀಲಿ_len = 0;
	response->ಕೀಲಿ_handle = ರಿಕ್ತ;
	response->ಕೀಲಿ_handle_len = 0;

	ಯದಿ ((ಕೀಲಿ = EC_ಕೀಲಿ_new_by_curve_name(NID_X9_62_prime256v1)) == ರಿಕ್ತ) {
		skdebug(__func__, "EC_KEY_new_by_curve_name");
		ಗಚ್ಛ out;
	}
	ಯದಿ (EC_ಕೀಲಿ_generate_ಕೀಲಿ(ಕೀಲಿ) != 1) {
		skdebug(__func__, "EC_KEY_generate_key");
		ಗಚ್ಛ out;
	}
	EC_ಕೀಲಿ_set_asn1_flag(ಕೀಲಿ, OPENSSL_EC_NAMED_CURVE);
	ಯದಿ ((bio = BIO_new(BIO_s_mem())) == ರಿಕ್ತ ||
	    (g = EC_ಕೀಲಿ_get0_group(ಕೀಲಿ)) == ರಿಕ್ತ ||
	    (q = EC_ಕೀಲಿ_get0_public_ಕೀಲಿ(ಕೀಲಿ)) == ರಿಕ್ತ) {
		skdebug(__func__, "couldn't get key parameters");
		ಗಚ್ಛ out;
	}
	response->public_ಕೀಲಿ_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, ರಿಕ್ತ, 0, ರಿಕ್ತ);
	ಯದಿ (response->public_ಕೀಲಿ_len == 0 || response->public_ಕೀಲಿ_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_ಕೀಲಿ_len);
		ಗಚ್ಛ out;
	}
	ಯದಿ ((response->public_ಕೀಲಿ = malloc(response->public_ಕೀಲಿ_len)) == ರಿಕ್ತ) {
		skdebug(__func__, "malloc pubkey failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_ಕೀಲಿ, response->public_ಕೀಲಿ_len, ರಿಕ್ತ) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		ಗಚ್ಛ out;
	}
	/* Key handle contains PEM encoded private key */
	ಯದಿ (!PEM_write_bio_ECPrivate_ಕೀಲಿ(bio, ಕೀಲಿ, ರಿಕ್ತ, ರಿಕ್ತ, 0, ರಿಕ್ತ, ರಿಕ್ತ)) {
		skdebug(__func__, "PEM_write_bio_ECPrivateKey failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((privlen = BIO_get_mem_data(bio, &privptr)) <= 0) {
		skdebug(__func__, "BIO_get_mem_data failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((response->ಕೀಲಿ_handle = malloc(privlen)) == ರಿಕ್ತ) {
		skdebug(__func__, "malloc key_handle failed");
		ಗಚ್ಛ out;
	}
	response->ಕೀಲಿ_handle_len = (size_t)privlen;
	memcpy(response->ಕೀಲಿ_handle, privptr, response->ಕೀಲಿ_handle_len);
	/* success */
	ret = 0;
 out:
	ಯದಿ (ret != 0) {
		ಯದಿ (response->public_ಕೀಲಿ != ರಿಕ್ತ) {
			memset(response->public_ಕೀಲಿ, 0,
			    response->public_ಕೀಲಿ_len);
			ಮುಕ್ತ(response->public_ಕೀಲಿ);
			response->public_ಕೀಲಿ = ರಿಕ್ತ;
		}
		ಯದಿ (response->ಕೀಲಿ_handle != ರಿಕ್ತ) {
			memset(response->ಕೀಲಿ_handle, 0,
			    response->ಕೀಲಿ_handle_len);
			ಮುಕ್ತ(response->ಕೀಲಿ_handle);
			response->ಕೀಲಿ_handle = ರಿಕ್ತ;
		}
	}
	BIO_free(bio);
	EC_ಕೀಲಿ_free(ಕೀಲಿ);
	ಪ್ರತ್ಯಾಗಮ ret;
#ಅನ್ಯಥಾ
	ಪ್ರತ್ಯಾಗಮ -1;
#endif
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pack_ಕೀಲಿ_ed25519(ಸಂರಚನಾ sk_enroll_response *response)
{
	ಪೂರ್ಣಾಙ್ಕ ret = -1;
	u_char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	u_char sk[crypto_sign_ed25519_SECRETKEYBYTES];

	response->public_ಕೀಲಿ = ರಿಕ್ತ;
	response->public_ಕೀಲಿ_len = 0;
	response->ಕೀಲಿ_handle = ರಿಕ್ತ;
	response->ಕೀಲಿ_handle_len = 0;

	memset(pk, 0, ಪರಿಮಾಣ(pk));
	memset(sk, 0, ಪರಿಮಾಣ(sk));
	crypto_sign_ed25519_keypair(pk, sk);

	response->public_ಕೀಲಿ_len = ಪರಿಮಾಣ(pk);
	ಯದಿ ((response->public_ಕೀಲಿ = malloc(response->public_ಕೀಲಿ_len)) == ರಿಕ್ತ) {
		skdebug(__func__, "malloc pubkey failed");
		ಗಚ್ಛ out;
	}
	memcpy(response->public_ಕೀಲಿ, pk, ಪರಿಮಾಣ(pk));
	/* Key handle contains sk */
	response->ಕೀಲಿ_handle_len = ಪರಿಮಾಣ(sk);
	ಯದಿ ((response->ಕೀಲಿ_handle = malloc(response->ಕೀಲಿ_handle_len)) == ರಿಕ್ತ) {
		skdebug(__func__, "malloc key_handle failed");
		ಗಚ್ಛ out;
	}
	memcpy(response->ಕೀಲಿ_handle, sk, ಪರಿಮಾಣ(sk));
	/* success */
	ret = 0;
 out:
	ಯದಿ (ret != 0)
		ಮುಕ್ತ(response->public_ಕೀಲಿ);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
check_options(ಸಂರಚನಾ sk_option **options)
{
	size_t i;

	ಯದಿ (options == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತಿ (i = 0; options[i] != ರಿಕ್ತ; i++) {
		skdebug(__func__, "requested unsupported option %s",
		    options[i]->name);
		ಯದಿ (options[i]->required) {
			skdebug(__func__, "unknown required option");
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sk_enroll(uint32_t alg, ಧ್ರುವ uint8_t *challenge, size_t challenge_len,
    ಧ್ರುವ ವರ್ಣ *application, uint8_t flags, ಧ್ರುವ ವರ್ಣ *pin,
    ಸಂರಚನಾ sk_option **options, ಸಂರಚನಾ sk_enroll_response **enroll_response)
{
	ಸಂರಚನಾ sk_enroll_response *response = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ ret = SSH_SK_ERR_GENERAL;

	(ಶೂನ್ಯ)flags; /* XXX; unused */

	ಯದಿ (enroll_response == ರಿಕ್ತ) {
		skdebug(__func__, "enroll_response == NULL");
		ಗಚ್ಛ out;
	}
	*enroll_response = ರಿಕ್ತ;
	ಯದಿ (check_options(options) != 0)
		ಗಚ್ಛ out; /* error already logged */
	ಯದಿ ((response = calloc(1, ಪರಿಮಾಣ(*response))) == ರಿಕ್ತ) {
		skdebug(__func__, "calloc response failed");
		ಗಚ್ಛ out;
	}
	response->flags = flags;
	ವಿಕಲ್ಪ(alg) {
	ಪಕ್ಷ SSH_SK_ECDSA:
		ಯದಿ (pack_ಕೀಲಿ_ecdsa(response) != 0)
			ಗಚ್ಛ out;
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH_SK_ED25519:
		ಯದಿ (pack_ಕೀಲಿ_ed25519(response) != 0)
			ಗಚ್ಛ out;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		skdebug(__func__, "unsupported key type %d", alg);
		ಗಚ್ಛ out;
	}
	/* Have to return something here */
	ಯದಿ ((response->signature = calloc(1, 1)) == ರಿಕ್ತ) {
		skdebug(__func__, "calloc signature failed");
		ಗಚ್ಛ out;
	}
	response->signature_len = 0;

	*enroll_response = response;
	response = ರಿಕ್ತ;
	ret = 0;
 out:
	ಯದಿ (response != ರಿಕ್ತ) {
		ಮುಕ್ತ(response->public_ಕೀಲಿ);
		ಮುಕ್ತ(response->ಕೀಲಿ_handle);
		ಮುಕ್ತ(response->signature);
		ಮುಕ್ತ(response->attestation_cert);
		ಮುಕ್ತ(response);
	}
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump(ಧ್ರುವ ವರ್ಣ *preamble, ಧ್ರುವ ಶೂನ್ಯ *sv, size_t l)
{
#ifdef SK_DEBUG
	ಧ್ರುವ u_char *s = (ಧ್ರುವ u_char *)sv;
	size_t i;

	fprintf(stderr, "%s (len %zu):\n", preamble, l);
	ಪ್ರತಿ (i = 0; i < l; i++) {
		ಯದಿ (i % 16 == 0)
			fprintf(stderr, "%04zu: ", i);
		fprintf(stderr, "%02x", s[i]);
		ಯದಿ (i % 16 == 15 || i == l - 1)
			fprintf(stderr, "\n");
	}
#endif
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sig_ecdsa(ಧ್ರುವ uint8_t *message, size_t message_len,
    ಧ್ರುವ ವರ್ಣ *application, uint32_t counter, uint8_t flags,
    ಧ್ರುವ uint8_t *ಕೀಲಿ_handle, size_t ಕೀಲಿ_handle_len,
    ಸಂರಚನಾ sk_sign_response *response)
{
#ifdef WITH_OPENSSL
	ECDSA_SIG *sig = ರಿಕ್ತ;
	ಧ್ರುವ BIGNUM *sig_r, *sig_s;
	ಪೂರ್ಣಾಙ್ಕ ret = -1;
	BIO *bio = ರಿಕ್ತ;
	EVP_PKEY *pk = ರಿಕ್ತ;
	EC_ಕೀಲಿ *ec = ರಿಕ್ತ;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_LENGTH];
	uint8_t	sighash[SHA256_DIGEST_LENGTH];
	uint8_t countbuf[4];

	/* Decode EC_KEY from key handle */
	ಯದಿ ((bio = BIO_new(BIO_s_mem())) == ರಿಕ್ತ ||
	    BIO_write(bio, ಕೀಲಿ_handle, ಕೀಲಿ_handle_len) != (ಪೂರ್ಣಾಙ್ಕ)ಕೀಲಿ_handle_len) {
		skdebug(__func__, "BIO setup failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((pk = PEM_read_bio_Private_ಕೀಲಿ(bio, ರಿಕ್ತ, ರಿಕ್ತ, "")) == ರಿಕ್ತ) {
		skdebug(__func__, "PEM_read_bio_PrivateKey failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ (EVP_PKEY_base_id(pk) != EVP_PKEY_EC) {
		skdebug(__func__, "Not an EC key: %d", EVP_PKEY_base_id(pk));
		ಗಚ್ಛ out;
	}
	ಯದಿ ((ec = EVP_PKEY_get1_EC_ಕೀಲಿ(pk)) == ರಿಕ್ತ) {
		skdebug(__func__, "EVP_PKEY_get1_EC_KEY failed");
		ಗಚ್ಛ out;
	}
	/* Expect message to be pre-hashed */
	ಯದಿ (message_len != SHA256_DIGEST_LENGTH) {
		skdebug(__func__, "bad message len %zu", message_len);
		ಗಚ್ಛ out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ಧ್ರುವ u_char *)application, strlen(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, ಪರಿಮಾಣ(apphash));
	countbuf[0] = (counter >> 24) & 0xff;
	countbuf[1] = (counter >> 16) & 0xff;
	countbuf[2] = (counter >> 8) & 0xff;
	countbuf[3] = counter & 0xff;
	dump("countbuf", countbuf, ಪರಿಮಾಣ(countbuf));
	dump("flags", &flags, ಪರಿಮಾಣ(flags));
	SHA256Init(&ctx);
	SHA256Update(&ctx, apphash, ಪರಿಮಾಣ(apphash));
	SHA256Update(&ctx, &flags, ಪರಿಮಾಣ(flags));
	SHA256Update(&ctx, countbuf, ಪರಿಮಾಣ(countbuf));
	SHA256Update(&ctx, message, message_len);
	SHA256Final(sighash, &ctx);
	dump("sighash", sighash, ಪರಿಮಾಣ(sighash));
	/* create and encode signature */
	ಯದಿ ((sig = ECDSA_do_sign(sighash, ಪರಿಮಾಣ(sighash), ec)) == ರಿಕ್ತ) {
		skdebug(__func__, "ECDSA_do_sign failed");
		ಗಚ್ಛ out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_ಅಂಕೆ_bytes(sig_r);
	response->sig_s_len = BN_ಅಂಕೆ_bytes(sig_s);
	ಯದಿ ((response->sig_r = calloc(1, response->sig_r_len)) == ರಿಕ್ತ ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == ರಿಕ್ತ) {
		skdebug(__func__, "calloc signature failed");
		ಗಚ್ಛ out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	explicit_bzero(&ctx, ಪರಿಮಾಣ(ctx));
	explicit_bzero(&apphash, ಪರಿಮಾಣ(apphash));
	explicit_bzero(&sighash, ಪರಿಮಾಣ(sighash));
	ECDSA_SIG_free(sig);
	ಯದಿ (ret != 0) {
		ಮುಕ್ತ(response->sig_r);
		ಮುಕ್ತ(response->sig_s);
		response->sig_r = ರಿಕ್ತ;
		response->sig_s = ರಿಕ್ತ;
	}
	BIO_free(bio);
	EC_ಕೀಲಿ_free(ec);
	EVP_PKEY_free(pk);
	ಪ್ರತ್ಯಾಗಮ ret;
#ಅನ್ಯಥಾ
	ಪ್ರತ್ಯಾಗಮ -1;
#endif
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sig_ed25519(ಧ್ರುವ uint8_t *message, size_t message_len,
    ಧ್ರುವ ವರ್ಣ *application, uint32_t counter, uint8_t flags,
    ಧ್ರುವ uint8_t *ಕೀಲಿ_handle, size_t ಕೀಲಿ_handle_len,
    ಸಂರಚನಾ sk_sign_response *response)
{
	size_t o;
	ಪೂರ್ಣಾಙ್ಕ ret = -1;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_LENGTH];
	uint8_t signbuf[ಪರಿಮಾಣ(apphash) + ಪರಿಮಾಣ(flags) +
	    ಪರಿಮಾಣ(counter) + SHA256_DIGEST_LENGTH];
	uint8_t sig[crypto_sign_ed25519_BYTES];
	unsigned long long siglen = 0;

	ಯದಿ (ಕೀಲಿ_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		skdebug(__func__, "bad key handle length %zu", ಕೀಲಿ_handle_len);
		ಗಚ್ಛ out;
	}
	/* Expect message to be pre-hashed */
	ಯದಿ (message_len != SHA256_DIGEST_LENGTH) {
		skdebug(__func__, "bad message len %zu", message_len);
		ಗಚ್ಛ out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ಧ್ರುವ u_char *)application, strlen(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, ಪರಿಮಾಣ(apphash));

	memcpy(signbuf, apphash, ಪರಿಮಾಣ(apphash));
	o = ಪರಿಮಾಣ(apphash);
	signbuf[o++] = flags;
	signbuf[o++] = (counter >> 24) & 0xff;
	signbuf[o++] = (counter >> 16) & 0xff;
	signbuf[o++] = (counter >> 8) & 0xff;
	signbuf[o++] = counter & 0xff;
	memcpy(signbuf + o, message, message_len);
	o += message_len;
	ಯದಿ (o != ಪರಿಮಾಣ(signbuf)) {
		skdebug(__func__, "bad sign buf len %zu, expected %zu",
		    o, ಪರಿಮಾಣ(signbuf));
		ಗಚ್ಛ out;
	}
	dump("signbuf", signbuf, ಪರಿಮಾಣ(signbuf));
	/* create and encode signature */
	ಯದಿ (crypto_sign_ed25519_detached(sig, &siglen, signbuf, ಪರಿಮಾಣ(signbuf),
	    ಕೀಲಿ_handle) != 0) {
		skdebug(__func__, "crypto_sign_ed25519_detached failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ (siglen != ಪರಿಮಾಣ(sig)) {
		skdebug(__func__, "bad signature length %llu", siglen);
		ಗಚ್ಛ out;
	}
	response->sig_r_len = ಪರಿಮಾಣ(sig);
	ಯದಿ ((response->sig_r = calloc(1, response->sig_r_len)) == ರಿಕ್ತ) {
		skdebug(__func__, "calloc signature failed");
		ಗಚ್ಛ out;
	}
	memcpy(response->sig_r, sig, response->sig_r_len);
	dump("sig_r", response->sig_r, response->sig_r_len);
	ret = 0;
 out:
	explicit_bzero(&ctx, ಪರಿಮಾಣ(ctx));
	explicit_bzero(&apphash, ಪರಿಮಾಣ(apphash));
	explicit_bzero(&signbuf, ಪರಿಮಾಣ(signbuf));
	explicit_bzero(&sig, ಪರಿಮಾಣ(sig));
	ಯದಿ (ret != 0) {
		ಮುಕ್ತ(response->sig_r);
		response->sig_r = ರಿಕ್ತ;
	}
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
sk_sign(uint32_t alg, ಧ್ರುವ uint8_t *data, size_t datalen,
    ಧ್ರುವ ವರ್ಣ *application, ಧ್ರುವ uint8_t *ಕೀಲಿ_handle, size_t ಕೀಲಿ_handle_len,
    uint8_t flags, ಧ್ರುವ ವರ್ಣ *pin, ಸಂರಚನಾ sk_option **options,
    ಸಂರಚನಾ sk_sign_response **sign_response)
{
	ಸಂರಚನಾ sk_sign_response *response = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ ret = SSH_SK_ERR_GENERAL;
	SHA2_CTX ctx;
	uint8_t message[32];

	ಯದಿ (sign_response == ರಿಕ್ತ) {
		skdebug(__func__, "sign_response == NULL");
		ಗಚ್ಛ out;
	}
	*sign_response = ರಿಕ್ತ;
	ಯದಿ (check_options(options) != 0)
		ಗಚ್ಛ out; /* error already logged */
	ಯದಿ ((response = calloc(1, ಪರಿಮಾಣ(*response))) == ರಿಕ್ತ) {
		skdebug(__func__, "calloc response failed");
		ಗಚ್ಛ out;
	}
	SHA256Init(&ctx);
	SHA256Update(&ctx, data, datalen);
	SHA256Final(message, &ctx);
	response->flags = flags;
	response->counter = 0x12345678;
	ವಿಕಲ್ಪ(alg) {
	ಪಕ್ಷ SSH_SK_ECDSA:
		ಯದಿ (sig_ecdsa(message, ಪರಿಮಾಣ(message), application,
		    response->counter, flags, ಕೀಲಿ_handle, ಕೀಲಿ_handle_len,
		    response) != 0)
			ಗಚ್ಛ out;
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH_SK_ED25519:
		ಯದಿ (sig_ed25519(message, ಪರಿಮಾಣ(message), application,
		    response->counter, flags, ಕೀಲಿ_handle, ಕೀಲಿ_handle_len,
		    response) != 0)
			ಗಚ್ಛ out;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		skdebug(__func__, "unsupported key type %d", alg);
		ಗಚ್ಛ out;
	}
	*sign_response = response;
	response = ರಿಕ್ತ;
	ret = 0;
 out:
	explicit_bzero(message, ಪರಿಮಾಣ(message));
	ಯದಿ (response != ರಿಕ್ತ) {
		ಮುಕ್ತ(response->sig_r);
		ಮುಕ್ತ(response->sig_s);
		ಮುಕ್ತ(response);
	}
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
sk_load_resident_ಕೀಲಿಗಳು(ಧ್ರುವ ವರ್ಣ *pin, ಸಂರಚನಾ sk_option **options,
    ಸಂರಚನಾ sk_resident_ಕೀಲಿ ***rks, size_t *nrks)
{
	ಪ್ರತ್ಯಾಗಮ SSH_SK_ERR_UNSUPPORTED;
}
