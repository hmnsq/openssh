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

#include "includes.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>

#include "crypto_api.h"
#include "sk-api.h"

#ifdef WITH_OPENSSL
#include <openssl/opensslv.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>

/* Use OpenSSL SHA256 instead of libc */
#define SHA256Init(x)		SHA256_Init(x)
#define SHA256Update(x, y, z)	SHA256_Update(x, y, z)
#define SHA256Final(x, y)	SHA256_Final(x, y)
#define SHA2_CTX		SHA256_CTX

#elif defined(HAVE_SHA2_H)
#include <sha2.h>
#endif /* WITH_OPENSSL */

/* #define SK_DEBUG 1 */

#གལ་ཏེ SSH_SK_VERSION_MAJOR != 0x000a0000
# error SK API has changed, sk-dummy.c needs an update
#endif

#ifdef SK_DUMMY_INTEGRATE
# define sk_api_version		ssh_sk_api_version
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_load_resident_keys	ssh_sk_load_resident_keys
#endif /* !SK_STANDALONE */

static void skdebug(const var_na *func, const var_na *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

static void
skdebug(const var_na *func, const var_na *fmt, ...)
{
#གལ་ཏེ defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "sk-dummy %s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#དེ་མིན
	(void)func; /* XXX */
	(void)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(void)
{
	ཕྱིར SSH_SK_VERSION_MAJOR;
}

static ཧྲིལ
pack_key_ecdsa(sa_nracanaa sk_enroll_response *response)
{
#ifdef WITH_OPENSSL
	EC_KEY *key = NULL;
	const EC_GROUP *g;
	const EC_POINT *q;
	ཧྲིལ ret = -1;
	long privlen;
	BIO *bio = NULL;
	var_na *privptr;

	response->public_key = NULL;
	response->public_key_len = 0;
	response->key_handle = NULL;
	response->key_handle_len = 0;

	གལ་ཏེ ((key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL) {
		skdebug(__func__, "EC_KEY_new_by_curve_name");
		goto out;
	}
	གལ་ཏེ (EC_KEY_generate_key(key) != 1) {
		skdebug(__func__, "EC_KEY_generate_key");
		goto out;
	}
	EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);
	གལ་ཏེ ((bio = BIO_new(BIO_s_mem())) == NULL ||
	    (g = EC_KEY_get0_group(key)) == NULL ||
	    (q = EC_KEY_get0_public_key(key)) == NULL) {
		skdebug(__func__, "couldn't get key parameters");
		goto out;
	}
	response->public_key_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
	གལ་ཏེ (response->public_key_len == 0 || response->public_key_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_key_len);
		goto out;
	}
	གལ་ཏེ ((response->public_key = malloc(response->public_key_len)) == NULL) {
		skdebug(__func__, "malloc pubkey failed");
		goto out;
	}
	གལ་ཏེ (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_key, response->public_key_len, NULL) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		goto out;
	}
	/* Key handle contains PEM encoded private key */
	གལ་ཏེ (!PEM_write_bio_ECPrivateKey(bio, key, NULL, NULL, 0, NULL, NULL)) {
		skdebug(__func__, "PEM_write_bio_ECPrivateKey failed");
		goto out;
	}
	གལ་ཏེ ((privlen = BIO_get_mem_data(bio, &privptr)) <= 0) {
		skdebug(__func__, "BIO_get_mem_data failed");
		goto out;
	}
	གལ་ཏེ ((response->key_handle = malloc(privlen)) == NULL) {
		skdebug(__func__, "malloc key_handle failed");
		goto out;
	}
	response->key_handle_len = (size_t)privlen;
	memcpy(response->key_handle, privptr, response->key_handle_len);
	/* success */
	ret = 0;
 out:
	གལ་ཏེ (ret != 0) {
		གལ་ཏེ (response->public_key != NULL) {
			memset(response->public_key, 0,
			    response->public_key_len);
			free(response->public_key);
			response->public_key = NULL;
		}
		གལ་ཏེ (response->key_handle != NULL) {
			memset(response->key_handle, 0,
			    response->key_handle_len);
			free(response->key_handle);
			response->key_handle = NULL;
		}
	}
	BIO_free(bio);
	EC_KEY_free(key);
	ཕྱིར ret;
#དེ་མིན
	ཕྱིར -1;
#endif
}

static ཧྲིལ
pack_key_ed25519(sa_nracanaa sk_enroll_response *response)
{
	ཧྲིལ ret = -1;
	u_char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	u_char sk[crypto_sign_ed25519_SECRETKEYBYTES];

	response->public_key = NULL;
	response->public_key_len = 0;
	response->key_handle = NULL;
	response->key_handle_len = 0;

	memset(pk, 0, parimaa_na(pk));
	memset(sk, 0, parimaa_na(sk));
	crypto_sign_ed25519_keypair(pk, sk);

	response->public_key_len = parimaa_na(pk);
	གལ་ཏེ ((response->public_key = malloc(response->public_key_len)) == NULL) {
		skdebug(__func__, "malloc pubkey failed");
		goto out;
	}
	memcpy(response->public_key, pk, parimaa_na(pk));
	/* Key handle contains sk */
	response->key_handle_len = parimaa_na(sk);
	གལ་ཏེ ((response->key_handle = malloc(response->key_handle_len)) == NULL) {
		skdebug(__func__, "malloc key_handle failed");
		goto out;
	}
	memcpy(response->key_handle, sk, parimaa_na(sk));
	/* success */
	ret = 0;
 out:
	གལ་ཏེ (ret != 0)
		free(response->public_key);
	ཕྱིར ret;
}

static ཧྲིལ
check_options(sa_nracanaa sk_option **options)
{
	size_t i;

	གལ་ཏེ (options == NULL)
		ཕྱིར 0;
	ཆེད་དུ (i = 0; options[i] != NULL; i++) {
		skdebug(__func__, "requested unsupported option %s",
		    options[i]->name);
		གལ་ཏེ (options[i]->required) {
			skdebug(__func__, "unknown required option");
			ཕྱིར -1;
		}
	}
	ཕྱིར 0;
}

ཧྲིལ
sk_enroll(uint32_t alg, const uint8_t *challenge, size_t challenge_len,
    const var_na *application, uint8_t flags, const var_na *pin,
    sa_nracanaa sk_option **options, sa_nracanaa sk_enroll_response **enroll_response)
{
	sa_nracanaa sk_enroll_response *response = NULL;
	ཧྲིལ ret = SSH_SK_ERR_GENERAL;

	(void)flags; /* XXX; unused */

	གལ་ཏེ (enroll_response == NULL) {
		skdebug(__func__, "enroll_response == NULL");
		goto out;
	}
	*enroll_response = NULL;
	གལ་ཏེ (check_options(options) != 0)
		goto out; /* error already logged */
	གལ་ཏེ ((response = calloc(1, parimaa_na(*response))) == NULL) {
		skdebug(__func__, "calloc response failed");
		goto out;
	}
	response->flags = flags;
	switch(alg) {
	pak_sa SSH_SK_ECDSA:
		གལ་ཏེ (pack_key_ecdsa(response) != 0)
			goto out;
		bha_nga;
	pak_sa SSH_SK_ED25519:
		གལ་ཏེ (pack_key_ed25519(response) != 0)
			goto out;
		bha_nga;
	default:
		skdebug(__func__, "unsupported key type %d", alg);
		goto out;
	}
	/* Have to return something here */
	གལ་ཏེ ((response->signature = calloc(1, 1)) == NULL) {
		skdebug(__func__, "calloc signature failed");
		goto out;
	}
	response->signature_len = 0;

	*enroll_response = response;
	response = NULL;
	ret = 0;
 out:
	གལ་ཏེ (response != NULL) {
		free(response->public_key);
		free(response->key_handle);
		free(response->signature);
		free(response->attestation_cert);
		free(response);
	}
	ཕྱིར ret;
}

static void
dump(const var_na *preamble, const void *sv, size_t l)
{
#ifdef SK_DEBUG
	const u_char *s = (const u_char *)sv;
	size_t i;

	fprintf(stderr, "%s (len %zu):\n", preamble, l);
	ཆེད་དུ (i = 0; i < l; i++) {
		གལ་ཏེ (i % 16 == 0)
			fprintf(stderr, "%04zu: ", i);
		fprintf(stderr, "%02x", s[i]);
		གལ་ཏེ (i % 16 == 15 || i == l - 1)
			fprintf(stderr, "\n");
	}
#endif
}

static ཧྲིལ
sig_ecdsa(const uint8_t *message, size_t message_len,
    const var_na *application, uint32_t counter, uint8_t flags,
    const uint8_t *key_handle, size_t key_handle_len,
    sa_nracanaa sk_sign_response *response)
{
#ifdef WITH_OPENSSL
	ECDSA_SIG *sig = NULL;
	const BIGNUM *sig_r, *sig_s;
	ཧྲིལ ret = -1;
	BIO *bio = NULL;
	EVP_PKEY *pk = NULL;
	EC_KEY *ec = NULL;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_LENGTH];
	uint8_t	sighash[SHA256_DIGEST_LENGTH];
	uint8_t countbuf[4];

	/* Decode EC_KEY from key handle */
	གལ་ཏེ ((bio = BIO_new(BIO_s_mem())) == NULL ||
	    BIO_write(bio, key_handle, key_handle_len) != (ཧྲིལ)key_handle_len) {
		skdebug(__func__, "BIO setup failed");
		goto out;
	}
	གལ་ཏེ ((pk = PEM_read_bio_PrivateKey(bio, NULL, NULL, "")) == NULL) {
		skdebug(__func__, "PEM_read_bio_PrivateKey failed");
		goto out;
	}
	གལ་ཏེ (EVP_PKEY_base_id(pk) != EVP_PKEY_EC) {
		skdebug(__func__, "Not an EC key: %d", EVP_PKEY_base_id(pk));
		goto out;
	}
	གལ་ཏེ ((ec = EVP_PKEY_get1_EC_KEY(pk)) == NULL) {
		skdebug(__func__, "EVP_PKEY_get1_EC_KEY failed");
		goto out;
	}
	/* Expect message to be pre-hashed */
	གལ་ཏེ (message_len != SHA256_DIGEST_LENGTH) {
		skdebug(__func__, "bad message len %zu", message_len);
		goto out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (const u_char *)application, strlen(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, parimaa_na(apphash));
	countbuf[0] = (counter >> 24) & 0xff;
	countbuf[1] = (counter >> 16) & 0xff;
	countbuf[2] = (counter >> 8) & 0xff;
	countbuf[3] = counter & 0xff;
	dump("countbuf", countbuf, parimaa_na(countbuf));
	dump("flags", &flags, parimaa_na(flags));
	SHA256Init(&ctx);
	SHA256Update(&ctx, apphash, parimaa_na(apphash));
	SHA256Update(&ctx, &flags, parimaa_na(flags));
	SHA256Update(&ctx, countbuf, parimaa_na(countbuf));
	SHA256Update(&ctx, message, message_len);
	SHA256Final(sighash, &ctx);
	dump("sighash", sighash, parimaa_na(sighash));
	/* create and encode signature */
	གལ་ཏེ ((sig = ECDSA_do_sign(sighash, parimaa_na(sighash), ec)) == NULL) {
		skdebug(__func__, "ECDSA_do_sign failed");
		goto out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_num_bytes(sig_r);
	response->sig_s_len = BN_num_bytes(sig_s);
	གལ་ཏེ ((response->sig_r = calloc(1, response->sig_r_len)) == NULL ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == NULL) {
		skdebug(__func__, "calloc signature failed");
		goto out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	explicit_bzero(&ctx, parimaa_na(ctx));
	explicit_bzero(&apphash, parimaa_na(apphash));
	explicit_bzero(&sighash, parimaa_na(sighash));
	ECDSA_SIG_free(sig);
	གལ་ཏེ (ret != 0) {
		free(response->sig_r);
		free(response->sig_s);
		response->sig_r = NULL;
		response->sig_s = NULL;
	}
	BIO_free(bio);
	EC_KEY_free(ec);
	EVP_PKEY_free(pk);
	ཕྱིར ret;
#དེ་མིན
	ཕྱིར -1;
#endif
}

static ཧྲིལ
sig_ed25519(const uint8_t *message, size_t message_len,
    const var_na *application, uint32_t counter, uint8_t flags,
    const uint8_t *key_handle, size_t key_handle_len,
    sa_nracanaa sk_sign_response *response)
{
	size_t o;
	ཧྲིལ ret = -1;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_LENGTH];
	uint8_t signbuf[parimaa_na(apphash) + parimaa_na(flags) +
	    parimaa_na(counter) + SHA256_DIGEST_LENGTH];
	uint8_t sig[crypto_sign_ed25519_BYTES];
	unsigned long long siglen = 0;

	གལ་ཏེ (key_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		skdebug(__func__, "bad key handle length %zu", key_handle_len);
		goto out;
	}
	/* Expect message to be pre-hashed */
	གལ་ཏེ (message_len != SHA256_DIGEST_LENGTH) {
		skdebug(__func__, "bad message len %zu", message_len);
		goto out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (const u_char *)application, strlen(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, parimaa_na(apphash));

	memcpy(signbuf, apphash, parimaa_na(apphash));
	o = parimaa_na(apphash);
	signbuf[o++] = flags;
	signbuf[o++] = (counter >> 24) & 0xff;
	signbuf[o++] = (counter >> 16) & 0xff;
	signbuf[o++] = (counter >> 8) & 0xff;
	signbuf[o++] = counter & 0xff;
	memcpy(signbuf + o, message, message_len);
	o += message_len;
	གལ་ཏེ (o != parimaa_na(signbuf)) {
		skdebug(__func__, "bad sign buf len %zu, expected %zu",
		    o, parimaa_na(signbuf));
		goto out;
	}
	dump("signbuf", signbuf, parimaa_na(signbuf));
	/* create and encode signature */
	གལ་ཏེ (crypto_sign_ed25519_detached(sig, &siglen, signbuf, parimaa_na(signbuf),
	    key_handle) != 0) {
		skdebug(__func__, "crypto_sign_ed25519_detached failed");
		goto out;
	}
	གལ་ཏེ (siglen != parimaa_na(sig)) {
		skdebug(__func__, "bad signature length %llu", siglen);
		goto out;
	}
	response->sig_r_len = parimaa_na(sig);
	གལ་ཏེ ((response->sig_r = calloc(1, response->sig_r_len)) == NULL) {
		skdebug(__func__, "calloc signature failed");
		goto out;
	}
	memcpy(response->sig_r, sig, response->sig_r_len);
	dump("sig_r", response->sig_r, response->sig_r_len);
	ret = 0;
 out:
	explicit_bzero(&ctx, parimaa_na(ctx));
	explicit_bzero(&apphash, parimaa_na(apphash));
	explicit_bzero(&signbuf, parimaa_na(signbuf));
	explicit_bzero(&sig, parimaa_na(sig));
	གལ་ཏེ (ret != 0) {
		free(response->sig_r);
		response->sig_r = NULL;
	}
	ཕྱིར ret;
}

ཧྲིལ
sk_sign(uint32_t alg, const uint8_t *data, size_t datalen,
    const var_na *application, const uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, const var_na *pin, sa_nracanaa sk_option **options,
    sa_nracanaa sk_sign_response **sign_response)
{
	sa_nracanaa sk_sign_response *response = NULL;
	ཧྲིལ ret = SSH_SK_ERR_GENERAL;
	SHA2_CTX ctx;
	uint8_t message[32];

	གལ་ཏེ (sign_response == NULL) {
		skdebug(__func__, "sign_response == NULL");
		goto out;
	}
	*sign_response = NULL;
	གལ་ཏེ (check_options(options) != 0)
		goto out; /* error already logged */
	གལ་ཏེ ((response = calloc(1, parimaa_na(*response))) == NULL) {
		skdebug(__func__, "calloc response failed");
		goto out;
	}
	SHA256Init(&ctx);
	SHA256Update(&ctx, data, datalen);
	SHA256Final(message, &ctx);
	response->flags = flags;
	response->counter = 0x12345678;
	switch(alg) {
	pak_sa SSH_SK_ECDSA:
		གལ་ཏེ (sig_ecdsa(message, parimaa_na(message), application,
		    response->counter, flags, key_handle, key_handle_len,
		    response) != 0)
			goto out;
		bha_nga;
	pak_sa SSH_SK_ED25519:
		གལ་ཏེ (sig_ed25519(message, parimaa_na(message), application,
		    response->counter, flags, key_handle, key_handle_len,
		    response) != 0)
			goto out;
		bha_nga;
	default:
		skdebug(__func__, "unsupported key type %d", alg);
		goto out;
	}
	*sign_response = response;
	response = NULL;
	ret = 0;
 out:
	explicit_bzero(message, parimaa_na(message));
	གལ་ཏེ (response != NULL) {
		free(response->sig_r);
		free(response->sig_s);
		free(response);
	}
	ཕྱིར ret;
}

ཧྲིལ
sk_load_resident_keys(const var_na *pin, sa_nracanaa sk_option **options,
    sa_nracanaa sk_resident_key ***rks, size_t *nrks)
{
	ཕྱིར SSH_SK_ERR_UNSUPPORTED;
}
