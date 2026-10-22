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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <stdarg.h>

#அந்தர்பாவ "crypto_api.h"
#அந்தர்பாவ "sk-api.h"

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/opensslv.h>
#அந்தர்பாவ <openssl/sha.h>
#அந்தர்பாவ <openssl/crypto.h>
#அந்தர்பாவ <openssl/evp.h>
#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/ec.h>
#அந்தர்பாவ <openssl/ecdsa.h>
#அந்தர்பாவ <openssl/pem.h>

/* Use OpenSSL SHA256 instead of libc */
#define SHA256Init(x)		SHA256_Init(x)
#define SHA256Update(x, y, z)	SHA256_Update(x, y, z)
#define SHA256Final(x, y)	SHA256_Final(x, y)
#define SHA2_CTX		SHA256_CTX

#அல்லதெனில் defined(HAVE_SHA2_H)
#அந்தர்பாவ <sha2.h>
#endif /* WITH_OPENSSL */

/* #define SK_DEBUG 1 */

#எனில் SSH_SK_VERSION_MAJOR != 0x000a0000
# error SK API has changed, sk-dummy.c needs an update
#endif

#ifdef SK_DUMMY_INTEGRATE
# define sk_api_version		ssh_sk_api_version
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_load_resident_சாவிகள்	ssh_sk_load_resident_சாவிகள்
#endif /* !SK_STANDALONE */

நிலையான வெறுமை skdebug(மாறிலி எழுத்து *func, மாறிலி எழுத்து *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

நிலையான வெறுமை
skdebug(மாறிலி எழுத்து *func, மாறிலி எழுத்து *fmt, ...)
{
#எனில் defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "sk-dummy %s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#இல்லையெனில்
	(வெறுமை)func; /* XXX */
	(வெறுமை)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(வெறுமை)
{
	திரும்பு SSH_SK_VERSION_MAJOR;
}

நிலையான முழு
pack_சாவி_ecdsa(கட்டமைப்பு sk_enroll_response *response)
{
#ifdef WITH_OPENSSL
	EC_சாவி *சாவி = வெற்று;
	மாறிலி EC_GROUP *g;
	மாறிலி EC_POINT *q;
	முழு ret = -1;
	long privlen;
	BIO *bio = வெற்று;
	எழுத்து *privptr;

	response->public_சாவி = வெற்று;
	response->public_சாவி_len = 0;
	response->சாவி_handle = வெற்று;
	response->சாவி_handle_len = 0;

	எனில் ((சாவி = EC_சாவி_new_by_curve_name(NID_X9_62_prime256v1)) == வெற்று) {
		skdebug(__func__, "EC_KEY_new_by_curve_name");
		செல் out;
	}
	எனில் (EC_சாவி_generate_சாவி(சாவி) != 1) {
		skdebug(__func__, "EC_KEY_generate_key");
		செல் out;
	}
	EC_சாவி_set_asn1_flag(சாவி, OPENSSL_EC_NAMED_CURVE);
	எனில் ((bio = BIO_new(BIO_s_mem())) == வெற்று ||
	    (g = EC_சாவி_get0_group(சாவி)) == வெற்று ||
	    (q = EC_சாவி_get0_public_சாவி(சாவி)) == வெற்று) {
		skdebug(__func__, "couldn't get key parameters");
		செல் out;
	}
	response->public_சாவி_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, வெற்று, 0, வெற்று);
	எனில் (response->public_சாவி_len == 0 || response->public_சாவி_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_சாவி_len);
		செல் out;
	}
	எனில் ((response->public_சாவி = malloc(response->public_சாவி_len)) == வெற்று) {
		skdebug(__func__, "malloc pubkey failed");
		செல் out;
	}
	எனில் (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_சாவி, response->public_சாவி_len, வெற்று) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		செல் out;
	}
	/* Key handle contains PEM encoded private key */
	எனில் (!PEM_write_bio_ECPrivate_சாவி(bio, சாவி, வெற்று, வெற்று, 0, வெற்று, வெற்று)) {
		skdebug(__func__, "PEM_write_bio_ECPrivateKey failed");
		செல் out;
	}
	எனில் ((privlen = BIO_get_mem_data(bio, &privptr)) <= 0) {
		skdebug(__func__, "BIO_get_mem_data failed");
		செல் out;
	}
	எனில் ((response->சாவி_handle = malloc(privlen)) == வெற்று) {
		skdebug(__func__, "malloc key_handle failed");
		செல் out;
	}
	response->சாவி_handle_len = (size_t)privlen;
	memcpy(response->சாவி_handle, privptr, response->சாவி_handle_len);
	/* success */
	ret = 0;
 out:
	எனில் (ret != 0) {
		எனில் (response->public_சாவி != வெற்று) {
			memset(response->public_சாவி, 0,
			    response->public_சாவி_len);
			விடுவி(response->public_சாவி);
			response->public_சாவி = வெற்று;
		}
		எனில் (response->சாவி_handle != வெற்று) {
			memset(response->சாவி_handle, 0,
			    response->சாவி_handle_len);
			விடுவி(response->சாவி_handle);
			response->சாவி_handle = வெற்று;
		}
	}
	BIO_free(bio);
	EC_சாவி_free(சாவி);
	திரும்பு ret;
#இல்லையெனில்
	திரும்பு -1;
#endif
}

நிலையான முழு
pack_சாவி_ed25519(கட்டமைப்பு sk_enroll_response *response)
{
	முழு ret = -1;
	u_char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	u_char sk[crypto_sign_ed25519_SECRETKEYBYTES];

	response->public_சாவி = வெற்று;
	response->public_சாவி_len = 0;
	response->சாவி_handle = வெற்று;
	response->சாவி_handle_len = 0;

	memset(pk, 0, அளவு(pk));
	memset(sk, 0, அளவு(sk));
	crypto_sign_ed25519_keypair(pk, sk);

	response->public_சாவி_len = அளவு(pk);
	எனில் ((response->public_சாவி = malloc(response->public_சாவி_len)) == வெற்று) {
		skdebug(__func__, "malloc pubkey failed");
		செல் out;
	}
	memcpy(response->public_சாவி, pk, அளவு(pk));
	/* Key handle contains sk */
	response->சாவி_handle_len = அளவு(sk);
	எனில் ((response->சாவி_handle = malloc(response->சாவி_handle_len)) == வெற்று) {
		skdebug(__func__, "malloc key_handle failed");
		செல் out;
	}
	memcpy(response->சாவி_handle, sk, அளவு(sk));
	/* success */
	ret = 0;
 out:
	எனில் (ret != 0)
		விடுவி(response->public_சாவி);
	திரும்பு ret;
}

நிலையான முழு
check_options(கட்டமைப்பு sk_option **options)
{
	size_t i;

	எனில் (options == வெற்று)
		திரும்பு 0;
	க்கு (i = 0; options[i] != வெற்று; i++) {
		skdebug(__func__, "requested unsupported option %s",
		    options[i]->name);
		எனில் (options[i]->required) {
			skdebug(__func__, "unknown required option");
			திரும்பு -1;
		}
	}
	திரும்பு 0;
}

முழு
sk_enroll(uint32_t alg, மாறிலி uint8_t *challenge, size_t challenge_len,
    மாறிலி எழுத்து *application, uint8_t flags, மாறிலி எழுத்து *pin,
    கட்டமைப்பு sk_option **options, கட்டமைப்பு sk_enroll_response **enroll_response)
{
	கட்டமைப்பு sk_enroll_response *response = வெற்று;
	முழு ret = SSH_SK_ERR_GENERAL;

	(வெறுமை)flags; /* XXX; unused */

	எனில் (enroll_response == வெற்று) {
		skdebug(__func__, "enroll_response == NULL");
		செல் out;
	}
	*enroll_response = வெற்று;
	எனில் (check_options(options) != 0)
		செல் out; /* error already logged */
	எனில் ((response = calloc(1, அளவு(*response))) == வெற்று) {
		skdebug(__func__, "calloc response failed");
		செல் out;
	}
	response->flags = flags;
	தேர்வு(alg) {
	நிலை SSH_SK_ECDSA:
		எனில் (pack_சாவி_ecdsa(response) != 0)
			செல் out;
		நிறுத்து;
	நிலை SSH_SK_ED25519:
		எனில் (pack_சாவி_ed25519(response) != 0)
			செல் out;
		நிறுத்து;
	இயல்பு:
		skdebug(__func__, "unsupported key type %d", alg);
		செல் out;
	}
	/* Have to return something here */
	எனில் ((response->signature = calloc(1, 1)) == வெற்று) {
		skdebug(__func__, "calloc signature failed");
		செல் out;
	}
	response->signature_len = 0;

	*enroll_response = response;
	response = வெற்று;
	ret = 0;
 out:
	எனில் (response != வெற்று) {
		விடுவி(response->public_சாவி);
		விடுவி(response->சாவி_handle);
		விடுவி(response->signature);
		விடுவி(response->attestation_cert);
		விடுவி(response);
	}
	திரும்பு ret;
}

நிலையான வெறுமை
dump(மாறிலி எழுத்து *preamble, மாறிலி வெறுமை *sv, size_t l)
{
#ifdef SK_DEBUG
	மாறிலி u_char *s = (மாறிலி u_char *)sv;
	size_t i;

	fprintf(stderr, "%s (len %zu):\n", preamble, l);
	க்கு (i = 0; i < l; i++) {
		எனில் (i % 16 == 0)
			fprintf(stderr, "%04zu: ", i);
		fprintf(stderr, "%02x", s[i]);
		எனில் (i % 16 == 15 || i == l - 1)
			fprintf(stderr, "\n");
	}
#endif
}

நிலையான முழு
sig_ecdsa(மாறிலி uint8_t *message, size_t message_len,
    மாறிலி எழுத்து *application, uint32_t counter, uint8_t flags,
    மாறிலி uint8_t *சாவி_handle, size_t சாவி_handle_len,
    கட்டமைப்பு sk_sign_response *response)
{
#ifdef WITH_OPENSSL
	ECDSA_SIG *sig = வெற்று;
	மாறிலி BIGNUM *sig_r, *sig_s;
	முழு ret = -1;
	BIO *bio = வெற்று;
	EVP_PKEY *pk = வெற்று;
	EC_சாவி *ec = வெற்று;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_LENGTH];
	uint8_t	sighash[SHA256_DIGEST_LENGTH];
	uint8_t countbuf[4];

	/* Decode EC_KEY from key handle */
	எனில் ((bio = BIO_new(BIO_s_mem())) == வெற்று ||
	    BIO_write(bio, சாவி_handle, சாவி_handle_len) != (முழு)சாவி_handle_len) {
		skdebug(__func__, "BIO setup failed");
		செல் out;
	}
	எனில் ((pk = PEM_read_bio_Private_சாவி(bio, வெற்று, வெற்று, "")) == வெற்று) {
		skdebug(__func__, "PEM_read_bio_PrivateKey failed");
		செல் out;
	}
	எனில் (EVP_PKEY_base_id(pk) != EVP_PKEY_EC) {
		skdebug(__func__, "Not an EC key: %d", EVP_PKEY_base_id(pk));
		செல் out;
	}
	எனில் ((ec = EVP_PKEY_get1_EC_சாவி(pk)) == வெற்று) {
		skdebug(__func__, "EVP_PKEY_get1_EC_KEY failed");
		செல் out;
	}
	/* Expect message to be pre-hashed */
	எனில் (message_len != SHA256_DIGEST_LENGTH) {
		skdebug(__func__, "bad message len %zu", message_len);
		செல் out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (மாறிலி u_char *)application, strlen(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, அளவு(apphash));
	countbuf[0] = (counter >> 24) & 0xff;
	countbuf[1] = (counter >> 16) & 0xff;
	countbuf[2] = (counter >> 8) & 0xff;
	countbuf[3] = counter & 0xff;
	dump("countbuf", countbuf, அளவு(countbuf));
	dump("flags", &flags, அளவு(flags));
	SHA256Init(&ctx);
	SHA256Update(&ctx, apphash, அளவு(apphash));
	SHA256Update(&ctx, &flags, அளவு(flags));
	SHA256Update(&ctx, countbuf, அளவு(countbuf));
	SHA256Update(&ctx, message, message_len);
	SHA256Final(sighash, &ctx);
	dump("sighash", sighash, அளவு(sighash));
	/* create and encode signature */
	எனில் ((sig = ECDSA_do_sign(sighash, அளவு(sighash), ec)) == வெற்று) {
		skdebug(__func__, "ECDSA_do_sign failed");
		செல் out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_இலக்கம்_bytes(sig_r);
	response->sig_s_len = BN_இலக்கம்_bytes(sig_s);
	எனில் ((response->sig_r = calloc(1, response->sig_r_len)) == வெற்று ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == வெற்று) {
		skdebug(__func__, "calloc signature failed");
		செல் out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	explicit_bzero(&ctx, அளவு(ctx));
	explicit_bzero(&apphash, அளவு(apphash));
	explicit_bzero(&sighash, அளவு(sighash));
	ECDSA_SIG_free(sig);
	எனில் (ret != 0) {
		விடுவி(response->sig_r);
		விடுவி(response->sig_s);
		response->sig_r = வெற்று;
		response->sig_s = வெற்று;
	}
	BIO_free(bio);
	EC_சாவி_free(ec);
	EVP_PKEY_free(pk);
	திரும்பு ret;
#இல்லையெனில்
	திரும்பு -1;
#endif
}

நிலையான முழு
sig_ed25519(மாறிலி uint8_t *message, size_t message_len,
    மாறிலி எழுத்து *application, uint32_t counter, uint8_t flags,
    மாறிலி uint8_t *சாவி_handle, size_t சாவி_handle_len,
    கட்டமைப்பு sk_sign_response *response)
{
	size_t o;
	முழு ret = -1;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_LENGTH];
	uint8_t signbuf[அளவு(apphash) + அளவு(flags) +
	    அளவு(counter) + SHA256_DIGEST_LENGTH];
	uint8_t sig[crypto_sign_ed25519_BYTES];
	unsigned long long siglen = 0;

	எனில் (சாவி_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		skdebug(__func__, "bad key handle length %zu", சாவி_handle_len);
		செல் out;
	}
	/* Expect message to be pre-hashed */
	எனில் (message_len != SHA256_DIGEST_LENGTH) {
		skdebug(__func__, "bad message len %zu", message_len);
		செல் out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (மாறிலி u_char *)application, strlen(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, அளவு(apphash));

	memcpy(signbuf, apphash, அளவு(apphash));
	o = அளவு(apphash);
	signbuf[o++] = flags;
	signbuf[o++] = (counter >> 24) & 0xff;
	signbuf[o++] = (counter >> 16) & 0xff;
	signbuf[o++] = (counter >> 8) & 0xff;
	signbuf[o++] = counter & 0xff;
	memcpy(signbuf + o, message, message_len);
	o += message_len;
	எனில் (o != அளவு(signbuf)) {
		skdebug(__func__, "bad sign buf len %zu, expected %zu",
		    o, அளவு(signbuf));
		செல் out;
	}
	dump("signbuf", signbuf, அளவு(signbuf));
	/* create and encode signature */
	எனில் (crypto_sign_ed25519_detached(sig, &siglen, signbuf, அளவு(signbuf),
	    சாவி_handle) != 0) {
		skdebug(__func__, "crypto_sign_ed25519_detached failed");
		செல் out;
	}
	எனில் (siglen != அளவு(sig)) {
		skdebug(__func__, "bad signature length %llu", siglen);
		செல் out;
	}
	response->sig_r_len = அளவு(sig);
	எனில் ((response->sig_r = calloc(1, response->sig_r_len)) == வெற்று) {
		skdebug(__func__, "calloc signature failed");
		செல் out;
	}
	memcpy(response->sig_r, sig, response->sig_r_len);
	dump("sig_r", response->sig_r, response->sig_r_len);
	ret = 0;
 out:
	explicit_bzero(&ctx, அளவு(ctx));
	explicit_bzero(&apphash, அளவு(apphash));
	explicit_bzero(&signbuf, அளவு(signbuf));
	explicit_bzero(&sig, அளவு(sig));
	எனில் (ret != 0) {
		விடுவி(response->sig_r);
		response->sig_r = வெற்று;
	}
	திரும்பு ret;
}

முழு
sk_sign(uint32_t alg, மாறிலி uint8_t *data, size_t datalen,
    மாறிலி எழுத்து *application, மாறிலி uint8_t *சாவி_handle, size_t சாவி_handle_len,
    uint8_t flags, மாறிலி எழுத்து *pin, கட்டமைப்பு sk_option **options,
    கட்டமைப்பு sk_sign_response **sign_response)
{
	கட்டமைப்பு sk_sign_response *response = வெற்று;
	முழு ret = SSH_SK_ERR_GENERAL;
	SHA2_CTX ctx;
	uint8_t message[32];

	எனில் (sign_response == வெற்று) {
		skdebug(__func__, "sign_response == NULL");
		செல் out;
	}
	*sign_response = வெற்று;
	எனில் (check_options(options) != 0)
		செல் out; /* error already logged */
	எனில் ((response = calloc(1, அளவு(*response))) == வெற்று) {
		skdebug(__func__, "calloc response failed");
		செல் out;
	}
	SHA256Init(&ctx);
	SHA256Update(&ctx, data, datalen);
	SHA256Final(message, &ctx);
	response->flags = flags;
	response->counter = 0x12345678;
	தேர்வு(alg) {
	நிலை SSH_SK_ECDSA:
		எனில் (sig_ecdsa(message, அளவு(message), application,
		    response->counter, flags, சாவி_handle, சாவி_handle_len,
		    response) != 0)
			செல் out;
		நிறுத்து;
	நிலை SSH_SK_ED25519:
		எனில் (sig_ed25519(message, அளவு(message), application,
		    response->counter, flags, சாவி_handle, சாவி_handle_len,
		    response) != 0)
			செல் out;
		நிறுத்து;
	இயல்பு:
		skdebug(__func__, "unsupported key type %d", alg);
		செல் out;
	}
	*sign_response = response;
	response = வெற்று;
	ret = 0;
 out:
	explicit_bzero(message, அளவு(message));
	எனில் (response != வெற்று) {
		விடுவி(response->sig_r);
		விடுவி(response->sig_s);
		விடுவி(response);
	}
	திரும்பு ret;
}

முழு
sk_load_resident_சாவிகள்(மாறிலி எழுத்து *pin, கட்டமைப்பு sk_option **options,
    கட்டமைப்பு sk_resident_சாவி ***rks, size_t *nrks)
{
	திரும்பு SSH_SK_ERR_UNSUPPORTED;
}
