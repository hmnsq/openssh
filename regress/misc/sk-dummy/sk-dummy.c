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

#ضمن "includes.h"

#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <stdio.h>
#ضمن <stddef.h>
#ضمن <stdarg.h>

#ضمن "crypto_api.h"
#ضمن "sk-api.h"

#ifdef WITH_OPENSSL
#ضمن <openssl/opensslv.h>
#ضمن <openssl/sha.h>
#ضمن <openssl/crypto.h>
#ضمن <openssl/evp.h>
#ضمن <openssl/bn.h>
#ضمن <openssl/ec.h>
#ضمن <openssl/ecdsa.h>
#ضمن <openssl/pem.h>

/* Use OpenSSL SHA256 instead of libc */
#define SHA256Init(x)		SHA256_Init(x)
#define SHA256Update(x, y, z)	SHA256_Update(x, y, z)
#define SHA256Final(x, y)	SHA256_Final(x, y)
#define SHA2_CTX		SHA256_CTX

#وإلاإذا defined(HAVE_SHA2_H)
#ضمن <sha2.h>
#endif /* WITH_OPENSSL */

/* #define SK_DEBUG 1 */

#אם SSH_SK_VERSION_MAJOR != 0x000a0000
# error SK API has changed, sk-dummy.c needs an update
#endif

#ifdef SK_DUMMY_INTEGRATE
# define sk_api_version		ssh_sk_api_version
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_load_resident_keys	ssh_sk_load_resident_keys
#endif /* !SK_STANDALONE */

ساكن فراغ skdebug(ثابت حرف *func, ثابت حرف *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

ساكن فراغ
skdebug(ثابت حرف *func, ثابت حرف *fmt, ...)
{
#אם defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "sk-dummy %s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#אחרת
	(فراغ)func; /* XXX */
	(فراغ)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(فراغ)
{
	החזר SSH_SK_VERSION_MAJOR;
}

ساكن صحيح
pack_key_ecdsa(بنية sk_enroll_response *response)
{
#ifdef WITH_OPENSSL
	EC_KEY *key = عدم;
	ثابت EC_GROUP *g;
	ثابت EC_POINT *q;
	صحيح ret = -1;
	long privlen;
	BIO *bio = عدم;
	حرف *privptr;

	response->public_key = عدم;
	response->public_key_len = 0;
	response->key_handle = عدم;
	response->key_handle_len = 0;

	אם ((key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == عدم) {
		skdebug(__func__, "EC_KEY_new_by_curve_name");
		اذهب out;
	}
	אם (EC_KEY_generate_key(key) != 1) {
		skdebug(__func__, "EC_KEY_generate_key");
		اذهب out;
	}
	EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);
	אם ((bio = BIO_new(BIO_s_mem())) == عدم ||
	    (g = EC_KEY_get0_group(key)) == عدم ||
	    (q = EC_KEY_get0_public_key(key)) == عدم) {
		skdebug(__func__, "couldn't get key parameters");
		اذهب out;
	}
	response->public_key_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, عدم, 0, عدم);
	אם (response->public_key_len == 0 || response->public_key_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_key_len);
		اذهب out;
	}
	אם ((response->public_key = malloc(response->public_key_len)) == عدم) {
		skdebug(__func__, "malloc pubkey failed");
		اذهب out;
	}
	אם (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_key, response->public_key_len, عدم) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		اذهب out;
	}
	/* Key handle contains PEM encoded private key */
	אם (!PEM_write_bio_ECPrivateKey(bio, key, عدم, عدم, 0, عدم, عدم)) {
		skdebug(__func__, "PEM_write_bio_ECPrivateKey failed");
		اذهب out;
	}
	אם ((privlen = BIO_get_mem_data(bio, &privptr)) <= 0) {
		skdebug(__func__, "BIO_get_mem_data failed");
		اذهب out;
	}
	אם ((response->key_handle = malloc(privlen)) == عدم) {
		skdebug(__func__, "malloc key_handle failed");
		اذهب out;
	}
	response->key_handle_len = (size_t)privlen;
	memcpy(response->key_handle, privptr, response->key_handle_len);
	/* success */
	ret = 0;
 out:
	אם (ret != 0) {
		אם (response->public_key != عدم) {
			memset(response->public_key, 0,
			    response->public_key_len);
			حرر(response->public_key);
			response->public_key = عدم;
		}
		אם (response->key_handle != عدم) {
			memset(response->key_handle, 0,
			    response->key_handle_len);
			حرر(response->key_handle);
			response->key_handle = عدم;
		}
	}
	BIO_free(bio);
	EC_KEY_free(key);
	החזר ret;
#אחרת
	החזר -1;
#endif
}

ساكن صحيح
pack_key_ed25519(بنية sk_enroll_response *response)
{
	صحيح ret = -1;
	u_char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	u_char sk[crypto_sign_ed25519_SECRETKEYBYTES];

	response->public_key = عدم;
	response->public_key_len = 0;
	response->key_handle = عدم;
	response->key_handle_len = 0;

	memset(pk, 0, حجم(pk));
	memset(sk, 0, حجم(sk));
	crypto_sign_ed25519_keypair(pk, sk);

	response->public_key_len = حجم(pk);
	אם ((response->public_key = malloc(response->public_key_len)) == عدم) {
		skdebug(__func__, "malloc pubkey failed");
		اذهب out;
	}
	memcpy(response->public_key, pk, حجم(pk));
	/* Key handle contains sk */
	response->key_handle_len = حجم(sk);
	אם ((response->key_handle = malloc(response->key_handle_len)) == عدم) {
		skdebug(__func__, "malloc key_handle failed");
		اذهب out;
	}
	memcpy(response->key_handle, sk, حجم(sk));
	/* success */
	ret = 0;
 out:
	אם (ret != 0)
		حرر(response->public_key);
	החזר ret;
}

ساكن صحيح
check_options(بنية sk_option **options)
{
	size_t i;

	אם (options == عدم)
		החזר 0;
	עבור (i = 0; options[i] != عدم; i++) {
		skdebug(__func__, "requested unsupported option %s",
		    options[i]->name);
		אם (options[i]->required) {
			skdebug(__func__, "unknown required option");
			החזר -1;
		}
	}
	החזר 0;
}

صحيح
sk_enroll(uint32_t alg, ثابت uint8_t *challenge, size_t challenge_len,
    ثابت حرف *application, uint8_t flags, ثابت حرف *pin,
    بنية sk_option **options, بنية sk_enroll_response **enroll_response)
{
	بنية sk_enroll_response *response = عدم;
	صحيح ret = SSH_SK_ERR_GENERAL;

	(فراغ)flags; /* XXX; unused */

	אם (enroll_response == عدم) {
		skdebug(__func__, "enroll_response == NULL");
		اذهب out;
	}
	*enroll_response = عدم;
	אם (check_options(options) != 0)
		اذهب out; /* error already logged */
	אם ((response = calloc(1, حجم(*response))) == عدم) {
		skdebug(__func__, "calloc response failed");
		اذهب out;
	}
	response->flags = flags;
	بدل(alg) {
	حالة SSH_SK_ECDSA:
		אם (pack_key_ecdsa(response) != 0)
			اذهب out;
		اكسر;
	حالة SSH_SK_ED25519:
		אם (pack_key_ed25519(response) != 0)
			اذهب out;
		اكسر;
	افتراضي:
		skdebug(__func__, "unsupported key type %d", alg);
		اذهب out;
	}
	/* Have to return something here */
	אם ((response->signature = calloc(1, 1)) == عدم) {
		skdebug(__func__, "calloc signature failed");
		اذهب out;
	}
	response->signature_len = 0;

	*enroll_response = response;
	response = عدم;
	ret = 0;
 out:
	אם (response != عدم) {
		حرر(response->public_key);
		حرر(response->key_handle);
		حرر(response->signature);
		حرر(response->attestation_cert);
		حرر(response);
	}
	החזר ret;
}

ساكن فراغ
dump(ثابت حرف *preamble, ثابت فراغ *sv, size_t l)
{
#ifdef SK_DEBUG
	ثابت u_char *s = (ثابت u_char *)sv;
	size_t i;

	fprintf(stderr, "%s (len %zu):\n", preamble, l);
	עבור (i = 0; i < l; i++) {
		אם (i % 16 == 0)
			fprintf(stderr, "%04zu: ", i);
		fprintf(stderr, "%02x", s[i]);
		אם (i % 16 == 15 || i == l - 1)
			fprintf(stderr, "\n");
	}
#endif
}

ساكن صحيح
sig_ecdsa(ثابت uint8_t *message, size_t message_len,
    ثابت حرف *application, uint32_t counter, uint8_t flags,
    ثابت uint8_t *key_handle, size_t key_handle_len,
    بنية sk_sign_response *response)
{
#ifdef WITH_OPENSSL
	ECDSA_SIG *sig = عدم;
	ثابت BIGNUM *sig_r, *sig_s;
	صحيح ret = -1;
	BIO *bio = عدم;
	EVP_PKEY *pk = عدم;
	EC_KEY *ec = عدم;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_LENGTH];
	uint8_t	sighash[SHA256_DIGEST_LENGTH];
	uint8_t countbuf[4];

	/* Decode EC_KEY from key handle */
	אם ((bio = BIO_new(BIO_s_mem())) == عدم ||
	    BIO_write(bio, key_handle, key_handle_len) != (صحيح)key_handle_len) {
		skdebug(__func__, "BIO setup failed");
		اذهب out;
	}
	אם ((pk = PEM_read_bio_PrivateKey(bio, عدم, عدم, "")) == عدم) {
		skdebug(__func__, "PEM_read_bio_PrivateKey failed");
		اذهب out;
	}
	אם (EVP_PKEY_base_id(pk) != EVP_PKEY_EC) {
		skdebug(__func__, "Not an EC key: %d", EVP_PKEY_base_id(pk));
		اذهب out;
	}
	אם ((ec = EVP_PKEY_get1_EC_KEY(pk)) == عدم) {
		skdebug(__func__, "EVP_PKEY_get1_EC_KEY failed");
		اذهب out;
	}
	/* Expect message to be pre-hashed */
	אם (message_len != SHA256_DIGEST_LENGTH) {
		skdebug(__func__, "bad message len %zu", message_len);
		اذهب out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ثابت u_char *)application, strlen(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, حجم(apphash));
	countbuf[0] = (counter >> 24) & 0xff;
	countbuf[1] = (counter >> 16) & 0xff;
	countbuf[2] = (counter >> 8) & 0xff;
	countbuf[3] = counter & 0xff;
	dump("countbuf", countbuf, حجم(countbuf));
	dump("flags", &flags, حجم(flags));
	SHA256Init(&ctx);
	SHA256Update(&ctx, apphash, حجم(apphash));
	SHA256Update(&ctx, &flags, حجم(flags));
	SHA256Update(&ctx, countbuf, حجم(countbuf));
	SHA256Update(&ctx, message, message_len);
	SHA256Final(sighash, &ctx);
	dump("sighash", sighash, حجم(sighash));
	/* create and encode signature */
	אם ((sig = ECDSA_do_sign(sighash, حجم(sighash), ec)) == عدم) {
		skdebug(__func__, "ECDSA_do_sign failed");
		اذهب out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_num_bytes(sig_r);
	response->sig_s_len = BN_num_bytes(sig_s);
	אם ((response->sig_r = calloc(1, response->sig_r_len)) == عدم ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == عدم) {
		skdebug(__func__, "calloc signature failed");
		اذهب out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	explicit_bzero(&ctx, حجم(ctx));
	explicit_bzero(&apphash, حجم(apphash));
	explicit_bzero(&sighash, حجم(sighash));
	ECDSA_SIG_free(sig);
	אם (ret != 0) {
		حرر(response->sig_r);
		حرر(response->sig_s);
		response->sig_r = عدم;
		response->sig_s = عدم;
	}
	BIO_free(bio);
	EC_KEY_free(ec);
	EVP_PKEY_free(pk);
	החזר ret;
#אחרת
	החזר -1;
#endif
}

ساكن صحيح
sig_ed25519(ثابت uint8_t *message, size_t message_len,
    ثابت حرف *application, uint32_t counter, uint8_t flags,
    ثابت uint8_t *key_handle, size_t key_handle_len,
    بنية sk_sign_response *response)
{
	size_t o;
	صحيح ret = -1;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_LENGTH];
	uint8_t signbuf[حجم(apphash) + حجم(flags) +
	    حجم(counter) + SHA256_DIGEST_LENGTH];
	uint8_t sig[crypto_sign_ed25519_BYTES];
	unsigned long long siglen = 0;

	אם (key_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		skdebug(__func__, "bad key handle length %zu", key_handle_len);
		اذهب out;
	}
	/* Expect message to be pre-hashed */
	אם (message_len != SHA256_DIGEST_LENGTH) {
		skdebug(__func__, "bad message len %zu", message_len);
		اذهب out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ثابت u_char *)application, strlen(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, حجم(apphash));

	memcpy(signbuf, apphash, حجم(apphash));
	o = حجم(apphash);
	signbuf[o++] = flags;
	signbuf[o++] = (counter >> 24) & 0xff;
	signbuf[o++] = (counter >> 16) & 0xff;
	signbuf[o++] = (counter >> 8) & 0xff;
	signbuf[o++] = counter & 0xff;
	memcpy(signbuf + o, message, message_len);
	o += message_len;
	אם (o != حجم(signbuf)) {
		skdebug(__func__, "bad sign buf len %zu, expected %zu",
		    o, حجم(signbuf));
		اذهب out;
	}
	dump("signbuf", signbuf, حجم(signbuf));
	/* create and encode signature */
	אם (crypto_sign_ed25519_detached(sig, &siglen, signbuf, حجم(signbuf),
	    key_handle) != 0) {
		skdebug(__func__, "crypto_sign_ed25519_detached failed");
		اذهب out;
	}
	אם (siglen != حجم(sig)) {
		skdebug(__func__, "bad signature length %llu", siglen);
		اذهب out;
	}
	response->sig_r_len = حجم(sig);
	אם ((response->sig_r = calloc(1, response->sig_r_len)) == عدم) {
		skdebug(__func__, "calloc signature failed");
		اذهب out;
	}
	memcpy(response->sig_r, sig, response->sig_r_len);
	dump("sig_r", response->sig_r, response->sig_r_len);
	ret = 0;
 out:
	explicit_bzero(&ctx, حجم(ctx));
	explicit_bzero(&apphash, حجم(apphash));
	explicit_bzero(&signbuf, حجم(signbuf));
	explicit_bzero(&sig, حجم(sig));
	אם (ret != 0) {
		حرر(response->sig_r);
		response->sig_r = عدم;
	}
	החזר ret;
}

صحيح
sk_sign(uint32_t alg, ثابت uint8_t *data, size_t datalen,
    ثابت حرف *application, ثابت uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, ثابت حرف *pin, بنية sk_option **options,
    بنية sk_sign_response **sign_response)
{
	بنية sk_sign_response *response = عدم;
	صحيح ret = SSH_SK_ERR_GENERAL;
	SHA2_CTX ctx;
	uint8_t message[32];

	אם (sign_response == عدم) {
		skdebug(__func__, "sign_response == NULL");
		اذهب out;
	}
	*sign_response = عدم;
	אם (check_options(options) != 0)
		اذهب out; /* error already logged */
	אם ((response = calloc(1, حجم(*response))) == عدم) {
		skdebug(__func__, "calloc response failed");
		اذهب out;
	}
	SHA256Init(&ctx);
	SHA256Update(&ctx, data, datalen);
	SHA256Final(message, &ctx);
	response->flags = flags;
	response->counter = 0x12345678;
	بدل(alg) {
	حالة SSH_SK_ECDSA:
		אם (sig_ecdsa(message, حجم(message), application,
		    response->counter, flags, key_handle, key_handle_len,
		    response) != 0)
			اذهب out;
		اكسر;
	حالة SSH_SK_ED25519:
		אם (sig_ed25519(message, حجم(message), application,
		    response->counter, flags, key_handle, key_handle_len,
		    response) != 0)
			اذهب out;
		اكسر;
	افتراضي:
		skdebug(__func__, "unsupported key type %d", alg);
		اذهب out;
	}
	*sign_response = response;
	response = عدم;
	ret = 0;
 out:
	explicit_bzero(message, حجم(message));
	אם (response != عدم) {
		حرر(response->sig_r);
		حرر(response->sig_s);
		حرر(response);
	}
	החזר ret;
}

صحيح
sk_load_resident_keys(ثابت حرف *pin, بنية sk_option **options,
    بنية sk_resident_key ***rks, size_t *nrks)
{
	החזר SSH_SK_ERR_UNSUPPORTED;
}
