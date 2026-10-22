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

#إذا SSH_SK_VERSION_MAJOR != 0x000a0000
# error SK API has changed, sk-dummy.c needs an update
#endif

#ifdef SK_DUMMY_INTEGRATE
# define sk_api_version		ssh_sk_api_version
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_load_resident_مفاتيح	ssh_sk_load_resident_مفاتيح
#endif /* !SK_STANDALONE */

ساكن فراغ skdebug(ثابت حرف *func, ثابت حرف *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

ساكن فراغ
skdebug(ثابت حرف *func, ثابت حرف *fmt, ...)
{
#إذا defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "sk-dummy %s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#وإلا
	(فراغ)func; /* XXX */
	(فراغ)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(فراغ)
{
	إرجاع SSH_SK_VERSION_MAJOR;
}

ساكن صحيح
pack_مفتاح_ecdsa(بنية sk_enroll_response *response)
{
#ifdef WITH_OPENSSL
	EC_مفتاح *مفتاح = عدم;
	ثابت EC_GROUP *g;
	ثابت EC_POINT *q;
	صحيح ret = -1;
	long privlen;
	BIO *bio = عدم;
	حرف *privptr;

	response->public_مفتاح = عدم;
	response->public_مفتاح_len = 0;
	response->مفتاح_handle = عدم;
	response->مفتاح_handle_len = 0;

	إذا ((مفتاح = EC_مفتاح_new_by_curve_name(NID_X9_62_prime256v1)) == عدم) {
		skdebug(__func__, "EC_KEY_new_by_curve_name");
		اذهب out;
	}
	إذا (EC_مفتاح_generate_مفتاح(مفتاح) != 1) {
		skdebug(__func__, "EC_KEY_generate_key");
		اذهب out;
	}
	EC_مفتاح_set_asn1_flag(مفتاح, OPENSSL_EC_NAMED_CURVE);
	إذا ((bio = BIO_new(BIO_s_mem())) == عدم ||
	    (g = EC_مفتاح_get0_group(مفتاح)) == عدم ||
	    (q = EC_مفتاح_get0_public_مفتاح(مفتاح)) == عدم) {
		skdebug(__func__, "couldn't get key parameters");
		اذهب out;
	}
	response->public_مفتاح_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, عدم, 0, عدم);
	إذا (response->public_مفتاح_len == 0 || response->public_مفتاح_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_مفتاح_len);
		اذهب out;
	}
	إذا ((response->public_مفتاح = malloc(response->public_مفتاح_len)) == عدم) {
		skdebug(__func__, "malloc pubkey failed");
		اذهب out;
	}
	إذا (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_مفتاح, response->public_مفتاح_len, عدم) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		اذهب out;
	}
	/* Key handle contains PEM encoded private key */
	إذا (!PEM_write_bio_ECPrivate_مفتاح(bio, مفتاح, عدم, عدم, 0, عدم, عدم)) {
		skdebug(__func__, "PEM_write_bio_ECPrivateKey failed");
		اذهب out;
	}
	إذا ((privlen = BIO_get_mem_data(bio, &privptr)) <= 0) {
		skdebug(__func__, "BIO_get_mem_data failed");
		اذهب out;
	}
	إذا ((response->مفتاح_handle = malloc(privlen)) == عدم) {
		skdebug(__func__, "malloc key_handle failed");
		اذهب out;
	}
	response->مفتاح_handle_len = (size_t)privlen;
	memcpy(response->مفتاح_handle, privptr, response->مفتاح_handle_len);
	/* success */
	ret = 0;
 out:
	إذا (ret != 0) {
		إذا (response->public_مفتاح != عدم) {
			memset(response->public_مفتاح, 0,
			    response->public_مفتاح_len);
			حرر(response->public_مفتاح);
			response->public_مفتاح = عدم;
		}
		إذا (response->مفتاح_handle != عدم) {
			memset(response->مفتاح_handle, 0,
			    response->مفتاح_handle_len);
			حرر(response->مفتاح_handle);
			response->مفتاح_handle = عدم;
		}
	}
	BIO_free(bio);
	EC_مفتاح_free(مفتاح);
	إرجاع ret;
#وإلا
	إرجاع -1;
#endif
}

ساكن صحيح
pack_مفتاح_ed25519(بنية sk_enroll_response *response)
{
	صحيح ret = -1;
	u_char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	u_char sk[crypto_sign_ed25519_SECRETKEYBYTES];

	response->public_مفتاح = عدم;
	response->public_مفتاح_len = 0;
	response->مفتاح_handle = عدم;
	response->مفتاح_handle_len = 0;

	memset(pk, 0, حجم(pk));
	memset(sk, 0, حجم(sk));
	crypto_sign_ed25519_keypair(pk, sk);

	response->public_مفتاح_len = حجم(pk);
	إذا ((response->public_مفتاح = malloc(response->public_مفتاح_len)) == عدم) {
		skdebug(__func__, "malloc pubkey failed");
		اذهب out;
	}
	memcpy(response->public_مفتاح, pk, حجم(pk));
	/* Key handle contains sk */
	response->مفتاح_handle_len = حجم(sk);
	إذا ((response->مفتاح_handle = malloc(response->مفتاح_handle_len)) == عدم) {
		skdebug(__func__, "malloc key_handle failed");
		اذهب out;
	}
	memcpy(response->مفتاح_handle, sk, حجم(sk));
	/* success */
	ret = 0;
 out:
	إذا (ret != 0)
		حرر(response->public_مفتاح);
	إرجاع ret;
}

ساكن صحيح
check_options(بنية sk_option **options)
{
	size_t i;

	إذا (options == عدم)
		إرجاع 0;
	لكل (i = 0; options[i] != عدم; i++) {
		skdebug(__func__, "requested unsupported option %s",
		    options[i]->name);
		إذا (options[i]->required) {
			skdebug(__func__, "unknown required option");
			إرجاع -1;
		}
	}
	إرجاع 0;
}

صحيح
sk_enroll(uint32_t alg, ثابت uint8_t *challenge, size_t challenge_len,
    ثابت حرف *application, uint8_t flags, ثابت حرف *pin,
    بنية sk_option **options, بنية sk_enroll_response **enroll_response)
{
	بنية sk_enroll_response *response = عدم;
	صحيح ret = SSH_SK_ERR_GENERAL;

	(فراغ)flags; /* XXX; unused */

	إذا (enroll_response == عدم) {
		skdebug(__func__, "enroll_response == NULL");
		اذهب out;
	}
	*enroll_response = عدم;
	إذا (check_options(options) != 0)
		اذهب out; /* error already logged */
	إذا ((response = calloc(1, حجم(*response))) == عدم) {
		skdebug(__func__, "calloc response failed");
		اذهب out;
	}
	response->flags = flags;
	بدل(alg) {
	حالة SSH_SK_ECDSA:
		إذا (pack_مفتاح_ecdsa(response) != 0)
			اذهب out;
		اكسر;
	حالة SSH_SK_ED25519:
		إذا (pack_مفتاح_ed25519(response) != 0)
			اذهب out;
		اكسر;
	افتراضي:
		skdebug(__func__, "unsupported key type %d", alg);
		اذهب out;
	}
	/* Have to return something here */
	إذا ((response->signature = calloc(1, 1)) == عدم) {
		skdebug(__func__, "calloc signature failed");
		اذهب out;
	}
	response->signature_len = 0;

	*enroll_response = response;
	response = عدم;
	ret = 0;
 out:
	إذا (response != عدم) {
		حرر(response->public_مفتاح);
		حرر(response->مفتاح_handle);
		حرر(response->signature);
		حرر(response->attestation_cert);
		حرر(response);
	}
	إرجاع ret;
}

ساكن فراغ
dump(ثابت حرف *preamble, ثابت فراغ *sv, size_t l)
{
#ifdef SK_DEBUG
	ثابت u_char *s = (ثابت u_char *)sv;
	size_t i;

	fprintf(stderr, "%s (len %zu):\n", preamble, l);
	لكل (i = 0; i < l; i++) {
		إذا (i % 16 == 0)
			fprintf(stderr, "%04zu: ", i);
		fprintf(stderr, "%02x", s[i]);
		إذا (i % 16 == 15 || i == l - 1)
			fprintf(stderr, "\n");
	}
#endif
}

ساكن صحيح
sig_ecdsa(ثابت uint8_t *message, size_t message_len,
    ثابت حرف *application, uint32_t counter, uint8_t flags,
    ثابت uint8_t *مفتاح_handle, size_t مفتاح_handle_len,
    بنية sk_sign_response *response)
{
#ifdef WITH_OPENSSL
	ECDSA_SIG *sig = عدم;
	ثابت BIGNUM *sig_r, *sig_s;
	صحيح ret = -1;
	BIO *bio = عدم;
	EVP_PKEY *pk = عدم;
	EC_مفتاح *ec = عدم;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_LENGTH];
	uint8_t	sighash[SHA256_DIGEST_LENGTH];
	uint8_t countbuf[4];

	/* Decode EC_KEY from key handle */
	إذا ((bio = BIO_new(BIO_s_mem())) == عدم ||
	    BIO_write(bio, مفتاح_handle, مفتاح_handle_len) != (صحيح)مفتاح_handle_len) {
		skdebug(__func__, "BIO setup failed");
		اذهب out;
	}
	إذا ((pk = PEM_read_bio_Private_مفتاح(bio, عدم, عدم, "")) == عدم) {
		skdebug(__func__, "PEM_read_bio_PrivateKey failed");
		اذهب out;
	}
	إذا (EVP_PKEY_base_id(pk) != EVP_PKEY_EC) {
		skdebug(__func__, "Not an EC key: %d", EVP_PKEY_base_id(pk));
		اذهب out;
	}
	إذا ((ec = EVP_PKEY_get1_EC_مفتاح(pk)) == عدم) {
		skdebug(__func__, "EVP_PKEY_get1_EC_KEY failed");
		اذهب out;
	}
	/* Expect message to be pre-hashed */
	إذا (message_len != SHA256_DIGEST_LENGTH) {
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
	إذا ((sig = ECDSA_do_sign(sighash, حجم(sighash), ec)) == عدم) {
		skdebug(__func__, "ECDSA_do_sign failed");
		اذهب out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_رقم_bytes(sig_r);
	response->sig_s_len = BN_رقم_bytes(sig_s);
	إذا ((response->sig_r = calloc(1, response->sig_r_len)) == عدم ||
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
	إذا (ret != 0) {
		حرر(response->sig_r);
		حرر(response->sig_s);
		response->sig_r = عدم;
		response->sig_s = عدم;
	}
	BIO_free(bio);
	EC_مفتاح_free(ec);
	EVP_PKEY_free(pk);
	إرجاع ret;
#وإلا
	إرجاع -1;
#endif
}

ساكن صحيح
sig_ed25519(ثابت uint8_t *message, size_t message_len,
    ثابت حرف *application, uint32_t counter, uint8_t flags,
    ثابت uint8_t *مفتاح_handle, size_t مفتاح_handle_len,
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

	إذا (مفتاح_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		skdebug(__func__, "bad key handle length %zu", مفتاح_handle_len);
		اذهب out;
	}
	/* Expect message to be pre-hashed */
	إذا (message_len != SHA256_DIGEST_LENGTH) {
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
	إذا (o != حجم(signbuf)) {
		skdebug(__func__, "bad sign buf len %zu, expected %zu",
		    o, حجم(signbuf));
		اذهب out;
	}
	dump("signbuf", signbuf, حجم(signbuf));
	/* create and encode signature */
	إذا (crypto_sign_ed25519_detached(sig, &siglen, signbuf, حجم(signbuf),
	    مفتاح_handle) != 0) {
		skdebug(__func__, "crypto_sign_ed25519_detached failed");
		اذهب out;
	}
	إذا (siglen != حجم(sig)) {
		skdebug(__func__, "bad signature length %llu", siglen);
		اذهب out;
	}
	response->sig_r_len = حجم(sig);
	إذا ((response->sig_r = calloc(1, response->sig_r_len)) == عدم) {
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
	إذا (ret != 0) {
		حرر(response->sig_r);
		response->sig_r = عدم;
	}
	إرجاع ret;
}

صحيح
sk_sign(uint32_t alg, ثابت uint8_t *data, size_t datalen,
    ثابت حرف *application, ثابت uint8_t *مفتاح_handle, size_t مفتاح_handle_len,
    uint8_t flags, ثابت حرف *pin, بنية sk_option **options,
    بنية sk_sign_response **sign_response)
{
	بنية sk_sign_response *response = عدم;
	صحيح ret = SSH_SK_ERR_GENERAL;
	SHA2_CTX ctx;
	uint8_t message[32];

	إذا (sign_response == عدم) {
		skdebug(__func__, "sign_response == NULL");
		اذهب out;
	}
	*sign_response = عدم;
	إذا (check_options(options) != 0)
		اذهب out; /* error already logged */
	إذا ((response = calloc(1, حجم(*response))) == عدم) {
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
		إذا (sig_ecdsa(message, حجم(message), application,
		    response->counter, flags, مفتاح_handle, مفتاح_handle_len,
		    response) != 0)
			اذهب out;
		اكسر;
	حالة SSH_SK_ED25519:
		إذا (sig_ed25519(message, حجم(message), application,
		    response->counter, flags, مفتاح_handle, مفتاح_handle_len,
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
	إذا (response != عدم) {
		حرر(response->sig_r);
		حرر(response->sig_s);
		حرر(response);
	}
	إرجاع ret;
}

صحيح
sk_load_resident_مفاتيح(ثابت حرف *pin, بنية sk_option **options,
    بنية sk_resident_مفتاح ***rks, size_t *nrks)
{
	إرجاع SSH_SK_ERR_UNSUPPORTED;
}
