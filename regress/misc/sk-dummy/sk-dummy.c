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

#شامل "includes.h"

#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <stdio.h>
#شامل <stddef.h>
#شامل <stdarg.h>

#شامل "crypto_api.h"
#شامل "sk-api.h"

#ifdef WITH_OPENSSL
#شامل <openssl/opensslv.h>
#شامل <openssl/sha.h>
#شامل <openssl/crypto.h>
#شامل <openssl/evp.h>
#شامل <openssl/bn.h>
#شامل <openssl/ec.h>
#شامل <openssl/ecdsa.h>
#شامل <openssl/pem.h>

/* Use OpenSSL SHA256 instead of libc */
#define SHA256Init(x)		SHA256_Init(x)
#define SHA256Update(x, y, z)	SHA256_Update(x, y, z)
#define SHA256Final(x, y)	SHA256_Final(x, y)
#define SHA2_CTX		SHA256_CTX

#وگرنهاگر defined(HAVE_SHA2_H)
#شامل <sha2.h>
#endif /* WITH_OPENSSL */

/* #define SK_DEBUG 1 */

#اگر SSH_SK_VERSION_MAJOR != 0x000a0000
# error SK API has changed, sk-dummy.c needs an update
#endif

#ifdef SK_DUMMY_INTEGRATE
# define sk_api_version		ssh_sk_api_version
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_load_resident_کلیدها	ssh_sk_load_resident_کلیدها
#endif /* !SK_STANDALONE */

ایستا تهی skdebug(ثابت نویسه *func, ثابت نویسه *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

ایستا تهی
skdebug(ثابت نویسه *func, ثابت نویسه *fmt, ...)
{
#اگر defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "sk-dummy %s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#وگرنه
	(تهی)func; /* XXX */
	(تهی)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(تهی)
{
	بازگشت SSH_SK_VERSION_MAJOR;
}

ایستا صحیح
pack_کلید_ecdsa(ساختار sk_enroll_response *response)
{
#ifdef WITH_OPENSSL
	EC_کلید *کلید = پوچ;
	ثابت EC_GROUP *g;
	ثابت EC_POINT *q;
	صحیح ret = -1;
	long privlen;
	BIO *bio = پوچ;
	نویسه *privptr;

	response->public_کلید = پوچ;
	response->public_کلید_len = 0;
	response->کلید_handle = پوچ;
	response->کلید_handle_len = 0;

	اگر ((کلید = EC_کلید_new_by_curve_name(NID_X9_62_prime256v1)) == پوچ) {
		skdebug(__func__, "EC_KEY_new_by_curve_name");
		برو out;
	}
	اگر (EC_کلید_generate_کلید(کلید) != 1) {
		skdebug(__func__, "EC_KEY_generate_key");
		برو out;
	}
	EC_کلید_set_asn1_flag(کلید, OPENSSL_EC_NAMED_CURVE);
	اگر ((bio = BIO_new(BIO_s_mem())) == پوچ ||
	    (g = EC_کلید_get0_group(کلید)) == پوچ ||
	    (q = EC_کلید_get0_public_کلید(کلید)) == پوچ) {
		skdebug(__func__, "couldn't get key parameters");
		برو out;
	}
	response->public_کلید_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, پوچ, 0, پوچ);
	اگر (response->public_کلید_len == 0 || response->public_کلید_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_کلید_len);
		برو out;
	}
	اگر ((response->public_کلید = malloc(response->public_کلید_len)) == پوچ) {
		skdebug(__func__, "malloc pubkey failed");
		برو out;
	}
	اگر (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_کلید, response->public_کلید_len, پوچ) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		برو out;
	}
	/* Key handle contains PEM encoded private key */
	اگر (!PEM_write_bio_ECPrivate_کلید(bio, کلید, پوچ, پوچ, 0, پوچ, پوچ)) {
		skdebug(__func__, "PEM_write_bio_ECPrivateKey failed");
		برو out;
	}
	اگر ((privlen = BIO_get_mem_data(bio, &privptr)) <= 0) {
		skdebug(__func__, "BIO_get_mem_data failed");
		برو out;
	}
	اگر ((response->کلید_handle = malloc(privlen)) == پوچ) {
		skdebug(__func__, "malloc key_handle failed");
		برو out;
	}
	response->کلید_handle_len = (size_t)privlen;
	memcpy(response->کلید_handle, privptr, response->کلید_handle_len);
	/* success */
	ret = 0;
 out:
	اگر (ret != 0) {
		اگر (response->public_کلید != پوچ) {
			memset(response->public_کلید, 0,
			    response->public_کلید_len);
			آزاد(response->public_کلید);
			response->public_کلید = پوچ;
		}
		اگر (response->کلید_handle != پوچ) {
			memset(response->کلید_handle, 0,
			    response->کلید_handle_len);
			آزاد(response->کلید_handle);
			response->کلید_handle = پوچ;
		}
	}
	BIO_free(bio);
	EC_کلید_free(کلید);
	بازگشت ret;
#وگرنه
	بازگشت -1;
#endif
}

ایستا صحیح
pack_کلید_ed25519(ساختار sk_enroll_response *response)
{
	صحیح ret = -1;
	u_char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	u_char sk[crypto_sign_ed25519_SECRETKEYBYTES];

	response->public_کلید = پوچ;
	response->public_کلید_len = 0;
	response->کلید_handle = پوچ;
	response->کلید_handle_len = 0;

	memset(pk, 0, اندازه(pk));
	memset(sk, 0, اندازه(sk));
	crypto_sign_ed25519_keypair(pk, sk);

	response->public_کلید_len = اندازه(pk);
	اگر ((response->public_کلید = malloc(response->public_کلید_len)) == پوچ) {
		skdebug(__func__, "malloc pubkey failed");
		برو out;
	}
	memcpy(response->public_کلید, pk, اندازه(pk));
	/* Key handle contains sk */
	response->کلید_handle_len = اندازه(sk);
	اگر ((response->کلید_handle = malloc(response->کلید_handle_len)) == پوچ) {
		skdebug(__func__, "malloc key_handle failed");
		برو out;
	}
	memcpy(response->کلید_handle, sk, اندازه(sk));
	/* success */
	ret = 0;
 out:
	اگر (ret != 0)
		آزاد(response->public_کلید);
	بازگشت ret;
}

ایستا صحیح
check_options(ساختار sk_option **options)
{
	size_t i;

	اگر (options == پوچ)
		بازگشت 0;
	برای (i = 0; options[i] != پوچ; i++) {
		skdebug(__func__, "requested unsupported option %s",
		    options[i]->name);
		اگر (options[i]->required) {
			skdebug(__func__, "unknown required option");
			بازگشت -1;
		}
	}
	بازگشت 0;
}

صحیح
sk_enroll(uint32_t alg, ثابت uint8_t *challenge, size_t challenge_len,
    ثابت نویسه *application, uint8_t flags, ثابت نویسه *pin,
    ساختار sk_option **options, ساختار sk_enroll_response **enroll_response)
{
	ساختار sk_enroll_response *response = پوچ;
	صحیح ret = SSH_SK_ERR_GENERAL;

	(تهی)flags; /* XXX; unused */

	اگر (enroll_response == پوچ) {
		skdebug(__func__, "enroll_response == NULL");
		برو out;
	}
	*enroll_response = پوچ;
	اگر (check_options(options) != 0)
		برو out; /* error already logged */
	اگر ((response = calloc(1, اندازه(*response))) == پوچ) {
		skdebug(__func__, "calloc response failed");
		برو out;
	}
	response->flags = flags;
	انتخاب(alg) {
	حالت SSH_SK_ECDSA:
		اگر (pack_کلید_ecdsa(response) != 0)
			برو out;
		بشکن;
	حالت SSH_SK_ED25519:
		اگر (pack_کلید_ed25519(response) != 0)
			برو out;
		بشکن;
	پیشفرض:
		skdebug(__func__, "unsupported key type %d", alg);
		برو out;
	}
	/* Have to return something here */
	اگر ((response->signature = calloc(1, 1)) == پوچ) {
		skdebug(__func__, "calloc signature failed");
		برو out;
	}
	response->signature_len = 0;

	*enroll_response = response;
	response = پوچ;
	ret = 0;
 out:
	اگر (response != پوچ) {
		آزاد(response->public_کلید);
		آزاد(response->کلید_handle);
		آزاد(response->signature);
		آزاد(response->attestation_cert);
		آزاد(response);
	}
	بازگشت ret;
}

ایستا تهی
dump(ثابت نویسه *preamble, ثابت تهی *sv, size_t l)
{
#ifdef SK_DEBUG
	ثابت u_char *s = (ثابت u_char *)sv;
	size_t i;

	fprintf(stderr, "%s (len %zu):\n", preamble, l);
	برای (i = 0; i < l; i++) {
		اگر (i % 16 == 0)
			fprintf(stderr, "%04zu: ", i);
		fprintf(stderr, "%02x", s[i]);
		اگر (i % 16 == 15 || i == l - 1)
			fprintf(stderr, "\n");
	}
#endif
}

ایستا صحیح
sig_ecdsa(ثابت uint8_t *message, size_t message_len,
    ثابت نویسه *application, uint32_t counter, uint8_t flags,
    ثابت uint8_t *کلید_handle, size_t کلید_handle_len,
    ساختار sk_sign_response *response)
{
#ifdef WITH_OPENSSL
	ECDSA_SIG *sig = پوچ;
	ثابت BIGNUM *sig_r, *sig_s;
	صحیح ret = -1;
	BIO *bio = پوچ;
	EVP_PKEY *pk = پوچ;
	EC_کلید *ec = پوچ;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_LENGTH];
	uint8_t	sighash[SHA256_DIGEST_LENGTH];
	uint8_t countbuf[4];

	/* Decode EC_KEY from key handle */
	اگر ((bio = BIO_new(BIO_s_mem())) == پوچ ||
	    BIO_write(bio, کلید_handle, کلید_handle_len) != (صحیح)کلید_handle_len) {
		skdebug(__func__, "BIO setup failed");
		برو out;
	}
	اگر ((pk = PEM_read_bio_Private_کلید(bio, پوچ, پوچ, "")) == پوچ) {
		skdebug(__func__, "PEM_read_bio_PrivateKey failed");
		برو out;
	}
	اگر (EVP_PKEY_base_id(pk) != EVP_PKEY_EC) {
		skdebug(__func__, "Not an EC key: %d", EVP_PKEY_base_id(pk));
		برو out;
	}
	اگر ((ec = EVP_PKEY_get1_EC_کلید(pk)) == پوچ) {
		skdebug(__func__, "EVP_PKEY_get1_EC_KEY failed");
		برو out;
	}
	/* Expect message to be pre-hashed */
	اگر (message_len != SHA256_DIGEST_LENGTH) {
		skdebug(__func__, "bad message len %zu", message_len);
		برو out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ثابت u_char *)application, strlen(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, اندازه(apphash));
	countbuf[0] = (counter >> 24) & 0xff;
	countbuf[1] = (counter >> 16) & 0xff;
	countbuf[2] = (counter >> 8) & 0xff;
	countbuf[3] = counter & 0xff;
	dump("countbuf", countbuf, اندازه(countbuf));
	dump("flags", &flags, اندازه(flags));
	SHA256Init(&ctx);
	SHA256Update(&ctx, apphash, اندازه(apphash));
	SHA256Update(&ctx, &flags, اندازه(flags));
	SHA256Update(&ctx, countbuf, اندازه(countbuf));
	SHA256Update(&ctx, message, message_len);
	SHA256Final(sighash, &ctx);
	dump("sighash", sighash, اندازه(sighash));
	/* create and encode signature */
	اگر ((sig = ECDSA_do_sign(sighash, اندازه(sighash), ec)) == پوچ) {
		skdebug(__func__, "ECDSA_do_sign failed");
		برو out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_رقم_bytes(sig_r);
	response->sig_s_len = BN_رقم_bytes(sig_s);
	اگر ((response->sig_r = calloc(1, response->sig_r_len)) == پوچ ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == پوچ) {
		skdebug(__func__, "calloc signature failed");
		برو out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	explicit_bzero(&ctx, اندازه(ctx));
	explicit_bzero(&apphash, اندازه(apphash));
	explicit_bzero(&sighash, اندازه(sighash));
	ECDSA_SIG_free(sig);
	اگر (ret != 0) {
		آزاد(response->sig_r);
		آزاد(response->sig_s);
		response->sig_r = پوچ;
		response->sig_s = پوچ;
	}
	BIO_free(bio);
	EC_کلید_free(ec);
	EVP_PKEY_free(pk);
	بازگشت ret;
#وگرنه
	بازگشت -1;
#endif
}

ایستا صحیح
sig_ed25519(ثابت uint8_t *message, size_t message_len,
    ثابت نویسه *application, uint32_t counter, uint8_t flags,
    ثابت uint8_t *کلید_handle, size_t کلید_handle_len,
    ساختار sk_sign_response *response)
{
	size_t o;
	صحیح ret = -1;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_LENGTH];
	uint8_t signbuf[اندازه(apphash) + اندازه(flags) +
	    اندازه(counter) + SHA256_DIGEST_LENGTH];
	uint8_t sig[crypto_sign_ed25519_BYTES];
	unsigned long long siglen = 0;

	اگر (کلید_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		skdebug(__func__, "bad key handle length %zu", کلید_handle_len);
		برو out;
	}
	/* Expect message to be pre-hashed */
	اگر (message_len != SHA256_DIGEST_LENGTH) {
		skdebug(__func__, "bad message len %zu", message_len);
		برو out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ثابت u_char *)application, strlen(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, اندازه(apphash));

	memcpy(signbuf, apphash, اندازه(apphash));
	o = اندازه(apphash);
	signbuf[o++] = flags;
	signbuf[o++] = (counter >> 24) & 0xff;
	signbuf[o++] = (counter >> 16) & 0xff;
	signbuf[o++] = (counter >> 8) & 0xff;
	signbuf[o++] = counter & 0xff;
	memcpy(signbuf + o, message, message_len);
	o += message_len;
	اگر (o != اندازه(signbuf)) {
		skdebug(__func__, "bad sign buf len %zu, expected %zu",
		    o, اندازه(signbuf));
		برو out;
	}
	dump("signbuf", signbuf, اندازه(signbuf));
	/* create and encode signature */
	اگر (crypto_sign_ed25519_detached(sig, &siglen, signbuf, اندازه(signbuf),
	    کلید_handle) != 0) {
		skdebug(__func__, "crypto_sign_ed25519_detached failed");
		برو out;
	}
	اگر (siglen != اندازه(sig)) {
		skdebug(__func__, "bad signature length %llu", siglen);
		برو out;
	}
	response->sig_r_len = اندازه(sig);
	اگر ((response->sig_r = calloc(1, response->sig_r_len)) == پوچ) {
		skdebug(__func__, "calloc signature failed");
		برو out;
	}
	memcpy(response->sig_r, sig, response->sig_r_len);
	dump("sig_r", response->sig_r, response->sig_r_len);
	ret = 0;
 out:
	explicit_bzero(&ctx, اندازه(ctx));
	explicit_bzero(&apphash, اندازه(apphash));
	explicit_bzero(&signbuf, اندازه(signbuf));
	explicit_bzero(&sig, اندازه(sig));
	اگر (ret != 0) {
		آزاد(response->sig_r);
		response->sig_r = پوچ;
	}
	بازگشت ret;
}

صحیح
sk_sign(uint32_t alg, ثابت uint8_t *data, size_t datalen,
    ثابت نویسه *application, ثابت uint8_t *کلید_handle, size_t کلید_handle_len,
    uint8_t flags, ثابت نویسه *pin, ساختار sk_option **options,
    ساختار sk_sign_response **sign_response)
{
	ساختار sk_sign_response *response = پوچ;
	صحیح ret = SSH_SK_ERR_GENERAL;
	SHA2_CTX ctx;
	uint8_t message[32];

	اگر (sign_response == پوچ) {
		skdebug(__func__, "sign_response == NULL");
		برو out;
	}
	*sign_response = پوچ;
	اگر (check_options(options) != 0)
		برو out; /* error already logged */
	اگر ((response = calloc(1, اندازه(*response))) == پوچ) {
		skdebug(__func__, "calloc response failed");
		برو out;
	}
	SHA256Init(&ctx);
	SHA256Update(&ctx, data, datalen);
	SHA256Final(message, &ctx);
	response->flags = flags;
	response->counter = 0x12345678;
	انتخاب(alg) {
	حالت SSH_SK_ECDSA:
		اگر (sig_ecdsa(message, اندازه(message), application,
		    response->counter, flags, کلید_handle, کلید_handle_len,
		    response) != 0)
			برو out;
		بشکن;
	حالت SSH_SK_ED25519:
		اگر (sig_ed25519(message, اندازه(message), application,
		    response->counter, flags, کلید_handle, کلید_handle_len,
		    response) != 0)
			برو out;
		بشکن;
	پیشفرض:
		skdebug(__func__, "unsupported key type %d", alg);
		برو out;
	}
	*sign_response = response;
	response = پوچ;
	ret = 0;
 out:
	explicit_bzero(message, اندازه(message));
	اگر (response != پوچ) {
		آزاد(response->sig_r);
		آزاد(response->sig_s);
		آزاد(response);
	}
	بازگشت ret;
}

صحیح
sk_load_resident_کلیدها(ثابت نویسه *pin, ساختار sk_option **options,
    ساختار sk_resident_کلید ***rks, size_t *nrks)
{
	بازگشت SSH_SK_ERR_UNSUPPORTED;
}
