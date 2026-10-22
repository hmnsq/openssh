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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdarg.h>

#অন্তর্ভাব "crypto_api.h"
#অন্তর্ভাব "sk-api.h"

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/opensslv.h>
#অন্তর্ভাব <openssl/sha.h>
#অন্তর্ভাব <openssl/crypto.h>
#অন্তর্ভাব <openssl/evp.h>
#অন্তর্ভাব <openssl/bn.h>
#অন্তর্ভাব <openssl/ec.h>
#অন্তর্ভাব <openssl/ecdsa.h>
#অন্তর্ভাব <openssl/pem.h>

/* Use OpenSSL SHA256 instead of libc */
#define SHA256Init(x)		SHA256_Init(x)
#define SHA256Update(x, y, z)	SHA256_Update(x, y, z)
#define SHA256Final(x, y)	SHA256_Final(x, y)
#define SHA2_CTX		SHA256_CTX

#নতুবা_যদি defined(HAVE_SHA2_H)
#অন্তর্ভাব <sha2.h>
#endif /* WITH_OPENSSL */

/* #define SK_DEBUG 1 */

#যদি SSH_SK_VERSION_MAJOR != 0x000a0000
# error SK API has changed, sk-dummy.c needs an update
#endif

#ifdef SK_DUMMY_INTEGRATE
# define sk_api_version		ssh_sk_api_version
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_load_resident_চাবিগুলি	ssh_sk_load_resident_চাবিগুলি
#endif /* !SK_STANDALONE */

স্থির শূন্য skdebug(ধ্রুবক অক্ষর *func, ধ্রুবক অক্ষর *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

স্থির শূন্য
skdebug(ধ্রুবক অক্ষর *func, ধ্রুবক অক্ষর *fmt, ...)
{
#যদি defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "sk-dummy %s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#অন্যথা
	(শূন্য)func; /* XXX */
	(শূন্য)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(শূন্য)
{
	ফেরত SSH_SK_VERSION_MAJOR;
}

স্থির পূর্ণসংখ্যা
pack_চাবি_ecdsa(কাঠামো sk_enroll_response *response)
{
#ifdef WITH_OPENSSL
	EC_চাবি *চাবি = ফাঁকা;
	ধ্রুবক EC_GROUP *g;
	ধ্রুবক EC_POINT *q;
	পূর্ণসংখ্যা ret = -1;
	long privlen;
	BIO *bio = ফাঁকা;
	অক্ষর *privptr;

	response->public_চাবি = ফাঁকা;
	response->public_চাবি_len = 0;
	response->চাবি_handle = ফাঁকা;
	response->চাবি_handle_len = 0;

	যদি ((চাবি = EC_চাবি_new_by_curve_name(NID_X9_62_prime256v1)) == ফাঁকা) {
		skdebug(__func__, "EC_KEY_new_by_curve_name");
		যাও out;
	}
	যদি (EC_চাবি_generate_চাবি(চাবি) != 1) {
		skdebug(__func__, "EC_KEY_generate_key");
		যাও out;
	}
	EC_চাবি_set_asn1_flag(চাবি, OPENSSL_EC_NAMED_CURVE);
	যদি ((bio = BIO_new(BIO_s_mem())) == ফাঁকা ||
	    (g = EC_চাবি_get0_group(চাবি)) == ফাঁকা ||
	    (q = EC_চাবি_get0_public_চাবি(চাবি)) == ফাঁকা) {
		skdebug(__func__, "couldn't get key parameters");
		যাও out;
	}
	response->public_চাবি_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, ফাঁকা, 0, ফাঁকা);
	যদি (response->public_চাবি_len == 0 || response->public_চাবি_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_চাবি_len);
		যাও out;
	}
	যদি ((response->public_চাবি = malloc(response->public_চাবি_len)) == ফাঁকা) {
		skdebug(__func__, "malloc pubkey failed");
		যাও out;
	}
	যদি (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_চাবি, response->public_চাবি_len, ফাঁকা) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		যাও out;
	}
	/* Key handle contains PEM encoded private key */
	যদি (!PEM_write_bio_ECPrivate_চাবি(bio, চাবি, ফাঁকা, ফাঁকা, 0, ফাঁকা, ফাঁকা)) {
		skdebug(__func__, "PEM_write_bio_ECPrivateKey failed");
		যাও out;
	}
	যদি ((privlen = BIO_get_mem_তথ্য(bio, &privptr)) <= 0) {
		skdebug(__func__, "BIO_get_mem_data failed");
		যাও out;
	}
	যদি ((response->চাবি_handle = malloc(privlen)) == ফাঁকা) {
		skdebug(__func__, "malloc key_handle failed");
		যাও out;
	}
	response->চাবি_handle_len = (আকার_t)privlen;
	memcpy(response->চাবি_handle, privptr, response->চাবি_handle_len);
	/* success */
	ret = 0;
 out:
	যদি (ret != 0) {
		যদি (response->public_চাবি != ফাঁকা) {
			memset(response->public_চাবি, 0,
			    response->public_চাবি_len);
			মুক্ত(response->public_চাবি);
			response->public_চাবি = ফাঁকা;
		}
		যদি (response->চাবি_handle != ফাঁকা) {
			memset(response->চাবি_handle, 0,
			    response->চাবি_handle_len);
			মুক্ত(response->চাবি_handle);
			response->চাবি_handle = ফাঁকা;
		}
	}
	BIO_free(bio);
	EC_চাবি_free(চাবি);
	ফেরত ret;
#অন্যথা
	ফেরত -1;
#endif
}

স্থির পূর্ণসংখ্যা
pack_চাবি_ed25519(কাঠামো sk_enroll_response *response)
{
	পূর্ণসংখ্যা ret = -1;
	u_char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	u_char sk[crypto_sign_ed25519_SECRETKEYBYTES];

	response->public_চাবি = ফাঁকা;
	response->public_চাবি_len = 0;
	response->চাবি_handle = ফাঁকা;
	response->চাবি_handle_len = 0;

	memset(pk, 0, আকার(pk));
	memset(sk, 0, আকার(sk));
	crypto_sign_ed25519_keypair(pk, sk);

	response->public_চাবি_len = আকার(pk);
	যদি ((response->public_চাবি = malloc(response->public_চাবি_len)) == ফাঁকা) {
		skdebug(__func__, "malloc pubkey failed");
		যাও out;
	}
	memcpy(response->public_চাবি, pk, আকার(pk));
	/* Key handle contains sk */
	response->চাবি_handle_len = আকার(sk);
	যদি ((response->চাবি_handle = malloc(response->চাবি_handle_len)) == ফাঁকা) {
		skdebug(__func__, "malloc key_handle failed");
		যাও out;
	}
	memcpy(response->চাবি_handle, sk, আকার(sk));
	/* success */
	ret = 0;
 out:
	যদি (ret != 0)
		মুক্ত(response->public_চাবি);
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
check_options(কাঠামো sk_option **options)
{
	আকার_t i;

	যদি (options == ফাঁকা)
		ফেরত 0;
	জন্য (i = 0; options[i] != ফাঁকা; i++) {
		skdebug(__func__, "requested unsupported option %s",
		    options[i]->name);
		যদি (options[i]->required) {
			skdebug(__func__, "unknown required option");
			ফেরত -1;
		}
	}
	ফেরত 0;
}

পূর্ণসংখ্যা
sk_enroll(uint32_t alg, ধ্রুবক uint8_t *challenge, আকার_t challenge_len,
    ধ্রুবক অক্ষর *application, uint8_t flags, ধ্রুবক অক্ষর *pin,
    কাঠামো sk_option **options, কাঠামো sk_enroll_response **enroll_response)
{
	কাঠামো sk_enroll_response *response = ফাঁকা;
	পূর্ণসংখ্যা ret = SSH_SK_ERR_GENERAL;

	(শূন্য)flags; /* XXX; unused */

	যদি (enroll_response == ফাঁকা) {
		skdebug(__func__, "enroll_response == NULL");
		যাও out;
	}
	*enroll_response = ফাঁকা;
	যদি (check_options(options) != 0)
		যাও out; /* error already logged */
	যদি ((response = calloc(1, আকার(*response))) == ফাঁকা) {
		skdebug(__func__, "calloc response failed");
		যাও out;
	}
	response->flags = flags;
	নির্বাচন(alg) {
	ক্ষেত্র SSH_SK_ECDSA:
		যদি (pack_চাবি_ecdsa(response) != 0)
			যাও out;
		বিরতি;
	ক্ষেত্র SSH_SK_ED25519:
		যদি (pack_চাবি_ed25519(response) != 0)
			যাও out;
		বিরতি;
	পূর্বনির্ধারিত:
		skdebug(__func__, "unsupported key type %d", alg);
		যাও out;
	}
	/* Have to return something here */
	যদি ((response->signature = calloc(1, 1)) == ফাঁকা) {
		skdebug(__func__, "calloc signature failed");
		যাও out;
	}
	response->signature_len = 0;

	*enroll_response = response;
	response = ফাঁকা;
	ret = 0;
 out:
	যদি (response != ফাঁকা) {
		মুক্ত(response->public_চাবি);
		মুক্ত(response->চাবি_handle);
		মুক্ত(response->signature);
		মুক্ত(response->attestation_cert);
		মুক্ত(response);
	}
	ফেরত ret;
}

স্থির শূন্য
dump(ধ্রুবক অক্ষর *preamble, ধ্রুবক শূন্য *sv, আকার_t l)
{
#ifdef SK_DEBUG
	ধ্রুবক u_char *s = (ধ্রুবক u_char *)sv;
	আকার_t i;

	fprintf(stderr, "%s (len %zu):\n", preamble, l);
	জন্য (i = 0; i < l; i++) {
		যদি (i % 16 == 0)
			fprintf(stderr, "%04zu: ", i);
		fprintf(stderr, "%02x", s[i]);
		যদি (i % 16 == 15 || i == l - 1)
			fprintf(stderr, "\n");
	}
#endif
}

স্থির পূর্ণসংখ্যা
sig_ecdsa(ধ্রুবক uint8_t *message, আকার_t message_len,
    ধ্রুবক অক্ষর *application, uint32_t গণক, uint8_t flags,
    ধ্রুবক uint8_t *চাবি_handle, আকার_t চাবি_handle_len,
    কাঠামো sk_sign_response *response)
{
#ifdef WITH_OPENSSL
	ECDSA_SIG *sig = ফাঁকা;
	ধ্রুবক BIGNUM *sig_r, *sig_s;
	পূর্ণসংখ্যা ret = -1;
	BIO *bio = ফাঁকা;
	EVP_PKEY *pk = ফাঁকা;
	EC_চাবি *ec = ফাঁকা;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_দৈর্ঘ্য];
	uint8_t	sighash[SHA256_DIGEST_দৈর্ঘ্য];
	uint8_t countbuf[4];

	/* Decode EC_KEY from key handle */
	যদি ((bio = BIO_new(BIO_s_mem())) == ফাঁকা ||
	    BIO_write(bio, চাবি_handle, চাবি_handle_len) != (পূর্ণসংখ্যা)চাবি_handle_len) {
		skdebug(__func__, "BIO setup failed");
		যাও out;
	}
	যদি ((pk = PEM_read_bio_Private_চাবি(bio, ফাঁকা, ফাঁকা, "")) == ফাঁকা) {
		skdebug(__func__, "PEM_read_bio_PrivateKey failed");
		যাও out;
	}
	যদি (EVP_PKEY_base_id(pk) != EVP_PKEY_EC) {
		skdebug(__func__, "Not an EC key: %d", EVP_PKEY_base_id(pk));
		যাও out;
	}
	যদি ((ec = EVP_PKEY_get1_EC_চাবি(pk)) == ফাঁকা) {
		skdebug(__func__, "EVP_PKEY_get1_EC_KEY failed");
		যাও out;
	}
	/* Expect message to be pre-hashed */
	যদি (message_len != SHA256_DIGEST_দৈর্ঘ্য) {
		skdebug(__func__, "bad message len %zu", message_len);
		যাও out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ধ্রুবক u_char *)application, strlen(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, আকার(apphash));
	countbuf[0] = (গণক >> 24) & 0xff;
	countbuf[1] = (গণক >> 16) & 0xff;
	countbuf[2] = (গণক >> 8) & 0xff;
	countbuf[3] = গণক & 0xff;
	dump("countbuf", countbuf, আকার(countbuf));
	dump("flags", &flags, আকার(flags));
	SHA256Init(&ctx);
	SHA256Update(&ctx, apphash, আকার(apphash));
	SHA256Update(&ctx, &flags, আকার(flags));
	SHA256Update(&ctx, countbuf, আকার(countbuf));
	SHA256Update(&ctx, message, message_len);
	SHA256Final(sighash, &ctx);
	dump("sighash", sighash, আকার(sighash));
	/* create and encode signature */
	যদি ((sig = ECDSA_do_sign(sighash, আকার(sighash), ec)) == ফাঁকা) {
		skdebug(__func__, "ECDSA_do_sign failed");
		যাও out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_অঙ্ক_bytes(sig_r);
	response->sig_s_len = BN_অঙ্ক_bytes(sig_s);
	যদি ((response->sig_r = calloc(1, response->sig_r_len)) == ফাঁকা ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == ফাঁকা) {
		skdebug(__func__, "calloc signature failed");
		যাও out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	explicit_bzero(&ctx, আকার(ctx));
	explicit_bzero(&apphash, আকার(apphash));
	explicit_bzero(&sighash, আকার(sighash));
	ECDSA_SIG_free(sig);
	যদি (ret != 0) {
		মুক্ত(response->sig_r);
		মুক্ত(response->sig_s);
		response->sig_r = ফাঁকা;
		response->sig_s = ফাঁকা;
	}
	BIO_free(bio);
	EC_চাবি_free(ec);
	EVP_PKEY_free(pk);
	ফেরত ret;
#অন্যথা
	ফেরত -1;
#endif
}

স্থির পূর্ণসংখ্যা
sig_ed25519(ধ্রুবক uint8_t *message, আকার_t message_len,
    ধ্রুবক অক্ষর *application, uint32_t গণক, uint8_t flags,
    ধ্রুবক uint8_t *চাবি_handle, আকার_t চাবি_handle_len,
    কাঠামো sk_sign_response *response)
{
	আকার_t o;
	পূর্ণসংখ্যা ret = -1;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_দৈর্ঘ্য];
	uint8_t signbuf[আকার(apphash) + আকার(flags) +
	    আকার(গণক) + SHA256_DIGEST_দৈর্ঘ্য];
	uint8_t sig[crypto_sign_ed25519_BYTES];
	unsigned long long siglen = 0;

	যদি (চাবি_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		skdebug(__func__, "bad key handle length %zu", চাবি_handle_len);
		যাও out;
	}
	/* Expect message to be pre-hashed */
	যদি (message_len != SHA256_DIGEST_দৈর্ঘ্য) {
		skdebug(__func__, "bad message len %zu", message_len);
		যাও out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ধ্রুবক u_char *)application, strlen(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, আকার(apphash));

	memcpy(signbuf, apphash, আকার(apphash));
	o = আকার(apphash);
	signbuf[o++] = flags;
	signbuf[o++] = (গণক >> 24) & 0xff;
	signbuf[o++] = (গণক >> 16) & 0xff;
	signbuf[o++] = (গণক >> 8) & 0xff;
	signbuf[o++] = গণক & 0xff;
	memcpy(signbuf + o, message, message_len);
	o += message_len;
	যদি (o != আকার(signbuf)) {
		skdebug(__func__, "bad sign buf len %zu, expected %zu",
		    o, আকার(signbuf));
		যাও out;
	}
	dump("signbuf", signbuf, আকার(signbuf));
	/* create and encode signature */
	যদি (crypto_sign_ed25519_detached(sig, &siglen, signbuf, আকার(signbuf),
	    চাবি_handle) != 0) {
		skdebug(__func__, "crypto_sign_ed25519_detached failed");
		যাও out;
	}
	যদি (siglen != আকার(sig)) {
		skdebug(__func__, "bad signature length %llu", siglen);
		যাও out;
	}
	response->sig_r_len = আকার(sig);
	যদি ((response->sig_r = calloc(1, response->sig_r_len)) == ফাঁকা) {
		skdebug(__func__, "calloc signature failed");
		যাও out;
	}
	memcpy(response->sig_r, sig, response->sig_r_len);
	dump("sig_r", response->sig_r, response->sig_r_len);
	ret = 0;
 out:
	explicit_bzero(&ctx, আকার(ctx));
	explicit_bzero(&apphash, আকার(apphash));
	explicit_bzero(&signbuf, আকার(signbuf));
	explicit_bzero(&sig, আকার(sig));
	যদি (ret != 0) {
		মুক্ত(response->sig_r);
		response->sig_r = ফাঁকা;
	}
	ফেরত ret;
}

পূর্ণসংখ্যা
sk_sign(uint32_t alg, ধ্রুবক uint8_t *তথ্য, আকার_t datalen,
    ধ্রুবক অক্ষর *application, ধ্রুবক uint8_t *চাবি_handle, আকার_t চাবি_handle_len,
    uint8_t flags, ধ্রুবক অক্ষর *pin, কাঠামো sk_option **options,
    কাঠামো sk_sign_response **sign_response)
{
	কাঠামো sk_sign_response *response = ফাঁকা;
	পূর্ণসংখ্যা ret = SSH_SK_ERR_GENERAL;
	SHA2_CTX ctx;
	uint8_t message[32];

	যদি (sign_response == ফাঁকা) {
		skdebug(__func__, "sign_response == NULL");
		যাও out;
	}
	*sign_response = ফাঁকা;
	যদি (check_options(options) != 0)
		যাও out; /* error already logged */
	যদি ((response = calloc(1, আকার(*response))) == ফাঁকা) {
		skdebug(__func__, "calloc response failed");
		যাও out;
	}
	SHA256Init(&ctx);
	SHA256Update(&ctx, তথ্য, datalen);
	SHA256Final(message, &ctx);
	response->flags = flags;
	response->গণক = 0x12345678;
	নির্বাচন(alg) {
	ক্ষেত্র SSH_SK_ECDSA:
		যদি (sig_ecdsa(message, আকার(message), application,
		    response->গণক, flags, চাবি_handle, চাবি_handle_len,
		    response) != 0)
			যাও out;
		বিরতি;
	ক্ষেত্র SSH_SK_ED25519:
		যদি (sig_ed25519(message, আকার(message), application,
		    response->গণক, flags, চাবি_handle, চাবি_handle_len,
		    response) != 0)
			যাও out;
		বিরতি;
	পূর্বনির্ধারিত:
		skdebug(__func__, "unsupported key type %d", alg);
		যাও out;
	}
	*sign_response = response;
	response = ফাঁকা;
	ret = 0;
 out:
	explicit_bzero(message, আকার(message));
	যদি (response != ফাঁকা) {
		মুক্ত(response->sig_r);
		মুক্ত(response->sig_s);
		মুক্ত(response);
	}
	ফেরত ret;
}

পূর্ণসংখ্যা
sk_load_resident_চাবিগুলি(ধ্রুবক অক্ষর *pin, কাঠামো sk_option **options,
    কাঠামো sk_resident_চাবি ***rks, আকার_t *nrks)
{
	ফেরত SSH_SK_ERR_UNSUPPORTED;
}
