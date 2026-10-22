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

#নোচেদ্যদি defined(HAVE_SHA2_H)
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

স্থির শূন্য skdebug(ধ্রুব বর্ণ *func, ধ্রুব বর্ণ *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

স্থির শূন্য
skdebug(ধ্রুব বর্ণ *func, ধ্রুব বর্ণ *fmt, ...)
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
	প্রত্যাগম SSH_SK_VERSION_MAJOR;
}

স্থির পূর্ণাঙ্ক
pack_চাবি_ecdsa(সংরচনা sk_enroll_response *response)
{
#ifdef WITH_OPENSSL
	EC_চাবি *চাবি = রিক্ত;
	ধ্রুব EC_GROUP *g;
	ধ্রুব EC_POINT *q;
	পূর্ণাঙ্ক ret = -1;
	long privlen;
	BIO *bio = রিক্ত;
	বর্ণ *privptr;

	response->public_চাবি = রিক্ত;
	response->public_চাবি_len = 0;
	response->চাবি_handle = রিক্ত;
	response->চাবি_handle_len = 0;

	যদি ((চাবি = EC_চাবি_new_by_curve_name(NID_X9_62_prime256v1)) == রিক্ত) {
		skdebug(__func__, "EC_KEY_new_by_curve_name");
		গচ্ছ out;
	}
	যদি (EC_চাবি_generate_চাবি(চাবি) != 1) {
		skdebug(__func__, "EC_KEY_generate_key");
		গচ্ছ out;
	}
	EC_চাবি_set_asn1_flag(চাবি, OPENSSL_EC_NAMED_CURVE);
	যদি ((bio = BIO_new(BIO_s_mem())) == রিক্ত ||
	    (g = EC_চাবি_get0_group(চাবি)) == রিক্ত ||
	    (q = EC_চাবি_get0_public_চাবি(চাবি)) == রিক্ত) {
		skdebug(__func__, "couldn't get key parameters");
		গচ্ছ out;
	}
	response->public_চাবি_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, রিক্ত, 0, রিক্ত);
	যদি (response->public_চাবি_len == 0 || response->public_চাবি_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_চাবি_len);
		গচ্ছ out;
	}
	যদি ((response->public_চাবি = malloc(response->public_চাবি_len)) == রিক্ত) {
		skdebug(__func__, "malloc pubkey failed");
		গচ্ছ out;
	}
	যদি (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_চাবি, response->public_চাবি_len, রিক্ত) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		গচ্ছ out;
	}
	/* Key handle contains PEM encoded private key */
	যদি (!PEM_write_bio_ECPrivate_চাবি(bio, চাবি, রিক্ত, রিক্ত, 0, রিক্ত, রিক্ত)) {
		skdebug(__func__, "PEM_write_bio_ECPrivateKey failed");
		গচ্ছ out;
	}
	যদি ((privlen = BIO_get_mem_data(bio, &privptr)) <= 0) {
		skdebug(__func__, "BIO_get_mem_data failed");
		গচ্ছ out;
	}
	যদি ((response->চাবি_handle = malloc(privlen)) == রিক্ত) {
		skdebug(__func__, "malloc key_handle failed");
		গচ্ছ out;
	}
	response->চাবি_handle_len = (size_t)privlen;
	memcpy(response->চাবি_handle, privptr, response->চাবি_handle_len);
	/* success */
	ret = 0;
 out:
	যদি (ret != 0) {
		যদি (response->public_চাবি != রিক্ত) {
			memset(response->public_চাবি, 0,
			    response->public_চাবি_len);
			মুক্ত(response->public_চাবি);
			response->public_চাবি = রিক্ত;
		}
		যদি (response->চাবি_handle != রিক্ত) {
			memset(response->চাবি_handle, 0,
			    response->চাবি_handle_len);
			মুক্ত(response->চাবি_handle);
			response->চাবি_handle = রিক্ত;
		}
	}
	BIO_free(bio);
	EC_চাবি_free(চাবি);
	প্রত্যাগম ret;
#অন্যথা
	প্রত্যাগম -1;
#endif
}

স্থির পূর্ণাঙ্ক
pack_চাবি_ed25519(সংরচনা sk_enroll_response *response)
{
	পূর্ণাঙ্ক ret = -1;
	u_char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	u_char sk[crypto_sign_ed25519_SECRETKEYBYTES];

	response->public_চাবি = রিক্ত;
	response->public_চাবি_len = 0;
	response->চাবি_handle = রিক্ত;
	response->চাবি_handle_len = 0;

	memset(pk, 0, পরিমাণ(pk));
	memset(sk, 0, পরিমাণ(sk));
	crypto_sign_ed25519_keypair(pk, sk);

	response->public_চাবি_len = পরিমাণ(pk);
	যদি ((response->public_চাবি = malloc(response->public_চাবি_len)) == রিক্ত) {
		skdebug(__func__, "malloc pubkey failed");
		গচ্ছ out;
	}
	memcpy(response->public_চাবি, pk, পরিমাণ(pk));
	/* Key handle contains sk */
	response->চাবি_handle_len = পরিমাণ(sk);
	যদি ((response->চাবি_handle = malloc(response->চাবি_handle_len)) == রিক্ত) {
		skdebug(__func__, "malloc key_handle failed");
		গচ্ছ out;
	}
	memcpy(response->চাবি_handle, sk, পরিমাণ(sk));
	/* success */
	ret = 0;
 out:
	যদি (ret != 0)
		মুক্ত(response->public_চাবি);
	প্রত্যাগম ret;
}

স্থির পূর্ণাঙ্ক
check_options(সংরচনা sk_option **options)
{
	size_t i;

	যদি (options == রিক্ত)
		প্রত্যাগম 0;
	প্রতি (i = 0; options[i] != রিক্ত; i++) {
		skdebug(__func__, "requested unsupported option %s",
		    options[i]->name);
		যদি (options[i]->required) {
			skdebug(__func__, "unknown required option");
			প্রত্যাগম -1;
		}
	}
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
sk_enroll(uint32_t alg, ধ্রুব uint8_t *challenge, size_t challenge_len,
    ধ্রুব বর্ণ *application, uint8_t flags, ধ্রুব বর্ণ *pin,
    সংরচনা sk_option **options, সংরচনা sk_enroll_response **enroll_response)
{
	সংরচনা sk_enroll_response *response = রিক্ত;
	পূর্ণাঙ্ক ret = SSH_SK_ERR_GENERAL;

	(শূন্য)flags; /* XXX; unused */

	যদি (enroll_response == রিক্ত) {
		skdebug(__func__, "enroll_response == NULL");
		গচ্ছ out;
	}
	*enroll_response = রিক্ত;
	যদি (check_options(options) != 0)
		গচ্ছ out; /* error already logged */
	যদি ((response = calloc(1, পরিমাণ(*response))) == রিক্ত) {
		skdebug(__func__, "calloc response failed");
		গচ্ছ out;
	}
	response->flags = flags;
	বিকল্প(alg) {
	পক্ষ SSH_SK_ECDSA:
		যদি (pack_চাবি_ecdsa(response) != 0)
			গচ্ছ out;
		ভঙ্গ;
	পক্ষ SSH_SK_ED25519:
		যদি (pack_চাবি_ed25519(response) != 0)
			গচ্ছ out;
		ভঙ্গ;
	স্বভাব:
		skdebug(__func__, "unsupported key type %d", alg);
		গচ্ছ out;
	}
	/* Have to return something here */
	যদি ((response->signature = calloc(1, 1)) == রিক্ত) {
		skdebug(__func__, "calloc signature failed");
		গচ্ছ out;
	}
	response->signature_len = 0;

	*enroll_response = response;
	response = রিক্ত;
	ret = 0;
 out:
	যদি (response != রিক্ত) {
		মুক্ত(response->public_চাবি);
		মুক্ত(response->চাবি_handle);
		মুক্ত(response->signature);
		মুক্ত(response->attestation_cert);
		মুক্ত(response);
	}
	প্রত্যাগম ret;
}

স্থির শূন্য
dump(ধ্রুব বর্ণ *preamble, ধ্রুব শূন্য *sv, size_t l)
{
#ifdef SK_DEBUG
	ধ্রুব u_char *s = (ধ্রুব u_char *)sv;
	size_t i;

	fprintf(stderr, "%s (len %zu):\n", preamble, l);
	প্রতি (i = 0; i < l; i++) {
		যদি (i % 16 == 0)
			fprintf(stderr, "%04zu: ", i);
		fprintf(stderr, "%02x", s[i]);
		যদি (i % 16 == 15 || i == l - 1)
			fprintf(stderr, "\n");
	}
#endif
}

স্থির পূর্ণাঙ্ক
sig_ecdsa(ধ্রুব uint8_t *message, size_t message_len,
    ধ্রুব বর্ণ *application, uint32_t counter, uint8_t flags,
    ধ্রুব uint8_t *চাবি_handle, size_t চাবি_handle_len,
    সংরচনা sk_sign_response *response)
{
#ifdef WITH_OPENSSL
	ECDSA_SIG *sig = রিক্ত;
	ধ্রুব BIGNUM *sig_r, *sig_s;
	পূর্ণাঙ্ক ret = -1;
	BIO *bio = রিক্ত;
	EVP_PKEY *pk = রিক্ত;
	EC_চাবি *ec = রিক্ত;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_LENGTH];
	uint8_t	sighash[SHA256_DIGEST_LENGTH];
	uint8_t countbuf[4];

	/* Decode EC_KEY from key handle */
	যদি ((bio = BIO_new(BIO_s_mem())) == রিক্ত ||
	    BIO_write(bio, চাবি_handle, চাবি_handle_len) != (পূর্ণাঙ্ক)চাবি_handle_len) {
		skdebug(__func__, "BIO setup failed");
		গচ্ছ out;
	}
	যদি ((pk = PEM_read_bio_Private_চাবি(bio, রিক্ত, রিক্ত, "")) == রিক্ত) {
		skdebug(__func__, "PEM_read_bio_PrivateKey failed");
		গচ্ছ out;
	}
	যদি (EVP_PKEY_base_id(pk) != EVP_PKEY_EC) {
		skdebug(__func__, "Not an EC key: %d", EVP_PKEY_base_id(pk));
		গচ্ছ out;
	}
	যদি ((ec = EVP_PKEY_get1_EC_চাবি(pk)) == রিক্ত) {
		skdebug(__func__, "EVP_PKEY_get1_EC_KEY failed");
		গচ্ছ out;
	}
	/* Expect message to be pre-hashed */
	যদি (message_len != SHA256_DIGEST_LENGTH) {
		skdebug(__func__, "bad message len %zu", message_len);
		গচ্ছ out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ধ্রুব u_char *)application, strlen(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, পরিমাণ(apphash));
	countbuf[0] = (counter >> 24) & 0xff;
	countbuf[1] = (counter >> 16) & 0xff;
	countbuf[2] = (counter >> 8) & 0xff;
	countbuf[3] = counter & 0xff;
	dump("countbuf", countbuf, পরিমাণ(countbuf));
	dump("flags", &flags, পরিমাণ(flags));
	SHA256Init(&ctx);
	SHA256Update(&ctx, apphash, পরিমাণ(apphash));
	SHA256Update(&ctx, &flags, পরিমাণ(flags));
	SHA256Update(&ctx, countbuf, পরিমাণ(countbuf));
	SHA256Update(&ctx, message, message_len);
	SHA256Final(sighash, &ctx);
	dump("sighash", sighash, পরিমাণ(sighash));
	/* create and encode signature */
	যদি ((sig = ECDSA_do_sign(sighash, পরিমাণ(sighash), ec)) == রিক্ত) {
		skdebug(__func__, "ECDSA_do_sign failed");
		গচ্ছ out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_অঙ্ক_bytes(sig_r);
	response->sig_s_len = BN_অঙ্ক_bytes(sig_s);
	যদি ((response->sig_r = calloc(1, response->sig_r_len)) == রিক্ত ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == রিক্ত) {
		skdebug(__func__, "calloc signature failed");
		গচ্ছ out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	explicit_bzero(&ctx, পরিমাণ(ctx));
	explicit_bzero(&apphash, পরিমাণ(apphash));
	explicit_bzero(&sighash, পরিমাণ(sighash));
	ECDSA_SIG_free(sig);
	যদি (ret != 0) {
		মুক্ত(response->sig_r);
		মুক্ত(response->sig_s);
		response->sig_r = রিক্ত;
		response->sig_s = রিক্ত;
	}
	BIO_free(bio);
	EC_চাবি_free(ec);
	EVP_PKEY_free(pk);
	প্রত্যাগম ret;
#অন্যথা
	প্রত্যাগম -1;
#endif
}

স্থির পূর্ণাঙ্ক
sig_ed25519(ধ্রুব uint8_t *message, size_t message_len,
    ধ্রুব বর্ণ *application, uint32_t counter, uint8_t flags,
    ধ্রুব uint8_t *চাবি_handle, size_t চাবি_handle_len,
    সংরচনা sk_sign_response *response)
{
	size_t o;
	পূর্ণাঙ্ক ret = -1;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_LENGTH];
	uint8_t signbuf[পরিমাণ(apphash) + পরিমাণ(flags) +
	    পরিমাণ(counter) + SHA256_DIGEST_LENGTH];
	uint8_t sig[crypto_sign_ed25519_BYTES];
	unsigned long long siglen = 0;

	যদি (চাবি_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		skdebug(__func__, "bad key handle length %zu", চাবি_handle_len);
		গচ্ছ out;
	}
	/* Expect message to be pre-hashed */
	যদি (message_len != SHA256_DIGEST_LENGTH) {
		skdebug(__func__, "bad message len %zu", message_len);
		গচ্ছ out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ধ্রুব u_char *)application, strlen(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, পরিমাণ(apphash));

	memcpy(signbuf, apphash, পরিমাণ(apphash));
	o = পরিমাণ(apphash);
	signbuf[o++] = flags;
	signbuf[o++] = (counter >> 24) & 0xff;
	signbuf[o++] = (counter >> 16) & 0xff;
	signbuf[o++] = (counter >> 8) & 0xff;
	signbuf[o++] = counter & 0xff;
	memcpy(signbuf + o, message, message_len);
	o += message_len;
	যদি (o != পরিমাণ(signbuf)) {
		skdebug(__func__, "bad sign buf len %zu, expected %zu",
		    o, পরিমাণ(signbuf));
		গচ্ছ out;
	}
	dump("signbuf", signbuf, পরিমাণ(signbuf));
	/* create and encode signature */
	যদি (crypto_sign_ed25519_detached(sig, &siglen, signbuf, পরিমাণ(signbuf),
	    চাবি_handle) != 0) {
		skdebug(__func__, "crypto_sign_ed25519_detached failed");
		গচ্ছ out;
	}
	যদি (siglen != পরিমাণ(sig)) {
		skdebug(__func__, "bad signature length %llu", siglen);
		গচ্ছ out;
	}
	response->sig_r_len = পরিমাণ(sig);
	যদি ((response->sig_r = calloc(1, response->sig_r_len)) == রিক্ত) {
		skdebug(__func__, "calloc signature failed");
		গচ্ছ out;
	}
	memcpy(response->sig_r, sig, response->sig_r_len);
	dump("sig_r", response->sig_r, response->sig_r_len);
	ret = 0;
 out:
	explicit_bzero(&ctx, পরিমাণ(ctx));
	explicit_bzero(&apphash, পরিমাণ(apphash));
	explicit_bzero(&signbuf, পরিমাণ(signbuf));
	explicit_bzero(&sig, পরিমাণ(sig));
	যদি (ret != 0) {
		মুক্ত(response->sig_r);
		response->sig_r = রিক্ত;
	}
	প্রত্যাগম ret;
}

পূর্ণাঙ্ক
sk_sign(uint32_t alg, ধ্রুব uint8_t *data, size_t datalen,
    ধ্রুব বর্ণ *application, ধ্রুব uint8_t *চাবি_handle, size_t চাবি_handle_len,
    uint8_t flags, ধ্রুব বর্ণ *pin, সংরচনা sk_option **options,
    সংরচনা sk_sign_response **sign_response)
{
	সংরচনা sk_sign_response *response = রিক্ত;
	পূর্ণাঙ্ক ret = SSH_SK_ERR_GENERAL;
	SHA2_CTX ctx;
	uint8_t message[32];

	যদি (sign_response == রিক্ত) {
		skdebug(__func__, "sign_response == NULL");
		গচ্ছ out;
	}
	*sign_response = রিক্ত;
	যদি (check_options(options) != 0)
		গচ্ছ out; /* error already logged */
	যদি ((response = calloc(1, পরিমাণ(*response))) == রিক্ত) {
		skdebug(__func__, "calloc response failed");
		গচ্ছ out;
	}
	SHA256Init(&ctx);
	SHA256Update(&ctx, data, datalen);
	SHA256Final(message, &ctx);
	response->flags = flags;
	response->counter = 0x12345678;
	বিকল্প(alg) {
	পক্ষ SSH_SK_ECDSA:
		যদি (sig_ecdsa(message, পরিমাণ(message), application,
		    response->counter, flags, চাবি_handle, চাবি_handle_len,
		    response) != 0)
			গচ্ছ out;
		ভঙ্গ;
	পক্ষ SSH_SK_ED25519:
		যদি (sig_ed25519(message, পরিমাণ(message), application,
		    response->counter, flags, চাবি_handle, চাবি_handle_len,
		    response) != 0)
			গচ্ছ out;
		ভঙ্গ;
	স্বভাব:
		skdebug(__func__, "unsupported key type %d", alg);
		গচ্ছ out;
	}
	*sign_response = response;
	response = রিক্ত;
	ret = 0;
 out:
	explicit_bzero(message, পরিমাণ(message));
	যদি (response != রিক্ত) {
		মুক্ত(response->sig_r);
		মুক্ত(response->sig_s);
		মুক্ত(response);
	}
	প্রত্যাগম ret;
}

পূর্ণাঙ্ক
sk_load_resident_চাবিগুলি(ধ্রুব বর্ণ *pin, সংরচনা sk_option **options,
    সংরচনা sk_resident_চাবি ***rks, size_t *nrks)
{
	প্রত্যাগম SSH_SK_ERR_UNSUPPORTED;
}
