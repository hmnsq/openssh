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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>

#ଅନ୍ତର୍ଭାଵ "crypto_api.h"
#ଅନ୍ତର୍ଭାଵ "sk-api.h"

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ <openssl/opensslv.h>
#ଅନ୍ତର୍ଭାଵ <openssl/sha.h>
#ଅନ୍ତର୍ଭାଵ <openssl/crypto.h>
#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>
#ଅନ୍ତର୍ଭାଵ <openssl/bn.h>
#ଅନ୍ତର୍ଭାଵ <openssl/ec.h>
#ଅନ୍ତର୍ଭାଵ <openssl/ecdsa.h>
#ଅନ୍ତର୍ଭାଵ <openssl/pem.h>

/* Use OpenSSL SHA256 instead of libc */
#define SHA256Init(x)		SHA256_Init(x)
#define SHA256Update(x, y, z)	SHA256_Update(x, y, z)
#define SHA256Final(x, y)	SHA256_Final(x, y)
#define SHA2_CTX		SHA256_CTX

#ନଚେତଯଦି defined(HAVE_SHA2_H)
#ଅନ୍ତର୍ଭାଵ <sha2.h>
#endif /* WITH_OPENSSL */

/* #define SK_DEBUG 1 */

#ଯଦି SSH_SK_VERSION_MAJOR != 0x000a0000
# error SK API has changed, sk-dummy.c needs an update
#endif

#ifdef SK_DUMMY_INTEGRATE
# define sk_api_version		ssh_sk_api_version
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_load_resident_ଚାବିଗୁଡ଼ିକ	ssh_sk_load_resident_ଚାବିଗୁଡ଼ିକ
#endif /* !SK_STANDALONE */

ସ୍ଥିର ଶୂନ୍ୟ skdebug(ଅଚଳ ଅକ୍ଷର *func, ଅଚଳ ଅକ୍ଷର *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

ସ୍ଥିର ଶୂନ୍ୟ
skdebug(ଅଚଳ ଅକ୍ଷର *func, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
#ଯଦି defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "sk-dummy %s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#ଅନ୍ୟଥା
	(ଶୂନ୍ୟ)func; /* XXX */
	(ଶୂନ୍ୟ)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(ଶୂନ୍ୟ)
{
	ଫେରନ୍ତୁ SSH_SK_VERSION_MAJOR;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pack_ଚାବି_ecdsa(ସଂରଚନା sk_enroll_response *response)
{
#ifdef WITH_OPENSSL
	EC_ଚାବି *ଚାବି = ଖାଲି;
	ଅଚଳ EC_GROUP *g;
	ଅଚଳ EC_POINT *q;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;
	long privlen;
	BIO *bio = ଖାଲି;
	ଅକ୍ଷର *privptr;

	response->public_ଚାବି = ଖାଲି;
	response->public_ଚାବି_len = 0;
	response->ଚାବି_handle = ଖାଲି;
	response->ଚାବି_handle_len = 0;

	ଯଦି ((ଚାବି = EC_ଚାବି_new_by_curve_name(NID_X9_62_prime256v1)) == ଖାଲି) {
		skdebug(__func__, "EC_KEY_new_by_curve_name");
		ଯାଅ out;
	}
	ଯଦି (EC_ଚାବି_generate_ଚାବି(ଚାବି) != 1) {
		skdebug(__func__, "EC_KEY_generate_key");
		ଯାଅ out;
	}
	EC_ଚାବି_set_asn1_flag(ଚାବି, OPENSSL_EC_NAMED_CURVE);
	ଯଦି ((bio = BIO_new(BIO_s_mem())) == ଖାଲି ||
	    (g = EC_ଚାବି_get0_group(ଚାବି)) == ଖାଲି ||
	    (q = EC_ଚାବି_get0_public_ଚାବି(ଚାବି)) == ଖାଲି) {
		skdebug(__func__, "couldn't get key parameters");
		ଯାଅ out;
	}
	response->public_ଚାବି_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, ଖାଲି, 0, ଖାଲି);
	ଯଦି (response->public_ଚାବି_len == 0 || response->public_ଚାବି_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_ଚାବି_len);
		ଯାଅ out;
	}
	ଯଦି ((response->public_ଚାବି = malloc(response->public_ଚାବି_len)) == ଖାଲି) {
		skdebug(__func__, "malloc pubkey failed");
		ଯାଅ out;
	}
	ଯଦି (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_ଚାବି, response->public_ଚାବି_len, ଖାଲି) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		ଯାଅ out;
	}
	/* Key handle contains PEM encoded private key */
	ଯଦି (!PEM_write_bio_ECPrivate_ଚାବି(bio, ଚାବି, ଖାଲି, ଖାଲି, 0, ଖାଲି, ଖାଲି)) {
		skdebug(__func__, "PEM_write_bio_ECPrivateKey failed");
		ଯାଅ out;
	}
	ଯଦି ((privlen = BIO_get_mem_data(bio, &privptr)) <= 0) {
		skdebug(__func__, "BIO_get_mem_data failed");
		ଯାଅ out;
	}
	ଯଦି ((response->ଚାବି_handle = malloc(privlen)) == ଖାଲି) {
		skdebug(__func__, "malloc key_handle failed");
		ଯାଅ out;
	}
	response->ଚାବି_handle_len = (size_t)privlen;
	memcpy(response->ଚାବି_handle, privptr, response->ଚାବି_handle_len);
	/* success */
	ret = 0;
 out:
	ଯଦି (ret != 0) {
		ଯଦି (response->public_ଚାବି != ଖାଲି) {
			memset(response->public_ଚାବି, 0,
			    response->public_ଚାବି_len);
			ମୁକ୍ତ(response->public_ଚାବି);
			response->public_ଚାବି = ଖାଲି;
		}
		ଯଦି (response->ଚାବି_handle != ଖାଲି) {
			memset(response->ଚାବି_handle, 0,
			    response->ଚାବି_handle_len);
			ମୁକ୍ତ(response->ଚାବି_handle);
			response->ଚାବି_handle = ଖାଲି;
		}
	}
	BIO_free(bio);
	EC_ଚାବି_free(ଚାବି);
	ଫେରନ୍ତୁ ret;
#ଅନ୍ୟଥା
	ଫେରନ୍ତୁ -1;
#endif
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pack_ଚାବି_ed25519(ସଂରଚନା sk_enroll_response *response)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;
	u_char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	u_char sk[crypto_sign_ed25519_SECRETKEYBYTES];

	response->public_ଚାବି = ଖାଲି;
	response->public_ଚାବି_len = 0;
	response->ଚାବି_handle = ଖାଲି;
	response->ଚାବି_handle_len = 0;

	memset(pk, 0, ଆକାର(pk));
	memset(sk, 0, ଆକାର(sk));
	crypto_sign_ed25519_keypair(pk, sk);

	response->public_ଚାବି_len = ଆକାର(pk);
	ଯଦି ((response->public_ଚାବି = malloc(response->public_ଚାବି_len)) == ଖାଲି) {
		skdebug(__func__, "malloc pubkey failed");
		ଯାଅ out;
	}
	memcpy(response->public_ଚାବି, pk, ଆକାର(pk));
	/* Key handle contains sk */
	response->ଚାବି_handle_len = ଆକାର(sk);
	ଯଦି ((response->ଚାବି_handle = malloc(response->ଚାବି_handle_len)) == ଖାଲି) {
		skdebug(__func__, "malloc key_handle failed");
		ଯାଅ out;
	}
	memcpy(response->ଚାବି_handle, sk, ଆକାର(sk));
	/* success */
	ret = 0;
 out:
	ଯଦି (ret != 0)
		ମୁକ୍ତ(response->public_ଚାବି);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
check_options(ସଂରଚନା sk_option **options)
{
	size_t i;

	ଯଦି (options == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ପାଇଁ (i = 0; options[i] != ଖାଲି; i++) {
		skdebug(__func__, "requested unsupported option %s",
		    options[i]->name);
		ଯଦି (options[i]->required) {
			skdebug(__func__, "unknown required option");
			ଫେରନ୍ତୁ -1;
		}
	}
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sk_enroll(uint32_t alg, ଅଚଳ uint8_t *challenge, size_t challenge_len,
    ଅଚଳ ଅକ୍ଷର *application, uint8_t flags, ଅଚଳ ଅକ୍ଷର *pin,
    ସଂରଚନା sk_option **options, ସଂରଚନା sk_enroll_response **enroll_response)
{
	ସଂରଚନା sk_enroll_response *response = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = SSH_SK_ERR_GENERAL;

	(ଶୂନ୍ୟ)flags; /* XXX; unused */

	ଯଦି (enroll_response == ଖାଲି) {
		skdebug(__func__, "enroll_response == NULL");
		ଯାଅ out;
	}
	*enroll_response = ଖାଲି;
	ଯଦି (check_options(options) != 0)
		ଯାଅ out; /* error already logged */
	ଯଦି ((response = calloc(1, ଆକାର(*response))) == ଖାଲି) {
		skdebug(__func__, "calloc response failed");
		ଯାଅ out;
	}
	response->flags = flags;
	ବାଛ(alg) {
	ସ୍ଥିତି SSH_SK_ECDSA:
		ଯଦି (pack_ଚାବି_ecdsa(response) != 0)
			ଯାଅ out;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH_SK_ED25519:
		ଯଦି (pack_ଚାବି_ed25519(response) != 0)
			ଯାଅ out;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		skdebug(__func__, "unsupported key type %d", alg);
		ଯାଅ out;
	}
	/* Have to return something here */
	ଯଦି ((response->signature = calloc(1, 1)) == ଖାଲି) {
		skdebug(__func__, "calloc signature failed");
		ଯାଅ out;
	}
	response->signature_len = 0;

	*enroll_response = response;
	response = ଖାଲି;
	ret = 0;
 out:
	ଯଦି (response != ଖାଲି) {
		ମୁକ୍ତ(response->public_ଚାବି);
		ମୁକ୍ତ(response->ଚାବି_handle);
		ମୁକ୍ତ(response->signature);
		ମୁକ୍ତ(response->attestation_cert);
		ମୁକ୍ତ(response);
	}
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ଶୂନ୍ୟ
dump(ଅଚଳ ଅକ୍ଷର *preamble, ଅଚଳ ଶୂନ୍ୟ *sv, size_t l)
{
#ifdef SK_DEBUG
	ଅଚଳ u_char *s = (ଅଚଳ u_char *)sv;
	size_t i;

	fprintf(stderr, "%s (len %zu):\n", preamble, l);
	ପାଇଁ (i = 0; i < l; i++) {
		ଯଦି (i % 16 == 0)
			fprintf(stderr, "%04zu: ", i);
		fprintf(stderr, "%02x", s[i]);
		ଯଦି (i % 16 == 15 || i == l - 1)
			fprintf(stderr, "\n");
	}
#endif
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sig_ecdsa(ଅଚଳ uint8_t *message, size_t message_len,
    ଅଚଳ ଅକ୍ଷର *application, uint32_t counter, uint8_t flags,
    ଅଚଳ uint8_t *ଚାବି_handle, size_t ଚାବି_handle_len,
    ସଂରଚନା sk_sign_response *response)
{
#ifdef WITH_OPENSSL
	ECDSA_SIG *sig = ଖାଲି;
	ଅଚଳ BIGNUM *sig_r, *sig_s;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;
	BIO *bio = ଖାଲି;
	EVP_PKEY *pk = ଖାଲି;
	EC_ଚାବି *ec = ଖାଲି;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_LENGTH];
	uint8_t	sighash[SHA256_DIGEST_LENGTH];
	uint8_t countbuf[4];

	/* Decode EC_KEY from key handle */
	ଯଦି ((bio = BIO_new(BIO_s_mem())) == ଖାଲି ||
	    BIO_write(bio, ଚାବି_handle, ଚାବି_handle_len) != (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)ଚାବି_handle_len) {
		skdebug(__func__, "BIO setup failed");
		ଯାଅ out;
	}
	ଯଦି ((pk = PEM_read_bio_Private_ଚାବି(bio, ଖାଲି, ଖାଲି, "")) == ଖାଲି) {
		skdebug(__func__, "PEM_read_bio_PrivateKey failed");
		ଯାଅ out;
	}
	ଯଦି (EVP_PKEY_base_id(pk) != EVP_PKEY_EC) {
		skdebug(__func__, "Not an EC key: %d", EVP_PKEY_base_id(pk));
		ଯାଅ out;
	}
	ଯଦି ((ec = EVP_PKEY_get1_EC_ଚାବି(pk)) == ଖାଲି) {
		skdebug(__func__, "EVP_PKEY_get1_EC_KEY failed");
		ଯାଅ out;
	}
	/* Expect message to be pre-hashed */
	ଯଦି (message_len != SHA256_DIGEST_LENGTH) {
		skdebug(__func__, "bad message len %zu", message_len);
		ଯାଅ out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ଅଚଳ u_char *)application, strlen(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, ଆକାର(apphash));
	countbuf[0] = (counter >> 24) & 0xff;
	countbuf[1] = (counter >> 16) & 0xff;
	countbuf[2] = (counter >> 8) & 0xff;
	countbuf[3] = counter & 0xff;
	dump("countbuf", countbuf, ଆକାର(countbuf));
	dump("flags", &flags, ଆକାର(flags));
	SHA256Init(&ctx);
	SHA256Update(&ctx, apphash, ଆକାର(apphash));
	SHA256Update(&ctx, &flags, ଆକାର(flags));
	SHA256Update(&ctx, countbuf, ଆକାର(countbuf));
	SHA256Update(&ctx, message, message_len);
	SHA256Final(sighash, &ctx);
	dump("sighash", sighash, ଆକାର(sighash));
	/* create and encode signature */
	ଯଦି ((sig = ECDSA_do_sign(sighash, ଆକାର(sighash), ec)) == ଖାଲି) {
		skdebug(__func__, "ECDSA_do_sign failed");
		ଯାଅ out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_ଅଙ୍କ_bytes(sig_r);
	response->sig_s_len = BN_ଅଙ୍କ_bytes(sig_s);
	ଯଦି ((response->sig_r = calloc(1, response->sig_r_len)) == ଖାଲି ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == ଖାଲି) {
		skdebug(__func__, "calloc signature failed");
		ଯାଅ out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	explicit_bzero(&ctx, ଆକାର(ctx));
	explicit_bzero(&apphash, ଆକାର(apphash));
	explicit_bzero(&sighash, ଆକାର(sighash));
	ECDSA_SIG_free(sig);
	ଯଦି (ret != 0) {
		ମୁକ୍ତ(response->sig_r);
		ମୁକ୍ତ(response->sig_s);
		response->sig_r = ଖାଲି;
		response->sig_s = ଖାଲି;
	}
	BIO_free(bio);
	EC_ଚାବି_free(ec);
	EVP_PKEY_free(pk);
	ଫେରନ୍ତୁ ret;
#ଅନ୍ୟଥା
	ଫେରନ୍ତୁ -1;
#endif
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sig_ed25519(ଅଚଳ uint8_t *message, size_t message_len,
    ଅଚଳ ଅକ୍ଷର *application, uint32_t counter, uint8_t flags,
    ଅଚଳ uint8_t *ଚାବି_handle, size_t ଚାବି_handle_len,
    ସଂରଚନା sk_sign_response *response)
{
	size_t o;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_LENGTH];
	uint8_t signbuf[ଆକାର(apphash) + ଆକାର(flags) +
	    ଆକାର(counter) + SHA256_DIGEST_LENGTH];
	uint8_t sig[crypto_sign_ed25519_BYTES];
	unsigned long long siglen = 0;

	ଯଦି (ଚାବି_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		skdebug(__func__, "bad key handle length %zu", ଚାବି_handle_len);
		ଯାଅ out;
	}
	/* Expect message to be pre-hashed */
	ଯଦି (message_len != SHA256_DIGEST_LENGTH) {
		skdebug(__func__, "bad message len %zu", message_len);
		ଯାଅ out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ଅଚଳ u_char *)application, strlen(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, ଆକାର(apphash));

	memcpy(signbuf, apphash, ଆକାର(apphash));
	o = ଆକାର(apphash);
	signbuf[o++] = flags;
	signbuf[o++] = (counter >> 24) & 0xff;
	signbuf[o++] = (counter >> 16) & 0xff;
	signbuf[o++] = (counter >> 8) & 0xff;
	signbuf[o++] = counter & 0xff;
	memcpy(signbuf + o, message, message_len);
	o += message_len;
	ଯଦି (o != ଆକାର(signbuf)) {
		skdebug(__func__, "bad sign buf len %zu, expected %zu",
		    o, ଆକାର(signbuf));
		ଯାଅ out;
	}
	dump("signbuf", signbuf, ଆକାର(signbuf));
	/* create and encode signature */
	ଯଦି (crypto_sign_ed25519_detached(sig, &siglen, signbuf, ଆକାର(signbuf),
	    ଚାବି_handle) != 0) {
		skdebug(__func__, "crypto_sign_ed25519_detached failed");
		ଯାଅ out;
	}
	ଯଦି (siglen != ଆକାର(sig)) {
		skdebug(__func__, "bad signature length %llu", siglen);
		ଯାଅ out;
	}
	response->sig_r_len = ଆକାର(sig);
	ଯଦି ((response->sig_r = calloc(1, response->sig_r_len)) == ଖାଲି) {
		skdebug(__func__, "calloc signature failed");
		ଯାଅ out;
	}
	memcpy(response->sig_r, sig, response->sig_r_len);
	dump("sig_r", response->sig_r, response->sig_r_len);
	ret = 0;
 out:
	explicit_bzero(&ctx, ଆକାର(ctx));
	explicit_bzero(&apphash, ଆକାର(apphash));
	explicit_bzero(&signbuf, ଆକାର(signbuf));
	explicit_bzero(&sig, ଆକାର(sig));
	ଯଦି (ret != 0) {
		ମୁକ୍ତ(response->sig_r);
		response->sig_r = ଖାଲି;
	}
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sk_sign(uint32_t alg, ଅଚଳ uint8_t *data, size_t datalen,
    ଅଚଳ ଅକ୍ଷର *application, ଅଚଳ uint8_t *ଚାବି_handle, size_t ଚାବି_handle_len,
    uint8_t flags, ଅଚଳ ଅକ୍ଷର *pin, ସଂରଚନା sk_option **options,
    ସଂରଚନା sk_sign_response **sign_response)
{
	ସଂରଚନା sk_sign_response *response = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = SSH_SK_ERR_GENERAL;
	SHA2_CTX ctx;
	uint8_t message[32];

	ଯଦି (sign_response == ଖାଲି) {
		skdebug(__func__, "sign_response == NULL");
		ଯାଅ out;
	}
	*sign_response = ଖାଲି;
	ଯଦି (check_options(options) != 0)
		ଯାଅ out; /* error already logged */
	ଯଦି ((response = calloc(1, ଆକାର(*response))) == ଖାଲି) {
		skdebug(__func__, "calloc response failed");
		ଯାଅ out;
	}
	SHA256Init(&ctx);
	SHA256Update(&ctx, data, datalen);
	SHA256Final(message, &ctx);
	response->flags = flags;
	response->counter = 0x12345678;
	ବାଛ(alg) {
	ସ୍ଥିତି SSH_SK_ECDSA:
		ଯଦି (sig_ecdsa(message, ଆକାର(message), application,
		    response->counter, flags, ଚାବି_handle, ଚାବି_handle_len,
		    response) != 0)
			ଯାଅ out;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH_SK_ED25519:
		ଯଦି (sig_ed25519(message, ଆକାର(message), application,
		    response->counter, flags, ଚାବି_handle, ଚାବି_handle_len,
		    response) != 0)
			ଯାଅ out;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		skdebug(__func__, "unsupported key type %d", alg);
		ଯାଅ out;
	}
	*sign_response = response;
	response = ଖାଲି;
	ret = 0;
 out:
	explicit_bzero(message, ଆକାର(message));
	ଯଦି (response != ଖାଲି) {
		ମୁକ୍ତ(response->sig_r);
		ମୁକ୍ତ(response->sig_s);
		ମୁକ୍ତ(response);
	}
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sk_load_resident_ଚାବିଗୁଡ଼ିକ(ଅଚଳ ଅକ୍ଷର *pin, ସଂରଚନା sk_option **options,
    ସଂରଚନା sk_resident_ଚାବି ***rks, size_t *nrks)
{
	ଫେରନ୍ତୁ SSH_SK_ERR_UNSUPPORTED;
}
