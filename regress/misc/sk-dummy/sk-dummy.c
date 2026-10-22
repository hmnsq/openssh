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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdarg.h>

#अन्तर्भाव "crypto_api.h"
#अन्तर्भाव "sk-api.h"

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/opensslv.h>
#अन्तर्भाव <openssl/sha.h>
#अन्तर्भाव <openssl/crypto.h>
#अन्तर्भाव <openssl/evp.h>
#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/ec.h>
#अन्तर्भाव <openssl/ecdsa.h>
#अन्तर्भाव <openssl/pem.h>

/* Use OpenSSL SHA256 instead of libc */
#define SHA256Init(x)		SHA256_Init(x)
#define SHA256Update(x, y, z)	SHA256_Update(x, y, z)
#define SHA256Final(x, y)	SHA256_Final(x, y)
#define SHA2_CTX		SHA256_CTX

#नोचेद्यदि defined(HAVE_SHA2_H)
#अन्तर्भाव <sha2.h>
#endif /* WITH_OPENSSL */

/* #define SK_DEBUG 1 */

#सचे SSH_SK_VERSION_MAJOR != 0x000a0000
# error SK API has changed, sk-dummy.c needs an update
#endif

#ifdef SK_DUMMY_INTEGRATE
# define sk_api_version		ssh_sk_api_version
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_load_resident_कुञ्चिकाः	ssh_sk_load_resident_कुञ्चिकाः
#endif /* !SK_STANDALONE */

स्थिर शून्य skdebug(ध्रुव वर्ण *func, ध्रुव वर्ण *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

स्थिर शून्य
skdebug(ध्रुव वर्ण *func, ध्रुव वर्ण *fmt, ...)
{
#सचे defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "sk-dummy %s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#अञ्ञथा
	(शून्य)func; /* XXX */
	(शून्य)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(शून्य)
{
	पटिनिवत्त SSH_SK_VERSION_MAJOR;
}

स्थिर पूर्णाङ्क
pack_कुञ्चिका_ecdsa(संरचना sk_enroll_response *response)
{
#ifdef WITH_OPENSSL
	EC_कुञ्चिका *कुञ्चिका = रिक्त;
	ध्रुव EC_GROUP *g;
	ध्रुव EC_POINT *q;
	पूर्णाङ्क ret = -1;
	long privlen;
	BIO *bio = रिक्त;
	वर्ण *privptr;

	response->public_कुञ्चिका = रिक्त;
	response->public_कुञ्चिका_len = 0;
	response->कुञ्चिका_handle = रिक्त;
	response->कुञ्चिका_handle_len = 0;

	सचे ((कुञ्चिका = EC_कुञ्चिका_new_by_curve_name(NID_X9_62_prime256v1)) == रिक्त) {
		skdebug(__func__, "EC_KEY_new_by_curve_name");
		गच्छ out;
	}
	सचे (EC_कुञ्चिका_generate_कुञ्चिका(कुञ्चिका) != 1) {
		skdebug(__func__, "EC_KEY_generate_key");
		गच्छ out;
	}
	EC_कुञ्चिका_set_asn1_flag(कुञ्चिका, OPENSSL_EC_NAMED_CURVE);
	सचे ((bio = BIO_new(BIO_s_mem())) == रिक्त ||
	    (g = EC_कुञ्चिका_get0_group(कुञ्चिका)) == रिक्त ||
	    (q = EC_कुञ्चिका_get0_public_कुञ्चिका(कुञ्चिका)) == रिक्त) {
		skdebug(__func__, "couldn't get key parameters");
		गच्छ out;
	}
	response->public_कुञ्चिका_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, रिक्त, 0, रिक्त);
	सचे (response->public_कुञ्चिका_len == 0 || response->public_कुञ्चिका_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_कुञ्चिका_len);
		गच्छ out;
	}
	सचे ((response->public_कुञ्चिका = malloc(response->public_कुञ्चिका_len)) == रिक्त) {
		skdebug(__func__, "malloc pubkey failed");
		गच्छ out;
	}
	सचे (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_कुञ्चिका, response->public_कुञ्चिका_len, रिक्त) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		गच्छ out;
	}
	/* Key handle contains PEM encoded private key */
	सचे (!PEM_write_bio_ECPrivate_कुञ्चिका(bio, कुञ्चिका, रिक्त, रिक्त, 0, रिक्त, रिक्त)) {
		skdebug(__func__, "PEM_write_bio_ECPrivateKey failed");
		गच्छ out;
	}
	सचे ((privlen = BIO_get_mem_data(bio, &privptr)) <= 0) {
		skdebug(__func__, "BIO_get_mem_data failed");
		गच्छ out;
	}
	सचे ((response->कुञ्चिका_handle = malloc(privlen)) == रिक्त) {
		skdebug(__func__, "malloc key_handle failed");
		गच्छ out;
	}
	response->कुञ्चिका_handle_len = (size_t)privlen;
	memcpy(response->कुञ्चिका_handle, privptr, response->कुञ्चिका_handle_len);
	/* success */
	ret = 0;
 out:
	सचे (ret != 0) {
		सचे (response->public_कुञ्चिका != रिक्त) {
			memset(response->public_कुञ्चिका, 0,
			    response->public_कुञ्चिका_len);
			मुक्त(response->public_कुञ्चिका);
			response->public_कुञ्चिका = रिक्त;
		}
		सचे (response->कुञ्चिका_handle != रिक्त) {
			memset(response->कुञ्चिका_handle, 0,
			    response->कुञ्चिका_handle_len);
			मुक्त(response->कुञ्चिका_handle);
			response->कुञ्चिका_handle = रिक्त;
		}
	}
	BIO_free(bio);
	EC_कुञ्चिका_free(कुञ्चिका);
	पटिनिवत्त ret;
#अञ्ञथा
	पटिनिवत्त -1;
#endif
}

स्थिर पूर्णाङ्क
pack_कुञ्चिका_ed25519(संरचना sk_enroll_response *response)
{
	पूर्णाङ्क ret = -1;
	u_char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	u_char sk[crypto_sign_ed25519_SECRETKEYBYTES];

	response->public_कुञ्चिका = रिक्त;
	response->public_कुञ्चिका_len = 0;
	response->कुञ्चिका_handle = रिक्त;
	response->कुञ्चिका_handle_len = 0;

	memset(pk, 0, परिमाण(pk));
	memset(sk, 0, परिमाण(sk));
	crypto_sign_ed25519_keypair(pk, sk);

	response->public_कुञ्चिका_len = परिमाण(pk);
	सचे ((response->public_कुञ्चिका = malloc(response->public_कुञ्चिका_len)) == रिक्त) {
		skdebug(__func__, "malloc pubkey failed");
		गच्छ out;
	}
	memcpy(response->public_कुञ्चिका, pk, परिमाण(pk));
	/* Key handle contains sk */
	response->कुञ्चिका_handle_len = परिमाण(sk);
	सचे ((response->कुञ्चिका_handle = malloc(response->कुञ्चिका_handle_len)) == रिक्त) {
		skdebug(__func__, "malloc key_handle failed");
		गच्छ out;
	}
	memcpy(response->कुञ्चिका_handle, sk, परिमाण(sk));
	/* success */
	ret = 0;
 out:
	सचे (ret != 0)
		मुक्त(response->public_कुञ्चिका);
	पटिनिवत्त ret;
}

स्थिर पूर्णाङ्क
check_options(संरचना sk_option **options)
{
	size_t i;

	सचे (options == रिक्त)
		पटिनिवत्त 0;
	अत्थाय (i = 0; options[i] != रिक्त; i++) {
		skdebug(__func__, "requested unsupported option %s",
		    options[i]->name);
		सचे (options[i]->required) {
			skdebug(__func__, "unknown required option");
			पटिनिवत्त -1;
		}
	}
	पटिनिवत्त 0;
}

पूर्णाङ्क
sk_enroll(uint32_t alg, ध्रुव uint8_t *challenge, size_t challenge_len,
    ध्रुव वर्ण *application, uint8_t flags, ध्रुव वर्ण *pin,
    संरचना sk_option **options, संरचना sk_enroll_response **enroll_response)
{
	संरचना sk_enroll_response *response = रिक्त;
	पूर्णाङ्क ret = SSH_SK_ERR_GENERAL;

	(शून्य)flags; /* XXX; unused */

	सचे (enroll_response == रिक्त) {
		skdebug(__func__, "enroll_response == NULL");
		गच्छ out;
	}
	*enroll_response = रिक्त;
	सचे (check_options(options) != 0)
		गच्छ out; /* error already logged */
	सचे ((response = calloc(1, परिमाण(*response))) == रिक्त) {
		skdebug(__func__, "calloc response failed");
		गच्छ out;
	}
	response->flags = flags;
	विकल्प(alg) {
	पक्ष SSH_SK_ECDSA:
		सचे (pack_कुञ्चिका_ecdsa(response) != 0)
			गच्छ out;
		भङ्ग;
	पक्ष SSH_SK_ED25519:
		सचे (pack_कुञ्चिका_ed25519(response) != 0)
			गच्छ out;
		भङ्ग;
	स्वभाव:
		skdebug(__func__, "unsupported key type %d", alg);
		गच्छ out;
	}
	/* Have to return something here */
	सचे ((response->signature = calloc(1, 1)) == रिक्त) {
		skdebug(__func__, "calloc signature failed");
		गच्छ out;
	}
	response->signature_len = 0;

	*enroll_response = response;
	response = रिक्त;
	ret = 0;
 out:
	सचे (response != रिक्त) {
		मुक्त(response->public_कुञ्चिका);
		मुक्त(response->कुञ्चिका_handle);
		मुक्त(response->signature);
		मुक्त(response->attestation_cert);
		मुक्त(response);
	}
	पटिनिवत्त ret;
}

स्थिर शून्य
dump(ध्रुव वर्ण *preamble, ध्रुव शून्य *sv, size_t l)
{
#ifdef SK_DEBUG
	ध्रुव u_char *s = (ध्रुव u_char *)sv;
	size_t i;

	fprintf(stderr, "%s (len %zu):\n", preamble, l);
	अत्थाय (i = 0; i < l; i++) {
		सचे (i % 16 == 0)
			fprintf(stderr, "%04zu: ", i);
		fprintf(stderr, "%02x", s[i]);
		सचे (i % 16 == 15 || i == l - 1)
			fprintf(stderr, "\n");
	}
#endif
}

स्थिर पूर्णाङ्क
sig_ecdsa(ध्रुव uint8_t *message, size_t message_len,
    ध्रुव वर्ण *application, uint32_t counter, uint8_t flags,
    ध्रुव uint8_t *कुञ्चिका_handle, size_t कुञ्चिका_handle_len,
    संरचना sk_sign_response *response)
{
#ifdef WITH_OPENSSL
	ECDSA_SIG *sig = रिक्त;
	ध्रुव BIGNUM *sig_r, *sig_s;
	पूर्णाङ्क ret = -1;
	BIO *bio = रिक्त;
	EVP_PKEY *pk = रिक्त;
	EC_कुञ्चिका *ec = रिक्त;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_LENGTH];
	uint8_t	sighash[SHA256_DIGEST_LENGTH];
	uint8_t countbuf[4];

	/* Decode EC_KEY from key handle */
	सचे ((bio = BIO_new(BIO_s_mem())) == रिक्त ||
	    BIO_write(bio, कुञ्चिका_handle, कुञ्चिका_handle_len) != (पूर्णाङ्क)कुञ्चिका_handle_len) {
		skdebug(__func__, "BIO setup failed");
		गच्छ out;
	}
	सचे ((pk = PEM_read_bio_Private_कुञ्चिका(bio, रिक्त, रिक्त, "")) == रिक्त) {
		skdebug(__func__, "PEM_read_bio_PrivateKey failed");
		गच्छ out;
	}
	सचे (EVP_PKEY_base_id(pk) != EVP_PKEY_EC) {
		skdebug(__func__, "Not an EC key: %d", EVP_PKEY_base_id(pk));
		गच्छ out;
	}
	सचे ((ec = EVP_PKEY_get1_EC_कुञ्चिका(pk)) == रिक्त) {
		skdebug(__func__, "EVP_PKEY_get1_EC_KEY failed");
		गच्छ out;
	}
	/* Expect message to be pre-hashed */
	सचे (message_len != SHA256_DIGEST_LENGTH) {
		skdebug(__func__, "bad message len %zu", message_len);
		गच्छ out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ध्रुव u_char *)application, strlen(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, परिमाण(apphash));
	countbuf[0] = (counter >> 24) & 0xff;
	countbuf[1] = (counter >> 16) & 0xff;
	countbuf[2] = (counter >> 8) & 0xff;
	countbuf[3] = counter & 0xff;
	dump("countbuf", countbuf, परिमाण(countbuf));
	dump("flags", &flags, परिमाण(flags));
	SHA256Init(&ctx);
	SHA256Update(&ctx, apphash, परिमाण(apphash));
	SHA256Update(&ctx, &flags, परिमाण(flags));
	SHA256Update(&ctx, countbuf, परिमाण(countbuf));
	SHA256Update(&ctx, message, message_len);
	SHA256Final(sighash, &ctx);
	dump("sighash", sighash, परिमाण(sighash));
	/* create and encode signature */
	सचे ((sig = ECDSA_do_sign(sighash, परिमाण(sighash), ec)) == रिक्त) {
		skdebug(__func__, "ECDSA_do_sign failed");
		गच्छ out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_अङ्कः_bytes(sig_r);
	response->sig_s_len = BN_अङ्कः_bytes(sig_s);
	सचे ((response->sig_r = calloc(1, response->sig_r_len)) == रिक्त ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == रिक्त) {
		skdebug(__func__, "calloc signature failed");
		गच्छ out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	explicit_bzero(&ctx, परिमाण(ctx));
	explicit_bzero(&apphash, परिमाण(apphash));
	explicit_bzero(&sighash, परिमाण(sighash));
	ECDSA_SIG_free(sig);
	सचे (ret != 0) {
		मुक्त(response->sig_r);
		मुक्त(response->sig_s);
		response->sig_r = रिक्त;
		response->sig_s = रिक्त;
	}
	BIO_free(bio);
	EC_कुञ्चिका_free(ec);
	EVP_PKEY_free(pk);
	पटिनिवत्त ret;
#अञ्ञथा
	पटिनिवत्त -1;
#endif
}

स्थिर पूर्णाङ्क
sig_ed25519(ध्रुव uint8_t *message, size_t message_len,
    ध्रुव वर्ण *application, uint32_t counter, uint8_t flags,
    ध्रुव uint8_t *कुञ्चिका_handle, size_t कुञ्चिका_handle_len,
    संरचना sk_sign_response *response)
{
	size_t o;
	पूर्णाङ्क ret = -1;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_LENGTH];
	uint8_t signbuf[परिमाण(apphash) + परिमाण(flags) +
	    परिमाण(counter) + SHA256_DIGEST_LENGTH];
	uint8_t sig[crypto_sign_ed25519_BYTES];
	unsigned long long siglen = 0;

	सचे (कुञ्चिका_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		skdebug(__func__, "bad key handle length %zu", कुञ्चिका_handle_len);
		गच्छ out;
	}
	/* Expect message to be pre-hashed */
	सचे (message_len != SHA256_DIGEST_LENGTH) {
		skdebug(__func__, "bad message len %zu", message_len);
		गच्छ out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ध्रुव u_char *)application, strlen(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, परिमाण(apphash));

	memcpy(signbuf, apphash, परिमाण(apphash));
	o = परिमाण(apphash);
	signbuf[o++] = flags;
	signbuf[o++] = (counter >> 24) & 0xff;
	signbuf[o++] = (counter >> 16) & 0xff;
	signbuf[o++] = (counter >> 8) & 0xff;
	signbuf[o++] = counter & 0xff;
	memcpy(signbuf + o, message, message_len);
	o += message_len;
	सचे (o != परिमाण(signbuf)) {
		skdebug(__func__, "bad sign buf len %zu, expected %zu",
		    o, परिमाण(signbuf));
		गच्छ out;
	}
	dump("signbuf", signbuf, परिमाण(signbuf));
	/* create and encode signature */
	सचे (crypto_sign_ed25519_detached(sig, &siglen, signbuf, परिमाण(signbuf),
	    कुञ्चिका_handle) != 0) {
		skdebug(__func__, "crypto_sign_ed25519_detached failed");
		गच्छ out;
	}
	सचे (siglen != परिमाण(sig)) {
		skdebug(__func__, "bad signature length %llu", siglen);
		गच्छ out;
	}
	response->sig_r_len = परिमाण(sig);
	सचे ((response->sig_r = calloc(1, response->sig_r_len)) == रिक्त) {
		skdebug(__func__, "calloc signature failed");
		गच्छ out;
	}
	memcpy(response->sig_r, sig, response->sig_r_len);
	dump("sig_r", response->sig_r, response->sig_r_len);
	ret = 0;
 out:
	explicit_bzero(&ctx, परिमाण(ctx));
	explicit_bzero(&apphash, परिमाण(apphash));
	explicit_bzero(&signbuf, परिमाण(signbuf));
	explicit_bzero(&sig, परिमाण(sig));
	सचे (ret != 0) {
		मुक्त(response->sig_r);
		response->sig_r = रिक्त;
	}
	पटिनिवत्त ret;
}

पूर्णाङ्क
sk_sign(uint32_t alg, ध्रुव uint8_t *data, size_t datalen,
    ध्रुव वर्ण *application, ध्रुव uint8_t *कुञ्चिका_handle, size_t कुञ्चिका_handle_len,
    uint8_t flags, ध्रुव वर्ण *pin, संरचना sk_option **options,
    संरचना sk_sign_response **sign_response)
{
	संरचना sk_sign_response *response = रिक्त;
	पूर्णाङ्क ret = SSH_SK_ERR_GENERAL;
	SHA2_CTX ctx;
	uint8_t message[32];

	सचे (sign_response == रिक्त) {
		skdebug(__func__, "sign_response == NULL");
		गच्छ out;
	}
	*sign_response = रिक्त;
	सचे (check_options(options) != 0)
		गच्छ out; /* error already logged */
	सचे ((response = calloc(1, परिमाण(*response))) == रिक्त) {
		skdebug(__func__, "calloc response failed");
		गच्छ out;
	}
	SHA256Init(&ctx);
	SHA256Update(&ctx, data, datalen);
	SHA256Final(message, &ctx);
	response->flags = flags;
	response->counter = 0x12345678;
	विकल्प(alg) {
	पक्ष SSH_SK_ECDSA:
		सचे (sig_ecdsa(message, परिमाण(message), application,
		    response->counter, flags, कुञ्चिका_handle, कुञ्चिका_handle_len,
		    response) != 0)
			गच्छ out;
		भङ्ग;
	पक्ष SSH_SK_ED25519:
		सचे (sig_ed25519(message, परिमाण(message), application,
		    response->counter, flags, कुञ्चिका_handle, कुञ्चिका_handle_len,
		    response) != 0)
			गच्छ out;
		भङ्ग;
	स्वभाव:
		skdebug(__func__, "unsupported key type %d", alg);
		गच्छ out;
	}
	*sign_response = response;
	response = रिक्त;
	ret = 0;
 out:
	explicit_bzero(message, परिमाण(message));
	सचे (response != रिक्त) {
		मुक्त(response->sig_r);
		मुक्त(response->sig_s);
		मुक्त(response);
	}
	पटिनिवत्त ret;
}

पूर्णाङ्क
sk_load_resident_कुञ्चिकाः(ध्रुव वर्ण *pin, संरचना sk_option **options,
    संरचना sk_resident_कुञ्चिका ***rks, size_t *nrks)
{
	पटिनिवत्त SSH_SK_ERR_UNSUPPORTED;
}
