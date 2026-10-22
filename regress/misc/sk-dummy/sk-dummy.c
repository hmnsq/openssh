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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <stdarg.h>

#അന്തര്ഭാവ "crypto_api.h"
#അന്തര്ഭാവ "sk-api.h"

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/opensslv.h>
#അന്തര്ഭാവ <openssl/sha.h>
#അന്തര്ഭാവ <openssl/crypto.h>
#അന്തര്ഭാവ <openssl/evp.h>
#അന്തര്ഭാവ <openssl/bn.h>
#അന്തര്ഭാവ <openssl/ec.h>
#അന്തര്ഭാവ <openssl/ecdsa.h>
#അന്തര്ഭാവ <openssl/pem.h>

/* Use OpenSSL SHA256 instead of libc */
#define SHA256Init(x)		SHA256_Init(x)
#define SHA256Update(x, y, z)	SHA256_Update(x, y, z)
#define SHA256Final(x, y)	SHA256_Final(x, y)
#define SHA2_CTX		SHA256_CTX

#അല്ലെങ്കിലെങ്കിൽ defined(HAVE_SHA2_H)
#അന്തര്ഭാവ <sha2.h>
#endif /* WITH_OPENSSL */

/* #define SK_DEBUG 1 */

#എങ്കിൽ SSH_SK_VERSION_MAJOR != 0x000a0000
# error SK API has changed, sk-dummy.c needs an update
#endif

#ifdef SK_DUMMY_INTEGRATE
# define sk_api_version		ssh_sk_api_version
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_load_resident_താക്കോലുകൾ	ssh_sk_load_resident_താക്കോലുകൾ
#endif /* !SK_STANDALONE */

സ്ഥിതം ശൂന്യം skdebug(സ്ഥിരം അക്ഷരം *func, സ്ഥിരം അക്ഷരം *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

സ്ഥിതം ശൂന്യം
skdebug(സ്ഥിരം അക്ഷരം *func, സ്ഥിരം അക്ഷരം *fmt, ...)
{
#എങ്കിൽ defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "sk-dummy %s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#അല്ലെങ്കിൽ
	(ശൂന്യം)func; /* XXX */
	(ശൂന്യം)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(ശൂന്യം)
{
	തിരികെ SSH_SK_VERSION_MAJOR;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
pack_താക്കോൽ_ecdsa(ഘടന sk_enroll_response *response)
{
#ifdef WITH_OPENSSL
	EC_താക്കോൽ *താക്കോൽ = ശൂന്യ;
	സ്ഥിരം EC_GROUP *g;
	സ്ഥിരം EC_POINT *q;
	പൂർണ്ണസംഖ്യ ret = -1;
	long privlen;
	BIO *bio = ശൂന്യ;
	അക്ഷരം *privptr;

	response->public_താക്കോൽ = ശൂന്യ;
	response->public_താക്കോൽ_len = 0;
	response->താക്കോൽ_handle = ശൂന്യ;
	response->താക്കോൽ_handle_len = 0;

	എങ്കിൽ ((താക്കോൽ = EC_താക്കോൽ_new_by_curve_name(NID_X9_62_prime256v1)) == ശൂന്യ) {
		skdebug(__func__, "EC_KEY_new_by_curve_name");
		പോകുക out;
	}
	എങ്കിൽ (EC_താക്കോൽ_generate_താക്കോൽ(താക്കോൽ) != 1) {
		skdebug(__func__, "EC_KEY_generate_key");
		പോകുക out;
	}
	EC_താക്കോൽ_set_asn1_flag(താക്കോൽ, OPENSSL_EC_NAMED_CURVE);
	എങ്കിൽ ((bio = BIO_new(BIO_s_mem())) == ശൂന്യ ||
	    (g = EC_താക്കോൽ_get0_group(താക്കോൽ)) == ശൂന്യ ||
	    (q = EC_താക്കോൽ_get0_public_താക്കോൽ(താക്കോൽ)) == ശൂന്യ) {
		skdebug(__func__, "couldn't get key parameters");
		പോകുക out;
	}
	response->public_താക്കോൽ_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, ശൂന്യ, 0, ശൂന്യ);
	എങ്കിൽ (response->public_താക്കോൽ_len == 0 || response->public_താക്കോൽ_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_താക്കോൽ_len);
		പോകുക out;
	}
	എങ്കിൽ ((response->public_താക്കോൽ = malloc(response->public_താക്കോൽ_len)) == ശൂന്യ) {
		skdebug(__func__, "malloc pubkey failed");
		പോകുക out;
	}
	എങ്കിൽ (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_താക്കോൽ, response->public_താക്കോൽ_len, ശൂന്യ) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		പോകുക out;
	}
	/* Key handle contains PEM encoded private key */
	എങ്കിൽ (!PEM_write_bio_ECPrivate_താക്കോൽ(bio, താക്കോൽ, ശൂന്യ, ശൂന്യ, 0, ശൂന്യ, ശൂന്യ)) {
		skdebug(__func__, "PEM_write_bio_ECPrivateKey failed");
		പോകുക out;
	}
	എങ്കിൽ ((privlen = BIO_get_mem_data(bio, &privptr)) <= 0) {
		skdebug(__func__, "BIO_get_mem_data failed");
		പോകുക out;
	}
	എങ്കിൽ ((response->താക്കോൽ_handle = malloc(privlen)) == ശൂന്യ) {
		skdebug(__func__, "malloc key_handle failed");
		പോകുക out;
	}
	response->താക്കോൽ_handle_len = (size_t)privlen;
	memcpy(response->താക്കോൽ_handle, privptr, response->താക്കോൽ_handle_len);
	/* success */
	ret = 0;
 out:
	എങ്കിൽ (ret != 0) {
		എങ്കിൽ (response->public_താക്കോൽ != ശൂന്യ) {
			memset(response->public_താക്കോൽ, 0,
			    response->public_താക്കോൽ_len);
			സ്വതന്ത്രം(response->public_താക്കോൽ);
			response->public_താക്കോൽ = ശൂന്യ;
		}
		എങ്കിൽ (response->താക്കോൽ_handle != ശൂന്യ) {
			memset(response->താക്കോൽ_handle, 0,
			    response->താക്കോൽ_handle_len);
			സ്വതന്ത്രം(response->താക്കോൽ_handle);
			response->താക്കോൽ_handle = ശൂന്യ;
		}
	}
	BIO_free(bio);
	EC_താക്കോൽ_free(താക്കോൽ);
	തിരികെ ret;
#അല്ലെങ്കിൽ
	തിരികെ -1;
#endif
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
pack_താക്കോൽ_ed25519(ഘടന sk_enroll_response *response)
{
	പൂർണ്ണസംഖ്യ ret = -1;
	u_char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	u_char sk[crypto_sign_ed25519_SECRETKEYBYTES];

	response->public_താക്കോൽ = ശൂന്യ;
	response->public_താക്കോൽ_len = 0;
	response->താക്കോൽ_handle = ശൂന്യ;
	response->താക്കോൽ_handle_len = 0;

	memset(pk, 0, വലുപ്പം(pk));
	memset(sk, 0, വലുപ്പം(sk));
	crypto_sign_ed25519_keypair(pk, sk);

	response->public_താക്കോൽ_len = വലുപ്പം(pk);
	എങ്കിൽ ((response->public_താക്കോൽ = malloc(response->public_താക്കോൽ_len)) == ശൂന്യ) {
		skdebug(__func__, "malloc pubkey failed");
		പോകുക out;
	}
	memcpy(response->public_താക്കോൽ, pk, വലുപ്പം(pk));
	/* Key handle contains sk */
	response->താക്കോൽ_handle_len = വലുപ്പം(sk);
	എങ്കിൽ ((response->താക്കോൽ_handle = malloc(response->താക്കോൽ_handle_len)) == ശൂന്യ) {
		skdebug(__func__, "malloc key_handle failed");
		പോകുക out;
	}
	memcpy(response->താക്കോൽ_handle, sk, വലുപ്പം(sk));
	/* success */
	ret = 0;
 out:
	എങ്കിൽ (ret != 0)
		സ്വതന്ത്രം(response->public_താക്കോൽ);
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
check_options(ഘടന sk_option **options)
{
	size_t i;

	എങ്കിൽ (options == ശൂന്യ)
		തിരികെ 0;
	വേണ്ടി (i = 0; options[i] != ശൂന്യ; i++) {
		skdebug(__func__, "requested unsupported option %s",
		    options[i]->name);
		എങ്കിൽ (options[i]->required) {
			skdebug(__func__, "unknown required option");
			തിരികെ -1;
		}
	}
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sk_enroll(uint32_t alg, സ്ഥിരം uint8_t *challenge, size_t challenge_len,
    സ്ഥിരം അക്ഷരം *application, uint8_t flags, സ്ഥിരം അക്ഷരം *pin,
    ഘടന sk_option **options, ഘടന sk_enroll_response **enroll_response)
{
	ഘടന sk_enroll_response *response = ശൂന്യ;
	പൂർണ്ണസംഖ്യ ret = SSH_SK_ERR_GENERAL;

	(ശൂന്യം)flags; /* XXX; unused */

	എങ്കിൽ (enroll_response == ശൂന്യ) {
		skdebug(__func__, "enroll_response == NULL");
		പോകുക out;
	}
	*enroll_response = ശൂന്യ;
	എങ്കിൽ (check_options(options) != 0)
		പോകുക out; /* error already logged */
	എങ്കിൽ ((response = calloc(1, വലുപ്പം(*response))) == ശൂന്യ) {
		skdebug(__func__, "calloc response failed");
		പോകുക out;
	}
	response->flags = flags;
	തിരഞ്ഞെടുപ്പ്(alg) {
	അവസ്ഥ SSH_SK_ECDSA:
		എങ്കിൽ (pack_താക്കോൽ_ecdsa(response) != 0)
			പോകുക out;
		നിർത്തുക;
	അവസ്ഥ SSH_SK_ED25519:
		എങ്കിൽ (pack_താക്കോൽ_ed25519(response) != 0)
			പോകുക out;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		skdebug(__func__, "unsupported key type %d", alg);
		പോകുക out;
	}
	/* Have to return something here */
	എങ്കിൽ ((response->signature = calloc(1, 1)) == ശൂന്യ) {
		skdebug(__func__, "calloc signature failed");
		പോകുക out;
	}
	response->signature_len = 0;

	*enroll_response = response;
	response = ശൂന്യ;
	ret = 0;
 out:
	എങ്കിൽ (response != ശൂന്യ) {
		സ്വതന്ത്രം(response->public_താക്കോൽ);
		സ്വതന്ത്രം(response->താക്കോൽ_handle);
		സ്വതന്ത്രം(response->signature);
		സ്വതന്ത്രം(response->attestation_cert);
		സ്വതന്ത്രം(response);
	}
	തിരികെ ret;
}

സ്ഥിതം ശൂന്യം
dump(സ്ഥിരം അക്ഷരം *preamble, സ്ഥിരം ശൂന്യം *sv, size_t l)
{
#ifdef SK_DEBUG
	സ്ഥിരം u_char *s = (സ്ഥിരം u_char *)sv;
	size_t i;

	fprintf(stderr, "%s (len %zu):\n", preamble, l);
	വേണ്ടി (i = 0; i < l; i++) {
		എങ്കിൽ (i % 16 == 0)
			fprintf(stderr, "%04zu: ", i);
		fprintf(stderr, "%02x", s[i]);
		എങ്കിൽ (i % 16 == 15 || i == l - 1)
			fprintf(stderr, "\n");
	}
#endif
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sig_ecdsa(സ്ഥിരം uint8_t *message, size_t message_len,
    സ്ഥിരം അക്ഷരം *application, uint32_t counter, uint8_t flags,
    സ്ഥിരം uint8_t *താക്കോൽ_handle, size_t താക്കോൽ_handle_len,
    ഘടന sk_sign_response *response)
{
#ifdef WITH_OPENSSL
	ECDSA_SIG *sig = ശൂന്യ;
	സ്ഥിരം BIGNUM *sig_r, *sig_s;
	പൂർണ്ണസംഖ്യ ret = -1;
	BIO *bio = ശൂന്യ;
	EVP_PKEY *pk = ശൂന്യ;
	EC_താക്കോൽ *ec = ശൂന്യ;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_LENGTH];
	uint8_t	sighash[SHA256_DIGEST_LENGTH];
	uint8_t countbuf[4];

	/* Decode EC_KEY from key handle */
	എങ്കിൽ ((bio = BIO_new(BIO_s_mem())) == ശൂന്യ ||
	    BIO_write(bio, താക്കോൽ_handle, താക്കോൽ_handle_len) != (പൂർണ്ണസംഖ്യ)താക്കോൽ_handle_len) {
		skdebug(__func__, "BIO setup failed");
		പോകുക out;
	}
	എങ്കിൽ ((pk = PEM_read_bio_Private_താക്കോൽ(bio, ശൂന്യ, ശൂന്യ, "")) == ശൂന്യ) {
		skdebug(__func__, "PEM_read_bio_PrivateKey failed");
		പോകുക out;
	}
	എങ്കിൽ (EVP_PKEY_base_id(pk) != EVP_PKEY_EC) {
		skdebug(__func__, "Not an EC key: %d", EVP_PKEY_base_id(pk));
		പോകുക out;
	}
	എങ്കിൽ ((ec = EVP_PKEY_get1_EC_താക്കോൽ(pk)) == ശൂന്യ) {
		skdebug(__func__, "EVP_PKEY_get1_EC_KEY failed");
		പോകുക out;
	}
	/* Expect message to be pre-hashed */
	എങ്കിൽ (message_len != SHA256_DIGEST_LENGTH) {
		skdebug(__func__, "bad message len %zu", message_len);
		പോകുക out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (സ്ഥിരം u_char *)application, strlen(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, വലുപ്പം(apphash));
	countbuf[0] = (counter >> 24) & 0xff;
	countbuf[1] = (counter >> 16) & 0xff;
	countbuf[2] = (counter >> 8) & 0xff;
	countbuf[3] = counter & 0xff;
	dump("countbuf", countbuf, വലുപ്പം(countbuf));
	dump("flags", &flags, വലുപ്പം(flags));
	SHA256Init(&ctx);
	SHA256Update(&ctx, apphash, വലുപ്പം(apphash));
	SHA256Update(&ctx, &flags, വലുപ്പം(flags));
	SHA256Update(&ctx, countbuf, വലുപ്പം(countbuf));
	SHA256Update(&ctx, message, message_len);
	SHA256Final(sighash, &ctx);
	dump("sighash", sighash, വലുപ്പം(sighash));
	/* create and encode signature */
	എങ്കിൽ ((sig = ECDSA_do_sign(sighash, വലുപ്പം(sighash), ec)) == ശൂന്യ) {
		skdebug(__func__, "ECDSA_do_sign failed");
		പോകുക out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_അക്കം_bytes(sig_r);
	response->sig_s_len = BN_അക്കം_bytes(sig_s);
	എങ്കിൽ ((response->sig_r = calloc(1, response->sig_r_len)) == ശൂന്യ ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == ശൂന്യ) {
		skdebug(__func__, "calloc signature failed");
		പോകുക out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	explicit_bzero(&ctx, വലുപ്പം(ctx));
	explicit_bzero(&apphash, വലുപ്പം(apphash));
	explicit_bzero(&sighash, വലുപ്പം(sighash));
	ECDSA_SIG_free(sig);
	എങ്കിൽ (ret != 0) {
		സ്വതന്ത്രം(response->sig_r);
		സ്വതന്ത്രം(response->sig_s);
		response->sig_r = ശൂന്യ;
		response->sig_s = ശൂന്യ;
	}
	BIO_free(bio);
	EC_താക്കോൽ_free(ec);
	EVP_PKEY_free(pk);
	തിരികെ ret;
#അല്ലെങ്കിൽ
	തിരികെ -1;
#endif
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sig_ed25519(സ്ഥിരം uint8_t *message, size_t message_len,
    സ്ഥിരം അക്ഷരം *application, uint32_t counter, uint8_t flags,
    സ്ഥിരം uint8_t *താക്കോൽ_handle, size_t താക്കോൽ_handle_len,
    ഘടന sk_sign_response *response)
{
	size_t o;
	പൂർണ്ണസംഖ്യ ret = -1;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_LENGTH];
	uint8_t signbuf[വലുപ്പം(apphash) + വലുപ്പം(flags) +
	    വലുപ്പം(counter) + SHA256_DIGEST_LENGTH];
	uint8_t sig[crypto_sign_ed25519_BYTES];
	unsigned long long siglen = 0;

	എങ്കിൽ (താക്കോൽ_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		skdebug(__func__, "bad key handle length %zu", താക്കോൽ_handle_len);
		പോകുക out;
	}
	/* Expect message to be pre-hashed */
	എങ്കിൽ (message_len != SHA256_DIGEST_LENGTH) {
		skdebug(__func__, "bad message len %zu", message_len);
		പോകുക out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (സ്ഥിരം u_char *)application, strlen(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, വലുപ്പം(apphash));

	memcpy(signbuf, apphash, വലുപ്പം(apphash));
	o = വലുപ്പം(apphash);
	signbuf[o++] = flags;
	signbuf[o++] = (counter >> 24) & 0xff;
	signbuf[o++] = (counter >> 16) & 0xff;
	signbuf[o++] = (counter >> 8) & 0xff;
	signbuf[o++] = counter & 0xff;
	memcpy(signbuf + o, message, message_len);
	o += message_len;
	എങ്കിൽ (o != വലുപ്പം(signbuf)) {
		skdebug(__func__, "bad sign buf len %zu, expected %zu",
		    o, വലുപ്പം(signbuf));
		പോകുക out;
	}
	dump("signbuf", signbuf, വലുപ്പം(signbuf));
	/* create and encode signature */
	എങ്കിൽ (crypto_sign_ed25519_detached(sig, &siglen, signbuf, വലുപ്പം(signbuf),
	    താക്കോൽ_handle) != 0) {
		skdebug(__func__, "crypto_sign_ed25519_detached failed");
		പോകുക out;
	}
	എങ്കിൽ (siglen != വലുപ്പം(sig)) {
		skdebug(__func__, "bad signature length %llu", siglen);
		പോകുക out;
	}
	response->sig_r_len = വലുപ്പം(sig);
	എങ്കിൽ ((response->sig_r = calloc(1, response->sig_r_len)) == ശൂന്യ) {
		skdebug(__func__, "calloc signature failed");
		പോകുക out;
	}
	memcpy(response->sig_r, sig, response->sig_r_len);
	dump("sig_r", response->sig_r, response->sig_r_len);
	ret = 0;
 out:
	explicit_bzero(&ctx, വലുപ്പം(ctx));
	explicit_bzero(&apphash, വലുപ്പം(apphash));
	explicit_bzero(&signbuf, വലുപ്പം(signbuf));
	explicit_bzero(&sig, വലുപ്പം(sig));
	എങ്കിൽ (ret != 0) {
		സ്വതന്ത്രം(response->sig_r);
		response->sig_r = ശൂന്യ;
	}
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
sk_sign(uint32_t alg, സ്ഥിരം uint8_t *data, size_t datalen,
    സ്ഥിരം അക്ഷരം *application, സ്ഥിരം uint8_t *താക്കോൽ_handle, size_t താക്കോൽ_handle_len,
    uint8_t flags, സ്ഥിരം അക്ഷരം *pin, ഘടന sk_option **options,
    ഘടന sk_sign_response **sign_response)
{
	ഘടന sk_sign_response *response = ശൂന്യ;
	പൂർണ്ണസംഖ്യ ret = SSH_SK_ERR_GENERAL;
	SHA2_CTX ctx;
	uint8_t message[32];

	എങ്കിൽ (sign_response == ശൂന്യ) {
		skdebug(__func__, "sign_response == NULL");
		പോകുക out;
	}
	*sign_response = ശൂന്യ;
	എങ്കിൽ (check_options(options) != 0)
		പോകുക out; /* error already logged */
	എങ്കിൽ ((response = calloc(1, വലുപ്പം(*response))) == ശൂന്യ) {
		skdebug(__func__, "calloc response failed");
		പോകുക out;
	}
	SHA256Init(&ctx);
	SHA256Update(&ctx, data, datalen);
	SHA256Final(message, &ctx);
	response->flags = flags;
	response->counter = 0x12345678;
	തിരഞ്ഞെടുപ്പ്(alg) {
	അവസ്ഥ SSH_SK_ECDSA:
		എങ്കിൽ (sig_ecdsa(message, വലുപ്പം(message), application,
		    response->counter, flags, താക്കോൽ_handle, താക്കോൽ_handle_len,
		    response) != 0)
			പോകുക out;
		നിർത്തുക;
	അവസ്ഥ SSH_SK_ED25519:
		എങ്കിൽ (sig_ed25519(message, വലുപ്പം(message), application,
		    response->counter, flags, താക്കോൽ_handle, താക്കോൽ_handle_len,
		    response) != 0)
			പോകുക out;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		skdebug(__func__, "unsupported key type %d", alg);
		പോകുക out;
	}
	*sign_response = response;
	response = ശൂന്യ;
	ret = 0;
 out:
	explicit_bzero(message, വലുപ്പം(message));
	എങ്കിൽ (response != ശൂന്യ) {
		സ്വതന്ത്രം(response->sig_r);
		സ്വതന്ത്രം(response->sig_s);
		സ്വതന്ത്രം(response);
	}
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
sk_load_resident_താക്കോലുകൾ(സ്ഥിരം അക്ഷരം *pin, ഘടന sk_option **options,
    ഘടന sk_resident_താക്കോൽ ***rks, size_t *nrks)
{
	തിരികെ SSH_SK_ERR_UNSUPPORTED;
}
