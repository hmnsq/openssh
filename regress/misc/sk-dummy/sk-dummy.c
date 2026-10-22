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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <stdarg.h>

#અન્તર્ભાવ "crypto_api.h"
#અન્તર્ભાવ "sk-api.h"

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/opensslv.h>
#અન્તર્ભાવ <openssl/sha.h>
#અન્તર્ભાવ <openssl/crypto.h>
#અન્તર્ભાવ <openssl/evp.h>
#અન્તર્ભાવ <openssl/bn.h>
#અન્તર્ભાવ <openssl/ec.h>
#અન્તર્ભાવ <openssl/ecdsa.h>
#અન્તર્ભાવ <openssl/pem.h>

/* Use OpenSSL SHA256 instead of libc */
#define SHA256Init(x)		SHA256_Init(x)
#define SHA256Update(x, y, z)	SHA256_Update(x, y, z)
#define SHA256Final(x, y)	SHA256_Final(x, y)
#define SHA2_CTX		SHA256_CTX

#અથવાજો defined(HAVE_SHA2_H)
#અન્તર્ભાવ <sha2.h>
#endif /* WITH_OPENSSL */

/* #define SK_DEBUG 1 */

#જો SSH_SK_VERSION_MAJOR != 0x000a0000
# error SK API has changed, sk-dummy.c needs an update
#endif

#ifdef SK_DUMMY_INTEGRATE
# define sk_api_version		ssh_sk_api_version
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_load_resident_ચાવીઓ	ssh_sk_load_resident_ચાવીઓ
#endif /* !SK_STANDALONE */

સ્થિર શૂન્ય skdebug(અચલ અક્ષર *func, અચલ અક્ષર *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

સ્થિર શૂન્ય
skdebug(અચલ અક્ષર *func, અચલ અક્ષર *fmt, ...)
{
#જો defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "sk-dummy %s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#નહીંતર
	(શૂન્ય)func; /* XXX */
	(શૂન્ય)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(શૂન્ય)
{
	પાછા SSH_SK_VERSION_MAJOR;
}

સ્થિર પૂર્ણાંક
pack_ચાવી_ecdsa(સંરચના sk_enroll_response *response)
{
#ifdef WITH_OPENSSL
	EC_ચાવી *ચાવી = ખાલી;
	અચલ EC_GROUP *g;
	અચલ EC_POINT *q;
	પૂર્ણાંક ret = -1;
	long privlen;
	BIO *bio = ખાલી;
	અક્ષર *privptr;

	response->public_ચાવી = ખાલી;
	response->public_ચાવી_len = 0;
	response->ચાવી_handle = ખાલી;
	response->ચાવી_handle_len = 0;

	જો ((ચાવી = EC_ચાવી_new_by_curve_name(NID_X9_62_prime256v1)) == ખાલી) {
		skdebug(__func__, "EC_KEY_new_by_curve_name");
		જાઓ out;
	}
	જો (EC_ચાવી_generate_ચાવી(ચાવી) != 1) {
		skdebug(__func__, "EC_KEY_generate_key");
		જાઓ out;
	}
	EC_ચાવી_set_asn1_flag(ચાવી, OPENSSL_EC_NAMED_CURVE);
	જો ((bio = BIO_new(BIO_s_mem())) == ખાલી ||
	    (g = EC_ચાવી_get0_group(ચાવી)) == ખાલી ||
	    (q = EC_ચાવી_get0_public_ચાવી(ચાવી)) == ખાલી) {
		skdebug(__func__, "couldn't get key parameters");
		જાઓ out;
	}
	response->public_ચાવી_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, ખાલી, 0, ખાલી);
	જો (response->public_ચાવી_len == 0 || response->public_ચાવી_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_ચાવી_len);
		જાઓ out;
	}
	જો ((response->public_ચાવી = malloc(response->public_ચાવી_len)) == ખાલી) {
		skdebug(__func__, "malloc pubkey failed");
		જાઓ out;
	}
	જો (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_ચાવી, response->public_ચાવી_len, ખાલી) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		જાઓ out;
	}
	/* Key handle contains PEM encoded private key */
	જો (!PEM_write_bio_ECPrivate_ચાવી(bio, ચાવી, ખાલી, ખાલી, 0, ખાલી, ખાલી)) {
		skdebug(__func__, "PEM_write_bio_ECPrivateKey failed");
		જાઓ out;
	}
	જો ((privlen = BIO_get_mem_data(bio, &privptr)) <= 0) {
		skdebug(__func__, "BIO_get_mem_data failed");
		જાઓ out;
	}
	જો ((response->ચાવી_handle = malloc(privlen)) == ખાલી) {
		skdebug(__func__, "malloc key_handle failed");
		જાઓ out;
	}
	response->ચાવી_handle_len = (size_t)privlen;
	memcpy(response->ચાવી_handle, privptr, response->ચાવી_handle_len);
	/* success */
	ret = 0;
 out:
	જો (ret != 0) {
		જો (response->public_ચાવી != ખાલી) {
			memset(response->public_ચાવી, 0,
			    response->public_ચાવી_len);
			મુક્ત(response->public_ચાવી);
			response->public_ચાવી = ખાલી;
		}
		જો (response->ચાવી_handle != ખાલી) {
			memset(response->ચાવી_handle, 0,
			    response->ચાવી_handle_len);
			મુક્ત(response->ચાવી_handle);
			response->ચાવી_handle = ખાલી;
		}
	}
	BIO_free(bio);
	EC_ચાવી_free(ચાવી);
	પાછા ret;
#નહીંતર
	પાછા -1;
#endif
}

સ્થિર પૂર્ણાંક
pack_ચાવી_ed25519(સંરચના sk_enroll_response *response)
{
	પૂર્ણાંક ret = -1;
	u_char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	u_char sk[crypto_sign_ed25519_SECRETKEYBYTES];

	response->public_ચાવી = ખાલી;
	response->public_ચાવી_len = 0;
	response->ચાવી_handle = ખાલી;
	response->ચાવી_handle_len = 0;

	memset(pk, 0, કદ(pk));
	memset(sk, 0, કદ(sk));
	crypto_sign_ed25519_keypair(pk, sk);

	response->public_ચાવી_len = કદ(pk);
	જો ((response->public_ચાવી = malloc(response->public_ચાવી_len)) == ખાલી) {
		skdebug(__func__, "malloc pubkey failed");
		જાઓ out;
	}
	memcpy(response->public_ચાવી, pk, કદ(pk));
	/* Key handle contains sk */
	response->ચાવી_handle_len = કદ(sk);
	જો ((response->ચાવી_handle = malloc(response->ચાવી_handle_len)) == ખાલી) {
		skdebug(__func__, "malloc key_handle failed");
		જાઓ out;
	}
	memcpy(response->ચાવી_handle, sk, કદ(sk));
	/* success */
	ret = 0;
 out:
	જો (ret != 0)
		મુક્ત(response->public_ચાવી);
	પાછા ret;
}

સ્થિર પૂર્ણાંક
check_options(સંરચના sk_option **options)
{
	size_t i;

	જો (options == ખાલી)
		પાછા 0;
	માટે (i = 0; options[i] != ખાલી; i++) {
		skdebug(__func__, "requested unsupported option %s",
		    options[i]->name);
		જો (options[i]->required) {
			skdebug(__func__, "unknown required option");
			પાછા -1;
		}
	}
	પાછા 0;
}

પૂર્ણાંક
sk_enroll(uint32_t alg, અચલ uint8_t *challenge, size_t challenge_len,
    અચલ અક્ષર *application, uint8_t flags, અચલ અક્ષર *pin,
    સંરચના sk_option **options, સંરચના sk_enroll_response **enroll_response)
{
	સંરચના sk_enroll_response *response = ખાલી;
	પૂર્ણાંક ret = SSH_SK_ERR_GENERAL;

	(શૂન્ય)flags; /* XXX; unused */

	જો (enroll_response == ખાલી) {
		skdebug(__func__, "enroll_response == NULL");
		જાઓ out;
	}
	*enroll_response = ખાલી;
	જો (check_options(options) != 0)
		જાઓ out; /* error already logged */
	જો ((response = calloc(1, કદ(*response))) == ખાલી) {
		skdebug(__func__, "calloc response failed");
		જાઓ out;
	}
	response->flags = flags;
	પસંદગી(alg) {
	સ્થિતિ SSH_SK_ECDSA:
		જો (pack_ચાવી_ecdsa(response) != 0)
			જાઓ out;
		તોડો;
	સ્થિતિ SSH_SK_ED25519:
		જો (pack_ચાવી_ed25519(response) != 0)
			જાઓ out;
		તોડો;
	મૂળભૂત:
		skdebug(__func__, "unsupported key type %d", alg);
		જાઓ out;
	}
	/* Have to return something here */
	જો ((response->signature = calloc(1, 1)) == ખાલી) {
		skdebug(__func__, "calloc signature failed");
		જાઓ out;
	}
	response->signature_len = 0;

	*enroll_response = response;
	response = ખાલી;
	ret = 0;
 out:
	જો (response != ખાલી) {
		મુક્ત(response->public_ચાવી);
		મુક્ત(response->ચાવી_handle);
		મુક્ત(response->signature);
		મુક્ત(response->attestation_cert);
		મુક્ત(response);
	}
	પાછા ret;
}

સ્થિર શૂન્ય
dump(અચલ અક્ષર *preamble, અચલ શૂન્ય *sv, size_t l)
{
#ifdef SK_DEBUG
	અચલ u_char *s = (અચલ u_char *)sv;
	size_t i;

	fprintf(stderr, "%s (len %zu):\n", preamble, l);
	માટે (i = 0; i < l; i++) {
		જો (i % 16 == 0)
			fprintf(stderr, "%04zu: ", i);
		fprintf(stderr, "%02x", s[i]);
		જો (i % 16 == 15 || i == l - 1)
			fprintf(stderr, "\n");
	}
#endif
}

સ્થિર પૂર્ણાંક
sig_ecdsa(અચલ uint8_t *message, size_t message_len,
    અચલ અક્ષર *application, uint32_t counter, uint8_t flags,
    અચલ uint8_t *ચાવી_handle, size_t ચાવી_handle_len,
    સંરચના sk_sign_response *response)
{
#ifdef WITH_OPENSSL
	ECDSA_SIG *sig = ખાલી;
	અચલ BIGNUM *sig_r, *sig_s;
	પૂર્ણાંક ret = -1;
	BIO *bio = ખાલી;
	EVP_PKEY *pk = ખાલી;
	EC_ચાવી *ec = ખાલી;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_LENGTH];
	uint8_t	sighash[SHA256_DIGEST_LENGTH];
	uint8_t countbuf[4];

	/* Decode EC_KEY from key handle */
	જો ((bio = BIO_new(BIO_s_mem())) == ખાલી ||
	    BIO_write(bio, ચાવી_handle, ચાવી_handle_len) != (પૂર્ણાંક)ચાવી_handle_len) {
		skdebug(__func__, "BIO setup failed");
		જાઓ out;
	}
	જો ((pk = PEM_read_bio_Private_ચાવી(bio, ખાલી, ખાલી, "")) == ખાલી) {
		skdebug(__func__, "PEM_read_bio_PrivateKey failed");
		જાઓ out;
	}
	જો (EVP_PKEY_base_id(pk) != EVP_PKEY_EC) {
		skdebug(__func__, "Not an EC key: %d", EVP_PKEY_base_id(pk));
		જાઓ out;
	}
	જો ((ec = EVP_PKEY_get1_EC_ચાવી(pk)) == ખાલી) {
		skdebug(__func__, "EVP_PKEY_get1_EC_KEY failed");
		જાઓ out;
	}
	/* Expect message to be pre-hashed */
	જો (message_len != SHA256_DIGEST_LENGTH) {
		skdebug(__func__, "bad message len %zu", message_len);
		જાઓ out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (અચલ u_char *)application, strlen(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, કદ(apphash));
	countbuf[0] = (counter >> 24) & 0xff;
	countbuf[1] = (counter >> 16) & 0xff;
	countbuf[2] = (counter >> 8) & 0xff;
	countbuf[3] = counter & 0xff;
	dump("countbuf", countbuf, કદ(countbuf));
	dump("flags", &flags, કદ(flags));
	SHA256Init(&ctx);
	SHA256Update(&ctx, apphash, કદ(apphash));
	SHA256Update(&ctx, &flags, કદ(flags));
	SHA256Update(&ctx, countbuf, કદ(countbuf));
	SHA256Update(&ctx, message, message_len);
	SHA256Final(sighash, &ctx);
	dump("sighash", sighash, કદ(sighash));
	/* create and encode signature */
	જો ((sig = ECDSA_do_sign(sighash, કદ(sighash), ec)) == ખાલી) {
		skdebug(__func__, "ECDSA_do_sign failed");
		જાઓ out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_અંક_bytes(sig_r);
	response->sig_s_len = BN_અંક_bytes(sig_s);
	જો ((response->sig_r = calloc(1, response->sig_r_len)) == ખાલી ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == ખાલી) {
		skdebug(__func__, "calloc signature failed");
		જાઓ out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	explicit_bzero(&ctx, કદ(ctx));
	explicit_bzero(&apphash, કદ(apphash));
	explicit_bzero(&sighash, કદ(sighash));
	ECDSA_SIG_free(sig);
	જો (ret != 0) {
		મુક્ત(response->sig_r);
		મુક્ત(response->sig_s);
		response->sig_r = ખાલી;
		response->sig_s = ખાલી;
	}
	BIO_free(bio);
	EC_ચાવી_free(ec);
	EVP_PKEY_free(pk);
	પાછા ret;
#નહીંતર
	પાછા -1;
#endif
}

સ્થિર પૂર્ણાંક
sig_ed25519(અચલ uint8_t *message, size_t message_len,
    અચલ અક્ષર *application, uint32_t counter, uint8_t flags,
    અચલ uint8_t *ચાવી_handle, size_t ચાવી_handle_len,
    સંરચના sk_sign_response *response)
{
	size_t o;
	પૂર્ણાંક ret = -1;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_LENGTH];
	uint8_t signbuf[કદ(apphash) + કદ(flags) +
	    કદ(counter) + SHA256_DIGEST_LENGTH];
	uint8_t sig[crypto_sign_ed25519_BYTES];
	unsigned long long siglen = 0;

	જો (ચાવી_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		skdebug(__func__, "bad key handle length %zu", ચાવી_handle_len);
		જાઓ out;
	}
	/* Expect message to be pre-hashed */
	જો (message_len != SHA256_DIGEST_LENGTH) {
		skdebug(__func__, "bad message len %zu", message_len);
		જાઓ out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (અચલ u_char *)application, strlen(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, કદ(apphash));

	memcpy(signbuf, apphash, કદ(apphash));
	o = કદ(apphash);
	signbuf[o++] = flags;
	signbuf[o++] = (counter >> 24) & 0xff;
	signbuf[o++] = (counter >> 16) & 0xff;
	signbuf[o++] = (counter >> 8) & 0xff;
	signbuf[o++] = counter & 0xff;
	memcpy(signbuf + o, message, message_len);
	o += message_len;
	જો (o != કદ(signbuf)) {
		skdebug(__func__, "bad sign buf len %zu, expected %zu",
		    o, કદ(signbuf));
		જાઓ out;
	}
	dump("signbuf", signbuf, કદ(signbuf));
	/* create and encode signature */
	જો (crypto_sign_ed25519_detached(sig, &siglen, signbuf, કદ(signbuf),
	    ચાવી_handle) != 0) {
		skdebug(__func__, "crypto_sign_ed25519_detached failed");
		જાઓ out;
	}
	જો (siglen != કદ(sig)) {
		skdebug(__func__, "bad signature length %llu", siglen);
		જાઓ out;
	}
	response->sig_r_len = કદ(sig);
	જો ((response->sig_r = calloc(1, response->sig_r_len)) == ખાલી) {
		skdebug(__func__, "calloc signature failed");
		જાઓ out;
	}
	memcpy(response->sig_r, sig, response->sig_r_len);
	dump("sig_r", response->sig_r, response->sig_r_len);
	ret = 0;
 out:
	explicit_bzero(&ctx, કદ(ctx));
	explicit_bzero(&apphash, કદ(apphash));
	explicit_bzero(&signbuf, કદ(signbuf));
	explicit_bzero(&sig, કદ(sig));
	જો (ret != 0) {
		મુક્ત(response->sig_r);
		response->sig_r = ખાલી;
	}
	પાછા ret;
}

પૂર્ણાંક
sk_sign(uint32_t alg, અચલ uint8_t *data, size_t datalen,
    અચલ અક્ષર *application, અચલ uint8_t *ચાવી_handle, size_t ચાવી_handle_len,
    uint8_t flags, અચલ અક્ષર *pin, સંરચના sk_option **options,
    સંરચના sk_sign_response **sign_response)
{
	સંરચના sk_sign_response *response = ખાલી;
	પૂર્ણાંક ret = SSH_SK_ERR_GENERAL;
	SHA2_CTX ctx;
	uint8_t message[32];

	જો (sign_response == ખાલી) {
		skdebug(__func__, "sign_response == NULL");
		જાઓ out;
	}
	*sign_response = ખાલી;
	જો (check_options(options) != 0)
		જાઓ out; /* error already logged */
	જો ((response = calloc(1, કદ(*response))) == ખાલી) {
		skdebug(__func__, "calloc response failed");
		જાઓ out;
	}
	SHA256Init(&ctx);
	SHA256Update(&ctx, data, datalen);
	SHA256Final(message, &ctx);
	response->flags = flags;
	response->counter = 0x12345678;
	પસંદગી(alg) {
	સ્થિતિ SSH_SK_ECDSA:
		જો (sig_ecdsa(message, કદ(message), application,
		    response->counter, flags, ચાવી_handle, ચાવી_handle_len,
		    response) != 0)
			જાઓ out;
		તોડો;
	સ્થિતિ SSH_SK_ED25519:
		જો (sig_ed25519(message, કદ(message), application,
		    response->counter, flags, ચાવી_handle, ચાવી_handle_len,
		    response) != 0)
			જાઓ out;
		તોડો;
	મૂળભૂત:
		skdebug(__func__, "unsupported key type %d", alg);
		જાઓ out;
	}
	*sign_response = response;
	response = ખાલી;
	ret = 0;
 out:
	explicit_bzero(message, કદ(message));
	જો (response != ખાલી) {
		મુક્ત(response->sig_r);
		મુક્ત(response->sig_s);
		મુક્ત(response);
	}
	પાછા ret;
}

પૂર્ણાંક
sk_load_resident_ચાવીઓ(અચલ અક્ષર *pin, સંરચના sk_option **options,
    સંરચના sk_resident_ચાવી ***rks, size_t *nrks)
{
	પાછા SSH_SK_ERR_UNSUPPORTED;
}
