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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "crypto_api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sk-api.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/opensslv.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/sha.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/crypto.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ec.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ecdsa.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/pem.h>

/* Use OpenSSL SHA256 instead of libc */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SHA256Init(x)		SHA256_Init(x)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SHA256Update(x, y, z)	SHA256_Update(x, y, z)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SHA256Final(x, y)	SHA256_Final(x, y)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SHA2_CTX		SHA256_CTX

#ਜਾਂਜੇ defined(HAVE_SHA2_H)
#ਅਨ੍ਤਰ੍ਭਾਵ <sha2.h>
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

/* #define SK_DEBUG 1 */

#ਜੇ SSH_SK_ਸੰਸਕਰਣ_MAJOR != 0x000a0000
# error SK API has ਬਦਲਿਆ, sk-dummy.c needs an update
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SK_DUMMY_INTEGRATE
# define sk_api_ਸੰਸਕਰਣ		ssh_sk_api_ਸੰਸਕਰਣ
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_ਲੱਦੋ_resident_ਕੁੰਜੀਆਂ	ssh_sk_ਲੱਦੋ_resident_ਕੁੰਜੀਆਂ
#ਜੇ_ਅੰਤ /* !SK_STANDALONE */

ਸਥਿਰ ਖਾਲੀ skdebug(ਅਚਲ ਅੱਖਰ *func, ਅਚਲ ਅੱਖਰ *fmt, ...)
    __attribute__((__format__ (ਲਿਖੋ, 2, 3)));

ਸਥਿਰ ਖਾਲੀ
skdebug(ਅਚਲ ਅੱਖਰ *func, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
#ਜੇ defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "sk-dummy %s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#ਨਹੀਂਤਾਂ
	(ਖਾਲੀ)func; /* XXX */
	(ਖਾਲੀ)fmt; /* XXX */
#ਜੇ_ਅੰਤ
}

uint32_t
sk_api_ਸੰਸਕਰਣ(ਖਾਲੀ)
{
	ਵਾਪਸ SSH_SK_ਸੰਸਕਰਣ_MAJOR;
}

ਸਥਿਰ ਪੂਰਨ
pack_ਕੁੰਜੀ_ecdsa(ਬਣਤਰ sk_enroll_response *response)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	EC_ਕੁੰਜੀ *ਕੁੰਜੀ = ਨਿਰਾ;
	ਅਚਲ EC_ਸਮੂਹ *g;
	ਅਚਲ EC_ਬਿੰਦੂ *q;
	ਪੂਰਨ ret = -1;
	ਲੰਮਾ privlen;
	BIO *bio = ਨਿਰਾ;
	ਅੱਖਰ *privptr;

	response->ਜਨਤਕ_ਕੁੰਜੀ = ਨਿਰਾ;
	response->ਜਨਤਕ_ਕੁੰਜੀ_len = 0;
	response->ਕੁੰਜੀ_handle = ਨਿਰਾ;
	response->ਕੁੰਜੀ_handle_len = 0;

	ਜੇ ((ਕੁੰਜੀ = EC_ਕੁੰਜੀ_new_by_ਵਕਰ_name(NID_X9_62_prime256v1)) == ਨਿਰਾ) {
		skdebug(__func__, "EC_KEY_new_by_curve_name");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EC_ਕੁੰਜੀ_generate_ਕੁੰਜੀ(ਕੁੰਜੀ) != 1) {
		skdebug(__func__, "EC_KEY_generate_key");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	EC_ਕੁੰਜੀ_ਸੈੱਟ_asn1_flag(ਕੁੰਜੀ, OPENSSL_EC_NAMED_ਵਕਰ);
	ਜੇ ((bio = BIO_new(BIO_s_mem())) == ਨਿਰਾ ||
	    (g = EC_ਕੁੰਜੀ_get0_ਸਮੂਹ(ਕੁੰਜੀ)) == ਨਿਰਾ ||
	    (q = EC_ਕੁੰਜੀ_get0_ਜਨਤਕ_ਕੁੰਜੀ(ਕੁੰਜੀ)) == ਨਿਰਾ) {
		skdebug(__func__, "couldn't get key parameters");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	response->ਜਨਤਕ_ਕੁੰਜੀ_len = EC_ਬਿੰਦੂ_point2oct(g, q,
	    ਬਿੰਦੂ_CONVERSION_UNCOMPRESSED, ਨਿਰਾ, 0, ਨਿਰਾ);
	ਜੇ (response->ਜਨਤਕ_ਕੁੰਜੀ_len == 0 || response->ਜਨਤਕ_ਕੁੰਜੀ_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->ਜਨਤਕ_ਕੁੰਜੀ_len);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((response->ਜਨਤਕ_ਕੁੰਜੀ = ਸਮ੍ਰਿਤੀ_ਦਿਓ(response->ਜਨਤਕ_ਕੁੰਜੀ_len)) == ਨਿਰਾ) {
		skdebug(__func__, "malloc pubkey failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EC_ਬਿੰਦੂ_point2oct(g, q, ਬਿੰਦੂ_CONVERSION_UNCOMPRESSED,
	    response->ਜਨਤਕ_ਕੁੰਜੀ, response->ਜਨਤਕ_ਕੁੰਜੀ_len, ਨਿਰਾ) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* Key handle contains PEM encoded private key */
	ਜੇ (!PEM_write_bio_ECPrivate_ਕੁੰਜੀ(bio, ਕੁੰਜੀ, ਨਿਰਾ, ਨਿਰਾ, 0, ਨਿਰਾ, ਨਿਰਾ)) {
		skdebug(__func__, "PEM_write_bio_ECPrivateKey failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((privlen = BIO_get_mem_ਅੰਕੜੇ(bio, &privptr)) <= 0) {
		skdebug(__func__, "BIO_get_mem_data failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((response->ਕੁੰਜੀ_handle = ਸਮ੍ਰਿਤੀ_ਦਿਓ(privlen)) == ਨਿਰਾ) {
		skdebug(__func__, "malloc key_handle failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	response->ਕੁੰਜੀ_handle_len = (ਮਾਪ_t)privlen;
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(response->ਕੁੰਜੀ_handle, privptr, response->ਕੁੰਜੀ_handle_len);
	/* success */
	ret = 0;
 ਬਾਹਰਲਾ:
	ਜੇ (ret != 0) {
		ਜੇ (response->ਜਨਤਕ_ਕੁੰਜੀ != ਨਿਰਾ) {
			memset(response->ਜਨਤਕ_ਕੁੰਜੀ, 0,
			    response->ਜਨਤਕ_ਕੁੰਜੀ_len);
			ਮੁਕਤ(response->ਜਨਤਕ_ਕੁੰਜੀ);
			response->ਜਨਤਕ_ਕੁੰਜੀ = ਨਿਰਾ;
		}
		ਜੇ (response->ਕੁੰਜੀ_handle != ਨਿਰਾ) {
			memset(response->ਕੁੰਜੀ_handle, 0,
			    response->ਕੁੰਜੀ_handle_len);
			ਮੁਕਤ(response->ਕੁੰਜੀ_handle);
			response->ਕੁੰਜੀ_handle = ਨਿਰਾ;
		}
	}
	BIO_free(bio);
	EC_ਕੁੰਜੀ_free(ਕੁੰਜੀ);
	ਵਾਪਸ ret;
#ਨਹੀਂਤਾਂ
	ਵਾਪਸ -1;
#ਜੇ_ਅੰਤ
}

ਸਥਿਰ ਪੂਰਨ
pack_ਕੁੰਜੀ_ed25519(ਬਣਤਰ sk_enroll_response *response)
{
	ਪੂਰਨ ret = -1;
	u_char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	u_char sk[crypto_sign_ed25519_SECRETKEYBYTES];

	response->ਜਨਤਕ_ਕੁੰਜੀ = ਨਿਰਾ;
	response->ਜਨਤਕ_ਕੁੰਜੀ_len = 0;
	response->ਕੁੰਜੀ_handle = ਨਿਰਾ;
	response->ਕੁੰਜੀ_handle_len = 0;

	memset(pk, 0, ਆਕਾਰ(pk));
	memset(sk, 0, ਆਕਾਰ(sk));
	crypto_sign_ed25519_keypair(pk, sk);

	response->ਜਨਤਕ_ਕੁੰਜੀ_len = ਆਕਾਰ(pk);
	ਜੇ ((response->ਜਨਤਕ_ਕੁੰਜੀ = ਸਮ੍ਰਿਤੀ_ਦਿਓ(response->ਜਨਤਕ_ਕੁੰਜੀ_len)) == ਨਿਰਾ) {
		skdebug(__func__, "malloc pubkey failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(response->ਜਨਤਕ_ਕੁੰਜੀ, pk, ਆਕਾਰ(pk));
	/* Key handle contains sk */
	response->ਕੁੰਜੀ_handle_len = ਆਕਾਰ(sk);
	ਜੇ ((response->ਕੁੰਜੀ_handle = ਸਮ੍ਰਿਤੀ_ਦਿਓ(response->ਕੁੰਜੀ_handle_len)) == ਨਿਰਾ) {
		skdebug(__func__, "malloc key_handle failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(response->ਕੁੰਜੀ_handle, sk, ਆਕਾਰ(sk));
	/* success */
	ret = 0;
 ਬਾਹਰਲਾ:
	ਜੇ (ret != 0)
		ਮੁਕਤ(response->ਜਨਤਕ_ਕੁੰਜੀ);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
check_options(ਬਣਤਰ sk_option **options)
{
	ਮਾਪ_t i;

	ਜੇ (options == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਲਈ (i = 0; options[i] != ਨਿਰਾ; i++) {
		skdebug(__func__, "requested unsupported option %s",
		    options[i]->name);
		ਜੇ (options[i]->required) {
			skdebug(__func__, "unknown required option");
			ਵਾਪਸ -1;
		}
	}
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sk_enroll(uint32_t alg, ਅਚਲ uint8_t *challenge, ਮਾਪ_t challenge_len,
    ਅਚਲ ਅੱਖਰ *application, uint8_t flags, ਅਚਲ ਅੱਖਰ *pin,
    ਬਣਤਰ sk_option **options, ਬਣਤਰ sk_enroll_response **enroll_response)
{
	ਬਣਤਰ sk_enroll_response *response = ਨਿਰਾ;
	ਪੂਰਨ ret = SSH_SK_ERR_GENERAL;

	(ਖਾਲੀ)flags; /* XXX; unused */

	ਜੇ (enroll_response == ਨਿਰਾ) {
		skdebug(__func__, "enroll_response == NULL");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	*enroll_response = ਨਿਰਾ;
	ਜੇ (check_options(options) != 0)
		ਜਾਓ ਬਾਹਰਲਾ; /* error already logged */
	ਜੇ ((response = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*response))) == ਨਿਰਾ) {
		skdebug(__func__, "calloc response failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	response->flags = flags;
	ਚੋਣ(alg) {
	ਹਾਲਤ SSH_SK_ECDSA:
		ਜੇ (pack_ਕੁੰਜੀ_ecdsa(response) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਰੋਕੋ;
	ਹਾਲਤ SSH_SK_ED25519:
		ਜੇ (pack_ਕੁੰਜੀ_ed25519(response) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਰੋਕੋ;
	ਮੂਲ:
		skdebug(__func__, "unsupported key type %d", alg);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* Have to return something here */
	ਜੇ ((response->signature = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, 1)) == ਨਿਰਾ) {
		skdebug(__func__, "calloc signature failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	response->signature_len = 0;

	*enroll_response = response;
	response = ਨਿਰਾ;
	ret = 0;
 ਬਾਹਰਲਾ:
	ਜੇ (response != ਨਿਰਾ) {
		ਮੁਕਤ(response->ਜਨਤਕ_ਕੁੰਜੀ);
		ਮੁਕਤ(response->ਕੁੰਜੀ_handle);
		ਮੁਕਤ(response->signature);
		ਮੁਕਤ(response->attestation_cert);
		ਮੁਕਤ(response);
	}
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਖਾਲੀ
dump(ਅਚਲ ਅੱਖਰ *preamble, ਅਚਲ ਖਾਲੀ *sv, ਮਾਪ_t l)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SK_DEBUG
	ਅਚਲ u_char *s = (ਅਚਲ u_char *)sv;
	ਮਾਪ_t i;

	fprintf(stderr, "%s (len %zu):\n", preamble, l);
	ਲਈ (i = 0; i < l; i++) {
		ਜੇ (i % 16 == 0)
			fprintf(stderr, "%04zu: ", i);
		fprintf(stderr, "%02x", s[i]);
		ਜੇ (i % 16 == 15 || i == l - 1)
			fprintf(stderr, "\n");
	}
#ਜੇ_ਅੰਤ
}

ਸਥਿਰ ਪੂਰਨ
sig_ecdsa(ਅਚਲ uint8_t *ਸੁਨੇਹਾ_2, ਮਾਪ_t ਸੁਨੇਹਾ_len_2,
    ਅਚਲ ਅੱਖਰ *application, uint32_t counter, uint8_t flags,
    ਅਚਲ uint8_t *ਕੁੰਜੀ_handle, ਮਾਪ_t ਕੁੰਜੀ_handle_len,
    ਬਣਤਰ sk_sign_response *response)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ECDSA_SIG *sig = ਨਿਰਾ;
	ਅਚਲ BIGNUM *sig_r, *sig_s;
	ਪੂਰਨ ret = -1;
	BIO *bio = ਨਿਰਾ;
	EVP_PKEY *pk = ਨਿਰਾ;
	EC_ਕੁੰਜੀ *ec = ਨਿਰਾ;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_ਲੰਮਾਈ];
	uint8_t	sighash[SHA256_DIGEST_ਲੰਮਾਈ];
	uint8_t countbuf[4];

	/* Decode EC_KEY from key handle */
	ਜੇ ((bio = BIO_new(BIO_s_mem())) == ਨਿਰਾ ||
	    BIO_write(bio, ਕੁੰਜੀ_handle, ਕੁੰਜੀ_handle_len) != (ਪੂਰਨ)ਕੁੰਜੀ_handle_len) {
		skdebug(__func__, "BIO setup failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((pk = PEM_read_bio_ਨਿੱਜੀ_ਕੁੰਜੀ(bio, ਨਿਰਾ, ਨਿਰਾ, "")) == ਨਿਰਾ) {
		skdebug(__func__, "PEM_read_bio_PrivateKey failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EVP_PKEY_ਅਧਾਰ_id(pk) != EVP_PKEY_EC) {
		skdebug(__func__, "Not an EC key: %d", EVP_PKEY_ਅਧਾਰ_id(pk));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((ec = EVP_PKEY_get1_EC_ਕੁੰਜੀ(pk)) == ਨਿਰਾ) {
		skdebug(__func__, "EVP_PKEY_get1_EC_KEY failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* Expect message to be pre-hashed */
	ਜੇ (ਸੁਨੇਹਾ_len_2 != SHA256_DIGEST_ਲੰਮਾਈ) {
		skdebug(__func__, "bad message len %zu", ਸੁਨੇਹਾ_len_2);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* Prepare data to be signed */
	dump("message", ਸੁਨੇਹਾ_2, ਸੁਨੇਹਾ_len_2);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ਅਚਲ u_char *)application, ਲੜੀ_ਲੰਬਾਈ(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, ਆਕਾਰ(apphash));
	countbuf[0] = (counter >> 24) & 0xff;
	countbuf[1] = (counter >> 16) & 0xff;
	countbuf[2] = (counter >> 8) & 0xff;
	countbuf[3] = counter & 0xff;
	dump("countbuf", countbuf, ਆਕਾਰ(countbuf));
	dump("flags", &flags, ਆਕਾਰ(flags));
	SHA256Init(&ctx);
	SHA256Update(&ctx, apphash, ਆਕਾਰ(apphash));
	SHA256Update(&ctx, &flags, ਆਕਾਰ(flags));
	SHA256Update(&ctx, countbuf, ਆਕਾਰ(countbuf));
	SHA256Update(&ctx, ਸੁਨੇਹਾ_2, ਸੁਨੇਹਾ_len_2);
	SHA256Final(sighash, &ctx);
	dump("sighash", sighash, ਆਕਾਰ(sighash));
	/* create and encode signature */
	ਜੇ ((sig = ECDSA_do_sign(sighash, ਆਕਾਰ(sighash), ec)) == ਨਿਰਾ) {
		skdebug(__func__, "ECDSA_do_sign failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_ਅੰਕ_ਬਾਈਟਾਂ(sig_r);
	response->sig_s_len = BN_ਅੰਕ_ਬਾਈਟਾਂ(sig_s);
	ਜੇ ((response->sig_r = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, response->sig_r_len)) == ਨਿਰਾ ||
	    (response->sig_s = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, response->sig_s_len)) == ਨਿਰਾ) {
		skdebug(__func__, "calloc signature failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 ਬਾਹਰਲਾ:
	explicit_bzero(&ctx, ਆਕਾਰ(ctx));
	explicit_bzero(&apphash, ਆਕਾਰ(apphash));
	explicit_bzero(&sighash, ਆਕਾਰ(sighash));
	ECDSA_SIG_free(sig);
	ਜੇ (ret != 0) {
		ਮੁਕਤ(response->sig_r);
		ਮੁਕਤ(response->sig_s);
		response->sig_r = ਨਿਰਾ;
		response->sig_s = ਨਿਰਾ;
	}
	BIO_free(bio);
	EC_ਕੁੰਜੀ_free(ec);
	EVP_PKEY_free(pk);
	ਵਾਪਸ ret;
#ਨਹੀਂਤਾਂ
	ਵਾਪਸ -1;
#ਜੇ_ਅੰਤ
}

ਸਥਿਰ ਪੂਰਨ
sig_ed25519(ਅਚਲ uint8_t *ਸੁਨੇਹਾ_2, ਮਾਪ_t ਸੁਨੇਹਾ_len_2,
    ਅਚਲ ਅੱਖਰ *application, uint32_t counter, uint8_t flags,
    ਅਚਲ uint8_t *ਕੁੰਜੀ_handle, ਮਾਪ_t ਕੁੰਜੀ_handle_len,
    ਬਣਤਰ sk_sign_response *response)
{
	ਮਾਪ_t o;
	ਪੂਰਨ ret = -1;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_ਲੰਮਾਈ];
	uint8_t signbuf[ਆਕਾਰ(apphash) + ਆਕਾਰ(flags) +
	    ਆਕਾਰ(counter) + SHA256_DIGEST_ਲੰਮਾਈ];
	uint8_t sig[crypto_sign_ed25519_ਬਾਈਟਾਂ];
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ siglen = 0;

	ਜੇ (ਕੁੰਜੀ_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		skdebug(__func__, "bad key handle length %zu", ਕੁੰਜੀ_handle_len);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* Expect message to be pre-hashed */
	ਜੇ (ਸੁਨੇਹਾ_len_2 != SHA256_DIGEST_ਲੰਮਾਈ) {
		skdebug(__func__, "bad message len %zu", ਸੁਨੇਹਾ_len_2);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* Prepare data to be signed */
	dump("message", ਸੁਨੇਹਾ_2, ਸੁਨੇਹਾ_len_2);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ਅਚਲ u_char *)application, ਲੜੀ_ਲੰਬਾਈ(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, ਆਕਾਰ(apphash));

	ਸਮ੍ਰਿਤੀ_ਨਕਲ(signbuf, apphash, ਆਕਾਰ(apphash));
	o = ਆਕਾਰ(apphash);
	signbuf[o++] = flags;
	signbuf[o++] = (counter >> 24) & 0xff;
	signbuf[o++] = (counter >> 16) & 0xff;
	signbuf[o++] = (counter >> 8) & 0xff;
	signbuf[o++] = counter & 0xff;
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(signbuf + o, ਸੁਨੇਹਾ_2, ਸੁਨੇਹਾ_len_2);
	o += ਸੁਨੇਹਾ_len_2;
	ਜੇ (o != ਆਕਾਰ(signbuf)) {
		skdebug(__func__, "bad sign buf len %zu, expected %zu",
		    o, ਆਕਾਰ(signbuf));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	dump("signbuf", signbuf, ਆਕਾਰ(signbuf));
	/* create and encode signature */
	ਜੇ (crypto_sign_ed25519_detached(sig, &siglen, signbuf, ਆਕਾਰ(signbuf),
	    ਕੁੰਜੀ_handle) != 0) {
		skdebug(__func__, "crypto_sign_ed25519_detached failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (siglen != ਆਕਾਰ(sig)) {
		skdebug(__func__, "bad signature length %llu", siglen);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	response->sig_r_len = ਆਕਾਰ(sig);
	ਜੇ ((response->sig_r = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, response->sig_r_len)) == ਨਿਰਾ) {
		skdebug(__func__, "calloc signature failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(response->sig_r, sig, response->sig_r_len);
	dump("sig_r", response->sig_r, response->sig_r_len);
	ret = 0;
 ਬਾਹਰਲਾ:
	explicit_bzero(&ctx, ਆਕਾਰ(ctx));
	explicit_bzero(&apphash, ਆਕਾਰ(apphash));
	explicit_bzero(&signbuf, ਆਕਾਰ(signbuf));
	explicit_bzero(&sig, ਆਕਾਰ(sig));
	ਜੇ (ret != 0) {
		ਮੁਕਤ(response->sig_r);
		response->sig_r = ਨਿਰਾ;
	}
	ਵਾਪਸ ret;
}

ਪੂਰਨ
sk_sign(uint32_t alg, ਅਚਲ uint8_t *ਅੰਕੜੇ, ਮਾਪ_t datalen,
    ਅਚਲ ਅੱਖਰ *application, ਅਚਲ uint8_t *ਕੁੰਜੀ_handle, ਮਾਪ_t ਕੁੰਜੀ_handle_len,
    uint8_t flags, ਅਚਲ ਅੱਖਰ *pin, ਬਣਤਰ sk_option **options,
    ਬਣਤਰ sk_sign_response **sign_response)
{
	ਬਣਤਰ sk_sign_response *response = ਨਿਰਾ;
	ਪੂਰਨ ret = SSH_SK_ERR_GENERAL;
	SHA2_CTX ctx;
	uint8_t ਸੁਨੇਹਾ_2[32];

	ਜੇ (sign_response == ਨਿਰਾ) {
		skdebug(__func__, "sign_response == NULL");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	*sign_response = ਨਿਰਾ;
	ਜੇ (check_options(options) != 0)
		ਜਾਓ ਬਾਹਰਲਾ; /* error already logged */
	ਜੇ ((response = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*response))) == ਨਿਰਾ) {
		skdebug(__func__, "calloc response failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	SHA256Init(&ctx);
	SHA256Update(&ctx, ਅੰਕੜੇ, datalen);
	SHA256Final(ਸੁਨੇਹਾ_2, &ctx);
	response->flags = flags;
	response->counter = 0x12345678;
	ਚੋਣ(alg) {
	ਹਾਲਤ SSH_SK_ECDSA:
		ਜੇ (sig_ecdsa(ਸੁਨੇਹਾ_2, ਆਕਾਰ(ਸੁਨੇਹਾ_2), application,
		    response->counter, flags, ਕੁੰਜੀ_handle, ਕੁੰਜੀ_handle_len,
		    response) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਰੋਕੋ;
	ਹਾਲਤ SSH_SK_ED25519:
		ਜੇ (sig_ed25519(ਸੁਨੇਹਾ_2, ਆਕਾਰ(ਸੁਨੇਹਾ_2), application,
		    response->counter, flags, ਕੁੰਜੀ_handle, ਕੁੰਜੀ_handle_len,
		    response) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਰੋਕੋ;
	ਮੂਲ:
		skdebug(__func__, "unsupported key type %d", alg);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	*sign_response = response;
	response = ਨਿਰਾ;
	ret = 0;
 ਬਾਹਰਲਾ:
	explicit_bzero(ਸੁਨੇਹਾ_2, ਆਕਾਰ(ਸੁਨੇਹਾ_2));
	ਜੇ (response != ਨਿਰਾ) {
		ਮੁਕਤ(response->sig_r);
		ਮੁਕਤ(response->sig_s);
		ਮੁਕਤ(response);
	}
	ਵਾਪਸ ret;
}

ਪੂਰਨ
sk_ਲੱਦੋ_resident_ਕੁੰਜੀਆਂ(ਅਚਲ ਅੱਖਰ *pin, ਬਣਤਰ sk_option **options,
    ਬਣਤਰ sk_resident_ਕੁੰਜੀ ***rks, ਮਾਪ_t *nrks)
{
	ਵਾਪਸ SSH_SK_ERR_UNSUPPORTED;
}
