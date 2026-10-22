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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stddef.h>
#అన్తర్భావ <stdarg.h>

#అన్తర్భావ "crypto_api.h"
#అన్తర్భావ "sk-api.h"

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/opensslv.h>
#అన్తర్భావ <openssl/sha.h>
#అన్తర్భావ <openssl/crypto.h>
#అన్తర్భావ <openssl/evp.h>
#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/ec.h>
#అన్తర్భావ <openssl/ecdsa.h>
#అన్తర్భావ <openssl/pem.h>

/* Use OpenSSL SHA256 instead of libc */
#నిర్వచించు SHA256Init(x)		SHA256_Init(x)
#నిర్వచించు SHA256Update(x, y, z)	SHA256_Update(x, y, z)
#నిర్వచించు SHA256Final(x, y)	SHA256_Final(x, y)
#నిర్వచించు SHA2_CTX		SHA256_CTX

#లేదావేళ defined(HAVE_SHA2_H)
#అన్తర్భావ <sha2.h>
#అయితే_ముగింపు /* WITH_OPENSSL */

/* #define SK_DEBUG 1 */

#ఒకవేళ SSH_SK_సంస్కరణ_MAJOR != 0x000a0000
# error SK API has మారింది, sk-dummy.c needs an update
#అయితే_ముగింపు

#నిర్వచితమైతే SK_DUMMY_INTEGRATE
# define sk_api_సంస్కరణ		ssh_sk_api_సంస్కరణ
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_ఎక్కించు_resident_కీలకాలు	ssh_sk_ఎక్కించు_resident_కీలకాలు
#అయితే_ముగింపు /* !SK_STANDALONE */

స్థిర శూన్య skdebug(స్థిరరాశి అక్షరం *func, స్థిరరాశి అక్షరం *fmt, ...)
    __attribute__((__format__ (రాయి, 2, 3)));

స్థిర శూన్య
skdebug(స్థిరరాశి అక్షరం *func, స్థిరరాశి అక్షరం *fmt, ...)
{
#ఒకవేళ defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "sk-dummy %s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#లేకపోతే
	(శూన్య)func; /* XXX */
	(శూన్య)fmt; /* XXX */
#అయితే_ముగింపు
}

uint32_t
sk_api_సంస్కరణ(శూన్య)
{
	తిరిగి SSH_SK_సంస్కరణ_MAJOR;
}

స్థిర పూర్ణాంకం
pack_కీలకం_ecdsa(నిర్మాణం sk_enroll_response *response)
{
#నిర్వచితమైతే WITH_OPENSSL
	EC_కీలకం *కీలకం = ఖాళీ;
	స్థిరరాశి EC_సమూహం *g;
	స్థిరరాశి EC_బిందువు *q;
	పూర్ణాంకం ret = -1;
	దీర్ఘ privlen;
	BIO *bio = ఖాళీ;
	అక్షరం *privptr;

	response->ప్రజా_కీలకం = ఖాళీ;
	response->ప్రజా_కీలకం_len = 0;
	response->కీలకం_handle = ఖాళీ;
	response->కీలకం_handle_len = 0;

	ఒకవేళ ((కీలకం = EC_కీలకం_new_by_వక్రం_name(NID_X9_62_prime256v1)) == ఖాళీ) {
		skdebug(__func__, "EC_KEY_new_by_curve_name");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EC_కీలకం_generate_కీలకం(కీలకం) != 1) {
		skdebug(__func__, "EC_KEY_generate_key");
		వెళ్ళు బహిర్గతం;
	}
	EC_కీలకం_సమితి_asn1_flag(కీలకం, OPENSSL_EC_NAMED_వక్రం);
	ఒకవేళ ((bio = BIO_new(BIO_s_mem())) == ఖాళీ ||
	    (g = EC_కీలకం_get0_సమూహం(కీలకం)) == ఖాళీ ||
	    (q = EC_కీలకం_get0_ప్రజా_కీలకం(కీలకం)) == ఖాళీ) {
		skdebug(__func__, "couldn't get key parameters");
		వెళ్ళు బహిర్గతం;
	}
	response->ప్రజా_కీలకం_len = EC_బిందువు_point2oct(g, q,
	    బిందువు_CONVERSION_UNCOMPRESSED, ఖాళీ, 0, ఖాళీ);
	ఒకవేళ (response->ప్రజా_కీలకం_len == 0 || response->ప్రజా_కీలకం_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->ప్రజా_కీలకం_len);
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((response->ప్రజా_కీలకం = జ్ఞాపకం_ఇవ్వు(response->ప్రజా_కీలకం_len)) == ఖాళీ) {
		skdebug(__func__, "malloc pubkey failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EC_బిందువు_point2oct(g, q, బిందువు_CONVERSION_UNCOMPRESSED,
	    response->ప్రజా_కీలకం, response->ప్రజా_కీలకం_len, ఖాళీ) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		వెళ్ళు బహిర్గతం;
	}
	/* Key handle contains PEM encoded private key */
	ఒకవేళ (!PEM_write_bio_ECPrivate_కీలకం(bio, కీలకం, ఖాళీ, ఖాళీ, 0, ఖాళీ, ఖాళీ)) {
		skdebug(__func__, "PEM_write_bio_ECPrivateKey failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((privlen = BIO_get_mem_దత్తాంశం(bio, &privptr)) <= 0) {
		skdebug(__func__, "BIO_get_mem_data failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((response->కీలకం_handle = జ్ఞాపకం_ఇవ్వు(privlen)) == ఖాళీ) {
		skdebug(__func__, "malloc key_handle failed");
		వెళ్ళు బహిర్గతం;
	}
	response->కీలకం_handle_len = (కొలత_t)privlen;
	జ్ఞాపకం_నకలు(response->కీలకం_handle, privptr, response->కీలకం_handle_len);
	/* success */
	ret = 0;
 బహిర్గతం:
	ఒకవేళ (ret != 0) {
		ఒకవేళ (response->ప్రజా_కీలకం != ఖాళీ) {
			memset(response->ప్రజా_కీలకం, 0,
			    response->ప్రజా_కీలకం_len);
			విడుదల(response->ప్రజా_కీలకం);
			response->ప్రజా_కీలకం = ఖాళీ;
		}
		ఒకవేళ (response->కీలకం_handle != ఖాళీ) {
			memset(response->కీలకం_handle, 0,
			    response->కీలకం_handle_len);
			విడుదల(response->కీలకం_handle);
			response->కీలకం_handle = ఖాళీ;
		}
	}
	BIO_free(bio);
	EC_కీలకం_free(కీలకం);
	తిరిగి ret;
#లేకపోతే
	తిరిగి -1;
#అయితే_ముగింపు
}

స్థిర పూర్ణాంకం
pack_కీలకం_ed25519(నిర్మాణం sk_enroll_response *response)
{
	పూర్ణాంకం ret = -1;
	u_char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	u_char sk[crypto_sign_ed25519_SECRETKEYBYTES];

	response->ప్రజా_కీలకం = ఖాళీ;
	response->ప్రజా_కీలకం_len = 0;
	response->కీలకం_handle = ఖాళీ;
	response->కీలకం_handle_len = 0;

	memset(pk, 0, పరిమాణం(pk));
	memset(sk, 0, పరిమాణం(sk));
	crypto_sign_ed25519_keypair(pk, sk);

	response->ప్రజా_కీలకం_len = పరిమాణం(pk);
	ఒకవేళ ((response->ప్రజా_కీలకం = జ్ఞాపకం_ఇవ్వు(response->ప్రజా_కీలకం_len)) == ఖాళీ) {
		skdebug(__func__, "malloc pubkey failed");
		వెళ్ళు బహిర్గతం;
	}
	జ్ఞాపకం_నకలు(response->ప్రజా_కీలకం, pk, పరిమాణం(pk));
	/* Key handle contains sk */
	response->కీలకం_handle_len = పరిమాణం(sk);
	ఒకవేళ ((response->కీలకం_handle = జ్ఞాపకం_ఇవ్వు(response->కీలకం_handle_len)) == ఖాళీ) {
		skdebug(__func__, "malloc key_handle failed");
		వెళ్ళు బహిర్గతం;
	}
	జ్ఞాపకం_నకలు(response->కీలకం_handle, sk, పరిమాణం(sk));
	/* success */
	ret = 0;
 బహిర్గతం:
	ఒకవేళ (ret != 0)
		విడుదల(response->ప్రజా_కీలకం);
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
check_options(నిర్మాణం sk_option **options)
{
	కొలత_t i;

	ఒకవేళ (options == ఖాళీ)
		తిరిగి 0;
	కొరకు (i = 0; options[i] != ఖాళీ; i++) {
		skdebug(__func__, "requested unsupported option %s",
		    options[i]->name);
		ఒకవేళ (options[i]->required) {
			skdebug(__func__, "unknown required option");
			తిరిగి -1;
		}
	}
	తిరిగి 0;
}

పూర్ణాంకం
sk_enroll(uint32_t alg, స్థిరరాశి uint8_t *challenge, కొలత_t challenge_len,
    స్థిరరాశి అక్షరం *application, uint8_t flags, స్థిరరాశి అక్షరం *pin,
    నిర్మాణం sk_option **options, నిర్మాణం sk_enroll_response **enroll_response)
{
	నిర్మాణం sk_enroll_response *response = ఖాళీ;
	పూర్ణాంకం ret = SSH_SK_ERR_GENERAL;

	(శూన్య)flags; /* XXX; unused */

	ఒకవేళ (enroll_response == ఖాళీ) {
		skdebug(__func__, "enroll_response == NULL");
		వెళ్ళు బహిర్గతం;
	}
	*enroll_response = ఖాళీ;
	ఒకవేళ (check_options(options) != 0)
		వెళ్ళు బహిర్గతం; /* error already logged */
	ఒకవేళ ((response = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*response))) == ఖాళీ) {
		skdebug(__func__, "calloc response failed");
		వెళ్ళు బహిర్గతం;
	}
	response->flags = flags;
	ఎంపిక(alg) {
	స్థితి SSH_SK_ECDSA:
		ఒకవేళ (pack_కీలకం_ecdsa(response) != 0)
			వెళ్ళు బహిర్గతం;
		ఆపు;
	స్థితి SSH_SK_ED25519:
		ఒకవేళ (pack_కీలకం_ed25519(response) != 0)
			వెళ్ళు బహిర్గతం;
		ఆపు;
	అప్రమేయ:
		skdebug(__func__, "unsupported key type %d", alg);
		వెళ్ళు బహిర్గతం;
	}
	/* Have to return something here */
	ఒకవేళ ((response->signature = సున్నా_జ్ఞాపకం_ఇవ్వు(1, 1)) == ఖాళీ) {
		skdebug(__func__, "calloc signature failed");
		వెళ్ళు బహిర్గతం;
	}
	response->signature_len = 0;

	*enroll_response = response;
	response = ఖాళీ;
	ret = 0;
 బహిర్గతం:
	ఒకవేళ (response != ఖాళీ) {
		విడుదల(response->ప్రజా_కీలకం);
		విడుదల(response->కీలకం_handle);
		విడుదల(response->signature);
		విడుదల(response->attestation_cert);
		విడుదల(response);
	}
	తిరిగి ret;
}

స్థిర శూన్య
dump(స్థిరరాశి అక్షరం *preamble, స్థిరరాశి శూన్య *sv, కొలత_t l)
{
#నిర్వచితమైతే SK_DEBUG
	స్థిరరాశి u_char *s = (స్థిరరాశి u_char *)sv;
	కొలత_t i;

	fprintf(stderr, "%s (len %zu):\n", preamble, l);
	కొరకు (i = 0; i < l; i++) {
		ఒకవేళ (i % 16 == 0)
			fprintf(stderr, "%04zu: ", i);
		fprintf(stderr, "%02x", s[i]);
		ఒకవేళ (i % 16 == 15 || i == l - 1)
			fprintf(stderr, "\n");
	}
#అయితే_ముగింపు
}

స్థిర పూర్ణాంకం
sig_ecdsa(స్థిరరాశి uint8_t *సందేశం_2, కొలత_t సందేశం_len_2,
    స్థిరరాశి అక్షరం *application, uint32_t counter, uint8_t flags,
    స్థిరరాశి uint8_t *కీలకం_handle, కొలత_t కీలకం_handle_len,
    నిర్మాణం sk_sign_response *response)
{
#నిర్వచితమైతే WITH_OPENSSL
	ECDSA_SIG *sig = ఖాళీ;
	స్థిరరాశి BIGNUM *sig_r, *sig_s;
	పూర్ణాంకం ret = -1;
	BIO *bio = ఖాళీ;
	EVP_PKEY *pk = ఖాళీ;
	EC_కీలకం *ec = ఖాళీ;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_నిడివి];
	uint8_t	sighash[SHA256_DIGEST_నిడివి];
	uint8_t countbuf[4];

	/* Decode EC_KEY from key handle */
	ఒకవేళ ((bio = BIO_new(BIO_s_mem())) == ఖాళీ ||
	    BIO_write(bio, కీలకం_handle, కీలకం_handle_len) != (పూర్ణాంకం)కీలకం_handle_len) {
		skdebug(__func__, "BIO setup failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((pk = PEM_read_bio_వ్యక్తిగత_కీలకం(bio, ఖాళీ, ఖాళీ, "")) == ఖాళీ) {
		skdebug(__func__, "PEM_read_bio_PrivateKey failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EVP_PKEY_పునాది_id(pk) != EVP_PKEY_EC) {
		skdebug(__func__, "Not an EC key: %d", EVP_PKEY_పునాది_id(pk));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((ec = EVP_PKEY_get1_EC_కీలకం(pk)) == ఖాళీ) {
		skdebug(__func__, "EVP_PKEY_get1_EC_KEY failed");
		వెళ్ళు బహిర్గతం;
	}
	/* Expect message to be pre-hashed */
	ఒకవేళ (సందేశం_len_2 != SHA256_DIGEST_నిడివి) {
		skdebug(__func__, "bad message len %zu", సందేశం_len_2);
		వెళ్ళు బహిర్గతం;
	}
	/* Prepare data to be signed */
	dump("message", సందేశం_2, సందేశం_len_2);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (స్థిరరాశి u_char *)application, అక్షరశ్రేణి_పొడవు(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, పరిమాణం(apphash));
	countbuf[0] = (counter >> 24) & 0xff;
	countbuf[1] = (counter >> 16) & 0xff;
	countbuf[2] = (counter >> 8) & 0xff;
	countbuf[3] = counter & 0xff;
	dump("countbuf", countbuf, పరిమాణం(countbuf));
	dump("flags", &flags, పరిమాణం(flags));
	SHA256Init(&ctx);
	SHA256Update(&ctx, apphash, పరిమాణం(apphash));
	SHA256Update(&ctx, &flags, పరిమాణం(flags));
	SHA256Update(&ctx, countbuf, పరిమాణం(countbuf));
	SHA256Update(&ctx, సందేశం_2, సందేశం_len_2);
	SHA256Final(sighash, &ctx);
	dump("sighash", sighash, పరిమాణం(sighash));
	/* create and encode signature */
	ఒకవేళ ((sig = ECDSA_do_sign(sighash, పరిమాణం(sighash), ec)) == ఖాళీ) {
		skdebug(__func__, "ECDSA_do_sign failed");
		వెళ్ళు బహిర్గతం;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_అంకె_బైట్లు(sig_r);
	response->sig_s_len = BN_అంకె_బైట్లు(sig_s);
	ఒకవేళ ((response->sig_r = సున్నా_జ్ఞాపకం_ఇవ్వు(1, response->sig_r_len)) == ఖాళీ ||
	    (response->sig_s = సున్నా_జ్ఞాపకం_ఇవ్వు(1, response->sig_s_len)) == ఖాళీ) {
		skdebug(__func__, "calloc signature failed");
		వెళ్ళు బహిర్గతం;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 బహిర్గతం:
	explicit_bzero(&ctx, పరిమాణం(ctx));
	explicit_bzero(&apphash, పరిమాణం(apphash));
	explicit_bzero(&sighash, పరిమాణం(sighash));
	ECDSA_SIG_free(sig);
	ఒకవేళ (ret != 0) {
		విడుదల(response->sig_r);
		విడుదల(response->sig_s);
		response->sig_r = ఖాళీ;
		response->sig_s = ఖాళీ;
	}
	BIO_free(bio);
	EC_కీలకం_free(ec);
	EVP_PKEY_free(pk);
	తిరిగి ret;
#లేకపోతే
	తిరిగి -1;
#అయితే_ముగింపు
}

స్థిర పూర్ణాంకం
sig_ed25519(స్థిరరాశి uint8_t *సందేశం_2, కొలత_t సందేశం_len_2,
    స్థిరరాశి అక్షరం *application, uint32_t counter, uint8_t flags,
    స్థిరరాశి uint8_t *కీలకం_handle, కొలత_t కీలకం_handle_len,
    నిర్మాణం sk_sign_response *response)
{
	కొలత_t o;
	పూర్ణాంకం ret = -1;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_నిడివి];
	uint8_t signbuf[పరిమాణం(apphash) + పరిమాణం(flags) +
	    పరిమాణం(counter) + SHA256_DIGEST_నిడివి];
	uint8_t sig[crypto_sign_ed25519_బైట్లు];
	గుర్తులేని దీర్ఘ దీర్ఘ siglen = 0;

	ఒకవేళ (కీలకం_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		skdebug(__func__, "bad key handle length %zu", కీలకం_handle_len);
		వెళ్ళు బహిర్గతం;
	}
	/* Expect message to be pre-hashed */
	ఒకవేళ (సందేశం_len_2 != SHA256_DIGEST_నిడివి) {
		skdebug(__func__, "bad message len %zu", సందేశం_len_2);
		వెళ్ళు బహిర్గతం;
	}
	/* Prepare data to be signed */
	dump("message", సందేశం_2, సందేశం_len_2);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (స్థిరరాశి u_char *)application, అక్షరశ్రేణి_పొడవు(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, పరిమాణం(apphash));

	జ్ఞాపకం_నకలు(signbuf, apphash, పరిమాణం(apphash));
	o = పరిమాణం(apphash);
	signbuf[o++] = flags;
	signbuf[o++] = (counter >> 24) & 0xff;
	signbuf[o++] = (counter >> 16) & 0xff;
	signbuf[o++] = (counter >> 8) & 0xff;
	signbuf[o++] = counter & 0xff;
	జ్ఞాపకం_నకలు(signbuf + o, సందేశం_2, సందేశం_len_2);
	o += సందేశం_len_2;
	ఒకవేళ (o != పరిమాణం(signbuf)) {
		skdebug(__func__, "bad sign buf len %zu, expected %zu",
		    o, పరిమాణం(signbuf));
		వెళ్ళు బహిర్గతం;
	}
	dump("signbuf", signbuf, పరిమాణం(signbuf));
	/* create and encode signature */
	ఒకవేళ (crypto_sign_ed25519_detached(sig, &siglen, signbuf, పరిమాణం(signbuf),
	    కీలకం_handle) != 0) {
		skdebug(__func__, "crypto_sign_ed25519_detached failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (siglen != పరిమాణం(sig)) {
		skdebug(__func__, "bad signature length %llu", siglen);
		వెళ్ళు బహిర్గతం;
	}
	response->sig_r_len = పరిమాణం(sig);
	ఒకవేళ ((response->sig_r = సున్నా_జ్ఞాపకం_ఇవ్వు(1, response->sig_r_len)) == ఖాళీ) {
		skdebug(__func__, "calloc signature failed");
		వెళ్ళు బహిర్గతం;
	}
	జ్ఞాపకం_నకలు(response->sig_r, sig, response->sig_r_len);
	dump("sig_r", response->sig_r, response->sig_r_len);
	ret = 0;
 బహిర్గతం:
	explicit_bzero(&ctx, పరిమాణం(ctx));
	explicit_bzero(&apphash, పరిమాణం(apphash));
	explicit_bzero(&signbuf, పరిమాణం(signbuf));
	explicit_bzero(&sig, పరిమాణం(sig));
	ఒకవేళ (ret != 0) {
		విడుదల(response->sig_r);
		response->sig_r = ఖాళీ;
	}
	తిరిగి ret;
}

పూర్ణాంకం
sk_sign(uint32_t alg, స్థిరరాశి uint8_t *దత్తాంశం, కొలత_t datalen,
    స్థిరరాశి అక్షరం *application, స్థిరరాశి uint8_t *కీలకం_handle, కొలత_t కీలకం_handle_len,
    uint8_t flags, స్థిరరాశి అక్షరం *pin, నిర్మాణం sk_option **options,
    నిర్మాణం sk_sign_response **sign_response)
{
	నిర్మాణం sk_sign_response *response = ఖాళీ;
	పూర్ణాంకం ret = SSH_SK_ERR_GENERAL;
	SHA2_CTX ctx;
	uint8_t సందేశం_2[32];

	ఒకవేళ (sign_response == ఖాళీ) {
		skdebug(__func__, "sign_response == NULL");
		వెళ్ళు బహిర్గతం;
	}
	*sign_response = ఖాళీ;
	ఒకవేళ (check_options(options) != 0)
		వెళ్ళు బహిర్గతం; /* error already logged */
	ఒకవేళ ((response = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*response))) == ఖాళీ) {
		skdebug(__func__, "calloc response failed");
		వెళ్ళు బహిర్గతం;
	}
	SHA256Init(&ctx);
	SHA256Update(&ctx, దత్తాంశం, datalen);
	SHA256Final(సందేశం_2, &ctx);
	response->flags = flags;
	response->counter = 0x12345678;
	ఎంపిక(alg) {
	స్థితి SSH_SK_ECDSA:
		ఒకవేళ (sig_ecdsa(సందేశం_2, పరిమాణం(సందేశం_2), application,
		    response->counter, flags, కీలకం_handle, కీలకం_handle_len,
		    response) != 0)
			వెళ్ళు బహిర్గతం;
		ఆపు;
	స్థితి SSH_SK_ED25519:
		ఒకవేళ (sig_ed25519(సందేశం_2, పరిమాణం(సందేశం_2), application,
		    response->counter, flags, కీలకం_handle, కీలకం_handle_len,
		    response) != 0)
			వెళ్ళు బహిర్గతం;
		ఆపు;
	అప్రమేయ:
		skdebug(__func__, "unsupported key type %d", alg);
		వెళ్ళు బహిర్గతం;
	}
	*sign_response = response;
	response = ఖాళీ;
	ret = 0;
 బహిర్గతం:
	explicit_bzero(సందేశం_2, పరిమాణం(సందేశం_2));
	ఒకవేళ (response != ఖాళీ) {
		విడుదల(response->sig_r);
		విడుదల(response->sig_s);
		విడుదల(response);
	}
	తిరిగి ret;
}

పూర్ణాంకం
sk_ఎక్కించు_resident_కీలకాలు(స్థిరరాశి అక్షరం *pin, నిర్మాణం sk_option **options,
    నిర్మాణం sk_resident_కీలకం ***rks, కొలత_t *nrks)
{
	తిరిగి SSH_SK_ERR_UNSUPPORTED;
}
