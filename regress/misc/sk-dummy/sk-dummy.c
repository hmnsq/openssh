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

#यदि_परिभाषितम् WITH_OPENSSL
#अन्तर्भाव <openssl/opensslv.h>
#अन्तर्भाव <openssl/sha.h>
#अन्तर्भाव <openssl/crypto.h>
#अन्तर्भाव <openssl/evp.h>
#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/ec.h>
#अन्तर्भाव <openssl/ecdsa.h>
#अन्तर्भाव <openssl/pem.h>

/* Use OpenSSL SHA256 instead of libc */
#परिभाषय SHA256Init(x)		SHA256_Init(x)
#परिभाषय SHA256Update(x, y, z)	SHA256_Update(x, y, z)
#परिभाषय SHA256Final(x, y)	SHA256_Final(x, y)
#परिभाषय SHA2_CTX		SHA256_CTX

#नोचेद्यदि defined(HAVE_SHA2_H)
#अन्तर्भाव <sha2.h>
#यदि_अन्तः /* WITH_OPENSSL */

/* #define SK_DEBUG 1 */

#यदि SSH_SK_संस्करणम्_MAJOR != 0x000a0000
# error SK API has परिवर्तितम्, sk-dummy.c needs an update
#यदि_अन्तः

#यदि_परिभाषितम् SK_DUMMY_INTEGRATE
# define sk_api_संस्करणम्		ssh_sk_api_संस्करणम्
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_आरोपय_resident_कुञ्चिकाः	ssh_sk_आरोपय_resident_कुञ्चिकाः
#यदि_अन्तः /* !SK_STANDALONE */

स्थिर शून्य skdebug(ध्रुव वर्ण *func, ध्रुव वर्ण *fmt, ...)
    __attribute__((__format__ (प्रारूप_लिख, 2, 3)));

स्थिर शून्य
skdebug(ध्रुव वर्ण *func, ध्रुव वर्ण *fmt, ...)
{
#यदि defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "sk-dummy %s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#अन्यथा
	(शून्य)func; /* XXX */
	(शून्य)fmt; /* XXX */
#यदि_अन्तः
}

uint32_t
sk_api_संस्करणम्(शून्य)
{
	प्रत्यागम SSH_SK_संस्करणम्_MAJOR;
}

स्थिर पूर्णाङ्क
pack_कुञ्चिका_ecdsa(संरचना sk_enroll_response *response)
{
#यदि_परिभाषितम् WITH_OPENSSL
	EC_कुञ्चिका *कुञ्चिका = रिक्त;
	ध्रुव EC_गणः *g;
	ध्रुव EC_POINT *q;
	पूर्णाङ्क ret = -1;
	दीर्घ privlen;
	BIO *bio = रिक्त;
	वर्ण *privptr;

	response->लौकिकम्_कुञ्चिका = रिक्त;
	response->लौकिकम्_कुञ्चिका_len = 0;
	response->कुञ्चिका_handle = रिक्त;
	response->कुञ्चिका_handle_len = 0;

	यदि ((कुञ्चिका = EC_कुञ्चिका_new_by_वक्रम्_name(NID_X9_62_prime256v1)) == रिक्त) {
		skdebug(__func__, "EC_KEY_new_by_curve_name");
		गच्छ बहिर्गमनम्;
	}
	यदि (EC_कुञ्चिका_generate_कुञ्चिका(कुञ्चिका) != 1) {
		skdebug(__func__, "EC_KEY_generate_key");
		गच्छ बहिर्गमनम्;
	}
	EC_कुञ्चिका_समुच्चयः_asn1_flag(कुञ्चिका, OPENSSL_EC_NAMED_वक्रम्);
	यदि ((bio = BIO_new(BIO_s_mem())) == रिक्त ||
	    (g = EC_कुञ्चिका_get0_गणः(कुञ्चिका)) == रिक्त ||
	    (q = EC_कुञ्चिका_get0_लौकिकम्_कुञ्चिका(कुञ्चिका)) == रिक्त) {
		skdebug(__func__, "couldn't get key parameters");
		गच्छ बहिर्गमनम्;
	}
	response->लौकिकम्_कुञ्चिका_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, रिक्त, 0, रिक्त);
	यदि (response->लौकिकम्_कुञ्चिका_len == 0 || response->लौकिकम्_कुञ्चिका_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->लौकिकम्_कुञ्चिका_len);
		गच्छ बहिर्गमनम्;
	}
	यदि ((response->लौकिकम्_कुञ्चिका = स्मृतिं_देहि(response->लौकिकम्_कुञ्चिका_len)) == रिक्त) {
		skdebug(__func__, "malloc pubkey failed");
		गच्छ बहिर्गमनम्;
	}
	यदि (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->लौकिकम्_कुञ्चिका, response->लौकिकम्_कुञ्चिका_len, रिक्त) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		गच्छ बहिर्गमनम्;
	}
	/* Key handle contains PEM encoded private key */
	यदि (!PEM_write_bio_ECPrivate_कुञ्चिका(bio, कुञ्चिका, रिक्त, रिक्त, 0, रिक्त, रिक्त)) {
		skdebug(__func__, "PEM_write_bio_ECPrivateKey failed");
		गच्छ बहिर्गमनम्;
	}
	यदि ((privlen = BIO_get_mem_दत्त(bio, &privptr)) <= 0) {
		skdebug(__func__, "BIO_get_mem_data failed");
		गच्छ बहिर्गमनम्;
	}
	यदि ((response->कुञ्चिका_handle = स्मृतिं_देहि(privlen)) == रिक्त) {
		skdebug(__func__, "malloc key_handle failed");
		गच्छ बहिर्गमनम्;
	}
	response->कुञ्चिका_handle_len = (आकार_t)privlen;
	स्मृतिं_प्रतिलिख(response->कुञ्चिका_handle, privptr, response->कुञ्चिका_handle_len);
	/* success */
	ret = 0;
 बहिर्गमनम्:
	यदि (ret != 0) {
		यदि (response->लौकिकम्_कुञ्चिका != रिक्त) {
			स्मृतिं_पूरय(response->लौकिकम्_कुञ्चिका, 0,
			    response->लौकिकम्_कुञ्चिका_len);
			मुक्त(response->लौकिकम्_कुञ्चिका);
			response->लौकिकम्_कुञ्चिका = रिक्त;
		}
		यदि (response->कुञ्चिका_handle != रिक्त) {
			स्मृतिं_पूरय(response->कुञ्चिका_handle, 0,
			    response->कुञ्चिका_handle_len);
			मुक्त(response->कुञ्चिका_handle);
			response->कुञ्चिका_handle = रिक्त;
		}
	}
	BIO_free(bio);
	EC_कुञ्चिका_free(कुञ्चिका);
	प्रत्यागम ret;
#अन्यथा
	प्रत्यागम -1;
#यदि_अन्तः
}

स्थिर पूर्णाङ्क
pack_कुञ्चिका_ed25519(संरचना sk_enroll_response *response)
{
	पूर्णाङ्क ret = -1;
	u_char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	u_char sk[crypto_sign_ed25519_SECRETKEYBYTES];

	response->लौकिकम्_कुञ्चिका = रिक्त;
	response->लौकिकम्_कुञ्चिका_len = 0;
	response->कुञ्चिका_handle = रिक्त;
	response->कुञ्चिका_handle_len = 0;

	स्मृतिं_पूरय(pk, 0, परिमाण(pk));
	स्मृतिं_पूरय(sk, 0, परिमाण(sk));
	crypto_sign_ed25519_keypair(pk, sk);

	response->लौकिकम्_कुञ्चिका_len = परिमाण(pk);
	यदि ((response->लौकिकम्_कुञ्चिका = स्मृतिं_देहि(response->लौकिकम्_कुञ्चिका_len)) == रिक्त) {
		skdebug(__func__, "malloc pubkey failed");
		गच्छ बहिर्गमनम्;
	}
	स्मृतिं_प्रतिलिख(response->लौकिकम्_कुञ्चिका, pk, परिमाण(pk));
	/* Key handle contains sk */
	response->कुञ्चिका_handle_len = परिमाण(sk);
	यदि ((response->कुञ्चिका_handle = स्मृतिं_देहि(response->कुञ्चिका_handle_len)) == रिक्त) {
		skdebug(__func__, "malloc key_handle failed");
		गच्छ बहिर्गमनम्;
	}
	स्मृतिं_प्रतिलिख(response->कुञ्चिका_handle, sk, परिमाण(sk));
	/* success */
	ret = 0;
 बहिर्गमनम्:
	यदि (ret != 0)
		मुक्त(response->लौकिकम्_कुञ्चिका);
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
check_options(संरचना sk_option **options)
{
	आकार_t i;

	यदि (options == रिक्त)
		प्रत्यागम 0;
	प्रति (i = 0; options[i] != रिक्त; i++) {
		skdebug(__func__, "requested unsupported option %s",
		    options[i]->name);
		यदि (options[i]->required) {
			skdebug(__func__, "unknown required option");
			प्रत्यागम -1;
		}
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
sk_enroll(uint32_t alg, ध्रुव uint8_t *challenge, आकार_t challenge_len,
    ध्रुव वर्ण *application, uint8_t flags, ध्रुव वर्ण *pin,
    संरचना sk_option **options, संरचना sk_enroll_response **enroll_response)
{
	संरचना sk_enroll_response *response = रिक्त;
	पूर्णाङ्क ret = SSH_SK_ERR_GENERAL;

	(शून्य)flags; /* XXX; unused */

	यदि (enroll_response == रिक्त) {
		skdebug(__func__, "enroll_response == NULL");
		गच्छ बहिर्गमनम्;
	}
	*enroll_response = रिक्त;
	यदि (check_options(options) != 0)
		गच्छ बहिर्गमनम्; /* error already logged */
	यदि ((response = शून्यस्मृतिं_देहि(1, परिमाण(*response))) == रिक्त) {
		skdebug(__func__, "calloc response failed");
		गच्छ बहिर्गमनम्;
	}
	response->flags = flags;
	विकल्प(alg) {
	पक्ष SSH_SK_ECDSA:
		यदि (pack_कुञ्चिका_ecdsa(response) != 0)
			गच्छ बहिर्गमनम्;
		भङ्ग;
	पक्ष SSH_SK_ED25519:
		यदि (pack_कुञ्चिका_ed25519(response) != 0)
			गच्छ बहिर्गमनम्;
		भङ्ग;
	स्वभाव:
		skdebug(__func__, "unsupported key type %d", alg);
		गच्छ बहिर्गमनम्;
	}
	/* Have to return something here */
	यदि ((response->signature = शून्यस्मृतिं_देहि(1, 1)) == रिक्त) {
		skdebug(__func__, "calloc signature failed");
		गच्छ बहिर्गमनम्;
	}
	response->signature_len = 0;

	*enroll_response = response;
	response = रिक्त;
	ret = 0;
 बहिर्गमनम्:
	यदि (response != रिक्त) {
		मुक्त(response->लौकिकम्_कुञ्चिका);
		मुक्त(response->कुञ्चिका_handle);
		मुक्त(response->signature);
		मुक्त(response->attestation_cert);
		मुक्त(response);
	}
	प्रत्यागम ret;
}

स्थिर शून्य
dump(ध्रुव वर्ण *preamble, ध्रुव शून्य *sv, आकार_t l)
{
#यदि_परिभाषितम् SK_DEBUG
	ध्रुव u_char *s = (ध्रुव u_char *)sv;
	आकार_t i;

	fprintf(stderr, "%s (len %zu):\n", preamble, l);
	प्रति (i = 0; i < l; i++) {
		यदि (i % 16 == 0)
			fprintf(stderr, "%04zu: ", i);
		fprintf(stderr, "%02x", s[i]);
		यदि (i % 16 == 15 || i == l - 1)
			fprintf(stderr, "\n");
	}
#यदि_अन्तः
}

स्थिर पूर्णाङ्क
sig_ecdsa(ध्रुव uint8_t *सन्देशः_2, आकार_t सन्देशः_len_2,
    ध्रुव वर्ण *application, uint32_t गणक, uint8_t flags,
    ध्रुव uint8_t *कुञ्चिका_handle, आकार_t कुञ्चिका_handle_len,
    संरचना sk_sign_response *response)
{
#यदि_परिभाषितम् WITH_OPENSSL
	ECDSA_SIG *sig = रिक्त;
	ध्रुव BIGNUM *sig_r, *sig_s;
	पूर्णाङ्क ret = -1;
	BIO *bio = रिक्त;
	EVP_PKEY *pk = रिक्त;
	EC_कुञ्चिका *ec = रिक्त;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_दीर्घता];
	uint8_t	sighash[SHA256_DIGEST_दीर्घता];
	uint8_t countbuf[4];

	/* Decode EC_KEY from key handle */
	यदि ((bio = BIO_new(BIO_s_mem())) == रिक्त ||
	    BIO_write(bio, कुञ्चिका_handle, कुञ्चिका_handle_len) != (पूर्णाङ्क)कुञ्चिका_handle_len) {
		skdebug(__func__, "BIO setup failed");
		गच्छ बहिर्गमनम्;
	}
	यदि ((pk = PEM_read_bio_वैयक्तिकम्_कुञ्चिका(bio, रिक्त, रिक्त, "")) == रिक्त) {
		skdebug(__func__, "PEM_read_bio_PrivateKey failed");
		गच्छ बहिर्गमनम्;
	}
	यदि (EVP_PKEY_आधारः_id(pk) != EVP_PKEY_EC) {
		skdebug(__func__, "Not an EC key: %d", EVP_PKEY_आधारः_id(pk));
		गच्छ बहिर्गमनम्;
	}
	यदि ((ec = EVP_PKEY_get1_EC_कुञ्चिका(pk)) == रिक्त) {
		skdebug(__func__, "EVP_PKEY_get1_EC_KEY failed");
		गच्छ बहिर्गमनम्;
	}
	/* Expect message to be pre-hashed */
	यदि (सन्देशः_len_2 != SHA256_DIGEST_दीर्घता) {
		skdebug(__func__, "bad message len %zu", सन्देशः_len_2);
		गच्छ बहिर्गमनम्;
	}
	/* Prepare data to be signed */
	dump("message", सन्देशः_2, सन्देशः_len_2);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ध्रुव u_char *)application, वाक्यदैर्घ्यम्(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, परिमाण(apphash));
	countbuf[0] = (गणक >> 24) & 0xff;
	countbuf[1] = (गणक >> 16) & 0xff;
	countbuf[2] = (गणक >> 8) & 0xff;
	countbuf[3] = गणक & 0xff;
	dump("countbuf", countbuf, परिमाण(countbuf));
	dump("flags", &flags, परिमाण(flags));
	SHA256Init(&ctx);
	SHA256Update(&ctx, apphash, परिमाण(apphash));
	SHA256Update(&ctx, &flags, परिमाण(flags));
	SHA256Update(&ctx, countbuf, परिमाण(countbuf));
	SHA256Update(&ctx, सन्देशः_2, सन्देशः_len_2);
	SHA256Final(sighash, &ctx);
	dump("sighash", sighash, परिमाण(sighash));
	/* create and encode signature */
	यदि ((sig = ECDSA_do_sign(sighash, परिमाण(sighash), ec)) == रिक्त) {
		skdebug(__func__, "ECDSA_do_sign failed");
		गच्छ बहिर्गमनम्;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_अङ्कः_अष्टकानि(sig_r);
	response->sig_s_len = BN_अङ्कः_अष्टकानि(sig_s);
	यदि ((response->sig_r = शून्यस्मृतिं_देहि(1, response->sig_r_len)) == रिक्त ||
	    (response->sig_s = शून्यस्मृतिं_देहि(1, response->sig_s_len)) == रिक्त) {
		skdebug(__func__, "calloc signature failed");
		गच्छ बहिर्गमनम्;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 बहिर्गमनम्:
	explicit_bzero(&ctx, परिमाण(ctx));
	explicit_bzero(&apphash, परिमाण(apphash));
	explicit_bzero(&sighash, परिमाण(sighash));
	ECDSA_SIG_free(sig);
	यदि (ret != 0) {
		मुक्त(response->sig_r);
		मुक्त(response->sig_s);
		response->sig_r = रिक्त;
		response->sig_s = रिक्त;
	}
	BIO_free(bio);
	EC_कुञ्चिका_free(ec);
	EVP_PKEY_free(pk);
	प्रत्यागम ret;
#अन्यथा
	प्रत्यागम -1;
#यदि_अन्तः
}

स्थिर पूर्णाङ्क
sig_ed25519(ध्रुव uint8_t *सन्देशः_2, आकार_t सन्देशः_len_2,
    ध्रुव वर्ण *application, uint32_t गणक, uint8_t flags,
    ध्रुव uint8_t *कुञ्चिका_handle, आकार_t कुञ्चिका_handle_len,
    संरचना sk_sign_response *response)
{
	आकार_t o;
	पूर्णाङ्क ret = -1;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_दीर्घता];
	uint8_t signbuf[परिमाण(apphash) + परिमाण(flags) +
	    परिमाण(गणक) + SHA256_DIGEST_दीर्घता];
	uint8_t sig[crypto_sign_ed25519_अष्टकानि];
	अचिह्नित दीर्घ दीर्घ siglen = 0;

	यदि (कुञ्चिका_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		skdebug(__func__, "bad key handle length %zu", कुञ्चिका_handle_len);
		गच्छ बहिर्गमनम्;
	}
	/* Expect message to be pre-hashed */
	यदि (सन्देशः_len_2 != SHA256_DIGEST_दीर्घता) {
		skdebug(__func__, "bad message len %zu", सन्देशः_len_2);
		गच्छ बहिर्गमनम्;
	}
	/* Prepare data to be signed */
	dump("message", सन्देशः_2, सन्देशः_len_2);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ध्रुव u_char *)application, वाक्यदैर्घ्यम्(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, परिमाण(apphash));

	स्मृतिं_प्रतिलिख(signbuf, apphash, परिमाण(apphash));
	o = परिमाण(apphash);
	signbuf[o++] = flags;
	signbuf[o++] = (गणक >> 24) & 0xff;
	signbuf[o++] = (गणक >> 16) & 0xff;
	signbuf[o++] = (गणक >> 8) & 0xff;
	signbuf[o++] = गणक & 0xff;
	स्मृतिं_प्रतिलिख(signbuf + o, सन्देशः_2, सन्देशः_len_2);
	o += सन्देशः_len_2;
	यदि (o != परिमाण(signbuf)) {
		skdebug(__func__, "bad sign buf len %zu, expected %zu",
		    o, परिमाण(signbuf));
		गच्छ बहिर्गमनम्;
	}
	dump("signbuf", signbuf, परिमाण(signbuf));
	/* create and encode signature */
	यदि (crypto_sign_ed25519_detached(sig, &siglen, signbuf, परिमाण(signbuf),
	    कुञ्चिका_handle) != 0) {
		skdebug(__func__, "crypto_sign_ed25519_detached failed");
		गच्छ बहिर्गमनम्;
	}
	यदि (siglen != परिमाण(sig)) {
		skdebug(__func__, "bad signature length %llu", siglen);
		गच्छ बहिर्गमनम्;
	}
	response->sig_r_len = परिमाण(sig);
	यदि ((response->sig_r = शून्यस्मृतिं_देहि(1, response->sig_r_len)) == रिक्त) {
		skdebug(__func__, "calloc signature failed");
		गच्छ बहिर्गमनम्;
	}
	स्मृतिं_प्रतिलिख(response->sig_r, sig, response->sig_r_len);
	dump("sig_r", response->sig_r, response->sig_r_len);
	ret = 0;
 बहिर्गमनम्:
	explicit_bzero(&ctx, परिमाण(ctx));
	explicit_bzero(&apphash, परिमाण(apphash));
	explicit_bzero(&signbuf, परिमाण(signbuf));
	explicit_bzero(&sig, परिमाण(sig));
	यदि (ret != 0) {
		मुक्त(response->sig_r);
		response->sig_r = रिक्त;
	}
	प्रत्यागम ret;
}

पूर्णाङ्क
sk_sign(uint32_t alg, ध्रुव uint8_t *दत्त, आकार_t datalen,
    ध्रुव वर्ण *application, ध्रुव uint8_t *कुञ्चिका_handle, आकार_t कुञ्चिका_handle_len,
    uint8_t flags, ध्रुव वर्ण *pin, संरचना sk_option **options,
    संरचना sk_sign_response **sign_response)
{
	संरचना sk_sign_response *response = रिक्त;
	पूर्णाङ्क ret = SSH_SK_ERR_GENERAL;
	SHA2_CTX ctx;
	uint8_t सन्देशः_2[32];

	यदि (sign_response == रिक्त) {
		skdebug(__func__, "sign_response == NULL");
		गच्छ बहिर्गमनम्;
	}
	*sign_response = रिक्त;
	यदि (check_options(options) != 0)
		गच्छ बहिर्गमनम्; /* error already logged */
	यदि ((response = शून्यस्मृतिं_देहि(1, परिमाण(*response))) == रिक्त) {
		skdebug(__func__, "calloc response failed");
		गच्छ बहिर्गमनम्;
	}
	SHA256Init(&ctx);
	SHA256Update(&ctx, दत्त, datalen);
	SHA256Final(सन्देशः_2, &ctx);
	response->flags = flags;
	response->गणक = 0x12345678;
	विकल्प(alg) {
	पक्ष SSH_SK_ECDSA:
		यदि (sig_ecdsa(सन्देशः_2, परिमाण(सन्देशः_2), application,
		    response->गणक, flags, कुञ्चिका_handle, कुञ्चिका_handle_len,
		    response) != 0)
			गच्छ बहिर्गमनम्;
		भङ्ग;
	पक्ष SSH_SK_ED25519:
		यदि (sig_ed25519(सन्देशः_2, परिमाण(सन्देशः_2), application,
		    response->गणक, flags, कुञ्चिका_handle, कुञ्चिका_handle_len,
		    response) != 0)
			गच्छ बहिर्गमनम्;
		भङ्ग;
	स्वभाव:
		skdebug(__func__, "unsupported key type %d", alg);
		गच्छ बहिर्गमनम्;
	}
	*sign_response = response;
	response = रिक्त;
	ret = 0;
 बहिर्गमनम्:
	explicit_bzero(सन्देशः_2, परिमाण(सन्देशः_2));
	यदि (response != रिक्त) {
		मुक्त(response->sig_r);
		मुक्त(response->sig_s);
		मुक्त(response);
	}
	प्रत्यागम ret;
}

पूर्णाङ्क
sk_आरोपय_resident_कुञ्चिकाः(ध्रुव वर्ण *pin, संरचना sk_option **options,
    संरचना sk_resident_कुञ्चिका ***rks, आकार_t *nrks)
{
	प्रत्यागम SSH_SK_ERR_UNSUPPORTED;
}
