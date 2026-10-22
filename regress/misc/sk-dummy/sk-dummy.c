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

#किंवाजर defined(HAVE_SHA2_H)
#अन्तर्भाव <sha2.h>
#endif /* WITH_OPENSSL */

/* #define SK_DEBUG 1 */

#जर SSH_SK_VERSION_MAJOR != 0x000a0000
# error SK API has changed, sk-dummy.c needs an update
#endif

#ifdef SK_DUMMY_INTEGRATE
# define sk_api_version		ssh_sk_api_version
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_load_resident_किल्ल्या	ssh_sk_load_resident_किल्ल्या
#endif /* !SK_STANDALONE */

स्थिर शून्य skdebug(स्थिरांक अक्षर *func, स्थिरांक अक्षर *fmt, ...)
    __attribute__((__format__ (म_लिखो, 2, 3)));

स्थिर शून्य
skdebug(स्थिरांक अक्षर *func, स्थिरांक अक्षर *fmt, ...)
{
#जर defined(SK_DEBUG)
	बहु_सूची ap;

	बहु_शुरू(ap, fmt);
	ख_लिखो(मानक_त्रुटि, "sk-dummy %s: ", func);
	भख_लिखो(मानक_त्रुटि, fmt, ap);
	ख_अक्षर_दो('\n', मानक_त्रुटि);
	बहु_पूर्ण(ap);
#अन्यथा
	(शून्य)func; /* XXX */
	(शून्य)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(शून्य)
{
	परत SSH_SK_VERSION_MAJOR;
}

स्थिर पूर्णांक
pack_किल्ली_ecdsa(संरचना sk_enroll_response *response)
{
#ifdef WITH_OPENSSL
	EC_किल्ली *किल्ली = रिक्त;
	स्थिरांक EC_GROUP *g;
	स्थिरांक EC_POINT *q;
	पूर्णांक ret = -1;
	दीर्घ privlen;
	BIO *bio = रिक्त;
	अक्षर *privptr;

	response->public_किल्ली = रिक्त;
	response->public_किल्ली_len = 0;
	response->किल्ली_handle = रिक्त;
	response->किल्ली_handle_len = 0;

	जर ((किल्ली = EC_किल्ली_new_by_curve_name(NID_X9_62_prime256v1)) == रिक्त) {
		skdebug(__func__, "EC_KEY_new_by_curve_name");
		जा out;
	}
	जर (EC_किल्ली_generate_किल्ली(किल्ली) != 1) {
		skdebug(__func__, "EC_KEY_generate_key");
		जा out;
	}
	EC_किल्ली_set_asn1_flag(किल्ली, OPENSSL_EC_NAMED_CURVE);
	जर ((bio = BIO_new(BIO_s_mem())) == रिक्त ||
	    (g = EC_किल्ली_get0_group(किल्ली)) == रिक्त ||
	    (q = EC_किल्ली_get0_public_किल्ली(किल्ली)) == रिक्त) {
		skdebug(__func__, "couldn't get key parameters");
		जा out;
	}
	response->public_किल्ली_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, रिक्त, 0, रिक्त);
	जर (response->public_किल्ली_len == 0 || response->public_किल्ली_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_किल्ली_len);
		जा out;
	}
	जर ((response->public_किल्ली = दो_स्मृति(response->public_किल्ली_len)) == रिक्त) {
		skdebug(__func__, "malloc pubkey failed");
		जा out;
	}
	जर (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_किल्ली, response->public_किल्ली_len, रिक्त) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		जा out;
	}
	/* Key handle contains PEM encoded private key */
	जर (!PEM_write_bio_ECPrivate_किल्ली(bio, किल्ली, रिक्त, रिक्त, 0, रिक्त, रिक्त)) {
		skdebug(__func__, "PEM_write_bio_ECPrivateKey failed");
		जा out;
	}
	जर ((privlen = BIO_get_mem_data(bio, &privptr)) <= 0) {
		skdebug(__func__, "BIO_get_mem_data failed");
		जा out;
	}
	जर ((response->किल्ली_handle = दो_स्मृति(privlen)) == रिक्त) {
		skdebug(__func__, "malloc key_handle failed");
		जा out;
	}
	response->किल्ली_handle_len = (माप_प्रकार)privlen;
	स_नकल(response->किल्ली_handle, privptr, response->किल्ली_handle_len);
	/* success */
	ret = 0;
 out:
	जर (ret != 0) {
		जर (response->public_किल्ली != रिक्त) {
			स_रखो(response->public_किल्ली, 0,
			    response->public_किल्ली_len);
			मुक्त(response->public_किल्ली);
			response->public_किल्ली = रिक्त;
		}
		जर (response->किल्ली_handle != रिक्त) {
			स_रखो(response->किल्ली_handle, 0,
			    response->किल्ली_handle_len);
			मुक्त(response->किल्ली_handle);
			response->किल्ली_handle = रिक्त;
		}
	}
	BIO_free(bio);
	EC_किल्ली_free(किल्ली);
	परत ret;
#अन्यथा
	परत -1;
#endif
}

स्थिर पूर्णांक
pack_किल्ली_ed25519(संरचना sk_enroll_response *response)
{
	पूर्णांक ret = -1;
	u_char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	u_char sk[crypto_sign_ed25519_SECRETKEYBYTES];

	response->public_किल्ली = रिक्त;
	response->public_किल्ली_len = 0;
	response->किल्ली_handle = रिक्त;
	response->किल्ली_handle_len = 0;

	स_रखो(pk, 0, आकार(pk));
	स_रखो(sk, 0, आकार(sk));
	crypto_sign_ed25519_keypair(pk, sk);

	response->public_किल्ली_len = आकार(pk);
	जर ((response->public_किल्ली = दो_स्मृति(response->public_किल्ली_len)) == रिक्त) {
		skdebug(__func__, "malloc pubkey failed");
		जा out;
	}
	स_नकल(response->public_किल्ली, pk, आकार(pk));
	/* Key handle contains sk */
	response->किल्ली_handle_len = आकार(sk);
	जर ((response->किल्ली_handle = दो_स्मृति(response->किल्ली_handle_len)) == रिक्त) {
		skdebug(__func__, "malloc key_handle failed");
		जा out;
	}
	स_नकल(response->किल्ली_handle, sk, आकार(sk));
	/* success */
	ret = 0;
 out:
	जर (ret != 0)
		मुक्त(response->public_किल्ली);
	परत ret;
}

स्थिर पूर्णांक
check_options(संरचना sk_option **options)
{
	माप_प्रकार i;

	जर (options == रिक्त)
		परत 0;
	साठी (i = 0; options[i] != रिक्त; i++) {
		skdebug(__func__, "requested unsupported option %s",
		    options[i]->name);
		जर (options[i]->required) {
			skdebug(__func__, "unknown required option");
			परत -1;
		}
	}
	परत 0;
}

पूर्णांक
sk_enroll(uint32_t alg, स्थिरांक uint8_t *challenge, माप_प्रकार challenge_len,
    स्थिरांक अक्षर *application, uint8_t flags, स्थिरांक अक्षर *pin,
    संरचना sk_option **options, संरचना sk_enroll_response **enroll_response)
{
	संरचना sk_enroll_response *response = रिक्त;
	पूर्णांक ret = SSH_SK_ERR_GENERAL;

	(शून्य)flags; /* XXX; unused */

	जर (enroll_response == रिक्त) {
		skdebug(__func__, "enroll_response == NULL");
		जा out;
	}
	*enroll_response = रिक्त;
	जर (check_options(options) != 0)
		जा out; /* error already logged */
	जर ((response = सुस्मृति(1, आकार(*response))) == रिक्त) {
		skdebug(__func__, "calloc response failed");
		जा out;
	}
	response->flags = flags;
	निवड(alg) {
	स्थिती SSH_SK_ECDSA:
		जर (pack_किल्ली_ecdsa(response) != 0)
			जा out;
		थांबा;
	स्थिती SSH_SK_ED25519:
		जर (pack_किल्ली_ed25519(response) != 0)
			जा out;
		थांबा;
	पूर्वनिर्धारित:
		skdebug(__func__, "unsupported key type %d", alg);
		जा out;
	}
	/* Have to return something here */
	जर ((response->signature = सुस्मृति(1, 1)) == रिक्त) {
		skdebug(__func__, "calloc signature failed");
		जा out;
	}
	response->signature_len = 0;

	*enroll_response = response;
	response = रिक्त;
	ret = 0;
 out:
	जर (response != रिक्त) {
		मुक्त(response->public_किल्ली);
		मुक्त(response->किल्ली_handle);
		मुक्त(response->signature);
		मुक्त(response->attestation_cert);
		मुक्त(response);
	}
	परत ret;
}

स्थिर शून्य
dump(स्थिरांक अक्षर *preamble, स्थिरांक शून्य *sv, माप_प्रकार l)
{
#ifdef SK_DEBUG
	स्थिरांक u_char *s = (स्थिरांक u_char *)sv;
	माप_प्रकार i;

	ख_लिखो(मानक_त्रुटि, "%s (len %zu):\n", preamble, l);
	साठी (i = 0; i < l; i++) {
		जर (i % 16 == 0)
			ख_लिखो(मानक_त्रुटि, "%04zu: ", i);
		ख_लिखो(मानक_त्रुटि, "%02x", s[i]);
		जर (i % 16 == 15 || i == l - 1)
			ख_लिखो(मानक_त्रुटि, "\n");
	}
#endif
}

स्थिर पूर्णांक
sig_ecdsa(स्थिरांक uint8_t *message, माप_प्रकार message_len,
    स्थिरांक अक्षर *application, uint32_t counter, uint8_t flags,
    स्थिरांक uint8_t *किल्ली_handle, माप_प्रकार किल्ली_handle_len,
    संरचना sk_sign_response *response)
{
#ifdef WITH_OPENSSL
	ECDSA_SIG *sig = रिक्त;
	स्थिरांक BIGNUM *sig_r, *sig_s;
	पूर्णांक ret = -1;
	BIO *bio = रिक्त;
	EVP_PKEY *pk = रिक्त;
	EC_किल्ली *ec = रिक्त;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_LENGTH];
	uint8_t	sighash[SHA256_DIGEST_LENGTH];
	uint8_t countbuf[4];

	/* Decode EC_KEY from key handle */
	जर ((bio = BIO_new(BIO_s_mem())) == रिक्त ||
	    BIO_write(bio, किल्ली_handle, किल्ली_handle_len) != (पूर्णांक)किल्ली_handle_len) {
		skdebug(__func__, "BIO setup failed");
		जा out;
	}
	जर ((pk = PEM_read_bio_Private_किल्ली(bio, रिक्त, रिक्त, "")) == रिक्त) {
		skdebug(__func__, "PEM_read_bio_PrivateKey failed");
		जा out;
	}
	जर (EVP_PKEY_base_id(pk) != EVP_PKEY_EC) {
		skdebug(__func__, "Not an EC key: %d", EVP_PKEY_base_id(pk));
		जा out;
	}
	जर ((ec = EVP_PKEY_get1_EC_किल्ली(pk)) == रिक्त) {
		skdebug(__func__, "EVP_PKEY_get1_EC_KEY failed");
		जा out;
	}
	/* Expect message to be pre-hashed */
	जर (message_len != SHA256_DIGEST_LENGTH) {
		skdebug(__func__, "bad message len %zu", message_len);
		जा out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (स्थिरांक u_char *)application, म_माप(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, आकार(apphash));
	countbuf[0] = (counter >> 24) & 0xff;
	countbuf[1] = (counter >> 16) & 0xff;
	countbuf[2] = (counter >> 8) & 0xff;
	countbuf[3] = counter & 0xff;
	dump("countbuf", countbuf, आकार(countbuf));
	dump("flags", &flags, आकार(flags));
	SHA256Init(&ctx);
	SHA256Update(&ctx, apphash, आकार(apphash));
	SHA256Update(&ctx, &flags, आकार(flags));
	SHA256Update(&ctx, countbuf, आकार(countbuf));
	SHA256Update(&ctx, message, message_len);
	SHA256Final(sighash, &ctx);
	dump("sighash", sighash, आकार(sighash));
	/* create and encode signature */
	जर ((sig = ECDSA_do_sign(sighash, आकार(sighash), ec)) == रिक्त) {
		skdebug(__func__, "ECDSA_do_sign failed");
		जा out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_अंक_bytes(sig_r);
	response->sig_s_len = BN_अंक_bytes(sig_s);
	जर ((response->sig_r = सुस्मृति(1, response->sig_r_len)) == रिक्त ||
	    (response->sig_s = सुस्मृति(1, response->sig_s_len)) == रिक्त) {
		skdebug(__func__, "calloc signature failed");
		जा out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	explicit_bzero(&ctx, आकार(ctx));
	explicit_bzero(&apphash, आकार(apphash));
	explicit_bzero(&sighash, आकार(sighash));
	ECDSA_SIG_free(sig);
	जर (ret != 0) {
		मुक्त(response->sig_r);
		मुक्त(response->sig_s);
		response->sig_r = रिक्त;
		response->sig_s = रिक्त;
	}
	BIO_free(bio);
	EC_किल्ली_free(ec);
	EVP_PKEY_free(pk);
	परत ret;
#अन्यथा
	परत -1;
#endif
}

स्थिर पूर्णांक
sig_ed25519(स्थिरांक uint8_t *message, माप_प्रकार message_len,
    स्थिरांक अक्षर *application, uint32_t counter, uint8_t flags,
    स्थिरांक uint8_t *किल्ली_handle, माप_प्रकार किल्ली_handle_len,
    संरचना sk_sign_response *response)
{
	माप_प्रकार o;
	पूर्णांक ret = -1;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_LENGTH];
	uint8_t signbuf[आकार(apphash) + आकार(flags) +
	    आकार(counter) + SHA256_DIGEST_LENGTH];
	uint8_t sig[crypto_sign_ed25519_BYTES];
	अचिन्हित दीर्घ दीर्घ siglen = 0;

	जर (किल्ली_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		skdebug(__func__, "bad key handle length %zu", किल्ली_handle_len);
		जा out;
	}
	/* Expect message to be pre-hashed */
	जर (message_len != SHA256_DIGEST_LENGTH) {
		skdebug(__func__, "bad message len %zu", message_len);
		जा out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (स्थिरांक u_char *)application, म_माप(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, आकार(apphash));

	स_नकल(signbuf, apphash, आकार(apphash));
	o = आकार(apphash);
	signbuf[o++] = flags;
	signbuf[o++] = (counter >> 24) & 0xff;
	signbuf[o++] = (counter >> 16) & 0xff;
	signbuf[o++] = (counter >> 8) & 0xff;
	signbuf[o++] = counter & 0xff;
	स_नकल(signbuf + o, message, message_len);
	o += message_len;
	जर (o != आकार(signbuf)) {
		skdebug(__func__, "bad sign buf len %zu, expected %zu",
		    o, आकार(signbuf));
		जा out;
	}
	dump("signbuf", signbuf, आकार(signbuf));
	/* create and encode signature */
	जर (crypto_sign_ed25519_detached(sig, &siglen, signbuf, आकार(signbuf),
	    किल्ली_handle) != 0) {
		skdebug(__func__, "crypto_sign_ed25519_detached failed");
		जा out;
	}
	जर (siglen != आकार(sig)) {
		skdebug(__func__, "bad signature length %llu", siglen);
		जा out;
	}
	response->sig_r_len = आकार(sig);
	जर ((response->sig_r = सुस्मृति(1, response->sig_r_len)) == रिक्त) {
		skdebug(__func__, "calloc signature failed");
		जा out;
	}
	स_नकल(response->sig_r, sig, response->sig_r_len);
	dump("sig_r", response->sig_r, response->sig_r_len);
	ret = 0;
 out:
	explicit_bzero(&ctx, आकार(ctx));
	explicit_bzero(&apphash, आकार(apphash));
	explicit_bzero(&signbuf, आकार(signbuf));
	explicit_bzero(&sig, आकार(sig));
	जर (ret != 0) {
		मुक्त(response->sig_r);
		response->sig_r = रिक्त;
	}
	परत ret;
}

पूर्णांक
sk_sign(uint32_t alg, स्थिरांक uint8_t *data, माप_प्रकार datalen,
    स्थिरांक अक्षर *application, स्थिरांक uint8_t *किल्ली_handle, माप_प्रकार किल्ली_handle_len,
    uint8_t flags, स्थिरांक अक्षर *pin, संरचना sk_option **options,
    संरचना sk_sign_response **sign_response)
{
	संरचना sk_sign_response *response = रिक्त;
	पूर्णांक ret = SSH_SK_ERR_GENERAL;
	SHA2_CTX ctx;
	uint8_t message[32];

	जर (sign_response == रिक्त) {
		skdebug(__func__, "sign_response == NULL");
		जा out;
	}
	*sign_response = रिक्त;
	जर (check_options(options) != 0)
		जा out; /* error already logged */
	जर ((response = सुस्मृति(1, आकार(*response))) == रिक्त) {
		skdebug(__func__, "calloc response failed");
		जा out;
	}
	SHA256Init(&ctx);
	SHA256Update(&ctx, data, datalen);
	SHA256Final(message, &ctx);
	response->flags = flags;
	response->counter = 0x12345678;
	निवड(alg) {
	स्थिती SSH_SK_ECDSA:
		जर (sig_ecdsa(message, आकार(message), application,
		    response->counter, flags, किल्ली_handle, किल्ली_handle_len,
		    response) != 0)
			जा out;
		थांबा;
	स्थिती SSH_SK_ED25519:
		जर (sig_ed25519(message, आकार(message), application,
		    response->counter, flags, किल्ली_handle, किल्ली_handle_len,
		    response) != 0)
			जा out;
		थांबा;
	पूर्वनिर्धारित:
		skdebug(__func__, "unsupported key type %d", alg);
		जा out;
	}
	*sign_response = response;
	response = रिक्त;
	ret = 0;
 out:
	explicit_bzero(message, आकार(message));
	जर (response != रिक्त) {
		मुक्त(response->sig_r);
		मुक्त(response->sig_s);
		मुक्त(response);
	}
	परत ret;
}

पूर्णांक
sk_load_resident_किल्ल्या(स्थिरांक अक्षर *pin, संरचना sk_option **options,
    संरचना sk_resident_किल्ली ***rks, माप_प्रकार *nrks)
{
	परत SSH_SK_ERR_UNSUPPORTED;
}
