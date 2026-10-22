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

#समावेश "includes.h"

#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <stdio.h>
#समावेश <stddef.h>
#समावेश <stdarg.h>

#समावेश "crypto_api.h"
#समावेश "sk-api.h"

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/opensslv.h>
#समावेश <openssl/sha.h>
#समावेश <openssl/crypto.h>
#समावेश <openssl/evp.h>
#समावेश <openssl/bn.h>
#समावेश <openssl/ec.h>
#समावेश <openssl/ecdsa.h>
#समावेश <openssl/pem.h>

/* Use OpenSSL SHA256 instead of libc */
#घोषणा SHA256Init(x)		SHA256_Init(x)
#घोषणा SHA256Update(x, y, z)	SHA256_Update(x, y, z)
#घोषणा SHA256Final(x, y)	SHA256_Final(x, y)
#घोषणा SHA2_CTX		SHA256_CTX

#या_अगर defined(HAVE_SHA2_H)
#समावेश <sha2.h>
#पूर्ण_अगर /* WITH_OPENSSL */

/* #define SK_DEBUG 1 */

#अगर SSH_SK_VERSION_MAJOR != 0x000a0000
# error SK API has changed, sk-dummy.c needs an update
#पूर्ण_अगर

#अगर_घोषित SK_DUMMY_INTEGRATE
# define sk_api_version		ssh_sk_api_version
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_load_resident_कुंजियाँ	ssh_sk_load_resident_कुंजियाँ
#पूर्ण_अगर /* !SK_STANDALONE */

अटल व्योम skdebug(स्थिर अक्षर *func, स्थिर अक्षर *fmt, ...)
    __attribute__((__format__ (म_लिखो, 2, 3)));

अटल व्योम
skdebug(स्थिर अक्षर *func, स्थिर अक्षर *fmt, ...)
{
#अगर defined(SK_DEBUG)
	बहु_सूची ap;

	बहु_शुरू(ap, fmt);
	ख_लिखो(मानक_त्रुटि, "sk-dummy %s: ", func);
	भख_लिखो(मानक_त्रुटि, fmt, ap);
	ख_अक्षर_दो('\n', मानक_त्रुटि);
	बहु_पूर्ण(ap);
#अन्यथा
	(व्योम)func; /* XXX */
	(व्योम)fmt; /* XXX */
#पूर्ण_अगर
}

uint32_t
sk_api_version(व्योम)
{
	वापस SSH_SK_VERSION_MAJOR;
}

अटल पूर्णांक
pack_कुंजी_ecdsa(काष्ठा sk_enroll_response *response)
{
#अगर_घोषित WITH_OPENSSL
	EC_कुंजी *कुंजी = शून्य;
	स्थिर EC_GROUP *g;
	स्थिर EC_POINT *q;
	पूर्णांक ret = -1;
	दीर्घ privlen;
	BIO *bio = शून्य;
	अक्षर *privptr;

	response->public_कुंजी = शून्य;
	response->public_कुंजी_len = 0;
	response->कुंजी_handle = शून्य;
	response->कुंजी_handle_len = 0;

	अगर ((कुंजी = EC_कुंजी_new_by_curve_name(NID_X9_62_prime256v1)) == शून्य) {
		skdebug(__func__, "EC_KEY_new_by_curve_name");
		जाओ out;
	}
	अगर (EC_कुंजी_generate_कुंजी(कुंजी) != 1) {
		skdebug(__func__, "EC_KEY_generate_key");
		जाओ out;
	}
	EC_कुंजी_set_asn1_flag(कुंजी, OPENSSL_EC_NAMED_CURVE);
	अगर ((bio = BIO_new(BIO_s_mem())) == शून्य ||
	    (g = EC_कुंजी_get0_group(कुंजी)) == शून्य ||
	    (q = EC_कुंजी_get0_public_कुंजी(कुंजी)) == शून्य) {
		skdebug(__func__, "couldn't get key parameters");
		जाओ out;
	}
	response->public_कुंजी_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, शून्य, 0, शून्य);
	अगर (response->public_कुंजी_len == 0 || response->public_कुंजी_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_कुंजी_len);
		जाओ out;
	}
	अगर ((response->public_कुंजी = दो_स्मृति(response->public_कुंजी_len)) == शून्य) {
		skdebug(__func__, "malloc pubkey failed");
		जाओ out;
	}
	अगर (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_कुंजी, response->public_कुंजी_len, शून्य) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		जाओ out;
	}
	/* Key handle contains PEM encoded private key */
	अगर (!PEM_write_bio_ECPrivate_कुंजी(bio, कुंजी, शून्य, शून्य, 0, शून्य, शून्य)) {
		skdebug(__func__, "PEM_write_bio_ECPrivateKey failed");
		जाओ out;
	}
	अगर ((privlen = BIO_get_mem_तथ्य(bio, &privptr)) <= 0) {
		skdebug(__func__, "BIO_get_mem_data failed");
		जाओ out;
	}
	अगर ((response->कुंजी_handle = दो_स्मृति(privlen)) == शून्य) {
		skdebug(__func__, "malloc key_handle failed");
		जाओ out;
	}
	response->कुंजी_handle_len = (माप_प्रकार)privlen;
	स_नकल(response->कुंजी_handle, privptr, response->कुंजी_handle_len);
	/* success */
	ret = 0;
 out:
	अगर (ret != 0) {
		अगर (response->public_कुंजी != शून्य) {
			स_रखो(response->public_कुंजी, 0,
			    response->public_कुंजी_len);
			मुक्त(response->public_कुंजी);
			response->public_कुंजी = शून्य;
		}
		अगर (response->कुंजी_handle != शून्य) {
			स_रखो(response->कुंजी_handle, 0,
			    response->कुंजी_handle_len);
			मुक्त(response->कुंजी_handle);
			response->कुंजी_handle = शून्य;
		}
	}
	BIO_free(bio);
	EC_कुंजी_free(कुंजी);
	वापस ret;
#अन्यथा
	वापस -1;
#पूर्ण_अगर
}

अटल पूर्णांक
pack_कुंजी_ed25519(काष्ठा sk_enroll_response *response)
{
	पूर्णांक ret = -1;
	u_char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	u_char sk[crypto_sign_ed25519_SECRETKEYBYTES];

	response->public_कुंजी = शून्य;
	response->public_कुंजी_len = 0;
	response->कुंजी_handle = शून्य;
	response->कुंजी_handle_len = 0;

	स_रखो(pk, 0, माप(pk));
	स_रखो(sk, 0, माप(sk));
	crypto_sign_ed25519_keypair(pk, sk);

	response->public_कुंजी_len = माप(pk);
	अगर ((response->public_कुंजी = दो_स्मृति(response->public_कुंजी_len)) == शून्य) {
		skdebug(__func__, "malloc pubkey failed");
		जाओ out;
	}
	स_नकल(response->public_कुंजी, pk, माप(pk));
	/* Key handle contains sk */
	response->कुंजी_handle_len = माप(sk);
	अगर ((response->कुंजी_handle = दो_स्मृति(response->कुंजी_handle_len)) == शून्य) {
		skdebug(__func__, "malloc key_handle failed");
		जाओ out;
	}
	स_नकल(response->कुंजी_handle, sk, माप(sk));
	/* success */
	ret = 0;
 out:
	अगर (ret != 0)
		मुक्त(response->public_कुंजी);
	वापस ret;
}

अटल पूर्णांक
check_options(काष्ठा sk_option **options)
{
	माप_प्रकार i;

	अगर (options == शून्य)
		वापस 0;
	क्रम (i = 0; options[i] != शून्य; i++) {
		skdebug(__func__, "requested unsupported option %s",
		    options[i]->name);
		अगर (options[i]->required) {
			skdebug(__func__, "unknown required option");
			वापस -1;
		}
	}
	वापस 0;
}

पूर्णांक
sk_enroll(uint32_t alg, स्थिर uint8_t *challenge, माप_प्रकार challenge_len,
    स्थिर अक्षर *application, uint8_t flags, स्थिर अक्षर *pin,
    काष्ठा sk_option **options, काष्ठा sk_enroll_response **enroll_response)
{
	काष्ठा sk_enroll_response *response = शून्य;
	पूर्णांक ret = SSH_SK_ERR_GENERAL;

	(व्योम)flags; /* XXX; unused */

	अगर (enroll_response == शून्य) {
		skdebug(__func__, "enroll_response == NULL");
		जाओ out;
	}
	*enroll_response = शून्य;
	अगर (check_options(options) != 0)
		जाओ out; /* error already logged */
	अगर ((response = सुस्मृति(1, माप(*response))) == शून्य) {
		skdebug(__func__, "calloc response failed");
		जाओ out;
	}
	response->flags = flags;
	चयन(alg) {
	हाल SSH_SK_ECDSA:
		अगर (pack_कुंजी_ecdsa(response) != 0)
			जाओ out;
		अवरोध;
	हाल SSH_SK_ED25519:
		अगर (pack_कुंजी_ed25519(response) != 0)
			जाओ out;
		अवरोध;
	शेष:
		skdebug(__func__, "unsupported key type %d", alg);
		जाओ out;
	}
	/* Have to return something here */
	अगर ((response->signature = सुस्मृति(1, 1)) == शून्य) {
		skdebug(__func__, "calloc signature failed");
		जाओ out;
	}
	response->signature_len = 0;

	*enroll_response = response;
	response = शून्य;
	ret = 0;
 out:
	अगर (response != शून्य) {
		मुक्त(response->public_कुंजी);
		मुक्त(response->कुंजी_handle);
		मुक्त(response->signature);
		मुक्त(response->attestation_cert);
		मुक्त(response);
	}
	वापस ret;
}

अटल व्योम
dump(स्थिर अक्षर *preamble, स्थिर व्योम *sv, माप_प्रकार l)
{
#अगर_घोषित SK_DEBUG
	स्थिर u_char *s = (स्थिर u_char *)sv;
	माप_प्रकार i;

	ख_लिखो(मानक_त्रुटि, "%s (len %zu):\n", preamble, l);
	क्रम (i = 0; i < l; i++) {
		अगर (i % 16 == 0)
			ख_लिखो(मानक_त्रुटि, "%04zu: ", i);
		ख_लिखो(मानक_त्रुटि, "%02x", s[i]);
		अगर (i % 16 == 15 || i == l - 1)
			ख_लिखो(मानक_त्रुटि, "\n");
	}
#पूर्ण_अगर
}

अटल पूर्णांक
sig_ecdsa(स्थिर uint8_t *message, माप_प्रकार message_len,
    स्थिर अक्षर *application, uint32_t गणक, uint8_t flags,
    स्थिर uint8_t *कुंजी_handle, माप_प्रकार कुंजी_handle_len,
    काष्ठा sk_sign_response *response)
{
#अगर_घोषित WITH_OPENSSL
	ECDSA_SIG *sig = शून्य;
	स्थिर BIGNUM *sig_r, *sig_s;
	पूर्णांक ret = -1;
	BIO *bio = शून्य;
	EVP_PKEY *pk = शून्य;
	EC_कुंजी *ec = शून्य;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_लंबाई];
	uint8_t	sighash[SHA256_DIGEST_लंबाई];
	uint8_t countbuf[4];

	/* Decode EC_KEY from key handle */
	अगर ((bio = BIO_new(BIO_s_mem())) == शून्य ||
	    BIO_write(bio, कुंजी_handle, कुंजी_handle_len) != (पूर्णांक)कुंजी_handle_len) {
		skdebug(__func__, "BIO setup failed");
		जाओ out;
	}
	अगर ((pk = PEM_read_bio_Private_कुंजी(bio, शून्य, शून्य, "")) == शून्य) {
		skdebug(__func__, "PEM_read_bio_PrivateKey failed");
		जाओ out;
	}
	अगर (EVP_PKEY_base_id(pk) != EVP_PKEY_EC) {
		skdebug(__func__, "Not an EC key: %d", EVP_PKEY_base_id(pk));
		जाओ out;
	}
	अगर ((ec = EVP_PKEY_get1_EC_कुंजी(pk)) == शून्य) {
		skdebug(__func__, "EVP_PKEY_get1_EC_KEY failed");
		जाओ out;
	}
	/* Expect message to be pre-hashed */
	अगर (message_len != SHA256_DIGEST_लंबाई) {
		skdebug(__func__, "bad message len %zu", message_len);
		जाओ out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (स्थिर u_char *)application, म_माप(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, माप(apphash));
	countbuf[0] = (गणक >> 24) & 0xff;
	countbuf[1] = (गणक >> 16) & 0xff;
	countbuf[2] = (गणक >> 8) & 0xff;
	countbuf[3] = गणक & 0xff;
	dump("countbuf", countbuf, माप(countbuf));
	dump("flags", &flags, माप(flags));
	SHA256Init(&ctx);
	SHA256Update(&ctx, apphash, माप(apphash));
	SHA256Update(&ctx, &flags, माप(flags));
	SHA256Update(&ctx, countbuf, माप(countbuf));
	SHA256Update(&ctx, message, message_len);
	SHA256Final(sighash, &ctx);
	dump("sighash", sighash, माप(sighash));
	/* create and encode signature */
	अगर ((sig = ECDSA_do_sign(sighash, माप(sighash), ec)) == शून्य) {
		skdebug(__func__, "ECDSA_do_sign failed");
		जाओ out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_अंक_bytes(sig_r);
	response->sig_s_len = BN_अंक_bytes(sig_s);
	अगर ((response->sig_r = सुस्मृति(1, response->sig_r_len)) == शून्य ||
	    (response->sig_s = सुस्मृति(1, response->sig_s_len)) == शून्य) {
		skdebug(__func__, "calloc signature failed");
		जाओ out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	explicit_bzero(&ctx, माप(ctx));
	explicit_bzero(&apphash, माप(apphash));
	explicit_bzero(&sighash, माप(sighash));
	ECDSA_SIG_free(sig);
	अगर (ret != 0) {
		मुक्त(response->sig_r);
		मुक्त(response->sig_s);
		response->sig_r = शून्य;
		response->sig_s = शून्य;
	}
	BIO_free(bio);
	EC_कुंजी_free(ec);
	EVP_PKEY_free(pk);
	वापस ret;
#अन्यथा
	वापस -1;
#पूर्ण_अगर
}

अटल पूर्णांक
sig_ed25519(स्थिर uint8_t *message, माप_प्रकार message_len,
    स्थिर अक्षर *application, uint32_t गणक, uint8_t flags,
    स्थिर uint8_t *कुंजी_handle, माप_प्रकार कुंजी_handle_len,
    काष्ठा sk_sign_response *response)
{
	माप_प्रकार o;
	पूर्णांक ret = -1;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_लंबाई];
	uint8_t signbuf[माप(apphash) + माप(flags) +
	    माप(गणक) + SHA256_DIGEST_लंबाई];
	uint8_t sig[crypto_sign_ed25519_BYTES];
	अचिन्हित दीर्घ दीर्घ siglen = 0;

	अगर (कुंजी_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		skdebug(__func__, "bad key handle length %zu", कुंजी_handle_len);
		जाओ out;
	}
	/* Expect message to be pre-hashed */
	अगर (message_len != SHA256_DIGEST_लंबाई) {
		skdebug(__func__, "bad message len %zu", message_len);
		जाओ out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (स्थिर u_char *)application, म_माप(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, माप(apphash));

	स_नकल(signbuf, apphash, माप(apphash));
	o = माप(apphash);
	signbuf[o++] = flags;
	signbuf[o++] = (गणक >> 24) & 0xff;
	signbuf[o++] = (गणक >> 16) & 0xff;
	signbuf[o++] = (गणक >> 8) & 0xff;
	signbuf[o++] = गणक & 0xff;
	स_नकल(signbuf + o, message, message_len);
	o += message_len;
	अगर (o != माप(signbuf)) {
		skdebug(__func__, "bad sign buf len %zu, expected %zu",
		    o, माप(signbuf));
		जाओ out;
	}
	dump("signbuf", signbuf, माप(signbuf));
	/* create and encode signature */
	अगर (crypto_sign_ed25519_detached(sig, &siglen, signbuf, माप(signbuf),
	    कुंजी_handle) != 0) {
		skdebug(__func__, "crypto_sign_ed25519_detached failed");
		जाओ out;
	}
	अगर (siglen != माप(sig)) {
		skdebug(__func__, "bad signature length %llu", siglen);
		जाओ out;
	}
	response->sig_r_len = माप(sig);
	अगर ((response->sig_r = सुस्मृति(1, response->sig_r_len)) == शून्य) {
		skdebug(__func__, "calloc signature failed");
		जाओ out;
	}
	स_नकल(response->sig_r, sig, response->sig_r_len);
	dump("sig_r", response->sig_r, response->sig_r_len);
	ret = 0;
 out:
	explicit_bzero(&ctx, माप(ctx));
	explicit_bzero(&apphash, माप(apphash));
	explicit_bzero(&signbuf, माप(signbuf));
	explicit_bzero(&sig, माप(sig));
	अगर (ret != 0) {
		मुक्त(response->sig_r);
		response->sig_r = शून्य;
	}
	वापस ret;
}

पूर्णांक
sk_sign(uint32_t alg, स्थिर uint8_t *तथ्य, माप_प्रकार datalen,
    स्थिर अक्षर *application, स्थिर uint8_t *कुंजी_handle, माप_प्रकार कुंजी_handle_len,
    uint8_t flags, स्थिर अक्षर *pin, काष्ठा sk_option **options,
    काष्ठा sk_sign_response **sign_response)
{
	काष्ठा sk_sign_response *response = शून्य;
	पूर्णांक ret = SSH_SK_ERR_GENERAL;
	SHA2_CTX ctx;
	uint8_t message[32];

	अगर (sign_response == शून्य) {
		skdebug(__func__, "sign_response == NULL");
		जाओ out;
	}
	*sign_response = शून्य;
	अगर (check_options(options) != 0)
		जाओ out; /* error already logged */
	अगर ((response = सुस्मृति(1, माप(*response))) == शून्य) {
		skdebug(__func__, "calloc response failed");
		जाओ out;
	}
	SHA256Init(&ctx);
	SHA256Update(&ctx, तथ्य, datalen);
	SHA256Final(message, &ctx);
	response->flags = flags;
	response->गणक = 0x12345678;
	चयन(alg) {
	हाल SSH_SK_ECDSA:
		अगर (sig_ecdsa(message, माप(message), application,
		    response->गणक, flags, कुंजी_handle, कुंजी_handle_len,
		    response) != 0)
			जाओ out;
		अवरोध;
	हाल SSH_SK_ED25519:
		अगर (sig_ed25519(message, माप(message), application,
		    response->गणक, flags, कुंजी_handle, कुंजी_handle_len,
		    response) != 0)
			जाओ out;
		अवरोध;
	शेष:
		skdebug(__func__, "unsupported key type %d", alg);
		जाओ out;
	}
	*sign_response = response;
	response = शून्य;
	ret = 0;
 out:
	explicit_bzero(message, माप(message));
	अगर (response != शून्य) {
		मुक्त(response->sig_r);
		मुक्त(response->sig_s);
		मुक्त(response);
	}
	वापस ret;
}

पूर्णांक
sk_load_resident_कुंजियाँ(स्थिर अक्षर *pin, काष्ठा sk_option **options,
    काष्ठा sk_resident_कुंजी ***rks, माप_प्रकार *nrks)
{
	वापस SSH_SK_ERR_UNSUPPORTED;
}
