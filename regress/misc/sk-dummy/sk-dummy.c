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

#شامل "includes.h"

#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <stdio.h>
#شامل <stddef.h>
#شامل <stdarg.h>

#شامل "crypto_api.h"
#شامل "sk-api.h"

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/opensslv.h>
#شامل <openssl/sha.h>
#شامل <openssl/crypto.h>
#شامل <openssl/evp.h>
#شامل <openssl/bn.h>
#شامل <openssl/ec.h>
#شامل <openssl/ecdsa.h>
#شامل <openssl/pem.h>

/* Use OpenSSL SHA256 instead of libc */
#تعریف_کرو SHA256Init(x)		SHA256_Init(x)
#تعریف_کرو SHA256Update(x, y, z)	SHA256_Update(x, y, z)
#تعریف_کرو SHA256Final(x, y)	SHA256_Final(x, y)
#تعریف_کرو SHA2_CTX		SHA256_CTX

#وگرنہ_اگر defined(HAVE_SHA2_H)
#شامل <sha2.h>
#اگر_ختم /* WITH_OPENSSL */

/* #define SK_DEBUG 1 */

#اگر SSH_SK_نسخہ_MAJOR != 0x000a0000
# error SK API has بدلا, sk-dummy.c needs an update
#اگر_ختم

#اگر_تعریف_شدہ SK_DUMMY_INTEGRATE
# define sk_api_نسخہ		ssh_sk_api_نسخہ
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_بھرو_resident_کلیدیں	ssh_sk_بھرو_resident_کلیدیں
#اگر_ختم /* !SK_STANDALONE */

ساکن خالی skdebug(ثابت حرف *func, ثابت حرف *fmt, ...)
    __attribute__((__format__ (لکھو, 2, 3)));

ساکن خالی
skdebug(ثابت حرف *func, ثابت حرف *fmt, ...)
{
#اگر defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "sk-dummy %s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#ورنہ
	(خالی)func; /* XXX */
	(خالی)fmt; /* XXX */
#اگر_ختم
}

uint32_t
sk_api_نسخہ(خالی)
{
	واپس SSH_SK_نسخہ_MAJOR;
}

ساکن صحیح
pack_کلید_ecdsa(ساخت sk_enroll_response *response)
{
#اگر_تعریف_شدہ WITH_OPENSSL
	EC_کلید *کلید = تہی;
	ثابت EC_گروہ *g;
	ثابت EC_نقطہ *q;
	صحیح ret = -1;
	طویل privlen;
	BIO *bio = تہی;
	حرف *privptr;

	response->عوامی_کلید = تہی;
	response->عوامی_کلید_len = 0;
	response->کلید_handle = تہی;
	response->کلید_handle_len = 0;

	اگر ((کلید = EC_کلید_new_by_خم_name(NID_X9_62_prime256v1)) == تہی) {
		skdebug(__func__, "EC_KEY_new_by_curve_name");
		جاؤ برآمد;
	}
	اگر (EC_کلید_generate_کلید(کلید) != 1) {
		skdebug(__func__, "EC_KEY_generate_key");
		جاؤ برآمد;
	}
	EC_کلید_سیٹ_asn1_flag(کلید, OPENSSL_EC_NAMED_خم);
	اگر ((bio = BIO_new(BIO_s_mem())) == تہی ||
	    (g = EC_کلید_get0_گروہ(کلید)) == تہی ||
	    (q = EC_کلید_get0_عوامی_کلید(کلید)) == تہی) {
		skdebug(__func__, "couldn't get key parameters");
		جاؤ برآمد;
	}
	response->عوامی_کلید_len = EC_نقطہ_point2oct(g, q,
	    نقطہ_CONVERSION_UNCOMPRESSED, تہی, 0, تہی);
	اگر (response->عوامی_کلید_len == 0 || response->عوامی_کلید_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->عوامی_کلید_len);
		جاؤ برآمد;
	}
	اگر ((response->عوامی_کلید = حافظہ_دو(response->عوامی_کلید_len)) == تہی) {
		skdebug(__func__, "malloc pubkey failed");
		جاؤ برآمد;
	}
	اگر (EC_نقطہ_point2oct(g, q, نقطہ_CONVERSION_UNCOMPRESSED,
	    response->عوامی_کلید, response->عوامی_کلید_len, تہی) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		جاؤ برآمد;
	}
	/* Key handle contains PEM encoded private key */
	اگر (!PEM_write_bio_ECPrivate_کلید(bio, کلید, تہی, تہی, 0, تہی, تہی)) {
		skdebug(__func__, "PEM_write_bio_ECPrivateKey failed");
		جاؤ برآمد;
	}
	اگر ((privlen = BIO_get_mem_ڈیٹا(bio, &privptr)) <= 0) {
		skdebug(__func__, "BIO_get_mem_data failed");
		جاؤ برآمد;
	}
	اگر ((response->کلید_handle = حافظہ_دو(privlen)) == تہی) {
		skdebug(__func__, "malloc key_handle failed");
		جاؤ برآمد;
	}
	response->کلید_handle_len = (سائز_t)privlen;
	حافظہ_نقل(response->کلید_handle, privptr, response->کلید_handle_len);
	/* success */
	ret = 0;
 برآمد:
	اگر (ret != 0) {
		اگر (response->عوامی_کلید != تہی) {
			memset(response->عوامی_کلید, 0,
			    response->عوامی_کلید_len);
			آزاد(response->عوامی_کلید);
			response->عوامی_کلید = تہی;
		}
		اگر (response->کلید_handle != تہی) {
			memset(response->کلید_handle, 0,
			    response->کلید_handle_len);
			آزاد(response->کلید_handle);
			response->کلید_handle = تہی;
		}
	}
	BIO_free(bio);
	EC_کلید_free(کلید);
	واپس ret;
#ورنہ
	واپس -1;
#اگر_ختم
}

ساکن صحیح
pack_کلید_ed25519(ساخت sk_enroll_response *response)
{
	صحیح ret = -1;
	u_char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	u_char sk[crypto_sign_ed25519_SECRETKEYBYTES];

	response->عوامی_کلید = تہی;
	response->عوامی_کلید_len = 0;
	response->کلید_handle = تہی;
	response->کلید_handle_len = 0;

	memset(pk, 0, حجم(pk));
	memset(sk, 0, حجم(sk));
	crypto_sign_ed25519_keypair(pk, sk);

	response->عوامی_کلید_len = حجم(pk);
	اگر ((response->عوامی_کلید = حافظہ_دو(response->عوامی_کلید_len)) == تہی) {
		skdebug(__func__, "malloc pubkey failed");
		جاؤ برآمد;
	}
	حافظہ_نقل(response->عوامی_کلید, pk, حجم(pk));
	/* Key handle contains sk */
	response->کلید_handle_len = حجم(sk);
	اگر ((response->کلید_handle = حافظہ_دو(response->کلید_handle_len)) == تہی) {
		skdebug(__func__, "malloc key_handle failed");
		جاؤ برآمد;
	}
	حافظہ_نقل(response->کلید_handle, sk, حجم(sk));
	/* success */
	ret = 0;
 برآمد:
	اگر (ret != 0)
		آزاد(response->عوامی_کلید);
	واپس ret;
}

ساکن صحیح
check_options(ساخت sk_option **options)
{
	سائز_t i;

	اگر (options == تہی)
		واپس 0;
	برائے (i = 0; options[i] != تہی; i++) {
		skdebug(__func__, "requested unsupported option %s",
		    options[i]->name);
		اگر (options[i]->required) {
			skdebug(__func__, "unknown required option");
			واپس -1;
		}
	}
	واپس 0;
}

صحیح
sk_enroll(uint32_t alg, ثابت uint8_t *challenge, سائز_t challenge_len,
    ثابت حرف *application, uint8_t flags, ثابت حرف *pin,
    ساخت sk_option **options, ساخت sk_enroll_response **enroll_response)
{
	ساخت sk_enroll_response *response = تہی;
	صحیح ret = SSH_SK_ERR_GENERAL;

	(خالی)flags; /* XXX; unused */

	اگر (enroll_response == تہی) {
		skdebug(__func__, "enroll_response == NULL");
		جاؤ برآمد;
	}
	*enroll_response = تہی;
	اگر (check_options(options) != 0)
		جاؤ برآمد; /* error already logged */
	اگر ((response = صفر_حافظہ_دو(1, حجم(*response))) == تہی) {
		skdebug(__func__, "calloc response failed");
		جاؤ برآمد;
	}
	response->flags = flags;
	انتخاب(alg) {
	حالت SSH_SK_ECDSA:
		اگر (pack_کلید_ecdsa(response) != 0)
			جاؤ برآمد;
		توڑو;
	حالت SSH_SK_ED25519:
		اگر (pack_کلید_ed25519(response) != 0)
			جاؤ برآمد;
		توڑو;
	طےشدہ:
		skdebug(__func__, "unsupported key type %d", alg);
		جاؤ برآمد;
	}
	/* Have to return something here */
	اگر ((response->signature = صفر_حافظہ_دو(1, 1)) == تہی) {
		skdebug(__func__, "calloc signature failed");
		جاؤ برآمد;
	}
	response->signature_len = 0;

	*enroll_response = response;
	response = تہی;
	ret = 0;
 برآمد:
	اگر (response != تہی) {
		آزاد(response->عوامی_کلید);
		آزاد(response->کلید_handle);
		آزاد(response->signature);
		آزاد(response->attestation_cert);
		آزاد(response);
	}
	واپس ret;
}

ساکن خالی
dump(ثابت حرف *preamble, ثابت خالی *sv, سائز_t l)
{
#اگر_تعریف_شدہ SK_DEBUG
	ثابت u_char *s = (ثابت u_char *)sv;
	سائز_t i;

	fprintf(stderr, "%s (len %zu):\n", preamble, l);
	برائے (i = 0; i < l; i++) {
		اگر (i % 16 == 0)
			fprintf(stderr, "%04zu: ", i);
		fprintf(stderr, "%02x", s[i]);
		اگر (i % 16 == 15 || i == l - 1)
			fprintf(stderr, "\n");
	}
#اگر_ختم
}

ساکن صحیح
sig_ecdsa(ثابت uint8_t *پیغام_2, سائز_t پیغام_len_2,
    ثابت حرف *application, uint32_t شمار_2, uint8_t flags,
    ثابت uint8_t *کلید_handle, سائز_t کلید_handle_len,
    ساخت sk_sign_response *response)
{
#اگر_تعریف_شدہ WITH_OPENSSL
	ECDSA_SIG *sig = تہی;
	ثابت BIGNUM *sig_r, *sig_s;
	صحیح ret = -1;
	BIO *bio = تہی;
	EVP_PKEY *pk = تہی;
	EC_کلید *ec = تہی;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_لمبائی];
	uint8_t	sighash[SHA256_DIGEST_لمبائی];
	uint8_t countbuf[4];

	/* Decode EC_KEY from key handle */
	اگر ((bio = BIO_new(BIO_s_mem())) == تہی ||
	    BIO_write(bio, کلید_handle, کلید_handle_len) != (صحیح)کلید_handle_len) {
		skdebug(__func__, "BIO setup failed");
		جاؤ برآمد;
	}
	اگر ((pk = PEM_read_bio_نجی_کلید(bio, تہی, تہی, "")) == تہی) {
		skdebug(__func__, "PEM_read_bio_PrivateKey failed");
		جاؤ برآمد;
	}
	اگر (EVP_PKEY_بنیاد_id(pk) != EVP_PKEY_EC) {
		skdebug(__func__, "Not an EC key: %d", EVP_PKEY_بنیاد_id(pk));
		جاؤ برآمد;
	}
	اگر ((ec = EVP_PKEY_get1_EC_کلید(pk)) == تہی) {
		skdebug(__func__, "EVP_PKEY_get1_EC_KEY failed");
		جاؤ برآمد;
	}
	/* Expect message to be pre-hashed */
	اگر (پیغام_len_2 != SHA256_DIGEST_لمبائی) {
		skdebug(__func__, "bad message len %zu", پیغام_len_2);
		جاؤ برآمد;
	}
	/* Prepare data to be signed */
	dump("message", پیغام_2, پیغام_len_2);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ثابت u_char *)application, لڑی_لمبائی(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, حجم(apphash));
	countbuf[0] = (شمار_2 >> 24) & 0xff;
	countbuf[1] = (شمار_2 >> 16) & 0xff;
	countbuf[2] = (شمار_2 >> 8) & 0xff;
	countbuf[3] = شمار_2 & 0xff;
	dump("countbuf", countbuf, حجم(countbuf));
	dump("flags", &flags, حجم(flags));
	SHA256Init(&ctx);
	SHA256Update(&ctx, apphash, حجم(apphash));
	SHA256Update(&ctx, &flags, حجم(flags));
	SHA256Update(&ctx, countbuf, حجم(countbuf));
	SHA256Update(&ctx, پیغام_2, پیغام_len_2);
	SHA256Final(sighash, &ctx);
	dump("sighash", sighash, حجم(sighash));
	/* create and encode signature */
	اگر ((sig = ECDSA_do_sign(sighash, حجم(sighash), ec)) == تہی) {
		skdebug(__func__, "ECDSA_do_sign failed");
		جاؤ برآمد;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_عدد_بائٹیں(sig_r);
	response->sig_s_len = BN_عدد_بائٹیں(sig_s);
	اگر ((response->sig_r = صفر_حافظہ_دو(1, response->sig_r_len)) == تہی ||
	    (response->sig_s = صفر_حافظہ_دو(1, response->sig_s_len)) == تہی) {
		skdebug(__func__, "calloc signature failed");
		جاؤ برآمد;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 برآمد:
	explicit_bzero(&ctx, حجم(ctx));
	explicit_bzero(&apphash, حجم(apphash));
	explicit_bzero(&sighash, حجم(sighash));
	ECDSA_SIG_free(sig);
	اگر (ret != 0) {
		آزاد(response->sig_r);
		آزاد(response->sig_s);
		response->sig_r = تہی;
		response->sig_s = تہی;
	}
	BIO_free(bio);
	EC_کلید_free(ec);
	EVP_PKEY_free(pk);
	واپس ret;
#ورنہ
	واپس -1;
#اگر_ختم
}

ساکن صحیح
sig_ed25519(ثابت uint8_t *پیغام_2, سائز_t پیغام_len_2,
    ثابت حرف *application, uint32_t شمار_2, uint8_t flags,
    ثابت uint8_t *کلید_handle, سائز_t کلید_handle_len,
    ساخت sk_sign_response *response)
{
	سائز_t o;
	صحیح ret = -1;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_لمبائی];
	uint8_t signbuf[حجم(apphash) + حجم(flags) +
	    حجم(شمار_2) + SHA256_DIGEST_لمبائی];
	uint8_t sig[crypto_sign_ed25519_بائٹیں];
	غیرعلامتی طویل طویل siglen = 0;

	اگر (کلید_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		skdebug(__func__, "bad key handle length %zu", کلید_handle_len);
		جاؤ برآمد;
	}
	/* Expect message to be pre-hashed */
	اگر (پیغام_len_2 != SHA256_DIGEST_لمبائی) {
		skdebug(__func__, "bad message len %zu", پیغام_len_2);
		جاؤ برآمد;
	}
	/* Prepare data to be signed */
	dump("message", پیغام_2, پیغام_len_2);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ثابت u_char *)application, لڑی_لمبائی(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, حجم(apphash));

	حافظہ_نقل(signbuf, apphash, حجم(apphash));
	o = حجم(apphash);
	signbuf[o++] = flags;
	signbuf[o++] = (شمار_2 >> 24) & 0xff;
	signbuf[o++] = (شمار_2 >> 16) & 0xff;
	signbuf[o++] = (شمار_2 >> 8) & 0xff;
	signbuf[o++] = شمار_2 & 0xff;
	حافظہ_نقل(signbuf + o, پیغام_2, پیغام_len_2);
	o += پیغام_len_2;
	اگر (o != حجم(signbuf)) {
		skdebug(__func__, "bad sign buf len %zu, expected %zu",
		    o, حجم(signbuf));
		جاؤ برآمد;
	}
	dump("signbuf", signbuf, حجم(signbuf));
	/* create and encode signature */
	اگر (crypto_sign_ed25519_detached(sig, &siglen, signbuf, حجم(signbuf),
	    کلید_handle) != 0) {
		skdebug(__func__, "crypto_sign_ed25519_detached failed");
		جاؤ برآمد;
	}
	اگر (siglen != حجم(sig)) {
		skdebug(__func__, "bad signature length %llu", siglen);
		جاؤ برآمد;
	}
	response->sig_r_len = حجم(sig);
	اگر ((response->sig_r = صفر_حافظہ_دو(1, response->sig_r_len)) == تہی) {
		skdebug(__func__, "calloc signature failed");
		جاؤ برآمد;
	}
	حافظہ_نقل(response->sig_r, sig, response->sig_r_len);
	dump("sig_r", response->sig_r, response->sig_r_len);
	ret = 0;
 برآمد:
	explicit_bzero(&ctx, حجم(ctx));
	explicit_bzero(&apphash, حجم(apphash));
	explicit_bzero(&signbuf, حجم(signbuf));
	explicit_bzero(&sig, حجم(sig));
	اگر (ret != 0) {
		آزاد(response->sig_r);
		response->sig_r = تہی;
	}
	واپس ret;
}

صحیح
sk_sign(uint32_t alg, ثابت uint8_t *ڈیٹا, سائز_t datalen,
    ثابت حرف *application, ثابت uint8_t *کلید_handle, سائز_t کلید_handle_len,
    uint8_t flags, ثابت حرف *pin, ساخت sk_option **options,
    ساخت sk_sign_response **sign_response)
{
	ساخت sk_sign_response *response = تہی;
	صحیح ret = SSH_SK_ERR_GENERAL;
	SHA2_CTX ctx;
	uint8_t پیغام_2[32];

	اگر (sign_response == تہی) {
		skdebug(__func__, "sign_response == NULL");
		جاؤ برآمد;
	}
	*sign_response = تہی;
	اگر (check_options(options) != 0)
		جاؤ برآمد; /* error already logged */
	اگر ((response = صفر_حافظہ_دو(1, حجم(*response))) == تہی) {
		skdebug(__func__, "calloc response failed");
		جاؤ برآمد;
	}
	SHA256Init(&ctx);
	SHA256Update(&ctx, ڈیٹا, datalen);
	SHA256Final(پیغام_2, &ctx);
	response->flags = flags;
	response->شمار_2 = 0x12345678;
	انتخاب(alg) {
	حالت SSH_SK_ECDSA:
		اگر (sig_ecdsa(پیغام_2, حجم(پیغام_2), application,
		    response->شمار_2, flags, کلید_handle, کلید_handle_len,
		    response) != 0)
			جاؤ برآمد;
		توڑو;
	حالت SSH_SK_ED25519:
		اگر (sig_ed25519(پیغام_2, حجم(پیغام_2), application,
		    response->شمار_2, flags, کلید_handle, کلید_handle_len,
		    response) != 0)
			جاؤ برآمد;
		توڑو;
	طےشدہ:
		skdebug(__func__, "unsupported key type %d", alg);
		جاؤ برآمد;
	}
	*sign_response = response;
	response = تہی;
	ret = 0;
 برآمد:
	explicit_bzero(پیغام_2, حجم(پیغام_2));
	اگر (response != تہی) {
		آزاد(response->sig_r);
		آزاد(response->sig_s);
		آزاد(response);
	}
	واپس ret;
}

صحیح
sk_بھرو_resident_کلیدیں(ثابت حرف *pin, ساخت sk_option **options,
    ساخت sk_resident_کلید ***rks, سائز_t *nrks)
{
	واپس SSH_SK_ERR_UNSUPPORTED;
}
