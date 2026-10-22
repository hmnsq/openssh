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

#ضمن "includes.h"

#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <stdio.h>
#ضمن <stddef.h>
#ضمن <stdarg.h>

#ضمن "crypto_api.h"
#ضمن "sk-api.h"

#اگر_تعریف_شده WITH_OPENSSL
#ضمن <openssl/opensslv.h>
#ضمن <openssl/sha.h>
#ضمن <openssl/crypto.h>
#ضمن <openssl/evp.h>
#ضمن <openssl/bn.h>
#ضمن <openssl/ec.h>
#ضمن <openssl/ecdsa.h>
#ضمن <openssl/pem.h>

/* Use OpenSSL SHA256 instead of libc */
#تعریف_کن SHA256Init(x)		SHA256_Init(x)
#تعریف_کن SHA256Update(x, y, z)	SHA256_Update(x, y, z)
#تعریف_کن SHA256Final(x, y)	SHA256_Final(x, y)
#تعریف_کن SHA2_CTX		SHA256_CTX

#وإلاإذا defined(HAVE_SHA2_H)
#ضمن <sha2.h>
#پایان_اگر /* WITH_OPENSSL */

/* #define SK_DEBUG 1 */

#إذا SSH_SK_نسخه_MAJOR != 0x000a0000
# error SK API has تغییریافته, sk-dummy.c needs an update
#پایان_اگر

#اگر_تعریف_شده SK_DUMMY_INTEGRATE
# define sk_api_نسخه		ssh_sk_api_نسخه
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_بارگیری_resident_کلیدها	ssh_sk_بارگیری_resident_کلیدها
#پایان_اگر /* !SK_STANDALONE */

ساكن فراغ skdebug(ثابت حرف *func, ثابت حرف *fmt, ...)
    __attribute__((__format__ (چاپ_کن, 2, 3)));

ساكن فراغ
skdebug(ثابت حرف *func, ثابت حرف *fmt, ...)
{
#إذا defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "sk-dummy %s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#وإلا
	(فراغ)func; /* XXX */
	(فراغ)fmt; /* XXX */
#پایان_اگر
}

uint32_t
sk_api_نسخه(فراغ)
{
	أرجع SSH_SK_نسخه_MAJOR;
}

ساكن صحيح
pack_کلید_ecdsa(بنية sk_enroll_response *response)
{
#اگر_تعریف_شده WITH_OPENSSL
	EC_کلید *کلید = عدم;
	ثابت EC_گروه *g;
	ثابت EC_نقطه *q;
	صحيح ret = -1;
	دراز privlen;
	BIO *bio = عدم;
	حرف *privptr;

	response->عمومی_کلید = عدم;
	response->عمومی_کلید_len = 0;
	response->کلید_handle = عدم;
	response->کلید_handle_len = 0;

	إذا ((کلید = EC_کلید_new_by_منحنی_name(NID_X9_62_prime256v1)) == عدم) {
		skdebug(__func__, "EC_KEY_new_by_curve_name");
		اذهب بیرون;
	}
	إذا (EC_کلید_generate_کلید(کلید) != 1) {
		skdebug(__func__, "EC_KEY_generate_key");
		اذهب بیرون;
	}
	EC_کلید_مجموعه_asn1_flag(کلید, OPENSSL_EC_NAMED_منحنی);
	إذا ((bio = BIO_new(BIO_s_mem())) == عدم ||
	    (g = EC_کلید_get0_گروه(کلید)) == عدم ||
	    (q = EC_کلید_get0_عمومی_کلید(کلید)) == عدم) {
		skdebug(__func__, "couldn't get key parameters");
		اذهب بیرون;
	}
	response->عمومی_کلید_len = EC_نقطه_point2oct(g, q,
	    نقطه_CONVERSION_UNCOMPRESSED, عدم, 0, عدم);
	إذا (response->عمومی_کلید_len == 0 || response->عمومی_کلید_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->عمومی_کلید_len);
		اذهب بیرون;
	}
	إذا ((response->عمومی_کلید = حافظه_بده(response->عمومی_کلید_len)) == عدم) {
		skdebug(__func__, "malloc pubkey failed");
		اذهب بیرون;
	}
	إذا (EC_نقطه_point2oct(g, q, نقطه_CONVERSION_UNCOMPRESSED,
	    response->عمومی_کلید, response->عمومی_کلید_len, عدم) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		اذهب بیرون;
	}
	/* Key handle contains PEM encoded private key */
	إذا (!PEM_write_bio_ECPrivate_کلید(bio, کلید, عدم, عدم, 0, عدم, عدم)) {
		skdebug(__func__, "PEM_write_bio_ECPrivateKey failed");
		اذهب بیرون;
	}
	إذا ((privlen = BIO_get_mem_داده(bio, &privptr)) <= 0) {
		skdebug(__func__, "BIO_get_mem_data failed");
		اذهب بیرون;
	}
	إذا ((response->کلید_handle = حافظه_بده(privlen)) == عدم) {
		skdebug(__func__, "malloc key_handle failed");
		اذهب بیرون;
	}
	response->کلید_handle_len = (اندازه_t)privlen;
	کپی_حافظه(response->کلید_handle, privptr, response->کلید_handle_len);
	/* success */
	ret = 0;
 بیرون:
	إذا (ret != 0) {
		إذا (response->عمومی_کلید != عدم) {
			memset(response->عمومی_کلید, 0,
			    response->عمومی_کلید_len);
			حرر(response->عمومی_کلید);
			response->عمومی_کلید = عدم;
		}
		إذا (response->کلید_handle != عدم) {
			memset(response->کلید_handle, 0,
			    response->کلید_handle_len);
			حرر(response->کلید_handle);
			response->کلید_handle = عدم;
		}
	}
	BIO_free(bio);
	EC_کلید_free(کلید);
	أرجع ret;
#وإلا
	أرجع -1;
#پایان_اگر
}

ساكن صحيح
pack_کلید_ed25519(بنية sk_enroll_response *response)
{
	صحيح ret = -1;
	u_char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	u_char sk[crypto_sign_ed25519_SECRETKEYBYTES];

	response->عمومی_کلید = عدم;
	response->عمومی_کلید_len = 0;
	response->کلید_handle = عدم;
	response->کلید_handle_len = 0;

	memset(pk, 0, حجم(pk));
	memset(sk, 0, حجم(sk));
	crypto_sign_ed25519_keypair(pk, sk);

	response->عمومی_کلید_len = حجم(pk);
	إذا ((response->عمومی_کلید = حافظه_بده(response->عمومی_کلید_len)) == عدم) {
		skdebug(__func__, "malloc pubkey failed");
		اذهب بیرون;
	}
	کپی_حافظه(response->عمومی_کلید, pk, حجم(pk));
	/* Key handle contains sk */
	response->کلید_handle_len = حجم(sk);
	إذا ((response->کلید_handle = حافظه_بده(response->کلید_handle_len)) == عدم) {
		skdebug(__func__, "malloc key_handle failed");
		اذهب بیرون;
	}
	کپی_حافظه(response->کلید_handle, sk, حجم(sk));
	/* success */
	ret = 0;
 بیرون:
	إذا (ret != 0)
		حرر(response->عمومی_کلید);
	أرجع ret;
}

ساكن صحيح
check_options(بنية sk_option **options)
{
	اندازه_t i;

	إذا (options == عدم)
		أرجع 0;
	لكل (i = 0; options[i] != عدم; i++) {
		skdebug(__func__, "requested unsupported option %s",
		    options[i]->name);
		إذا (options[i]->required) {
			skdebug(__func__, "unknown required option");
			أرجع -1;
		}
	}
	أرجع 0;
}

صحيح
sk_enroll(uint32_t alg, ثابت uint8_t *challenge, اندازه_t challenge_len,
    ثابت حرف *application, uint8_t flags, ثابت حرف *pin,
    بنية sk_option **options, بنية sk_enroll_response **enroll_response)
{
	بنية sk_enroll_response *response = عدم;
	صحيح ret = SSH_SK_ERR_GENERAL;

	(فراغ)flags; /* XXX; unused */

	إذا (enroll_response == عدم) {
		skdebug(__func__, "enroll_response == NULL");
		اذهب بیرون;
	}
	*enroll_response = عدم;
	إذا (check_options(options) != 0)
		اذهب بیرون; /* error already logged */
	إذا ((response = حافظه_صفر_بده(1, حجم(*response))) == عدم) {
		skdebug(__func__, "calloc response failed");
		اذهب بیرون;
	}
	response->flags = flags;
	بدل(alg) {
	حالة SSH_SK_ECDSA:
		إذا (pack_کلید_ecdsa(response) != 0)
			اذهب بیرون;
		اكسر;
	حالة SSH_SK_ED25519:
		إذا (pack_کلید_ed25519(response) != 0)
			اذهب بیرون;
		اكسر;
	افتراضي:
		skdebug(__func__, "unsupported key type %d", alg);
		اذهب بیرون;
	}
	/* Have to return something here */
	إذا ((response->signature = حافظه_صفر_بده(1, 1)) == عدم) {
		skdebug(__func__, "calloc signature failed");
		اذهب بیرون;
	}
	response->signature_len = 0;

	*enroll_response = response;
	response = عدم;
	ret = 0;
 بیرون:
	إذا (response != عدم) {
		حرر(response->عمومی_کلید);
		حرر(response->کلید_handle);
		حرر(response->signature);
		حرر(response->attestation_cert);
		حرر(response);
	}
	أرجع ret;
}

ساكن فراغ
dump(ثابت حرف *preamble, ثابت فراغ *sv, اندازه_t l)
{
#اگر_تعریف_شده SK_DEBUG
	ثابت u_char *s = (ثابت u_char *)sv;
	اندازه_t i;

	fprintf(stderr, "%s (len %zu):\n", preamble, l);
	لكل (i = 0; i < l; i++) {
		إذا (i % 16 == 0)
			fprintf(stderr, "%04zu: ", i);
		fprintf(stderr, "%02x", s[i]);
		إذا (i % 16 == 15 || i == l - 1)
			fprintf(stderr, "\n");
	}
#پایان_اگر
}

ساكن صحيح
sig_ecdsa(ثابت uint8_t *پیام_2, اندازه_t پیام_len_2,
    ثابت حرف *application, uint32_t counter, uint8_t flags,
    ثابت uint8_t *کلید_handle, اندازه_t کلید_handle_len,
    بنية sk_sign_response *response)
{
#اگر_تعریف_شده WITH_OPENSSL
	ECDSA_SIG *sig = عدم;
	ثابت BIGNUM *sig_r, *sig_s;
	صحيح ret = -1;
	BIO *bio = عدم;
	EVP_PKEY *pk = عدم;
	EC_کلید *ec = عدم;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_درازی];
	uint8_t	sighash[SHA256_DIGEST_درازی];
	uint8_t countbuf[4];

	/* Decode EC_KEY from key handle */
	إذا ((bio = BIO_new(BIO_s_mem())) == عدم ||
	    BIO_write(bio, کلید_handle, کلید_handle_len) != (صحيح)کلید_handle_len) {
		skdebug(__func__, "BIO setup failed");
		اذهب بیرون;
	}
	إذا ((pk = PEM_read_bio_خصوصی_کلید(bio, عدم, عدم, "")) == عدم) {
		skdebug(__func__, "PEM_read_bio_PrivateKey failed");
		اذهب بیرون;
	}
	إذا (EVP_PKEY_پایه_id(pk) != EVP_PKEY_EC) {
		skdebug(__func__, "Not an EC key: %d", EVP_PKEY_پایه_id(pk));
		اذهب بیرون;
	}
	إذا ((ec = EVP_PKEY_get1_EC_کلید(pk)) == عدم) {
		skdebug(__func__, "EVP_PKEY_get1_EC_KEY failed");
		اذهب بیرون;
	}
	/* Expect message to be pre-hashed */
	إذا (پیام_len_2 != SHA256_DIGEST_درازی) {
		skdebug(__func__, "bad message len %zu", پیام_len_2);
		اذهب بیرون;
	}
	/* Prepare data to be signed */
	dump("message", پیام_2, پیام_len_2);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ثابت u_char *)application, طول_رشته(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, حجم(apphash));
	countbuf[0] = (counter >> 24) & 0xff;
	countbuf[1] = (counter >> 16) & 0xff;
	countbuf[2] = (counter >> 8) & 0xff;
	countbuf[3] = counter & 0xff;
	dump("countbuf", countbuf, حجم(countbuf));
	dump("flags", &flags, حجم(flags));
	SHA256Init(&ctx);
	SHA256Update(&ctx, apphash, حجم(apphash));
	SHA256Update(&ctx, &flags, حجم(flags));
	SHA256Update(&ctx, countbuf, حجم(countbuf));
	SHA256Update(&ctx, پیام_2, پیام_len_2);
	SHA256Final(sighash, &ctx);
	dump("sighash", sighash, حجم(sighash));
	/* create and encode signature */
	إذا ((sig = ECDSA_do_sign(sighash, حجم(sighash), ec)) == عدم) {
		skdebug(__func__, "ECDSA_do_sign failed");
		اذهب بیرون;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_رقم_بایتها(sig_r);
	response->sig_s_len = BN_رقم_بایتها(sig_s);
	إذا ((response->sig_r = حافظه_صفر_بده(1, response->sig_r_len)) == عدم ||
	    (response->sig_s = حافظه_صفر_بده(1, response->sig_s_len)) == عدم) {
		skdebug(__func__, "calloc signature failed");
		اذهب بیرون;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 بیرون:
	explicit_bzero(&ctx, حجم(ctx));
	explicit_bzero(&apphash, حجم(apphash));
	explicit_bzero(&sighash, حجم(sighash));
	ECDSA_SIG_free(sig);
	إذا (ret != 0) {
		حرر(response->sig_r);
		حرر(response->sig_s);
		response->sig_r = عدم;
		response->sig_s = عدم;
	}
	BIO_free(bio);
	EC_کلید_free(ec);
	EVP_PKEY_free(pk);
	أرجع ret;
#وإلا
	أرجع -1;
#پایان_اگر
}

ساكن صحيح
sig_ed25519(ثابت uint8_t *پیام_2, اندازه_t پیام_len_2,
    ثابت حرف *application, uint32_t counter, uint8_t flags,
    ثابت uint8_t *کلید_handle, اندازه_t کلید_handle_len,
    بنية sk_sign_response *response)
{
	اندازه_t o;
	صحيح ret = -1;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_درازی];
	uint8_t signbuf[حجم(apphash) + حجم(flags) +
	    حجم(counter) + SHA256_DIGEST_درازی];
	uint8_t sig[crypto_sign_ed25519_بایتها];
	بیعلامت دراز دراز siglen = 0;

	إذا (کلید_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		skdebug(__func__, "bad key handle length %zu", کلید_handle_len);
		اذهب بیرون;
	}
	/* Expect message to be pre-hashed */
	إذا (پیام_len_2 != SHA256_DIGEST_درازی) {
		skdebug(__func__, "bad message len %zu", پیام_len_2);
		اذهب بیرون;
	}
	/* Prepare data to be signed */
	dump("message", پیام_2, پیام_len_2);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ثابت u_char *)application, طول_رشته(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, حجم(apphash));

	کپی_حافظه(signbuf, apphash, حجم(apphash));
	o = حجم(apphash);
	signbuf[o++] = flags;
	signbuf[o++] = (counter >> 24) & 0xff;
	signbuf[o++] = (counter >> 16) & 0xff;
	signbuf[o++] = (counter >> 8) & 0xff;
	signbuf[o++] = counter & 0xff;
	کپی_حافظه(signbuf + o, پیام_2, پیام_len_2);
	o += پیام_len_2;
	إذا (o != حجم(signbuf)) {
		skdebug(__func__, "bad sign buf len %zu, expected %zu",
		    o, حجم(signbuf));
		اذهب بیرون;
	}
	dump("signbuf", signbuf, حجم(signbuf));
	/* create and encode signature */
	إذا (crypto_sign_ed25519_detached(sig, &siglen, signbuf, حجم(signbuf),
	    کلید_handle) != 0) {
		skdebug(__func__, "crypto_sign_ed25519_detached failed");
		اذهب بیرون;
	}
	إذا (siglen != حجم(sig)) {
		skdebug(__func__, "bad signature length %llu", siglen);
		اذهب بیرون;
	}
	response->sig_r_len = حجم(sig);
	إذا ((response->sig_r = حافظه_صفر_بده(1, response->sig_r_len)) == عدم) {
		skdebug(__func__, "calloc signature failed");
		اذهب بیرون;
	}
	کپی_حافظه(response->sig_r, sig, response->sig_r_len);
	dump("sig_r", response->sig_r, response->sig_r_len);
	ret = 0;
 بیرون:
	explicit_bzero(&ctx, حجم(ctx));
	explicit_bzero(&apphash, حجم(apphash));
	explicit_bzero(&signbuf, حجم(signbuf));
	explicit_bzero(&sig, حجم(sig));
	إذا (ret != 0) {
		حرر(response->sig_r);
		response->sig_r = عدم;
	}
	أرجع ret;
}

صحيح
sk_sign(uint32_t alg, ثابت uint8_t *داده, اندازه_t datalen,
    ثابت حرف *application, ثابت uint8_t *کلید_handle, اندازه_t کلید_handle_len,
    uint8_t flags, ثابت حرف *pin, بنية sk_option **options,
    بنية sk_sign_response **sign_response)
{
	بنية sk_sign_response *response = عدم;
	صحيح ret = SSH_SK_ERR_GENERAL;
	SHA2_CTX ctx;
	uint8_t پیام_2[32];

	إذا (sign_response == عدم) {
		skdebug(__func__, "sign_response == NULL");
		اذهب بیرون;
	}
	*sign_response = عدم;
	إذا (check_options(options) != 0)
		اذهب بیرون; /* error already logged */
	إذا ((response = حافظه_صفر_بده(1, حجم(*response))) == عدم) {
		skdebug(__func__, "calloc response failed");
		اذهب بیرون;
	}
	SHA256Init(&ctx);
	SHA256Update(&ctx, داده, datalen);
	SHA256Final(پیام_2, &ctx);
	response->flags = flags;
	response->counter = 0x12345678;
	بدل(alg) {
	حالة SSH_SK_ECDSA:
		إذا (sig_ecdsa(پیام_2, حجم(پیام_2), application,
		    response->counter, flags, کلید_handle, کلید_handle_len,
		    response) != 0)
			اذهب بیرون;
		اكسر;
	حالة SSH_SK_ED25519:
		إذا (sig_ed25519(پیام_2, حجم(پیام_2), application,
		    response->counter, flags, کلید_handle, کلید_handle_len,
		    response) != 0)
			اذهب بیرون;
		اكسر;
	افتراضي:
		skdebug(__func__, "unsupported key type %d", alg);
		اذهب بیرون;
	}
	*sign_response = response;
	response = عدم;
	ret = 0;
 بیرون:
	explicit_bzero(پیام_2, حجم(پیام_2));
	إذا (response != عدم) {
		حرر(response->sig_r);
		حرر(response->sig_s);
		حرر(response);
	}
	أرجع ret;
}

صحيح
sk_بارگیری_resident_کلیدها(ثابت حرف *pin, بنية sk_option **options,
    بنية sk_resident_کلید ***rks, اندازه_t *nrks)
{
	أرجع SSH_SK_ERR_UNSUPPORTED;
}
