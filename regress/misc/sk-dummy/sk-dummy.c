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

#جے_تعریف_شدہ WITH_OPENSSL
#ضمن <openssl/opensslv.h>
#ضمن <openssl/sha.h>
#ضمن <openssl/crypto.h>
#ضمن <openssl/evp.h>
#ضمن <openssl/bn.h>
#ضمن <openssl/ec.h>
#ضمن <openssl/ecdsa.h>
#ضمن <openssl/pem.h>

/* Use OpenSSL SHA256 instead of libc */
#تعریف_کرو SHA256Init(x)		SHA256_Init(x)
#تعریف_کرو SHA256Update(x, y, z)	SHA256_Update(x, y, z)
#تعریف_کرو SHA256Final(x, y)	SHA256_Final(x, y)
#تعریف_کرو SHA2_CTX		SHA256_CTX

#وإلاإذا defined(HAVE_SHA2_H)
#ضمن <sha2.h>
#جے_انت /* WITH_OPENSSL */

/* #define SK_DEBUG 1 */

#إذا SSH_SK_نسخہ_MAJOR != 0x000a0000
# error SK API has بدلیا, sk-dummy.c needs an update
#جے_انت

#جے_تعریف_شدہ SK_DUMMY_INTEGRATE
# define sk_api_نسخہ		ssh_sk_api_نسخہ
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_لدو_resident_کلیدیں	ssh_sk_لدو_resident_کلیدیں
#جے_انت /* !SK_STANDALONE */

ساكن فراغ skdebug(ثابت حرف *func, ثابت حرف *fmt, ...)
    __attribute__((__format__ (لکھو, 2, 3)));

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
#جے_انت
}

uint32_t
sk_api_نسخہ(فراغ)
{
	أرجع SSH_SK_نسخہ_MAJOR;
}

ساكن صحيح
pack_کلید_ecdsa(بنية sk_enroll_response *response)
{
#جے_تعریف_شدہ WITH_OPENSSL
	EC_کلید *کلید = عدم;
	ثابت EC_گروہ *g;
	ثابت EC_نقطہ *q;
	صحيح ret = -1;
	لما privlen;
	BIO *bio = عدم;
	حرف *privptr;

	response->عوامی_کلید = عدم;
	response->عوامی_کلید_len = 0;
	response->کلید_handle = عدم;
	response->کلید_handle_len = 0;

	إذا ((کلید = EC_کلید_new_by_ونگ_name(NID_X9_62_prime256v1)) == عدم) {
		skdebug(__func__, "EC_KEY_new_by_curve_name");
		اذهب باہرلا;
	}
	إذا (EC_کلید_generate_کلید(کلید) != 1) {
		skdebug(__func__, "EC_KEY_generate_key");
		اذهب باہرلا;
	}
	EC_کلید_سیٹ_asn1_flag(کلید, OPENSSL_EC_NAMED_ونگ);
	إذا ((bio = BIO_new(BIO_s_mem())) == عدم ||
	    (g = EC_کلید_get0_گروہ(کلید)) == عدم ||
	    (q = EC_کلید_get0_عوامی_کلید(کلید)) == عدم) {
		skdebug(__func__, "couldn't get key parameters");
		اذهب باہرلا;
	}
	response->عوامی_کلید_len = EC_نقطہ_point2oct(g, q,
	    نقطہ_CONVERSION_UNCOMPRESSED, عدم, 0, عدم);
	إذا (response->عوامی_کلید_len == 0 || response->عوامی_کلید_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->عوامی_کلید_len);
		اذهب باہرلا;
	}
	إذا ((response->عوامی_کلید = حافظہ_دیو(response->عوامی_کلید_len)) == عدم) {
		skdebug(__func__, "malloc pubkey failed");
		اذهب باہرلا;
	}
	إذا (EC_نقطہ_point2oct(g, q, نقطہ_CONVERSION_UNCOMPRESSED,
	    response->عوامی_کلید, response->عوامی_کلید_len, عدم) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		اذهب باہرلا;
	}
	/* Key handle contains PEM encoded private key */
	إذا (!PEM_write_bio_ECPrivate_کلید(bio, کلید, عدم, عدم, 0, عدم, عدم)) {
		skdebug(__func__, "PEM_write_bio_ECPrivateKey failed");
		اذهب باہرلا;
	}
	إذا ((privlen = BIO_get_mem_انکڑے(bio, &privptr)) <= 0) {
		skdebug(__func__, "BIO_get_mem_data failed");
		اذهب باہرلا;
	}
	إذا ((response->کلید_handle = حافظہ_دیو(privlen)) == عدم) {
		skdebug(__func__, "malloc key_handle failed");
		اذهب باہرلا;
	}
	response->کلید_handle_len = (ناپ_t)privlen;
	حافظہ_نقل(response->کلید_handle, privptr, response->کلید_handle_len);
	/* success */
	ret = 0;
 باہرلا:
	إذا (ret != 0) {
		إذا (response->عوامی_کلید != عدم) {
			memset(response->عوامی_کلید, 0,
			    response->عوامی_کلید_len);
			حرر(response->عوامی_کلید);
			response->عوامی_کلید = عدم;
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
#جے_انت
}

ساكن صحيح
pack_کلید_ed25519(بنية sk_enroll_response *response)
{
	صحيح ret = -1;
	u_char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	u_char sk[crypto_sign_ed25519_SECRETKEYBYTES];

	response->عوامی_کلید = عدم;
	response->عوامی_کلید_len = 0;
	response->کلید_handle = عدم;
	response->کلید_handle_len = 0;

	memset(pk, 0, حجم(pk));
	memset(sk, 0, حجم(sk));
	crypto_sign_ed25519_keypair(pk, sk);

	response->عوامی_کلید_len = حجم(pk);
	إذا ((response->عوامی_کلید = حافظہ_دیو(response->عوامی_کلید_len)) == عدم) {
		skdebug(__func__, "malloc pubkey failed");
		اذهب باہرلا;
	}
	حافظہ_نقل(response->عوامی_کلید, pk, حجم(pk));
	/* Key handle contains sk */
	response->کلید_handle_len = حجم(sk);
	إذا ((response->کلید_handle = حافظہ_دیو(response->کلید_handle_len)) == عدم) {
		skdebug(__func__, "malloc key_handle failed");
		اذهب باہرلا;
	}
	حافظہ_نقل(response->کلید_handle, sk, حجم(sk));
	/* success */
	ret = 0;
 باہرلا:
	إذا (ret != 0)
		حرر(response->عوامی_کلید);
	أرجع ret;
}

ساكن صحيح
check_options(بنية sk_option **options)
{
	ناپ_t i;

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
sk_enroll(uint32_t alg, ثابت uint8_t *challenge, ناپ_t challenge_len,
    ثابت حرف *application, uint8_t flags, ثابت حرف *pin,
    بنية sk_option **options, بنية sk_enroll_response **enroll_response)
{
	بنية sk_enroll_response *response = عدم;
	صحيح ret = SSH_SK_ERR_GENERAL;

	(فراغ)flags; /* XXX; unused */

	إذا (enroll_response == عدم) {
		skdebug(__func__, "enroll_response == NULL");
		اذهب باہرلا;
	}
	*enroll_response = عدم;
	إذا (check_options(options) != 0)
		اذهب باہرلا; /* error already logged */
	إذا ((response = صفر_حافظہ_دیو(1, حجم(*response))) == عدم) {
		skdebug(__func__, "calloc response failed");
		اذهب باہرلا;
	}
	response->flags = flags;
	بدل(alg) {
	حالة SSH_SK_ECDSA:
		إذا (pack_کلید_ecdsa(response) != 0)
			اذهب باہرلا;
		اكسر;
	حالة SSH_SK_ED25519:
		إذا (pack_کلید_ed25519(response) != 0)
			اذهب باہرلا;
		اكسر;
	افتراضي:
		skdebug(__func__, "unsupported key type %d", alg);
		اذهب باہرلا;
	}
	/* Have to return something here */
	إذا ((response->signature = صفر_حافظہ_دیو(1, 1)) == عدم) {
		skdebug(__func__, "calloc signature failed");
		اذهب باہرلا;
	}
	response->signature_len = 0;

	*enroll_response = response;
	response = عدم;
	ret = 0;
 باہرلا:
	إذا (response != عدم) {
		حرر(response->عوامی_کلید);
		حرر(response->کلید_handle);
		حرر(response->signature);
		حرر(response->attestation_cert);
		حرر(response);
	}
	أرجع ret;
}

ساكن فراغ
dump(ثابت حرف *preamble, ثابت فراغ *sv, ناپ_t l)
{
#جے_تعریف_شدہ SK_DEBUG
	ثابت u_char *s = (ثابت u_char *)sv;
	ناپ_t i;

	fprintf(stderr, "%s (len %zu):\n", preamble, l);
	لكل (i = 0; i < l; i++) {
		إذا (i % 16 == 0)
			fprintf(stderr, "%04zu: ", i);
		fprintf(stderr, "%02x", s[i]);
		إذا (i % 16 == 15 || i == l - 1)
			fprintf(stderr, "\n");
	}
#جے_انت
}

ساكن صحيح
sig_ecdsa(ثابت uint8_t *سنیہا, ناپ_t سنیہا_len,
    ثابت حرف *application, uint32_t counter, uint8_t flags,
    ثابت uint8_t *کلید_handle, ناپ_t کلید_handle_len,
    بنية sk_sign_response *response)
{
#جے_تعریف_شدہ WITH_OPENSSL
	ECDSA_SIG *sig = عدم;
	ثابت BIGNUM *sig_r, *sig_s;
	صحيح ret = -1;
	BIO *bio = عدم;
	EVP_PKEY *pk = عدم;
	EC_کلید *ec = عدم;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_لمائی];
	uint8_t	sighash[SHA256_DIGEST_لمائی];
	uint8_t countbuf[4];

	/* Decode EC_KEY from key handle */
	إذا ((bio = BIO_new(BIO_s_mem())) == عدم ||
	    BIO_write(bio, کلید_handle, کلید_handle_len) != (صحيح)کلید_handle_len) {
		skdebug(__func__, "BIO setup failed");
		اذهب باہرلا;
	}
	إذا ((pk = PEM_read_bio_نجی_کلید(bio, عدم, عدم, "")) == عدم) {
		skdebug(__func__, "PEM_read_bio_PrivateKey failed");
		اذهب باہرلا;
	}
	إذا (EVP_PKEY_ادھار_id(pk) != EVP_PKEY_EC) {
		skdebug(__func__, "Not an EC key: %d", EVP_PKEY_ادھار_id(pk));
		اذهب باہرلا;
	}
	إذا ((ec = EVP_PKEY_get1_EC_کلید(pk)) == عدم) {
		skdebug(__func__, "EVP_PKEY_get1_EC_KEY failed");
		اذهب باہرلا;
	}
	/* Expect message to be pre-hashed */
	إذا (سنیہا_len != SHA256_DIGEST_لمائی) {
		skdebug(__func__, "bad message len %zu", سنیہا_len);
		اذهب باہرلا;
	}
	/* Prepare data to be signed */
	dump("message", سنیہا, سنیہا_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ثابت u_char *)application, لڑی_لمبائی(application));
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
	SHA256Update(&ctx, سنیہا, سنیہا_len);
	SHA256Final(sighash, &ctx);
	dump("sighash", sighash, حجم(sighash));
	/* create and encode signature */
	إذا ((sig = ECDSA_do_sign(sighash, حجم(sighash), ec)) == عدم) {
		skdebug(__func__, "ECDSA_do_sign failed");
		اذهب باہرلا;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_عدد_بائٹاں(sig_r);
	response->sig_s_len = BN_عدد_بائٹاں(sig_s);
	إذا ((response->sig_r = صفر_حافظہ_دیو(1, response->sig_r_len)) == عدم ||
	    (response->sig_s = صفر_حافظہ_دیو(1, response->sig_s_len)) == عدم) {
		skdebug(__func__, "calloc signature failed");
		اذهب باہرلا;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 باہرلا:
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
#جے_انت
}

ساكن صحيح
sig_ed25519(ثابت uint8_t *سنیہا, ناپ_t سنیہا_len,
    ثابت حرف *application, uint32_t counter, uint8_t flags,
    ثابت uint8_t *کلید_handle, ناپ_t کلید_handle_len,
    بنية sk_sign_response *response)
{
	ناپ_t o;
	صحيح ret = -1;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_لمائی];
	uint8_t signbuf[حجم(apphash) + حجم(flags) +
	    حجم(counter) + SHA256_DIGEST_لمائی];
	uint8_t sig[crypto_sign_ed25519_بائٹاں];
	بنانشانی لما لما siglen = 0;

	إذا (کلید_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		skdebug(__func__, "bad key handle length %zu", کلید_handle_len);
		اذهب باہرلا;
	}
	/* Expect message to be pre-hashed */
	إذا (سنیہا_len != SHA256_DIGEST_لمائی) {
		skdebug(__func__, "bad message len %zu", سنیہا_len);
		اذهب باہرلا;
	}
	/* Prepare data to be signed */
	dump("message", سنیہا, سنیہا_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ثابت u_char *)application, لڑی_لمبائی(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, حجم(apphash));

	حافظہ_نقل(signbuf, apphash, حجم(apphash));
	o = حجم(apphash);
	signbuf[o++] = flags;
	signbuf[o++] = (counter >> 24) & 0xff;
	signbuf[o++] = (counter >> 16) & 0xff;
	signbuf[o++] = (counter >> 8) & 0xff;
	signbuf[o++] = counter & 0xff;
	حافظہ_نقل(signbuf + o, سنیہا, سنیہا_len);
	o += سنیہا_len;
	إذا (o != حجم(signbuf)) {
		skdebug(__func__, "bad sign buf len %zu, expected %zu",
		    o, حجم(signbuf));
		اذهب باہرلا;
	}
	dump("signbuf", signbuf, حجم(signbuf));
	/* create and encode signature */
	إذا (crypto_sign_ed25519_detached(sig, &siglen, signbuf, حجم(signbuf),
	    کلید_handle) != 0) {
		skdebug(__func__, "crypto_sign_ed25519_detached failed");
		اذهب باہرلا;
	}
	إذا (siglen != حجم(sig)) {
		skdebug(__func__, "bad signature length %llu", siglen);
		اذهب باہرلا;
	}
	response->sig_r_len = حجم(sig);
	إذا ((response->sig_r = صفر_حافظہ_دیو(1, response->sig_r_len)) == عدم) {
		skdebug(__func__, "calloc signature failed");
		اذهب باہرلا;
	}
	حافظہ_نقل(response->sig_r, sig, response->sig_r_len);
	dump("sig_r", response->sig_r, response->sig_r_len);
	ret = 0;
 باہرلا:
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
sk_sign(uint32_t alg, ثابت uint8_t *انکڑے, ناپ_t datalen,
    ثابت حرف *application, ثابت uint8_t *کلید_handle, ناپ_t کلید_handle_len,
    uint8_t flags, ثابت حرف *pin, بنية sk_option **options,
    بنية sk_sign_response **sign_response)
{
	بنية sk_sign_response *response = عدم;
	صحيح ret = SSH_SK_ERR_GENERAL;
	SHA2_CTX ctx;
	uint8_t سنیہا[32];

	إذا (sign_response == عدم) {
		skdebug(__func__, "sign_response == NULL");
		اذهب باہرلا;
	}
	*sign_response = عدم;
	إذا (check_options(options) != 0)
		اذهب باہرلا; /* error already logged */
	إذا ((response = صفر_حافظہ_دیو(1, حجم(*response))) == عدم) {
		skdebug(__func__, "calloc response failed");
		اذهب باہرلا;
	}
	SHA256Init(&ctx);
	SHA256Update(&ctx, انکڑے, datalen);
	SHA256Final(سنیہا, &ctx);
	response->flags = flags;
	response->counter = 0x12345678;
	بدل(alg) {
	حالة SSH_SK_ECDSA:
		إذا (sig_ecdsa(سنیہا, حجم(سنیہا), application,
		    response->counter, flags, کلید_handle, کلید_handle_len,
		    response) != 0)
			اذهب باہرلا;
		اكسر;
	حالة SSH_SK_ED25519:
		إذا (sig_ed25519(سنیہا, حجم(سنیہا), application,
		    response->counter, flags, کلید_handle, کلید_handle_len,
		    response) != 0)
			اذهب باہرلا;
		اكسر;
	افتراضي:
		skdebug(__func__, "unsupported key type %d", alg);
		اذهب باہرلا;
	}
	*sign_response = response;
	response = عدم;
	ret = 0;
 باہرلا:
	explicit_bzero(سنیہا, حجم(سنیہا));
	إذا (response != عدم) {
		حرر(response->sig_r);
		حرر(response->sig_s);
		حرر(response);
	}
	أرجع ret;
}

صحيح
sk_لدو_resident_کلیدیں(ثابت حرف *pin, بنية sk_option **options,
    بنية sk_resident_کلید ***rks, ناپ_t *nrks)
{
	أرجع SSH_SK_ERR_UNSUPPORTED;
}
