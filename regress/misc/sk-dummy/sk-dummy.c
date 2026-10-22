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

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
#ضمن <openssl/opensslv.h>
#ضمن <openssl/sha.h>
#ضمن <openssl/crypto.h>
#ضمن <openssl/evp.h>
#ضمن <openssl/bn.h>
#ضمن <openssl/ec.h>
#ضمن <openssl/ecdsa.h>
#ضمن <openssl/pem.h>

/* Use OpenSSL SHA256 instead of libc */
#وصف_ڪريو SHA256Init(x)		SHA256_Init(x)
#وصف_ڪريو SHA256Update(x, y, z)	SHA256_Update(x, y, z)
#وصف_ڪريو SHA256Final(x, y)	SHA256_Final(x, y)
#وصف_ڪريو SHA2_CTX		SHA256_CTX

#وإلاإذا defined(HAVE_SHA2_H)
#ضمن <sha2.h>
#جيڪڏهن_پورو /* WITH_OPENSSL */

/* #define SK_DEBUG 1 */

#إذا SSH_SK_نسخو_MAJOR != 0x000a0000
# error SK API has بدليو, sk-dummy.c needs an update
#جيڪڏهن_پورو

#جيڪڏهن_وصف_ٿيل SK_DUMMY_INTEGRATE
# define sk_api_نسخو		ssh_sk_api_نسخو
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_ڀريو_resident_ڪنجيون	ssh_sk_ڀريو_resident_ڪنجيون
#جيڪڏهن_پورو /* !SK_STANDALONE */

ساكن فراغ skdebug(ثابت حرف *func, ثابت حرف *fmt, ...)
    __attribute__((__format__ (لکو, 2, 3)));

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
#جيڪڏهن_پورو
}

uint32_t
sk_api_نسخو(فراغ)
{
	أرجع SSH_SK_نسخو_MAJOR;
}

ساكن صحيح
pack_ڪنجي_ecdsa(بنية sk_enroll_response *response)
{
#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
	EC_ڪنجي *ڪنجي = عدم;
	ثابت EC_گروهه *g;
	ثابت EC_نقطو *q;
	صحيح ret = -1;
	ڊگهو privlen;
	BIO *bio = عدم;
	حرف *privptr;

	response->عوامي_ڪنجي = عدم;
	response->عوامي_ڪنجي_len = 0;
	response->ڪنجي_handle = عدم;
	response->ڪنجي_handle_len = 0;

	إذا ((ڪنجي = EC_ڪنجي_new_by_وڪر_name(NID_X9_62_prime256v1)) == عدم) {
		skdebug(__func__, "EC_KEY_new_by_curve_name");
		اذهب ٻاهريون;
	}
	إذا (EC_ڪنجي_generate_ڪنجي(ڪنجي) != 1) {
		skdebug(__func__, "EC_KEY_generate_key");
		اذهب ٻاهريون;
	}
	EC_ڪنجي_سيٽ_asn1_flag(ڪنجي, OPENSSL_EC_NAMED_وڪر);
	إذا ((bio = BIO_new(BIO_s_mem())) == عدم ||
	    (g = EC_ڪنجي_get0_گروهه(ڪنجي)) == عدم ||
	    (q = EC_ڪنجي_get0_عوامي_ڪنجي(ڪنجي)) == عدم) {
		skdebug(__func__, "couldn't get key parameters");
		اذهب ٻاهريون;
	}
	response->عوامي_ڪنجي_len = EC_نقطو_point2oct(g, q,
	    نقطو_CONVERSION_UNCOMPRESSED, عدم, 0, عدم);
	إذا (response->عوامي_ڪنجي_len == 0 || response->عوامي_ڪنجي_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->عوامي_ڪنجي_len);
		اذهب ٻاهريون;
	}
	إذا ((response->عوامي_ڪنجي = يادگيري_ڏيو(response->عوامي_ڪنجي_len)) == عدم) {
		skdebug(__func__, "malloc pubkey failed");
		اذهب ٻاهريون;
	}
	إذا (EC_نقطو_point2oct(g, q, نقطو_CONVERSION_UNCOMPRESSED,
	    response->عوامي_ڪنجي, response->عوامي_ڪنجي_len, عدم) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		اذهب ٻاهريون;
	}
	/* Key handle contains PEM encoded private key */
	إذا (!PEM_write_bio_ECPrivate_ڪنجي(bio, ڪنجي, عدم, عدم, 0, عدم, عدم)) {
		skdebug(__func__, "PEM_write_bio_ECPrivateKey failed");
		اذهب ٻاهريون;
	}
	إذا ((privlen = BIO_get_mem_معلومات(bio, &privptr)) <= 0) {
		skdebug(__func__, "BIO_get_mem_data failed");
		اذهب ٻاهريون;
	}
	إذا ((response->ڪنجي_handle = يادگيري_ڏيو(privlen)) == عدم) {
		skdebug(__func__, "malloc key_handle failed");
		اذهب ٻاهريون;
	}
	response->ڪنجي_handle_len = (سائيز_t)privlen;
	يادگيري_نقل(response->ڪنجي_handle, privptr, response->ڪنجي_handle_len);
	/* success */
	ret = 0;
 ٻاهريون:
	إذا (ret != 0) {
		إذا (response->عوامي_ڪنجي != عدم) {
			memset(response->عوامي_ڪنجي, 0,
			    response->عوامي_ڪنجي_len);
			حرر(response->عوامي_ڪنجي);
			response->عوامي_ڪنجي = عدم;
		}
		إذا (response->ڪنجي_handle != عدم) {
			memset(response->ڪنجي_handle, 0,
			    response->ڪنجي_handle_len);
			حرر(response->ڪنجي_handle);
			response->ڪنجي_handle = عدم;
		}
	}
	BIO_free(bio);
	EC_ڪنجي_free(ڪنجي);
	أرجع ret;
#وإلا
	أرجع -1;
#جيڪڏهن_پورو
}

ساكن صحيح
pack_ڪنجي_ed25519(بنية sk_enroll_response *response)
{
	صحيح ret = -1;
	u_char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	u_char sk[crypto_sign_ed25519_SECRETKEYBYTES];

	response->عوامي_ڪنجي = عدم;
	response->عوامي_ڪنجي_len = 0;
	response->ڪنجي_handle = عدم;
	response->ڪنجي_handle_len = 0;

	memset(pk, 0, حجم(pk));
	memset(sk, 0, حجم(sk));
	crypto_sign_ed25519_keypair(pk, sk);

	response->عوامي_ڪنجي_len = حجم(pk);
	إذا ((response->عوامي_ڪنجي = يادگيري_ڏيو(response->عوامي_ڪنجي_len)) == عدم) {
		skdebug(__func__, "malloc pubkey failed");
		اذهب ٻاهريون;
	}
	يادگيري_نقل(response->عوامي_ڪنجي, pk, حجم(pk));
	/* Key handle contains sk */
	response->ڪنجي_handle_len = حجم(sk);
	إذا ((response->ڪنجي_handle = يادگيري_ڏيو(response->ڪنجي_handle_len)) == عدم) {
		skdebug(__func__, "malloc key_handle failed");
		اذهب ٻاهريون;
	}
	يادگيري_نقل(response->ڪنجي_handle, sk, حجم(sk));
	/* success */
	ret = 0;
 ٻاهريون:
	إذا (ret != 0)
		حرر(response->عوامي_ڪنجي);
	أرجع ret;
}

ساكن صحيح
check_options(بنية sk_option **options)
{
	سائيز_t i;

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
sk_enroll(uint32_t alg, ثابت uint8_t *challenge, سائيز_t challenge_len,
    ثابت حرف *application, uint8_t flags, ثابت حرف *pin,
    بنية sk_option **options, بنية sk_enroll_response **enroll_response)
{
	بنية sk_enroll_response *response = عدم;
	صحيح ret = SSH_SK_ERR_GENERAL;

	(فراغ)flags; /* XXX; unused */

	إذا (enroll_response == عدم) {
		skdebug(__func__, "enroll_response == NULL");
		اذهب ٻاهريون;
	}
	*enroll_response = عدم;
	إذا (check_options(options) != 0)
		اذهب ٻاهريون; /* error already logged */
	إذا ((response = صفر_يادگيري_ڏيو(1, حجم(*response))) == عدم) {
		skdebug(__func__, "calloc response failed");
		اذهب ٻاهريون;
	}
	response->flags = flags;
	بدل(alg) {
	حالة SSH_SK_ECDSA:
		إذا (pack_ڪنجي_ecdsa(response) != 0)
			اذهب ٻاهريون;
		اكسر;
	حالة SSH_SK_ED25519:
		إذا (pack_ڪنجي_ed25519(response) != 0)
			اذهب ٻاهريون;
		اكسر;
	افتراضي:
		skdebug(__func__, "unsupported key type %d", alg);
		اذهب ٻاهريون;
	}
	/* Have to return something here */
	إذا ((response->signature = صفر_يادگيري_ڏيو(1, 1)) == عدم) {
		skdebug(__func__, "calloc signature failed");
		اذهب ٻاهريون;
	}
	response->signature_len = 0;

	*enroll_response = response;
	response = عدم;
	ret = 0;
 ٻاهريون:
	إذا (response != عدم) {
		حرر(response->عوامي_ڪنجي);
		حرر(response->ڪنجي_handle);
		حرر(response->signature);
		حرر(response->attestation_cert);
		حرر(response);
	}
	أرجع ret;
}

ساكن فراغ
dump(ثابت حرف *preamble, ثابت فراغ *sv, سائيز_t l)
{
#جيڪڏهن_وصف_ٿيل SK_DEBUG
	ثابت u_char *s = (ثابت u_char *)sv;
	سائيز_t i;

	fprintf(stderr, "%s (len %zu):\n", preamble, l);
	لكل (i = 0; i < l; i++) {
		إذا (i % 16 == 0)
			fprintf(stderr, "%04zu: ", i);
		fprintf(stderr, "%02x", s[i]);
		إذا (i % 16 == 15 || i == l - 1)
			fprintf(stderr, "\n");
	}
#جيڪڏهن_پورو
}

ساكن صحيح
sig_ecdsa(ثابت uint8_t *پيغام, سائيز_t پيغام_len,
    ثابت حرف *application, uint32_t counter, uint8_t flags,
    ثابت uint8_t *ڪنجي_handle, سائيز_t ڪنجي_handle_len,
    بنية sk_sign_response *response)
{
#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
	ECDSA_SIG *sig = عدم;
	ثابت BIGNUM *sig_r, *sig_s;
	صحيح ret = -1;
	BIO *bio = عدم;
	EVP_PKEY *pk = عدم;
	EC_ڪنجي *ec = عدم;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_ڊيگهائي];
	uint8_t	sighash[SHA256_DIGEST_ڊيگهائي];
	uint8_t countbuf[4];

	/* Decode EC_KEY from key handle */
	إذا ((bio = BIO_new(BIO_s_mem())) == عدم ||
	    BIO_write(bio, ڪنجي_handle, ڪنجي_handle_len) != (صحيح)ڪنجي_handle_len) {
		skdebug(__func__, "BIO setup failed");
		اذهب ٻاهريون;
	}
	إذا ((pk = PEM_read_bio_ذاتي_ڪنجي(bio, عدم, عدم, "")) == عدم) {
		skdebug(__func__, "PEM_read_bio_PrivateKey failed");
		اذهب ٻاهريون;
	}
	إذا (EVP_PKEY_بنياد_id(pk) != EVP_PKEY_EC) {
		skdebug(__func__, "Not an EC key: %d", EVP_PKEY_بنياد_id(pk));
		اذهب ٻاهريون;
	}
	إذا ((ec = EVP_PKEY_get1_EC_ڪنجي(pk)) == عدم) {
		skdebug(__func__, "EVP_PKEY_get1_EC_KEY failed");
		اذهب ٻاهريون;
	}
	/* Expect message to be pre-hashed */
	إذا (پيغام_len != SHA256_DIGEST_ڊيگهائي) {
		skdebug(__func__, "bad message len %zu", پيغام_len);
		اذهب ٻاهريون;
	}
	/* Prepare data to be signed */
	dump("message", پيغام, پيغام_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ثابت u_char *)application, لڙي_ڊيگهه(application));
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
	SHA256Update(&ctx, پيغام, پيغام_len);
	SHA256Final(sighash, &ctx);
	dump("sighash", sighash, حجم(sighash));
	/* create and encode signature */
	إذا ((sig = ECDSA_do_sign(sighash, حجم(sighash), ec)) == عدم) {
		skdebug(__func__, "ECDSA_do_sign failed");
		اذهب ٻاهريون;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_انگ_بائيٽون(sig_r);
	response->sig_s_len = BN_انگ_بائيٽون(sig_s);
	إذا ((response->sig_r = صفر_يادگيري_ڏيو(1, response->sig_r_len)) == عدم ||
	    (response->sig_s = صفر_يادگيري_ڏيو(1, response->sig_s_len)) == عدم) {
		skdebug(__func__, "calloc signature failed");
		اذهب ٻاهريون;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 ٻاهريون:
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
	EC_ڪنجي_free(ec);
	EVP_PKEY_free(pk);
	أرجع ret;
#وإلا
	أرجع -1;
#جيڪڏهن_پورو
}

ساكن صحيح
sig_ed25519(ثابت uint8_t *پيغام, سائيز_t پيغام_len,
    ثابت حرف *application, uint32_t counter, uint8_t flags,
    ثابت uint8_t *ڪنجي_handle, سائيز_t ڪنجي_handle_len,
    بنية sk_sign_response *response)
{
	سائيز_t o;
	صحيح ret = -1;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_ڊيگهائي];
	uint8_t signbuf[حجم(apphash) + حجم(flags) +
	    حجم(counter) + SHA256_DIGEST_ڊيگهائي];
	uint8_t sig[crypto_sign_ed25519_بائيٽون];
	بنانشان ڊگهو ڊگهو siglen = 0;

	إذا (ڪنجي_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		skdebug(__func__, "bad key handle length %zu", ڪنجي_handle_len);
		اذهب ٻاهريون;
	}
	/* Expect message to be pre-hashed */
	إذا (پيغام_len != SHA256_DIGEST_ڊيگهائي) {
		skdebug(__func__, "bad message len %zu", پيغام_len);
		اذهب ٻاهريون;
	}
	/* Prepare data to be signed */
	dump("message", پيغام, پيغام_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ثابت u_char *)application, لڙي_ڊيگهه(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, حجم(apphash));

	يادگيري_نقل(signbuf, apphash, حجم(apphash));
	o = حجم(apphash);
	signbuf[o++] = flags;
	signbuf[o++] = (counter >> 24) & 0xff;
	signbuf[o++] = (counter >> 16) & 0xff;
	signbuf[o++] = (counter >> 8) & 0xff;
	signbuf[o++] = counter & 0xff;
	يادگيري_نقل(signbuf + o, پيغام, پيغام_len);
	o += پيغام_len;
	إذا (o != حجم(signbuf)) {
		skdebug(__func__, "bad sign buf len %zu, expected %zu",
		    o, حجم(signbuf));
		اذهب ٻاهريون;
	}
	dump("signbuf", signbuf, حجم(signbuf));
	/* create and encode signature */
	إذا (crypto_sign_ed25519_detached(sig, &siglen, signbuf, حجم(signbuf),
	    ڪنجي_handle) != 0) {
		skdebug(__func__, "crypto_sign_ed25519_detached failed");
		اذهب ٻاهريون;
	}
	إذا (siglen != حجم(sig)) {
		skdebug(__func__, "bad signature length %llu", siglen);
		اذهب ٻاهريون;
	}
	response->sig_r_len = حجم(sig);
	إذا ((response->sig_r = صفر_يادگيري_ڏيو(1, response->sig_r_len)) == عدم) {
		skdebug(__func__, "calloc signature failed");
		اذهب ٻاهريون;
	}
	يادگيري_نقل(response->sig_r, sig, response->sig_r_len);
	dump("sig_r", response->sig_r, response->sig_r_len);
	ret = 0;
 ٻاهريون:
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
sk_sign(uint32_t alg, ثابت uint8_t *معلومات, سائيز_t datalen,
    ثابت حرف *application, ثابت uint8_t *ڪنجي_handle, سائيز_t ڪنجي_handle_len,
    uint8_t flags, ثابت حرف *pin, بنية sk_option **options,
    بنية sk_sign_response **sign_response)
{
	بنية sk_sign_response *response = عدم;
	صحيح ret = SSH_SK_ERR_GENERAL;
	SHA2_CTX ctx;
	uint8_t پيغام[32];

	إذا (sign_response == عدم) {
		skdebug(__func__, "sign_response == NULL");
		اذهب ٻاهريون;
	}
	*sign_response = عدم;
	إذا (check_options(options) != 0)
		اذهب ٻاهريون; /* error already logged */
	إذا ((response = صفر_يادگيري_ڏيو(1, حجم(*response))) == عدم) {
		skdebug(__func__, "calloc response failed");
		اذهب ٻاهريون;
	}
	SHA256Init(&ctx);
	SHA256Update(&ctx, معلومات, datalen);
	SHA256Final(پيغام, &ctx);
	response->flags = flags;
	response->counter = 0x12345678;
	بدل(alg) {
	حالة SSH_SK_ECDSA:
		إذا (sig_ecdsa(پيغام, حجم(پيغام), application,
		    response->counter, flags, ڪنجي_handle, ڪنجي_handle_len,
		    response) != 0)
			اذهب ٻاهريون;
		اكسر;
	حالة SSH_SK_ED25519:
		إذا (sig_ed25519(پيغام, حجم(پيغام), application,
		    response->counter, flags, ڪنجي_handle, ڪنجي_handle_len,
		    response) != 0)
			اذهب ٻاهريون;
		اكسر;
	افتراضي:
		skdebug(__func__, "unsupported key type %d", alg);
		اذهب ٻاهريون;
	}
	*sign_response = response;
	response = عدم;
	ret = 0;
 ٻاهريون:
	explicit_bzero(پيغام, حجم(پيغام));
	إذا (response != عدم) {
		حرر(response->sig_r);
		حرر(response->sig_s);
		حرر(response);
	}
	أرجع ret;
}

صحيح
sk_ڀريو_resident_ڪنجيون(ثابت حرف *pin, بنية sk_option **options,
    بنية sk_resident_ڪنجي ***rks, سائيز_t *nrks)
{
	أرجع SSH_SK_ERR_UNSUPPORTED;
}
