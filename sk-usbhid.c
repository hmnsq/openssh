/* $OpenBSD: sk-usbhid.c,v 1.50 2026/09/15 08:28:26 djm Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl
 * Copyright (c) 2020 Pedro Martelletto
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

#ifdef ENABLE_SK_INTERNAL

#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <stdio.h>
#شامل <stddef.h>
#شامل <stdarg.h>
#شامل <time.h>
#ifdef HAVE_SHA2_H
#شامل <sha2.h>
#endif

#ifdef WITH_OPENSSL
#شامل <openssl/opensslv.h>
#شامل <openssl/crypto.h>
#شامل <openssl/bn.h>
#شامل <openssl/ec.h>
#شامل <openssl/ecdsa.h>
#شامل <openssl/evp.h>
#شامل "openbsd-compat/openssl-compat.h"
#endif /* WITH_OPENSSL */

#شامل <fido.h>
#شامل <fido/credman.h>

/* backwards compat for libfido2 */
#ifndef HAVE_FIDO_CRED_PROT
#define fido_cred_prot(x) (0)
#endif
#ifndef HAVE_FIDO_CRED_SET_PROT
#define fido_cred_set_prot(x, y) (FIDO_ERR_UNSUPPORTED_OPTION)
#endif
#ifndef HAVE_FIDO_DEV_SUPPORTS_CRED_PROT
#define fido_dev_supports_cred_prot(x) (0)
#endif
#ifndef HAVE_FIDO_DEV_GET_TOUCH_BEGIN
#define fido_dev_get_touch_begin(x) (FIDO_ERR_UNSUPPORTED_OPTION)
#endif
#ifndef HAVE_FIDO_DEV_GET_TOUCH_STATUS
#define fido_dev_get_touch_status(x, y, z) (FIDO_ERR_UNSUPPORTED_OPTION)
#endif
#ifndef FIDO_CRED_PROT_UV_REQUIRED
#define FIDO_CRED_PROT_UV_REQUIRED 0
#endif
#ifndef FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID
#define FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID 0
#endif

# include "misc.h"

#ifndef SK_STANDALONE
# include "log.h"
# include "xmalloc.h"
/*
 * If building as part of OpenSSH, then rename exported functions.
 * This must be done before including sk-api.h.
 */
# define sk_api_version		ssh_sk_api_version
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_load_resident_کلیدها	ssh_sk_load_resident_کلیدها
#endif /* !SK_STANDALONE */

#شامل "sk-api.h"

/* #define SK_DEBUG 1 */

#ifdef SK_DEBUG
#define SSH_FIDO_INIT_ARG	FIDO_DEBUG
#وگرنه
#define SSH_FIDO_INIT_ARG	0
#endif

#define MAX_FIDO_DEVICES	8
#define FIDO_POLL_MS		50
#define SELECT_MS		15000
#define POLL_SLEEP_NS		200000000

#ifndef FIDO_ERR_OPERATION_DENIED
#define FIDO_ERR_OPERATION_DENIED 0x27
#endif

ساختار sk_usbhid {
	fido_dev_t *dev;
	نویسه *path;
};

/* Return the version of the middleware API */
uint32_t sk_api_version(تهی);

/* Enroll a U2F key (private key generation) */
صحیح sk_enroll(uint32_t alg, ثابت uint8_t *challenge, size_t challenge_len,
    ثابت نویسه *application, uint8_t flags, ثابت نویسه *pin,
    ساختار sk_option **options, ساختار sk_enroll_response **enroll_response);

/* Sign a challenge */
صحیح sk_sign(uint32_t alg, ثابت uint8_t *data, size_t data_len,
    ثابت نویسه *application, ثابت uint8_t *کلید_handle, size_t کلید_handle_len,
    uint8_t flags, ثابت نویسه *pin, ساختار sk_option **options,
    ساختار sk_sign_response **sign_response);

/* Load resident keys */
صحیح sk_load_resident_کلیدها(ثابت نویسه *pin, ساختار sk_option **options,
    ساختار sk_resident_کلید ***rks, size_t *nrks);

ایستا تهی skdebug(ثابت نویسه *func, ثابت نویسه *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

ایستا تهی
skdebug(ثابت نویسه *func, ثابت نویسه *fmt, ...)
{
#اگر !defined(SK_STANDALONE)
	نویسه *پیام;
	va_list ap;

	va_start(ap, fmt);
	xvasprintf(&پیام, fmt, ap);
	va_end(ap);
	debug("%s: %s", func, پیام);
	آزاد(پیام);
#وگرنهاگر defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#وگرنه
	(تهی)func; /* XXX */
	(تهی)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(تهی)
{
	بازگشت SSH_SK_VERSION_MAJOR;
}

ایستا ساختار sk_usbhid *
sk_open(ثابت نویسه *path)
{
	ساختار sk_usbhid *sk;
	صحیح r;

	اگر (path == پوچ) {
		skdebug(__func__, "path == NULL");
		بازگشت پوچ;
	}
	اگر ((sk = calloc(1, اندازه(*sk))) == پوچ) {
		skdebug(__func__, "calloc sk failed");
		بازگشت پوچ;
	}
	اگر ((sk->path = strdup(path)) == پوچ) {
		skdebug(__func__, "strdup path failed");
		آزاد(sk);
		بازگشت پوچ;
	}
	اگر ((sk->dev = fido_dev_new()) == پوچ) {
		skdebug(__func__, "fido_dev_new failed");
		آزاد(sk->path);
		آزاد(sk);
		بازگشت پوچ;
	}
	اگر ((r = fido_dev_open(sk->dev, sk->path)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_open %s failed: %s", sk->path,
		    fido_strerr(r));
		fido_dev_free(&sk->dev);
		آزاد(sk->path);
		آزاد(sk);
		بازگشت پوچ;
	}
	بازگشت sk;
}

ایستا تهی
sk_close(ساختار sk_usbhid *sk)
{
	اگر (sk == پوچ)
		بازگشت;
	fido_dev_cancel(sk->dev); /* cancel any pending operation */
	fido_dev_close(sk->dev);
	fido_dev_free(&sk->dev);
	آزاد(sk->path);
	آزاد(sk);
}

ایستا ساختار sk_usbhid **
sk_openv(ثابت fido_dev_info_t *devlist, size_t ndevs, size_t *nopen)
{
	ثابت fido_dev_info_t *di;
	ساختار sk_usbhid **skv;
	size_t i;

	*nopen = 0;
	اگر ((skv = calloc(ndevs, اندازه(*skv))) == پوچ) {
		skdebug(__func__, "calloc skv failed");
		بازگشت پوچ;
	}
	برای (i = 0; i < ndevs; i++) {
		اگر ((di = fido_dev_info_ptr(devlist, i)) == پوچ)
			skdebug(__func__, "fido_dev_info_ptr failed");
		وگرنه اگر ((skv[*nopen] = sk_open(fido_dev_info_path(di))) == پوچ)
			skdebug(__func__, "sk_open failed");
		وگرنه
			(*nopen)++;
	}
	اگر (*nopen == 0) {
		برای (i = 0; i < ndevs; i++)
			sk_close(skv[i]);
		آزاد(skv);
		skv = پوچ;
	}

	بازگشت skv;
}

ایستا تهی
sk_closev(ساختار sk_usbhid **skv, size_t nsk)
{
	size_t i;

	برای (i = 0; i < nsk; i++)
		sk_close(skv[i]);
	آزاد(skv);
}

ایستا صحیح
sk_touch_begin(ساختار sk_usbhid **skv, size_t nsk)
{
	size_t i, ok = 0;
	صحیح r;

	برای (i = 0; i < nsk; i++)
		اگر ((r = fido_dev_get_touch_begin(skv[i]->dev)) != FIDO_OK)
			skdebug(__func__, "fido_dev_get_touch_begin %s failed:"
			    " %s", skv[i]->path, fido_strerr(r));
		وگرنه
			ok++;

	بازگشت ok ? 0 : -1;
}

ایستا صحیح
sk_touch_poll(ساختار sk_usbhid **skv, size_t nsk, صحیح *touch, size_t *idx)
{
	ساختار timespec ts_pause;
	size_t npoll, i;
	صحیح r;

	ts_pause.tv_sec = 0;
	ts_pause.tv_nsec = POLL_SLEEP_NS;
	nanosleep(&ts_pause, پوچ);
	npoll = nsk;
	برای (i = 0; i < nsk; i++) {
		اگر (skv[i] == پوچ)
			ادامه; /* device discarded */
		skdebug(__func__, "polling %s", skv[i]->path);
		اگر ((r = fido_dev_get_touch_status(skv[i]->dev, touch,
		    FIDO_POLL_MS)) != FIDO_OK) {
			skdebug(__func__, "fido_dev_get_touch_status %s: %s",
			    skv[i]->path, fido_strerr(r));
			sk_close(skv[i]); /* discard device */
			skv[i] = پوچ;
			اگر (--npoll == 0) {
				skdebug(__func__, "no device left to poll");
				بازگشت -1;
			}
		} وگرنه اگر (*touch) {
			*idx = i;
			بازگشت 0;
		}
	}
	*touch = 0;
	بازگشت 0;
}

#اگر !defined(HAVE_FIDO_ASSERT_SET_CLIENTDATA) || \
    !defined(HAVE_FIDO_CRED_SET_CLIENTDATA)
/* Calculate SHA256(m) */
ایستا صحیح
sha256_mem(ثابت تهی *m, size_t mlen, u_char *d, size_t dlen)
{
#ifdef WITH_OPENSSL
	u_int mdlen;
#وگرنه
	SHA2_CTX ctx;
#endif

	اگر (dlen != 32)
		بازگشت -1;
#ifdef WITH_OPENSSL
	mdlen = dlen;
	اگر (!EVP_Digest(m, mlen, d, &mdlen, EVP_sha256(), پوچ))
		بازگشت -1;
#وگرنه
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ثابت uint8_t *)m, mlen);
	SHA256Final(d, &ctx);
#endif
	بازگشت 0;
}
#endif /* !HAVE_FIDO_ASSERT_SET_CLIENTDATA || !HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_CRED_SET_CLIENTDATA
ایستا صحیح
fido_cred_set_clientdata(fido_cred_t *cred, ثابت u_char *ptr, size_t len)
{
	uint8_t d[32];
	صحیح r;

	اگر (sha256_mem(ptr, len, d, اندازه(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		بازگشت FIDO_ERR_INTERNAL;
	}
	r = fido_cred_set_clientdata_hash(cred, d, اندازه(d));
	explicit_bzero(d, اندازه(d));
	اگر (r != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	بازگشت r;
}
#endif /* HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_ASSERT_SET_CLIENTDATA
ایستا صحیح
fido_assert_set_clientdata(fido_assert_t *أكد, ثابت u_char *ptr, size_t len)
{
	uint8_t d[32];
	صحیح r;

	اگر (sha256_mem(ptr, len, d, اندازه(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		بازگشت FIDO_ERR_INTERNAL;
	}
	r = fido_assert_set_clientdata_hash(أكد, d, اندازه(d));
	explicit_bzero(d, اندازه(d));
	اگر (r != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	بازگشت r;
}
#endif /* HAVE_FIDO_ASSERT_SET_CLIENTDATA */

#ifndef HAVE_FIDO_DEV_IS_WINHELLO
ایستا bool
fido_dev_is_winhello(ثابت fido_dev_t *fdev)
{
	بازگشت 0;
}
#endif /* HAVE_FIDO_DEV_IS_WINHELLO */

/* Check if the specified key handle exists on a given sk. */
ایستا صحیح
sk_try(ثابت ساختار sk_usbhid *sk, ثابت نویسه *application,
    ثابت uint8_t *کلید_handle, size_t کلید_handle_len)
{
	fido_assert_t *أكد = پوچ;
	صحیح r = FIDO_ERR_INTERNAL;
	uint8_t message[32];

	memset(message, '\0', اندازه(message));
	اگر ((أكد = fido_assert_new()) == پوچ) {
		skdebug(__func__, "fido_assert_new failed");
		برو out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	اگر ((r = fido_assert_set_clientdata(أكد, message,
	    اندازه(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		برو out;
	}
	اگر ((r = fido_assert_set_rp(أكد, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		برو out;
	}
	اگر ((r = fido_assert_allow_cred(أكد, کلید_handle,
	    کلید_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		برو out;
	}
	اگر ((r = fido_assert_set_up(أكد, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_up: %s", fido_strerr(r));
		برو out;
	}
	r = fido_dev_get_assert(sk->dev, أكد, پوچ);
	skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
	اگر (r == FIDO_ERR_USER_PRESENCE_REQUIRED) {
		/* U2F tokens may return this */
		r = FIDO_OK;
	}
 out:
	fido_assert_free(&أكد);

	بازگشت r != FIDO_OK ? -1 : 0;
}

ایستا صحیح
check_sk_options(fido_dev_t *dev, ثابت نویسه *opt, صحیح *ret)
{
	fido_cbor_info_t *info;
	نویسه * ثابت *name;
	ثابت bool *مقدار;
	size_t len, i;
	صحیح r;

	*ret = -1;

	اگر (!fido_dev_is_fido2(dev)) {
		skdebug(__func__, "device is not fido2");
		بازگشت 0;
	}
	اگر ((info = fido_cbor_info_new()) == پوچ) {
		skdebug(__func__, "fido_cbor_info_new failed");
		بازگشت -1;
	}
	اگر ((r = fido_dev_get_cbor_info(dev, info)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_cbor_info: %s", fido_strerr(r));
		fido_cbor_info_free(&info);
		بازگشت -1;
	}
	name = fido_cbor_info_options_name_ptr(info);
	مقدار = fido_cbor_info_options_مقدار_ptr(info);
	len = fido_cbor_info_options_len(info);
	برای (i = 0; i < len; i++) {
		اگر (!strcmp(name[i], opt)) {
			*ret = مقدار[i];
			بشکن;
		}
	}
	fido_cbor_info_free(&info);
	اگر (*ret == -1)
		skdebug(__func__, "option %s is unknown", opt);
	وگرنه
		skdebug(__func__, "option %s is %s", opt, *ret ? "on" : "off");

	بازگشت 0;
}

ایستا ساختار sk_usbhid *
sk_select_by_cred(ثابت fido_dev_info_t *devlist, size_t ndevs,
    ثابت نویسه *application, ثابت uint8_t *کلید_handle, size_t کلید_handle_len)
{
	ساختار sk_usbhid **skv, *sk;
	size_t skvcnt, i;
	صحیح internal_uv;

	اگر ((skv = sk_openv(devlist, ndevs, &skvcnt)) == پوچ) {
		skdebug(__func__, "sk_openv failed");
		بازگشت پوچ;
	}
	اگر (skvcnt == 1 && check_sk_options(skv[0]->dev, "uv",
	    &internal_uv) == 0 && internal_uv != -1) {
		sk = skv[0];
		skv[0] = پوچ;
		برو out;
	}
	sk = پوچ;
	برای (i = 0; i < skvcnt; i++) {
		اگر (sk_try(skv[i], application, کلید_handle,
		    کلید_handle_len) == 0) {
			sk = skv[i];
			skv[i] = پوچ;
			skdebug(__func__, "found key in %s", sk->path);
			بشکن;
		}
	}
 out:
	sk_closev(skv, skvcnt);
	بازگشت sk;
}

ایستا ساختار sk_usbhid *
sk_select_by_touch(ثابت fido_dev_info_t *devlist, size_t ndevs)
{
	ساختار sk_usbhid **skv, *sk;
	ساختار timeval tv_start, tv_now, tv_delta;
	size_t skvcnt, idx;
	صحیح touch, ms_remain;

	اگر ((skv = sk_openv(devlist, ndevs, &skvcnt)) == پوچ) {
		skdebug(__func__, "sk_openv failed");
		بازگشت پوچ;
	}
	sk = پوچ;
	اگر (skvcnt < 2) {
		اگر (skvcnt == 1) {
			/* single candidate */
			sk = skv[0];
			skv[0] = پوچ;
		}
		برو out;
	}
#ifndef HAVE_FIDO_DEV_GET_TOUCH_STATUS
	skdebug(__func__, "libfido2 version does not support a feature needed for multiple tokens. Please upgrade to >=1.5.0");
	برو out;
#endif

	اگر (sk_touch_begin(skv, skvcnt) == -1) {
		skdebug(__func__, "sk_touch_begin failed");
		برو out;
	}
	monotime_tv(&tv_start);
	انجامبده {
		اگر (sk_touch_poll(skv, skvcnt, &touch, &idx) == -1) {
			skdebug(__func__, "sk_touch_poll failed");
			برو out;
		}
		اگر (touch) {
			sk = skv[idx];
			skv[idx] = پوچ;
			برو out;
		}
		monotime_tv(&tv_now);
		timersub(&tv_now, &tv_start, &tv_delta);
		ms_remain = SELECT_MS - tv_delta.tv_sec * 1000 -
		    tv_delta.tv_usec / 1000;
	} وقتی (ms_remain >= FIDO_POLL_MS);
	skdebug(__func__, "timeout");
out:
	sk_closev(skv, skvcnt);
	بازگشت sk;
}

ایستا ساختار sk_usbhid *
sk_probe(ثابت نویسه *application, ثابت uint8_t *کلید_handle,
    size_t کلید_handle_len, صحیح probe_resident)
{
	ساختار sk_usbhid *sk;
	fido_dev_info_t *devlist;
	size_t ndevs;
	صحیح r;

#ifdef HAVE_CYGWIN
	اگر (!probe_resident && (sk = sk_open("windows://hello")) != پوچ)
		بازگشت sk;
#endif /* HAVE_CYGWIN */
	اگر ((devlist = fido_dev_info_new(MAX_FIDO_DEVICES)) == پوچ) {
		skdebug(__func__, "fido_dev_info_new failed");
		بازگشت پوچ;
	}
	اگر ((r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES,
	    &ndevs)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_info_manifest failed: %s",
		    fido_strerr(r));
		fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
		بازگشت پوچ;
	}
	skdebug(__func__, "%zu device(s) detected", ndevs);
	اگر (ndevs == 0) {
		sk = پوچ;
	} وگرنه اگر (application != پوچ && کلید_handle != پوچ) {
		skdebug(__func__, "selecting sk by cred");
		sk = sk_select_by_cred(devlist, ndevs, application, کلید_handle,
		    کلید_handle_len);
	} وگرنه {
		skdebug(__func__, "selecting sk by touch");
		sk = sk_select_by_touch(devlist, ndevs);
	}
	fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
	بازگشت sk;
}

#ifdef WITH_OPENSSL
/*
 * The key returned via fido_cred_pubkey_ptr() is in affine coordinates,
 * but the API expects a SEC1 octet string.
 */
ایستا صحیح
pack_public_کلید_ecdsa(ثابت fido_cred_t *cred,
    ساختار sk_enroll_response *response)
{
	ثابت uint8_t *ptr;
	BIGNUM *x = پوچ, *y = پوچ;
	EC_POINT *q = پوچ;
	EC_GROUP *g = پوچ;
	صحیح ret = -1;

	response->public_کلید = پوچ;
	response->public_کلید_len = 0;

	اگر ((x = BN_new()) == پوچ ||
	    (y = BN_new()) == پوچ ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == پوچ ||
	    (q = EC_POINT_new(g)) == پوچ) {
		skdebug(__func__, "libcrypto setup failed");
		برو out;
	}
	اگر ((ptr = fido_cred_pubkey_ptr(cred)) == پوچ) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		برو out;
	}
	اگر (fido_cred_pubkey_len(cred) != 64) {
		skdebug(__func__, "bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		برو out;
	}

	اگر (BN_bin2bn(ptr, 32, x) == پوچ ||
	    BN_bin2bn(ptr + 32, 32, y) == پوچ) {
		skdebug(__func__, "BN_bin2bn failed");
		برو out;
	}
	اگر (EC_POINT_set_affine_coordinates(g, q, x, y, پوچ) != 1) {
		skdebug(__func__, "EC_POINT_set_affine_coordinates failed");
		برو out;
	}
	response->public_کلید_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, پوچ, 0, پوچ);
	اگر (response->public_کلید_len == 0 || response->public_کلید_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_کلید_len);
		برو out;
	}
	اگر ((response->public_کلید = malloc(response->public_کلید_len)) == پوچ) {
		skdebug(__func__, "malloc pubkey failed");
		برو out;
	}
	اگر (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_کلید, response->public_کلید_len, پوچ) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		برو out;
	}
	/* success */
	ret = 0;
 out:
	اگر (ret != 0 && response->public_کلید != پوچ) {
		memset(response->public_کلید, 0, response->public_کلید_len);
		آزاد(response->public_کلید);
		response->public_کلید = پوچ;
	}
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	بازگشت ret;
}
#endif /* WITH_OPENSSL */

ایستا صحیح
pack_public_کلید_ed25519(ثابت fido_cred_t *cred,
    ساختار sk_enroll_response *response)
{
	ثابت uint8_t *ptr;
	size_t len;
	صحیح ret = -1;

	response->public_کلید = پوچ;
	response->public_کلید_len = 0;

	اگر ((len = fido_cred_pubkey_len(cred)) != 32) {
		skdebug(__func__, "bad fido_cred_pubkey_len len %zu", len);
		برو out;
	}
	اگر ((ptr = fido_cred_pubkey_ptr(cred)) == پوچ) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		برو out;
	}
	response->public_کلید_len = len;
	اگر ((response->public_کلید = malloc(response->public_کلید_len)) == پوچ) {
		skdebug(__func__, "malloc pubkey failed");
		برو out;
	}
	memcpy(response->public_کلید, ptr, len);
	ret = 0;
 out:
	اگر (ret != 0)
		آزاد(response->public_کلید);
	بازگشت ret;
}

ایستا صحیح
pack_public_کلید(uint32_t alg, ثابت fido_cred_t *cred,
    ساختار sk_enroll_response *response)
{
	انتخاب(alg) {
#ifdef WITH_OPENSSL
	حالت SSH_SK_ECDSA:
		بازگشت pack_public_کلید_ecdsa(cred, response);
#endif /* WITH_OPENSSL */
	حالت SSH_SK_ED25519:
		بازگشت pack_public_کلید_ed25519(cred, response);
	پیشفرض:
		بازگشت -1;
	}
}

ایستا صحیح
fidoerr_to_skerr(صحیح fidoerr)
{
	انتخاب (fidoerr) {
	حالت FIDO_ERR_UNSUPPORTED_OPTION:
	حالت FIDO_ERR_UNSUPPORTED_ALGORITHM:
		بازگشت SSH_SK_ERR_UNSUPPORTED;
	حالت FIDO_ERR_PIN_REQUIRED:
	حالت FIDO_ERR_PIN_INVALID:
	حالت FIDO_ERR_OPERATION_DENIED:
		بازگشت SSH_SK_ERR_PIN_REQUIRED;
	پیشفرض:
		بازگشت -1;
	}
}

ایستا صحیح
check_enroll_options(ساختار sk_option **options, نویسه **devicep,
    uint8_t *user_id, size_t user_id_len)
{
	size_t i;

	اگر (options == پوچ)
		بازگشت 0;
	برای (i = 0; options[i] != پوچ; i++) {
		اگر (strcmp(options[i]->name, "device") == 0) {
			اگر ((*devicep = strdup(options[i]->مقدار)) == پوچ) {
				skdebug(__func__, "strdup device failed");
				بازگشت -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} وگرنه اگر (strcmp(options[i]->name, "user") == 0) {
			اگر (strlcpy(user_id, options[i]->مقدار, user_id_len) >=
			    user_id_len) {
				skdebug(__func__, "user too long");
				بازگشت -1;
			}
			skdebug(__func__, "requested user %s",
			    (نویسه *)user_id);
		} وگرنه {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			اگر (options[i]->required) {
				skdebug(__func__, "unknown required option");
				بازگشت -1;
			}
		}
	}
	بازگشت 0;
}

ایستا صحیح
کلید_lookup(fido_dev_t *dev, ثابت نویسه *application, ثابت uint8_t *user_id,
    size_t user_id_len, ثابت نویسه *pin)
{
	fido_assert_t *أكد = پوچ;
	uint8_t message[32];
	صحیح r = FIDO_ERR_INTERNAL;
	صحیح sk_supports_uv, uv;
	size_t i;

	memset(message, '\0', اندازه(message));
	اگر ((أكد = fido_assert_new()) == پوچ) {
		skdebug(__func__, "fido_assert_new failed");
		برو out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	اگر ((r = fido_assert_set_clientdata(أكد, message,
	    اندازه(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		برو out;
	}
	اگر ((r = fido_assert_set_rp(أكد, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		برو out;
	}
	اگر ((r = fido_assert_set_up(أكد, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		برو out;
	}
	uv = FIDO_OPT_OMIT;
	اگر (pin == پوچ && check_sk_options(dev, "uv", &sk_supports_uv) == 0 &&
	    sk_supports_uv != -1)
		uv = FIDO_OPT_TRUE;
	اگر ((r = fido_assert_set_uv(أكد, uv)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
		برو out;
	}
	اگر ((r = fido_dev_get_assert(dev, أكد, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		برو out;
	}
	r = FIDO_ERR_NO_CREDENTIALS;
	skdebug(__func__, "%zu signatures returned", fido_assert_شمار(أكد));
	برای (i = 0; i < fido_assert_شمار(أكد); i++) {
		اگر (fido_assert_user_id_len(أكد, i) == user_id_len &&
		    memcmp(fido_assert_user_id_ptr(أكد, i), user_id,
		    user_id_len) == 0) {
			skdebug(__func__, "credential exists");
			r = FIDO_OK;
			برو out;
		}
	}
 out:
	fido_assert_free(&أكد);

	بازگشت r;
}

صحیح
sk_enroll(uint32_t alg, ثابت uint8_t *challenge, size_t challenge_len,
    ثابت نویسه *application, uint8_t flags, ثابت نویسه *pin,
    ساختار sk_option **options, ساختار sk_enroll_response **enroll_response)
{
	fido_cred_t *cred = پوچ;
	ثابت uint8_t *ptr;
	uint8_t user_id[32];
	ساختار sk_usbhid *sk = پوچ;
	ساختار sk_enroll_response *response = پوچ;
	size_t len;
	صحیح credprot;
	صحیح cose_alg;
	صحیح ret = SSH_SK_ERR_GENERAL;
	صحیح r;
	نویسه *device = پوچ;

	fido_init(SSH_FIDO_INIT_ARG);

	اگر (enroll_response == پوچ) {
		skdebug(__func__, "enroll_response == NULL");
		برو out;
	}
	*enroll_response = پوچ;
	memset(user_id, 0, اندازه(user_id));
	اگر (check_enroll_options(options, &device, user_id,
	    اندازه(user_id)) != 0)
		برو out; /* error already logged */

	انتخاب(alg) {
#ifdef WITH_OPENSSL
	حالت SSH_SK_ECDSA:
		cose_alg = COSE_ES256;
		بشکن;
#endif /* WITH_OPENSSL */
	حالت SSH_SK_ED25519:
		cose_alg = COSE_EDDSA;
		بشکن;
	پیشفرض:
		skdebug(__func__, "unsupported key type %d", alg);
		برو out;
	}
	اگر (device != پوچ)
		sk = sk_open(device);
	وگرنه
		sk = sk_probe(پوچ, پوچ, 0, 0);
	اگر (sk == پوچ) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		برو out;
	}
	skdebug(__func__, "using device %s", sk->path);
	اگر ((flags & SSH_SK_RESIDENT_کلید) != 0 &&
	    (flags & SSH_SK_FORCE_OPERATION) == 0 &&
	    (r = کلید_lookup(sk->dev, application, user_id, اندازه(user_id),
	    pin)) != FIDO_ERR_NO_CREDENTIALS) {
		اگر (r != FIDO_OK) {
			ret = fidoerr_to_skerr(r);
			skdebug(__func__, "key_lookup failed");
		} وگرنه {
			ret = SSH_SK_ERR_CREDENTIAL_EXISTS;
			skdebug(__func__, "key exists");
		}
		برو out;
	}
	اگر ((cred = fido_cred_new()) == پوچ) {
		skdebug(__func__, "fido_cred_new failed");
		برو out;
	}
	اگر ((r = fido_cred_set_type(cred, cose_alg)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_type: %s", fido_strerr(r));
		برو out;
	}
	اگر ((r = fido_cred_set_clientdata(cred,
	    challenge, challenge_len)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata: %s",
		    fido_strerr(r));
		برو out;
	}
	اگر ((r = fido_cred_set_rk(cred, (flags & SSH_SK_RESIDENT_کلید) != 0 ?
	    FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rk: %s", fido_strerr(r));
		برو out;
	}
	اگر ((r = fido_cred_set_user(cred, user_id, اندازه(user_id),
	    "openssh", "openssh", پوچ)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_user: %s", fido_strerr(r));
		برو out;
	}
	اگر ((r = fido_cred_set_rp(cred, application, پوچ)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rp: %s", fido_strerr(r));
		برو out;
	}
	اگر ((flags & (SSH_SK_RESIDENT_کلید|SSH_SK_USER_VERIFICATION_REQD)) != 0) {
#اگر !defined(HAVE_FIDO_DEV_SUPPORTS_CRED_PROT) || \
    !defined(HAVE_FIDO_CRED_SET_PROT)
		skdebug(__func__, "libfido2 version does not support a feature required for this operation. Please upgrade to >=1.5.0");
		ret = SSH_SK_ERR_UNSUPPORTED;
		برو out;
		credprot = 0; (تهی)credprot; /* avoid warning */
#endif
		اگر (!fido_dev_supports_cred_prot(sk->dev)) {
			skdebug(__func__, "%s does not support credprot, "
			    "refusing to create unprotected "
			    "resident/verify-required key", sk->path);
			ret = SSH_SK_ERR_UNSUPPORTED;
			برو out;
		}
		اگر ((flags & SSH_SK_USER_VERIFICATION_REQD))
			credprot = FIDO_CRED_PROT_UV_REQUIRED;
		وگرنه
			credprot = FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID;

		اگر ((r = fido_cred_set_prot(cred, credprot)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_set_prot: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			برو out;
		}
	}
	اگر ((r = fido_dev_make_cred(sk->dev, cred, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_make_cred: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		برو out;
	}
	اگر (fido_cred_x5c_ptr(cred) != پوچ) {
		اگر ((r = fido_cred_verify(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify: %s",
			    fido_strerr(r));
			برو out;
		}
	} وگرنه اگر (strcmp(fido_cred_fmt(cred), "none") != 0) {
		skdebug(__func__, "self-attested credential");
		اگر ((r = fido_cred_verify_self(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify_self: %s",
			    fido_strerr(r));
			برو out;
		}
	} وگرنه {
		skdebug(__func__, "no attestation data");
	}
	اگر ((response = calloc(1, اندازه(*response))) == پوچ) {
		skdebug(__func__, "calloc response failed");
		برو out;
	}
	response->flags = flags;
	اگر (pack_public_کلید(alg, cred, response) != 0) {
		skdebug(__func__, "pack_public_key failed");
		برو out;
	}
	اگر ((ptr = fido_cred_id_ptr(cred)) != پوچ) {
		len = fido_cred_id_len(cred);
		اگر ((response->کلید_handle = calloc(1, len)) == پوچ) {
			skdebug(__func__, "calloc key handle failed");
			برو out;
		}
		memcpy(response->کلید_handle, ptr, len);
		response->کلید_handle_len = len;
	}
	اگر ((ptr = fido_cred_sig_ptr(cred)) != پوچ) {
		len = fido_cred_sig_len(cred);
		اگر ((response->signature = calloc(1, len)) == پوچ) {
			skdebug(__func__, "calloc signature failed");
			برو out;
		}
		memcpy(response->signature, ptr, len);
		response->signature_len = len;
	}
	اگر ((ptr = fido_cred_x5c_ptr(cred)) != پوچ) {
		len = fido_cred_x5c_len(cred);
		skdebug(__func__, "attestation cert len=%zu", len);
		اگر ((response->attestation_cert = calloc(1, len)) == پوچ) {
			skdebug(__func__, "calloc attestation cert failed");
			برو out;
		}
		memcpy(response->attestation_cert, ptr, len);
		response->attestation_cert_len = len;
	}
	اگر ((ptr = fido_cred_authdata_ptr(cred)) != پوچ) {
		len = fido_cred_authdata_len(cred);
		skdebug(__func__, "authdata len=%zu", len);
		اگر ((response->authdata = calloc(1, len)) == پوچ) {
			skdebug(__func__, "calloc authdata failed");
			برو out;
		}
		memcpy(response->authdata, ptr, len);
		response->authdata_len = len;
	}
	*enroll_response = response;
	response = پوچ;
	ret = 0;
 out:
	آزاد(device);
	اگر (response != پوچ) {
		آزاد(response->public_کلید);
		آزاد(response->کلید_handle);
		آزاد(response->signature);
		آزاد(response->attestation_cert);
		آزاد(response->authdata);
		آزاد(response);
	}
	sk_close(sk);
	fido_cred_free(&cred);
	بازگشت ret;
}

#ifdef WITH_OPENSSL
ایستا صحیح
pack_sig_ecdsa(fido_assert_t *أكد, ساختار sk_sign_response *response)
{
	ECDSA_SIG *sig = پوچ;
	ثابت BIGNUM *sig_r, *sig_s;
	ثابت unsigned نویسه *cp;
	size_t sig_len;
	صحیح ret = -1;

	cp = fido_assert_sig_ptr(أكد, 0);
	sig_len = fido_assert_sig_len(أكد, 0);
	اگر ((sig = d2i_ECDSA_SIG(پوچ, &cp, sig_len)) == پوچ) {
		skdebug(__func__, "d2i_ECDSA_SIG failed");
		برو out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_رقم_bytes(sig_r);
	response->sig_s_len = BN_رقم_bytes(sig_s);
	اگر ((response->sig_r = calloc(1, response->sig_r_len)) == پوچ ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == پوچ) {
		skdebug(__func__, "calloc signature failed");
		برو out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	ECDSA_SIG_free(sig);
	اگر (ret != 0) {
		آزاد(response->sig_r);
		آزاد(response->sig_s);
		response->sig_r = پوچ;
		response->sig_s = پوچ;
	}
	بازگشت ret;
}
#endif /* WITH_OPENSSL */

ایستا صحیح
pack_sig_ed25519(fido_assert_t *أكد, ساختار sk_sign_response *response)
{
	ثابت unsigned نویسه *ptr;
	size_t len;
	صحیح ret = -1;

	ptr = fido_assert_sig_ptr(أكد, 0);
	len = fido_assert_sig_len(أكد, 0);
	اگر (len != 64) {
		skdebug(__func__, "bad length %zu", len);
		برو out;
	}
	response->sig_r_len = len;
	اگر ((response->sig_r = calloc(1, response->sig_r_len)) == پوچ) {
		skdebug(__func__, "calloc signature failed");
		برو out;
	}
	memcpy(response->sig_r, ptr, len);
	ret = 0;
 out:
	اگر (ret != 0) {
		آزاد(response->sig_r);
		response->sig_r = پوچ;
	}
	بازگشت ret;
}

ایستا صحیح
pack_sig(uint32_t  alg, fido_assert_t *أكد,
    ساختار sk_sign_response *response)
{
	انتخاب(alg) {
#ifdef WITH_OPENSSL
	حالت SSH_SK_ECDSA:
		بازگشت pack_sig_ecdsa(أكد, response);
#endif /* WITH_OPENSSL */
	حالت SSH_SK_ED25519:
		بازگشت pack_sig_ed25519(أكد, response);
	پیشفرض:
		بازگشت -1;
	}
}

/* Checks sk_options for sk_sign() and sk_load_resident_keys() */
ایستا صحیح
check_sign_load_resident_options(ساختار sk_option **options, نویسه **devicep)
{
	size_t i;

	اگر (options == پوچ)
		بازگشت 0;
	برای (i = 0; options[i] != پوچ; i++) {
		اگر (strcmp(options[i]->name, "device") == 0) {
			اگر ((*devicep = strdup(options[i]->مقدار)) == پوچ) {
				skdebug(__func__, "strdup device failed");
				بازگشت -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} وگرنه {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			اگر (options[i]->required) {
				skdebug(__func__, "unknown required option");
				بازگشت -1;
			}
		}
	}
	بازگشت 0;
}

صحیح
sk_sign(uint32_t alg, ثابت uint8_t *data, size_t datalen,
    ثابت نویسه *application,
    ثابت uint8_t *کلید_handle, size_t کلید_handle_len,
    uint8_t flags, ثابت نویسه *pin, ساختار sk_option **options,
    ساختار sk_sign_response **sign_response)
{
	fido_assert_t *أكد = پوچ;
	نویسه *device = پوچ;
	ساختار sk_usbhid *sk = پوچ;
	ساختار sk_sign_response *response = پوچ;
	صحیح ret = SSH_SK_ERR_GENERAL, internal_uv;
	صحیح r;

	fido_init(SSH_FIDO_INIT_ARG);

	اگر (sign_response == پوچ) {
		skdebug(__func__, "sign_response == NULL");
		برو out;
	}
	*sign_response = پوچ;
	اگر (check_sign_load_resident_options(options, &device) != 0)
		برو out; /* error already logged */
	اگر (device != پوچ)
		sk = sk_open(device);
	وگرنه اگر (pin != پوچ || (flags & SSH_SK_USER_VERIFICATION_REQD))
		sk = sk_probe(پوچ, پوچ, 0, 0);
	وگرنه
		sk = sk_probe(application, کلید_handle, کلید_handle_len, 0);
	اگر (sk == پوچ) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		برو out;
	}
	اگر ((أكد = fido_assert_new()) == پوچ) {
		skdebug(__func__, "fido_assert_new failed");
		برو out;
	}
	اگر ((r = fido_assert_set_clientdata(أكد,
	    data, datalen)) != FIDO_OK)  {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		برو out;
	}
	اگر ((r = fido_assert_set_rp(أكد, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		برو out;
	}
	اگر ((r = fido_assert_allow_cred(أكد, کلید_handle,
	    کلید_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		برو out;
	}
	اگر ((r = fido_assert_set_up(أكد,
	    (flags & SSH_SK_USER_PRESENCE_REQD) ?
	    FIDO_OPT_TRUE : FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		برو out;
	}
	/*
	 * WinHello requests the PIN by default.  Make "uv" request explicit
	 * to allow keys with and without -O verify-required to make sense.
	 */
	اگر (pin == پوچ && fido_dev_is_winhello (sk->dev) &&
	    (r = fido_assert_set_uv(أكد, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
	}
	اگر (pin == پوچ && (flags & SSH_SK_USER_VERIFICATION_REQD)) {
		اگر (check_sk_options(sk->dev, "uv", &internal_uv) < 0 ||
		    internal_uv != 1) {
			skdebug(__func__, "check_sk_options uv");
			ret = SSH_SK_ERR_PIN_REQUIRED;
			برو out;
		}
		اگر ((r = fido_assert_set_uv(أكد,
		    FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_assert_set_uv: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			برو out;
		}
	}
	اگر ((r = fido_dev_get_assert(sk->dev, أكد, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		برو out;
	}
	اگر ((response = calloc(1, اندازه(*response))) == پوچ) {
		skdebug(__func__, "calloc response failed");
		برو out;
	}
	response->flags = fido_assert_flags(أكد, 0);
	response->counter = fido_assert_sigcount(أكد, 0);
	اگر (pack_sig(alg, أكد, response) != 0) {
		skdebug(__func__, "pack_sig failed");
		برو out;
	}
	*sign_response = response;
	response = پوچ;
	ret = 0;
 out:
	آزاد(device);
	اگر (response != پوچ) {
		آزاد(response->sig_r);
		آزاد(response->sig_s);
		آزاد(response);
	}
	sk_close(sk);
	fido_assert_free(&أكد);
	بازگشت ret;
}

ایستا صحیح
read_rks(ساختار sk_usbhid *sk, ثابت نویسه *pin,
    ساختار sk_resident_کلید ***rksp, size_t *nrksp)
{
	صحیح ret = SSH_SK_ERR_GENERAL, r = -1;
	uint32_t alg;
	fido_credman_metadata_t *metadata = پوچ;
	fido_credman_rp_t *rp = پوچ;
	fido_credman_rk_t *rk = پوچ;
	size_t i, j, nrp, nrk, user_id_len;
	ثابت fido_cred_t *cred;
	ثابت نویسه *rp_id, *rp_name, *user_name;
	ساختار sk_resident_کلید *srk = پوچ, **tmp;
	ثابت u_char *user_id;

	اگر (pin == پوچ) {
		skdebug(__func__, "no PIN specified");
		ret = SSH_SK_ERR_PIN_REQUIRED;
		برو out;
	}
	اگر ((metadata = fido_credman_metadata_new()) == پوچ) {
		skdebug(__func__, "alloc failed");
		برو out;
	}
	اگر ((r = fido_credman_get_dev_metadata(sk->dev, metadata, pin)) != 0) {
		اگر (r == FIDO_ERR_INVALID_COMMAND) {
			skdebug(__func__, "device %s does not support "
			    "resident keys", sk->path);
			ret = 0;
			برو out;
		}
		skdebug(__func__, "get metadata for %s failed: %s",
		    sk->path, fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		برو out;
	}
	skdebug(__func__, "existing %llu, remaining %llu",
	    (unsigned long long)fido_credman_rk_existing(metadata),
	    (unsigned long long)fido_credman_rk_remaining(metadata));
	اگر ((rp = fido_credman_rp_new()) == پوچ) {
		skdebug(__func__, "alloc rp failed");
		برو out;
	}
	اگر ((r = fido_credman_get_dev_rp(sk->dev, rp, pin)) != 0) {
		skdebug(__func__, "get RPs for %s failed: %s",
		    sk->path, fido_strerr(r));
		برو out;
	}
	nrp = fido_credman_rp_شمار(rp);
	skdebug(__func__, "Device %s has resident keys for %zu RPs",
	    sk->path, nrp);

	/* Iterate over RP IDs that have resident keys */
	برای (i = 0; i < nrp; i++) {
		rp_id = fido_credman_rp_id(rp, i);
		rp_name = fido_credman_rp_name(rp, i);
		skdebug(__func__, "rp %zu: name=\"%s\" id=\"%s\" hashlen=%zu",
		    i, rp_name == پوچ ? "(none)" : rp_name,
		    rp_id == پوچ ? "(none)" : rp_id,
		    fido_credman_rp_id_hash_len(rp, i));

		/* Skip non-SSH RP IDs */
		اگر (rp_id == پوچ ||
		    strncasecmp(fido_credman_rp_id(rp, i), "ssh:", 4) != 0)
			ادامه;

		fido_credman_rk_free(&rk);
		اگر ((rk = fido_credman_rk_new()) == پوچ) {
			skdebug(__func__, "alloc rk failed");
			برو out;
		}
		اگر ((r = fido_credman_get_dev_rk(sk->dev,
		    fido_credman_rp_id(rp, i), rk, pin)) != 0) {
			skdebug(__func__, "get RKs for %s slot %zu failed: %s",
			    sk->path, i, fido_strerr(r));
			برو out;
		}
		nrk = fido_credman_rk_شمار(rk);
		skdebug(__func__, "RP \"%s\" has %zu resident keys",
		    fido_credman_rp_id(rp, i), nrk);

		/* Iterate over resident keys for this RP ID */
		برای (j = 0; j < nrk; j++) {
			اگر ((cred = fido_credman_rk(rk, j)) == پوچ) {
				skdebug(__func__, "no RK in slot %zu", j);
				ادامه;
			}
			اگر ((user_name = fido_cred_user_name(cred)) == پوچ)
				user_name = "";
			user_id = fido_cred_user_id_ptr(cred);
			user_id_len = fido_cred_user_id_len(cred);
			skdebug(__func__, "Device %s RP \"%s\" user \"%s\" "
			    "uidlen %zu slot %zu: type %d flags 0x%02x "
			    "prot 0x%02x", sk->path, rp_id, user_name,
			    user_id_len, j, fido_cred_type(cred),
			    fido_cred_flags(cred), fido_cred_prot(cred));

			/* Determine key algorithm */
			انتخاب (fido_cred_type(cred)) {
			حالت COSE_ES256:
				alg = SSH_SK_ECDSA;
				بشکن;
			حالت COSE_EDDSA:
				alg = SSH_SK_ED25519;
				بشکن;
			پیشفرض:
				skdebug(__func__, "unsupported key type %d",
				    fido_cred_type(cred));
				ادامه;
			}

			/* build response entry */
			اگر ((srk = calloc(1, اندازه(*srk))) == پوچ ||
			    (srk->کلید.کلید_handle = calloc(1,
			    fido_cred_id_len(cred))) == پوچ ||
			    (srk->application = strdup(rp_id)) == پوچ ||
			    (user_id_len > 0 &&
			     (srk->user_id = calloc(1, user_id_len)) == پوچ)) {
				skdebug(__func__, "alloc sk_resident_key");
				برو out;
			}

			srk->alg = alg;
			srk->کلید.کلید_handle_len = fido_cred_id_len(cred);
			memcpy(srk->کلید.کلید_handle, fido_cred_id_ptr(cred),
			    srk->کلید.کلید_handle_len);
			srk->user_id_len = user_id_len;
			اگر (srk->user_id_len != 0)
				memcpy(srk->user_id, user_id, srk->user_id_len);

#ifdef HAVE_FIDO_CRED_PROT
			اگر (fido_cred_prot(cred) ==
			    FIDO_CRED_PROT_UV_REQUIRED)
				srk->flags |=  SSH_SK_USER_VERIFICATION_REQD;
#endif

			اگر ((r = pack_public_کلید(srk->alg, cred,
			    &srk->کلید)) != 0) {
				skdebug(__func__, "pack public key failed");
				برو out;
			}
			/* append */
			اگر ((tmp = recallocarray(*rksp, *nrksp, (*nrksp) + 1,
			    اندازه(**rksp))) == پوچ) {
				skdebug(__func__, "alloc rksp");
				برو out;
			}
			*rksp = tmp;
			(*rksp)[(*nrksp)++] = srk;
			srk = پوچ;
		}
	}
	/* Success */
	ret = 0;
 out:
	اگر (srk != پوچ) {
		آزاد(srk->application);
		freezero(srk->کلید.public_کلید, srk->کلید.public_کلید_len);
		freezero(srk->کلید.کلید_handle, srk->کلید.کلید_handle_len);
		freezero(srk->user_id, srk->user_id_len);
		freezero(srk, اندازه(*srk));
	}
	fido_credman_rp_free(&rp);
	fido_credman_rk_free(&rk);
	fido_credman_metadata_free(&metadata);
	بازگشت ret;
}

صحیح
sk_load_resident_کلیدها(ثابت نویسه *pin, ساختار sk_option **options,
    ساختار sk_resident_کلید ***rksp, size_t *nrksp)
{
	صحیح ret = SSH_SK_ERR_GENERAL, r = -1;
	size_t i, nrks = 0;
	ساختار sk_resident_کلید **rks = پوچ;
	ساختار sk_usbhid *sk = پوچ;
	نویسه *device = پوچ;

	*rksp = پوچ;
	*nrksp = 0;

	fido_init(SSH_FIDO_INIT_ARG);

	اگر (check_sign_load_resident_options(options, &device) != 0)
		برو out; /* error already logged */
	اگر (device != پوچ)
		sk = sk_open(device);
	وگرنه
		sk = sk_probe(پوچ, پوچ, 0, 1);
	اگر (sk == پوچ) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		برو out;
	}
	skdebug(__func__, "trying %s", sk->path);
	اگر ((r = read_rks(sk, pin, &rks, &nrks)) != 0) {
		skdebug(__func__, "read_rks failed for %s", sk->path);
		ret = r;
		برو out;
	}
	/* success, unless we have no keys but a specific error */
	اگر (nrks > 0 || ret == SSH_SK_ERR_GENERAL)
		ret = 0;
	*rksp = rks;
	*nrksp = nrks;
	rks = پوچ;
	nrks = 0;
 out:
	sk_close(sk);
	برای (i = 0; i < nrks; i++) {
		آزاد(rks[i]->application);
		freezero(rks[i]->کلید.public_کلید, rks[i]->کلید.public_کلید_len);
		freezero(rks[i]->کلید.کلید_handle, rks[i]->کلید.کلید_handle_len);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i], اندازه(*rks[i]));
	}
	آزاد(device);
	آزاد(rks);
	بازگشت ret;
}

#endif /* ENABLE_SK_INTERNAL */
