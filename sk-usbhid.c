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

#ضمن "includes.h"

#ifdef ENABLE_SK_INTERNAL

#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <stdio.h>
#ضمن <stddef.h>
#ضمن <stdarg.h>
#ضمن <time.h>
#ifdef HAVE_SHA2_H
#ضمن <sha2.h>
#endif

#ifdef WITH_OPENSSL
#ضمن <openssl/opensslv.h>
#ضمن <openssl/crypto.h>
#ضمن <openssl/bn.h>
#ضمن <openssl/ec.h>
#ضمن <openssl/ecdsa.h>
#ضمن <openssl/evp.h>
#ضمن "openbsd-compat/openssl-compat.h"
#endif /* WITH_OPENSSL */

#ضمن <fido.h>
#ضمن <fido/credman.h>

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
# define sk_load_resident_keys	ssh_sk_load_resident_keys
#endif /* !SK_STANDALONE */

#ضمن "sk-api.h"

/* #define SK_DEBUG 1 */

#ifdef SK_DEBUG
#define SSH_FIDO_INIT_ARG	FIDO_DEBUG
#אחרת
#define SSH_FIDO_INIT_ARG	0
#endif

#define MAX_FIDO_DEVICES	8
#define FIDO_POLL_MS		50
#define SELECT_MS		15000
#define POLL_SLEEP_NS		200000000

#ifndef FIDO_ERR_OPERATION_DENIED
#define FIDO_ERR_OPERATION_DENIED 0x27
#endif

بنية sk_usbhid {
	fido_dev_t *dev;
	حرف *path;
};

/* Return the version of the middleware API */
uint32_t sk_api_version(فراغ);

/* Enroll a U2F key (private key generation) */
صحيح sk_enroll(uint32_t alg, ثابت uint8_t *challenge, size_t challenge_len,
    ثابت حرف *application, uint8_t flags, ثابت حرف *pin,
    بنية sk_option **options, بنية sk_enroll_response **enroll_response);

/* Sign a challenge */
صحيح sk_sign(uint32_t alg, ثابت uint8_t *data, size_t data_len,
    ثابت حرف *application, ثابت uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, ثابت حرف *pin, بنية sk_option **options,
    بنية sk_sign_response **sign_response);

/* Load resident keys */
صحيح sk_load_resident_keys(ثابت حرف *pin, بنية sk_option **options,
    بنية sk_resident_key ***rks, size_t *nrks);

ساكن فراغ skdebug(ثابت حرف *func, ثابت حرف *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

ساكن فراغ
skdebug(ثابت حرف *func, ثابت حرف *fmt, ...)
{
#אם !defined(SK_STANDALONE)
	حرف *msg;
	va_list ap;

	va_start(ap, fmt);
	xvasprintf(&msg, fmt, ap);
	va_end(ap);
	debug("%s: %s", func, msg);
	حرر(msg);
#وإلاإذا defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#אחרת
	(فراغ)func; /* XXX */
	(فراغ)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(فراغ)
{
	החזר SSH_SK_VERSION_MAJOR;
}

ساكن بنية sk_usbhid *
sk_open(ثابت حرف *path)
{
	بنية sk_usbhid *sk;
	صحيح r;

	אם (path == عدم) {
		skdebug(__func__, "path == NULL");
		החזר عدم;
	}
	אם ((sk = calloc(1, حجم(*sk))) == عدم) {
		skdebug(__func__, "calloc sk failed");
		החזר عدم;
	}
	אם ((sk->path = strdup(path)) == عدم) {
		skdebug(__func__, "strdup path failed");
		حرر(sk);
		החזר عدم;
	}
	אם ((sk->dev = fido_dev_new()) == عدم) {
		skdebug(__func__, "fido_dev_new failed");
		حرر(sk->path);
		حرر(sk);
		החזר عدم;
	}
	אם ((r = fido_dev_open(sk->dev, sk->path)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_open %s failed: %s", sk->path,
		    fido_strerr(r));
		fido_dev_free(&sk->dev);
		حرر(sk->path);
		حرر(sk);
		החזר عدم;
	}
	החזר sk;
}

ساكن فراغ
sk_close(بنية sk_usbhid *sk)
{
	אם (sk == عدم)
		החזר;
	fido_dev_cancel(sk->dev); /* cancel any pending operation */
	fido_dev_close(sk->dev);
	fido_dev_free(&sk->dev);
	حرر(sk->path);
	حرر(sk);
}

ساكن بنية sk_usbhid **
sk_openv(ثابت fido_dev_info_t *devlist, size_t ndevs, size_t *nopen)
{
	ثابت fido_dev_info_t *di;
	بنية sk_usbhid **skv;
	size_t i;

	*nopen = 0;
	אם ((skv = calloc(ndevs, حجم(*skv))) == عدم) {
		skdebug(__func__, "calloc skv failed");
		החזר عدم;
	}
	עבור (i = 0; i < ndevs; i++) {
		אם ((di = fido_dev_info_ptr(devlist, i)) == عدم)
			skdebug(__func__, "fido_dev_info_ptr failed");
		אחרת אם ((skv[*nopen] = sk_open(fido_dev_info_path(di))) == عدم)
			skdebug(__func__, "sk_open failed");
		אחרת
			(*nopen)++;
	}
	אם (*nopen == 0) {
		עבור (i = 0; i < ndevs; i++)
			sk_close(skv[i]);
		حرر(skv);
		skv = عدم;
	}

	החזר skv;
}

ساكن فراغ
sk_closev(بنية sk_usbhid **skv, size_t nsk)
{
	size_t i;

	עבור (i = 0; i < nsk; i++)
		sk_close(skv[i]);
	حرر(skv);
}

ساكن صحيح
sk_touch_begin(بنية sk_usbhid **skv, size_t nsk)
{
	size_t i, ok = 0;
	صحيح r;

	עבור (i = 0; i < nsk; i++)
		אם ((r = fido_dev_get_touch_begin(skv[i]->dev)) != FIDO_OK)
			skdebug(__func__, "fido_dev_get_touch_begin %s failed:"
			    " %s", skv[i]->path, fido_strerr(r));
		אחרת
			ok++;

	החזר ok ? 0 : -1;
}

ساكن صحيح
sk_touch_poll(بنية sk_usbhid **skv, size_t nsk, صحيح *touch, size_t *idx)
{
	بنية timespec ts_pause;
	size_t npoll, i;
	صحيح r;

	ts_pause.tv_sec = 0;
	ts_pause.tv_nsec = POLL_SLEEP_NS;
	nanosleep(&ts_pause, عدم);
	npoll = nsk;
	עבור (i = 0; i < nsk; i++) {
		אם (skv[i] == عدم)
			استمر; /* device discarded */
		skdebug(__func__, "polling %s", skv[i]->path);
		אם ((r = fido_dev_get_touch_status(skv[i]->dev, touch,
		    FIDO_POLL_MS)) != FIDO_OK) {
			skdebug(__func__, "fido_dev_get_touch_status %s: %s",
			    skv[i]->path, fido_strerr(r));
			sk_close(skv[i]); /* discard device */
			skv[i] = عدم;
			אם (--npoll == 0) {
				skdebug(__func__, "no device left to poll");
				החזר -1;
			}
		} אחרת אם (*touch) {
			*idx = i;
			החזר 0;
		}
	}
	*touch = 0;
	החזר 0;
}

#אם !defined(HAVE_FIDO_ASSERT_SET_CLIENTDATA) || \
    !defined(HAVE_FIDO_CRED_SET_CLIENTDATA)
/* Calculate SHA256(m) */
ساكن صحيح
sha256_mem(ثابت فراغ *m, size_t mlen, u_char *d, size_t dlen)
{
#ifdef WITH_OPENSSL
	u_int mdlen;
#אחרת
	SHA2_CTX ctx;
#endif

	אם (dlen != 32)
		החזר -1;
#ifdef WITH_OPENSSL
	mdlen = dlen;
	אם (!EVP_Digest(m, mlen, d, &mdlen, EVP_sha256(), عدم))
		החזר -1;
#אחרת
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ثابت uint8_t *)m, mlen);
	SHA256Final(d, &ctx);
#endif
	החזר 0;
}
#endif /* !HAVE_FIDO_ASSERT_SET_CLIENTDATA || !HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_CRED_SET_CLIENTDATA
ساكن صحيح
fido_cred_set_clientdata(fido_cred_t *cred, ثابت u_char *ptr, size_t len)
{
	uint8_t d[32];
	صحيح r;

	אם (sha256_mem(ptr, len, d, حجم(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		החזר FIDO_ERR_INTERNAL;
	}
	r = fido_cred_set_clientdata_hash(cred, d, حجم(d));
	explicit_bzero(d, حجم(d));
	אם (r != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	החזר r;
}
#endif /* HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_ASSERT_SET_CLIENTDATA
ساكن صحيح
fido_assert_set_clientdata(fido_assert_t *أكد, ثابت u_char *ptr, size_t len)
{
	uint8_t d[32];
	صحيح r;

	אם (sha256_mem(ptr, len, d, حجم(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		החזר FIDO_ERR_INTERNAL;
	}
	r = fido_assert_set_clientdata_hash(أكد, d, حجم(d));
	explicit_bzero(d, حجم(d));
	אם (r != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	החזר r;
}
#endif /* HAVE_FIDO_ASSERT_SET_CLIENTDATA */

#ifndef HAVE_FIDO_DEV_IS_WINHELLO
ساكن bool
fido_dev_is_winhello(ثابت fido_dev_t *fdev)
{
	החזר 0;
}
#endif /* HAVE_FIDO_DEV_IS_WINHELLO */

/* Check if the specified key handle exists on a given sk. */
ساكن صحيح
sk_try(ثابت بنية sk_usbhid *sk, ثابت حرف *application,
    ثابت uint8_t *key_handle, size_t key_handle_len)
{
	fido_assert_t *أكد = عدم;
	صحيح r = FIDO_ERR_INTERNAL;
	uint8_t message[32];

	memset(message, '\0', حجم(message));
	אם ((أكد = fido_assert_new()) == عدم) {
		skdebug(__func__, "fido_assert_new failed");
		اذهب out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	אם ((r = fido_assert_set_clientdata(أكد, message,
	    حجم(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		اذهب out;
	}
	אם ((r = fido_assert_set_rp(أكد, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		اذهب out;
	}
	אם ((r = fido_assert_allow_cred(أكد, key_handle,
	    key_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		اذهب out;
	}
	אם ((r = fido_assert_set_up(أكد, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_up: %s", fido_strerr(r));
		اذهب out;
	}
	r = fido_dev_get_assert(sk->dev, أكد, عدم);
	skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
	אם (r == FIDO_ERR_USER_PRESENCE_REQUIRED) {
		/* U2F tokens may return this */
		r = FIDO_OK;
	}
 out:
	fido_assert_free(&أكد);

	החזר r != FIDO_OK ? -1 : 0;
}

ساكن صحيح
check_sk_options(fido_dev_t *dev, ثابت حرف *opt, صحيح *ret)
{
	fido_cbor_info_t *info;
	حرف * ثابت *name;
	ثابت bool *value;
	size_t len, i;
	صحيح r;

	*ret = -1;

	אם (!fido_dev_is_fido2(dev)) {
		skdebug(__func__, "device is not fido2");
		החזר 0;
	}
	אם ((info = fido_cbor_info_new()) == عدم) {
		skdebug(__func__, "fido_cbor_info_new failed");
		החזר -1;
	}
	אם ((r = fido_dev_get_cbor_info(dev, info)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_cbor_info: %s", fido_strerr(r));
		fido_cbor_info_free(&info);
		החזר -1;
	}
	name = fido_cbor_info_options_name_ptr(info);
	value = fido_cbor_info_options_value_ptr(info);
	len = fido_cbor_info_options_len(info);
	עבור (i = 0; i < len; i++) {
		אם (!strcmp(name[i], opt)) {
			*ret = value[i];
			اكسر;
		}
	}
	fido_cbor_info_free(&info);
	אם (*ret == -1)
		skdebug(__func__, "option %s is unknown", opt);
	אחרת
		skdebug(__func__, "option %s is %s", opt, *ret ? "on" : "off");

	החזר 0;
}

ساكن بنية sk_usbhid *
sk_select_by_cred(ثابت fido_dev_info_t *devlist, size_t ndevs,
    ثابت حرف *application, ثابت uint8_t *key_handle, size_t key_handle_len)
{
	بنية sk_usbhid **skv, *sk;
	size_t skvcnt, i;
	صحيح internal_uv;

	אם ((skv = sk_openv(devlist, ndevs, &skvcnt)) == عدم) {
		skdebug(__func__, "sk_openv failed");
		החזר عدم;
	}
	אם (skvcnt == 1 && check_sk_options(skv[0]->dev, "uv",
	    &internal_uv) == 0 && internal_uv != -1) {
		sk = skv[0];
		skv[0] = عدم;
		اذهب out;
	}
	sk = عدم;
	עבור (i = 0; i < skvcnt; i++) {
		אם (sk_try(skv[i], application, key_handle,
		    key_handle_len) == 0) {
			sk = skv[i];
			skv[i] = عدم;
			skdebug(__func__, "found key in %s", sk->path);
			اكسر;
		}
	}
 out:
	sk_closev(skv, skvcnt);
	החזר sk;
}

ساكن بنية sk_usbhid *
sk_select_by_touch(ثابت fido_dev_info_t *devlist, size_t ndevs)
{
	بنية sk_usbhid **skv, *sk;
	بنية timeval tv_start, tv_now, tv_delta;
	size_t skvcnt, idx;
	صحيح touch, ms_remain;

	אם ((skv = sk_openv(devlist, ndevs, &skvcnt)) == عدم) {
		skdebug(__func__, "sk_openv failed");
		החזר عدم;
	}
	sk = عدم;
	אם (skvcnt < 2) {
		אם (skvcnt == 1) {
			/* single candidate */
			sk = skv[0];
			skv[0] = عدم;
		}
		اذهب out;
	}
#ifndef HAVE_FIDO_DEV_GET_TOUCH_STATUS
	skdebug(__func__, "libfido2 version does not support a feature needed for multiple tokens. Please upgrade to >=1.5.0");
	اذهب out;
#endif

	אם (sk_touch_begin(skv, skvcnt) == -1) {
		skdebug(__func__, "sk_touch_begin failed");
		اذهب out;
	}
	monotime_tv(&tv_start);
	עשה {
		אם (sk_touch_poll(skv, skvcnt, &touch, &idx) == -1) {
			skdebug(__func__, "sk_touch_poll failed");
			اذهب out;
		}
		אם (touch) {
			sk = skv[idx];
			skv[idx] = عدم;
			اذهب out;
		}
		monotime_tv(&tv_now);
		timersub(&tv_now, &tv_start, &tv_delta);
		ms_remain = SELECT_MS - tv_delta.tv_sec * 1000 -
		    tv_delta.tv_usec / 1000;
	} כלעוד (ms_remain >= FIDO_POLL_MS);
	skdebug(__func__, "timeout");
out:
	sk_closev(skv, skvcnt);
	החזר sk;
}

ساكن بنية sk_usbhid *
sk_probe(ثابت حرف *application, ثابت uint8_t *key_handle,
    size_t key_handle_len, صحيح probe_resident)
{
	بنية sk_usbhid *sk;
	fido_dev_info_t *devlist;
	size_t ndevs;
	صحيح r;

#ifdef HAVE_CYGWIN
	אם (!probe_resident && (sk = sk_open("windows://hello")) != عدم)
		החזר sk;
#endif /* HAVE_CYGWIN */
	אם ((devlist = fido_dev_info_new(MAX_FIDO_DEVICES)) == عدم) {
		skdebug(__func__, "fido_dev_info_new failed");
		החזר عدم;
	}
	אם ((r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES,
	    &ndevs)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_info_manifest failed: %s",
		    fido_strerr(r));
		fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
		החזר عدم;
	}
	skdebug(__func__, "%zu device(s) detected", ndevs);
	אם (ndevs == 0) {
		sk = عدم;
	} אחרת אם (application != عدم && key_handle != عدم) {
		skdebug(__func__, "selecting sk by cred");
		sk = sk_select_by_cred(devlist, ndevs, application, key_handle,
		    key_handle_len);
	} אחרת {
		skdebug(__func__, "selecting sk by touch");
		sk = sk_select_by_touch(devlist, ndevs);
	}
	fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
	החזר sk;
}

#ifdef WITH_OPENSSL
/*
 * The key returned via fido_cred_pubkey_ptr() is in affine coordinates,
 * but the API expects a SEC1 octet string.
 */
ساكن صحيح
pack_public_key_ecdsa(ثابت fido_cred_t *cred,
    بنية sk_enroll_response *response)
{
	ثابت uint8_t *ptr;
	BIGNUM *x = عدم, *y = عدم;
	EC_POINT *q = عدم;
	EC_GROUP *g = عدم;
	صحيح ret = -1;

	response->public_key = عدم;
	response->public_key_len = 0;

	אם ((x = BN_new()) == عدم ||
	    (y = BN_new()) == عدم ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == عدم ||
	    (q = EC_POINT_new(g)) == عدم) {
		skdebug(__func__, "libcrypto setup failed");
		اذهب out;
	}
	אם ((ptr = fido_cred_pubkey_ptr(cred)) == عدم) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		اذهب out;
	}
	אם (fido_cred_pubkey_len(cred) != 64) {
		skdebug(__func__, "bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		اذهب out;
	}

	אם (BN_bin2bn(ptr, 32, x) == عدم ||
	    BN_bin2bn(ptr + 32, 32, y) == عدم) {
		skdebug(__func__, "BN_bin2bn failed");
		اذهب out;
	}
	אם (EC_POINT_set_affine_coordinates(g, q, x, y, عدم) != 1) {
		skdebug(__func__, "EC_POINT_set_affine_coordinates failed");
		اذهب out;
	}
	response->public_key_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, عدم, 0, عدم);
	אם (response->public_key_len == 0 || response->public_key_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_key_len);
		اذهب out;
	}
	אם ((response->public_key = malloc(response->public_key_len)) == عدم) {
		skdebug(__func__, "malloc pubkey failed");
		اذهب out;
	}
	אם (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_key, response->public_key_len, عدم) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		اذهب out;
	}
	/* success */
	ret = 0;
 out:
	אם (ret != 0 && response->public_key != عدم) {
		memset(response->public_key, 0, response->public_key_len);
		حرر(response->public_key);
		response->public_key = عدم;
	}
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	החזר ret;
}
#endif /* WITH_OPENSSL */

ساكن صحيح
pack_public_key_ed25519(ثابت fido_cred_t *cred,
    بنية sk_enroll_response *response)
{
	ثابت uint8_t *ptr;
	size_t len;
	صحيح ret = -1;

	response->public_key = عدم;
	response->public_key_len = 0;

	אם ((len = fido_cred_pubkey_len(cred)) != 32) {
		skdebug(__func__, "bad fido_cred_pubkey_len len %zu", len);
		اذهب out;
	}
	אם ((ptr = fido_cred_pubkey_ptr(cred)) == عدم) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		اذهب out;
	}
	response->public_key_len = len;
	אם ((response->public_key = malloc(response->public_key_len)) == عدم) {
		skdebug(__func__, "malloc pubkey failed");
		اذهب out;
	}
	memcpy(response->public_key, ptr, len);
	ret = 0;
 out:
	אם (ret != 0)
		حرر(response->public_key);
	החזר ret;
}

ساكن صحيح
pack_public_key(uint32_t alg, ثابت fido_cred_t *cred,
    بنية sk_enroll_response *response)
{
	بدل(alg) {
#ifdef WITH_OPENSSL
	حالة SSH_SK_ECDSA:
		החזר pack_public_key_ecdsa(cred, response);
#endif /* WITH_OPENSSL */
	حالة SSH_SK_ED25519:
		החזר pack_public_key_ed25519(cred, response);
	افتراضي:
		החזר -1;
	}
}

ساكن صحيح
fidoerr_to_skerr(صحيح fidoerr)
{
	بدل (fidoerr) {
	حالة FIDO_ERR_UNSUPPORTED_OPTION:
	حالة FIDO_ERR_UNSUPPORTED_ALGORITHM:
		החזר SSH_SK_ERR_UNSUPPORTED;
	حالة FIDO_ERR_PIN_REQUIRED:
	حالة FIDO_ERR_PIN_INVALID:
	حالة FIDO_ERR_OPERATION_DENIED:
		החזר SSH_SK_ERR_PIN_REQUIRED;
	افتراضي:
		החזר -1;
	}
}

ساكن صحيح
check_enroll_options(بنية sk_option **options, حرف **devicep,
    uint8_t *user_id, size_t user_id_len)
{
	size_t i;

	אם (options == عدم)
		החזר 0;
	עבור (i = 0; options[i] != عدم; i++) {
		אם (strcmp(options[i]->name, "device") == 0) {
			אם ((*devicep = strdup(options[i]->value)) == عدم) {
				skdebug(__func__, "strdup device failed");
				החזר -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} אחרת אם (strcmp(options[i]->name, "user") == 0) {
			אם (strlcpy(user_id, options[i]->value, user_id_len) >=
			    user_id_len) {
				skdebug(__func__, "user too long");
				החזר -1;
			}
			skdebug(__func__, "requested user %s",
			    (حرف *)user_id);
		} אחרת {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			אם (options[i]->required) {
				skdebug(__func__, "unknown required option");
				החזר -1;
			}
		}
	}
	החזר 0;
}

ساكن صحيح
key_lookup(fido_dev_t *dev, ثابت حرف *application, ثابت uint8_t *user_id,
    size_t user_id_len, ثابت حرف *pin)
{
	fido_assert_t *أكد = عدم;
	uint8_t message[32];
	صحيح r = FIDO_ERR_INTERNAL;
	صحيح sk_supports_uv, uv;
	size_t i;

	memset(message, '\0', حجم(message));
	אם ((أكد = fido_assert_new()) == عدم) {
		skdebug(__func__, "fido_assert_new failed");
		اذهب out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	אם ((r = fido_assert_set_clientdata(أكد, message,
	    حجم(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		اذهب out;
	}
	אם ((r = fido_assert_set_rp(أكد, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		اذهب out;
	}
	אם ((r = fido_assert_set_up(أكد, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		اذهب out;
	}
	uv = FIDO_OPT_OMIT;
	אם (pin == عدم && check_sk_options(dev, "uv", &sk_supports_uv) == 0 &&
	    sk_supports_uv != -1)
		uv = FIDO_OPT_TRUE;
	אם ((r = fido_assert_set_uv(أكد, uv)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
		اذهب out;
	}
	אם ((r = fido_dev_get_assert(dev, أكد, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		اذهب out;
	}
	r = FIDO_ERR_NO_CREDENTIALS;
	skdebug(__func__, "%zu signatures returned", fido_assert_count(أكد));
	עבור (i = 0; i < fido_assert_count(أكد); i++) {
		אם (fido_assert_user_id_len(أكد, i) == user_id_len &&
		    memcmp(fido_assert_user_id_ptr(أكد, i), user_id,
		    user_id_len) == 0) {
			skdebug(__func__, "credential exists");
			r = FIDO_OK;
			اذهب out;
		}
	}
 out:
	fido_assert_free(&أكد);

	החזר r;
}

صحيح
sk_enroll(uint32_t alg, ثابت uint8_t *challenge, size_t challenge_len,
    ثابت حرف *application, uint8_t flags, ثابت حرف *pin,
    بنية sk_option **options, بنية sk_enroll_response **enroll_response)
{
	fido_cred_t *cred = عدم;
	ثابت uint8_t *ptr;
	uint8_t user_id[32];
	بنية sk_usbhid *sk = عدم;
	بنية sk_enroll_response *response = عدم;
	size_t len;
	صحيح credprot;
	صحيح cose_alg;
	صحيح ret = SSH_SK_ERR_GENERAL;
	صحيح r;
	حرف *device = عدم;

	fido_init(SSH_FIDO_INIT_ARG);

	אם (enroll_response == عدم) {
		skdebug(__func__, "enroll_response == NULL");
		اذهب out;
	}
	*enroll_response = عدم;
	memset(user_id, 0, حجم(user_id));
	אם (check_enroll_options(options, &device, user_id,
	    حجم(user_id)) != 0)
		اذهب out; /* error already logged */

	بدل(alg) {
#ifdef WITH_OPENSSL
	حالة SSH_SK_ECDSA:
		cose_alg = COSE_ES256;
		اكسر;
#endif /* WITH_OPENSSL */
	حالة SSH_SK_ED25519:
		cose_alg = COSE_EDDSA;
		اكسر;
	افتراضي:
		skdebug(__func__, "unsupported key type %d", alg);
		اذهب out;
	}
	אם (device != عدم)
		sk = sk_open(device);
	אחרת
		sk = sk_probe(عدم, عدم, 0, 0);
	אם (sk == عدم) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		اذهب out;
	}
	skdebug(__func__, "using device %s", sk->path);
	אם ((flags & SSH_SK_RESIDENT_KEY) != 0 &&
	    (flags & SSH_SK_FORCE_OPERATION) == 0 &&
	    (r = key_lookup(sk->dev, application, user_id, حجم(user_id),
	    pin)) != FIDO_ERR_NO_CREDENTIALS) {
		אם (r != FIDO_OK) {
			ret = fidoerr_to_skerr(r);
			skdebug(__func__, "key_lookup failed");
		} אחרת {
			ret = SSH_SK_ERR_CREDENTIAL_EXISTS;
			skdebug(__func__, "key exists");
		}
		اذهب out;
	}
	אם ((cred = fido_cred_new()) == عدم) {
		skdebug(__func__, "fido_cred_new failed");
		اذهب out;
	}
	אם ((r = fido_cred_set_type(cred, cose_alg)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_type: %s", fido_strerr(r));
		اذهب out;
	}
	אם ((r = fido_cred_set_clientdata(cred,
	    challenge, challenge_len)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata: %s",
		    fido_strerr(r));
		اذهب out;
	}
	אם ((r = fido_cred_set_rk(cred, (flags & SSH_SK_RESIDENT_KEY) != 0 ?
	    FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rk: %s", fido_strerr(r));
		اذهب out;
	}
	אם ((r = fido_cred_set_user(cred, user_id, حجم(user_id),
	    "openssh", "openssh", عدم)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_user: %s", fido_strerr(r));
		اذهب out;
	}
	אם ((r = fido_cred_set_rp(cred, application, عدم)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rp: %s", fido_strerr(r));
		اذهب out;
	}
	אם ((flags & (SSH_SK_RESIDENT_KEY|SSH_SK_USER_VERIFICATION_REQD)) != 0) {
#אם !defined(HAVE_FIDO_DEV_SUPPORTS_CRED_PROT) || \
    !defined(HAVE_FIDO_CRED_SET_PROT)
		skdebug(__func__, "libfido2 version does not support a feature required for this operation. Please upgrade to >=1.5.0");
		ret = SSH_SK_ERR_UNSUPPORTED;
		اذهب out;
		credprot = 0; (فراغ)credprot; /* avoid warning */
#endif
		אם (!fido_dev_supports_cred_prot(sk->dev)) {
			skdebug(__func__, "%s does not support credprot, "
			    "refusing to create unprotected "
			    "resident/verify-required key", sk->path);
			ret = SSH_SK_ERR_UNSUPPORTED;
			اذهب out;
		}
		אם ((flags & SSH_SK_USER_VERIFICATION_REQD))
			credprot = FIDO_CRED_PROT_UV_REQUIRED;
		אחרת
			credprot = FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID;

		אם ((r = fido_cred_set_prot(cred, credprot)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_set_prot: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			اذهب out;
		}
	}
	אם ((r = fido_dev_make_cred(sk->dev, cred, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_make_cred: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		اذهب out;
	}
	אם (fido_cred_x5c_ptr(cred) != عدم) {
		אם ((r = fido_cred_verify(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify: %s",
			    fido_strerr(r));
			اذهب out;
		}
	} אחרת אם (strcmp(fido_cred_fmt(cred), "none") != 0) {
		skdebug(__func__, "self-attested credential");
		אם ((r = fido_cred_verify_self(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify_self: %s",
			    fido_strerr(r));
			اذهب out;
		}
	} אחרת {
		skdebug(__func__, "no attestation data");
	}
	אם ((response = calloc(1, حجم(*response))) == عدم) {
		skdebug(__func__, "calloc response failed");
		اذهب out;
	}
	response->flags = flags;
	אם (pack_public_key(alg, cred, response) != 0) {
		skdebug(__func__, "pack_public_key failed");
		اذهب out;
	}
	אם ((ptr = fido_cred_id_ptr(cred)) != عدم) {
		len = fido_cred_id_len(cred);
		אם ((response->key_handle = calloc(1, len)) == عدم) {
			skdebug(__func__, "calloc key handle failed");
			اذهب out;
		}
		memcpy(response->key_handle, ptr, len);
		response->key_handle_len = len;
	}
	אם ((ptr = fido_cred_sig_ptr(cred)) != عدم) {
		len = fido_cred_sig_len(cred);
		אם ((response->signature = calloc(1, len)) == عدم) {
			skdebug(__func__, "calloc signature failed");
			اذهب out;
		}
		memcpy(response->signature, ptr, len);
		response->signature_len = len;
	}
	אם ((ptr = fido_cred_x5c_ptr(cred)) != عدم) {
		len = fido_cred_x5c_len(cred);
		skdebug(__func__, "attestation cert len=%zu", len);
		אם ((response->attestation_cert = calloc(1, len)) == عدم) {
			skdebug(__func__, "calloc attestation cert failed");
			اذهب out;
		}
		memcpy(response->attestation_cert, ptr, len);
		response->attestation_cert_len = len;
	}
	אם ((ptr = fido_cred_authdata_ptr(cred)) != عدم) {
		len = fido_cred_authdata_len(cred);
		skdebug(__func__, "authdata len=%zu", len);
		אם ((response->authdata = calloc(1, len)) == عدم) {
			skdebug(__func__, "calloc authdata failed");
			اذهب out;
		}
		memcpy(response->authdata, ptr, len);
		response->authdata_len = len;
	}
	*enroll_response = response;
	response = عدم;
	ret = 0;
 out:
	حرر(device);
	אם (response != عدم) {
		حرر(response->public_key);
		حرر(response->key_handle);
		حرر(response->signature);
		حرر(response->attestation_cert);
		حرر(response->authdata);
		حرر(response);
	}
	sk_close(sk);
	fido_cred_free(&cred);
	החזר ret;
}

#ifdef WITH_OPENSSL
ساكن صحيح
pack_sig_ecdsa(fido_assert_t *أكد, بنية sk_sign_response *response)
{
	ECDSA_SIG *sig = عدم;
	ثابت BIGNUM *sig_r, *sig_s;
	ثابت unsigned حرف *cp;
	size_t sig_len;
	صحيح ret = -1;

	cp = fido_assert_sig_ptr(أكد, 0);
	sig_len = fido_assert_sig_len(أكد, 0);
	אם ((sig = d2i_ECDSA_SIG(عدم, &cp, sig_len)) == عدم) {
		skdebug(__func__, "d2i_ECDSA_SIG failed");
		اذهب out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_num_bytes(sig_r);
	response->sig_s_len = BN_num_bytes(sig_s);
	אם ((response->sig_r = calloc(1, response->sig_r_len)) == عدم ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == عدم) {
		skdebug(__func__, "calloc signature failed");
		اذهب out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	ECDSA_SIG_free(sig);
	אם (ret != 0) {
		حرر(response->sig_r);
		حرر(response->sig_s);
		response->sig_r = عدم;
		response->sig_s = عدم;
	}
	החזר ret;
}
#endif /* WITH_OPENSSL */

ساكن صحيح
pack_sig_ed25519(fido_assert_t *أكد, بنية sk_sign_response *response)
{
	ثابت unsigned حرف *ptr;
	size_t len;
	صحيح ret = -1;

	ptr = fido_assert_sig_ptr(أكد, 0);
	len = fido_assert_sig_len(أكد, 0);
	אם (len != 64) {
		skdebug(__func__, "bad length %zu", len);
		اذهب out;
	}
	response->sig_r_len = len;
	אם ((response->sig_r = calloc(1, response->sig_r_len)) == عدم) {
		skdebug(__func__, "calloc signature failed");
		اذهب out;
	}
	memcpy(response->sig_r, ptr, len);
	ret = 0;
 out:
	אם (ret != 0) {
		حرر(response->sig_r);
		response->sig_r = عدم;
	}
	החזר ret;
}

ساكن صحيح
pack_sig(uint32_t  alg, fido_assert_t *أكد,
    بنية sk_sign_response *response)
{
	بدل(alg) {
#ifdef WITH_OPENSSL
	حالة SSH_SK_ECDSA:
		החזר pack_sig_ecdsa(أكد, response);
#endif /* WITH_OPENSSL */
	حالة SSH_SK_ED25519:
		החזר pack_sig_ed25519(أكد, response);
	افتراضي:
		החזר -1;
	}
}

/* Checks sk_options for sk_sign() and sk_load_resident_keys() */
ساكن صحيح
check_sign_load_resident_options(بنية sk_option **options, حرف **devicep)
{
	size_t i;

	אם (options == عدم)
		החזר 0;
	עבור (i = 0; options[i] != عدم; i++) {
		אם (strcmp(options[i]->name, "device") == 0) {
			אם ((*devicep = strdup(options[i]->value)) == عدم) {
				skdebug(__func__, "strdup device failed");
				החזר -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} אחרת {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			אם (options[i]->required) {
				skdebug(__func__, "unknown required option");
				החזר -1;
			}
		}
	}
	החזר 0;
}

صحيح
sk_sign(uint32_t alg, ثابت uint8_t *data, size_t datalen,
    ثابت حرف *application,
    ثابت uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, ثابت حرف *pin, بنية sk_option **options,
    بنية sk_sign_response **sign_response)
{
	fido_assert_t *أكد = عدم;
	حرف *device = عدم;
	بنية sk_usbhid *sk = عدم;
	بنية sk_sign_response *response = عدم;
	صحيح ret = SSH_SK_ERR_GENERAL, internal_uv;
	صحيح r;

	fido_init(SSH_FIDO_INIT_ARG);

	אם (sign_response == عدم) {
		skdebug(__func__, "sign_response == NULL");
		اذهب out;
	}
	*sign_response = عدم;
	אם (check_sign_load_resident_options(options, &device) != 0)
		اذهب out; /* error already logged */
	אם (device != عدم)
		sk = sk_open(device);
	אחרת אם (pin != عدم || (flags & SSH_SK_USER_VERIFICATION_REQD))
		sk = sk_probe(عدم, عدم, 0, 0);
	אחרת
		sk = sk_probe(application, key_handle, key_handle_len, 0);
	אם (sk == عدم) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		اذهب out;
	}
	אם ((أكد = fido_assert_new()) == عدم) {
		skdebug(__func__, "fido_assert_new failed");
		اذهب out;
	}
	אם ((r = fido_assert_set_clientdata(أكد,
	    data, datalen)) != FIDO_OK)  {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		اذهب out;
	}
	אם ((r = fido_assert_set_rp(أكد, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		اذهب out;
	}
	אם ((r = fido_assert_allow_cred(أكد, key_handle,
	    key_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		اذهب out;
	}
	אם ((r = fido_assert_set_up(أكد,
	    (flags & SSH_SK_USER_PRESENCE_REQD) ?
	    FIDO_OPT_TRUE : FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		اذهب out;
	}
	/*
	 * WinHello requests the PIN by default.  Make "uv" request explicit
	 * to allow keys with and without -O verify-required to make sense.
	 */
	אם (pin == عدم && fido_dev_is_winhello (sk->dev) &&
	    (r = fido_assert_set_uv(أكد, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
	}
	אם (pin == عدم && (flags & SSH_SK_USER_VERIFICATION_REQD)) {
		אם (check_sk_options(sk->dev, "uv", &internal_uv) < 0 ||
		    internal_uv != 1) {
			skdebug(__func__, "check_sk_options uv");
			ret = SSH_SK_ERR_PIN_REQUIRED;
			اذهب out;
		}
		אם ((r = fido_assert_set_uv(أكد,
		    FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_assert_set_uv: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			اذهب out;
		}
	}
	אם ((r = fido_dev_get_assert(sk->dev, أكد, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		اذهب out;
	}
	אם ((response = calloc(1, حجم(*response))) == عدم) {
		skdebug(__func__, "calloc response failed");
		اذهب out;
	}
	response->flags = fido_assert_flags(أكد, 0);
	response->counter = fido_assert_sigcount(أكد, 0);
	אם (pack_sig(alg, أكد, response) != 0) {
		skdebug(__func__, "pack_sig failed");
		اذهب out;
	}
	*sign_response = response;
	response = عدم;
	ret = 0;
 out:
	حرر(device);
	אם (response != عدم) {
		حرر(response->sig_r);
		حرر(response->sig_s);
		حرر(response);
	}
	sk_close(sk);
	fido_assert_free(&أكد);
	החזר ret;
}

ساكن صحيح
read_rks(بنية sk_usbhid *sk, ثابت حرف *pin,
    بنية sk_resident_key ***rksp, size_t *nrksp)
{
	صحيح ret = SSH_SK_ERR_GENERAL, r = -1;
	uint32_t alg;
	fido_credman_metadata_t *metadata = عدم;
	fido_credman_rp_t *rp = عدم;
	fido_credman_rk_t *rk = عدم;
	size_t i, j, nrp, nrk, user_id_len;
	ثابت fido_cred_t *cred;
	ثابت حرف *rp_id, *rp_name, *user_name;
	بنية sk_resident_key *srk = عدم, **tmp;
	ثابت u_char *user_id;

	אם (pin == عدم) {
		skdebug(__func__, "no PIN specified");
		ret = SSH_SK_ERR_PIN_REQUIRED;
		اذهب out;
	}
	אם ((metadata = fido_credman_metadata_new()) == عدم) {
		skdebug(__func__, "alloc failed");
		اذهب out;
	}
	אם ((r = fido_credman_get_dev_metadata(sk->dev, metadata, pin)) != 0) {
		אם (r == FIDO_ERR_INVALID_COMMAND) {
			skdebug(__func__, "device %s does not support "
			    "resident keys", sk->path);
			ret = 0;
			اذهب out;
		}
		skdebug(__func__, "get metadata for %s failed: %s",
		    sk->path, fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		اذهب out;
	}
	skdebug(__func__, "existing %llu, remaining %llu",
	    (unsigned long long)fido_credman_rk_existing(metadata),
	    (unsigned long long)fido_credman_rk_remaining(metadata));
	אם ((rp = fido_credman_rp_new()) == عدم) {
		skdebug(__func__, "alloc rp failed");
		اذهب out;
	}
	אם ((r = fido_credman_get_dev_rp(sk->dev, rp, pin)) != 0) {
		skdebug(__func__, "get RPs for %s failed: %s",
		    sk->path, fido_strerr(r));
		اذهب out;
	}
	nrp = fido_credman_rp_count(rp);
	skdebug(__func__, "Device %s has resident keys for %zu RPs",
	    sk->path, nrp);

	/* Iterate over RP IDs that have resident keys */
	עבור (i = 0; i < nrp; i++) {
		rp_id = fido_credman_rp_id(rp, i);
		rp_name = fido_credman_rp_name(rp, i);
		skdebug(__func__, "rp %zu: name=\"%s\" id=\"%s\" hashlen=%zu",
		    i, rp_name == عدم ? "(none)" : rp_name,
		    rp_id == عدم ? "(none)" : rp_id,
		    fido_credman_rp_id_hash_len(rp, i));

		/* Skip non-SSH RP IDs */
		אם (rp_id == عدم ||
		    strncasecmp(fido_credman_rp_id(rp, i), "ssh:", 4) != 0)
			استمر;

		fido_credman_rk_free(&rk);
		אם ((rk = fido_credman_rk_new()) == عدم) {
			skdebug(__func__, "alloc rk failed");
			اذهب out;
		}
		אם ((r = fido_credman_get_dev_rk(sk->dev,
		    fido_credman_rp_id(rp, i), rk, pin)) != 0) {
			skdebug(__func__, "get RKs for %s slot %zu failed: %s",
			    sk->path, i, fido_strerr(r));
			اذهب out;
		}
		nrk = fido_credman_rk_count(rk);
		skdebug(__func__, "RP \"%s\" has %zu resident keys",
		    fido_credman_rp_id(rp, i), nrk);

		/* Iterate over resident keys for this RP ID */
		עבור (j = 0; j < nrk; j++) {
			אם ((cred = fido_credman_rk(rk, j)) == عدم) {
				skdebug(__func__, "no RK in slot %zu", j);
				استمر;
			}
			אם ((user_name = fido_cred_user_name(cred)) == عدم)
				user_name = "";
			user_id = fido_cred_user_id_ptr(cred);
			user_id_len = fido_cred_user_id_len(cred);
			skdebug(__func__, "Device %s RP \"%s\" user \"%s\" "
			    "uidlen %zu slot %zu: type %d flags 0x%02x "
			    "prot 0x%02x", sk->path, rp_id, user_name,
			    user_id_len, j, fido_cred_type(cred),
			    fido_cred_flags(cred), fido_cred_prot(cred));

			/* Determine key algorithm */
			بدل (fido_cred_type(cred)) {
			حالة COSE_ES256:
				alg = SSH_SK_ECDSA;
				اكسر;
			حالة COSE_EDDSA:
				alg = SSH_SK_ED25519;
				اكسر;
			افتراضي:
				skdebug(__func__, "unsupported key type %d",
				    fido_cred_type(cred));
				استمر;
			}

			/* build response entry */
			אם ((srk = calloc(1, حجم(*srk))) == عدم ||
			    (srk->key.key_handle = calloc(1,
			    fido_cred_id_len(cred))) == عدم ||
			    (srk->application = strdup(rp_id)) == عدم ||
			    (user_id_len > 0 &&
			     (srk->user_id = calloc(1, user_id_len)) == عدم)) {
				skdebug(__func__, "alloc sk_resident_key");
				اذهب out;
			}

			srk->alg = alg;
			srk->key.key_handle_len = fido_cred_id_len(cred);
			memcpy(srk->key.key_handle, fido_cred_id_ptr(cred),
			    srk->key.key_handle_len);
			srk->user_id_len = user_id_len;
			אם (srk->user_id_len != 0)
				memcpy(srk->user_id, user_id, srk->user_id_len);

#ifdef HAVE_FIDO_CRED_PROT
			אם (fido_cred_prot(cred) ==
			    FIDO_CRED_PROT_UV_REQUIRED)
				srk->flags |=  SSH_SK_USER_VERIFICATION_REQD;
#endif

			אם ((r = pack_public_key(srk->alg, cred,
			    &srk->key)) != 0) {
				skdebug(__func__, "pack public key failed");
				اذهب out;
			}
			/* append */
			אם ((tmp = recallocarray(*rksp, *nrksp, (*nrksp) + 1,
			    حجم(**rksp))) == عدم) {
				skdebug(__func__, "alloc rksp");
				اذهب out;
			}
			*rksp = tmp;
			(*rksp)[(*nrksp)++] = srk;
			srk = عدم;
		}
	}
	/* Success */
	ret = 0;
 out:
	אם (srk != عدم) {
		حرر(srk->application);
		freezero(srk->key.public_key, srk->key.public_key_len);
		freezero(srk->key.key_handle, srk->key.key_handle_len);
		freezero(srk->user_id, srk->user_id_len);
		freezero(srk, حجم(*srk));
	}
	fido_credman_rp_free(&rp);
	fido_credman_rk_free(&rk);
	fido_credman_metadata_free(&metadata);
	החזר ret;
}

صحيح
sk_load_resident_keys(ثابت حرف *pin, بنية sk_option **options,
    بنية sk_resident_key ***rksp, size_t *nrksp)
{
	صحيح ret = SSH_SK_ERR_GENERAL, r = -1;
	size_t i, nrks = 0;
	بنية sk_resident_key **rks = عدم;
	بنية sk_usbhid *sk = عدم;
	حرف *device = عدم;

	*rksp = عدم;
	*nrksp = 0;

	fido_init(SSH_FIDO_INIT_ARG);

	אם (check_sign_load_resident_options(options, &device) != 0)
		اذهب out; /* error already logged */
	אם (device != عدم)
		sk = sk_open(device);
	אחרת
		sk = sk_probe(عدم, عدم, 0, 1);
	אם (sk == عدم) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		اذهب out;
	}
	skdebug(__func__, "trying %s", sk->path);
	אם ((r = read_rks(sk, pin, &rks, &nrks)) != 0) {
		skdebug(__func__, "read_rks failed for %s", sk->path);
		ret = r;
		اذهب out;
	}
	/* success, unless we have no keys but a specific error */
	אם (nrks > 0 || ret == SSH_SK_ERR_GENERAL)
		ret = 0;
	*rksp = rks;
	*nrksp = nrks;
	rks = عدم;
	nrks = 0;
 out:
	sk_close(sk);
	עבור (i = 0; i < nrks; i++) {
		حرر(rks[i]->application);
		freezero(rks[i]->key.public_key, rks[i]->key.public_key_len);
		freezero(rks[i]->key.key_handle, rks[i]->key.key_handle_len);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i], حجم(*rks[i]));
	}
	حرر(device);
	حرر(rks);
	החזר ret;
}

#endif /* ENABLE_SK_INTERNAL */
