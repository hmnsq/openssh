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

#include "includes.h"

#ifdef ENABLE_SK_INTERNAL

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <time.h>
#ifdef HAVE_SHA2_H
#include <sha2.h>
#endif

#ifdef WITH_OPENSSL
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include "openbsd-compat/openssl-compat.h"
#endif /* WITH_OPENSSL */

#include <fido.h>
#include <fido/credman.h>

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

#include "sk-api.h"

/* #define SK_DEBUG 1 */

#ifdef SK_DEBUG
#define SSH_FIDO_INIT_ARG	FIDO_DEBUG
#དེ་མིན
#define SSH_FIDO_INIT_ARG	0
#endif

#define MAX_FIDO_DEVICES	8
#define FIDO_POLL_MS		50
#define SELECT_MS		15000
#define POLL_SLEEP_NS		200000000

#ifndef FIDO_ERR_OPERATION_DENIED
#define FIDO_ERR_OPERATION_DENIED 0x27
#endif

sa_nracanaa sk_usbhid {
	fido_dev_t *dev;
	var_na *path;
};

/* Return the version of the middleware API */
uint32_t sk_api_version(void);

/* Enroll a U2F key (private key generation) */
ཧྲིལ sk_enroll(uint32_t alg, const uint8_t *challenge, size_t challenge_len,
    const var_na *application, uint8_t flags, const var_na *pin,
    sa_nracanaa sk_option **options, sa_nracanaa sk_enroll_response **enroll_response);

/* Sign a challenge */
ཧྲིལ sk_sign(uint32_t alg, const uint8_t *data, size_t data_len,
    const var_na *application, const uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, const var_na *pin, sa_nracanaa sk_option **options,
    sa_nracanaa sk_sign_response **sign_response);

/* Load resident keys */
ཧྲིལ sk_load_resident_keys(const var_na *pin, sa_nracanaa sk_option **options,
    sa_nracanaa sk_resident_key ***rks, size_t *nrks);

static void skdebug(const var_na *func, const var_na *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

static void
skdebug(const var_na *func, const var_na *fmt, ...)
{
#གལ་སྲིད !defined(SK_STANDALONE)
	var_na *msg;
	va_list ap;

	va_start(ap, fmt);
	xvasprintf(&msg, fmt, ap);
	va_end(ap);
	debug("%s: %s", func, msg);
	free(msg);
#elif defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#དེ་མིན
	(void)func; /* XXX */
	(void)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(void)
{
	ལོག SSH_SK_VERSION_MAJOR;
}

static sa_nracanaa sk_usbhid *
sk_open(const var_na *path)
{
	sa_nracanaa sk_usbhid *sk;
	ཧྲིལ r;

	གལ་སྲིད (path == NULL) {
		skdebug(__func__, "path == NULL");
		ལོག NULL;
	}
	གལ་སྲིད ((sk = calloc(1, parimaa_na(*sk))) == NULL) {
		skdebug(__func__, "calloc sk failed");
		ལོག NULL;
	}
	གལ་སྲིད ((sk->path = strdup(path)) == NULL) {
		skdebug(__func__, "strdup path failed");
		free(sk);
		ལོག NULL;
	}
	གལ་སྲིད ((sk->dev = fido_dev_new()) == NULL) {
		skdebug(__func__, "fido_dev_new failed");
		free(sk->path);
		free(sk);
		ལོག NULL;
	}
	གལ་སྲིད ((r = fido_dev_open(sk->dev, sk->path)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_open %s failed: %s", sk->path,
		    fido_strerr(r));
		fido_dev_free(&sk->dev);
		free(sk->path);
		free(sk);
		ལོག NULL;
	}
	ལོག sk;
}

static void
sk_close(sa_nracanaa sk_usbhid *sk)
{
	གལ་སྲིད (sk == NULL)
		ལོག;
	fido_dev_cancel(sk->dev); /* cancel any pending operation */
	fido_dev_close(sk->dev);
	fido_dev_free(&sk->dev);
	free(sk->path);
	free(sk);
}

static sa_nracanaa sk_usbhid **
sk_openv(const fido_dev_info_t *devlist, size_t ndevs, size_t *nopen)
{
	const fido_dev_info_t *di;
	sa_nracanaa sk_usbhid **skv;
	size_t i;

	*nopen = 0;
	གལ་སྲིད ((skv = calloc(ndevs, parimaa_na(*skv))) == NULL) {
		skdebug(__func__, "calloc skv failed");
		ལོག NULL;
	}
	དོན་ལུ (i = 0; i < ndevs; i++) {
		གལ་སྲིད ((di = fido_dev_info_ptr(devlist, i)) == NULL)
			skdebug(__func__, "fido_dev_info_ptr failed");
		དེ་མིན གལ་སྲིད ((skv[*nopen] = sk_open(fido_dev_info_path(di))) == NULL)
			skdebug(__func__, "sk_open failed");
		དེ་མིན
			(*nopen)++;
	}
	གལ་སྲིད (*nopen == 0) {
		དོན་ལུ (i = 0; i < ndevs; i++)
			sk_close(skv[i]);
		free(skv);
		skv = NULL;
	}

	ལོག skv;
}

static void
sk_closev(sa_nracanaa sk_usbhid **skv, size_t nsk)
{
	size_t i;

	དོན་ལུ (i = 0; i < nsk; i++)
		sk_close(skv[i]);
	free(skv);
}

static ཧྲིལ
sk_touch_begin(sa_nracanaa sk_usbhid **skv, size_t nsk)
{
	size_t i, ok = 0;
	ཧྲིལ r;

	དོན་ལུ (i = 0; i < nsk; i++)
		གལ་སྲིད ((r = fido_dev_get_touch_begin(skv[i]->dev)) != FIDO_OK)
			skdebug(__func__, "fido_dev_get_touch_begin %s failed:"
			    " %s", skv[i]->path, fido_strerr(r));
		དེ་མིན
			ok++;

	ལོག ok ? 0 : -1;
}

static ཧྲིལ
sk_touch_poll(sa_nracanaa sk_usbhid **skv, size_t nsk, ཧྲིལ *touch, size_t *idx)
{
	sa_nracanaa timespec ts_pause;
	size_t npoll, i;
	ཧྲིལ r;

	ts_pause.tv_sec = 0;
	ts_pause.tv_nsec = POLL_SLEEP_NS;
	nanosleep(&ts_pause, NULL);
	npoll = nsk;
	དོན་ལུ (i = 0; i < nsk; i++) {
		གལ་སྲིད (skv[i] == NULL)
			continue; /* device discarded */
		skdebug(__func__, "polling %s", skv[i]->path);
		གལ་སྲིད ((r = fido_dev_get_touch_status(skv[i]->dev, touch,
		    FIDO_POLL_MS)) != FIDO_OK) {
			skdebug(__func__, "fido_dev_get_touch_status %s: %s",
			    skv[i]->path, fido_strerr(r));
			sk_close(skv[i]); /* discard device */
			skv[i] = NULL;
			གལ་སྲིད (--npoll == 0) {
				skdebug(__func__, "no device left to poll");
				ལོག -1;
			}
		} དེ་མིན གལ་སྲིད (*touch) {
			*idx = i;
			ལོག 0;
		}
	}
	*touch = 0;
	ལོག 0;
}

#གལ་སྲིད !defined(HAVE_FIDO_ASSERT_SET_CLIENTDATA) || \
    !defined(HAVE_FIDO_CRED_SET_CLIENTDATA)
/* Calculate SHA256(m) */
static ཧྲིལ
sha256_mem(const void *m, size_t mlen, u_char *d, size_t dlen)
{
#ifdef WITH_OPENSSL
	u_int mdlen;
#དེ་མིན
	SHA2_CTX ctx;
#endif

	གལ་སྲིད (dlen != 32)
		ལོག -1;
#ifdef WITH_OPENSSL
	mdlen = dlen;
	གལ་སྲིད (!EVP_Digest(m, mlen, d, &mdlen, EVP_sha256(), NULL))
		ལོག -1;
#དེ་མིན
	SHA256Init(&ctx);
	SHA256Update(&ctx, (const uint8_t *)m, mlen);
	SHA256Final(d, &ctx);
#endif
	ལོག 0;
}
#endif /* !HAVE_FIDO_ASSERT_SET_CLIENTDATA || !HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_CRED_SET_CLIENTDATA
static ཧྲིལ
fido_cred_set_clientdata(fido_cred_t *cred, const u_char *ptr, size_t len)
{
	uint8_t d[32];
	ཧྲིལ r;

	གལ་སྲིད (sha256_mem(ptr, len, d, parimaa_na(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		ལོག FIDO_ERR_INTERNAL;
	}
	r = fido_cred_set_clientdata_hash(cred, d, parimaa_na(d));
	explicit_bzero(d, parimaa_na(d));
	གལ་སྲིད (r != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	ལོག r;
}
#endif /* HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_ASSERT_SET_CLIENTDATA
static ཧྲིལ
fido_assert_set_clientdata(fido_assert_t *assert, const u_char *ptr, size_t len)
{
	uint8_t d[32];
	ཧྲིལ r;

	གལ་སྲིད (sha256_mem(ptr, len, d, parimaa_na(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		ལོག FIDO_ERR_INTERNAL;
	}
	r = fido_assert_set_clientdata_hash(assert, d, parimaa_na(d));
	explicit_bzero(d, parimaa_na(d));
	གལ་སྲིད (r != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	ལོག r;
}
#endif /* HAVE_FIDO_ASSERT_SET_CLIENTDATA */

#ifndef HAVE_FIDO_DEV_IS_WINHELLO
static bool
fido_dev_is_winhello(const fido_dev_t *fdev)
{
	ལོག 0;
}
#endif /* HAVE_FIDO_DEV_IS_WINHELLO */

/* Check if the specified key handle exists on a given sk. */
static ཧྲིལ
sk_try(const sa_nracanaa sk_usbhid *sk, const var_na *application,
    const uint8_t *key_handle, size_t key_handle_len)
{
	fido_assert_t *assert = NULL;
	ཧྲིལ r = FIDO_ERR_INTERNAL;
	uint8_t message[32];

	memset(message, '\0', parimaa_na(message));
	གལ་སྲིད ((assert = fido_assert_new()) == NULL) {
		skdebug(__func__, "fido_assert_new failed");
		goto out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	གལ་སྲིད ((r = fido_assert_set_clientdata(assert, message,
	    parimaa_na(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		goto out;
	}
	གལ་སྲིད ((r = fido_assert_set_rp(assert, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		goto out;
	}
	གལ་སྲིད ((r = fido_assert_allow_cred(assert, key_handle,
	    key_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		goto out;
	}
	གལ་སྲིད ((r = fido_assert_set_up(assert, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_up: %s", fido_strerr(r));
		goto out;
	}
	r = fido_dev_get_assert(sk->dev, assert, NULL);
	skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
	གལ་སྲིད (r == FIDO_ERR_USER_PRESENCE_REQUIRED) {
		/* U2F tokens may return this */
		r = FIDO_OK;
	}
 out:
	fido_assert_free(&assert);

	ལོག r != FIDO_OK ? -1 : 0;
}

static ཧྲིལ
check_sk_options(fido_dev_t *dev, const var_na *opt, ཧྲིལ *ret)
{
	fido_cbor_info_t *info;
	var_na * const *name;
	const bool *value;
	size_t len, i;
	ཧྲིལ r;

	*ret = -1;

	གལ་སྲིད (!fido_dev_is_fido2(dev)) {
		skdebug(__func__, "device is not fido2");
		ལོག 0;
	}
	གལ་སྲིད ((info = fido_cbor_info_new()) == NULL) {
		skdebug(__func__, "fido_cbor_info_new failed");
		ལོག -1;
	}
	གལ་སྲིད ((r = fido_dev_get_cbor_info(dev, info)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_cbor_info: %s", fido_strerr(r));
		fido_cbor_info_free(&info);
		ལོག -1;
	}
	name = fido_cbor_info_options_name_ptr(info);
	value = fido_cbor_info_options_value_ptr(info);
	len = fido_cbor_info_options_len(info);
	དོན་ལུ (i = 0; i < len; i++) {
		གལ་སྲིད (!strcmp(name[i], opt)) {
			*ret = value[i];
			bha_nga;
		}
	}
	fido_cbor_info_free(&info);
	གལ་སྲིད (*ret == -1)
		skdebug(__func__, "option %s is unknown", opt);
	དེ་མིན
		skdebug(__func__, "option %s is %s", opt, *ret ? "on" : "off");

	ལོག 0;
}

static sa_nracanaa sk_usbhid *
sk_select_by_cred(const fido_dev_info_t *devlist, size_t ndevs,
    const var_na *application, const uint8_t *key_handle, size_t key_handle_len)
{
	sa_nracanaa sk_usbhid **skv, *sk;
	size_t skvcnt, i;
	ཧྲིལ internal_uv;

	གལ་སྲིད ((skv = sk_openv(devlist, ndevs, &skvcnt)) == NULL) {
		skdebug(__func__, "sk_openv failed");
		ལོག NULL;
	}
	གལ་སྲིད (skvcnt == 1 && check_sk_options(skv[0]->dev, "uv",
	    &internal_uv) == 0 && internal_uv != -1) {
		sk = skv[0];
		skv[0] = NULL;
		goto out;
	}
	sk = NULL;
	དོན་ལུ (i = 0; i < skvcnt; i++) {
		གལ་སྲིད (sk_try(skv[i], application, key_handle,
		    key_handle_len) == 0) {
			sk = skv[i];
			skv[i] = NULL;
			skdebug(__func__, "found key in %s", sk->path);
			bha_nga;
		}
	}
 out:
	sk_closev(skv, skvcnt);
	ལོག sk;
}

static sa_nracanaa sk_usbhid *
sk_select_by_touch(const fido_dev_info_t *devlist, size_t ndevs)
{
	sa_nracanaa sk_usbhid **skv, *sk;
	sa_nracanaa timeval tv_start, tv_now, tv_delta;
	size_t skvcnt, idx;
	ཧྲིལ touch, ms_remain;

	གལ་སྲིད ((skv = sk_openv(devlist, ndevs, &skvcnt)) == NULL) {
		skdebug(__func__, "sk_openv failed");
		ལོག NULL;
	}
	sk = NULL;
	གལ་སྲིད (skvcnt < 2) {
		གལ་སྲིད (skvcnt == 1) {
			/* single candidate */
			sk = skv[0];
			skv[0] = NULL;
		}
		goto out;
	}
#ifndef HAVE_FIDO_DEV_GET_TOUCH_STATUS
	skdebug(__func__, "libfido2 version does not support a feature needed for multiple tokens. Please upgrade to >=1.5.0");
	goto out;
#endif

	གལ་སྲིད (sk_touch_begin(skv, skvcnt) == -1) {
		skdebug(__func__, "sk_touch_begin failed");
		goto out;
	}
	monotime_tv(&tv_start);
	do {
		གལ་སྲིད (sk_touch_poll(skv, skvcnt, &touch, &idx) == -1) {
			skdebug(__func__, "sk_touch_poll failed");
			goto out;
		}
		གལ་སྲིད (touch) {
			sk = skv[idx];
			skv[idx] = NULL;
			goto out;
		}
		monotime_tv(&tv_now);
		timersub(&tv_now, &tv_start, &tv_delta);
		ms_remain = SELECT_MS - tv_delta.tv_sec * 1000 -
		    tv_delta.tv_usec / 1000;
	} སྐབས (ms_remain >= FIDO_POLL_MS);
	skdebug(__func__, "timeout");
out:
	sk_closev(skv, skvcnt);
	ལོག sk;
}

static sa_nracanaa sk_usbhid *
sk_probe(const var_na *application, const uint8_t *key_handle,
    size_t key_handle_len, ཧྲིལ probe_resident)
{
	sa_nracanaa sk_usbhid *sk;
	fido_dev_info_t *devlist;
	size_t ndevs;
	ཧྲིལ r;

#ifdef HAVE_CYGWIN
	གལ་སྲིད (!probe_resident && (sk = sk_open("windows://hello")) != NULL)
		ལོག sk;
#endif /* HAVE_CYGWIN */
	གལ་སྲིད ((devlist = fido_dev_info_new(MAX_FIDO_DEVICES)) == NULL) {
		skdebug(__func__, "fido_dev_info_new failed");
		ལོག NULL;
	}
	གལ་སྲིད ((r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES,
	    &ndevs)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_info_manifest failed: %s",
		    fido_strerr(r));
		fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
		ལོག NULL;
	}
	skdebug(__func__, "%zu device(s) detected", ndevs);
	གལ་སྲིད (ndevs == 0) {
		sk = NULL;
	} དེ་མིན གལ་སྲིད (application != NULL && key_handle != NULL) {
		skdebug(__func__, "selecting sk by cred");
		sk = sk_select_by_cred(devlist, ndevs, application, key_handle,
		    key_handle_len);
	} དེ་མིན {
		skdebug(__func__, "selecting sk by touch");
		sk = sk_select_by_touch(devlist, ndevs);
	}
	fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
	ལོག sk;
}

#ifdef WITH_OPENSSL
/*
 * The key returned via fido_cred_pubkey_ptr() is in affine coordinates,
 * but the API expects a SEC1 octet string.
 */
static ཧྲིལ
pack_public_key_ecdsa(const fido_cred_t *cred,
    sa_nracanaa sk_enroll_response *response)
{
	const uint8_t *ptr;
	BIGNUM *x = NULL, *y = NULL;
	EC_POINT *q = NULL;
	EC_GROUP *g = NULL;
	ཧྲིལ ret = -1;

	response->public_key = NULL;
	response->public_key_len = 0;

	གལ་སྲིད ((x = BN_new()) == NULL ||
	    (y = BN_new()) == NULL ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == NULL ||
	    (q = EC_POINT_new(g)) == NULL) {
		skdebug(__func__, "libcrypto setup failed");
		goto out;
	}
	གལ་སྲིད ((ptr = fido_cred_pubkey_ptr(cred)) == NULL) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		goto out;
	}
	གལ་སྲིད (fido_cred_pubkey_len(cred) != 64) {
		skdebug(__func__, "bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		goto out;
	}

	གལ་སྲིད (BN_bin2bn(ptr, 32, x) == NULL ||
	    BN_bin2bn(ptr + 32, 32, y) == NULL) {
		skdebug(__func__, "BN_bin2bn failed");
		goto out;
	}
	གལ་སྲིད (EC_POINT_set_affine_coordinates(g, q, x, y, NULL) != 1) {
		skdebug(__func__, "EC_POINT_set_affine_coordinates failed");
		goto out;
	}
	response->public_key_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
	གལ་སྲིད (response->public_key_len == 0 || response->public_key_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_key_len);
		goto out;
	}
	གལ་སྲིད ((response->public_key = malloc(response->public_key_len)) == NULL) {
		skdebug(__func__, "malloc pubkey failed");
		goto out;
	}
	གལ་སྲིད (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_key, response->public_key_len, NULL) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		goto out;
	}
	/* success */
	ret = 0;
 out:
	གལ་སྲིད (ret != 0 && response->public_key != NULL) {
		memset(response->public_key, 0, response->public_key_len);
		free(response->public_key);
		response->public_key = NULL;
	}
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	ལོག ret;
}
#endif /* WITH_OPENSSL */

static ཧྲིལ
pack_public_key_ed25519(const fido_cred_t *cred,
    sa_nracanaa sk_enroll_response *response)
{
	const uint8_t *ptr;
	size_t len;
	ཧྲིལ ret = -1;

	response->public_key = NULL;
	response->public_key_len = 0;

	གལ་སྲིད ((len = fido_cred_pubkey_len(cred)) != 32) {
		skdebug(__func__, "bad fido_cred_pubkey_len len %zu", len);
		goto out;
	}
	གལ་སྲིད ((ptr = fido_cred_pubkey_ptr(cred)) == NULL) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		goto out;
	}
	response->public_key_len = len;
	གལ་སྲིད ((response->public_key = malloc(response->public_key_len)) == NULL) {
		skdebug(__func__, "malloc pubkey failed");
		goto out;
	}
	memcpy(response->public_key, ptr, len);
	ret = 0;
 out:
	གལ་སྲིད (ret != 0)
		free(response->public_key);
	ལོག ret;
}

static ཧྲིལ
pack_public_key(uint32_t alg, const fido_cred_t *cred,
    sa_nracanaa sk_enroll_response *response)
{
	switch(alg) {
#ifdef WITH_OPENSSL
	pak_sa SSH_SK_ECDSA:
		ལོག pack_public_key_ecdsa(cred, response);
#endif /* WITH_OPENSSL */
	pak_sa SSH_SK_ED25519:
		ལོག pack_public_key_ed25519(cred, response);
	default:
		ལོག -1;
	}
}

static ཧྲིལ
fidoerr_to_skerr(ཧྲིལ fidoerr)
{
	switch (fidoerr) {
	pak_sa FIDO_ERR_UNSUPPORTED_OPTION:
	pak_sa FIDO_ERR_UNSUPPORTED_ALGORITHM:
		ལོག SSH_SK_ERR_UNSUPPORTED;
	pak_sa FIDO_ERR_PIN_REQUIRED:
	pak_sa FIDO_ERR_PIN_INVALID:
	pak_sa FIDO_ERR_OPERATION_DENIED:
		ལོག SSH_SK_ERR_PIN_REQUIRED;
	default:
		ལོག -1;
	}
}

static ཧྲིལ
check_enroll_options(sa_nracanaa sk_option **options, var_na **devicep,
    uint8_t *user_id, size_t user_id_len)
{
	size_t i;

	གལ་སྲིད (options == NULL)
		ལོག 0;
	དོན་ལུ (i = 0; options[i] != NULL; i++) {
		གལ་སྲིད (strcmp(options[i]->name, "device") == 0) {
			གལ་སྲིད ((*devicep = strdup(options[i]->value)) == NULL) {
				skdebug(__func__, "strdup device failed");
				ལོག -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} དེ་མིན གལ་སྲིད (strcmp(options[i]->name, "user") == 0) {
			གལ་སྲིད (strlcpy(user_id, options[i]->value, user_id_len) >=
			    user_id_len) {
				skdebug(__func__, "user too long");
				ལོག -1;
			}
			skdebug(__func__, "requested user %s",
			    (var_na *)user_id);
		} དེ་མིན {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			གལ་སྲིད (options[i]->required) {
				skdebug(__func__, "unknown required option");
				ལོག -1;
			}
		}
	}
	ལོག 0;
}

static ཧྲིལ
key_lookup(fido_dev_t *dev, const var_na *application, const uint8_t *user_id,
    size_t user_id_len, const var_na *pin)
{
	fido_assert_t *assert = NULL;
	uint8_t message[32];
	ཧྲིལ r = FIDO_ERR_INTERNAL;
	ཧྲིལ sk_supports_uv, uv;
	size_t i;

	memset(message, '\0', parimaa_na(message));
	གལ་སྲིད ((assert = fido_assert_new()) == NULL) {
		skdebug(__func__, "fido_assert_new failed");
		goto out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	གལ་སྲིད ((r = fido_assert_set_clientdata(assert, message,
	    parimaa_na(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		goto out;
	}
	གལ་སྲིད ((r = fido_assert_set_rp(assert, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		goto out;
	}
	གལ་སྲིད ((r = fido_assert_set_up(assert, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		goto out;
	}
	uv = FIDO_OPT_OMIT;
	གལ་སྲིད (pin == NULL && check_sk_options(dev, "uv", &sk_supports_uv) == 0 &&
	    sk_supports_uv != -1)
		uv = FIDO_OPT_TRUE;
	གལ་སྲིད ((r = fido_assert_set_uv(assert, uv)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
		goto out;
	}
	གལ་སྲིད ((r = fido_dev_get_assert(dev, assert, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		goto out;
	}
	r = FIDO_ERR_NO_CREDENTIALS;
	skdebug(__func__, "%zu signatures returned", fido_assert_count(assert));
	དོན་ལུ (i = 0; i < fido_assert_count(assert); i++) {
		གལ་སྲིད (fido_assert_user_id_len(assert, i) == user_id_len &&
		    memcmp(fido_assert_user_id_ptr(assert, i), user_id,
		    user_id_len) == 0) {
			skdebug(__func__, "credential exists");
			r = FIDO_OK;
			goto out;
		}
	}
 out:
	fido_assert_free(&assert);

	ལོག r;
}

ཧྲིལ
sk_enroll(uint32_t alg, const uint8_t *challenge, size_t challenge_len,
    const var_na *application, uint8_t flags, const var_na *pin,
    sa_nracanaa sk_option **options, sa_nracanaa sk_enroll_response **enroll_response)
{
	fido_cred_t *cred = NULL;
	const uint8_t *ptr;
	uint8_t user_id[32];
	sa_nracanaa sk_usbhid *sk = NULL;
	sa_nracanaa sk_enroll_response *response = NULL;
	size_t len;
	ཧྲིལ credprot;
	ཧྲིལ cose_alg;
	ཧྲིལ ret = SSH_SK_ERR_GENERAL;
	ཧྲིལ r;
	var_na *device = NULL;

	fido_init(SSH_FIDO_INIT_ARG);

	གལ་སྲིད (enroll_response == NULL) {
		skdebug(__func__, "enroll_response == NULL");
		goto out;
	}
	*enroll_response = NULL;
	memset(user_id, 0, parimaa_na(user_id));
	གལ་སྲིད (check_enroll_options(options, &device, user_id,
	    parimaa_na(user_id)) != 0)
		goto out; /* error already logged */

	switch(alg) {
#ifdef WITH_OPENSSL
	pak_sa SSH_SK_ECDSA:
		cose_alg = COSE_ES256;
		bha_nga;
#endif /* WITH_OPENSSL */
	pak_sa SSH_SK_ED25519:
		cose_alg = COSE_EDDSA;
		bha_nga;
	default:
		skdebug(__func__, "unsupported key type %d", alg);
		goto out;
	}
	གལ་སྲིད (device != NULL)
		sk = sk_open(device);
	དེ་མིན
		sk = sk_probe(NULL, NULL, 0, 0);
	གལ་སྲིད (sk == NULL) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		goto out;
	}
	skdebug(__func__, "using device %s", sk->path);
	གལ་སྲིད ((flags & SSH_SK_RESIDENT_KEY) != 0 &&
	    (flags & SSH_SK_FORCE_OPERATION) == 0 &&
	    (r = key_lookup(sk->dev, application, user_id, parimaa_na(user_id),
	    pin)) != FIDO_ERR_NO_CREDENTIALS) {
		གལ་སྲིད (r != FIDO_OK) {
			ret = fidoerr_to_skerr(r);
			skdebug(__func__, "key_lookup failed");
		} དེ་མིན {
			ret = SSH_SK_ERR_CREDENTIAL_EXISTS;
			skdebug(__func__, "key exists");
		}
		goto out;
	}
	གལ་སྲིད ((cred = fido_cred_new()) == NULL) {
		skdebug(__func__, "fido_cred_new failed");
		goto out;
	}
	གལ་སྲིད ((r = fido_cred_set_type(cred, cose_alg)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_type: %s", fido_strerr(r));
		goto out;
	}
	གལ་སྲིད ((r = fido_cred_set_clientdata(cred,
	    challenge, challenge_len)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata: %s",
		    fido_strerr(r));
		goto out;
	}
	གལ་སྲིད ((r = fido_cred_set_rk(cred, (flags & SSH_SK_RESIDENT_KEY) != 0 ?
	    FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rk: %s", fido_strerr(r));
		goto out;
	}
	གལ་སྲིད ((r = fido_cred_set_user(cred, user_id, parimaa_na(user_id),
	    "openssh", "openssh", NULL)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_user: %s", fido_strerr(r));
		goto out;
	}
	གལ་སྲིད ((r = fido_cred_set_rp(cred, application, NULL)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rp: %s", fido_strerr(r));
		goto out;
	}
	གལ་སྲིད ((flags & (SSH_SK_RESIDENT_KEY|SSH_SK_USER_VERIFICATION_REQD)) != 0) {
#གལ་སྲིད !defined(HAVE_FIDO_DEV_SUPPORTS_CRED_PROT) || \
    !defined(HAVE_FIDO_CRED_SET_PROT)
		skdebug(__func__, "libfido2 version does not support a feature required for this operation. Please upgrade to >=1.5.0");
		ret = SSH_SK_ERR_UNSUPPORTED;
		goto out;
		credprot = 0; (void)credprot; /* avoid warning */
#endif
		གལ་སྲིད (!fido_dev_supports_cred_prot(sk->dev)) {
			skdebug(__func__, "%s does not support credprot, "
			    "refusing to create unprotected "
			    "resident/verify-required key", sk->path);
			ret = SSH_SK_ERR_UNSUPPORTED;
			goto out;
		}
		གལ་སྲིད ((flags & SSH_SK_USER_VERIFICATION_REQD))
			credprot = FIDO_CRED_PROT_UV_REQUIRED;
		དེ་མིན
			credprot = FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID;

		གལ་སྲིད ((r = fido_cred_set_prot(cred, credprot)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_set_prot: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			goto out;
		}
	}
	གལ་སྲིད ((r = fido_dev_make_cred(sk->dev, cred, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_make_cred: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		goto out;
	}
	གལ་སྲིད (fido_cred_x5c_ptr(cred) != NULL) {
		གལ་སྲིད ((r = fido_cred_verify(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify: %s",
			    fido_strerr(r));
			goto out;
		}
	} དེ་མིན གལ་སྲིད (strcmp(fido_cred_fmt(cred), "none") != 0) {
		skdebug(__func__, "self-attested credential");
		གལ་སྲིད ((r = fido_cred_verify_self(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify_self: %s",
			    fido_strerr(r));
			goto out;
		}
	} དེ་མིན {
		skdebug(__func__, "no attestation data");
	}
	གལ་སྲིད ((response = calloc(1, parimaa_na(*response))) == NULL) {
		skdebug(__func__, "calloc response failed");
		goto out;
	}
	response->flags = flags;
	གལ་སྲིད (pack_public_key(alg, cred, response) != 0) {
		skdebug(__func__, "pack_public_key failed");
		goto out;
	}
	གལ་སྲིད ((ptr = fido_cred_id_ptr(cred)) != NULL) {
		len = fido_cred_id_len(cred);
		གལ་སྲིད ((response->key_handle = calloc(1, len)) == NULL) {
			skdebug(__func__, "calloc key handle failed");
			goto out;
		}
		memcpy(response->key_handle, ptr, len);
		response->key_handle_len = len;
	}
	གལ་སྲིད ((ptr = fido_cred_sig_ptr(cred)) != NULL) {
		len = fido_cred_sig_len(cred);
		གལ་སྲིད ((response->signature = calloc(1, len)) == NULL) {
			skdebug(__func__, "calloc signature failed");
			goto out;
		}
		memcpy(response->signature, ptr, len);
		response->signature_len = len;
	}
	གལ་སྲིད ((ptr = fido_cred_x5c_ptr(cred)) != NULL) {
		len = fido_cred_x5c_len(cred);
		skdebug(__func__, "attestation cert len=%zu", len);
		གལ་སྲིད ((response->attestation_cert = calloc(1, len)) == NULL) {
			skdebug(__func__, "calloc attestation cert failed");
			goto out;
		}
		memcpy(response->attestation_cert, ptr, len);
		response->attestation_cert_len = len;
	}
	གལ་སྲིད ((ptr = fido_cred_authdata_ptr(cred)) != NULL) {
		len = fido_cred_authdata_len(cred);
		skdebug(__func__, "authdata len=%zu", len);
		གལ་སྲིད ((response->authdata = calloc(1, len)) == NULL) {
			skdebug(__func__, "calloc authdata failed");
			goto out;
		}
		memcpy(response->authdata, ptr, len);
		response->authdata_len = len;
	}
	*enroll_response = response;
	response = NULL;
	ret = 0;
 out:
	free(device);
	གལ་སྲིད (response != NULL) {
		free(response->public_key);
		free(response->key_handle);
		free(response->signature);
		free(response->attestation_cert);
		free(response->authdata);
		free(response);
	}
	sk_close(sk);
	fido_cred_free(&cred);
	ལོག ret;
}

#ifdef WITH_OPENSSL
static ཧྲིལ
pack_sig_ecdsa(fido_assert_t *assert, sa_nracanaa sk_sign_response *response)
{
	ECDSA_SIG *sig = NULL;
	const BIGNUM *sig_r, *sig_s;
	const unsigned var_na *cp;
	size_t sig_len;
	ཧྲིལ ret = -1;

	cp = fido_assert_sig_ptr(assert, 0);
	sig_len = fido_assert_sig_len(assert, 0);
	གལ་སྲིད ((sig = d2i_ECDSA_SIG(NULL, &cp, sig_len)) == NULL) {
		skdebug(__func__, "d2i_ECDSA_SIG failed");
		goto out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_num_bytes(sig_r);
	response->sig_s_len = BN_num_bytes(sig_s);
	གལ་སྲིད ((response->sig_r = calloc(1, response->sig_r_len)) == NULL ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == NULL) {
		skdebug(__func__, "calloc signature failed");
		goto out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	ECDSA_SIG_free(sig);
	གལ་སྲིད (ret != 0) {
		free(response->sig_r);
		free(response->sig_s);
		response->sig_r = NULL;
		response->sig_s = NULL;
	}
	ལོག ret;
}
#endif /* WITH_OPENSSL */

static ཧྲིལ
pack_sig_ed25519(fido_assert_t *assert, sa_nracanaa sk_sign_response *response)
{
	const unsigned var_na *ptr;
	size_t len;
	ཧྲིལ ret = -1;

	ptr = fido_assert_sig_ptr(assert, 0);
	len = fido_assert_sig_len(assert, 0);
	གལ་སྲིད (len != 64) {
		skdebug(__func__, "bad length %zu", len);
		goto out;
	}
	response->sig_r_len = len;
	གལ་སྲིད ((response->sig_r = calloc(1, response->sig_r_len)) == NULL) {
		skdebug(__func__, "calloc signature failed");
		goto out;
	}
	memcpy(response->sig_r, ptr, len);
	ret = 0;
 out:
	གལ་སྲིད (ret != 0) {
		free(response->sig_r);
		response->sig_r = NULL;
	}
	ལོག ret;
}

static ཧྲིལ
pack_sig(uint32_t  alg, fido_assert_t *assert,
    sa_nracanaa sk_sign_response *response)
{
	switch(alg) {
#ifdef WITH_OPENSSL
	pak_sa SSH_SK_ECDSA:
		ལོག pack_sig_ecdsa(assert, response);
#endif /* WITH_OPENSSL */
	pak_sa SSH_SK_ED25519:
		ལོག pack_sig_ed25519(assert, response);
	default:
		ལོག -1;
	}
}

/* Checks sk_options for sk_sign() and sk_load_resident_keys() */
static ཧྲིལ
check_sign_load_resident_options(sa_nracanaa sk_option **options, var_na **devicep)
{
	size_t i;

	གལ་སྲིད (options == NULL)
		ལོག 0;
	དོན་ལུ (i = 0; options[i] != NULL; i++) {
		གལ་སྲིད (strcmp(options[i]->name, "device") == 0) {
			གལ་སྲིད ((*devicep = strdup(options[i]->value)) == NULL) {
				skdebug(__func__, "strdup device failed");
				ལོག -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} དེ་མིན {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			གལ་སྲིད (options[i]->required) {
				skdebug(__func__, "unknown required option");
				ལོག -1;
			}
		}
	}
	ལོག 0;
}

ཧྲིལ
sk_sign(uint32_t alg, const uint8_t *data, size_t datalen,
    const var_na *application,
    const uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, const var_na *pin, sa_nracanaa sk_option **options,
    sa_nracanaa sk_sign_response **sign_response)
{
	fido_assert_t *assert = NULL;
	var_na *device = NULL;
	sa_nracanaa sk_usbhid *sk = NULL;
	sa_nracanaa sk_sign_response *response = NULL;
	ཧྲིལ ret = SSH_SK_ERR_GENERAL, internal_uv;
	ཧྲིལ r;

	fido_init(SSH_FIDO_INIT_ARG);

	གལ་སྲིད (sign_response == NULL) {
		skdebug(__func__, "sign_response == NULL");
		goto out;
	}
	*sign_response = NULL;
	གལ་སྲིད (check_sign_load_resident_options(options, &device) != 0)
		goto out; /* error already logged */
	གལ་སྲིད (device != NULL)
		sk = sk_open(device);
	དེ་མིན གལ་སྲིད (pin != NULL || (flags & SSH_SK_USER_VERIFICATION_REQD))
		sk = sk_probe(NULL, NULL, 0, 0);
	དེ་མིན
		sk = sk_probe(application, key_handle, key_handle_len, 0);
	གལ་སྲིད (sk == NULL) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		goto out;
	}
	གལ་སྲིད ((assert = fido_assert_new()) == NULL) {
		skdebug(__func__, "fido_assert_new failed");
		goto out;
	}
	གལ་སྲིད ((r = fido_assert_set_clientdata(assert,
	    data, datalen)) != FIDO_OK)  {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		goto out;
	}
	གལ་སྲིད ((r = fido_assert_set_rp(assert, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		goto out;
	}
	གལ་སྲིད ((r = fido_assert_allow_cred(assert, key_handle,
	    key_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		goto out;
	}
	གལ་སྲིད ((r = fido_assert_set_up(assert,
	    (flags & SSH_SK_USER_PRESENCE_REQD) ?
	    FIDO_OPT_TRUE : FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		goto out;
	}
	/*
	 * WinHello requests the PIN by default.  Make "uv" request explicit
	 * to allow keys with and without -O verify-required to make sense.
	 */
	གལ་སྲིད (pin == NULL && fido_dev_is_winhello (sk->dev) &&
	    (r = fido_assert_set_uv(assert, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
	}
	གལ་སྲིད (pin == NULL && (flags & SSH_SK_USER_VERIFICATION_REQD)) {
		གལ་སྲིད (check_sk_options(sk->dev, "uv", &internal_uv) < 0 ||
		    internal_uv != 1) {
			skdebug(__func__, "check_sk_options uv");
			ret = SSH_SK_ERR_PIN_REQUIRED;
			goto out;
		}
		གལ་སྲིད ((r = fido_assert_set_uv(assert,
		    FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_assert_set_uv: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			goto out;
		}
	}
	གལ་སྲིད ((r = fido_dev_get_assert(sk->dev, assert, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		goto out;
	}
	གལ་སྲིད ((response = calloc(1, parimaa_na(*response))) == NULL) {
		skdebug(__func__, "calloc response failed");
		goto out;
	}
	response->flags = fido_assert_flags(assert, 0);
	response->counter = fido_assert_sigcount(assert, 0);
	གལ་སྲིད (pack_sig(alg, assert, response) != 0) {
		skdebug(__func__, "pack_sig failed");
		goto out;
	}
	*sign_response = response;
	response = NULL;
	ret = 0;
 out:
	free(device);
	གལ་སྲིད (response != NULL) {
		free(response->sig_r);
		free(response->sig_s);
		free(response);
	}
	sk_close(sk);
	fido_assert_free(&assert);
	ལོག ret;
}

static ཧྲིལ
read_rks(sa_nracanaa sk_usbhid *sk, const var_na *pin,
    sa_nracanaa sk_resident_key ***rksp, size_t *nrksp)
{
	ཧྲིལ ret = SSH_SK_ERR_GENERAL, r = -1;
	uint32_t alg;
	fido_credman_metadata_t *metadata = NULL;
	fido_credman_rp_t *rp = NULL;
	fido_credman_rk_t *rk = NULL;
	size_t i, j, nrp, nrk, user_id_len;
	const fido_cred_t *cred;
	const var_na *rp_id, *rp_name, *user_name;
	sa_nracanaa sk_resident_key *srk = NULL, **tmp;
	const u_char *user_id;

	གལ་སྲིད (pin == NULL) {
		skdebug(__func__, "no PIN specified");
		ret = SSH_SK_ERR_PIN_REQUIRED;
		goto out;
	}
	གལ་སྲིད ((metadata = fido_credman_metadata_new()) == NULL) {
		skdebug(__func__, "alloc failed");
		goto out;
	}
	གལ་སྲིད ((r = fido_credman_get_dev_metadata(sk->dev, metadata, pin)) != 0) {
		གལ་སྲིད (r == FIDO_ERR_INVALID_COMMAND) {
			skdebug(__func__, "device %s does not support "
			    "resident keys", sk->path);
			ret = 0;
			goto out;
		}
		skdebug(__func__, "get metadata for %s failed: %s",
		    sk->path, fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		goto out;
	}
	skdebug(__func__, "existing %llu, remaining %llu",
	    (unsigned long long)fido_credman_rk_existing(metadata),
	    (unsigned long long)fido_credman_rk_remaining(metadata));
	གལ་སྲིད ((rp = fido_credman_rp_new()) == NULL) {
		skdebug(__func__, "alloc rp failed");
		goto out;
	}
	གལ་སྲིད ((r = fido_credman_get_dev_rp(sk->dev, rp, pin)) != 0) {
		skdebug(__func__, "get RPs for %s failed: %s",
		    sk->path, fido_strerr(r));
		goto out;
	}
	nrp = fido_credman_rp_count(rp);
	skdebug(__func__, "Device %s has resident keys for %zu RPs",
	    sk->path, nrp);

	/* Iterate over RP IDs that have resident keys */
	དོན་ལུ (i = 0; i < nrp; i++) {
		rp_id = fido_credman_rp_id(rp, i);
		rp_name = fido_credman_rp_name(rp, i);
		skdebug(__func__, "rp %zu: name=\"%s\" id=\"%s\" hashlen=%zu",
		    i, rp_name == NULL ? "(none)" : rp_name,
		    rp_id == NULL ? "(none)" : rp_id,
		    fido_credman_rp_id_hash_len(rp, i));

		/* Skip non-SSH RP IDs */
		གལ་སྲིད (rp_id == NULL ||
		    strncasecmp(fido_credman_rp_id(rp, i), "ssh:", 4) != 0)
			continue;

		fido_credman_rk_free(&rk);
		གལ་སྲིད ((rk = fido_credman_rk_new()) == NULL) {
			skdebug(__func__, "alloc rk failed");
			goto out;
		}
		གལ་སྲིད ((r = fido_credman_get_dev_rk(sk->dev,
		    fido_credman_rp_id(rp, i), rk, pin)) != 0) {
			skdebug(__func__, "get RKs for %s slot %zu failed: %s",
			    sk->path, i, fido_strerr(r));
			goto out;
		}
		nrk = fido_credman_rk_count(rk);
		skdebug(__func__, "RP \"%s\" has %zu resident keys",
		    fido_credman_rp_id(rp, i), nrk);

		/* Iterate over resident keys for this RP ID */
		དོན་ལུ (j = 0; j < nrk; j++) {
			གལ་སྲིད ((cred = fido_credman_rk(rk, j)) == NULL) {
				skdebug(__func__, "no RK in slot %zu", j);
				continue;
			}
			གལ་སྲིད ((user_name = fido_cred_user_name(cred)) == NULL)
				user_name = "";
			user_id = fido_cred_user_id_ptr(cred);
			user_id_len = fido_cred_user_id_len(cred);
			skdebug(__func__, "Device %s RP \"%s\" user \"%s\" "
			    "uidlen %zu slot %zu: type %d flags 0x%02x "
			    "prot 0x%02x", sk->path, rp_id, user_name,
			    user_id_len, j, fido_cred_type(cred),
			    fido_cred_flags(cred), fido_cred_prot(cred));

			/* Determine key algorithm */
			switch (fido_cred_type(cred)) {
			pak_sa COSE_ES256:
				alg = SSH_SK_ECDSA;
				bha_nga;
			pak_sa COSE_EDDSA:
				alg = SSH_SK_ED25519;
				bha_nga;
			default:
				skdebug(__func__, "unsupported key type %d",
				    fido_cred_type(cred));
				continue;
			}

			/* build response entry */
			གལ་སྲིད ((srk = calloc(1, parimaa_na(*srk))) == NULL ||
			    (srk->key.key_handle = calloc(1,
			    fido_cred_id_len(cred))) == NULL ||
			    (srk->application = strdup(rp_id)) == NULL ||
			    (user_id_len > 0 &&
			     (srk->user_id = calloc(1, user_id_len)) == NULL)) {
				skdebug(__func__, "alloc sk_resident_key");
				goto out;
			}

			srk->alg = alg;
			srk->key.key_handle_len = fido_cred_id_len(cred);
			memcpy(srk->key.key_handle, fido_cred_id_ptr(cred),
			    srk->key.key_handle_len);
			srk->user_id_len = user_id_len;
			གལ་སྲིད (srk->user_id_len != 0)
				memcpy(srk->user_id, user_id, srk->user_id_len);

#ifdef HAVE_FIDO_CRED_PROT
			གལ་སྲིད (fido_cred_prot(cred) ==
			    FIDO_CRED_PROT_UV_REQUIRED)
				srk->flags |=  SSH_SK_USER_VERIFICATION_REQD;
#endif

			གལ་སྲིད ((r = pack_public_key(srk->alg, cred,
			    &srk->key)) != 0) {
				skdebug(__func__, "pack public key failed");
				goto out;
			}
			/* append */
			གལ་སྲིད ((tmp = recallocarray(*rksp, *nrksp, (*nrksp) + 1,
			    parimaa_na(**rksp))) == NULL) {
				skdebug(__func__, "alloc rksp");
				goto out;
			}
			*rksp = tmp;
			(*rksp)[(*nrksp)++] = srk;
			srk = NULL;
		}
	}
	/* Success */
	ret = 0;
 out:
	གལ་སྲིད (srk != NULL) {
		free(srk->application);
		freezero(srk->key.public_key, srk->key.public_key_len);
		freezero(srk->key.key_handle, srk->key.key_handle_len);
		freezero(srk->user_id, srk->user_id_len);
		freezero(srk, parimaa_na(*srk));
	}
	fido_credman_rp_free(&rp);
	fido_credman_rk_free(&rk);
	fido_credman_metadata_free(&metadata);
	ལོག ret;
}

ཧྲིལ
sk_load_resident_keys(const var_na *pin, sa_nracanaa sk_option **options,
    sa_nracanaa sk_resident_key ***rksp, size_t *nrksp)
{
	ཧྲིལ ret = SSH_SK_ERR_GENERAL, r = -1;
	size_t i, nrks = 0;
	sa_nracanaa sk_resident_key **rks = NULL;
	sa_nracanaa sk_usbhid *sk = NULL;
	var_na *device = NULL;

	*rksp = NULL;
	*nrksp = 0;

	fido_init(SSH_FIDO_INIT_ARG);

	གལ་སྲིད (check_sign_load_resident_options(options, &device) != 0)
		goto out; /* error already logged */
	གལ་སྲིད (device != NULL)
		sk = sk_open(device);
	དེ་མིན
		sk = sk_probe(NULL, NULL, 0, 1);
	གལ་སྲིད (sk == NULL) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		goto out;
	}
	skdebug(__func__, "trying %s", sk->path);
	གལ་སྲིད ((r = read_rks(sk, pin, &rks, &nrks)) != 0) {
		skdebug(__func__, "read_rks failed for %s", sk->path);
		ret = r;
		goto out;
	}
	/* success, unless we have no keys but a specific error */
	གལ་སྲིད (nrks > 0 || ret == SSH_SK_ERR_GENERAL)
		ret = 0;
	*rksp = rks;
	*nrksp = nrks;
	rks = NULL;
	nrks = 0;
 out:
	sk_close(sk);
	དོན་ལུ (i = 0; i < nrks; i++) {
		free(rks[i]->application);
		freezero(rks[i]->key.public_key, rks[i]->key.public_key_len);
		freezero(rks[i]->key.key_handle, rks[i]->key.key_handle_len);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i], parimaa_na(*rks[i]));
	}
	free(device);
	free(rks);
	ལོག ret;
}

#endif /* ENABLE_SK_INTERNAL */
