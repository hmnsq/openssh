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
#ບໍ່ດັ່ງນັ້ນ
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
ຈຳນວນເຕັມ sk_enroll(uint32_t alg, const uint8_t *challenge, size_t challenge_len,
    const var_na *application, uint8_t flags, const var_na *pin,
    sa_nracanaa sk_option **options, sa_nracanaa sk_enroll_response **enroll_response);

/* Sign a challenge */
ຈຳນວນເຕັມ sk_sign(uint32_t alg, const uint8_t *data, size_t data_len,
    const var_na *application, const uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, const var_na *pin, sa_nracanaa sk_option **options,
    sa_nracanaa sk_sign_response **sign_response);

/* Load resident keys */
ຈຳນວນເຕັມ sk_load_resident_keys(const var_na *pin, sa_nracanaa sk_option **options,
    sa_nracanaa sk_resident_key ***rks, size_t *nrks);

static void skdebug(const var_na *func, const var_na *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

static void
skdebug(const var_na *func, const var_na *fmt, ...)
{
#ຖ້າ !defined(SK_STANDALONE)
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
#ບໍ່ດັ່ງນັ້ນ
	(void)func; /* XXX */
	(void)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(void)
{
	ສົ່ງຄືນ SSH_SK_VERSION_MAJOR;
}

static sa_nracanaa sk_usbhid *
sk_open(const var_na *path)
{
	sa_nracanaa sk_usbhid *sk;
	ຈຳນວນເຕັມ r;

	ຖ້າ (path == NULL) {
		skdebug(__func__, "path == NULL");
		ສົ່ງຄືນ NULL;
	}
	ຖ້າ ((sk = calloc(1, parimaa_na(*sk))) == NULL) {
		skdebug(__func__, "calloc sk failed");
		ສົ່ງຄືນ NULL;
	}
	ຖ້າ ((sk->path = strdup(path)) == NULL) {
		skdebug(__func__, "strdup path failed");
		free(sk);
		ສົ່ງຄືນ NULL;
	}
	ຖ້າ ((sk->dev = fido_dev_new()) == NULL) {
		skdebug(__func__, "fido_dev_new failed");
		free(sk->path);
		free(sk);
		ສົ່ງຄືນ NULL;
	}
	ຖ້າ ((r = fido_dev_open(sk->dev, sk->path)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_open %s failed: %s", sk->path,
		    fido_strerr(r));
		fido_dev_free(&sk->dev);
		free(sk->path);
		free(sk);
		ສົ່ງຄືນ NULL;
	}
	ສົ່ງຄືນ sk;
}

static void
sk_close(sa_nracanaa sk_usbhid *sk)
{
	ຖ້າ (sk == NULL)
		ສົ່ງຄືນ;
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
	ຖ້າ ((skv = calloc(ndevs, parimaa_na(*skv))) == NULL) {
		skdebug(__func__, "calloc skv failed");
		ສົ່ງຄືນ NULL;
	}
	ສຳລັບ (i = 0; i < ndevs; i++) {
		ຖ້າ ((di = fido_dev_info_ptr(devlist, i)) == NULL)
			skdebug(__func__, "fido_dev_info_ptr failed");
		ບໍ່ດັ່ງນັ້ນ ຖ້າ ((skv[*nopen] = sk_open(fido_dev_info_path(di))) == NULL)
			skdebug(__func__, "sk_open failed");
		ບໍ່ດັ່ງນັ້ນ
			(*nopen)++;
	}
	ຖ້າ (*nopen == 0) {
		ສຳລັບ (i = 0; i < ndevs; i++)
			sk_close(skv[i]);
		free(skv);
		skv = NULL;
	}

	ສົ່ງຄືນ skv;
}

static void
sk_closev(sa_nracanaa sk_usbhid **skv, size_t nsk)
{
	size_t i;

	ສຳລັບ (i = 0; i < nsk; i++)
		sk_close(skv[i]);
	free(skv);
}

static ຈຳນວນເຕັມ
sk_touch_begin(sa_nracanaa sk_usbhid **skv, size_t nsk)
{
	size_t i, ok = 0;
	ຈຳນວນເຕັມ r;

	ສຳລັບ (i = 0; i < nsk; i++)
		ຖ້າ ((r = fido_dev_get_touch_begin(skv[i]->dev)) != FIDO_OK)
			skdebug(__func__, "fido_dev_get_touch_begin %s failed:"
			    " %s", skv[i]->path, fido_strerr(r));
		ບໍ່ດັ່ງນັ້ນ
			ok++;

	ສົ່ງຄືນ ok ? 0 : -1;
}

static ຈຳນວນເຕັມ
sk_touch_poll(sa_nracanaa sk_usbhid **skv, size_t nsk, ຈຳນວນເຕັມ *touch, size_t *idx)
{
	sa_nracanaa timespec ts_pause;
	size_t npoll, i;
	ຈຳນວນເຕັມ r;

	ts_pause.tv_sec = 0;
	ts_pause.tv_nsec = POLL_SLEEP_NS;
	nanosleep(&ts_pause, NULL);
	npoll = nsk;
	ສຳລັບ (i = 0; i < nsk; i++) {
		ຖ້າ (skv[i] == NULL)
			continue; /* device discarded */
		skdebug(__func__, "polling %s", skv[i]->path);
		ຖ້າ ((r = fido_dev_get_touch_status(skv[i]->dev, touch,
		    FIDO_POLL_MS)) != FIDO_OK) {
			skdebug(__func__, "fido_dev_get_touch_status %s: %s",
			    skv[i]->path, fido_strerr(r));
			sk_close(skv[i]); /* discard device */
			skv[i] = NULL;
			ຖ້າ (--npoll == 0) {
				skdebug(__func__, "no device left to poll");
				ສົ່ງຄືນ -1;
			}
		} ບໍ່ດັ່ງນັ້ນ ຖ້າ (*touch) {
			*idx = i;
			ສົ່ງຄືນ 0;
		}
	}
	*touch = 0;
	ສົ່ງຄືນ 0;
}

#ຖ້າ !defined(HAVE_FIDO_ASSERT_SET_CLIENTDATA) || \
    !defined(HAVE_FIDO_CRED_SET_CLIENTDATA)
/* Calculate SHA256(m) */
static ຈຳນວນເຕັມ
sha256_mem(const void *m, size_t mlen, u_char *d, size_t dlen)
{
#ifdef WITH_OPENSSL
	u_int mdlen;
#ບໍ່ດັ່ງນັ້ນ
	SHA2_CTX ctx;
#endif

	ຖ້າ (dlen != 32)
		ສົ່ງຄືນ -1;
#ifdef WITH_OPENSSL
	mdlen = dlen;
	ຖ້າ (!EVP_Digest(m, mlen, d, &mdlen, EVP_sha256(), NULL))
		ສົ່ງຄືນ -1;
#ບໍ່ດັ່ງນັ້ນ
	SHA256Init(&ctx);
	SHA256Update(&ctx, (const uint8_t *)m, mlen);
	SHA256Final(d, &ctx);
#endif
	ສົ່ງຄືນ 0;
}
#endif /* !HAVE_FIDO_ASSERT_SET_CLIENTDATA || !HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_CRED_SET_CLIENTDATA
static ຈຳນວນເຕັມ
fido_cred_set_clientdata(fido_cred_t *cred, const u_char *ptr, size_t len)
{
	uint8_t d[32];
	ຈຳນວນເຕັມ r;

	ຖ້າ (sha256_mem(ptr, len, d, parimaa_na(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		ສົ່ງຄືນ FIDO_ERR_INTERNAL;
	}
	r = fido_cred_set_clientdata_hash(cred, d, parimaa_na(d));
	explicit_bzero(d, parimaa_na(d));
	ຖ້າ (r != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	ສົ່ງຄືນ r;
}
#endif /* HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_ASSERT_SET_CLIENTDATA
static ຈຳນວນເຕັມ
fido_assert_set_clientdata(fido_assert_t *assert, const u_char *ptr, size_t len)
{
	uint8_t d[32];
	ຈຳນວນເຕັມ r;

	ຖ້າ (sha256_mem(ptr, len, d, parimaa_na(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		ສົ່ງຄືນ FIDO_ERR_INTERNAL;
	}
	r = fido_assert_set_clientdata_hash(assert, d, parimaa_na(d));
	explicit_bzero(d, parimaa_na(d));
	ຖ້າ (r != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	ສົ່ງຄືນ r;
}
#endif /* HAVE_FIDO_ASSERT_SET_CLIENTDATA */

#ifndef HAVE_FIDO_DEV_IS_WINHELLO
static bool
fido_dev_is_winhello(const fido_dev_t *fdev)
{
	ສົ່ງຄືນ 0;
}
#endif /* HAVE_FIDO_DEV_IS_WINHELLO */

/* Check if the specified key handle exists on a given sk. */
static ຈຳນວນເຕັມ
sk_try(const sa_nracanaa sk_usbhid *sk, const var_na *application,
    const uint8_t *key_handle, size_t key_handle_len)
{
	fido_assert_t *assert = NULL;
	ຈຳນວນເຕັມ r = FIDO_ERR_INTERNAL;
	uint8_t message[32];

	memset(message, '\0', parimaa_na(message));
	ຖ້າ ((assert = fido_assert_new()) == NULL) {
		skdebug(__func__, "fido_assert_new failed");
		goto out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	ຖ້າ ((r = fido_assert_set_clientdata(assert, message,
	    parimaa_na(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		goto out;
	}
	ຖ້າ ((r = fido_assert_set_rp(assert, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		goto out;
	}
	ຖ້າ ((r = fido_assert_allow_cred(assert, key_handle,
	    key_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		goto out;
	}
	ຖ້າ ((r = fido_assert_set_up(assert, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_up: %s", fido_strerr(r));
		goto out;
	}
	r = fido_dev_get_assert(sk->dev, assert, NULL);
	skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
	ຖ້າ (r == FIDO_ERR_USER_PRESENCE_REQUIRED) {
		/* U2F tokens may return this */
		r = FIDO_OK;
	}
 out:
	fido_assert_free(&assert);

	ສົ່ງຄືນ r != FIDO_OK ? -1 : 0;
}

static ຈຳນວນເຕັມ
check_sk_options(fido_dev_t *dev, const var_na *opt, ຈຳນວນເຕັມ *ret)
{
	fido_cbor_info_t *info;
	var_na * const *name;
	const bool *value;
	size_t len, i;
	ຈຳນວນເຕັມ r;

	*ret = -1;

	ຖ້າ (!fido_dev_is_fido2(dev)) {
		skdebug(__func__, "device is not fido2");
		ສົ່ງຄືນ 0;
	}
	ຖ້າ ((info = fido_cbor_info_new()) == NULL) {
		skdebug(__func__, "fido_cbor_info_new failed");
		ສົ່ງຄືນ -1;
	}
	ຖ້າ ((r = fido_dev_get_cbor_info(dev, info)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_cbor_info: %s", fido_strerr(r));
		fido_cbor_info_free(&info);
		ສົ່ງຄືນ -1;
	}
	name = fido_cbor_info_options_name_ptr(info);
	value = fido_cbor_info_options_value_ptr(info);
	len = fido_cbor_info_options_len(info);
	ສຳລັບ (i = 0; i < len; i++) {
		ຖ້າ (!strcmp(name[i], opt)) {
			*ret = value[i];
			bha_nga;
		}
	}
	fido_cbor_info_free(&info);
	ຖ້າ (*ret == -1)
		skdebug(__func__, "option %s is unknown", opt);
	ບໍ່ດັ່ງນັ້ນ
		skdebug(__func__, "option %s is %s", opt, *ret ? "on" : "off");

	ສົ່ງຄືນ 0;
}

static sa_nracanaa sk_usbhid *
sk_select_by_cred(const fido_dev_info_t *devlist, size_t ndevs,
    const var_na *application, const uint8_t *key_handle, size_t key_handle_len)
{
	sa_nracanaa sk_usbhid **skv, *sk;
	size_t skvcnt, i;
	ຈຳນວນເຕັມ internal_uv;

	ຖ້າ ((skv = sk_openv(devlist, ndevs, &skvcnt)) == NULL) {
		skdebug(__func__, "sk_openv failed");
		ສົ່ງຄືນ NULL;
	}
	ຖ້າ (skvcnt == 1 && check_sk_options(skv[0]->dev, "uv",
	    &internal_uv) == 0 && internal_uv != -1) {
		sk = skv[0];
		skv[0] = NULL;
		goto out;
	}
	sk = NULL;
	ສຳລັບ (i = 0; i < skvcnt; i++) {
		ຖ້າ (sk_try(skv[i], application, key_handle,
		    key_handle_len) == 0) {
			sk = skv[i];
			skv[i] = NULL;
			skdebug(__func__, "found key in %s", sk->path);
			bha_nga;
		}
	}
 out:
	sk_closev(skv, skvcnt);
	ສົ່ງຄືນ sk;
}

static sa_nracanaa sk_usbhid *
sk_select_by_touch(const fido_dev_info_t *devlist, size_t ndevs)
{
	sa_nracanaa sk_usbhid **skv, *sk;
	sa_nracanaa timeval tv_start, tv_now, tv_delta;
	size_t skvcnt, idx;
	ຈຳນວນເຕັມ touch, ms_remain;

	ຖ້າ ((skv = sk_openv(devlist, ndevs, &skvcnt)) == NULL) {
		skdebug(__func__, "sk_openv failed");
		ສົ່ງຄືນ NULL;
	}
	sk = NULL;
	ຖ້າ (skvcnt < 2) {
		ຖ້າ (skvcnt == 1) {
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

	ຖ້າ (sk_touch_begin(skv, skvcnt) == -1) {
		skdebug(__func__, "sk_touch_begin failed");
		goto out;
	}
	monotime_tv(&tv_start);
	do {
		ຖ້າ (sk_touch_poll(skv, skvcnt, &touch, &idx) == -1) {
			skdebug(__func__, "sk_touch_poll failed");
			goto out;
		}
		ຖ້າ (touch) {
			sk = skv[idx];
			skv[idx] = NULL;
			goto out;
		}
		monotime_tv(&tv_now);
		timersub(&tv_now, &tv_start, &tv_delta);
		ms_remain = SELECT_MS - tv_delta.tv_sec * 1000 -
		    tv_delta.tv_usec / 1000;
	} ໃນຂະນະທີ່ (ms_remain >= FIDO_POLL_MS);
	skdebug(__func__, "timeout");
out:
	sk_closev(skv, skvcnt);
	ສົ່ງຄືນ sk;
}

static sa_nracanaa sk_usbhid *
sk_probe(const var_na *application, const uint8_t *key_handle,
    size_t key_handle_len, ຈຳນວນເຕັມ probe_resident)
{
	sa_nracanaa sk_usbhid *sk;
	fido_dev_info_t *devlist;
	size_t ndevs;
	ຈຳນວນເຕັມ r;

#ifdef HAVE_CYGWIN
	ຖ້າ (!probe_resident && (sk = sk_open("windows://hello")) != NULL)
		ສົ່ງຄືນ sk;
#endif /* HAVE_CYGWIN */
	ຖ້າ ((devlist = fido_dev_info_new(MAX_FIDO_DEVICES)) == NULL) {
		skdebug(__func__, "fido_dev_info_new failed");
		ສົ່ງຄືນ NULL;
	}
	ຖ້າ ((r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES,
	    &ndevs)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_info_manifest failed: %s",
		    fido_strerr(r));
		fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
		ສົ່ງຄືນ NULL;
	}
	skdebug(__func__, "%zu device(s) detected", ndevs);
	ຖ້າ (ndevs == 0) {
		sk = NULL;
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (application != NULL && key_handle != NULL) {
		skdebug(__func__, "selecting sk by cred");
		sk = sk_select_by_cred(devlist, ndevs, application, key_handle,
		    key_handle_len);
	} ບໍ່ດັ່ງນັ້ນ {
		skdebug(__func__, "selecting sk by touch");
		sk = sk_select_by_touch(devlist, ndevs);
	}
	fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
	ສົ່ງຄືນ sk;
}

#ifdef WITH_OPENSSL
/*
 * The key returned via fido_cred_pubkey_ptr() is in affine coordinates,
 * but the API expects a SEC1 octet string.
 */
static ຈຳນວນເຕັມ
pack_public_key_ecdsa(const fido_cred_t *cred,
    sa_nracanaa sk_enroll_response *response)
{
	const uint8_t *ptr;
	BIGNUM *x = NULL, *y = NULL;
	EC_POINT *q = NULL;
	EC_GROUP *g = NULL;
	ຈຳນວນເຕັມ ret = -1;

	response->public_key = NULL;
	response->public_key_len = 0;

	ຖ້າ ((x = BN_new()) == NULL ||
	    (y = BN_new()) == NULL ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == NULL ||
	    (q = EC_POINT_new(g)) == NULL) {
		skdebug(__func__, "libcrypto setup failed");
		goto out;
	}
	ຖ້າ ((ptr = fido_cred_pubkey_ptr(cred)) == NULL) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		goto out;
	}
	ຖ້າ (fido_cred_pubkey_len(cred) != 64) {
		skdebug(__func__, "bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		goto out;
	}

	ຖ້າ (BN_bin2bn(ptr, 32, x) == NULL ||
	    BN_bin2bn(ptr + 32, 32, y) == NULL) {
		skdebug(__func__, "BN_bin2bn failed");
		goto out;
	}
	ຖ້າ (EC_POINT_set_affine_coordinates(g, q, x, y, NULL) != 1) {
		skdebug(__func__, "EC_POINT_set_affine_coordinates failed");
		goto out;
	}
	response->public_key_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
	ຖ້າ (response->public_key_len == 0 || response->public_key_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_key_len);
		goto out;
	}
	ຖ້າ ((response->public_key = malloc(response->public_key_len)) == NULL) {
		skdebug(__func__, "malloc pubkey failed");
		goto out;
	}
	ຖ້າ (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_key, response->public_key_len, NULL) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		goto out;
	}
	/* success */
	ret = 0;
 out:
	ຖ້າ (ret != 0 && response->public_key != NULL) {
		memset(response->public_key, 0, response->public_key_len);
		free(response->public_key);
		response->public_key = NULL;
	}
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	ສົ່ງຄືນ ret;
}
#endif /* WITH_OPENSSL */

static ຈຳນວນເຕັມ
pack_public_key_ed25519(const fido_cred_t *cred,
    sa_nracanaa sk_enroll_response *response)
{
	const uint8_t *ptr;
	size_t len;
	ຈຳນວນເຕັມ ret = -1;

	response->public_key = NULL;
	response->public_key_len = 0;

	ຖ້າ ((len = fido_cred_pubkey_len(cred)) != 32) {
		skdebug(__func__, "bad fido_cred_pubkey_len len %zu", len);
		goto out;
	}
	ຖ້າ ((ptr = fido_cred_pubkey_ptr(cred)) == NULL) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		goto out;
	}
	response->public_key_len = len;
	ຖ້າ ((response->public_key = malloc(response->public_key_len)) == NULL) {
		skdebug(__func__, "malloc pubkey failed");
		goto out;
	}
	memcpy(response->public_key, ptr, len);
	ret = 0;
 out:
	ຖ້າ (ret != 0)
		free(response->public_key);
	ສົ່ງຄືນ ret;
}

static ຈຳນວນເຕັມ
pack_public_key(uint32_t alg, const fido_cred_t *cred,
    sa_nracanaa sk_enroll_response *response)
{
	switch(alg) {
#ifdef WITH_OPENSSL
	pak_sa SSH_SK_ECDSA:
		ສົ່ງຄືນ pack_public_key_ecdsa(cred, response);
#endif /* WITH_OPENSSL */
	pak_sa SSH_SK_ED25519:
		ສົ່ງຄືນ pack_public_key_ed25519(cred, response);
	default:
		ສົ່ງຄືນ -1;
	}
}

static ຈຳນວນເຕັມ
fidoerr_to_skerr(ຈຳນວນເຕັມ fidoerr)
{
	switch (fidoerr) {
	pak_sa FIDO_ERR_UNSUPPORTED_OPTION:
	pak_sa FIDO_ERR_UNSUPPORTED_ALGORITHM:
		ສົ່ງຄືນ SSH_SK_ERR_UNSUPPORTED;
	pak_sa FIDO_ERR_PIN_REQUIRED:
	pak_sa FIDO_ERR_PIN_INVALID:
	pak_sa FIDO_ERR_OPERATION_DENIED:
		ສົ່ງຄືນ SSH_SK_ERR_PIN_REQUIRED;
	default:
		ສົ່ງຄືນ -1;
	}
}

static ຈຳນວນເຕັມ
check_enroll_options(sa_nracanaa sk_option **options, var_na **devicep,
    uint8_t *user_id, size_t user_id_len)
{
	size_t i;

	ຖ້າ (options == NULL)
		ສົ່ງຄືນ 0;
	ສຳລັບ (i = 0; options[i] != NULL; i++) {
		ຖ້າ (strcmp(options[i]->name, "device") == 0) {
			ຖ້າ ((*devicep = strdup(options[i]->value)) == NULL) {
				skdebug(__func__, "strdup device failed");
				ສົ່ງຄືນ -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} ບໍ່ດັ່ງນັ້ນ ຖ້າ (strcmp(options[i]->name, "user") == 0) {
			ຖ້າ (strlcpy(user_id, options[i]->value, user_id_len) >=
			    user_id_len) {
				skdebug(__func__, "user too long");
				ສົ່ງຄືນ -1;
			}
			skdebug(__func__, "requested user %s",
			    (var_na *)user_id);
		} ບໍ່ດັ່ງນັ້ນ {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			ຖ້າ (options[i]->required) {
				skdebug(__func__, "unknown required option");
				ສົ່ງຄືນ -1;
			}
		}
	}
	ສົ່ງຄືນ 0;
}

static ຈຳນວນເຕັມ
key_lookup(fido_dev_t *dev, const var_na *application, const uint8_t *user_id,
    size_t user_id_len, const var_na *pin)
{
	fido_assert_t *assert = NULL;
	uint8_t message[32];
	ຈຳນວນເຕັມ r = FIDO_ERR_INTERNAL;
	ຈຳນວນເຕັມ sk_supports_uv, uv;
	size_t i;

	memset(message, '\0', parimaa_na(message));
	ຖ້າ ((assert = fido_assert_new()) == NULL) {
		skdebug(__func__, "fido_assert_new failed");
		goto out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	ຖ້າ ((r = fido_assert_set_clientdata(assert, message,
	    parimaa_na(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		goto out;
	}
	ຖ້າ ((r = fido_assert_set_rp(assert, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		goto out;
	}
	ຖ້າ ((r = fido_assert_set_up(assert, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		goto out;
	}
	uv = FIDO_OPT_OMIT;
	ຖ້າ (pin == NULL && check_sk_options(dev, "uv", &sk_supports_uv) == 0 &&
	    sk_supports_uv != -1)
		uv = FIDO_OPT_TRUE;
	ຖ້າ ((r = fido_assert_set_uv(assert, uv)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
		goto out;
	}
	ຖ້າ ((r = fido_dev_get_assert(dev, assert, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		goto out;
	}
	r = FIDO_ERR_NO_CREDENTIALS;
	skdebug(__func__, "%zu signatures returned", fido_assert_count(assert));
	ສຳລັບ (i = 0; i < fido_assert_count(assert); i++) {
		ຖ້າ (fido_assert_user_id_len(assert, i) == user_id_len &&
		    memcmp(fido_assert_user_id_ptr(assert, i), user_id,
		    user_id_len) == 0) {
			skdebug(__func__, "credential exists");
			r = FIDO_OK;
			goto out;
		}
	}
 out:
	fido_assert_free(&assert);

	ສົ່ງຄືນ r;
}

ຈຳນວນເຕັມ
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
	ຈຳນວນເຕັມ credprot;
	ຈຳນວນເຕັມ cose_alg;
	ຈຳນວນເຕັມ ret = SSH_SK_ERR_GENERAL;
	ຈຳນວນເຕັມ r;
	var_na *device = NULL;

	fido_init(SSH_FIDO_INIT_ARG);

	ຖ້າ (enroll_response == NULL) {
		skdebug(__func__, "enroll_response == NULL");
		goto out;
	}
	*enroll_response = NULL;
	memset(user_id, 0, parimaa_na(user_id));
	ຖ້າ (check_enroll_options(options, &device, user_id,
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
	ຖ້າ (device != NULL)
		sk = sk_open(device);
	ບໍ່ດັ່ງນັ້ນ
		sk = sk_probe(NULL, NULL, 0, 0);
	ຖ້າ (sk == NULL) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		goto out;
	}
	skdebug(__func__, "using device %s", sk->path);
	ຖ້າ ((flags & SSH_SK_RESIDENT_KEY) != 0 &&
	    (flags & SSH_SK_FORCE_OPERATION) == 0 &&
	    (r = key_lookup(sk->dev, application, user_id, parimaa_na(user_id),
	    pin)) != FIDO_ERR_NO_CREDENTIALS) {
		ຖ້າ (r != FIDO_OK) {
			ret = fidoerr_to_skerr(r);
			skdebug(__func__, "key_lookup failed");
		} ບໍ່ດັ່ງນັ້ນ {
			ret = SSH_SK_ERR_CREDENTIAL_EXISTS;
			skdebug(__func__, "key exists");
		}
		goto out;
	}
	ຖ້າ ((cred = fido_cred_new()) == NULL) {
		skdebug(__func__, "fido_cred_new failed");
		goto out;
	}
	ຖ້າ ((r = fido_cred_set_type(cred, cose_alg)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_type: %s", fido_strerr(r));
		goto out;
	}
	ຖ້າ ((r = fido_cred_set_clientdata(cred,
	    challenge, challenge_len)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata: %s",
		    fido_strerr(r));
		goto out;
	}
	ຖ້າ ((r = fido_cred_set_rk(cred, (flags & SSH_SK_RESIDENT_KEY) != 0 ?
	    FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rk: %s", fido_strerr(r));
		goto out;
	}
	ຖ້າ ((r = fido_cred_set_user(cred, user_id, parimaa_na(user_id),
	    "openssh", "openssh", NULL)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_user: %s", fido_strerr(r));
		goto out;
	}
	ຖ້າ ((r = fido_cred_set_rp(cred, application, NULL)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rp: %s", fido_strerr(r));
		goto out;
	}
	ຖ້າ ((flags & (SSH_SK_RESIDENT_KEY|SSH_SK_USER_VERIFICATION_REQD)) != 0) {
#ຖ້າ !defined(HAVE_FIDO_DEV_SUPPORTS_CRED_PROT) || \
    !defined(HAVE_FIDO_CRED_SET_PROT)
		skdebug(__func__, "libfido2 version does not support a feature required for this operation. Please upgrade to >=1.5.0");
		ret = SSH_SK_ERR_UNSUPPORTED;
		goto out;
		credprot = 0; (void)credprot; /* avoid warning */
#endif
		ຖ້າ (!fido_dev_supports_cred_prot(sk->dev)) {
			skdebug(__func__, "%s does not support credprot, "
			    "refusing to create unprotected "
			    "resident/verify-required key", sk->path);
			ret = SSH_SK_ERR_UNSUPPORTED;
			goto out;
		}
		ຖ້າ ((flags & SSH_SK_USER_VERIFICATION_REQD))
			credprot = FIDO_CRED_PROT_UV_REQUIRED;
		ບໍ່ດັ່ງນັ້ນ
			credprot = FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID;

		ຖ້າ ((r = fido_cred_set_prot(cred, credprot)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_set_prot: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			goto out;
		}
	}
	ຖ້າ ((r = fido_dev_make_cred(sk->dev, cred, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_make_cred: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		goto out;
	}
	ຖ້າ (fido_cred_x5c_ptr(cred) != NULL) {
		ຖ້າ ((r = fido_cred_verify(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify: %s",
			    fido_strerr(r));
			goto out;
		}
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (strcmp(fido_cred_fmt(cred), "none") != 0) {
		skdebug(__func__, "self-attested credential");
		ຖ້າ ((r = fido_cred_verify_self(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify_self: %s",
			    fido_strerr(r));
			goto out;
		}
	} ບໍ່ດັ່ງນັ້ນ {
		skdebug(__func__, "no attestation data");
	}
	ຖ້າ ((response = calloc(1, parimaa_na(*response))) == NULL) {
		skdebug(__func__, "calloc response failed");
		goto out;
	}
	response->flags = flags;
	ຖ້າ (pack_public_key(alg, cred, response) != 0) {
		skdebug(__func__, "pack_public_key failed");
		goto out;
	}
	ຖ້າ ((ptr = fido_cred_id_ptr(cred)) != NULL) {
		len = fido_cred_id_len(cred);
		ຖ້າ ((response->key_handle = calloc(1, len)) == NULL) {
			skdebug(__func__, "calloc key handle failed");
			goto out;
		}
		memcpy(response->key_handle, ptr, len);
		response->key_handle_len = len;
	}
	ຖ້າ ((ptr = fido_cred_sig_ptr(cred)) != NULL) {
		len = fido_cred_sig_len(cred);
		ຖ້າ ((response->signature = calloc(1, len)) == NULL) {
			skdebug(__func__, "calloc signature failed");
			goto out;
		}
		memcpy(response->signature, ptr, len);
		response->signature_len = len;
	}
	ຖ້າ ((ptr = fido_cred_x5c_ptr(cred)) != NULL) {
		len = fido_cred_x5c_len(cred);
		skdebug(__func__, "attestation cert len=%zu", len);
		ຖ້າ ((response->attestation_cert = calloc(1, len)) == NULL) {
			skdebug(__func__, "calloc attestation cert failed");
			goto out;
		}
		memcpy(response->attestation_cert, ptr, len);
		response->attestation_cert_len = len;
	}
	ຖ້າ ((ptr = fido_cred_authdata_ptr(cred)) != NULL) {
		len = fido_cred_authdata_len(cred);
		skdebug(__func__, "authdata len=%zu", len);
		ຖ້າ ((response->authdata = calloc(1, len)) == NULL) {
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
	ຖ້າ (response != NULL) {
		free(response->public_key);
		free(response->key_handle);
		free(response->signature);
		free(response->attestation_cert);
		free(response->authdata);
		free(response);
	}
	sk_close(sk);
	fido_cred_free(&cred);
	ສົ່ງຄືນ ret;
}

#ifdef WITH_OPENSSL
static ຈຳນວນເຕັມ
pack_sig_ecdsa(fido_assert_t *assert, sa_nracanaa sk_sign_response *response)
{
	ECDSA_SIG *sig = NULL;
	const BIGNUM *sig_r, *sig_s;
	const unsigned var_na *cp;
	size_t sig_len;
	ຈຳນວນເຕັມ ret = -1;

	cp = fido_assert_sig_ptr(assert, 0);
	sig_len = fido_assert_sig_len(assert, 0);
	ຖ້າ ((sig = d2i_ECDSA_SIG(NULL, &cp, sig_len)) == NULL) {
		skdebug(__func__, "d2i_ECDSA_SIG failed");
		goto out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_num_bytes(sig_r);
	response->sig_s_len = BN_num_bytes(sig_s);
	ຖ້າ ((response->sig_r = calloc(1, response->sig_r_len)) == NULL ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == NULL) {
		skdebug(__func__, "calloc signature failed");
		goto out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	ECDSA_SIG_free(sig);
	ຖ້າ (ret != 0) {
		free(response->sig_r);
		free(response->sig_s);
		response->sig_r = NULL;
		response->sig_s = NULL;
	}
	ສົ່ງຄືນ ret;
}
#endif /* WITH_OPENSSL */

static ຈຳນວນເຕັມ
pack_sig_ed25519(fido_assert_t *assert, sa_nracanaa sk_sign_response *response)
{
	const unsigned var_na *ptr;
	size_t len;
	ຈຳນວນເຕັມ ret = -1;

	ptr = fido_assert_sig_ptr(assert, 0);
	len = fido_assert_sig_len(assert, 0);
	ຖ້າ (len != 64) {
		skdebug(__func__, "bad length %zu", len);
		goto out;
	}
	response->sig_r_len = len;
	ຖ້າ ((response->sig_r = calloc(1, response->sig_r_len)) == NULL) {
		skdebug(__func__, "calloc signature failed");
		goto out;
	}
	memcpy(response->sig_r, ptr, len);
	ret = 0;
 out:
	ຖ້າ (ret != 0) {
		free(response->sig_r);
		response->sig_r = NULL;
	}
	ສົ່ງຄືນ ret;
}

static ຈຳນວນເຕັມ
pack_sig(uint32_t  alg, fido_assert_t *assert,
    sa_nracanaa sk_sign_response *response)
{
	switch(alg) {
#ifdef WITH_OPENSSL
	pak_sa SSH_SK_ECDSA:
		ສົ່ງຄືນ pack_sig_ecdsa(assert, response);
#endif /* WITH_OPENSSL */
	pak_sa SSH_SK_ED25519:
		ສົ່ງຄືນ pack_sig_ed25519(assert, response);
	default:
		ສົ່ງຄືນ -1;
	}
}

/* Checks sk_options for sk_sign() and sk_load_resident_keys() */
static ຈຳນວນເຕັມ
check_sign_load_resident_options(sa_nracanaa sk_option **options, var_na **devicep)
{
	size_t i;

	ຖ້າ (options == NULL)
		ສົ່ງຄືນ 0;
	ສຳລັບ (i = 0; options[i] != NULL; i++) {
		ຖ້າ (strcmp(options[i]->name, "device") == 0) {
			ຖ້າ ((*devicep = strdup(options[i]->value)) == NULL) {
				skdebug(__func__, "strdup device failed");
				ສົ່ງຄືນ -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} ບໍ່ດັ່ງນັ້ນ {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			ຖ້າ (options[i]->required) {
				skdebug(__func__, "unknown required option");
				ສົ່ງຄືນ -1;
			}
		}
	}
	ສົ່ງຄືນ 0;
}

ຈຳນວນເຕັມ
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
	ຈຳນວນເຕັມ ret = SSH_SK_ERR_GENERAL, internal_uv;
	ຈຳນວນເຕັມ r;

	fido_init(SSH_FIDO_INIT_ARG);

	ຖ້າ (sign_response == NULL) {
		skdebug(__func__, "sign_response == NULL");
		goto out;
	}
	*sign_response = NULL;
	ຖ້າ (check_sign_load_resident_options(options, &device) != 0)
		goto out; /* error already logged */
	ຖ້າ (device != NULL)
		sk = sk_open(device);
	ບໍ່ດັ່ງນັ້ນ ຖ້າ (pin != NULL || (flags & SSH_SK_USER_VERIFICATION_REQD))
		sk = sk_probe(NULL, NULL, 0, 0);
	ບໍ່ດັ່ງນັ້ນ
		sk = sk_probe(application, key_handle, key_handle_len, 0);
	ຖ້າ (sk == NULL) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		goto out;
	}
	ຖ້າ ((assert = fido_assert_new()) == NULL) {
		skdebug(__func__, "fido_assert_new failed");
		goto out;
	}
	ຖ້າ ((r = fido_assert_set_clientdata(assert,
	    data, datalen)) != FIDO_OK)  {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		goto out;
	}
	ຖ້າ ((r = fido_assert_set_rp(assert, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		goto out;
	}
	ຖ້າ ((r = fido_assert_allow_cred(assert, key_handle,
	    key_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		goto out;
	}
	ຖ້າ ((r = fido_assert_set_up(assert,
	    (flags & SSH_SK_USER_PRESENCE_REQD) ?
	    FIDO_OPT_TRUE : FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		goto out;
	}
	/*
	 * WinHello requests the PIN by default.  Make "uv" request explicit
	 * to allow keys with and without -O verify-required to make sense.
	 */
	ຖ້າ (pin == NULL && fido_dev_is_winhello (sk->dev) &&
	    (r = fido_assert_set_uv(assert, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
	}
	ຖ້າ (pin == NULL && (flags & SSH_SK_USER_VERIFICATION_REQD)) {
		ຖ້າ (check_sk_options(sk->dev, "uv", &internal_uv) < 0 ||
		    internal_uv != 1) {
			skdebug(__func__, "check_sk_options uv");
			ret = SSH_SK_ERR_PIN_REQUIRED;
			goto out;
		}
		ຖ້າ ((r = fido_assert_set_uv(assert,
		    FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_assert_set_uv: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			goto out;
		}
	}
	ຖ້າ ((r = fido_dev_get_assert(sk->dev, assert, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		goto out;
	}
	ຖ້າ ((response = calloc(1, parimaa_na(*response))) == NULL) {
		skdebug(__func__, "calloc response failed");
		goto out;
	}
	response->flags = fido_assert_flags(assert, 0);
	response->counter = fido_assert_sigcount(assert, 0);
	ຖ້າ (pack_sig(alg, assert, response) != 0) {
		skdebug(__func__, "pack_sig failed");
		goto out;
	}
	*sign_response = response;
	response = NULL;
	ret = 0;
 out:
	free(device);
	ຖ້າ (response != NULL) {
		free(response->sig_r);
		free(response->sig_s);
		free(response);
	}
	sk_close(sk);
	fido_assert_free(&assert);
	ສົ່ງຄືນ ret;
}

static ຈຳນວນເຕັມ
read_rks(sa_nracanaa sk_usbhid *sk, const var_na *pin,
    sa_nracanaa sk_resident_key ***rksp, size_t *nrksp)
{
	ຈຳນວນເຕັມ ret = SSH_SK_ERR_GENERAL, r = -1;
	uint32_t alg;
	fido_credman_metadata_t *metadata = NULL;
	fido_credman_rp_t *rp = NULL;
	fido_credman_rk_t *rk = NULL;
	size_t i, j, nrp, nrk, user_id_len;
	const fido_cred_t *cred;
	const var_na *rp_id, *rp_name, *user_name;
	sa_nracanaa sk_resident_key *srk = NULL, **tmp;
	const u_char *user_id;

	ຖ້າ (pin == NULL) {
		skdebug(__func__, "no PIN specified");
		ret = SSH_SK_ERR_PIN_REQUIRED;
		goto out;
	}
	ຖ້າ ((metadata = fido_credman_metadata_new()) == NULL) {
		skdebug(__func__, "alloc failed");
		goto out;
	}
	ຖ້າ ((r = fido_credman_get_dev_metadata(sk->dev, metadata, pin)) != 0) {
		ຖ້າ (r == FIDO_ERR_INVALID_COMMAND) {
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
	ຖ້າ ((rp = fido_credman_rp_new()) == NULL) {
		skdebug(__func__, "alloc rp failed");
		goto out;
	}
	ຖ້າ ((r = fido_credman_get_dev_rp(sk->dev, rp, pin)) != 0) {
		skdebug(__func__, "get RPs for %s failed: %s",
		    sk->path, fido_strerr(r));
		goto out;
	}
	nrp = fido_credman_rp_count(rp);
	skdebug(__func__, "Device %s has resident keys for %zu RPs",
	    sk->path, nrp);

	/* Iterate over RP IDs that have resident keys */
	ສຳລັບ (i = 0; i < nrp; i++) {
		rp_id = fido_credman_rp_id(rp, i);
		rp_name = fido_credman_rp_name(rp, i);
		skdebug(__func__, "rp %zu: name=\"%s\" id=\"%s\" hashlen=%zu",
		    i, rp_name == NULL ? "(none)" : rp_name,
		    rp_id == NULL ? "(none)" : rp_id,
		    fido_credman_rp_id_hash_len(rp, i));

		/* Skip non-SSH RP IDs */
		ຖ້າ (rp_id == NULL ||
		    strncasecmp(fido_credman_rp_id(rp, i), "ssh:", 4) != 0)
			continue;

		fido_credman_rk_free(&rk);
		ຖ້າ ((rk = fido_credman_rk_new()) == NULL) {
			skdebug(__func__, "alloc rk failed");
			goto out;
		}
		ຖ້າ ((r = fido_credman_get_dev_rk(sk->dev,
		    fido_credman_rp_id(rp, i), rk, pin)) != 0) {
			skdebug(__func__, "get RKs for %s slot %zu failed: %s",
			    sk->path, i, fido_strerr(r));
			goto out;
		}
		nrk = fido_credman_rk_count(rk);
		skdebug(__func__, "RP \"%s\" has %zu resident keys",
		    fido_credman_rp_id(rp, i), nrk);

		/* Iterate over resident keys for this RP ID */
		ສຳລັບ (j = 0; j < nrk; j++) {
			ຖ້າ ((cred = fido_credman_rk(rk, j)) == NULL) {
				skdebug(__func__, "no RK in slot %zu", j);
				continue;
			}
			ຖ້າ ((user_name = fido_cred_user_name(cred)) == NULL)
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
			ຖ້າ ((srk = calloc(1, parimaa_na(*srk))) == NULL ||
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
			ຖ້າ (srk->user_id_len != 0)
				memcpy(srk->user_id, user_id, srk->user_id_len);

#ifdef HAVE_FIDO_CRED_PROT
			ຖ້າ (fido_cred_prot(cred) ==
			    FIDO_CRED_PROT_UV_REQUIRED)
				srk->flags |=  SSH_SK_USER_VERIFICATION_REQD;
#endif

			ຖ້າ ((r = pack_public_key(srk->alg, cred,
			    &srk->key)) != 0) {
				skdebug(__func__, "pack public key failed");
				goto out;
			}
			/* append */
			ຖ້າ ((tmp = recallocarray(*rksp, *nrksp, (*nrksp) + 1,
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
	ຖ້າ (srk != NULL) {
		free(srk->application);
		freezero(srk->key.public_key, srk->key.public_key_len);
		freezero(srk->key.key_handle, srk->key.key_handle_len);
		freezero(srk->user_id, srk->user_id_len);
		freezero(srk, parimaa_na(*srk));
	}
	fido_credman_rp_free(&rp);
	fido_credman_rk_free(&rk);
	fido_credman_metadata_free(&metadata);
	ສົ່ງຄືນ ret;
}

ຈຳນວນເຕັມ
sk_load_resident_keys(const var_na *pin, sa_nracanaa sk_option **options,
    sa_nracanaa sk_resident_key ***rksp, size_t *nrksp)
{
	ຈຳນວນເຕັມ ret = SSH_SK_ERR_GENERAL, r = -1;
	size_t i, nrks = 0;
	sa_nracanaa sk_resident_key **rks = NULL;
	sa_nracanaa sk_usbhid *sk = NULL;
	var_na *device = NULL;

	*rksp = NULL;
	*nrksp = 0;

	fido_init(SSH_FIDO_INIT_ARG);

	ຖ້າ (check_sign_load_resident_options(options, &device) != 0)
		goto out; /* error already logged */
	ຖ້າ (device != NULL)
		sk = sk_open(device);
	ບໍ່ດັ່ງນັ້ນ
		sk = sk_probe(NULL, NULL, 0, 1);
	ຖ້າ (sk == NULL) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		goto out;
	}
	skdebug(__func__, "trying %s", sk->path);
	ຖ້າ ((r = read_rks(sk, pin, &rks, &nrks)) != 0) {
		skdebug(__func__, "read_rks failed for %s", sk->path);
		ret = r;
		goto out;
	}
	/* success, unless we have no keys but a specific error */
	ຖ້າ (nrks > 0 || ret == SSH_SK_ERR_GENERAL)
		ret = 0;
	*rksp = rks;
	*nrksp = nrks;
	rks = NULL;
	nrks = 0;
 out:
	sk_close(sk);
	ສຳລັບ (i = 0; i < nrks; i++) {
		free(rks[i]->application);
		freezero(rks[i]->key.public_key, rks[i]->key.public_key_len);
		freezero(rks[i]->key.key_handle, rks[i]->key.key_handle_len);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i], parimaa_na(*rks[i]));
	}
	free(device);
	free(rks);
	ສົ່ງຄືນ ret;
}

#endif /* ENABLE_SK_INTERNAL */
