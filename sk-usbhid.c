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
#아니면
#define SSH_FIDO_INIT_ARG	0
#endif

#define MAX_FIDO_DEVICES	8
#define FIDO_POLL_MS		50
#define SELECT_MS		15000
#define POLL_SLEEP_NS		200000000

#ifndef FIDO_ERR_OPERATION_DENIED
#define FIDO_ERR_OPERATION_DENIED 0x27
#endif

struct sk_usbhid {
	fido_dev_t *dev;
	char *path;
};

/* Return the version of the middleware API */
uint32_t sk_api_version(void);

/* Enroll a U2F key (private key generation) */
정수 sk_enroll(uint32_t alg, const uint8_t *challenge, size_t challenge_len,
    const char *application, uint8_t flags, const char *pin,
    struct sk_option **options, struct sk_enroll_response **enroll_response);

/* Sign a challenge */
정수 sk_sign(uint32_t alg, const uint8_t *data, size_t data_len,
    const char *application, const uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, const char *pin, struct sk_option **options,
    struct sk_sign_response **sign_response);

/* Load resident keys */
정수 sk_load_resident_keys(const char *pin, struct sk_option **options,
    struct sk_resident_key ***rks, size_t *nrks);

static void skdebug(const char *func, const char *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

static void
skdebug(const char *func, const char *fmt, ...)
{
#만약 !defined(SK_STANDALONE)
	char *msg;
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
#아니면
	(void)func; /* XXX */
	(void)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(void)
{
	반환 SSH_SK_VERSION_MAJOR;
}

static struct sk_usbhid *
sk_open(const char *path)
{
	struct sk_usbhid *sk;
	정수 r;

	만약 (path == NULL) {
		skdebug(__func__, "path == NULL");
		반환 NULL;
	}
	만약 ((sk = calloc(1, sizeof(*sk))) == NULL) {
		skdebug(__func__, "calloc sk failed");
		반환 NULL;
	}
	만약 ((sk->path = strdup(path)) == NULL) {
		skdebug(__func__, "strdup path failed");
		free(sk);
		반환 NULL;
	}
	만약 ((sk->dev = fido_dev_new()) == NULL) {
		skdebug(__func__, "fido_dev_new failed");
		free(sk->path);
		free(sk);
		반환 NULL;
	}
	만약 ((r = fido_dev_open(sk->dev, sk->path)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_open %s failed: %s", sk->path,
		    fido_strerr(r));
		fido_dev_free(&sk->dev);
		free(sk->path);
		free(sk);
		반환 NULL;
	}
	반환 sk;
}

static void
sk_close(struct sk_usbhid *sk)
{
	만약 (sk == NULL)
		반환;
	fido_dev_cancel(sk->dev); /* cancel any pending operation */
	fido_dev_close(sk->dev);
	fido_dev_free(&sk->dev);
	free(sk->path);
	free(sk);
}

static struct sk_usbhid **
sk_openv(const fido_dev_info_t *devlist, size_t ndevs, size_t *nopen)
{
	const fido_dev_info_t *di;
	struct sk_usbhid **skv;
	size_t i;

	*nopen = 0;
	만약 ((skv = calloc(ndevs, sizeof(*skv))) == NULL) {
		skdebug(__func__, "calloc skv failed");
		반환 NULL;
	}
	위해 (i = 0; i < ndevs; i++) {
		만약 ((di = fido_dev_info_ptr(devlist, i)) == NULL)
			skdebug(__func__, "fido_dev_info_ptr failed");
		아니면 만약 ((skv[*nopen] = sk_open(fido_dev_info_path(di))) == NULL)
			skdebug(__func__, "sk_open failed");
		아니면
			(*nopen)++;
	}
	만약 (*nopen == 0) {
		위해 (i = 0; i < ndevs; i++)
			sk_close(skv[i]);
		free(skv);
		skv = NULL;
	}

	반환 skv;
}

static void
sk_closev(struct sk_usbhid **skv, size_t nsk)
{
	size_t i;

	위해 (i = 0; i < nsk; i++)
		sk_close(skv[i]);
	free(skv);
}

static 정수
sk_touch_begin(struct sk_usbhid **skv, size_t nsk)
{
	size_t i, ok = 0;
	정수 r;

	위해 (i = 0; i < nsk; i++)
		만약 ((r = fido_dev_get_touch_begin(skv[i]->dev)) != FIDO_OK)
			skdebug(__func__, "fido_dev_get_touch_begin %s failed:"
			    " %s", skv[i]->path, fido_strerr(r));
		아니면
			ok++;

	반환 ok ? 0 : -1;
}

static 정수
sk_touch_poll(struct sk_usbhid **skv, size_t nsk, 정수 *touch, size_t *idx)
{
	struct timespec ts_pause;
	size_t npoll, i;
	정수 r;

	ts_pause.tv_sec = 0;
	ts_pause.tv_nsec = POLL_SLEEP_NS;
	nanosleep(&ts_pause, NULL);
	npoll = nsk;
	위해 (i = 0; i < nsk; i++) {
		만약 (skv[i] == NULL)
			continue; /* device discarded */
		skdebug(__func__, "polling %s", skv[i]->path);
		만약 ((r = fido_dev_get_touch_status(skv[i]->dev, touch,
		    FIDO_POLL_MS)) != FIDO_OK) {
			skdebug(__func__, "fido_dev_get_touch_status %s: %s",
			    skv[i]->path, fido_strerr(r));
			sk_close(skv[i]); /* discard device */
			skv[i] = NULL;
			만약 (--npoll == 0) {
				skdebug(__func__, "no device left to poll");
				반환 -1;
			}
		} 아니면 만약 (*touch) {
			*idx = i;
			반환 0;
		}
	}
	*touch = 0;
	반환 0;
}

#만약 !defined(HAVE_FIDO_ASSERT_SET_CLIENTDATA) || \
    !defined(HAVE_FIDO_CRED_SET_CLIENTDATA)
/* Calculate SHA256(m) */
static 정수
sha256_mem(const void *m, size_t mlen, u_char *d, size_t dlen)
{
#ifdef WITH_OPENSSL
	u_int mdlen;
#아니면
	SHA2_CTX ctx;
#endif

	만약 (dlen != 32)
		반환 -1;
#ifdef WITH_OPENSSL
	mdlen = dlen;
	만약 (!EVP_Digest(m, mlen, d, &mdlen, EVP_sha256(), NULL))
		반환 -1;
#아니면
	SHA256Init(&ctx);
	SHA256Update(&ctx, (const uint8_t *)m, mlen);
	SHA256Final(d, &ctx);
#endif
	반환 0;
}
#endif /* !HAVE_FIDO_ASSERT_SET_CLIENTDATA || !HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_CRED_SET_CLIENTDATA
static 정수
fido_cred_set_clientdata(fido_cred_t *cred, const u_char *ptr, size_t len)
{
	uint8_t d[32];
	정수 r;

	만약 (sha256_mem(ptr, len, d, sizeof(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		반환 FIDO_ERR_INTERNAL;
	}
	r = fido_cred_set_clientdata_hash(cred, d, sizeof(d));
	explicit_bzero(d, sizeof(d));
	만약 (r != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	반환 r;
}
#endif /* HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_ASSERT_SET_CLIENTDATA
static 정수
fido_assert_set_clientdata(fido_assert_t *assert, const u_char *ptr, size_t len)
{
	uint8_t d[32];
	정수 r;

	만약 (sha256_mem(ptr, len, d, sizeof(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		반환 FIDO_ERR_INTERNAL;
	}
	r = fido_assert_set_clientdata_hash(assert, d, sizeof(d));
	explicit_bzero(d, sizeof(d));
	만약 (r != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	반환 r;
}
#endif /* HAVE_FIDO_ASSERT_SET_CLIENTDATA */

#ifndef HAVE_FIDO_DEV_IS_WINHELLO
static bool
fido_dev_is_winhello(const fido_dev_t *fdev)
{
	반환 0;
}
#endif /* HAVE_FIDO_DEV_IS_WINHELLO */

/* Check if the specified key handle exists on a given sk. */
static 정수
sk_try(const struct sk_usbhid *sk, const char *application,
    const uint8_t *key_handle, size_t key_handle_len)
{
	fido_assert_t *assert = NULL;
	정수 r = FIDO_ERR_INTERNAL;
	uint8_t message[32];

	memset(message, '\0', sizeof(message));
	만약 ((assert = fido_assert_new()) == NULL) {
		skdebug(__func__, "fido_assert_new failed");
		goto out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	만약 ((r = fido_assert_set_clientdata(assert, message,
	    sizeof(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		goto out;
	}
	만약 ((r = fido_assert_set_rp(assert, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		goto out;
	}
	만약 ((r = fido_assert_allow_cred(assert, key_handle,
	    key_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		goto out;
	}
	만약 ((r = fido_assert_set_up(assert, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_up: %s", fido_strerr(r));
		goto out;
	}
	r = fido_dev_get_assert(sk->dev, assert, NULL);
	skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
	만약 (r == FIDO_ERR_USER_PRESENCE_REQUIRED) {
		/* U2F tokens may return this */
		r = FIDO_OK;
	}
 out:
	fido_assert_free(&assert);

	반환 r != FIDO_OK ? -1 : 0;
}

static 정수
check_sk_options(fido_dev_t *dev, const char *opt, 정수 *ret)
{
	fido_cbor_info_t *info;
	char * const *name;
	const bool *value;
	size_t len, i;
	정수 r;

	*ret = -1;

	만약 (!fido_dev_is_fido2(dev)) {
		skdebug(__func__, "device is not fido2");
		반환 0;
	}
	만약 ((info = fido_cbor_info_new()) == NULL) {
		skdebug(__func__, "fido_cbor_info_new failed");
		반환 -1;
	}
	만약 ((r = fido_dev_get_cbor_info(dev, info)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_cbor_info: %s", fido_strerr(r));
		fido_cbor_info_free(&info);
		반환 -1;
	}
	name = fido_cbor_info_options_name_ptr(info);
	value = fido_cbor_info_options_value_ptr(info);
	len = fido_cbor_info_options_len(info);
	위해 (i = 0; i < len; i++) {
		만약 (!strcmp(name[i], opt)) {
			*ret = value[i];
			break;
		}
	}
	fido_cbor_info_free(&info);
	만약 (*ret == -1)
		skdebug(__func__, "option %s is unknown", opt);
	아니면
		skdebug(__func__, "option %s is %s", opt, *ret ? "on" : "off");

	반환 0;
}

static struct sk_usbhid *
sk_select_by_cred(const fido_dev_info_t *devlist, size_t ndevs,
    const char *application, const uint8_t *key_handle, size_t key_handle_len)
{
	struct sk_usbhid **skv, *sk;
	size_t skvcnt, i;
	정수 internal_uv;

	만약 ((skv = sk_openv(devlist, ndevs, &skvcnt)) == NULL) {
		skdebug(__func__, "sk_openv failed");
		반환 NULL;
	}
	만약 (skvcnt == 1 && check_sk_options(skv[0]->dev, "uv",
	    &internal_uv) == 0 && internal_uv != -1) {
		sk = skv[0];
		skv[0] = NULL;
		goto out;
	}
	sk = NULL;
	위해 (i = 0; i < skvcnt; i++) {
		만약 (sk_try(skv[i], application, key_handle,
		    key_handle_len) == 0) {
			sk = skv[i];
			skv[i] = NULL;
			skdebug(__func__, "found key in %s", sk->path);
			break;
		}
	}
 out:
	sk_closev(skv, skvcnt);
	반환 sk;
}

static struct sk_usbhid *
sk_select_by_touch(const fido_dev_info_t *devlist, size_t ndevs)
{
	struct sk_usbhid **skv, *sk;
	struct timeval tv_start, tv_now, tv_delta;
	size_t skvcnt, idx;
	정수 touch, ms_remain;

	만약 ((skv = sk_openv(devlist, ndevs, &skvcnt)) == NULL) {
		skdebug(__func__, "sk_openv failed");
		반환 NULL;
	}
	sk = NULL;
	만약 (skvcnt < 2) {
		만약 (skvcnt == 1) {
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

	만약 (sk_touch_begin(skv, skvcnt) == -1) {
		skdebug(__func__, "sk_touch_begin failed");
		goto out;
	}
	monotime_tv(&tv_start);
	do {
		만약 (sk_touch_poll(skv, skvcnt, &touch, &idx) == -1) {
			skdebug(__func__, "sk_touch_poll failed");
			goto out;
		}
		만약 (touch) {
			sk = skv[idx];
			skv[idx] = NULL;
			goto out;
		}
		monotime_tv(&tv_now);
		timersub(&tv_now, &tv_start, &tv_delta);
		ms_remain = SELECT_MS - tv_delta.tv_sec * 1000 -
		    tv_delta.tv_usec / 1000;
	} 동안 (ms_remain >= FIDO_POLL_MS);
	skdebug(__func__, "timeout");
out:
	sk_closev(skv, skvcnt);
	반환 sk;
}

static struct sk_usbhid *
sk_probe(const char *application, const uint8_t *key_handle,
    size_t key_handle_len, 정수 probe_resident)
{
	struct sk_usbhid *sk;
	fido_dev_info_t *devlist;
	size_t ndevs;
	정수 r;

#ifdef HAVE_CYGWIN
	만약 (!probe_resident && (sk = sk_open("windows://hello")) != NULL)
		반환 sk;
#endif /* HAVE_CYGWIN */
	만약 ((devlist = fido_dev_info_new(MAX_FIDO_DEVICES)) == NULL) {
		skdebug(__func__, "fido_dev_info_new failed");
		반환 NULL;
	}
	만약 ((r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES,
	    &ndevs)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_info_manifest failed: %s",
		    fido_strerr(r));
		fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
		반환 NULL;
	}
	skdebug(__func__, "%zu device(s) detected", ndevs);
	만약 (ndevs == 0) {
		sk = NULL;
	} 아니면 만약 (application != NULL && key_handle != NULL) {
		skdebug(__func__, "selecting sk by cred");
		sk = sk_select_by_cred(devlist, ndevs, application, key_handle,
		    key_handle_len);
	} 아니면 {
		skdebug(__func__, "selecting sk by touch");
		sk = sk_select_by_touch(devlist, ndevs);
	}
	fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
	반환 sk;
}

#ifdef WITH_OPENSSL
/*
 * The key returned via fido_cred_pubkey_ptr() is in affine coordinates,
 * but the API expects a SEC1 octet string.
 */
static 정수
pack_public_key_ecdsa(const fido_cred_t *cred,
    struct sk_enroll_response *response)
{
	const uint8_t *ptr;
	BIGNUM *x = NULL, *y = NULL;
	EC_POINT *q = NULL;
	EC_GROUP *g = NULL;
	정수 ret = -1;

	response->public_key = NULL;
	response->public_key_len = 0;

	만약 ((x = BN_new()) == NULL ||
	    (y = BN_new()) == NULL ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == NULL ||
	    (q = EC_POINT_new(g)) == NULL) {
		skdebug(__func__, "libcrypto setup failed");
		goto out;
	}
	만약 ((ptr = fido_cred_pubkey_ptr(cred)) == NULL) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		goto out;
	}
	만약 (fido_cred_pubkey_len(cred) != 64) {
		skdebug(__func__, "bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		goto out;
	}

	만약 (BN_bin2bn(ptr, 32, x) == NULL ||
	    BN_bin2bn(ptr + 32, 32, y) == NULL) {
		skdebug(__func__, "BN_bin2bn failed");
		goto out;
	}
	만약 (EC_POINT_set_affine_coordinates(g, q, x, y, NULL) != 1) {
		skdebug(__func__, "EC_POINT_set_affine_coordinates failed");
		goto out;
	}
	response->public_key_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
	만약 (response->public_key_len == 0 || response->public_key_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_key_len);
		goto out;
	}
	만약 ((response->public_key = malloc(response->public_key_len)) == NULL) {
		skdebug(__func__, "malloc pubkey failed");
		goto out;
	}
	만약 (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_key, response->public_key_len, NULL) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		goto out;
	}
	/* success */
	ret = 0;
 out:
	만약 (ret != 0 && response->public_key != NULL) {
		memset(response->public_key, 0, response->public_key_len);
		free(response->public_key);
		response->public_key = NULL;
	}
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	반환 ret;
}
#endif /* WITH_OPENSSL */

static 정수
pack_public_key_ed25519(const fido_cred_t *cred,
    struct sk_enroll_response *response)
{
	const uint8_t *ptr;
	size_t len;
	정수 ret = -1;

	response->public_key = NULL;
	response->public_key_len = 0;

	만약 ((len = fido_cred_pubkey_len(cred)) != 32) {
		skdebug(__func__, "bad fido_cred_pubkey_len len %zu", len);
		goto out;
	}
	만약 ((ptr = fido_cred_pubkey_ptr(cred)) == NULL) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		goto out;
	}
	response->public_key_len = len;
	만약 ((response->public_key = malloc(response->public_key_len)) == NULL) {
		skdebug(__func__, "malloc pubkey failed");
		goto out;
	}
	memcpy(response->public_key, ptr, len);
	ret = 0;
 out:
	만약 (ret != 0)
		free(response->public_key);
	반환 ret;
}

static 정수
pack_public_key(uint32_t alg, const fido_cred_t *cred,
    struct sk_enroll_response *response)
{
	switch(alg) {
#ifdef WITH_OPENSSL
	case SSH_SK_ECDSA:
		반환 pack_public_key_ecdsa(cred, response);
#endif /* WITH_OPENSSL */
	case SSH_SK_ED25519:
		반환 pack_public_key_ed25519(cred, response);
	default:
		반환 -1;
	}
}

static 정수
fidoerr_to_skerr(정수 fidoerr)
{
	switch (fidoerr) {
	case FIDO_ERR_UNSUPPORTED_OPTION:
	case FIDO_ERR_UNSUPPORTED_ALGORITHM:
		반환 SSH_SK_ERR_UNSUPPORTED;
	case FIDO_ERR_PIN_REQUIRED:
	case FIDO_ERR_PIN_INVALID:
	case FIDO_ERR_OPERATION_DENIED:
		반환 SSH_SK_ERR_PIN_REQUIRED;
	default:
		반환 -1;
	}
}

static 정수
check_enroll_options(struct sk_option **options, char **devicep,
    uint8_t *user_id, size_t user_id_len)
{
	size_t i;

	만약 (options == NULL)
		반환 0;
	위해 (i = 0; options[i] != NULL; i++) {
		만약 (strcmp(options[i]->name, "device") == 0) {
			만약 ((*devicep = strdup(options[i]->value)) == NULL) {
				skdebug(__func__, "strdup device failed");
				반환 -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} 아니면 만약 (strcmp(options[i]->name, "user") == 0) {
			만약 (strlcpy(user_id, options[i]->value, user_id_len) >=
			    user_id_len) {
				skdebug(__func__, "user too long");
				반환 -1;
			}
			skdebug(__func__, "requested user %s",
			    (char *)user_id);
		} 아니면 {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			만약 (options[i]->required) {
				skdebug(__func__, "unknown required option");
				반환 -1;
			}
		}
	}
	반환 0;
}

static 정수
key_lookup(fido_dev_t *dev, const char *application, const uint8_t *user_id,
    size_t user_id_len, const char *pin)
{
	fido_assert_t *assert = NULL;
	uint8_t message[32];
	정수 r = FIDO_ERR_INTERNAL;
	정수 sk_supports_uv, uv;
	size_t i;

	memset(message, '\0', sizeof(message));
	만약 ((assert = fido_assert_new()) == NULL) {
		skdebug(__func__, "fido_assert_new failed");
		goto out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	만약 ((r = fido_assert_set_clientdata(assert, message,
	    sizeof(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		goto out;
	}
	만약 ((r = fido_assert_set_rp(assert, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		goto out;
	}
	만약 ((r = fido_assert_set_up(assert, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		goto out;
	}
	uv = FIDO_OPT_OMIT;
	만약 (pin == NULL && check_sk_options(dev, "uv", &sk_supports_uv) == 0 &&
	    sk_supports_uv != -1)
		uv = FIDO_OPT_TRUE;
	만약 ((r = fido_assert_set_uv(assert, uv)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
		goto out;
	}
	만약 ((r = fido_dev_get_assert(dev, assert, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		goto out;
	}
	r = FIDO_ERR_NO_CREDENTIALS;
	skdebug(__func__, "%zu signatures returned", fido_assert_count(assert));
	위해 (i = 0; i < fido_assert_count(assert); i++) {
		만약 (fido_assert_user_id_len(assert, i) == user_id_len &&
		    memcmp(fido_assert_user_id_ptr(assert, i), user_id,
		    user_id_len) == 0) {
			skdebug(__func__, "credential exists");
			r = FIDO_OK;
			goto out;
		}
	}
 out:
	fido_assert_free(&assert);

	반환 r;
}

정수
sk_enroll(uint32_t alg, const uint8_t *challenge, size_t challenge_len,
    const char *application, uint8_t flags, const char *pin,
    struct sk_option **options, struct sk_enroll_response **enroll_response)
{
	fido_cred_t *cred = NULL;
	const uint8_t *ptr;
	uint8_t user_id[32];
	struct sk_usbhid *sk = NULL;
	struct sk_enroll_response *response = NULL;
	size_t len;
	정수 credprot;
	정수 cose_alg;
	정수 ret = SSH_SK_ERR_GENERAL;
	정수 r;
	char *device = NULL;

	fido_init(SSH_FIDO_INIT_ARG);

	만약 (enroll_response == NULL) {
		skdebug(__func__, "enroll_response == NULL");
		goto out;
	}
	*enroll_response = NULL;
	memset(user_id, 0, sizeof(user_id));
	만약 (check_enroll_options(options, &device, user_id,
	    sizeof(user_id)) != 0)
		goto out; /* error already logged */

	switch(alg) {
#ifdef WITH_OPENSSL
	case SSH_SK_ECDSA:
		cose_alg = COSE_ES256;
		break;
#endif /* WITH_OPENSSL */
	case SSH_SK_ED25519:
		cose_alg = COSE_EDDSA;
		break;
	default:
		skdebug(__func__, "unsupported key type %d", alg);
		goto out;
	}
	만약 (device != NULL)
		sk = sk_open(device);
	아니면
		sk = sk_probe(NULL, NULL, 0, 0);
	만약 (sk == NULL) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		goto out;
	}
	skdebug(__func__, "using device %s", sk->path);
	만약 ((flags & SSH_SK_RESIDENT_KEY) != 0 &&
	    (flags & SSH_SK_FORCE_OPERATION) == 0 &&
	    (r = key_lookup(sk->dev, application, user_id, sizeof(user_id),
	    pin)) != FIDO_ERR_NO_CREDENTIALS) {
		만약 (r != FIDO_OK) {
			ret = fidoerr_to_skerr(r);
			skdebug(__func__, "key_lookup failed");
		} 아니면 {
			ret = SSH_SK_ERR_CREDENTIAL_EXISTS;
			skdebug(__func__, "key exists");
		}
		goto out;
	}
	만약 ((cred = fido_cred_new()) == NULL) {
		skdebug(__func__, "fido_cred_new failed");
		goto out;
	}
	만약 ((r = fido_cred_set_type(cred, cose_alg)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_type: %s", fido_strerr(r));
		goto out;
	}
	만약 ((r = fido_cred_set_clientdata(cred,
	    challenge, challenge_len)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata: %s",
		    fido_strerr(r));
		goto out;
	}
	만약 ((r = fido_cred_set_rk(cred, (flags & SSH_SK_RESIDENT_KEY) != 0 ?
	    FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rk: %s", fido_strerr(r));
		goto out;
	}
	만약 ((r = fido_cred_set_user(cred, user_id, sizeof(user_id),
	    "openssh", "openssh", NULL)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_user: %s", fido_strerr(r));
		goto out;
	}
	만약 ((r = fido_cred_set_rp(cred, application, NULL)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rp: %s", fido_strerr(r));
		goto out;
	}
	만약 ((flags & (SSH_SK_RESIDENT_KEY|SSH_SK_USER_VERIFICATION_REQD)) != 0) {
#만약 !defined(HAVE_FIDO_DEV_SUPPORTS_CRED_PROT) || \
    !defined(HAVE_FIDO_CRED_SET_PROT)
		skdebug(__func__, "libfido2 version does not support a feature required for this operation. Please upgrade to >=1.5.0");
		ret = SSH_SK_ERR_UNSUPPORTED;
		goto out;
		credprot = 0; (void)credprot; /* avoid warning */
#endif
		만약 (!fido_dev_supports_cred_prot(sk->dev)) {
			skdebug(__func__, "%s does not support credprot, "
			    "refusing to create unprotected "
			    "resident/verify-required key", sk->path);
			ret = SSH_SK_ERR_UNSUPPORTED;
			goto out;
		}
		만약 ((flags & SSH_SK_USER_VERIFICATION_REQD))
			credprot = FIDO_CRED_PROT_UV_REQUIRED;
		아니면
			credprot = FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID;

		만약 ((r = fido_cred_set_prot(cred, credprot)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_set_prot: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			goto out;
		}
	}
	만약 ((r = fido_dev_make_cred(sk->dev, cred, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_make_cred: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		goto out;
	}
	만약 (fido_cred_x5c_ptr(cred) != NULL) {
		만약 ((r = fido_cred_verify(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify: %s",
			    fido_strerr(r));
			goto out;
		}
	} 아니면 만약 (strcmp(fido_cred_fmt(cred), "none") != 0) {
		skdebug(__func__, "self-attested credential");
		만약 ((r = fido_cred_verify_self(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify_self: %s",
			    fido_strerr(r));
			goto out;
		}
	} 아니면 {
		skdebug(__func__, "no attestation data");
	}
	만약 ((response = calloc(1, sizeof(*response))) == NULL) {
		skdebug(__func__, "calloc response failed");
		goto out;
	}
	response->flags = flags;
	만약 (pack_public_key(alg, cred, response) != 0) {
		skdebug(__func__, "pack_public_key failed");
		goto out;
	}
	만약 ((ptr = fido_cred_id_ptr(cred)) != NULL) {
		len = fido_cred_id_len(cred);
		만약 ((response->key_handle = calloc(1, len)) == NULL) {
			skdebug(__func__, "calloc key handle failed");
			goto out;
		}
		memcpy(response->key_handle, ptr, len);
		response->key_handle_len = len;
	}
	만약 ((ptr = fido_cred_sig_ptr(cred)) != NULL) {
		len = fido_cred_sig_len(cred);
		만약 ((response->signature = calloc(1, len)) == NULL) {
			skdebug(__func__, "calloc signature failed");
			goto out;
		}
		memcpy(response->signature, ptr, len);
		response->signature_len = len;
	}
	만약 ((ptr = fido_cred_x5c_ptr(cred)) != NULL) {
		len = fido_cred_x5c_len(cred);
		skdebug(__func__, "attestation cert len=%zu", len);
		만약 ((response->attestation_cert = calloc(1, len)) == NULL) {
			skdebug(__func__, "calloc attestation cert failed");
			goto out;
		}
		memcpy(response->attestation_cert, ptr, len);
		response->attestation_cert_len = len;
	}
	만약 ((ptr = fido_cred_authdata_ptr(cred)) != NULL) {
		len = fido_cred_authdata_len(cred);
		skdebug(__func__, "authdata len=%zu", len);
		만약 ((response->authdata = calloc(1, len)) == NULL) {
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
	만약 (response != NULL) {
		free(response->public_key);
		free(response->key_handle);
		free(response->signature);
		free(response->attestation_cert);
		free(response->authdata);
		free(response);
	}
	sk_close(sk);
	fido_cred_free(&cred);
	반환 ret;
}

#ifdef WITH_OPENSSL
static 정수
pack_sig_ecdsa(fido_assert_t *assert, struct sk_sign_response *response)
{
	ECDSA_SIG *sig = NULL;
	const BIGNUM *sig_r, *sig_s;
	const unsigned char *cp;
	size_t sig_len;
	정수 ret = -1;

	cp = fido_assert_sig_ptr(assert, 0);
	sig_len = fido_assert_sig_len(assert, 0);
	만약 ((sig = d2i_ECDSA_SIG(NULL, &cp, sig_len)) == NULL) {
		skdebug(__func__, "d2i_ECDSA_SIG failed");
		goto out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_num_bytes(sig_r);
	response->sig_s_len = BN_num_bytes(sig_s);
	만약 ((response->sig_r = calloc(1, response->sig_r_len)) == NULL ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == NULL) {
		skdebug(__func__, "calloc signature failed");
		goto out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	ECDSA_SIG_free(sig);
	만약 (ret != 0) {
		free(response->sig_r);
		free(response->sig_s);
		response->sig_r = NULL;
		response->sig_s = NULL;
	}
	반환 ret;
}
#endif /* WITH_OPENSSL */

static 정수
pack_sig_ed25519(fido_assert_t *assert, struct sk_sign_response *response)
{
	const unsigned char *ptr;
	size_t len;
	정수 ret = -1;

	ptr = fido_assert_sig_ptr(assert, 0);
	len = fido_assert_sig_len(assert, 0);
	만약 (len != 64) {
		skdebug(__func__, "bad length %zu", len);
		goto out;
	}
	response->sig_r_len = len;
	만약 ((response->sig_r = calloc(1, response->sig_r_len)) == NULL) {
		skdebug(__func__, "calloc signature failed");
		goto out;
	}
	memcpy(response->sig_r, ptr, len);
	ret = 0;
 out:
	만약 (ret != 0) {
		free(response->sig_r);
		response->sig_r = NULL;
	}
	반환 ret;
}

static 정수
pack_sig(uint32_t  alg, fido_assert_t *assert,
    struct sk_sign_response *response)
{
	switch(alg) {
#ifdef WITH_OPENSSL
	case SSH_SK_ECDSA:
		반환 pack_sig_ecdsa(assert, response);
#endif /* WITH_OPENSSL */
	case SSH_SK_ED25519:
		반환 pack_sig_ed25519(assert, response);
	default:
		반환 -1;
	}
}

/* Checks sk_options for sk_sign() and sk_load_resident_keys() */
static 정수
check_sign_load_resident_options(struct sk_option **options, char **devicep)
{
	size_t i;

	만약 (options == NULL)
		반환 0;
	위해 (i = 0; options[i] != NULL; i++) {
		만약 (strcmp(options[i]->name, "device") == 0) {
			만약 ((*devicep = strdup(options[i]->value)) == NULL) {
				skdebug(__func__, "strdup device failed");
				반환 -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} 아니면 {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			만약 (options[i]->required) {
				skdebug(__func__, "unknown required option");
				반환 -1;
			}
		}
	}
	반환 0;
}

정수
sk_sign(uint32_t alg, const uint8_t *data, size_t datalen,
    const char *application,
    const uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, const char *pin, struct sk_option **options,
    struct sk_sign_response **sign_response)
{
	fido_assert_t *assert = NULL;
	char *device = NULL;
	struct sk_usbhid *sk = NULL;
	struct sk_sign_response *response = NULL;
	정수 ret = SSH_SK_ERR_GENERAL, internal_uv;
	정수 r;

	fido_init(SSH_FIDO_INIT_ARG);

	만약 (sign_response == NULL) {
		skdebug(__func__, "sign_response == NULL");
		goto out;
	}
	*sign_response = NULL;
	만약 (check_sign_load_resident_options(options, &device) != 0)
		goto out; /* error already logged */
	만약 (device != NULL)
		sk = sk_open(device);
	아니면 만약 (pin != NULL || (flags & SSH_SK_USER_VERIFICATION_REQD))
		sk = sk_probe(NULL, NULL, 0, 0);
	아니면
		sk = sk_probe(application, key_handle, key_handle_len, 0);
	만약 (sk == NULL) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		goto out;
	}
	만약 ((assert = fido_assert_new()) == NULL) {
		skdebug(__func__, "fido_assert_new failed");
		goto out;
	}
	만약 ((r = fido_assert_set_clientdata(assert,
	    data, datalen)) != FIDO_OK)  {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		goto out;
	}
	만약 ((r = fido_assert_set_rp(assert, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		goto out;
	}
	만약 ((r = fido_assert_allow_cred(assert, key_handle,
	    key_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		goto out;
	}
	만약 ((r = fido_assert_set_up(assert,
	    (flags & SSH_SK_USER_PRESENCE_REQD) ?
	    FIDO_OPT_TRUE : FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		goto out;
	}
	/*
	 * WinHello requests the PIN by default.  Make "uv" request explicit
	 * to allow keys with and without -O verify-required to make sense.
	 */
	만약 (pin == NULL && fido_dev_is_winhello (sk->dev) &&
	    (r = fido_assert_set_uv(assert, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
	}
	만약 (pin == NULL && (flags & SSH_SK_USER_VERIFICATION_REQD)) {
		만약 (check_sk_options(sk->dev, "uv", &internal_uv) < 0 ||
		    internal_uv != 1) {
			skdebug(__func__, "check_sk_options uv");
			ret = SSH_SK_ERR_PIN_REQUIRED;
			goto out;
		}
		만약 ((r = fido_assert_set_uv(assert,
		    FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_assert_set_uv: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			goto out;
		}
	}
	만약 ((r = fido_dev_get_assert(sk->dev, assert, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		goto out;
	}
	만약 ((response = calloc(1, sizeof(*response))) == NULL) {
		skdebug(__func__, "calloc response failed");
		goto out;
	}
	response->flags = fido_assert_flags(assert, 0);
	response->counter = fido_assert_sigcount(assert, 0);
	만약 (pack_sig(alg, assert, response) != 0) {
		skdebug(__func__, "pack_sig failed");
		goto out;
	}
	*sign_response = response;
	response = NULL;
	ret = 0;
 out:
	free(device);
	만약 (response != NULL) {
		free(response->sig_r);
		free(response->sig_s);
		free(response);
	}
	sk_close(sk);
	fido_assert_free(&assert);
	반환 ret;
}

static 정수
read_rks(struct sk_usbhid *sk, const char *pin,
    struct sk_resident_key ***rksp, size_t *nrksp)
{
	정수 ret = SSH_SK_ERR_GENERAL, r = -1;
	uint32_t alg;
	fido_credman_metadata_t *metadata = NULL;
	fido_credman_rp_t *rp = NULL;
	fido_credman_rk_t *rk = NULL;
	size_t i, j, nrp, nrk, user_id_len;
	const fido_cred_t *cred;
	const char *rp_id, *rp_name, *user_name;
	struct sk_resident_key *srk = NULL, **tmp;
	const u_char *user_id;

	만약 (pin == NULL) {
		skdebug(__func__, "no PIN specified");
		ret = SSH_SK_ERR_PIN_REQUIRED;
		goto out;
	}
	만약 ((metadata = fido_credman_metadata_new()) == NULL) {
		skdebug(__func__, "alloc failed");
		goto out;
	}
	만약 ((r = fido_credman_get_dev_metadata(sk->dev, metadata, pin)) != 0) {
		만약 (r == FIDO_ERR_INVALID_COMMAND) {
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
	만약 ((rp = fido_credman_rp_new()) == NULL) {
		skdebug(__func__, "alloc rp failed");
		goto out;
	}
	만약 ((r = fido_credman_get_dev_rp(sk->dev, rp, pin)) != 0) {
		skdebug(__func__, "get RPs for %s failed: %s",
		    sk->path, fido_strerr(r));
		goto out;
	}
	nrp = fido_credman_rp_count(rp);
	skdebug(__func__, "Device %s has resident keys for %zu RPs",
	    sk->path, nrp);

	/* Iterate over RP IDs that have resident keys */
	위해 (i = 0; i < nrp; i++) {
		rp_id = fido_credman_rp_id(rp, i);
		rp_name = fido_credman_rp_name(rp, i);
		skdebug(__func__, "rp %zu: name=\"%s\" id=\"%s\" hashlen=%zu",
		    i, rp_name == NULL ? "(none)" : rp_name,
		    rp_id == NULL ? "(none)" : rp_id,
		    fido_credman_rp_id_hash_len(rp, i));

		/* Skip non-SSH RP IDs */
		만약 (rp_id == NULL ||
		    strncasecmp(fido_credman_rp_id(rp, i), "ssh:", 4) != 0)
			continue;

		fido_credman_rk_free(&rk);
		만약 ((rk = fido_credman_rk_new()) == NULL) {
			skdebug(__func__, "alloc rk failed");
			goto out;
		}
		만약 ((r = fido_credman_get_dev_rk(sk->dev,
		    fido_credman_rp_id(rp, i), rk, pin)) != 0) {
			skdebug(__func__, "get RKs for %s slot %zu failed: %s",
			    sk->path, i, fido_strerr(r));
			goto out;
		}
		nrk = fido_credman_rk_count(rk);
		skdebug(__func__, "RP \"%s\" has %zu resident keys",
		    fido_credman_rp_id(rp, i), nrk);

		/* Iterate over resident keys for this RP ID */
		위해 (j = 0; j < nrk; j++) {
			만약 ((cred = fido_credman_rk(rk, j)) == NULL) {
				skdebug(__func__, "no RK in slot %zu", j);
				continue;
			}
			만약 ((user_name = fido_cred_user_name(cred)) == NULL)
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
			case COSE_ES256:
				alg = SSH_SK_ECDSA;
				break;
			case COSE_EDDSA:
				alg = SSH_SK_ED25519;
				break;
			default:
				skdebug(__func__, "unsupported key type %d",
				    fido_cred_type(cred));
				continue;
			}

			/* build response entry */
			만약 ((srk = calloc(1, sizeof(*srk))) == NULL ||
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
			만약 (srk->user_id_len != 0)
				memcpy(srk->user_id, user_id, srk->user_id_len);

#ifdef HAVE_FIDO_CRED_PROT
			만약 (fido_cred_prot(cred) ==
			    FIDO_CRED_PROT_UV_REQUIRED)
				srk->flags |=  SSH_SK_USER_VERIFICATION_REQD;
#endif

			만약 ((r = pack_public_key(srk->alg, cred,
			    &srk->key)) != 0) {
				skdebug(__func__, "pack public key failed");
				goto out;
			}
			/* append */
			만약 ((tmp = recallocarray(*rksp, *nrksp, (*nrksp) + 1,
			    sizeof(**rksp))) == NULL) {
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
	만약 (srk != NULL) {
		free(srk->application);
		freezero(srk->key.public_key, srk->key.public_key_len);
		freezero(srk->key.key_handle, srk->key.key_handle_len);
		freezero(srk->user_id, srk->user_id_len);
		freezero(srk, sizeof(*srk));
	}
	fido_credman_rp_free(&rp);
	fido_credman_rk_free(&rk);
	fido_credman_metadata_free(&metadata);
	반환 ret;
}

정수
sk_load_resident_keys(const char *pin, struct sk_option **options,
    struct sk_resident_key ***rksp, size_t *nrksp)
{
	정수 ret = SSH_SK_ERR_GENERAL, r = -1;
	size_t i, nrks = 0;
	struct sk_resident_key **rks = NULL;
	struct sk_usbhid *sk = NULL;
	char *device = NULL;

	*rksp = NULL;
	*nrksp = 0;

	fido_init(SSH_FIDO_INIT_ARG);

	만약 (check_sign_load_resident_options(options, &device) != 0)
		goto out; /* error already logged */
	만약 (device != NULL)
		sk = sk_open(device);
	아니면
		sk = sk_probe(NULL, NULL, 0, 1);
	만약 (sk == NULL) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		goto out;
	}
	skdebug(__func__, "trying %s", sk->path);
	만약 ((r = read_rks(sk, pin, &rks, &nrks)) != 0) {
		skdebug(__func__, "read_rks failed for %s", sk->path);
		ret = r;
		goto out;
	}
	/* success, unless we have no keys but a specific error */
	만약 (nrks > 0 || ret == SSH_SK_ERR_GENERAL)
		ret = 0;
	*rksp = rks;
	*nrksp = nrks;
	rks = NULL;
	nrks = 0;
 out:
	sk_close(sk);
	위해 (i = 0; i < nrks; i++) {
		free(rks[i]->application);
		freezero(rks[i]->key.public_key, rks[i]->key.public_key_len);
		freezero(rks[i]->key.key_handle, rks[i]->key.key_handle_len);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i], sizeof(*rks[i]));
	}
	free(device);
	free(rks);
	반환 ret;
}

#endif /* ENABLE_SK_INTERNAL */
