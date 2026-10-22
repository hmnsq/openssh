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

#அந்தர்பாவ "includes.h"

#ifdef ENABLE_SK_INTERNAL

#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <time.h>
#ifdef HAVE_SHA2_H
#அந்தர்பாவ <sha2.h>
#endif

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/opensslv.h>
#அந்தர்பாவ <openssl/crypto.h>
#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/ec.h>
#அந்தர்பாவ <openssl/ecdsa.h>
#அந்தர்பாவ <openssl/evp.h>
#அந்தர்பாவ "openbsd-compat/openssl-compat.h"
#endif /* WITH_OPENSSL */

#அந்தர்பாவ <fido.h>
#அந்தர்பாவ <fido/credman.h>

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
# define sk_load_resident_சாவிகள்	ssh_sk_load_resident_சாவிகள்
#endif /* !SK_STANDALONE */

#அந்தர்பாவ "sk-api.h"

/* #define SK_DEBUG 1 */

#ifdef SK_DEBUG
#define SSH_FIDO_INIT_ARG	FIDO_DEBUG
#இல்லையெனில்
#define SSH_FIDO_INIT_ARG	0
#endif

#define MAX_FIDO_DEVICES	8
#define FIDO_POLL_MS		50
#define SELECT_MS		15000
#define POLL_SLEEP_NS		200000000

#ifndef FIDO_ERR_OPERATION_DENIED
#define FIDO_ERR_OPERATION_DENIED 0x27
#endif

கட்டமைப்பு sk_usbhid {
	fido_dev_t *dev;
	எழுத்து *path;
};

/* Return the version of the middleware API */
uint32_t sk_api_version(வெறுமை);

/* Enroll a U2F key (private key generation) */
முழு sk_enroll(uint32_t alg, மாறிலி uint8_t *challenge, size_t challenge_len,
    மாறிலி எழுத்து *application, uint8_t flags, மாறிலி எழுத்து *pin,
    கட்டமைப்பு sk_option **options, கட்டமைப்பு sk_enroll_response **enroll_response);

/* Sign a challenge */
முழு sk_sign(uint32_t alg, மாறிலி uint8_t *data, size_t data_len,
    மாறிலி எழுத்து *application, மாறிலி uint8_t *சாவி_handle, size_t சாவி_handle_len,
    uint8_t flags, மாறிலி எழுத்து *pin, கட்டமைப்பு sk_option **options,
    கட்டமைப்பு sk_sign_response **sign_response);

/* Load resident keys */
முழு sk_load_resident_சாவிகள்(மாறிலி எழுத்து *pin, கட்டமைப்பு sk_option **options,
    கட்டமைப்பு sk_resident_சாவி ***rks, size_t *nrks);

நிலையான வெறுமை skdebug(மாறிலி எழுத்து *func, மாறிலி எழுத்து *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

நிலையான வெறுமை
skdebug(மாறிலி எழுத்து *func, மாறிலி எழுத்து *fmt, ...)
{
#எனில் !defined(SK_STANDALONE)
	எழுத்து *செய்தி;
	va_list ap;

	va_start(ap, fmt);
	xvasprintf(&செய்தி, fmt, ap);
	va_end(ap);
	debug("%s: %s", func, செய்தி);
	விடுவி(செய்தி);
#அல்லதெனில் defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#இல்லையெனில்
	(வெறுமை)func; /* XXX */
	(வெறுமை)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(வெறுமை)
{
	திரும்பு SSH_SK_VERSION_MAJOR;
}

நிலையான கட்டமைப்பு sk_usbhid *
sk_open(மாறிலி எழுத்து *path)
{
	கட்டமைப்பு sk_usbhid *sk;
	முழு r;

	எனில் (path == வெற்று) {
		skdebug(__func__, "path == NULL");
		திரும்பு வெற்று;
	}
	எனில் ((sk = calloc(1, அளவு(*sk))) == வெற்று) {
		skdebug(__func__, "calloc sk failed");
		திரும்பு வெற்று;
	}
	எனில் ((sk->path = strdup(path)) == வெற்று) {
		skdebug(__func__, "strdup path failed");
		விடுவி(sk);
		திரும்பு வெற்று;
	}
	எனில் ((sk->dev = fido_dev_new()) == வெற்று) {
		skdebug(__func__, "fido_dev_new failed");
		விடுவி(sk->path);
		விடுவி(sk);
		திரும்பு வெற்று;
	}
	எனில் ((r = fido_dev_open(sk->dev, sk->path)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_open %s failed: %s", sk->path,
		    fido_strerr(r));
		fido_dev_free(&sk->dev);
		விடுவி(sk->path);
		விடுவி(sk);
		திரும்பு வெற்று;
	}
	திரும்பு sk;
}

நிலையான வெறுமை
sk_close(கட்டமைப்பு sk_usbhid *sk)
{
	எனில் (sk == வெற்று)
		திரும்பு;
	fido_dev_cancel(sk->dev); /* cancel any pending operation */
	fido_dev_close(sk->dev);
	fido_dev_free(&sk->dev);
	விடுவி(sk->path);
	விடுவி(sk);
}

நிலையான கட்டமைப்பு sk_usbhid **
sk_openv(மாறிலி fido_dev_info_t *devlist, size_t ndevs, size_t *nopen)
{
	மாறிலி fido_dev_info_t *di;
	கட்டமைப்பு sk_usbhid **skv;
	size_t i;

	*nopen = 0;
	எனில் ((skv = calloc(ndevs, அளவு(*skv))) == வெற்று) {
		skdebug(__func__, "calloc skv failed");
		திரும்பு வெற்று;
	}
	க்கு (i = 0; i < ndevs; i++) {
		எனில் ((di = fido_dev_info_ptr(devlist, i)) == வெற்று)
			skdebug(__func__, "fido_dev_info_ptr failed");
		இல்லையெனில் எனில் ((skv[*nopen] = sk_open(fido_dev_info_path(di))) == வெற்று)
			skdebug(__func__, "sk_open failed");
		இல்லையெனில்
			(*nopen)++;
	}
	எனில் (*nopen == 0) {
		க்கு (i = 0; i < ndevs; i++)
			sk_close(skv[i]);
		விடுவி(skv);
		skv = வெற்று;
	}

	திரும்பு skv;
}

நிலையான வெறுமை
sk_closev(கட்டமைப்பு sk_usbhid **skv, size_t nsk)
{
	size_t i;

	க்கு (i = 0; i < nsk; i++)
		sk_close(skv[i]);
	விடுவி(skv);
}

நிலையான முழு
sk_touch_begin(கட்டமைப்பு sk_usbhid **skv, size_t nsk)
{
	size_t i, ok = 0;
	முழு r;

	க்கு (i = 0; i < nsk; i++)
		எனில் ((r = fido_dev_get_touch_begin(skv[i]->dev)) != FIDO_OK)
			skdebug(__func__, "fido_dev_get_touch_begin %s failed:"
			    " %s", skv[i]->path, fido_strerr(r));
		இல்லையெனில்
			ok++;

	திரும்பு ok ? 0 : -1;
}

நிலையான முழு
sk_touch_poll(கட்டமைப்பு sk_usbhid **skv, size_t nsk, முழு *touch, size_t *idx)
{
	கட்டமைப்பு timespec ts_pause;
	size_t npoll, i;
	முழு r;

	ts_pause.tv_sec = 0;
	ts_pause.tv_nsec = POLL_SLEEP_NS;
	nanosleep(&ts_pause, வெற்று);
	npoll = nsk;
	க்கு (i = 0; i < nsk; i++) {
		எனில் (skv[i] == வெற்று)
			தொடர்; /* device discarded */
		skdebug(__func__, "polling %s", skv[i]->path);
		எனில் ((r = fido_dev_get_touch_status(skv[i]->dev, touch,
		    FIDO_POLL_MS)) != FIDO_OK) {
			skdebug(__func__, "fido_dev_get_touch_status %s: %s",
			    skv[i]->path, fido_strerr(r));
			sk_close(skv[i]); /* discard device */
			skv[i] = வெற்று;
			எனில் (--npoll == 0) {
				skdebug(__func__, "no device left to poll");
				திரும்பு -1;
			}
		} இல்லையெனில் எனில் (*touch) {
			*idx = i;
			திரும்பு 0;
		}
	}
	*touch = 0;
	திரும்பு 0;
}

#எனில் !defined(HAVE_FIDO_ASSERT_SET_CLIENTDATA) || \
    !defined(HAVE_FIDO_CRED_SET_CLIENTDATA)
/* Calculate SHA256(m) */
நிலையான முழு
sha256_mem(மாறிலி வெறுமை *m, size_t mlen, u_char *d, size_t dlen)
{
#ifdef WITH_OPENSSL
	u_int mdlen;
#இல்லையெனில்
	SHA2_CTX ctx;
#endif

	எனில் (dlen != 32)
		திரும்பு -1;
#ifdef WITH_OPENSSL
	mdlen = dlen;
	எனில் (!EVP_Digest(m, mlen, d, &mdlen, EVP_sha256(), வெற்று))
		திரும்பு -1;
#இல்லையெனில்
	SHA256Init(&ctx);
	SHA256Update(&ctx, (மாறிலி uint8_t *)m, mlen);
	SHA256Final(d, &ctx);
#endif
	திரும்பு 0;
}
#endif /* !HAVE_FIDO_ASSERT_SET_CLIENTDATA || !HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_CRED_SET_CLIENTDATA
நிலையான முழு
fido_cred_set_clientdata(fido_cred_t *cred, மாறிலி u_char *ptr, size_t len)
{
	uint8_t d[32];
	முழு r;

	எனில் (sha256_mem(ptr, len, d, அளவு(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		திரும்பு FIDO_ERR_INTERNAL;
	}
	r = fido_cred_set_clientdata_hash(cred, d, அளவு(d));
	explicit_bzero(d, அளவு(d));
	எனில் (r != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	திரும்பு r;
}
#endif /* HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_ASSERT_SET_CLIENTDATA
நிலையான முழு
fido_assert_set_clientdata(fido_assert_t *ப்ரதிஜ்ஞா, மாறிலி u_char *ptr, size_t len)
{
	uint8_t d[32];
	முழு r;

	எனில் (sha256_mem(ptr, len, d, அளவு(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		திரும்பு FIDO_ERR_INTERNAL;
	}
	r = fido_assert_set_clientdata_hash(ப்ரதிஜ்ஞா, d, அளவு(d));
	explicit_bzero(d, அளவு(d));
	எனில் (r != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	திரும்பு r;
}
#endif /* HAVE_FIDO_ASSERT_SET_CLIENTDATA */

#ifndef HAVE_FIDO_DEV_IS_WINHELLO
நிலையான bool
fido_dev_is_winhello(மாறிலி fido_dev_t *fdev)
{
	திரும்பு 0;
}
#endif /* HAVE_FIDO_DEV_IS_WINHELLO */

/* Check if the specified key handle exists on a given sk. */
நிலையான முழு
sk_try(மாறிலி கட்டமைப்பு sk_usbhid *sk, மாறிலி எழுத்து *application,
    மாறிலி uint8_t *சாவி_handle, size_t சாவி_handle_len)
{
	fido_assert_t *ப்ரதிஜ்ஞா = வெற்று;
	முழு r = FIDO_ERR_INTERNAL;
	uint8_t message[32];

	memset(message, '\0', அளவு(message));
	எனில் ((ப்ரதிஜ்ஞா = fido_assert_new()) == வெற்று) {
		skdebug(__func__, "fido_assert_new failed");
		செல் out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	எனில் ((r = fido_assert_set_clientdata(ப்ரதிஜ்ஞா, message,
	    அளவு(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		செல் out;
	}
	எனில் ((r = fido_assert_set_rp(ப்ரதிஜ்ஞா, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		செல் out;
	}
	எனில் ((r = fido_assert_allow_cred(ப்ரதிஜ்ஞா, சாவி_handle,
	    சாவி_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		செல் out;
	}
	எனில் ((r = fido_assert_set_up(ப்ரதிஜ்ஞா, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_up: %s", fido_strerr(r));
		செல் out;
	}
	r = fido_dev_get_assert(sk->dev, ப்ரதிஜ்ஞா, வெற்று);
	skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
	எனில் (r == FIDO_ERR_USER_PRESENCE_REQUIRED) {
		/* U2F tokens may return this */
		r = FIDO_OK;
	}
 out:
	fido_assert_free(&ப்ரதிஜ்ஞா);

	திரும்பு r != FIDO_OK ? -1 : 0;
}

நிலையான முழு
check_sk_options(fido_dev_t *dev, மாறிலி எழுத்து *opt, முழு *ret)
{
	fido_cbor_info_t *info;
	எழுத்து * மாறிலி *name;
	மாறிலி bool *மதிப்பு;
	size_t len, i;
	முழு r;

	*ret = -1;

	எனில் (!fido_dev_is_fido2(dev)) {
		skdebug(__func__, "device is not fido2");
		திரும்பு 0;
	}
	எனில் ((info = fido_cbor_info_new()) == வெற்று) {
		skdebug(__func__, "fido_cbor_info_new failed");
		திரும்பு -1;
	}
	எனில் ((r = fido_dev_get_cbor_info(dev, info)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_cbor_info: %s", fido_strerr(r));
		fido_cbor_info_free(&info);
		திரும்பு -1;
	}
	name = fido_cbor_info_options_name_ptr(info);
	மதிப்பு = fido_cbor_info_options_மதிப்பு_ptr(info);
	len = fido_cbor_info_options_len(info);
	க்கு (i = 0; i < len; i++) {
		எனில் (!strcmp(name[i], opt)) {
			*ret = மதிப்பு[i];
			நிறுத்து;
		}
	}
	fido_cbor_info_free(&info);
	எனில் (*ret == -1)
		skdebug(__func__, "option %s is unknown", opt);
	இல்லையெனில்
		skdebug(__func__, "option %s is %s", opt, *ret ? "on" : "off");

	திரும்பு 0;
}

நிலையான கட்டமைப்பு sk_usbhid *
sk_select_by_cred(மாறிலி fido_dev_info_t *devlist, size_t ndevs,
    மாறிலி எழுத்து *application, மாறிலி uint8_t *சாவி_handle, size_t சாவி_handle_len)
{
	கட்டமைப்பு sk_usbhid **skv, *sk;
	size_t skvcnt, i;
	முழு internal_uv;

	எனில் ((skv = sk_openv(devlist, ndevs, &skvcnt)) == வெற்று) {
		skdebug(__func__, "sk_openv failed");
		திரும்பு வெற்று;
	}
	எனில் (skvcnt == 1 && check_sk_options(skv[0]->dev, "uv",
	    &internal_uv) == 0 && internal_uv != -1) {
		sk = skv[0];
		skv[0] = வெற்று;
		செல் out;
	}
	sk = வெற்று;
	க்கு (i = 0; i < skvcnt; i++) {
		எனில் (sk_try(skv[i], application, சாவி_handle,
		    சாவி_handle_len) == 0) {
			sk = skv[i];
			skv[i] = வெற்று;
			skdebug(__func__, "found key in %s", sk->path);
			நிறுத்து;
		}
	}
 out:
	sk_closev(skv, skvcnt);
	திரும்பு sk;
}

நிலையான கட்டமைப்பு sk_usbhid *
sk_select_by_touch(மாறிலி fido_dev_info_t *devlist, size_t ndevs)
{
	கட்டமைப்பு sk_usbhid **skv, *sk;
	கட்டமைப்பு timeval tv_start, tv_now, tv_delta;
	size_t skvcnt, idx;
	முழு touch, ms_remain;

	எனில் ((skv = sk_openv(devlist, ndevs, &skvcnt)) == வெற்று) {
		skdebug(__func__, "sk_openv failed");
		திரும்பு வெற்று;
	}
	sk = வெற்று;
	எனில் (skvcnt < 2) {
		எனில் (skvcnt == 1) {
			/* single candidate */
			sk = skv[0];
			skv[0] = வெற்று;
		}
		செல் out;
	}
#ifndef HAVE_FIDO_DEV_GET_TOUCH_STATUS
	skdebug(__func__, "libfido2 version does not support a feature needed for multiple tokens. Please upgrade to >=1.5.0");
	செல் out;
#endif

	எனில் (sk_touch_begin(skv, skvcnt) == -1) {
		skdebug(__func__, "sk_touch_begin failed");
		செல் out;
	}
	monotime_tv(&tv_start);
	செய் {
		எனில் (sk_touch_poll(skv, skvcnt, &touch, &idx) == -1) {
			skdebug(__func__, "sk_touch_poll failed");
			செல் out;
		}
		எனில் (touch) {
			sk = skv[idx];
			skv[idx] = வெற்று;
			செல் out;
		}
		monotime_tv(&tv_now);
		timersub(&tv_now, &tv_start, &tv_delta);
		ms_remain = SELECT_MS - tv_delta.tv_sec * 1000 -
		    tv_delta.tv_usec / 1000;
	} போது (ms_remain >= FIDO_POLL_MS);
	skdebug(__func__, "timeout");
out:
	sk_closev(skv, skvcnt);
	திரும்பு sk;
}

நிலையான கட்டமைப்பு sk_usbhid *
sk_probe(மாறிலி எழுத்து *application, மாறிலி uint8_t *சாவி_handle,
    size_t சாவி_handle_len, முழு probe_resident)
{
	கட்டமைப்பு sk_usbhid *sk;
	fido_dev_info_t *devlist;
	size_t ndevs;
	முழு r;

#ifdef HAVE_CYGWIN
	எனில் (!probe_resident && (sk = sk_open("windows://hello")) != வெற்று)
		திரும்பு sk;
#endif /* HAVE_CYGWIN */
	எனில் ((devlist = fido_dev_info_new(MAX_FIDO_DEVICES)) == வெற்று) {
		skdebug(__func__, "fido_dev_info_new failed");
		திரும்பு வெற்று;
	}
	எனில் ((r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES,
	    &ndevs)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_info_manifest failed: %s",
		    fido_strerr(r));
		fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
		திரும்பு வெற்று;
	}
	skdebug(__func__, "%zu device(s) detected", ndevs);
	எனில் (ndevs == 0) {
		sk = வெற்று;
	} இல்லையெனில் எனில் (application != வெற்று && சாவி_handle != வெற்று) {
		skdebug(__func__, "selecting sk by cred");
		sk = sk_select_by_cred(devlist, ndevs, application, சாவி_handle,
		    சாவி_handle_len);
	} இல்லையெனில் {
		skdebug(__func__, "selecting sk by touch");
		sk = sk_select_by_touch(devlist, ndevs);
	}
	fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
	திரும்பு sk;
}

#ifdef WITH_OPENSSL
/*
 * The key returned via fido_cred_pubkey_ptr() is in affine coordinates,
 * but the API expects a SEC1 octet string.
 */
நிலையான முழு
pack_public_சாவி_ecdsa(மாறிலி fido_cred_t *cred,
    கட்டமைப்பு sk_enroll_response *response)
{
	மாறிலி uint8_t *ptr;
	BIGNUM *x = வெற்று, *y = வெற்று;
	EC_POINT *q = வெற்று;
	EC_GROUP *g = வெற்று;
	முழு ret = -1;

	response->public_சாவி = வெற்று;
	response->public_சாவி_len = 0;

	எனில் ((x = BN_new()) == வெற்று ||
	    (y = BN_new()) == வெற்று ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == வெற்று ||
	    (q = EC_POINT_new(g)) == வெற்று) {
		skdebug(__func__, "libcrypto setup failed");
		செல் out;
	}
	எனில் ((ptr = fido_cred_pubkey_ptr(cred)) == வெற்று) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		செல் out;
	}
	எனில் (fido_cred_pubkey_len(cred) != 64) {
		skdebug(__func__, "bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		செல் out;
	}

	எனில் (BN_bin2bn(ptr, 32, x) == வெற்று ||
	    BN_bin2bn(ptr + 32, 32, y) == வெற்று) {
		skdebug(__func__, "BN_bin2bn failed");
		செல் out;
	}
	எனில் (EC_POINT_set_affine_coordinates(g, q, x, y, வெற்று) != 1) {
		skdebug(__func__, "EC_POINT_set_affine_coordinates failed");
		செல் out;
	}
	response->public_சாவி_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, வெற்று, 0, வெற்று);
	எனில் (response->public_சாவி_len == 0 || response->public_சாவி_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_சாவி_len);
		செல் out;
	}
	எனில் ((response->public_சாவி = malloc(response->public_சாவி_len)) == வெற்று) {
		skdebug(__func__, "malloc pubkey failed");
		செல் out;
	}
	எனில் (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_சாவி, response->public_சாவி_len, வெற்று) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		செல் out;
	}
	/* success */
	ret = 0;
 out:
	எனில் (ret != 0 && response->public_சாவி != வெற்று) {
		memset(response->public_சாவி, 0, response->public_சாவி_len);
		விடுவி(response->public_சாவி);
		response->public_சாவி = வெற்று;
	}
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	திரும்பு ret;
}
#endif /* WITH_OPENSSL */

நிலையான முழு
pack_public_சாவி_ed25519(மாறிலி fido_cred_t *cred,
    கட்டமைப்பு sk_enroll_response *response)
{
	மாறிலி uint8_t *ptr;
	size_t len;
	முழு ret = -1;

	response->public_சாவி = வெற்று;
	response->public_சாவி_len = 0;

	எனில் ((len = fido_cred_pubkey_len(cred)) != 32) {
		skdebug(__func__, "bad fido_cred_pubkey_len len %zu", len);
		செல் out;
	}
	எனில் ((ptr = fido_cred_pubkey_ptr(cred)) == வெற்று) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		செல் out;
	}
	response->public_சாவி_len = len;
	எனில் ((response->public_சாவி = malloc(response->public_சாவி_len)) == வெற்று) {
		skdebug(__func__, "malloc pubkey failed");
		செல் out;
	}
	memcpy(response->public_சாவி, ptr, len);
	ret = 0;
 out:
	எனில் (ret != 0)
		விடுவி(response->public_சாவி);
	திரும்பு ret;
}

நிலையான முழு
pack_public_சாவி(uint32_t alg, மாறிலி fido_cred_t *cred,
    கட்டமைப்பு sk_enroll_response *response)
{
	தேர்வு(alg) {
#ifdef WITH_OPENSSL
	நிலை SSH_SK_ECDSA:
		திரும்பு pack_public_சாவி_ecdsa(cred, response);
#endif /* WITH_OPENSSL */
	நிலை SSH_SK_ED25519:
		திரும்பு pack_public_சாவி_ed25519(cred, response);
	இயல்பு:
		திரும்பு -1;
	}
}

நிலையான முழு
fidoerr_to_skerr(முழு fidoerr)
{
	தேர்வு (fidoerr) {
	நிலை FIDO_ERR_UNSUPPORTED_OPTION:
	நிலை FIDO_ERR_UNSUPPORTED_ALGORITHM:
		திரும்பு SSH_SK_ERR_UNSUPPORTED;
	நிலை FIDO_ERR_PIN_REQUIRED:
	நிலை FIDO_ERR_PIN_INVALID:
	நிலை FIDO_ERR_OPERATION_DENIED:
		திரும்பு SSH_SK_ERR_PIN_REQUIRED;
	இயல்பு:
		திரும்பு -1;
	}
}

நிலையான முழு
check_enroll_options(கட்டமைப்பு sk_option **options, எழுத்து **devicep,
    uint8_t *user_id, size_t user_id_len)
{
	size_t i;

	எனில் (options == வெற்று)
		திரும்பு 0;
	க்கு (i = 0; options[i] != வெற்று; i++) {
		எனில் (strcmp(options[i]->name, "device") == 0) {
			எனில் ((*devicep = strdup(options[i]->மதிப்பு)) == வெற்று) {
				skdebug(__func__, "strdup device failed");
				திரும்பு -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} இல்லையெனில் எனில் (strcmp(options[i]->name, "user") == 0) {
			எனில் (strlcpy(user_id, options[i]->மதிப்பு, user_id_len) >=
			    user_id_len) {
				skdebug(__func__, "user too long");
				திரும்பு -1;
			}
			skdebug(__func__, "requested user %s",
			    (எழுத்து *)user_id);
		} இல்லையெனில் {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			எனில் (options[i]->required) {
				skdebug(__func__, "unknown required option");
				திரும்பு -1;
			}
		}
	}
	திரும்பு 0;
}

நிலையான முழு
சாவி_lookup(fido_dev_t *dev, மாறிலி எழுத்து *application, மாறிலி uint8_t *user_id,
    size_t user_id_len, மாறிலி எழுத்து *pin)
{
	fido_assert_t *ப்ரதிஜ்ஞா = வெற்று;
	uint8_t message[32];
	முழு r = FIDO_ERR_INTERNAL;
	முழு sk_supports_uv, uv;
	size_t i;

	memset(message, '\0', அளவு(message));
	எனில் ((ப்ரதிஜ்ஞா = fido_assert_new()) == வெற்று) {
		skdebug(__func__, "fido_assert_new failed");
		செல் out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	எனில் ((r = fido_assert_set_clientdata(ப்ரதிஜ்ஞா, message,
	    அளவு(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		செல் out;
	}
	எனில் ((r = fido_assert_set_rp(ப்ரதிஜ்ஞா, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		செல் out;
	}
	எனில் ((r = fido_assert_set_up(ப்ரதிஜ்ஞா, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		செல் out;
	}
	uv = FIDO_OPT_OMIT;
	எனில் (pin == வெற்று && check_sk_options(dev, "uv", &sk_supports_uv) == 0 &&
	    sk_supports_uv != -1)
		uv = FIDO_OPT_TRUE;
	எனில் ((r = fido_assert_set_uv(ப்ரதிஜ்ஞா, uv)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
		செல் out;
	}
	எனில் ((r = fido_dev_get_assert(dev, ப்ரதிஜ்ஞா, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		செல் out;
	}
	r = FIDO_ERR_NO_CREDENTIALS;
	skdebug(__func__, "%zu signatures returned", fido_assert_மொத்தம்(ப்ரதிஜ்ஞா));
	க்கு (i = 0; i < fido_assert_மொத்தம்(ப்ரதிஜ்ஞா); i++) {
		எனில் (fido_assert_user_id_len(ப்ரதிஜ்ஞா, i) == user_id_len &&
		    memcmp(fido_assert_user_id_ptr(ப்ரதிஜ்ஞா, i), user_id,
		    user_id_len) == 0) {
			skdebug(__func__, "credential exists");
			r = FIDO_OK;
			செல் out;
		}
	}
 out:
	fido_assert_free(&ப்ரதிஜ்ஞா);

	திரும்பு r;
}

முழு
sk_enroll(uint32_t alg, மாறிலி uint8_t *challenge, size_t challenge_len,
    மாறிலி எழுத்து *application, uint8_t flags, மாறிலி எழுத்து *pin,
    கட்டமைப்பு sk_option **options, கட்டமைப்பு sk_enroll_response **enroll_response)
{
	fido_cred_t *cred = வெற்று;
	மாறிலி uint8_t *ptr;
	uint8_t user_id[32];
	கட்டமைப்பு sk_usbhid *sk = வெற்று;
	கட்டமைப்பு sk_enroll_response *response = வெற்று;
	size_t len;
	முழு credprot;
	முழு cose_alg;
	முழு ret = SSH_SK_ERR_GENERAL;
	முழு r;
	எழுத்து *device = வெற்று;

	fido_init(SSH_FIDO_INIT_ARG);

	எனில் (enroll_response == வெற்று) {
		skdebug(__func__, "enroll_response == NULL");
		செல் out;
	}
	*enroll_response = வெற்று;
	memset(user_id, 0, அளவு(user_id));
	எனில் (check_enroll_options(options, &device, user_id,
	    அளவு(user_id)) != 0)
		செல் out; /* error already logged */

	தேர்வு(alg) {
#ifdef WITH_OPENSSL
	நிலை SSH_SK_ECDSA:
		cose_alg = COSE_ES256;
		நிறுத்து;
#endif /* WITH_OPENSSL */
	நிலை SSH_SK_ED25519:
		cose_alg = COSE_EDDSA;
		நிறுத்து;
	இயல்பு:
		skdebug(__func__, "unsupported key type %d", alg);
		செல் out;
	}
	எனில் (device != வெற்று)
		sk = sk_open(device);
	இல்லையெனில்
		sk = sk_probe(வெற்று, வெற்று, 0, 0);
	எனில் (sk == வெற்று) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		செல் out;
	}
	skdebug(__func__, "using device %s", sk->path);
	எனில் ((flags & SSH_SK_RESIDENT_சாவி) != 0 &&
	    (flags & SSH_SK_FORCE_OPERATION) == 0 &&
	    (r = சாவி_lookup(sk->dev, application, user_id, அளவு(user_id),
	    pin)) != FIDO_ERR_NO_CREDENTIALS) {
		எனில் (r != FIDO_OK) {
			ret = fidoerr_to_skerr(r);
			skdebug(__func__, "key_lookup failed");
		} இல்லையெனில் {
			ret = SSH_SK_ERR_CREDENTIAL_EXISTS;
			skdebug(__func__, "key exists");
		}
		செல் out;
	}
	எனில் ((cred = fido_cred_new()) == வெற்று) {
		skdebug(__func__, "fido_cred_new failed");
		செல் out;
	}
	எனில் ((r = fido_cred_set_type(cred, cose_alg)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_type: %s", fido_strerr(r));
		செல் out;
	}
	எனில் ((r = fido_cred_set_clientdata(cred,
	    challenge, challenge_len)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata: %s",
		    fido_strerr(r));
		செல் out;
	}
	எனில் ((r = fido_cred_set_rk(cred, (flags & SSH_SK_RESIDENT_சாவி) != 0 ?
	    FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rk: %s", fido_strerr(r));
		செல் out;
	}
	எனில் ((r = fido_cred_set_user(cred, user_id, அளவு(user_id),
	    "openssh", "openssh", வெற்று)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_user: %s", fido_strerr(r));
		செல் out;
	}
	எனில் ((r = fido_cred_set_rp(cred, application, வெற்று)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rp: %s", fido_strerr(r));
		செல் out;
	}
	எனில் ((flags & (SSH_SK_RESIDENT_சாவி|SSH_SK_USER_VERIFICATION_REQD)) != 0) {
#எனில் !defined(HAVE_FIDO_DEV_SUPPORTS_CRED_PROT) || \
    !defined(HAVE_FIDO_CRED_SET_PROT)
		skdebug(__func__, "libfido2 version does not support a feature required for this operation. Please upgrade to >=1.5.0");
		ret = SSH_SK_ERR_UNSUPPORTED;
		செல் out;
		credprot = 0; (வெறுமை)credprot; /* avoid warning */
#endif
		எனில் (!fido_dev_supports_cred_prot(sk->dev)) {
			skdebug(__func__, "%s does not support credprot, "
			    "refusing to create unprotected "
			    "resident/verify-required key", sk->path);
			ret = SSH_SK_ERR_UNSUPPORTED;
			செல் out;
		}
		எனில் ((flags & SSH_SK_USER_VERIFICATION_REQD))
			credprot = FIDO_CRED_PROT_UV_REQUIRED;
		இல்லையெனில்
			credprot = FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID;

		எனில் ((r = fido_cred_set_prot(cred, credprot)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_set_prot: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			செல் out;
		}
	}
	எனில் ((r = fido_dev_make_cred(sk->dev, cred, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_make_cred: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		செல் out;
	}
	எனில் (fido_cred_x5c_ptr(cred) != வெற்று) {
		எனில் ((r = fido_cred_verify(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify: %s",
			    fido_strerr(r));
			செல் out;
		}
	} இல்லையெனில் எனில் (strcmp(fido_cred_fmt(cred), "none") != 0) {
		skdebug(__func__, "self-attested credential");
		எனில் ((r = fido_cred_verify_self(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify_self: %s",
			    fido_strerr(r));
			செல் out;
		}
	} இல்லையெனில் {
		skdebug(__func__, "no attestation data");
	}
	எனில் ((response = calloc(1, அளவு(*response))) == வெற்று) {
		skdebug(__func__, "calloc response failed");
		செல் out;
	}
	response->flags = flags;
	எனில் (pack_public_சாவி(alg, cred, response) != 0) {
		skdebug(__func__, "pack_public_key failed");
		செல் out;
	}
	எனில் ((ptr = fido_cred_id_ptr(cred)) != வெற்று) {
		len = fido_cred_id_len(cred);
		எனில் ((response->சாவி_handle = calloc(1, len)) == வெற்று) {
			skdebug(__func__, "calloc key handle failed");
			செல் out;
		}
		memcpy(response->சாவி_handle, ptr, len);
		response->சாவி_handle_len = len;
	}
	எனில் ((ptr = fido_cred_sig_ptr(cred)) != வெற்று) {
		len = fido_cred_sig_len(cred);
		எனில் ((response->signature = calloc(1, len)) == வெற்று) {
			skdebug(__func__, "calloc signature failed");
			செல் out;
		}
		memcpy(response->signature, ptr, len);
		response->signature_len = len;
	}
	எனில் ((ptr = fido_cred_x5c_ptr(cred)) != வெற்று) {
		len = fido_cred_x5c_len(cred);
		skdebug(__func__, "attestation cert len=%zu", len);
		எனில் ((response->attestation_cert = calloc(1, len)) == வெற்று) {
			skdebug(__func__, "calloc attestation cert failed");
			செல் out;
		}
		memcpy(response->attestation_cert, ptr, len);
		response->attestation_cert_len = len;
	}
	எனில் ((ptr = fido_cred_authdata_ptr(cred)) != வெற்று) {
		len = fido_cred_authdata_len(cred);
		skdebug(__func__, "authdata len=%zu", len);
		எனில் ((response->authdata = calloc(1, len)) == வெற்று) {
			skdebug(__func__, "calloc authdata failed");
			செல் out;
		}
		memcpy(response->authdata, ptr, len);
		response->authdata_len = len;
	}
	*enroll_response = response;
	response = வெற்று;
	ret = 0;
 out:
	விடுவி(device);
	எனில் (response != வெற்று) {
		விடுவி(response->public_சாவி);
		விடுவி(response->சாவி_handle);
		விடுவி(response->signature);
		விடுவி(response->attestation_cert);
		விடுவி(response->authdata);
		விடுவி(response);
	}
	sk_close(sk);
	fido_cred_free(&cred);
	திரும்பு ret;
}

#ifdef WITH_OPENSSL
நிலையான முழு
pack_sig_ecdsa(fido_assert_t *ப்ரதிஜ்ஞா, கட்டமைப்பு sk_sign_response *response)
{
	ECDSA_SIG *sig = வெற்று;
	மாறிலி BIGNUM *sig_r, *sig_s;
	மாறிலி unsigned எழுத்து *cp;
	size_t sig_len;
	முழு ret = -1;

	cp = fido_assert_sig_ptr(ப்ரதிஜ்ஞா, 0);
	sig_len = fido_assert_sig_len(ப்ரதிஜ்ஞா, 0);
	எனில் ((sig = d2i_ECDSA_SIG(வெற்று, &cp, sig_len)) == வெற்று) {
		skdebug(__func__, "d2i_ECDSA_SIG failed");
		செல் out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_இலக்கம்_bytes(sig_r);
	response->sig_s_len = BN_இலக்கம்_bytes(sig_s);
	எனில் ((response->sig_r = calloc(1, response->sig_r_len)) == வெற்று ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == வெற்று) {
		skdebug(__func__, "calloc signature failed");
		செல் out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	ECDSA_SIG_free(sig);
	எனில் (ret != 0) {
		விடுவி(response->sig_r);
		விடுவி(response->sig_s);
		response->sig_r = வெற்று;
		response->sig_s = வெற்று;
	}
	திரும்பு ret;
}
#endif /* WITH_OPENSSL */

நிலையான முழு
pack_sig_ed25519(fido_assert_t *ப்ரதிஜ்ஞா, கட்டமைப்பு sk_sign_response *response)
{
	மாறிலி unsigned எழுத்து *ptr;
	size_t len;
	முழு ret = -1;

	ptr = fido_assert_sig_ptr(ப்ரதிஜ்ஞா, 0);
	len = fido_assert_sig_len(ப்ரதிஜ்ஞா, 0);
	எனில் (len != 64) {
		skdebug(__func__, "bad length %zu", len);
		செல் out;
	}
	response->sig_r_len = len;
	எனில் ((response->sig_r = calloc(1, response->sig_r_len)) == வெற்று) {
		skdebug(__func__, "calloc signature failed");
		செல் out;
	}
	memcpy(response->sig_r, ptr, len);
	ret = 0;
 out:
	எனில் (ret != 0) {
		விடுவி(response->sig_r);
		response->sig_r = வெற்று;
	}
	திரும்பு ret;
}

நிலையான முழு
pack_sig(uint32_t  alg, fido_assert_t *ப்ரதிஜ்ஞா,
    கட்டமைப்பு sk_sign_response *response)
{
	தேர்வு(alg) {
#ifdef WITH_OPENSSL
	நிலை SSH_SK_ECDSA:
		திரும்பு pack_sig_ecdsa(ப்ரதிஜ்ஞா, response);
#endif /* WITH_OPENSSL */
	நிலை SSH_SK_ED25519:
		திரும்பு pack_sig_ed25519(ப்ரதிஜ்ஞா, response);
	இயல்பு:
		திரும்பு -1;
	}
}

/* Checks sk_options for sk_sign() and sk_load_resident_keys() */
நிலையான முழு
check_sign_load_resident_options(கட்டமைப்பு sk_option **options, எழுத்து **devicep)
{
	size_t i;

	எனில் (options == வெற்று)
		திரும்பு 0;
	க்கு (i = 0; options[i] != வெற்று; i++) {
		எனில் (strcmp(options[i]->name, "device") == 0) {
			எனில் ((*devicep = strdup(options[i]->மதிப்பு)) == வெற்று) {
				skdebug(__func__, "strdup device failed");
				திரும்பு -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} இல்லையெனில் {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			எனில் (options[i]->required) {
				skdebug(__func__, "unknown required option");
				திரும்பு -1;
			}
		}
	}
	திரும்பு 0;
}

முழு
sk_sign(uint32_t alg, மாறிலி uint8_t *data, size_t datalen,
    மாறிலி எழுத்து *application,
    மாறிலி uint8_t *சாவி_handle, size_t சாவி_handle_len,
    uint8_t flags, மாறிலி எழுத்து *pin, கட்டமைப்பு sk_option **options,
    கட்டமைப்பு sk_sign_response **sign_response)
{
	fido_assert_t *ப்ரதிஜ்ஞா = வெற்று;
	எழுத்து *device = வெற்று;
	கட்டமைப்பு sk_usbhid *sk = வெற்று;
	கட்டமைப்பு sk_sign_response *response = வெற்று;
	முழு ret = SSH_SK_ERR_GENERAL, internal_uv;
	முழு r;

	fido_init(SSH_FIDO_INIT_ARG);

	எனில் (sign_response == வெற்று) {
		skdebug(__func__, "sign_response == NULL");
		செல் out;
	}
	*sign_response = வெற்று;
	எனில் (check_sign_load_resident_options(options, &device) != 0)
		செல் out; /* error already logged */
	எனில் (device != வெற்று)
		sk = sk_open(device);
	இல்லையெனில் எனில் (pin != வெற்று || (flags & SSH_SK_USER_VERIFICATION_REQD))
		sk = sk_probe(வெற்று, வெற்று, 0, 0);
	இல்லையெனில்
		sk = sk_probe(application, சாவி_handle, சாவி_handle_len, 0);
	எனில் (sk == வெற்று) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		செல் out;
	}
	எனில் ((ப்ரதிஜ்ஞா = fido_assert_new()) == வெற்று) {
		skdebug(__func__, "fido_assert_new failed");
		செல் out;
	}
	எனில் ((r = fido_assert_set_clientdata(ப்ரதிஜ்ஞா,
	    data, datalen)) != FIDO_OK)  {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		செல் out;
	}
	எனில் ((r = fido_assert_set_rp(ப்ரதிஜ்ஞா, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		செல் out;
	}
	எனில் ((r = fido_assert_allow_cred(ப்ரதிஜ்ஞா, சாவி_handle,
	    சாவி_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		செல் out;
	}
	எனில் ((r = fido_assert_set_up(ப்ரதிஜ்ஞா,
	    (flags & SSH_SK_USER_PRESENCE_REQD) ?
	    FIDO_OPT_TRUE : FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		செல் out;
	}
	/*
	 * WinHello requests the PIN by default.  Make "uv" request explicit
	 * to allow keys with and without -O verify-required to make sense.
	 */
	எனில் (pin == வெற்று && fido_dev_is_winhello (sk->dev) &&
	    (r = fido_assert_set_uv(ப்ரதிஜ்ஞா, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
	}
	எனில் (pin == வெற்று && (flags & SSH_SK_USER_VERIFICATION_REQD)) {
		எனில் (check_sk_options(sk->dev, "uv", &internal_uv) < 0 ||
		    internal_uv != 1) {
			skdebug(__func__, "check_sk_options uv");
			ret = SSH_SK_ERR_PIN_REQUIRED;
			செல் out;
		}
		எனில் ((r = fido_assert_set_uv(ப்ரதிஜ்ஞா,
		    FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_assert_set_uv: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			செல் out;
		}
	}
	எனில் ((r = fido_dev_get_assert(sk->dev, ப்ரதிஜ்ஞா, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		செல் out;
	}
	எனில் ((response = calloc(1, அளவு(*response))) == வெற்று) {
		skdebug(__func__, "calloc response failed");
		செல் out;
	}
	response->flags = fido_assert_flags(ப்ரதிஜ்ஞா, 0);
	response->counter = fido_assert_sigcount(ப்ரதிஜ்ஞா, 0);
	எனில் (pack_sig(alg, ப்ரதிஜ்ஞா, response) != 0) {
		skdebug(__func__, "pack_sig failed");
		செல் out;
	}
	*sign_response = response;
	response = வெற்று;
	ret = 0;
 out:
	விடுவி(device);
	எனில் (response != வெற்று) {
		விடுவி(response->sig_r);
		விடுவி(response->sig_s);
		விடுவி(response);
	}
	sk_close(sk);
	fido_assert_free(&ப்ரதிஜ்ஞா);
	திரும்பு ret;
}

நிலையான முழு
read_rks(கட்டமைப்பு sk_usbhid *sk, மாறிலி எழுத்து *pin,
    கட்டமைப்பு sk_resident_சாவி ***rksp, size_t *nrksp)
{
	முழு ret = SSH_SK_ERR_GENERAL, r = -1;
	uint32_t alg;
	fido_credman_metadata_t *metadata = வெற்று;
	fido_credman_rp_t *rp = வெற்று;
	fido_credman_rk_t *rk = வெற்று;
	size_t i, j, nrp, nrk, user_id_len;
	மாறிலி fido_cred_t *cred;
	மாறிலி எழுத்து *rp_id, *rp_name, *user_name;
	கட்டமைப்பு sk_resident_சாவி *srk = வெற்று, **tmp;
	மாறிலி u_char *user_id;

	எனில் (pin == வெற்று) {
		skdebug(__func__, "no PIN specified");
		ret = SSH_SK_ERR_PIN_REQUIRED;
		செல் out;
	}
	எனில் ((metadata = fido_credman_metadata_new()) == வெற்று) {
		skdebug(__func__, "alloc failed");
		செல் out;
	}
	எனில் ((r = fido_credman_get_dev_metadata(sk->dev, metadata, pin)) != 0) {
		எனில் (r == FIDO_ERR_INVALID_COMMAND) {
			skdebug(__func__, "device %s does not support "
			    "resident keys", sk->path);
			ret = 0;
			செல் out;
		}
		skdebug(__func__, "get metadata for %s failed: %s",
		    sk->path, fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		செல் out;
	}
	skdebug(__func__, "existing %llu, remaining %llu",
	    (unsigned long long)fido_credman_rk_existing(metadata),
	    (unsigned long long)fido_credman_rk_remaining(metadata));
	எனில் ((rp = fido_credman_rp_new()) == வெற்று) {
		skdebug(__func__, "alloc rp failed");
		செல் out;
	}
	எனில் ((r = fido_credman_get_dev_rp(sk->dev, rp, pin)) != 0) {
		skdebug(__func__, "get RPs for %s failed: %s",
		    sk->path, fido_strerr(r));
		செல் out;
	}
	nrp = fido_credman_rp_மொத்தம்(rp);
	skdebug(__func__, "Device %s has resident keys for %zu RPs",
	    sk->path, nrp);

	/* Iterate over RP IDs that have resident keys */
	க்கு (i = 0; i < nrp; i++) {
		rp_id = fido_credman_rp_id(rp, i);
		rp_name = fido_credman_rp_name(rp, i);
		skdebug(__func__, "rp %zu: name=\"%s\" id=\"%s\" hashlen=%zu",
		    i, rp_name == வெற்று ? "(none)" : rp_name,
		    rp_id == வெற்று ? "(none)" : rp_id,
		    fido_credman_rp_id_hash_len(rp, i));

		/* Skip non-SSH RP IDs */
		எனில் (rp_id == வெற்று ||
		    strncasecmp(fido_credman_rp_id(rp, i), "ssh:", 4) != 0)
			தொடர்;

		fido_credman_rk_free(&rk);
		எனில் ((rk = fido_credman_rk_new()) == வெற்று) {
			skdebug(__func__, "alloc rk failed");
			செல் out;
		}
		எனில் ((r = fido_credman_get_dev_rk(sk->dev,
		    fido_credman_rp_id(rp, i), rk, pin)) != 0) {
			skdebug(__func__, "get RKs for %s slot %zu failed: %s",
			    sk->path, i, fido_strerr(r));
			செல் out;
		}
		nrk = fido_credman_rk_மொத்தம்(rk);
		skdebug(__func__, "RP \"%s\" has %zu resident keys",
		    fido_credman_rp_id(rp, i), nrk);

		/* Iterate over resident keys for this RP ID */
		க்கு (j = 0; j < nrk; j++) {
			எனில் ((cred = fido_credman_rk(rk, j)) == வெற்று) {
				skdebug(__func__, "no RK in slot %zu", j);
				தொடர்;
			}
			எனில் ((user_name = fido_cred_user_name(cred)) == வெற்று)
				user_name = "";
			user_id = fido_cred_user_id_ptr(cred);
			user_id_len = fido_cred_user_id_len(cred);
			skdebug(__func__, "Device %s RP \"%s\" user \"%s\" "
			    "uidlen %zu slot %zu: type %d flags 0x%02x "
			    "prot 0x%02x", sk->path, rp_id, user_name,
			    user_id_len, j, fido_cred_type(cred),
			    fido_cred_flags(cred), fido_cred_prot(cred));

			/* Determine key algorithm */
			தேர்வு (fido_cred_type(cred)) {
			நிலை COSE_ES256:
				alg = SSH_SK_ECDSA;
				நிறுத்து;
			நிலை COSE_EDDSA:
				alg = SSH_SK_ED25519;
				நிறுத்து;
			இயல்பு:
				skdebug(__func__, "unsupported key type %d",
				    fido_cred_type(cred));
				தொடர்;
			}

			/* build response entry */
			எனில் ((srk = calloc(1, அளவு(*srk))) == வெற்று ||
			    (srk->சாவி.சாவி_handle = calloc(1,
			    fido_cred_id_len(cred))) == வெற்று ||
			    (srk->application = strdup(rp_id)) == வெற்று ||
			    (user_id_len > 0 &&
			     (srk->user_id = calloc(1, user_id_len)) == வெற்று)) {
				skdebug(__func__, "alloc sk_resident_key");
				செல் out;
			}

			srk->alg = alg;
			srk->சாவி.சாவி_handle_len = fido_cred_id_len(cred);
			memcpy(srk->சாவி.சாவி_handle, fido_cred_id_ptr(cred),
			    srk->சாவி.சாவி_handle_len);
			srk->user_id_len = user_id_len;
			எனில் (srk->user_id_len != 0)
				memcpy(srk->user_id, user_id, srk->user_id_len);

#ifdef HAVE_FIDO_CRED_PROT
			எனில் (fido_cred_prot(cred) ==
			    FIDO_CRED_PROT_UV_REQUIRED)
				srk->flags |=  SSH_SK_USER_VERIFICATION_REQD;
#endif

			எனில் ((r = pack_public_சாவி(srk->alg, cred,
			    &srk->சாவி)) != 0) {
				skdebug(__func__, "pack public key failed");
				செல் out;
			}
			/* append */
			எனில் ((tmp = recallocarray(*rksp, *nrksp, (*nrksp) + 1,
			    அளவு(**rksp))) == வெற்று) {
				skdebug(__func__, "alloc rksp");
				செல் out;
			}
			*rksp = tmp;
			(*rksp)[(*nrksp)++] = srk;
			srk = வெற்று;
		}
	}
	/* Success */
	ret = 0;
 out:
	எனில் (srk != வெற்று) {
		விடுவி(srk->application);
		freezero(srk->சாவி.public_சாவி, srk->சாவி.public_சாவி_len);
		freezero(srk->சாவி.சாவி_handle, srk->சாவி.சாவி_handle_len);
		freezero(srk->user_id, srk->user_id_len);
		freezero(srk, அளவு(*srk));
	}
	fido_credman_rp_free(&rp);
	fido_credman_rk_free(&rk);
	fido_credman_metadata_free(&metadata);
	திரும்பு ret;
}

முழு
sk_load_resident_சாவிகள்(மாறிலி எழுத்து *pin, கட்டமைப்பு sk_option **options,
    கட்டமைப்பு sk_resident_சாவி ***rksp, size_t *nrksp)
{
	முழு ret = SSH_SK_ERR_GENERAL, r = -1;
	size_t i, nrks = 0;
	கட்டமைப்பு sk_resident_சாவி **rks = வெற்று;
	கட்டமைப்பு sk_usbhid *sk = வெற்று;
	எழுத்து *device = வெற்று;

	*rksp = வெற்று;
	*nrksp = 0;

	fido_init(SSH_FIDO_INIT_ARG);

	எனில் (check_sign_load_resident_options(options, &device) != 0)
		செல் out; /* error already logged */
	எனில் (device != வெற்று)
		sk = sk_open(device);
	இல்லையெனில்
		sk = sk_probe(வெற்று, வெற்று, 0, 1);
	எனில் (sk == வெற்று) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		செல் out;
	}
	skdebug(__func__, "trying %s", sk->path);
	எனில் ((r = read_rks(sk, pin, &rks, &nrks)) != 0) {
		skdebug(__func__, "read_rks failed for %s", sk->path);
		ret = r;
		செல் out;
	}
	/* success, unless we have no keys but a specific error */
	எனில் (nrks > 0 || ret == SSH_SK_ERR_GENERAL)
		ret = 0;
	*rksp = rks;
	*nrksp = nrks;
	rks = வெற்று;
	nrks = 0;
 out:
	sk_close(sk);
	க்கு (i = 0; i < nrks; i++) {
		விடுவி(rks[i]->application);
		freezero(rks[i]->சாவி.public_சாவி, rks[i]->சாவி.public_சாவி_len);
		freezero(rks[i]->சாவி.சாவி_handle, rks[i]->சாவி.சாவி_handle_len);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i], அளவு(*rks[i]));
	}
	விடுவி(device);
	விடுவி(rks);
	திரும்பு ret;
}

#endif /* ENABLE_SK_INTERNAL */
