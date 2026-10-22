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

#അന്തര്ഭാവ "includes.h"

#ifdef ENABLE_SK_INTERNAL

#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <time.h>
#ifdef HAVE_SHA2_H
#അന്തര്ഭാവ <sha2.h>
#endif

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/opensslv.h>
#അന്തര്ഭാവ <openssl/crypto.h>
#അന്തര്ഭാവ <openssl/bn.h>
#അന്തര്ഭാവ <openssl/ec.h>
#അന്തര്ഭാവ <openssl/ecdsa.h>
#അന്തര്ഭാവ <openssl/evp.h>
#അന്തര്ഭാവ "openbsd-compat/openssl-compat.h"
#endif /* WITH_OPENSSL */

#അന്തര്ഭാവ <fido.h>
#അന്തര്ഭാവ <fido/credman.h>

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
# define sk_load_resident_താക്കോലുകൾ	ssh_sk_load_resident_താക്കോലുകൾ
#endif /* !SK_STANDALONE */

#അന്തര്ഭാവ "sk-api.h"

/* #define SK_DEBUG 1 */

#ifdef SK_DEBUG
#define SSH_FIDO_INIT_ARG	FIDO_DEBUG
#അല്ലെങ്കിൽ
#define SSH_FIDO_INIT_ARG	0
#endif

#define MAX_FIDO_DEVICES	8
#define FIDO_POLL_MS		50
#define SELECT_MS		15000
#define POLL_SLEEP_NS		200000000

#ifndef FIDO_ERR_OPERATION_DENIED
#define FIDO_ERR_OPERATION_DENIED 0x27
#endif

ഘടന sk_usbhid {
	fido_dev_t *dev;
	അക്ഷരം *path;
};

/* Return the version of the middleware API */
uint32_t sk_api_version(ശൂന്യം);

/* Enroll a U2F key (private key generation) */
പൂർണ്ണസംഖ്യ sk_enroll(uint32_t alg, സ്ഥിരം uint8_t *challenge, size_t challenge_len,
    സ്ഥിരം അക്ഷരം *application, uint8_t flags, സ്ഥിരം അക്ഷരം *pin,
    ഘടന sk_option **options, ഘടന sk_enroll_response **enroll_response);

/* Sign a challenge */
പൂർണ്ണസംഖ്യ sk_sign(uint32_t alg, സ്ഥിരം uint8_t *data, size_t data_len,
    സ്ഥിരം അക്ഷരം *application, സ്ഥിരം uint8_t *താക്കോൽ_handle, size_t താക്കോൽ_handle_len,
    uint8_t flags, സ്ഥിരം അക്ഷരം *pin, ഘടന sk_option **options,
    ഘടന sk_sign_response **sign_response);

/* Load resident keys */
പൂർണ്ണസംഖ്യ sk_load_resident_താക്കോലുകൾ(സ്ഥിരം അക്ഷരം *pin, ഘടന sk_option **options,
    ഘടന sk_resident_താക്കോൽ ***rks, size_t *nrks);

സ്ഥിതം ശൂന്യം skdebug(സ്ഥിരം അക്ഷരം *func, സ്ഥിരം അക്ഷരം *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

സ്ഥിതം ശൂന്യം
skdebug(സ്ഥിരം അക്ഷരം *func, സ്ഥിരം അക്ഷരം *fmt, ...)
{
#എങ്കിൽ !defined(SK_STANDALONE)
	അക്ഷരം *സന്ദേശം;
	va_list ap;

	va_start(ap, fmt);
	xvasprintf(&സന്ദേശം, fmt, ap);
	va_end(ap);
	debug("%s: %s", func, സന്ദേശം);
	സ്വതന്ത്രം(സന്ദേശം);
#അല്ലെങ്കിലെങ്കിൽ defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#അല്ലെങ്കിൽ
	(ശൂന്യം)func; /* XXX */
	(ശൂന്യം)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(ശൂന്യം)
{
	തിരികെ SSH_SK_VERSION_MAJOR;
}

സ്ഥിതം ഘടന sk_usbhid *
sk_open(സ്ഥിരം അക്ഷരം *path)
{
	ഘടന sk_usbhid *sk;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (path == ശൂന്യ) {
		skdebug(__func__, "path == NULL");
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ ((sk = calloc(1, വലുപ്പം(*sk))) == ശൂന്യ) {
		skdebug(__func__, "calloc sk failed");
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ ((sk->path = strdup(path)) == ശൂന്യ) {
		skdebug(__func__, "strdup path failed");
		സ്വതന്ത്രം(sk);
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ ((sk->dev = fido_dev_new()) == ശൂന്യ) {
		skdebug(__func__, "fido_dev_new failed");
		സ്വതന്ത്രം(sk->path);
		സ്വതന്ത്രം(sk);
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ ((r = fido_dev_open(sk->dev, sk->path)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_open %s failed: %s", sk->path,
		    fido_strerr(r));
		fido_dev_free(&sk->dev);
		സ്വതന്ത്രം(sk->path);
		സ്വതന്ത്രം(sk);
		തിരികെ ശൂന്യ;
	}
	തിരികെ sk;
}

സ്ഥിതം ശൂന്യം
sk_close(ഘടന sk_usbhid *sk)
{
	എങ്കിൽ (sk == ശൂന്യ)
		തിരികെ;
	fido_dev_cancel(sk->dev); /* cancel any pending operation */
	fido_dev_close(sk->dev);
	fido_dev_free(&sk->dev);
	സ്വതന്ത്രം(sk->path);
	സ്വതന്ത്രം(sk);
}

സ്ഥിതം ഘടന sk_usbhid **
sk_openv(സ്ഥിരം fido_dev_info_t *devlist, size_t ndevs, size_t *nopen)
{
	സ്ഥിരം fido_dev_info_t *di;
	ഘടന sk_usbhid **skv;
	size_t i;

	*nopen = 0;
	എങ്കിൽ ((skv = calloc(ndevs, വലുപ്പം(*skv))) == ശൂന്യ) {
		skdebug(__func__, "calloc skv failed");
		തിരികെ ശൂന്യ;
	}
	വേണ്ടി (i = 0; i < ndevs; i++) {
		എങ്കിൽ ((di = fido_dev_info_ptr(devlist, i)) == ശൂന്യ)
			skdebug(__func__, "fido_dev_info_ptr failed");
		അല്ലെങ്കിൽ എങ്കിൽ ((skv[*nopen] = sk_open(fido_dev_info_path(di))) == ശൂന്യ)
			skdebug(__func__, "sk_open failed");
		അല്ലെങ്കിൽ
			(*nopen)++;
	}
	എങ്കിൽ (*nopen == 0) {
		വേണ്ടി (i = 0; i < ndevs; i++)
			sk_close(skv[i]);
		സ്വതന്ത്രം(skv);
		skv = ശൂന്യ;
	}

	തിരികെ skv;
}

സ്ഥിതം ശൂന്യം
sk_closev(ഘടന sk_usbhid **skv, size_t nsk)
{
	size_t i;

	വേണ്ടി (i = 0; i < nsk; i++)
		sk_close(skv[i]);
	സ്വതന്ത്രം(skv);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sk_touch_begin(ഘടന sk_usbhid **skv, size_t nsk)
{
	size_t i, ok = 0;
	പൂർണ്ണസംഖ്യ r;

	വേണ്ടി (i = 0; i < nsk; i++)
		എങ്കിൽ ((r = fido_dev_get_touch_begin(skv[i]->dev)) != FIDO_OK)
			skdebug(__func__, "fido_dev_get_touch_begin %s failed:"
			    " %s", skv[i]->path, fido_strerr(r));
		അല്ലെങ്കിൽ
			ok++;

	തിരികെ ok ? 0 : -1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sk_touch_poll(ഘടന sk_usbhid **skv, size_t nsk, പൂർണ്ണസംഖ്യ *touch, size_t *idx)
{
	ഘടന timespec ts_pause;
	size_t npoll, i;
	പൂർണ്ണസംഖ്യ r;

	ts_pause.tv_sec = 0;
	ts_pause.tv_nsec = POLL_SLEEP_NS;
	nanosleep(&ts_pause, ശൂന്യ);
	npoll = nsk;
	വേണ്ടി (i = 0; i < nsk; i++) {
		എങ്കിൽ (skv[i] == ശൂന്യ)
			തുടരുക; /* device discarded */
		skdebug(__func__, "polling %s", skv[i]->path);
		എങ്കിൽ ((r = fido_dev_get_touch_status(skv[i]->dev, touch,
		    FIDO_POLL_MS)) != FIDO_OK) {
			skdebug(__func__, "fido_dev_get_touch_status %s: %s",
			    skv[i]->path, fido_strerr(r));
			sk_close(skv[i]); /* discard device */
			skv[i] = ശൂന്യ;
			എങ്കിൽ (--npoll == 0) {
				skdebug(__func__, "no device left to poll");
				തിരികെ -1;
			}
		} അല്ലെങ്കിൽ എങ്കിൽ (*touch) {
			*idx = i;
			തിരികെ 0;
		}
	}
	*touch = 0;
	തിരികെ 0;
}

#എങ്കിൽ !defined(HAVE_FIDO_ASSERT_SET_CLIENTDATA) || \
    !defined(HAVE_FIDO_CRED_SET_CLIENTDATA)
/* Calculate SHA256(m) */
സ്ഥിതം പൂർണ്ണസംഖ്യ
sha256_mem(സ്ഥിരം ശൂന്യം *m, size_t mlen, u_char *d, size_t dlen)
{
#ifdef WITH_OPENSSL
	u_int mdlen;
#അല്ലെങ്കിൽ
	SHA2_CTX ctx;
#endif

	എങ്കിൽ (dlen != 32)
		തിരികെ -1;
#ifdef WITH_OPENSSL
	mdlen = dlen;
	എങ്കിൽ (!EVP_Digest(m, mlen, d, &mdlen, EVP_sha256(), ശൂന്യ))
		തിരികെ -1;
#അല്ലെങ്കിൽ
	SHA256Init(&ctx);
	SHA256Update(&ctx, (സ്ഥിരം uint8_t *)m, mlen);
	SHA256Final(d, &ctx);
#endif
	തിരികെ 0;
}
#endif /* !HAVE_FIDO_ASSERT_SET_CLIENTDATA || !HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_CRED_SET_CLIENTDATA
സ്ഥിതം പൂർണ്ണസംഖ്യ
fido_cred_set_clientdata(fido_cred_t *cred, സ്ഥിരം u_char *ptr, size_t len)
{
	uint8_t d[32];
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (sha256_mem(ptr, len, d, വലുപ്പം(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		തിരികെ FIDO_ERR_INTERNAL;
	}
	r = fido_cred_set_clientdata_hash(cred, d, വലുപ്പം(d));
	explicit_bzero(d, വലുപ്പം(d));
	എങ്കിൽ (r != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	തിരികെ r;
}
#endif /* HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_ASSERT_SET_CLIENTDATA
സ്ഥിതം പൂർണ്ണസംഖ്യ
fido_assert_set_clientdata(fido_assert_t *പ്രതിജ്ഞാ, സ്ഥിരം u_char *ptr, size_t len)
{
	uint8_t d[32];
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (sha256_mem(ptr, len, d, വലുപ്പം(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		തിരികെ FIDO_ERR_INTERNAL;
	}
	r = fido_assert_set_clientdata_hash(പ്രതിജ്ഞാ, d, വലുപ്പം(d));
	explicit_bzero(d, വലുപ്പം(d));
	എങ്കിൽ (r != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	തിരികെ r;
}
#endif /* HAVE_FIDO_ASSERT_SET_CLIENTDATA */

#ifndef HAVE_FIDO_DEV_IS_WINHELLO
സ്ഥിതം bool
fido_dev_is_winhello(സ്ഥിരം fido_dev_t *fdev)
{
	തിരികെ 0;
}
#endif /* HAVE_FIDO_DEV_IS_WINHELLO */

/* Check if the specified key handle exists on a given sk. */
സ്ഥിതം പൂർണ്ണസംഖ്യ
sk_try(സ്ഥിരം ഘടന sk_usbhid *sk, സ്ഥിരം അക്ഷരം *application,
    സ്ഥിരം uint8_t *താക്കോൽ_handle, size_t താക്കോൽ_handle_len)
{
	fido_assert_t *പ്രതിജ്ഞാ = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = FIDO_ERR_INTERNAL;
	uint8_t message[32];

	memset(message, '\0', വലുപ്പം(message));
	എങ്കിൽ ((പ്രതിജ്ഞാ = fido_assert_new()) == ശൂന്യ) {
		skdebug(__func__, "fido_assert_new failed");
		പോകുക out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	എങ്കിൽ ((r = fido_assert_set_clientdata(പ്രതിജ്ഞാ, message,
	    വലുപ്പം(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		പോകുക out;
	}
	എങ്കിൽ ((r = fido_assert_set_rp(പ്രതിജ്ഞാ, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		പോകുക out;
	}
	എങ്കിൽ ((r = fido_assert_allow_cred(പ്രതിജ്ഞാ, താക്കോൽ_handle,
	    താക്കോൽ_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		പോകുക out;
	}
	എങ്കിൽ ((r = fido_assert_set_up(പ്രതിജ്ഞാ, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_up: %s", fido_strerr(r));
		പോകുക out;
	}
	r = fido_dev_get_assert(sk->dev, പ്രതിജ്ഞാ, ശൂന്യ);
	skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
	എങ്കിൽ (r == FIDO_ERR_USER_PRESENCE_REQUIRED) {
		/* U2F tokens may return this */
		r = FIDO_OK;
	}
 out:
	fido_assert_free(&പ്രതിജ്ഞാ);

	തിരികെ r != FIDO_OK ? -1 : 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
check_sk_options(fido_dev_t *dev, സ്ഥിരം അക്ഷരം *opt, പൂർണ്ണസംഖ്യ *ret)
{
	fido_cbor_info_t *info;
	അക്ഷരം * സ്ഥിരം *name;
	സ്ഥിരം bool *മൂല്യം;
	size_t len, i;
	പൂർണ്ണസംഖ്യ r;

	*ret = -1;

	എങ്കിൽ (!fido_dev_is_fido2(dev)) {
		skdebug(__func__, "device is not fido2");
		തിരികെ 0;
	}
	എങ്കിൽ ((info = fido_cbor_info_new()) == ശൂന്യ) {
		skdebug(__func__, "fido_cbor_info_new failed");
		തിരികെ -1;
	}
	എങ്കിൽ ((r = fido_dev_get_cbor_info(dev, info)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_cbor_info: %s", fido_strerr(r));
		fido_cbor_info_free(&info);
		തിരികെ -1;
	}
	name = fido_cbor_info_options_name_ptr(info);
	മൂല്യം = fido_cbor_info_options_മൂല്യം_ptr(info);
	len = fido_cbor_info_options_len(info);
	വേണ്ടി (i = 0; i < len; i++) {
		എങ്കിൽ (!strcmp(name[i], opt)) {
			*ret = മൂല്യം[i];
			നിർത്തുക;
		}
	}
	fido_cbor_info_free(&info);
	എങ്കിൽ (*ret == -1)
		skdebug(__func__, "option %s is unknown", opt);
	അല്ലെങ്കിൽ
		skdebug(__func__, "option %s is %s", opt, *ret ? "on" : "off");

	തിരികെ 0;
}

സ്ഥിതം ഘടന sk_usbhid *
sk_select_by_cred(സ്ഥിരം fido_dev_info_t *devlist, size_t ndevs,
    സ്ഥിരം അക്ഷരം *application, സ്ഥിരം uint8_t *താക്കോൽ_handle, size_t താക്കോൽ_handle_len)
{
	ഘടന sk_usbhid **skv, *sk;
	size_t skvcnt, i;
	പൂർണ്ണസംഖ്യ internal_uv;

	എങ്കിൽ ((skv = sk_openv(devlist, ndevs, &skvcnt)) == ശൂന്യ) {
		skdebug(__func__, "sk_openv failed");
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ (skvcnt == 1 && check_sk_options(skv[0]->dev, "uv",
	    &internal_uv) == 0 && internal_uv != -1) {
		sk = skv[0];
		skv[0] = ശൂന്യ;
		പോകുക out;
	}
	sk = ശൂന്യ;
	വേണ്ടി (i = 0; i < skvcnt; i++) {
		എങ്കിൽ (sk_try(skv[i], application, താക്കോൽ_handle,
		    താക്കോൽ_handle_len) == 0) {
			sk = skv[i];
			skv[i] = ശൂന്യ;
			skdebug(__func__, "found key in %s", sk->path);
			നിർത്തുക;
		}
	}
 out:
	sk_closev(skv, skvcnt);
	തിരികെ sk;
}

സ്ഥിതം ഘടന sk_usbhid *
sk_select_by_touch(സ്ഥിരം fido_dev_info_t *devlist, size_t ndevs)
{
	ഘടന sk_usbhid **skv, *sk;
	ഘടന timeval tv_start, tv_now, tv_delta;
	size_t skvcnt, idx;
	പൂർണ്ണസംഖ്യ touch, ms_remain;

	എങ്കിൽ ((skv = sk_openv(devlist, ndevs, &skvcnt)) == ശൂന്യ) {
		skdebug(__func__, "sk_openv failed");
		തിരികെ ശൂന്യ;
	}
	sk = ശൂന്യ;
	എങ്കിൽ (skvcnt < 2) {
		എങ്കിൽ (skvcnt == 1) {
			/* single candidate */
			sk = skv[0];
			skv[0] = ശൂന്യ;
		}
		പോകുക out;
	}
#ifndef HAVE_FIDO_DEV_GET_TOUCH_STATUS
	skdebug(__func__, "libfido2 version does not support a feature needed for multiple tokens. Please upgrade to >=1.5.0");
	പോകുക out;
#endif

	എങ്കിൽ (sk_touch_begin(skv, skvcnt) == -1) {
		skdebug(__func__, "sk_touch_begin failed");
		പോകുക out;
	}
	monotime_tv(&tv_start);
	ചെയ്യുക {
		എങ്കിൽ (sk_touch_poll(skv, skvcnt, &touch, &idx) == -1) {
			skdebug(__func__, "sk_touch_poll failed");
			പോകുക out;
		}
		എങ്കിൽ (touch) {
			sk = skv[idx];
			skv[idx] = ശൂന്യ;
			പോകുക out;
		}
		monotime_tv(&tv_now);
		timersub(&tv_now, &tv_start, &tv_delta);
		ms_remain = SELECT_MS - tv_delta.tv_sec * 1000 -
		    tv_delta.tv_usec / 1000;
	} ആകുമ്പോൾ (ms_remain >= FIDO_POLL_MS);
	skdebug(__func__, "timeout");
out:
	sk_closev(skv, skvcnt);
	തിരികെ sk;
}

സ്ഥിതം ഘടന sk_usbhid *
sk_probe(സ്ഥിരം അക്ഷരം *application, സ്ഥിരം uint8_t *താക്കോൽ_handle,
    size_t താക്കോൽ_handle_len, പൂർണ്ണസംഖ്യ probe_resident)
{
	ഘടന sk_usbhid *sk;
	fido_dev_info_t *devlist;
	size_t ndevs;
	പൂർണ്ണസംഖ്യ r;

#ifdef HAVE_CYGWIN
	എങ്കിൽ (!probe_resident && (sk = sk_open("windows://hello")) != ശൂന്യ)
		തിരികെ sk;
#endif /* HAVE_CYGWIN */
	എങ്കിൽ ((devlist = fido_dev_info_new(MAX_FIDO_DEVICES)) == ശൂന്യ) {
		skdebug(__func__, "fido_dev_info_new failed");
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ ((r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES,
	    &ndevs)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_info_manifest failed: %s",
		    fido_strerr(r));
		fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
		തിരികെ ശൂന്യ;
	}
	skdebug(__func__, "%zu device(s) detected", ndevs);
	എങ്കിൽ (ndevs == 0) {
		sk = ശൂന്യ;
	} അല്ലെങ്കിൽ എങ്കിൽ (application != ശൂന്യ && താക്കോൽ_handle != ശൂന്യ) {
		skdebug(__func__, "selecting sk by cred");
		sk = sk_select_by_cred(devlist, ndevs, application, താക്കോൽ_handle,
		    താക്കോൽ_handle_len);
	} അല്ലെങ്കിൽ {
		skdebug(__func__, "selecting sk by touch");
		sk = sk_select_by_touch(devlist, ndevs);
	}
	fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
	തിരികെ sk;
}

#ifdef WITH_OPENSSL
/*
 * The key returned via fido_cred_pubkey_ptr() is in affine coordinates,
 * but the API expects a SEC1 octet string.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
pack_public_താക്കോൽ_ecdsa(സ്ഥിരം fido_cred_t *cred,
    ഘടന sk_enroll_response *response)
{
	സ്ഥിരം uint8_t *ptr;
	BIGNUM *x = ശൂന്യ, *y = ശൂന്യ;
	EC_POINT *q = ശൂന്യ;
	EC_GROUP *g = ശൂന്യ;
	പൂർണ്ണസംഖ്യ ret = -1;

	response->public_താക്കോൽ = ശൂന്യ;
	response->public_താക്കോൽ_len = 0;

	എങ്കിൽ ((x = BN_new()) == ശൂന്യ ||
	    (y = BN_new()) == ശൂന്യ ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == ശൂന്യ ||
	    (q = EC_POINT_new(g)) == ശൂന്യ) {
		skdebug(__func__, "libcrypto setup failed");
		പോകുക out;
	}
	എങ്കിൽ ((ptr = fido_cred_pubkey_ptr(cred)) == ശൂന്യ) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		പോകുക out;
	}
	എങ്കിൽ (fido_cred_pubkey_len(cred) != 64) {
		skdebug(__func__, "bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		പോകുക out;
	}

	എങ്കിൽ (BN_bin2bn(ptr, 32, x) == ശൂന്യ ||
	    BN_bin2bn(ptr + 32, 32, y) == ശൂന്യ) {
		skdebug(__func__, "BN_bin2bn failed");
		പോകുക out;
	}
	എങ്കിൽ (EC_POINT_set_affine_coordinates(g, q, x, y, ശൂന്യ) != 1) {
		skdebug(__func__, "EC_POINT_set_affine_coordinates failed");
		പോകുക out;
	}
	response->public_താക്കോൽ_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, ശൂന്യ, 0, ശൂന്യ);
	എങ്കിൽ (response->public_താക്കോൽ_len == 0 || response->public_താക്കോൽ_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_താക്കോൽ_len);
		പോകുക out;
	}
	എങ്കിൽ ((response->public_താക്കോൽ = malloc(response->public_താക്കോൽ_len)) == ശൂന്യ) {
		skdebug(__func__, "malloc pubkey failed");
		പോകുക out;
	}
	എങ്കിൽ (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_താക്കോൽ, response->public_താക്കോൽ_len, ശൂന്യ) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		പോകുക out;
	}
	/* success */
	ret = 0;
 out:
	എങ്കിൽ (ret != 0 && response->public_താക്കോൽ != ശൂന്യ) {
		memset(response->public_താക്കോൽ, 0, response->public_താക്കോൽ_len);
		സ്വതന്ത്രം(response->public_താക്കോൽ);
		response->public_താക്കോൽ = ശൂന്യ;
	}
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	തിരികെ ret;
}
#endif /* WITH_OPENSSL */

സ്ഥിതം പൂർണ്ണസംഖ്യ
pack_public_താക്കോൽ_ed25519(സ്ഥിരം fido_cred_t *cred,
    ഘടന sk_enroll_response *response)
{
	സ്ഥിരം uint8_t *ptr;
	size_t len;
	പൂർണ്ണസംഖ്യ ret = -1;

	response->public_താക്കോൽ = ശൂന്യ;
	response->public_താക്കോൽ_len = 0;

	എങ്കിൽ ((len = fido_cred_pubkey_len(cred)) != 32) {
		skdebug(__func__, "bad fido_cred_pubkey_len len %zu", len);
		പോകുക out;
	}
	എങ്കിൽ ((ptr = fido_cred_pubkey_ptr(cred)) == ശൂന്യ) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		പോകുക out;
	}
	response->public_താക്കോൽ_len = len;
	എങ്കിൽ ((response->public_താക്കോൽ = malloc(response->public_താക്കോൽ_len)) == ശൂന്യ) {
		skdebug(__func__, "malloc pubkey failed");
		പോകുക out;
	}
	memcpy(response->public_താക്കോൽ, ptr, len);
	ret = 0;
 out:
	എങ്കിൽ (ret != 0)
		സ്വതന്ത്രം(response->public_താക്കോൽ);
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
pack_public_താക്കോൽ(uint32_t alg, സ്ഥിരം fido_cred_t *cred,
    ഘടന sk_enroll_response *response)
{
	തിരഞ്ഞെടുപ്പ്(alg) {
#ifdef WITH_OPENSSL
	അവസ്ഥ SSH_SK_ECDSA:
		തിരികെ pack_public_താക്കോൽ_ecdsa(cred, response);
#endif /* WITH_OPENSSL */
	അവസ്ഥ SSH_SK_ED25519:
		തിരികെ pack_public_താക്കോൽ_ed25519(cred, response);
	സ്ഥിരസ്ഥിതി:
		തിരികെ -1;
	}
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
fidoerr_to_skerr(പൂർണ്ണസംഖ്യ fidoerr)
{
	തിരഞ്ഞെടുപ്പ് (fidoerr) {
	അവസ്ഥ FIDO_ERR_UNSUPPORTED_OPTION:
	അവസ്ഥ FIDO_ERR_UNSUPPORTED_ALGORITHM:
		തിരികെ SSH_SK_ERR_UNSUPPORTED;
	അവസ്ഥ FIDO_ERR_PIN_REQUIRED:
	അവസ്ഥ FIDO_ERR_PIN_INVALID:
	അവസ്ഥ FIDO_ERR_OPERATION_DENIED:
		തിരികെ SSH_SK_ERR_PIN_REQUIRED;
	സ്ഥിരസ്ഥിതി:
		തിരികെ -1;
	}
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
check_enroll_options(ഘടന sk_option **options, അക്ഷരം **devicep,
    uint8_t *user_id, size_t user_id_len)
{
	size_t i;

	എങ്കിൽ (options == ശൂന്യ)
		തിരികെ 0;
	വേണ്ടി (i = 0; options[i] != ശൂന്യ; i++) {
		എങ്കിൽ (strcmp(options[i]->name, "device") == 0) {
			എങ്കിൽ ((*devicep = strdup(options[i]->മൂല്യം)) == ശൂന്യ) {
				skdebug(__func__, "strdup device failed");
				തിരികെ -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(options[i]->name, "user") == 0) {
			എങ്കിൽ (strlcpy(user_id, options[i]->മൂല്യം, user_id_len) >=
			    user_id_len) {
				skdebug(__func__, "user too long");
				തിരികെ -1;
			}
			skdebug(__func__, "requested user %s",
			    (അക്ഷരം *)user_id);
		} അല്ലെങ്കിൽ {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			എങ്കിൽ (options[i]->required) {
				skdebug(__func__, "unknown required option");
				തിരികെ -1;
			}
		}
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
താക്കോൽ_lookup(fido_dev_t *dev, സ്ഥിരം അക്ഷരം *application, സ്ഥിരം uint8_t *user_id,
    size_t user_id_len, സ്ഥിരം അക്ഷരം *pin)
{
	fido_assert_t *പ്രതിജ്ഞാ = ശൂന്യ;
	uint8_t message[32];
	പൂർണ്ണസംഖ്യ r = FIDO_ERR_INTERNAL;
	പൂർണ്ണസംഖ്യ sk_supports_uv, uv;
	size_t i;

	memset(message, '\0', വലുപ്പം(message));
	എങ്കിൽ ((പ്രതിജ്ഞാ = fido_assert_new()) == ശൂന്യ) {
		skdebug(__func__, "fido_assert_new failed");
		പോകുക out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	എങ്കിൽ ((r = fido_assert_set_clientdata(പ്രതിജ്ഞാ, message,
	    വലുപ്പം(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		പോകുക out;
	}
	എങ്കിൽ ((r = fido_assert_set_rp(പ്രതിജ്ഞാ, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		പോകുക out;
	}
	എങ്കിൽ ((r = fido_assert_set_up(പ്രതിജ്ഞാ, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		പോകുക out;
	}
	uv = FIDO_OPT_OMIT;
	എങ്കിൽ (pin == ശൂന്യ && check_sk_options(dev, "uv", &sk_supports_uv) == 0 &&
	    sk_supports_uv != -1)
		uv = FIDO_OPT_TRUE;
	എങ്കിൽ ((r = fido_assert_set_uv(പ്രതിജ്ഞാ, uv)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
		പോകുക out;
	}
	എങ്കിൽ ((r = fido_dev_get_assert(dev, പ്രതിജ്ഞാ, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		പോകുക out;
	}
	r = FIDO_ERR_NO_CREDENTIALS;
	skdebug(__func__, "%zu signatures returned", fido_assert_എണ്ണം(പ്രതിജ്ഞാ));
	വേണ്ടി (i = 0; i < fido_assert_എണ്ണം(പ്രതിജ്ഞാ); i++) {
		എങ്കിൽ (fido_assert_user_id_len(പ്രതിജ്ഞാ, i) == user_id_len &&
		    memcmp(fido_assert_user_id_ptr(പ്രതിജ്ഞാ, i), user_id,
		    user_id_len) == 0) {
			skdebug(__func__, "credential exists");
			r = FIDO_OK;
			പോകുക out;
		}
	}
 out:
	fido_assert_free(&പ്രതിജ്ഞാ);

	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sk_enroll(uint32_t alg, സ്ഥിരം uint8_t *challenge, size_t challenge_len,
    സ്ഥിരം അക്ഷരം *application, uint8_t flags, സ്ഥിരം അക്ഷരം *pin,
    ഘടന sk_option **options, ഘടന sk_enroll_response **enroll_response)
{
	fido_cred_t *cred = ശൂന്യ;
	സ്ഥിരം uint8_t *ptr;
	uint8_t user_id[32];
	ഘടന sk_usbhid *sk = ശൂന്യ;
	ഘടന sk_enroll_response *response = ശൂന്യ;
	size_t len;
	പൂർണ്ണസംഖ്യ credprot;
	പൂർണ്ണസംഖ്യ cose_alg;
	പൂർണ്ണസംഖ്യ ret = SSH_SK_ERR_GENERAL;
	പൂർണ്ണസംഖ്യ r;
	അക്ഷരം *device = ശൂന്യ;

	fido_init(SSH_FIDO_INIT_ARG);

	എങ്കിൽ (enroll_response == ശൂന്യ) {
		skdebug(__func__, "enroll_response == NULL");
		പോകുക out;
	}
	*enroll_response = ശൂന്യ;
	memset(user_id, 0, വലുപ്പം(user_id));
	എങ്കിൽ (check_enroll_options(options, &device, user_id,
	    വലുപ്പം(user_id)) != 0)
		പോകുക out; /* error already logged */

	തിരഞ്ഞെടുപ്പ്(alg) {
#ifdef WITH_OPENSSL
	അവസ്ഥ SSH_SK_ECDSA:
		cose_alg = COSE_ES256;
		നിർത്തുക;
#endif /* WITH_OPENSSL */
	അവസ്ഥ SSH_SK_ED25519:
		cose_alg = COSE_EDDSA;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		skdebug(__func__, "unsupported key type %d", alg);
		പോകുക out;
	}
	എങ്കിൽ (device != ശൂന്യ)
		sk = sk_open(device);
	അല്ലെങ്കിൽ
		sk = sk_probe(ശൂന്യ, ശൂന്യ, 0, 0);
	എങ്കിൽ (sk == ശൂന്യ) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		പോകുക out;
	}
	skdebug(__func__, "using device %s", sk->path);
	എങ്കിൽ ((flags & SSH_SK_RESIDENT_താക്കോൽ) != 0 &&
	    (flags & SSH_SK_FORCE_OPERATION) == 0 &&
	    (r = താക്കോൽ_lookup(sk->dev, application, user_id, വലുപ്പം(user_id),
	    pin)) != FIDO_ERR_NO_CREDENTIALS) {
		എങ്കിൽ (r != FIDO_OK) {
			ret = fidoerr_to_skerr(r);
			skdebug(__func__, "key_lookup failed");
		} അല്ലെങ്കിൽ {
			ret = SSH_SK_ERR_CREDENTIAL_EXISTS;
			skdebug(__func__, "key exists");
		}
		പോകുക out;
	}
	എങ്കിൽ ((cred = fido_cred_new()) == ശൂന്യ) {
		skdebug(__func__, "fido_cred_new failed");
		പോകുക out;
	}
	എങ്കിൽ ((r = fido_cred_set_type(cred, cose_alg)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_type: %s", fido_strerr(r));
		പോകുക out;
	}
	എങ്കിൽ ((r = fido_cred_set_clientdata(cred,
	    challenge, challenge_len)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata: %s",
		    fido_strerr(r));
		പോകുക out;
	}
	എങ്കിൽ ((r = fido_cred_set_rk(cred, (flags & SSH_SK_RESIDENT_താക്കോൽ) != 0 ?
	    FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rk: %s", fido_strerr(r));
		പോകുക out;
	}
	എങ്കിൽ ((r = fido_cred_set_user(cred, user_id, വലുപ്പം(user_id),
	    "openssh", "openssh", ശൂന്യ)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_user: %s", fido_strerr(r));
		പോകുക out;
	}
	എങ്കിൽ ((r = fido_cred_set_rp(cred, application, ശൂന്യ)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rp: %s", fido_strerr(r));
		പോകുക out;
	}
	എങ്കിൽ ((flags & (SSH_SK_RESIDENT_താക്കോൽ|SSH_SK_USER_VERIFICATION_REQD)) != 0) {
#എങ്കിൽ !defined(HAVE_FIDO_DEV_SUPPORTS_CRED_PROT) || \
    !defined(HAVE_FIDO_CRED_SET_PROT)
		skdebug(__func__, "libfido2 version does not support a feature required for this operation. Please upgrade to >=1.5.0");
		ret = SSH_SK_ERR_UNSUPPORTED;
		പോകുക out;
		credprot = 0; (ശൂന്യം)credprot; /* avoid warning */
#endif
		എങ്കിൽ (!fido_dev_supports_cred_prot(sk->dev)) {
			skdebug(__func__, "%s does not support credprot, "
			    "refusing to create unprotected "
			    "resident/verify-required key", sk->path);
			ret = SSH_SK_ERR_UNSUPPORTED;
			പോകുക out;
		}
		എങ്കിൽ ((flags & SSH_SK_USER_VERIFICATION_REQD))
			credprot = FIDO_CRED_PROT_UV_REQUIRED;
		അല്ലെങ്കിൽ
			credprot = FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID;

		എങ്കിൽ ((r = fido_cred_set_prot(cred, credprot)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_set_prot: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			പോകുക out;
		}
	}
	എങ്കിൽ ((r = fido_dev_make_cred(sk->dev, cred, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_make_cred: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		പോകുക out;
	}
	എങ്കിൽ (fido_cred_x5c_ptr(cred) != ശൂന്യ) {
		എങ്കിൽ ((r = fido_cred_verify(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify: %s",
			    fido_strerr(r));
			പോകുക out;
		}
	} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(fido_cred_fmt(cred), "none") != 0) {
		skdebug(__func__, "self-attested credential");
		എങ്കിൽ ((r = fido_cred_verify_self(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify_self: %s",
			    fido_strerr(r));
			പോകുക out;
		}
	} അല്ലെങ്കിൽ {
		skdebug(__func__, "no attestation data");
	}
	എങ്കിൽ ((response = calloc(1, വലുപ്പം(*response))) == ശൂന്യ) {
		skdebug(__func__, "calloc response failed");
		പോകുക out;
	}
	response->flags = flags;
	എങ്കിൽ (pack_public_താക്കോൽ(alg, cred, response) != 0) {
		skdebug(__func__, "pack_public_key failed");
		പോകുക out;
	}
	എങ്കിൽ ((ptr = fido_cred_id_ptr(cred)) != ശൂന്യ) {
		len = fido_cred_id_len(cred);
		എങ്കിൽ ((response->താക്കോൽ_handle = calloc(1, len)) == ശൂന്യ) {
			skdebug(__func__, "calloc key handle failed");
			പോകുക out;
		}
		memcpy(response->താക്കോൽ_handle, ptr, len);
		response->താക്കോൽ_handle_len = len;
	}
	എങ്കിൽ ((ptr = fido_cred_sig_ptr(cred)) != ശൂന്യ) {
		len = fido_cred_sig_len(cred);
		എങ്കിൽ ((response->signature = calloc(1, len)) == ശൂന്യ) {
			skdebug(__func__, "calloc signature failed");
			പോകുക out;
		}
		memcpy(response->signature, ptr, len);
		response->signature_len = len;
	}
	എങ്കിൽ ((ptr = fido_cred_x5c_ptr(cred)) != ശൂന്യ) {
		len = fido_cred_x5c_len(cred);
		skdebug(__func__, "attestation cert len=%zu", len);
		എങ്കിൽ ((response->attestation_cert = calloc(1, len)) == ശൂന്യ) {
			skdebug(__func__, "calloc attestation cert failed");
			പോകുക out;
		}
		memcpy(response->attestation_cert, ptr, len);
		response->attestation_cert_len = len;
	}
	എങ്കിൽ ((ptr = fido_cred_authdata_ptr(cred)) != ശൂന്യ) {
		len = fido_cred_authdata_len(cred);
		skdebug(__func__, "authdata len=%zu", len);
		എങ്കിൽ ((response->authdata = calloc(1, len)) == ശൂന്യ) {
			skdebug(__func__, "calloc authdata failed");
			പോകുക out;
		}
		memcpy(response->authdata, ptr, len);
		response->authdata_len = len;
	}
	*enroll_response = response;
	response = ശൂന്യ;
	ret = 0;
 out:
	സ്വതന്ത്രം(device);
	എങ്കിൽ (response != ശൂന്യ) {
		സ്വതന്ത്രം(response->public_താക്കോൽ);
		സ്വതന്ത്രം(response->താക്കോൽ_handle);
		സ്വതന്ത്രം(response->signature);
		സ്വതന്ത്രം(response->attestation_cert);
		സ്വതന്ത്രം(response->authdata);
		സ്വതന്ത്രം(response);
	}
	sk_close(sk);
	fido_cred_free(&cred);
	തിരികെ ret;
}

#ifdef WITH_OPENSSL
സ്ഥിതം പൂർണ്ണസംഖ്യ
pack_sig_ecdsa(fido_assert_t *പ്രതിജ്ഞാ, ഘടന sk_sign_response *response)
{
	ECDSA_SIG *sig = ശൂന്യ;
	സ്ഥിരം BIGNUM *sig_r, *sig_s;
	സ്ഥിരം unsigned അക്ഷരം *cp;
	size_t sig_len;
	പൂർണ്ണസംഖ്യ ret = -1;

	cp = fido_assert_sig_ptr(പ്രതിജ്ഞാ, 0);
	sig_len = fido_assert_sig_len(പ്രതിജ്ഞാ, 0);
	എങ്കിൽ ((sig = d2i_ECDSA_SIG(ശൂന്യ, &cp, sig_len)) == ശൂന്യ) {
		skdebug(__func__, "d2i_ECDSA_SIG failed");
		പോകുക out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_അക്കം_bytes(sig_r);
	response->sig_s_len = BN_അക്കം_bytes(sig_s);
	എങ്കിൽ ((response->sig_r = calloc(1, response->sig_r_len)) == ശൂന്യ ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == ശൂന്യ) {
		skdebug(__func__, "calloc signature failed");
		പോകുക out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	ECDSA_SIG_free(sig);
	എങ്കിൽ (ret != 0) {
		സ്വതന്ത്രം(response->sig_r);
		സ്വതന്ത്രം(response->sig_s);
		response->sig_r = ശൂന്യ;
		response->sig_s = ശൂന്യ;
	}
	തിരികെ ret;
}
#endif /* WITH_OPENSSL */

സ്ഥിതം പൂർണ്ണസംഖ്യ
pack_sig_ed25519(fido_assert_t *പ്രതിജ്ഞാ, ഘടന sk_sign_response *response)
{
	സ്ഥിരം unsigned അക്ഷരം *ptr;
	size_t len;
	പൂർണ്ണസംഖ്യ ret = -1;

	ptr = fido_assert_sig_ptr(പ്രതിജ്ഞാ, 0);
	len = fido_assert_sig_len(പ്രതിജ്ഞാ, 0);
	എങ്കിൽ (len != 64) {
		skdebug(__func__, "bad length %zu", len);
		പോകുക out;
	}
	response->sig_r_len = len;
	എങ്കിൽ ((response->sig_r = calloc(1, response->sig_r_len)) == ശൂന്യ) {
		skdebug(__func__, "calloc signature failed");
		പോകുക out;
	}
	memcpy(response->sig_r, ptr, len);
	ret = 0;
 out:
	എങ്കിൽ (ret != 0) {
		സ്വതന്ത്രം(response->sig_r);
		response->sig_r = ശൂന്യ;
	}
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
pack_sig(uint32_t  alg, fido_assert_t *പ്രതിജ്ഞാ,
    ഘടന sk_sign_response *response)
{
	തിരഞ്ഞെടുപ്പ്(alg) {
#ifdef WITH_OPENSSL
	അവസ്ഥ SSH_SK_ECDSA:
		തിരികെ pack_sig_ecdsa(പ്രതിജ്ഞാ, response);
#endif /* WITH_OPENSSL */
	അവസ്ഥ SSH_SK_ED25519:
		തിരികെ pack_sig_ed25519(പ്രതിജ്ഞാ, response);
	സ്ഥിരസ്ഥിതി:
		തിരികെ -1;
	}
}

/* Checks sk_options for sk_sign() and sk_load_resident_keys() */
സ്ഥിതം പൂർണ്ണസംഖ്യ
check_sign_load_resident_options(ഘടന sk_option **options, അക്ഷരം **devicep)
{
	size_t i;

	എങ്കിൽ (options == ശൂന്യ)
		തിരികെ 0;
	വേണ്ടി (i = 0; options[i] != ശൂന്യ; i++) {
		എങ്കിൽ (strcmp(options[i]->name, "device") == 0) {
			എങ്കിൽ ((*devicep = strdup(options[i]->മൂല്യം)) == ശൂന്യ) {
				skdebug(__func__, "strdup device failed");
				തിരികെ -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} അല്ലെങ്കിൽ {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			എങ്കിൽ (options[i]->required) {
				skdebug(__func__, "unknown required option");
				തിരികെ -1;
			}
		}
	}
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sk_sign(uint32_t alg, സ്ഥിരം uint8_t *data, size_t datalen,
    സ്ഥിരം അക്ഷരം *application,
    സ്ഥിരം uint8_t *താക്കോൽ_handle, size_t താക്കോൽ_handle_len,
    uint8_t flags, സ്ഥിരം അക്ഷരം *pin, ഘടന sk_option **options,
    ഘടന sk_sign_response **sign_response)
{
	fido_assert_t *പ്രതിജ്ഞാ = ശൂന്യ;
	അക്ഷരം *device = ശൂന്യ;
	ഘടന sk_usbhid *sk = ശൂന്യ;
	ഘടന sk_sign_response *response = ശൂന്യ;
	പൂർണ്ണസംഖ്യ ret = SSH_SK_ERR_GENERAL, internal_uv;
	പൂർണ്ണസംഖ്യ r;

	fido_init(SSH_FIDO_INIT_ARG);

	എങ്കിൽ (sign_response == ശൂന്യ) {
		skdebug(__func__, "sign_response == NULL");
		പോകുക out;
	}
	*sign_response = ശൂന്യ;
	എങ്കിൽ (check_sign_load_resident_options(options, &device) != 0)
		പോകുക out; /* error already logged */
	എങ്കിൽ (device != ശൂന്യ)
		sk = sk_open(device);
	അല്ലെങ്കിൽ എങ്കിൽ (pin != ശൂന്യ || (flags & SSH_SK_USER_VERIFICATION_REQD))
		sk = sk_probe(ശൂന്യ, ശൂന്യ, 0, 0);
	അല്ലെങ്കിൽ
		sk = sk_probe(application, താക്കോൽ_handle, താക്കോൽ_handle_len, 0);
	എങ്കിൽ (sk == ശൂന്യ) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		പോകുക out;
	}
	എങ്കിൽ ((പ്രതിജ്ഞാ = fido_assert_new()) == ശൂന്യ) {
		skdebug(__func__, "fido_assert_new failed");
		പോകുക out;
	}
	എങ്കിൽ ((r = fido_assert_set_clientdata(പ്രതിജ്ഞാ,
	    data, datalen)) != FIDO_OK)  {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		പോകുക out;
	}
	എങ്കിൽ ((r = fido_assert_set_rp(പ്രതിജ്ഞാ, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		പോകുക out;
	}
	എങ്കിൽ ((r = fido_assert_allow_cred(പ്രതിജ്ഞാ, താക്കോൽ_handle,
	    താക്കോൽ_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		പോകുക out;
	}
	എങ്കിൽ ((r = fido_assert_set_up(പ്രതിജ്ഞാ,
	    (flags & SSH_SK_USER_PRESENCE_REQD) ?
	    FIDO_OPT_TRUE : FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		പോകുക out;
	}
	/*
	 * WinHello requests the PIN by default.  Make "uv" request explicit
	 * to allow keys with and without -O verify-required to make sense.
	 */
	എങ്കിൽ (pin == ശൂന്യ && fido_dev_is_winhello (sk->dev) &&
	    (r = fido_assert_set_uv(പ്രതിജ്ഞാ, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
	}
	എങ്കിൽ (pin == ശൂന്യ && (flags & SSH_SK_USER_VERIFICATION_REQD)) {
		എങ്കിൽ (check_sk_options(sk->dev, "uv", &internal_uv) < 0 ||
		    internal_uv != 1) {
			skdebug(__func__, "check_sk_options uv");
			ret = SSH_SK_ERR_PIN_REQUIRED;
			പോകുക out;
		}
		എങ്കിൽ ((r = fido_assert_set_uv(പ്രതിജ്ഞാ,
		    FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_assert_set_uv: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			പോകുക out;
		}
	}
	എങ്കിൽ ((r = fido_dev_get_assert(sk->dev, പ്രതിജ്ഞാ, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		പോകുക out;
	}
	എങ്കിൽ ((response = calloc(1, വലുപ്പം(*response))) == ശൂന്യ) {
		skdebug(__func__, "calloc response failed");
		പോകുക out;
	}
	response->flags = fido_assert_flags(പ്രതിജ്ഞാ, 0);
	response->counter = fido_assert_sigcount(പ്രതിജ്ഞാ, 0);
	എങ്കിൽ (pack_sig(alg, പ്രതിജ്ഞാ, response) != 0) {
		skdebug(__func__, "pack_sig failed");
		പോകുക out;
	}
	*sign_response = response;
	response = ശൂന്യ;
	ret = 0;
 out:
	സ്വതന്ത്രം(device);
	എങ്കിൽ (response != ശൂന്യ) {
		സ്വതന്ത്രം(response->sig_r);
		സ്വതന്ത്രം(response->sig_s);
		സ്വതന്ത്രം(response);
	}
	sk_close(sk);
	fido_assert_free(&പ്രതിജ്ഞാ);
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
read_rks(ഘടന sk_usbhid *sk, സ്ഥിരം അക്ഷരം *pin,
    ഘടന sk_resident_താക്കോൽ ***rksp, size_t *nrksp)
{
	പൂർണ്ണസംഖ്യ ret = SSH_SK_ERR_GENERAL, r = -1;
	uint32_t alg;
	fido_credman_metadata_t *metadata = ശൂന്യ;
	fido_credman_rp_t *rp = ശൂന്യ;
	fido_credman_rk_t *rk = ശൂന്യ;
	size_t i, j, nrp, nrk, user_id_len;
	സ്ഥിരം fido_cred_t *cred;
	സ്ഥിരം അക്ഷരം *rp_id, *rp_name, *user_name;
	ഘടന sk_resident_താക്കോൽ *srk = ശൂന്യ, **tmp;
	സ്ഥിരം u_char *user_id;

	എങ്കിൽ (pin == ശൂന്യ) {
		skdebug(__func__, "no PIN specified");
		ret = SSH_SK_ERR_PIN_REQUIRED;
		പോകുക out;
	}
	എങ്കിൽ ((metadata = fido_credman_metadata_new()) == ശൂന്യ) {
		skdebug(__func__, "alloc failed");
		പോകുക out;
	}
	എങ്കിൽ ((r = fido_credman_get_dev_metadata(sk->dev, metadata, pin)) != 0) {
		എങ്കിൽ (r == FIDO_ERR_INVALID_COMMAND) {
			skdebug(__func__, "device %s does not support "
			    "resident keys", sk->path);
			ret = 0;
			പോകുക out;
		}
		skdebug(__func__, "get metadata for %s failed: %s",
		    sk->path, fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		പോകുക out;
	}
	skdebug(__func__, "existing %llu, remaining %llu",
	    (unsigned long long)fido_credman_rk_existing(metadata),
	    (unsigned long long)fido_credman_rk_remaining(metadata));
	എങ്കിൽ ((rp = fido_credman_rp_new()) == ശൂന്യ) {
		skdebug(__func__, "alloc rp failed");
		പോകുക out;
	}
	എങ്കിൽ ((r = fido_credman_get_dev_rp(sk->dev, rp, pin)) != 0) {
		skdebug(__func__, "get RPs for %s failed: %s",
		    sk->path, fido_strerr(r));
		പോകുക out;
	}
	nrp = fido_credman_rp_എണ്ണം(rp);
	skdebug(__func__, "Device %s has resident keys for %zu RPs",
	    sk->path, nrp);

	/* Iterate over RP IDs that have resident keys */
	വേണ്ടി (i = 0; i < nrp; i++) {
		rp_id = fido_credman_rp_id(rp, i);
		rp_name = fido_credman_rp_name(rp, i);
		skdebug(__func__, "rp %zu: name=\"%s\" id=\"%s\" hashlen=%zu",
		    i, rp_name == ശൂന്യ ? "(none)" : rp_name,
		    rp_id == ശൂന്യ ? "(none)" : rp_id,
		    fido_credman_rp_id_hash_len(rp, i));

		/* Skip non-SSH RP IDs */
		എങ്കിൽ (rp_id == ശൂന്യ ||
		    strncasecmp(fido_credman_rp_id(rp, i), "ssh:", 4) != 0)
			തുടരുക;

		fido_credman_rk_free(&rk);
		എങ്കിൽ ((rk = fido_credman_rk_new()) == ശൂന്യ) {
			skdebug(__func__, "alloc rk failed");
			പോകുക out;
		}
		എങ്കിൽ ((r = fido_credman_get_dev_rk(sk->dev,
		    fido_credman_rp_id(rp, i), rk, pin)) != 0) {
			skdebug(__func__, "get RKs for %s slot %zu failed: %s",
			    sk->path, i, fido_strerr(r));
			പോകുക out;
		}
		nrk = fido_credman_rk_എണ്ണം(rk);
		skdebug(__func__, "RP \"%s\" has %zu resident keys",
		    fido_credman_rp_id(rp, i), nrk);

		/* Iterate over resident keys for this RP ID */
		വേണ്ടി (j = 0; j < nrk; j++) {
			എങ്കിൽ ((cred = fido_credman_rk(rk, j)) == ശൂന്യ) {
				skdebug(__func__, "no RK in slot %zu", j);
				തുടരുക;
			}
			എങ്കിൽ ((user_name = fido_cred_user_name(cred)) == ശൂന്യ)
				user_name = "";
			user_id = fido_cred_user_id_ptr(cred);
			user_id_len = fido_cred_user_id_len(cred);
			skdebug(__func__, "Device %s RP \"%s\" user \"%s\" "
			    "uidlen %zu slot %zu: type %d flags 0x%02x "
			    "prot 0x%02x", sk->path, rp_id, user_name,
			    user_id_len, j, fido_cred_type(cred),
			    fido_cred_flags(cred), fido_cred_prot(cred));

			/* Determine key algorithm */
			തിരഞ്ഞെടുപ്പ് (fido_cred_type(cred)) {
			അവസ്ഥ COSE_ES256:
				alg = SSH_SK_ECDSA;
				നിർത്തുക;
			അവസ്ഥ COSE_EDDSA:
				alg = SSH_SK_ED25519;
				നിർത്തുക;
			സ്ഥിരസ്ഥിതി:
				skdebug(__func__, "unsupported key type %d",
				    fido_cred_type(cred));
				തുടരുക;
			}

			/* build response entry */
			എങ്കിൽ ((srk = calloc(1, വലുപ്പം(*srk))) == ശൂന്യ ||
			    (srk->താക്കോൽ.താക്കോൽ_handle = calloc(1,
			    fido_cred_id_len(cred))) == ശൂന്യ ||
			    (srk->application = strdup(rp_id)) == ശൂന്യ ||
			    (user_id_len > 0 &&
			     (srk->user_id = calloc(1, user_id_len)) == ശൂന്യ)) {
				skdebug(__func__, "alloc sk_resident_key");
				പോകുക out;
			}

			srk->alg = alg;
			srk->താക്കോൽ.താക്കോൽ_handle_len = fido_cred_id_len(cred);
			memcpy(srk->താക്കോൽ.താക്കോൽ_handle, fido_cred_id_ptr(cred),
			    srk->താക്കോൽ.താക്കോൽ_handle_len);
			srk->user_id_len = user_id_len;
			എങ്കിൽ (srk->user_id_len != 0)
				memcpy(srk->user_id, user_id, srk->user_id_len);

#ifdef HAVE_FIDO_CRED_PROT
			എങ്കിൽ (fido_cred_prot(cred) ==
			    FIDO_CRED_PROT_UV_REQUIRED)
				srk->flags |=  SSH_SK_USER_VERIFICATION_REQD;
#endif

			എങ്കിൽ ((r = pack_public_താക്കോൽ(srk->alg, cred,
			    &srk->താക്കോൽ)) != 0) {
				skdebug(__func__, "pack public key failed");
				പോകുക out;
			}
			/* append */
			എങ്കിൽ ((tmp = recallocarray(*rksp, *nrksp, (*nrksp) + 1,
			    വലുപ്പം(**rksp))) == ശൂന്യ) {
				skdebug(__func__, "alloc rksp");
				പോകുക out;
			}
			*rksp = tmp;
			(*rksp)[(*nrksp)++] = srk;
			srk = ശൂന്യ;
		}
	}
	/* Success */
	ret = 0;
 out:
	എങ്കിൽ (srk != ശൂന്യ) {
		സ്വതന്ത്രം(srk->application);
		freezero(srk->താക്കോൽ.public_താക്കോൽ, srk->താക്കോൽ.public_താക്കോൽ_len);
		freezero(srk->താക്കോൽ.താക്കോൽ_handle, srk->താക്കോൽ.താക്കോൽ_handle_len);
		freezero(srk->user_id, srk->user_id_len);
		freezero(srk, വലുപ്പം(*srk));
	}
	fido_credman_rp_free(&rp);
	fido_credman_rk_free(&rk);
	fido_credman_metadata_free(&metadata);
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
sk_load_resident_താക്കോലുകൾ(സ്ഥിരം അക്ഷരം *pin, ഘടന sk_option **options,
    ഘടന sk_resident_താക്കോൽ ***rksp, size_t *nrksp)
{
	പൂർണ്ണസംഖ്യ ret = SSH_SK_ERR_GENERAL, r = -1;
	size_t i, nrks = 0;
	ഘടന sk_resident_താക്കോൽ **rks = ശൂന്യ;
	ഘടന sk_usbhid *sk = ശൂന്യ;
	അക്ഷരം *device = ശൂന്യ;

	*rksp = ശൂന്യ;
	*nrksp = 0;

	fido_init(SSH_FIDO_INIT_ARG);

	എങ്കിൽ (check_sign_load_resident_options(options, &device) != 0)
		പോകുക out; /* error already logged */
	എങ്കിൽ (device != ശൂന്യ)
		sk = sk_open(device);
	അല്ലെങ്കിൽ
		sk = sk_probe(ശൂന്യ, ശൂന്യ, 0, 1);
	എങ്കിൽ (sk == ശൂന്യ) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		പോകുക out;
	}
	skdebug(__func__, "trying %s", sk->path);
	എങ്കിൽ ((r = read_rks(sk, pin, &rks, &nrks)) != 0) {
		skdebug(__func__, "read_rks failed for %s", sk->path);
		ret = r;
		പോകുക out;
	}
	/* success, unless we have no keys but a specific error */
	എങ്കിൽ (nrks > 0 || ret == SSH_SK_ERR_GENERAL)
		ret = 0;
	*rksp = rks;
	*nrksp = nrks;
	rks = ശൂന്യ;
	nrks = 0;
 out:
	sk_close(sk);
	വേണ്ടി (i = 0; i < nrks; i++) {
		സ്വതന്ത്രം(rks[i]->application);
		freezero(rks[i]->താക്കോൽ.public_താക്കോൽ, rks[i]->താക്കോൽ.public_താക്കോൽ_len);
		freezero(rks[i]->താക്കോൽ.താക്കോൽ_handle, rks[i]->താക്കോൽ.താക്കോൽ_handle_len);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i], വലുപ്പം(*rks[i]));
	}
	സ്വതന്ത്രം(device);
	സ്വതന്ത്രം(rks);
	തിരികെ ret;
}

#endif /* ENABLE_SK_INTERNAL */
