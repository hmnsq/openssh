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

#অন্তর্ভাৱ "includes.h"

#ifdef ENABLE_SK_INTERNAL

#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stddef.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <time.h>
#ifdef HAVE_SHA2_H
#অন্তর্ভাৱ <sha2.h>
#endif

#ifdef WITH_OPENSSL
#অন্তর্ভাৱ <openssl/opensslv.h>
#অন্তর্ভাৱ <openssl/crypto.h>
#অন্তর্ভাৱ <openssl/bn.h>
#অন্তর্ভাৱ <openssl/ec.h>
#অন্তর্ভাৱ <openssl/ecdsa.h>
#অন্তর্ভাৱ <openssl/evp.h>
#অন্তর্ভাৱ "openbsd-compat/openssl-compat.h"
#endif /* WITH_OPENSSL */

#অন্তর্ভাৱ <fido.h>
#অন্তর্ভাৱ <fido/credman.h>

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
# define sk_load_resident_চাবিগুলি	ssh_sk_load_resident_চাবিগুলি
#endif /* !SK_STANDALONE */

#অন্তর্ভাৱ "sk-api.h"

/* #define SK_DEBUG 1 */

#ifdef SK_DEBUG
#define SSH_FIDO_INIT_ARG	FIDO_DEBUG
#অন্যথা
#define SSH_FIDO_INIT_ARG	0
#endif

#define MAX_FIDO_DEVICES	8
#define FIDO_POLL_MS		50
#define SELECT_MS		15000
#define POLL_SLEEP_NS		200000000

#ifndef FIDO_ERR_OPERATION_DENIED
#define FIDO_ERR_OPERATION_DENIED 0x27
#endif

সংরচনা sk_usbhid {
	fido_dev_t *dev;
	ৱর্ণ *path;
};

/* Return the version of the middleware API */
uint32_t sk_api_version(শূন্য);

/* Enroll a U2F key (private key generation) */
পূর্ণাঙ্ক sk_enroll(uint32_t alg, ধ্রুৱ uint8_t *challenge, size_t challenge_len,
    ধ্রুৱ ৱর্ণ *application, uint8_t flags, ধ্রুৱ ৱর্ণ *pin,
    সংরচনা sk_option **options, সংরচনা sk_enroll_response **enroll_response);

/* Sign a challenge */
পূর্ণাঙ্ক sk_sign(uint32_t alg, ধ্রুৱ uint8_t *data, size_t data_len,
    ধ্রুৱ ৱর্ণ *application, ধ্রুৱ uint8_t *চাবি_handle, size_t চাবি_handle_len,
    uint8_t flags, ধ্রুৱ ৱর্ণ *pin, সংরচনা sk_option **options,
    সংরচনা sk_sign_response **sign_response);

/* Load resident keys */
পূর্ণাঙ্ক sk_load_resident_চাবিগুলি(ধ্রুৱ ৱর্ণ *pin, সংরচনা sk_option **options,
    সংরচনা sk_resident_চাবি ***rks, size_t *nrks);

স্থির শূন্য skdebug(ধ্রুৱ ৱর্ণ *func, ধ্রুৱ ৱর্ণ *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

স্থির শূন্য
skdebug(ধ্রুৱ ৱর্ণ *func, ধ্রুৱ ৱর্ণ *fmt, ...)
{
#যদি !defined(SK_STANDALONE)
	ৱর্ণ *বাৰ্তা;
	va_list ap;

	va_start(ap, fmt);
	xvasprintf(&বাৰ্তা, fmt, ap);
	va_end(ap);
	debug("%s: %s", func, বাৰ্তা);
	মুক্ত(বাৰ্তা);
#নোচেদ্যদি defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#অন্যথা
	(শূন্য)func; /* XXX */
	(শূন্য)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(শূন্য)
{
	ঘূৰাই SSH_SK_VERSION_MAJOR;
}

স্থির সংরচনা sk_usbhid *
sk_open(ধ্রুৱ ৱর্ণ *path)
{
	সংরচনা sk_usbhid *sk;
	পূর্ণাঙ্ক r;

	যদি (path == রিক্ত) {
		skdebug(__func__, "path == NULL");
		ঘূৰাই রিক্ত;
	}
	যদি ((sk = calloc(1, পরিমাণ(*sk))) == রিক্ত) {
		skdebug(__func__, "calloc sk failed");
		ঘূৰাই রিক্ত;
	}
	যদি ((sk->path = strdup(path)) == রিক্ত) {
		skdebug(__func__, "strdup path failed");
		মুক্ত(sk);
		ঘূৰাই রিক্ত;
	}
	যদি ((sk->dev = fido_dev_new()) == রিক্ত) {
		skdebug(__func__, "fido_dev_new failed");
		মুক্ত(sk->path);
		মুক্ত(sk);
		ঘূৰাই রিক্ত;
	}
	যদি ((r = fido_dev_open(sk->dev, sk->path)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_open %s failed: %s", sk->path,
		    fido_strerr(r));
		fido_dev_free(&sk->dev);
		মুক্ত(sk->path);
		মুক্ত(sk);
		ঘূৰাই রিক্ত;
	}
	ঘূৰাই sk;
}

স্থির শূন্য
sk_close(সংরচনা sk_usbhid *sk)
{
	যদি (sk == রিক্ত)
		ঘূৰাই;
	fido_dev_cancel(sk->dev); /* cancel any pending operation */
	fido_dev_close(sk->dev);
	fido_dev_free(&sk->dev);
	মুক্ত(sk->path);
	মুক্ত(sk);
}

স্থির সংরচনা sk_usbhid **
sk_openv(ধ্রুৱ fido_dev_info_t *devlist, size_t ndevs, size_t *nopen)
{
	ধ্রুৱ fido_dev_info_t *di;
	সংরচনা sk_usbhid **skv;
	size_t i;

	*nopen = 0;
	যদি ((skv = calloc(ndevs, পরিমাণ(*skv))) == রিক্ত) {
		skdebug(__func__, "calloc skv failed");
		ঘূৰাই রিক্ত;
	}
	বাবে (i = 0; i < ndevs; i++) {
		যদি ((di = fido_dev_info_ptr(devlist, i)) == রিক্ত)
			skdebug(__func__, "fido_dev_info_ptr failed");
		অন্যথা যদি ((skv[*nopen] = sk_open(fido_dev_info_path(di))) == রিক্ত)
			skdebug(__func__, "sk_open failed");
		অন্যথা
			(*nopen)++;
	}
	যদি (*nopen == 0) {
		বাবে (i = 0; i < ndevs; i++)
			sk_close(skv[i]);
		মুক্ত(skv);
		skv = রিক্ত;
	}

	ঘূৰাই skv;
}

স্থির শূন্য
sk_closev(সংরচনা sk_usbhid **skv, size_t nsk)
{
	size_t i;

	বাবে (i = 0; i < nsk; i++)
		sk_close(skv[i]);
	মুক্ত(skv);
}

স্থির পূর্ণাঙ্ক
sk_touch_begin(সংরচনা sk_usbhid **skv, size_t nsk)
{
	size_t i, ok = 0;
	পূর্ণাঙ্ক r;

	বাবে (i = 0; i < nsk; i++)
		যদি ((r = fido_dev_get_touch_begin(skv[i]->dev)) != FIDO_OK)
			skdebug(__func__, "fido_dev_get_touch_begin %s failed:"
			    " %s", skv[i]->path, fido_strerr(r));
		অন্যথা
			ok++;

	ঘূৰাই ok ? 0 : -1;
}

স্থির পূর্ণাঙ্ক
sk_touch_poll(সংরচনা sk_usbhid **skv, size_t nsk, পূর্ণাঙ্ক *touch, size_t *idx)
{
	সংরচনা timespec ts_pause;
	size_t npoll, i;
	পূর্ণাঙ্ক r;

	ts_pause.tv_sec = 0;
	ts_pause.tv_nsec = POLL_SLEEP_NS;
	nanosleep(&ts_pause, রিক্ত);
	npoll = nsk;
	বাবে (i = 0; i < nsk; i++) {
		যদি (skv[i] == রিক্ত)
			অনুৱর্ত; /* device discarded */
		skdebug(__func__, "polling %s", skv[i]->path);
		যদি ((r = fido_dev_get_touch_status(skv[i]->dev, touch,
		    FIDO_POLL_MS)) != FIDO_OK) {
			skdebug(__func__, "fido_dev_get_touch_status %s: %s",
			    skv[i]->path, fido_strerr(r));
			sk_close(skv[i]); /* discard device */
			skv[i] = রিক্ত;
			যদি (--npoll == 0) {
				skdebug(__func__, "no device left to poll");
				ঘূৰাই -1;
			}
		} অন্যথা যদি (*touch) {
			*idx = i;
			ঘূৰাই 0;
		}
	}
	*touch = 0;
	ঘূৰাই 0;
}

#যদি !defined(HAVE_FIDO_ASSERT_SET_CLIENTDATA) || \
    !defined(HAVE_FIDO_CRED_SET_CLIENTDATA)
/* Calculate SHA256(m) */
স্থির পূর্ণাঙ্ক
sha256_mem(ধ্রুৱ শূন্য *m, size_t mlen, u_char *d, size_t dlen)
{
#ifdef WITH_OPENSSL
	u_int mdlen;
#অন্যথা
	SHA2_CTX ctx;
#endif

	যদি (dlen != 32)
		ঘূৰাই -1;
#ifdef WITH_OPENSSL
	mdlen = dlen;
	যদি (!EVP_Digest(m, mlen, d, &mdlen, EVP_sha256(), রিক্ত))
		ঘূৰাই -1;
#অন্যথা
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ধ্রুৱ uint8_t *)m, mlen);
	SHA256Final(d, &ctx);
#endif
	ঘূৰাই 0;
}
#endif /* !HAVE_FIDO_ASSERT_SET_CLIENTDATA || !HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_CRED_SET_CLIENTDATA
স্থির পূর্ণাঙ্ক
fido_cred_set_clientdata(fido_cred_t *cred, ধ্রুৱ u_char *ptr, size_t len)
{
	uint8_t d[32];
	পূর্ণাঙ্ক r;

	যদি (sha256_mem(ptr, len, d, পরিমাণ(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		ঘূৰাই FIDO_ERR_INTERNAL;
	}
	r = fido_cred_set_clientdata_hash(cred, d, পরিমাণ(d));
	explicit_bzero(d, পরিমাণ(d));
	যদি (r != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	ঘূৰাই r;
}
#endif /* HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_ASSERT_SET_CLIENTDATA
স্থির পূর্ণাঙ্ক
fido_assert_set_clientdata(fido_assert_t *প্রতিজ্ঞা, ধ্রুৱ u_char *ptr, size_t len)
{
	uint8_t d[32];
	পূর্ণাঙ্ক r;

	যদি (sha256_mem(ptr, len, d, পরিমাণ(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		ঘূৰাই FIDO_ERR_INTERNAL;
	}
	r = fido_assert_set_clientdata_hash(প্রতিজ্ঞা, d, পরিমাণ(d));
	explicit_bzero(d, পরিমাণ(d));
	যদি (r != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	ঘূৰাই r;
}
#endif /* HAVE_FIDO_ASSERT_SET_CLIENTDATA */

#ifndef HAVE_FIDO_DEV_IS_WINHELLO
স্থির bool
fido_dev_is_winhello(ধ্রুৱ fido_dev_t *fdev)
{
	ঘূৰাই 0;
}
#endif /* HAVE_FIDO_DEV_IS_WINHELLO */

/* Check if the specified key handle exists on a given sk. */
স্থির পূর্ণাঙ্ক
sk_try(ধ্রুৱ সংরচনা sk_usbhid *sk, ধ্রুৱ ৱর্ণ *application,
    ধ্রুৱ uint8_t *চাবি_handle, size_t চাবি_handle_len)
{
	fido_assert_t *প্রতিজ্ঞা = রিক্ত;
	পূর্ণাঙ্ক r = FIDO_ERR_INTERNAL;
	uint8_t message[32];

	memset(message, '\0', পরিমাণ(message));
	যদি ((প্রতিজ্ঞা = fido_assert_new()) == রিক্ত) {
		skdebug(__func__, "fido_assert_new failed");
		গচ্ছ out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	যদি ((r = fido_assert_set_clientdata(প্রতিজ্ঞা, message,
	    পরিমাণ(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		গচ্ছ out;
	}
	যদি ((r = fido_assert_set_rp(প্রতিজ্ঞা, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		গচ্ছ out;
	}
	যদি ((r = fido_assert_allow_cred(প্রতিজ্ঞা, চাবি_handle,
	    চাবি_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		গচ্ছ out;
	}
	যদি ((r = fido_assert_set_up(প্রতিজ্ঞা, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_up: %s", fido_strerr(r));
		গচ্ছ out;
	}
	r = fido_dev_get_assert(sk->dev, প্রতিজ্ঞা, রিক্ত);
	skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
	যদি (r == FIDO_ERR_USER_PRESENCE_REQUIRED) {
		/* U2F tokens may return this */
		r = FIDO_OK;
	}
 out:
	fido_assert_free(&প্রতিজ্ঞা);

	ঘূৰাই r != FIDO_OK ? -1 : 0;
}

স্থির পূর্ণাঙ্ক
check_sk_options(fido_dev_t *dev, ধ্রুৱ ৱর্ণ *opt, পূর্ণাঙ্ক *ret)
{
	fido_cbor_info_t *info;
	ৱর্ণ * ধ্রুৱ *name;
	ধ্রুৱ bool *মান;
	size_t len, i;
	পূর্ণাঙ্ক r;

	*ret = -1;

	যদি (!fido_dev_is_fido2(dev)) {
		skdebug(__func__, "device is not fido2");
		ঘূৰাই 0;
	}
	যদি ((info = fido_cbor_info_new()) == রিক্ত) {
		skdebug(__func__, "fido_cbor_info_new failed");
		ঘূৰাই -1;
	}
	যদি ((r = fido_dev_get_cbor_info(dev, info)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_cbor_info: %s", fido_strerr(r));
		fido_cbor_info_free(&info);
		ঘূৰাই -1;
	}
	name = fido_cbor_info_options_name_ptr(info);
	মান = fido_cbor_info_options_মান_ptr(info);
	len = fido_cbor_info_options_len(info);
	বাবে (i = 0; i < len; i++) {
		যদি (!strcmp(name[i], opt)) {
			*ret = মান[i];
			ভঙ্গ;
		}
	}
	fido_cbor_info_free(&info);
	যদি (*ret == -1)
		skdebug(__func__, "option %s is unknown", opt);
	অন্যথা
		skdebug(__func__, "option %s is %s", opt, *ret ? "on" : "off");

	ঘূৰাই 0;
}

স্থির সংরচনা sk_usbhid *
sk_select_by_cred(ধ্রুৱ fido_dev_info_t *devlist, size_t ndevs,
    ধ্রুৱ ৱর্ণ *application, ধ্রুৱ uint8_t *চাবি_handle, size_t চাবি_handle_len)
{
	সংরচনা sk_usbhid **skv, *sk;
	size_t skvcnt, i;
	পূর্ণাঙ্ক internal_uv;

	যদি ((skv = sk_openv(devlist, ndevs, &skvcnt)) == রিক্ত) {
		skdebug(__func__, "sk_openv failed");
		ঘূৰাই রিক্ত;
	}
	যদি (skvcnt == 1 && check_sk_options(skv[0]->dev, "uv",
	    &internal_uv) == 0 && internal_uv != -1) {
		sk = skv[0];
		skv[0] = রিক্ত;
		গচ্ছ out;
	}
	sk = রিক্ত;
	বাবে (i = 0; i < skvcnt; i++) {
		যদি (sk_try(skv[i], application, চাবি_handle,
		    চাবি_handle_len) == 0) {
			sk = skv[i];
			skv[i] = রিক্ত;
			skdebug(__func__, "found key in %s", sk->path);
			ভঙ্গ;
		}
	}
 out:
	sk_closev(skv, skvcnt);
	ঘূৰাই sk;
}

স্থির সংরচনা sk_usbhid *
sk_select_by_touch(ধ্রুৱ fido_dev_info_t *devlist, size_t ndevs)
{
	সংরচনা sk_usbhid **skv, *sk;
	সংরচনা timeval tv_start, tv_now, tv_delta;
	size_t skvcnt, idx;
	পূর্ণাঙ্ক touch, ms_remain;

	যদি ((skv = sk_openv(devlist, ndevs, &skvcnt)) == রিক্ত) {
		skdebug(__func__, "sk_openv failed");
		ঘূৰাই রিক্ত;
	}
	sk = রিক্ত;
	যদি (skvcnt < 2) {
		যদি (skvcnt == 1) {
			/* single candidate */
			sk = skv[0];
			skv[0] = রিক্ত;
		}
		গচ্ছ out;
	}
#ifndef HAVE_FIDO_DEV_GET_TOUCH_STATUS
	skdebug(__func__, "libfido2 version does not support a feature needed for multiple tokens. Please upgrade to >=1.5.0");
	গচ্ছ out;
#endif

	যদি (sk_touch_begin(skv, skvcnt) == -1) {
		skdebug(__func__, "sk_touch_begin failed");
		গচ্ছ out;
	}
	monotime_tv(&tv_start);
	কৰা {
		যদি (sk_touch_poll(skv, skvcnt, &touch, &idx) == -1) {
			skdebug(__func__, "sk_touch_poll failed");
			গচ্ছ out;
		}
		যদি (touch) {
			sk = skv[idx];
			skv[idx] = রিক্ত;
			গচ্ছ out;
		}
		monotime_tv(&tv_now);
		timersub(&tv_now, &tv_start, &tv_delta);
		ms_remain = SELECT_MS - tv_delta.tv_sec * 1000 -
		    tv_delta.tv_usec / 1000;
	} যেতিয়ালৈ (ms_remain >= FIDO_POLL_MS);
	skdebug(__func__, "timeout");
out:
	sk_closev(skv, skvcnt);
	ঘূৰাই sk;
}

স্থির সংরচনা sk_usbhid *
sk_probe(ধ্রুৱ ৱর্ণ *application, ধ্রুৱ uint8_t *চাবি_handle,
    size_t চাবি_handle_len, পূর্ণাঙ্ক probe_resident)
{
	সংরচনা sk_usbhid *sk;
	fido_dev_info_t *devlist;
	size_t ndevs;
	পূর্ণাঙ্ক r;

#ifdef HAVE_CYGWIN
	যদি (!probe_resident && (sk = sk_open("windows://hello")) != রিক্ত)
		ঘূৰাই sk;
#endif /* HAVE_CYGWIN */
	যদি ((devlist = fido_dev_info_new(MAX_FIDO_DEVICES)) == রিক্ত) {
		skdebug(__func__, "fido_dev_info_new failed");
		ঘূৰাই রিক্ত;
	}
	যদি ((r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES,
	    &ndevs)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_info_manifest failed: %s",
		    fido_strerr(r));
		fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
		ঘূৰাই রিক্ত;
	}
	skdebug(__func__, "%zu device(s) detected", ndevs);
	যদি (ndevs == 0) {
		sk = রিক্ত;
	} অন্যথা যদি (application != রিক্ত && চাবি_handle != রিক্ত) {
		skdebug(__func__, "selecting sk by cred");
		sk = sk_select_by_cred(devlist, ndevs, application, চাবি_handle,
		    চাবি_handle_len);
	} অন্যথা {
		skdebug(__func__, "selecting sk by touch");
		sk = sk_select_by_touch(devlist, ndevs);
	}
	fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
	ঘূৰাই sk;
}

#ifdef WITH_OPENSSL
/*
 * The key returned via fido_cred_pubkey_ptr() is in affine coordinates,
 * but the API expects a SEC1 octet string.
 */
স্থির পূর্ণাঙ্ক
pack_public_চাবি_ecdsa(ধ্রুৱ fido_cred_t *cred,
    সংরচনা sk_enroll_response *response)
{
	ধ্রুৱ uint8_t *ptr;
	BIGNUM *x = রিক্ত, *y = রিক্ত;
	EC_POINT *q = রিক্ত;
	EC_GROUP *g = রিক্ত;
	পূর্ণাঙ্ক ret = -1;

	response->public_চাবি = রিক্ত;
	response->public_চাবি_len = 0;

	যদি ((x = BN_new()) == রিক্ত ||
	    (y = BN_new()) == রিক্ত ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == রিক্ত ||
	    (q = EC_POINT_new(g)) == রিক্ত) {
		skdebug(__func__, "libcrypto setup failed");
		গচ্ছ out;
	}
	যদি ((ptr = fido_cred_pubkey_ptr(cred)) == রিক্ত) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		গচ্ছ out;
	}
	যদি (fido_cred_pubkey_len(cred) != 64) {
		skdebug(__func__, "bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		গচ্ছ out;
	}

	যদি (BN_bin2bn(ptr, 32, x) == রিক্ত ||
	    BN_bin2bn(ptr + 32, 32, y) == রিক্ত) {
		skdebug(__func__, "BN_bin2bn failed");
		গচ্ছ out;
	}
	যদি (EC_POINT_set_affine_coordinates(g, q, x, y, রিক্ত) != 1) {
		skdebug(__func__, "EC_POINT_set_affine_coordinates failed");
		গচ্ছ out;
	}
	response->public_চাবি_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, রিক্ত, 0, রিক্ত);
	যদি (response->public_চাবি_len == 0 || response->public_চাবি_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_চাবি_len);
		গচ্ছ out;
	}
	যদি ((response->public_চাবি = malloc(response->public_চাবি_len)) == রিক্ত) {
		skdebug(__func__, "malloc pubkey failed");
		গচ্ছ out;
	}
	যদি (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_চাবি, response->public_চাবি_len, রিক্ত) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		গচ্ছ out;
	}
	/* success */
	ret = 0;
 out:
	যদি (ret != 0 && response->public_চাবি != রিক্ত) {
		memset(response->public_চাবি, 0, response->public_চাবি_len);
		মুক্ত(response->public_চাবি);
		response->public_চাবি = রিক্ত;
	}
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	ঘূৰাই ret;
}
#endif /* WITH_OPENSSL */

স্থির পূর্ণাঙ্ক
pack_public_চাবি_ed25519(ধ্রুৱ fido_cred_t *cred,
    সংরচনা sk_enroll_response *response)
{
	ধ্রুৱ uint8_t *ptr;
	size_t len;
	পূর্ণাঙ্ক ret = -1;

	response->public_চাবি = রিক্ত;
	response->public_চাবি_len = 0;

	যদি ((len = fido_cred_pubkey_len(cred)) != 32) {
		skdebug(__func__, "bad fido_cred_pubkey_len len %zu", len);
		গচ্ছ out;
	}
	যদি ((ptr = fido_cred_pubkey_ptr(cred)) == রিক্ত) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		গচ্ছ out;
	}
	response->public_চাবি_len = len;
	যদি ((response->public_চাবি = malloc(response->public_চাবি_len)) == রিক্ত) {
		skdebug(__func__, "malloc pubkey failed");
		গচ্ছ out;
	}
	memcpy(response->public_চাবি, ptr, len);
	ret = 0;
 out:
	যদি (ret != 0)
		মুক্ত(response->public_চাবি);
	ঘূৰাই ret;
}

স্থির পূর্ণাঙ্ক
pack_public_চাবি(uint32_t alg, ধ্রুৱ fido_cred_t *cred,
    সংরচনা sk_enroll_response *response)
{
	ৱিকল্প(alg) {
#ifdef WITH_OPENSSL
	পক্ষ SSH_SK_ECDSA:
		ঘূৰাই pack_public_চাবি_ecdsa(cred, response);
#endif /* WITH_OPENSSL */
	পক্ষ SSH_SK_ED25519:
		ঘূৰাই pack_public_চাবি_ed25519(cred, response);
	স্ৱভাৱ:
		ঘূৰাই -1;
	}
}

স্থির পূর্ণাঙ্ক
fidoerr_to_skerr(পূর্ণাঙ্ক fidoerr)
{
	ৱিকল্প (fidoerr) {
	পক্ষ FIDO_ERR_UNSUPPORTED_OPTION:
	পক্ষ FIDO_ERR_UNSUPPORTED_ALGORITHM:
		ঘূৰাই SSH_SK_ERR_UNSUPPORTED;
	পক্ষ FIDO_ERR_PIN_REQUIRED:
	পক্ষ FIDO_ERR_PIN_INVALID:
	পক্ষ FIDO_ERR_OPERATION_DENIED:
		ঘূৰাই SSH_SK_ERR_PIN_REQUIRED;
	স্ৱভাৱ:
		ঘূৰাই -1;
	}
}

স্থির পূর্ণাঙ্ক
check_enroll_options(সংরচনা sk_option **options, ৱর্ণ **devicep,
    uint8_t *user_id, size_t user_id_len)
{
	size_t i;

	যদি (options == রিক্ত)
		ঘূৰাই 0;
	বাবে (i = 0; options[i] != রিক্ত; i++) {
		যদি (strcmp(options[i]->name, "device") == 0) {
			যদি ((*devicep = strdup(options[i]->মান)) == রিক্ত) {
				skdebug(__func__, "strdup device failed");
				ঘূৰাই -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} অন্যথা যদি (strcmp(options[i]->name, "user") == 0) {
			যদি (strlcpy(user_id, options[i]->মান, user_id_len) >=
			    user_id_len) {
				skdebug(__func__, "user too long");
				ঘূৰাই -1;
			}
			skdebug(__func__, "requested user %s",
			    (ৱর্ণ *)user_id);
		} অন্যথা {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			যদি (options[i]->required) {
				skdebug(__func__, "unknown required option");
				ঘূৰাই -1;
			}
		}
	}
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
চাবি_lookup(fido_dev_t *dev, ধ্রুৱ ৱর্ণ *application, ধ্রুৱ uint8_t *user_id,
    size_t user_id_len, ধ্রুৱ ৱর্ণ *pin)
{
	fido_assert_t *প্রতিজ্ঞা = রিক্ত;
	uint8_t message[32];
	পূর্ণাঙ্ক r = FIDO_ERR_INTERNAL;
	পূর্ণাঙ্ক sk_supports_uv, uv;
	size_t i;

	memset(message, '\0', পরিমাণ(message));
	যদি ((প্রতিজ্ঞা = fido_assert_new()) == রিক্ত) {
		skdebug(__func__, "fido_assert_new failed");
		গচ্ছ out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	যদি ((r = fido_assert_set_clientdata(প্রতিজ্ঞা, message,
	    পরিমাণ(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		গচ্ছ out;
	}
	যদি ((r = fido_assert_set_rp(প্রতিজ্ঞা, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		গচ্ছ out;
	}
	যদি ((r = fido_assert_set_up(প্রতিজ্ঞা, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		গচ্ছ out;
	}
	uv = FIDO_OPT_OMIT;
	যদি (pin == রিক্ত && check_sk_options(dev, "uv", &sk_supports_uv) == 0 &&
	    sk_supports_uv != -1)
		uv = FIDO_OPT_TRUE;
	যদি ((r = fido_assert_set_uv(প্রতিজ্ঞা, uv)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
		গচ্ছ out;
	}
	যদি ((r = fido_dev_get_assert(dev, প্রতিজ্ঞা, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		গচ্ছ out;
	}
	r = FIDO_ERR_NO_CREDENTIALS;
	skdebug(__func__, "%zu signatures returned", fido_assert_গুনতি(প্রতিজ্ঞা));
	বাবে (i = 0; i < fido_assert_গুনতি(প্রতিজ্ঞা); i++) {
		যদি (fido_assert_user_id_len(প্রতিজ্ঞা, i) == user_id_len &&
		    memcmp(fido_assert_user_id_ptr(প্রতিজ্ঞা, i), user_id,
		    user_id_len) == 0) {
			skdebug(__func__, "credential exists");
			r = FIDO_OK;
			গচ্ছ out;
		}
	}
 out:
	fido_assert_free(&প্রতিজ্ঞা);

	ঘূৰাই r;
}

পূর্ণাঙ্ক
sk_enroll(uint32_t alg, ধ্রুৱ uint8_t *challenge, size_t challenge_len,
    ধ্রুৱ ৱর্ণ *application, uint8_t flags, ধ্রুৱ ৱর্ণ *pin,
    সংরচনা sk_option **options, সংরচনা sk_enroll_response **enroll_response)
{
	fido_cred_t *cred = রিক্ত;
	ধ্রুৱ uint8_t *ptr;
	uint8_t user_id[32];
	সংরচনা sk_usbhid *sk = রিক্ত;
	সংরচনা sk_enroll_response *response = রিক্ত;
	size_t len;
	পূর্ণাঙ্ক credprot;
	পূর্ণাঙ্ক cose_alg;
	পূর্ণাঙ্ক ret = SSH_SK_ERR_GENERAL;
	পূর্ণাঙ্ক r;
	ৱর্ণ *device = রিক্ত;

	fido_init(SSH_FIDO_INIT_ARG);

	যদি (enroll_response == রিক্ত) {
		skdebug(__func__, "enroll_response == NULL");
		গচ্ছ out;
	}
	*enroll_response = রিক্ত;
	memset(user_id, 0, পরিমাণ(user_id));
	যদি (check_enroll_options(options, &device, user_id,
	    পরিমাণ(user_id)) != 0)
		গচ্ছ out; /* error already logged */

	ৱিকল্প(alg) {
#ifdef WITH_OPENSSL
	পক্ষ SSH_SK_ECDSA:
		cose_alg = COSE_ES256;
		ভঙ্গ;
#endif /* WITH_OPENSSL */
	পক্ষ SSH_SK_ED25519:
		cose_alg = COSE_EDDSA;
		ভঙ্গ;
	স্ৱভাৱ:
		skdebug(__func__, "unsupported key type %d", alg);
		গচ্ছ out;
	}
	যদি (device != রিক্ত)
		sk = sk_open(device);
	অন্যথা
		sk = sk_probe(রিক্ত, রিক্ত, 0, 0);
	যদি (sk == রিক্ত) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		গচ্ছ out;
	}
	skdebug(__func__, "using device %s", sk->path);
	যদি ((flags & SSH_SK_RESIDENT_চাবি) != 0 &&
	    (flags & SSH_SK_FORCE_OPERATION) == 0 &&
	    (r = চাবি_lookup(sk->dev, application, user_id, পরিমাণ(user_id),
	    pin)) != FIDO_ERR_NO_CREDENTIALS) {
		যদি (r != FIDO_OK) {
			ret = fidoerr_to_skerr(r);
			skdebug(__func__, "key_lookup failed");
		} অন্যথা {
			ret = SSH_SK_ERR_CREDENTIAL_EXISTS;
			skdebug(__func__, "key exists");
		}
		গচ্ছ out;
	}
	যদি ((cred = fido_cred_new()) == রিক্ত) {
		skdebug(__func__, "fido_cred_new failed");
		গচ্ছ out;
	}
	যদি ((r = fido_cred_set_type(cred, cose_alg)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_type: %s", fido_strerr(r));
		গচ্ছ out;
	}
	যদি ((r = fido_cred_set_clientdata(cred,
	    challenge, challenge_len)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata: %s",
		    fido_strerr(r));
		গচ্ছ out;
	}
	যদি ((r = fido_cred_set_rk(cred, (flags & SSH_SK_RESIDENT_চাবি) != 0 ?
	    FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rk: %s", fido_strerr(r));
		গচ্ছ out;
	}
	যদি ((r = fido_cred_set_user(cred, user_id, পরিমাণ(user_id),
	    "openssh", "openssh", রিক্ত)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_user: %s", fido_strerr(r));
		গচ্ছ out;
	}
	যদি ((r = fido_cred_set_rp(cred, application, রিক্ত)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rp: %s", fido_strerr(r));
		গচ্ছ out;
	}
	যদি ((flags & (SSH_SK_RESIDENT_চাবি|SSH_SK_USER_VERIFICATION_REQD)) != 0) {
#যদি !defined(HAVE_FIDO_DEV_SUPPORTS_CRED_PROT) || \
    !defined(HAVE_FIDO_CRED_SET_PROT)
		skdebug(__func__, "libfido2 version does not support a feature required for this operation. Please upgrade to >=1.5.0");
		ret = SSH_SK_ERR_UNSUPPORTED;
		গচ্ছ out;
		credprot = 0; (শূন্য)credprot; /* avoid warning */
#endif
		যদি (!fido_dev_supports_cred_prot(sk->dev)) {
			skdebug(__func__, "%s does not support credprot, "
			    "refusing to create unprotected "
			    "resident/verify-required key", sk->path);
			ret = SSH_SK_ERR_UNSUPPORTED;
			গচ্ছ out;
		}
		যদি ((flags & SSH_SK_USER_VERIFICATION_REQD))
			credprot = FIDO_CRED_PROT_UV_REQUIRED;
		অন্যথা
			credprot = FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID;

		যদি ((r = fido_cred_set_prot(cred, credprot)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_set_prot: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			গচ্ছ out;
		}
	}
	যদি ((r = fido_dev_make_cred(sk->dev, cred, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_make_cred: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		গচ্ছ out;
	}
	যদি (fido_cred_x5c_ptr(cred) != রিক্ত) {
		যদি ((r = fido_cred_verify(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify: %s",
			    fido_strerr(r));
			গচ্ছ out;
		}
	} অন্যথা যদি (strcmp(fido_cred_fmt(cred), "none") != 0) {
		skdebug(__func__, "self-attested credential");
		যদি ((r = fido_cred_verify_self(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify_self: %s",
			    fido_strerr(r));
			গচ্ছ out;
		}
	} অন্যথা {
		skdebug(__func__, "no attestation data");
	}
	যদি ((response = calloc(1, পরিমাণ(*response))) == রিক্ত) {
		skdebug(__func__, "calloc response failed");
		গচ্ছ out;
	}
	response->flags = flags;
	যদি (pack_public_চাবি(alg, cred, response) != 0) {
		skdebug(__func__, "pack_public_key failed");
		গচ্ছ out;
	}
	যদি ((ptr = fido_cred_id_ptr(cred)) != রিক্ত) {
		len = fido_cred_id_len(cred);
		যদি ((response->চাবি_handle = calloc(1, len)) == রিক্ত) {
			skdebug(__func__, "calloc key handle failed");
			গচ্ছ out;
		}
		memcpy(response->চাবি_handle, ptr, len);
		response->চাবি_handle_len = len;
	}
	যদি ((ptr = fido_cred_sig_ptr(cred)) != রিক্ত) {
		len = fido_cred_sig_len(cred);
		যদি ((response->signature = calloc(1, len)) == রিক্ত) {
			skdebug(__func__, "calloc signature failed");
			গচ্ছ out;
		}
		memcpy(response->signature, ptr, len);
		response->signature_len = len;
	}
	যদি ((ptr = fido_cred_x5c_ptr(cred)) != রিক্ত) {
		len = fido_cred_x5c_len(cred);
		skdebug(__func__, "attestation cert len=%zu", len);
		যদি ((response->attestation_cert = calloc(1, len)) == রিক্ত) {
			skdebug(__func__, "calloc attestation cert failed");
			গচ্ছ out;
		}
		memcpy(response->attestation_cert, ptr, len);
		response->attestation_cert_len = len;
	}
	যদি ((ptr = fido_cred_authdata_ptr(cred)) != রিক্ত) {
		len = fido_cred_authdata_len(cred);
		skdebug(__func__, "authdata len=%zu", len);
		যদি ((response->authdata = calloc(1, len)) == রিক্ত) {
			skdebug(__func__, "calloc authdata failed");
			গচ্ছ out;
		}
		memcpy(response->authdata, ptr, len);
		response->authdata_len = len;
	}
	*enroll_response = response;
	response = রিক্ত;
	ret = 0;
 out:
	মুক্ত(device);
	যদি (response != রিক্ত) {
		মুক্ত(response->public_চাবি);
		মুক্ত(response->চাবি_handle);
		মুক্ত(response->signature);
		মুক্ত(response->attestation_cert);
		মুক্ত(response->authdata);
		মুক্ত(response);
	}
	sk_close(sk);
	fido_cred_free(&cred);
	ঘূৰাই ret;
}

#ifdef WITH_OPENSSL
স্থির পূর্ণাঙ্ক
pack_sig_ecdsa(fido_assert_t *প্রতিজ্ঞা, সংরচনা sk_sign_response *response)
{
	ECDSA_SIG *sig = রিক্ত;
	ধ্রুৱ BIGNUM *sig_r, *sig_s;
	ধ্রুৱ unsigned ৱর্ণ *cp;
	size_t sig_len;
	পূর্ণাঙ্ক ret = -1;

	cp = fido_assert_sig_ptr(প্রতিজ্ঞা, 0);
	sig_len = fido_assert_sig_len(প্রতিজ্ঞা, 0);
	যদি ((sig = d2i_ECDSA_SIG(রিক্ত, &cp, sig_len)) == রিক্ত) {
		skdebug(__func__, "d2i_ECDSA_SIG failed");
		গচ্ছ out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_অঙ্ক_bytes(sig_r);
	response->sig_s_len = BN_অঙ্ক_bytes(sig_s);
	যদি ((response->sig_r = calloc(1, response->sig_r_len)) == রিক্ত ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == রিক্ত) {
		skdebug(__func__, "calloc signature failed");
		গচ্ছ out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	ECDSA_SIG_free(sig);
	যদি (ret != 0) {
		মুক্ত(response->sig_r);
		মুক্ত(response->sig_s);
		response->sig_r = রিক্ত;
		response->sig_s = রিক্ত;
	}
	ঘূৰাই ret;
}
#endif /* WITH_OPENSSL */

স্থির পূর্ণাঙ্ক
pack_sig_ed25519(fido_assert_t *প্রতিজ্ঞা, সংরচনা sk_sign_response *response)
{
	ধ্রুৱ unsigned ৱর্ণ *ptr;
	size_t len;
	পূর্ণাঙ্ক ret = -1;

	ptr = fido_assert_sig_ptr(প্রতিজ্ঞা, 0);
	len = fido_assert_sig_len(প্রতিজ্ঞা, 0);
	যদি (len != 64) {
		skdebug(__func__, "bad length %zu", len);
		গচ্ছ out;
	}
	response->sig_r_len = len;
	যদি ((response->sig_r = calloc(1, response->sig_r_len)) == রিক্ত) {
		skdebug(__func__, "calloc signature failed");
		গচ্ছ out;
	}
	memcpy(response->sig_r, ptr, len);
	ret = 0;
 out:
	যদি (ret != 0) {
		মুক্ত(response->sig_r);
		response->sig_r = রিক্ত;
	}
	ঘূৰাই ret;
}

স্থির পূর্ণাঙ্ক
pack_sig(uint32_t  alg, fido_assert_t *প্রতিজ্ঞা,
    সংরচনা sk_sign_response *response)
{
	ৱিকল্প(alg) {
#ifdef WITH_OPENSSL
	পক্ষ SSH_SK_ECDSA:
		ঘূৰাই pack_sig_ecdsa(প্রতিজ্ঞা, response);
#endif /* WITH_OPENSSL */
	পক্ষ SSH_SK_ED25519:
		ঘূৰাই pack_sig_ed25519(প্রতিজ্ঞা, response);
	স্ৱভাৱ:
		ঘূৰাই -1;
	}
}

/* Checks sk_options for sk_sign() and sk_load_resident_keys() */
স্থির পূর্ণাঙ্ক
check_sign_load_resident_options(সংরচনা sk_option **options, ৱর্ণ **devicep)
{
	size_t i;

	যদি (options == রিক্ত)
		ঘূৰাই 0;
	বাবে (i = 0; options[i] != রিক্ত; i++) {
		যদি (strcmp(options[i]->name, "device") == 0) {
			যদি ((*devicep = strdup(options[i]->মান)) == রিক্ত) {
				skdebug(__func__, "strdup device failed");
				ঘূৰাই -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} অন্যথা {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			যদি (options[i]->required) {
				skdebug(__func__, "unknown required option");
				ঘূৰাই -1;
			}
		}
	}
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sk_sign(uint32_t alg, ধ্রুৱ uint8_t *data, size_t datalen,
    ধ্রুৱ ৱর্ণ *application,
    ধ্রুৱ uint8_t *চাবি_handle, size_t চাবি_handle_len,
    uint8_t flags, ধ্রুৱ ৱর্ণ *pin, সংরচনা sk_option **options,
    সংরচনা sk_sign_response **sign_response)
{
	fido_assert_t *প্রতিজ্ঞা = রিক্ত;
	ৱর্ণ *device = রিক্ত;
	সংরচনা sk_usbhid *sk = রিক্ত;
	সংরচনা sk_sign_response *response = রিক্ত;
	পূর্ণাঙ্ক ret = SSH_SK_ERR_GENERAL, internal_uv;
	পূর্ণাঙ্ক r;

	fido_init(SSH_FIDO_INIT_ARG);

	যদি (sign_response == রিক্ত) {
		skdebug(__func__, "sign_response == NULL");
		গচ্ছ out;
	}
	*sign_response = রিক্ত;
	যদি (check_sign_load_resident_options(options, &device) != 0)
		গচ্ছ out; /* error already logged */
	যদি (device != রিক্ত)
		sk = sk_open(device);
	অন্যথা যদি (pin != রিক্ত || (flags & SSH_SK_USER_VERIFICATION_REQD))
		sk = sk_probe(রিক্ত, রিক্ত, 0, 0);
	অন্যথা
		sk = sk_probe(application, চাবি_handle, চাবি_handle_len, 0);
	যদি (sk == রিক্ত) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		গচ্ছ out;
	}
	যদি ((প্রতিজ্ঞা = fido_assert_new()) == রিক্ত) {
		skdebug(__func__, "fido_assert_new failed");
		গচ্ছ out;
	}
	যদি ((r = fido_assert_set_clientdata(প্রতিজ্ঞা,
	    data, datalen)) != FIDO_OK)  {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		গচ্ছ out;
	}
	যদি ((r = fido_assert_set_rp(প্রতিজ্ঞা, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		গচ্ছ out;
	}
	যদি ((r = fido_assert_allow_cred(প্রতিজ্ঞা, চাবি_handle,
	    চাবি_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		গচ্ছ out;
	}
	যদি ((r = fido_assert_set_up(প্রতিজ্ঞা,
	    (flags & SSH_SK_USER_PRESENCE_REQD) ?
	    FIDO_OPT_TRUE : FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		গচ্ছ out;
	}
	/*
	 * WinHello requests the PIN by default.  Make "uv" request explicit
	 * to allow keys with and without -O verify-required to make sense.
	 */
	যদি (pin == রিক্ত && fido_dev_is_winhello (sk->dev) &&
	    (r = fido_assert_set_uv(প্রতিজ্ঞা, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
	}
	যদি (pin == রিক্ত && (flags & SSH_SK_USER_VERIFICATION_REQD)) {
		যদি (check_sk_options(sk->dev, "uv", &internal_uv) < 0 ||
		    internal_uv != 1) {
			skdebug(__func__, "check_sk_options uv");
			ret = SSH_SK_ERR_PIN_REQUIRED;
			গচ্ছ out;
		}
		যদি ((r = fido_assert_set_uv(প্রতিজ্ঞা,
		    FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_assert_set_uv: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			গচ্ছ out;
		}
	}
	যদি ((r = fido_dev_get_assert(sk->dev, প্রতিজ্ঞা, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		গচ্ছ out;
	}
	যদি ((response = calloc(1, পরিমাণ(*response))) == রিক্ত) {
		skdebug(__func__, "calloc response failed");
		গচ্ছ out;
	}
	response->flags = fido_assert_flags(প্রতিজ্ঞা, 0);
	response->counter = fido_assert_sigcount(প্রতিজ্ঞা, 0);
	যদি (pack_sig(alg, প্রতিজ্ঞা, response) != 0) {
		skdebug(__func__, "pack_sig failed");
		গচ্ছ out;
	}
	*sign_response = response;
	response = রিক্ত;
	ret = 0;
 out:
	মুক্ত(device);
	যদি (response != রিক্ত) {
		মুক্ত(response->sig_r);
		মুক্ত(response->sig_s);
		মুক্ত(response);
	}
	sk_close(sk);
	fido_assert_free(&প্রতিজ্ঞা);
	ঘূৰাই ret;
}

স্থির পূর্ণাঙ্ক
read_rks(সংরচনা sk_usbhid *sk, ধ্রুৱ ৱর্ণ *pin,
    সংরচনা sk_resident_চাবি ***rksp, size_t *nrksp)
{
	পূর্ণাঙ্ক ret = SSH_SK_ERR_GENERAL, r = -1;
	uint32_t alg;
	fido_credman_metadata_t *metadata = রিক্ত;
	fido_credman_rp_t *rp = রিক্ত;
	fido_credman_rk_t *rk = রিক্ত;
	size_t i, j, nrp, nrk, user_id_len;
	ধ্রুৱ fido_cred_t *cred;
	ধ্রুৱ ৱর্ণ *rp_id, *rp_name, *user_name;
	সংরচনা sk_resident_চাবি *srk = রিক্ত, **tmp;
	ধ্রুৱ u_char *user_id;

	যদি (pin == রিক্ত) {
		skdebug(__func__, "no PIN specified");
		ret = SSH_SK_ERR_PIN_REQUIRED;
		গচ্ছ out;
	}
	যদি ((metadata = fido_credman_metadata_new()) == রিক্ত) {
		skdebug(__func__, "alloc failed");
		গচ্ছ out;
	}
	যদি ((r = fido_credman_get_dev_metadata(sk->dev, metadata, pin)) != 0) {
		যদি (r == FIDO_ERR_INVALID_COMMAND) {
			skdebug(__func__, "device %s does not support "
			    "resident keys", sk->path);
			ret = 0;
			গচ্ছ out;
		}
		skdebug(__func__, "get metadata for %s failed: %s",
		    sk->path, fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		গচ্ছ out;
	}
	skdebug(__func__, "existing %llu, remaining %llu",
	    (unsigned long long)fido_credman_rk_existing(metadata),
	    (unsigned long long)fido_credman_rk_remaining(metadata));
	যদি ((rp = fido_credman_rp_new()) == রিক্ত) {
		skdebug(__func__, "alloc rp failed");
		গচ্ছ out;
	}
	যদি ((r = fido_credman_get_dev_rp(sk->dev, rp, pin)) != 0) {
		skdebug(__func__, "get RPs for %s failed: %s",
		    sk->path, fido_strerr(r));
		গচ্ছ out;
	}
	nrp = fido_credman_rp_গুনতি(rp);
	skdebug(__func__, "Device %s has resident keys for %zu RPs",
	    sk->path, nrp);

	/* Iterate over RP IDs that have resident keys */
	বাবে (i = 0; i < nrp; i++) {
		rp_id = fido_credman_rp_id(rp, i);
		rp_name = fido_credman_rp_name(rp, i);
		skdebug(__func__, "rp %zu: name=\"%s\" id=\"%s\" hashlen=%zu",
		    i, rp_name == রিক্ত ? "(none)" : rp_name,
		    rp_id == রিক্ত ? "(none)" : rp_id,
		    fido_credman_rp_id_hash_len(rp, i));

		/* Skip non-SSH RP IDs */
		যদি (rp_id == রিক্ত ||
		    strncasecmp(fido_credman_rp_id(rp, i), "ssh:", 4) != 0)
			অনুৱর্ত;

		fido_credman_rk_free(&rk);
		যদি ((rk = fido_credman_rk_new()) == রিক্ত) {
			skdebug(__func__, "alloc rk failed");
			গচ্ছ out;
		}
		যদি ((r = fido_credman_get_dev_rk(sk->dev,
		    fido_credman_rp_id(rp, i), rk, pin)) != 0) {
			skdebug(__func__, "get RKs for %s slot %zu failed: %s",
			    sk->path, i, fido_strerr(r));
			গচ্ছ out;
		}
		nrk = fido_credman_rk_গুনতি(rk);
		skdebug(__func__, "RP \"%s\" has %zu resident keys",
		    fido_credman_rp_id(rp, i), nrk);

		/* Iterate over resident keys for this RP ID */
		বাবে (j = 0; j < nrk; j++) {
			যদি ((cred = fido_credman_rk(rk, j)) == রিক্ত) {
				skdebug(__func__, "no RK in slot %zu", j);
				অনুৱর্ত;
			}
			যদি ((user_name = fido_cred_user_name(cred)) == রিক্ত)
				user_name = "";
			user_id = fido_cred_user_id_ptr(cred);
			user_id_len = fido_cred_user_id_len(cred);
			skdebug(__func__, "Device %s RP \"%s\" user \"%s\" "
			    "uidlen %zu slot %zu: type %d flags 0x%02x "
			    "prot 0x%02x", sk->path, rp_id, user_name,
			    user_id_len, j, fido_cred_type(cred),
			    fido_cred_flags(cred), fido_cred_prot(cred));

			/* Determine key algorithm */
			ৱিকল্প (fido_cred_type(cred)) {
			পক্ষ COSE_ES256:
				alg = SSH_SK_ECDSA;
				ভঙ্গ;
			পক্ষ COSE_EDDSA:
				alg = SSH_SK_ED25519;
				ভঙ্গ;
			স্ৱভাৱ:
				skdebug(__func__, "unsupported key type %d",
				    fido_cred_type(cred));
				অনুৱর্ত;
			}

			/* build response entry */
			যদি ((srk = calloc(1, পরিমাণ(*srk))) == রিক্ত ||
			    (srk->চাবি.চাবি_handle = calloc(1,
			    fido_cred_id_len(cred))) == রিক্ত ||
			    (srk->application = strdup(rp_id)) == রিক্ত ||
			    (user_id_len > 0 &&
			     (srk->user_id = calloc(1, user_id_len)) == রিক্ত)) {
				skdebug(__func__, "alloc sk_resident_key");
				গচ্ছ out;
			}

			srk->alg = alg;
			srk->চাবি.চাবি_handle_len = fido_cred_id_len(cred);
			memcpy(srk->চাবি.চাবি_handle, fido_cred_id_ptr(cred),
			    srk->চাবি.চাবি_handle_len);
			srk->user_id_len = user_id_len;
			যদি (srk->user_id_len != 0)
				memcpy(srk->user_id, user_id, srk->user_id_len);

#ifdef HAVE_FIDO_CRED_PROT
			যদি (fido_cred_prot(cred) ==
			    FIDO_CRED_PROT_UV_REQUIRED)
				srk->flags |=  SSH_SK_USER_VERIFICATION_REQD;
#endif

			যদি ((r = pack_public_চাবি(srk->alg, cred,
			    &srk->চাবি)) != 0) {
				skdebug(__func__, "pack public key failed");
				গচ্ছ out;
			}
			/* append */
			যদি ((tmp = recallocarray(*rksp, *nrksp, (*nrksp) + 1,
			    পরিমাণ(**rksp))) == রিক্ত) {
				skdebug(__func__, "alloc rksp");
				গচ্ছ out;
			}
			*rksp = tmp;
			(*rksp)[(*nrksp)++] = srk;
			srk = রিক্ত;
		}
	}
	/* Success */
	ret = 0;
 out:
	যদি (srk != রিক্ত) {
		মুক্ত(srk->application);
		freezero(srk->চাবি.public_চাবি, srk->চাবি.public_চাবি_len);
		freezero(srk->চাবি.চাবি_handle, srk->চাবি.চাবি_handle_len);
		freezero(srk->user_id, srk->user_id_len);
		freezero(srk, পরিমাণ(*srk));
	}
	fido_credman_rp_free(&rp);
	fido_credman_rk_free(&rk);
	fido_credman_metadata_free(&metadata);
	ঘূৰাই ret;
}

পূর্ণাঙ্ক
sk_load_resident_চাবিগুলি(ধ্রুৱ ৱর্ণ *pin, সংরচনা sk_option **options,
    সংরচনা sk_resident_চাবি ***rksp, size_t *nrksp)
{
	পূর্ণাঙ্ক ret = SSH_SK_ERR_GENERAL, r = -1;
	size_t i, nrks = 0;
	সংরচনা sk_resident_চাবি **rks = রিক্ত;
	সংরচনা sk_usbhid *sk = রিক্ত;
	ৱর্ণ *device = রিক্ত;

	*rksp = রিক্ত;
	*nrksp = 0;

	fido_init(SSH_FIDO_INIT_ARG);

	যদি (check_sign_load_resident_options(options, &device) != 0)
		গচ্ছ out; /* error already logged */
	যদি (device != রিক্ত)
		sk = sk_open(device);
	অন্যথা
		sk = sk_probe(রিক্ত, রিক্ত, 0, 1);
	যদি (sk == রিক্ত) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		গচ্ছ out;
	}
	skdebug(__func__, "trying %s", sk->path);
	যদি ((r = read_rks(sk, pin, &rks, &nrks)) != 0) {
		skdebug(__func__, "read_rks failed for %s", sk->path);
		ret = r;
		গচ্ছ out;
	}
	/* success, unless we have no keys but a specific error */
	যদি (nrks > 0 || ret == SSH_SK_ERR_GENERAL)
		ret = 0;
	*rksp = rks;
	*nrksp = nrks;
	rks = রিক্ত;
	nrks = 0;
 out:
	sk_close(sk);
	বাবে (i = 0; i < nrks; i++) {
		মুক্ত(rks[i]->application);
		freezero(rks[i]->চাবি.public_চাবি, rks[i]->চাবি.public_চাবি_len);
		freezero(rks[i]->চাবি.চাবি_handle, rks[i]->চাবি.চাবি_handle_len);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i], পরিমাণ(*rks[i]));
	}
	মুক্ত(device);
	মুক্ত(rks);
	ঘূৰাই ret;
}

#endif /* ENABLE_SK_INTERNAL */
