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

#অন্তর্ভাব "includes.h"

#ifdef ENABLE_SK_INTERNAL

#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <time.h>
#ifdef HAVE_SHA2_H
#অন্তর্ভাব <sha2.h>
#endif

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/opensslv.h>
#অন্তর্ভাব <openssl/crypto.h>
#অন্তর্ভাব <openssl/bn.h>
#অন্তর্ভাব <openssl/ec.h>
#অন্তর্ভাব <openssl/ecdsa.h>
#অন্তর্ভাব <openssl/evp.h>
#অন্তর্ভাব "openbsd-compat/openssl-compat.h"
#endif /* WITH_OPENSSL */

#অন্তর্ভাব <fido.h>
#অন্তর্ভাব <fido/credman.h>

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

#অন্তর্ভাব "sk-api.h"

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

কাঠামো sk_usbhid {
	fido_dev_t *dev;
	অক্ষর *path;
};

/* Return the version of the middleware API */
uint32_t sk_api_version(শূন্য);

/* Enroll a U2F key (private key generation) */
পূর্ণসংখ্যা sk_enroll(uint32_t alg, ধ্রুবক uint8_t *challenge, আকার_t challenge_len,
    ধ্রুবক অক্ষর *application, uint8_t flags, ধ্রুবক অক্ষর *pin,
    কাঠামো sk_option **options, কাঠামো sk_enroll_response **enroll_response);

/* Sign a challenge */
পূর্ণসংখ্যা sk_sign(uint32_t alg, ধ্রুবক uint8_t *তথ্য, আকার_t তথ্য_len,
    ধ্রুবক অক্ষর *application, ধ্রুবক uint8_t *চাবি_handle, আকার_t চাবি_handle_len,
    uint8_t flags, ধ্রুবক অক্ষর *pin, কাঠামো sk_option **options,
    কাঠামো sk_sign_response **sign_response);

/* Load resident keys */
পূর্ণসংখ্যা sk_load_resident_চাবিগুলি(ধ্রুবক অক্ষর *pin, কাঠামো sk_option **options,
    কাঠামো sk_resident_চাবি ***rks, আকার_t *nrks);

স্থির শূন্য skdebug(ধ্রুবক অক্ষর *func, ধ্রুবক অক্ষর *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

স্থির শূন্য
skdebug(ধ্রুবক অক্ষর *func, ধ্রুবক অক্ষর *fmt, ...)
{
#যদি !defined(SK_STANDALONE)
	অক্ষর *বার্তা;
	va_list ap;

	va_start(ap, fmt);
	xvasprintf(&বার্তা, fmt, ap);
	va_end(ap);
	debug("%s: %s", func, বার্তা);
	মুক্ত(বার্তা);
#নতুবা_যদি defined(SK_DEBUG)
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
	ফেরত SSH_SK_VERSION_MAJOR;
}

স্থির কাঠামো sk_usbhid *
sk_open(ধ্রুবক অক্ষর *path)
{
	কাঠামো sk_usbhid *sk;
	পূর্ণসংখ্যা r;

	যদি (path == ফাঁকা) {
		skdebug(__func__, "path == NULL");
		ফেরত ফাঁকা;
	}
	যদি ((sk = calloc(1, আকার(*sk))) == ফাঁকা) {
		skdebug(__func__, "calloc sk failed");
		ফেরত ফাঁকা;
	}
	যদি ((sk->path = strdup(path)) == ফাঁকা) {
		skdebug(__func__, "strdup path failed");
		মুক্ত(sk);
		ফেরত ফাঁকা;
	}
	যদি ((sk->dev = fido_dev_new()) == ফাঁকা) {
		skdebug(__func__, "fido_dev_new failed");
		মুক্ত(sk->path);
		মুক্ত(sk);
		ফেরত ফাঁকা;
	}
	যদি ((r = fido_dev_open(sk->dev, sk->path)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_open %s failed: %s", sk->path,
		    fido_strerr(r));
		fido_dev_free(&sk->dev);
		মুক্ত(sk->path);
		মুক্ত(sk);
		ফেরত ফাঁকা;
	}
	ফেরত sk;
}

স্থির শূন্য
sk_close(কাঠামো sk_usbhid *sk)
{
	যদি (sk == ফাঁকা)
		ফেরত;
	fido_dev_cancel(sk->dev); /* cancel any pending operation */
	fido_dev_close(sk->dev);
	fido_dev_free(&sk->dev);
	মুক্ত(sk->path);
	মুক্ত(sk);
}

স্থির কাঠামো sk_usbhid **
sk_openv(ধ্রুবক fido_dev_info_t *devlist, আকার_t ndevs, আকার_t *nopen)
{
	ধ্রুবক fido_dev_info_t *di;
	কাঠামো sk_usbhid **skv;
	আকার_t i;

	*nopen = 0;
	যদি ((skv = calloc(ndevs, আকার(*skv))) == ফাঁকা) {
		skdebug(__func__, "calloc skv failed");
		ফেরত ফাঁকা;
	}
	জন্য (i = 0; i < ndevs; i++) {
		যদি ((di = fido_dev_info_ptr(devlist, i)) == ফাঁকা)
			skdebug(__func__, "fido_dev_info_ptr failed");
		অন্যথা যদি ((skv[*nopen] = sk_open(fido_dev_info_path(di))) == ফাঁকা)
			skdebug(__func__, "sk_open failed");
		অন্যথা
			(*nopen)++;
	}
	যদি (*nopen == 0) {
		জন্য (i = 0; i < ndevs; i++)
			sk_close(skv[i]);
		মুক্ত(skv);
		skv = ফাঁকা;
	}

	ফেরত skv;
}

স্থির শূন্য
sk_closev(কাঠামো sk_usbhid **skv, আকার_t nsk)
{
	আকার_t i;

	জন্য (i = 0; i < nsk; i++)
		sk_close(skv[i]);
	মুক্ত(skv);
}

স্থির পূর্ণসংখ্যা
sk_touch_begin(কাঠামো sk_usbhid **skv, আকার_t nsk)
{
	আকার_t i, ok = 0;
	পূর্ণসংখ্যা r;

	জন্য (i = 0; i < nsk; i++)
		যদি ((r = fido_dev_get_touch_begin(skv[i]->dev)) != FIDO_OK)
			skdebug(__func__, "fido_dev_get_touch_begin %s failed:"
			    " %s", skv[i]->path, fido_strerr(r));
		অন্যথা
			ok++;

	ফেরত ok ? 0 : -1;
}

স্থির পূর্ণসংখ্যা
sk_touch_poll(কাঠামো sk_usbhid **skv, আকার_t nsk, পূর্ণসংখ্যা *touch, আকার_t *idx)
{
	কাঠামো timespec ts_pause;
	আকার_t npoll, i;
	পূর্ণসংখ্যা r;

	ts_pause.tv_sec = 0;
	ts_pause.tv_nsec = POLL_SLEEP_NS;
	nanosleep(&ts_pause, ফাঁকা);
	npoll = nsk;
	জন্য (i = 0; i < nsk; i++) {
		যদি (skv[i] == ফাঁকা)
			চালু; /* device discarded */
		skdebug(__func__, "polling %s", skv[i]->path);
		যদি ((r = fido_dev_get_touch_status(skv[i]->dev, touch,
		    FIDO_POLL_MS)) != FIDO_OK) {
			skdebug(__func__, "fido_dev_get_touch_status %s: %s",
			    skv[i]->path, fido_strerr(r));
			sk_close(skv[i]); /* discard device */
			skv[i] = ফাঁকা;
			যদি (--npoll == 0) {
				skdebug(__func__, "no device left to poll");
				ফেরত -1;
			}
		} অন্যথা যদি (*touch) {
			*idx = i;
			ফেরত 0;
		}
	}
	*touch = 0;
	ফেরত 0;
}

#যদি !defined(HAVE_FIDO_ASSERT_SET_CLIENTDATA) || \
    !defined(HAVE_FIDO_CRED_SET_CLIENTDATA)
/* Calculate SHA256(m) */
স্থির পূর্ণসংখ্যা
sha256_mem(ধ্রুবক শূন্য *m, আকার_t mlen, u_char *d, আকার_t dlen)
{
#ifdef WITH_OPENSSL
	u_int mdlen;
#অন্যথা
	SHA2_CTX ctx;
#endif

	যদি (dlen != 32)
		ফেরত -1;
#ifdef WITH_OPENSSL
	mdlen = dlen;
	যদি (!EVP_Digest(m, mlen, d, &mdlen, EVP_sha256(), ফাঁকা))
		ফেরত -1;
#অন্যথা
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ধ্রুবক uint8_t *)m, mlen);
	SHA256Final(d, &ctx);
#endif
	ফেরত 0;
}
#endif /* !HAVE_FIDO_ASSERT_SET_CLIENTDATA || !HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_CRED_SET_CLIENTDATA
স্থির পূর্ণসংখ্যা
fido_cred_set_clientdata(fido_cred_t *cred, ধ্রুবক u_char *ptr, আকার_t len)
{
	uint8_t d[32];
	পূর্ণসংখ্যা r;

	যদি (sha256_mem(ptr, len, d, আকার(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		ফেরত FIDO_ERR_INTERNAL;
	}
	r = fido_cred_set_clientdata_hash(cred, d, আকার(d));
	explicit_bzero(d, আকার(d));
	যদি (r != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	ফেরত r;
}
#endif /* HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_ASSERT_SET_CLIENTDATA
স্থির পূর্ণসংখ্যা
fido_assert_set_clientdata(fido_assert_t *প্রতিজ্ঞা, ধ্রুবক u_char *ptr, আকার_t len)
{
	uint8_t d[32];
	পূর্ণসংখ্যা r;

	যদি (sha256_mem(ptr, len, d, আকার(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		ফেরত FIDO_ERR_INTERNAL;
	}
	r = fido_assert_set_clientdata_hash(প্রতিজ্ঞা, d, আকার(d));
	explicit_bzero(d, আকার(d));
	যদি (r != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	ফেরত r;
}
#endif /* HAVE_FIDO_ASSERT_SET_CLIENTDATA */

#ifndef HAVE_FIDO_DEV_IS_WINHELLO
স্থির bool
fido_dev_is_winhello(ধ্রুবক fido_dev_t *fdev)
{
	ফেরত 0;
}
#endif /* HAVE_FIDO_DEV_IS_WINHELLO */

/* Check if the specified key handle exists on a given sk. */
স্থির পূর্ণসংখ্যা
sk_try(ধ্রুবক কাঠামো sk_usbhid *sk, ধ্রুবক অক্ষর *application,
    ধ্রুবক uint8_t *চাবি_handle, আকার_t চাবি_handle_len)
{
	fido_assert_t *প্রতিজ্ঞা = ফাঁকা;
	পূর্ণসংখ্যা r = FIDO_ERR_INTERNAL;
	uint8_t message[32];

	memset(message, '\0', আকার(message));
	যদি ((প্রতিজ্ঞা = fido_assert_new()) == ফাঁকা) {
		skdebug(__func__, "fido_assert_new failed");
		যাও out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	যদি ((r = fido_assert_set_clientdata(প্রতিজ্ঞা, message,
	    আকার(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		যাও out;
	}
	যদি ((r = fido_assert_set_rp(প্রতিজ্ঞা, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		যাও out;
	}
	যদি ((r = fido_assert_allow_cred(প্রতিজ্ঞা, চাবি_handle,
	    চাবি_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		যাও out;
	}
	যদি ((r = fido_assert_set_up(প্রতিজ্ঞা, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_up: %s", fido_strerr(r));
		যাও out;
	}
	r = fido_dev_get_assert(sk->dev, প্রতিজ্ঞা, ফাঁকা);
	skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
	যদি (r == FIDO_ERR_USER_PRESENCE_REQUIRED) {
		/* U2F tokens may return this */
		r = FIDO_OK;
	}
 out:
	fido_assert_free(&প্রতিজ্ঞা);

	ফেরত r != FIDO_OK ? -1 : 0;
}

স্থির পূর্ণসংখ্যা
check_sk_options(fido_dev_t *dev, ধ্রুবক অক্ষর *opt, পূর্ণসংখ্যা *ret)
{
	fido_cbor_info_t *info;
	অক্ষর * ধ্রুবক *name;
	ধ্রুবক bool *মান;
	আকার_t len, i;
	পূর্ণসংখ্যা r;

	*ret = -1;

	যদি (!fido_dev_is_fido2(dev)) {
		skdebug(__func__, "device is not fido2");
		ফেরত 0;
	}
	যদি ((info = fido_cbor_info_new()) == ফাঁকা) {
		skdebug(__func__, "fido_cbor_info_new failed");
		ফেরত -1;
	}
	যদি ((r = fido_dev_get_cbor_info(dev, info)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_cbor_info: %s", fido_strerr(r));
		fido_cbor_info_free(&info);
		ফেরত -1;
	}
	name = fido_cbor_info_options_name_ptr(info);
	মান = fido_cbor_info_options_মান_ptr(info);
	len = fido_cbor_info_options_len(info);
	জন্য (i = 0; i < len; i++) {
		যদি (!strcmp(name[i], opt)) {
			*ret = মান[i];
			বিরতি;
		}
	}
	fido_cbor_info_free(&info);
	যদি (*ret == -1)
		skdebug(__func__, "option %s is unknown", opt);
	অন্যথা
		skdebug(__func__, "option %s is %s", opt, *ret ? "on" : "off");

	ফেরত 0;
}

স্থির কাঠামো sk_usbhid *
sk_select_by_cred(ধ্রুবক fido_dev_info_t *devlist, আকার_t ndevs,
    ধ্রুবক অক্ষর *application, ধ্রুবক uint8_t *চাবি_handle, আকার_t চাবি_handle_len)
{
	কাঠামো sk_usbhid **skv, *sk;
	আকার_t skvcnt, i;
	পূর্ণসংখ্যা internal_uv;

	যদি ((skv = sk_openv(devlist, ndevs, &skvcnt)) == ফাঁকা) {
		skdebug(__func__, "sk_openv failed");
		ফেরত ফাঁকা;
	}
	যদি (skvcnt == 1 && check_sk_options(skv[0]->dev, "uv",
	    &internal_uv) == 0 && internal_uv != -1) {
		sk = skv[0];
		skv[0] = ফাঁকা;
		যাও out;
	}
	sk = ফাঁকা;
	জন্য (i = 0; i < skvcnt; i++) {
		যদি (sk_try(skv[i], application, চাবি_handle,
		    চাবি_handle_len) == 0) {
			sk = skv[i];
			skv[i] = ফাঁকা;
			skdebug(__func__, "found key in %s", sk->path);
			বিরতি;
		}
	}
 out:
	sk_closev(skv, skvcnt);
	ফেরত sk;
}

স্থির কাঠামো sk_usbhid *
sk_select_by_touch(ধ্রুবক fido_dev_info_t *devlist, আকার_t ndevs)
{
	কাঠামো sk_usbhid **skv, *sk;
	কাঠামো timeval tv_start, tv_now, tv_delta;
	আকার_t skvcnt, idx;
	পূর্ণসংখ্যা touch, ms_remain;

	যদি ((skv = sk_openv(devlist, ndevs, &skvcnt)) == ফাঁকা) {
		skdebug(__func__, "sk_openv failed");
		ফেরত ফাঁকা;
	}
	sk = ফাঁকা;
	যদি (skvcnt < 2) {
		যদি (skvcnt == 1) {
			/* single candidate */
			sk = skv[0];
			skv[0] = ফাঁকা;
		}
		যাও out;
	}
#ifndef HAVE_FIDO_DEV_GET_TOUCH_STATUS
	skdebug(__func__, "libfido2 version does not support a feature needed for multiple tokens. Please upgrade to >=1.5.0");
	যাও out;
#endif

	যদি (sk_touch_begin(skv, skvcnt) == -1) {
		skdebug(__func__, "sk_touch_begin failed");
		যাও out;
	}
	monotime_tv(&tv_start);
	করো {
		যদি (sk_touch_poll(skv, skvcnt, &touch, &idx) == -1) {
			skdebug(__func__, "sk_touch_poll failed");
			যাও out;
		}
		যদি (touch) {
			sk = skv[idx];
			skv[idx] = ফাঁকা;
			যাও out;
		}
		monotime_tv(&tv_now);
		timersub(&tv_now, &tv_start, &tv_delta);
		ms_remain = SELECT_MS - tv_delta.tv_sec * 1000 -
		    tv_delta.tv_usec / 1000;
	} যখন (ms_remain >= FIDO_POLL_MS);
	skdebug(__func__, "timeout");
out:
	sk_closev(skv, skvcnt);
	ফেরত sk;
}

স্থির কাঠামো sk_usbhid *
sk_probe(ধ্রুবক অক্ষর *application, ধ্রুবক uint8_t *চাবি_handle,
    আকার_t চাবি_handle_len, পূর্ণসংখ্যা probe_resident)
{
	কাঠামো sk_usbhid *sk;
	fido_dev_info_t *devlist;
	আকার_t ndevs;
	পূর্ণসংখ্যা r;

#ifdef HAVE_CYGWIN
	যদি (!probe_resident && (sk = sk_open("windows://hello")) != ফাঁকা)
		ফেরত sk;
#endif /* HAVE_CYGWIN */
	যদি ((devlist = fido_dev_info_new(MAX_FIDO_DEVICES)) == ফাঁকা) {
		skdebug(__func__, "fido_dev_info_new failed");
		ফেরত ফাঁকা;
	}
	যদি ((r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES,
	    &ndevs)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_info_manifest failed: %s",
		    fido_strerr(r));
		fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
		ফেরত ফাঁকা;
	}
	skdebug(__func__, "%zu device(s) detected", ndevs);
	যদি (ndevs == 0) {
		sk = ফাঁকা;
	} অন্যথা যদি (application != ফাঁকা && চাবি_handle != ফাঁকা) {
		skdebug(__func__, "selecting sk by cred");
		sk = sk_select_by_cred(devlist, ndevs, application, চাবি_handle,
		    চাবি_handle_len);
	} অন্যথা {
		skdebug(__func__, "selecting sk by touch");
		sk = sk_select_by_touch(devlist, ndevs);
	}
	fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
	ফেরত sk;
}

#ifdef WITH_OPENSSL
/*
 * The key returned via fido_cred_pubkey_ptr() is in affine coordinates,
 * but the API expects a SEC1 octet string.
 */
স্থির পূর্ণসংখ্যা
pack_public_চাবি_ecdsa(ধ্রুবক fido_cred_t *cred,
    কাঠামো sk_enroll_response *response)
{
	ধ্রুবক uint8_t *ptr;
	BIGNUM *x = ফাঁকা, *y = ফাঁকা;
	EC_POINT *q = ফাঁকা;
	EC_GROUP *g = ফাঁকা;
	পূর্ণসংখ্যা ret = -1;

	response->public_চাবি = ফাঁকা;
	response->public_চাবি_len = 0;

	যদি ((x = BN_new()) == ফাঁকা ||
	    (y = BN_new()) == ফাঁকা ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == ফাঁকা ||
	    (q = EC_POINT_new(g)) == ফাঁকা) {
		skdebug(__func__, "libcrypto setup failed");
		যাও out;
	}
	যদি ((ptr = fido_cred_pubkey_ptr(cred)) == ফাঁকা) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		যাও out;
	}
	যদি (fido_cred_pubkey_len(cred) != 64) {
		skdebug(__func__, "bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		যাও out;
	}

	যদি (BN_bin2bn(ptr, 32, x) == ফাঁকা ||
	    BN_bin2bn(ptr + 32, 32, y) == ফাঁকা) {
		skdebug(__func__, "BN_bin2bn failed");
		যাও out;
	}
	যদি (EC_POINT_set_affine_coordinates(g, q, x, y, ফাঁকা) != 1) {
		skdebug(__func__, "EC_POINT_set_affine_coordinates failed");
		যাও out;
	}
	response->public_চাবি_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, ফাঁকা, 0, ফাঁকা);
	যদি (response->public_চাবি_len == 0 || response->public_চাবি_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_চাবি_len);
		যাও out;
	}
	যদি ((response->public_চাবি = malloc(response->public_চাবি_len)) == ফাঁকা) {
		skdebug(__func__, "malloc pubkey failed");
		যাও out;
	}
	যদি (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_চাবি, response->public_চাবি_len, ফাঁকা) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		যাও out;
	}
	/* success */
	ret = 0;
 out:
	যদি (ret != 0 && response->public_চাবি != ফাঁকা) {
		memset(response->public_চাবি, 0, response->public_চাবি_len);
		মুক্ত(response->public_চাবি);
		response->public_চাবি = ফাঁকা;
	}
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	ফেরত ret;
}
#endif /* WITH_OPENSSL */

স্থির পূর্ণসংখ্যা
pack_public_চাবি_ed25519(ধ্রুবক fido_cred_t *cred,
    কাঠামো sk_enroll_response *response)
{
	ধ্রুবক uint8_t *ptr;
	আকার_t len;
	পূর্ণসংখ্যা ret = -1;

	response->public_চাবি = ফাঁকা;
	response->public_চাবি_len = 0;

	যদি ((len = fido_cred_pubkey_len(cred)) != 32) {
		skdebug(__func__, "bad fido_cred_pubkey_len len %zu", len);
		যাও out;
	}
	যদি ((ptr = fido_cred_pubkey_ptr(cred)) == ফাঁকা) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		যাও out;
	}
	response->public_চাবি_len = len;
	যদি ((response->public_চাবি = malloc(response->public_চাবি_len)) == ফাঁকা) {
		skdebug(__func__, "malloc pubkey failed");
		যাও out;
	}
	memcpy(response->public_চাবি, ptr, len);
	ret = 0;
 out:
	যদি (ret != 0)
		মুক্ত(response->public_চাবি);
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
pack_public_চাবি(uint32_t alg, ধ্রুবক fido_cred_t *cred,
    কাঠামো sk_enroll_response *response)
{
	নির্বাচন(alg) {
#ifdef WITH_OPENSSL
	ক্ষেত্র SSH_SK_ECDSA:
		ফেরত pack_public_চাবি_ecdsa(cred, response);
#endif /* WITH_OPENSSL */
	ক্ষেত্র SSH_SK_ED25519:
		ফেরত pack_public_চাবি_ed25519(cred, response);
	পূর্বনির্ধারিত:
		ফেরত -1;
	}
}

স্থির পূর্ণসংখ্যা
fidoerr_to_skerr(পূর্ণসংখ্যা fidoerr)
{
	নির্বাচন (fidoerr) {
	ক্ষেত্র FIDO_ERR_UNSUPPORTED_OPTION:
	ক্ষেত্র FIDO_ERR_UNSUPPORTED_ALGORITHM:
		ফেরত SSH_SK_ERR_UNSUPPORTED;
	ক্ষেত্র FIDO_ERR_PIN_REQUIRED:
	ক্ষেত্র FIDO_ERR_PIN_INVALID:
	ক্ষেত্র FIDO_ERR_OPERATION_DENIED:
		ফেরত SSH_SK_ERR_PIN_REQUIRED;
	পূর্বনির্ধারিত:
		ফেরত -1;
	}
}

স্থির পূর্ণসংখ্যা
check_enroll_options(কাঠামো sk_option **options, অক্ষর **devicep,
    uint8_t *user_id, আকার_t user_id_len)
{
	আকার_t i;

	যদি (options == ফাঁকা)
		ফেরত 0;
	জন্য (i = 0; options[i] != ফাঁকা; i++) {
		যদি (strcmp(options[i]->name, "device") == 0) {
			যদি ((*devicep = strdup(options[i]->মান)) == ফাঁকা) {
				skdebug(__func__, "strdup device failed");
				ফেরত -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} অন্যথা যদি (strcmp(options[i]->name, "user") == 0) {
			যদি (strlcpy(user_id, options[i]->মান, user_id_len) >=
			    user_id_len) {
				skdebug(__func__, "user too long");
				ফেরত -1;
			}
			skdebug(__func__, "requested user %s",
			    (অক্ষর *)user_id);
		} অন্যথা {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			যদি (options[i]->required) {
				skdebug(__func__, "unknown required option");
				ফেরত -1;
			}
		}
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
চাবি_lookup(fido_dev_t *dev, ধ্রুবক অক্ষর *application, ধ্রুবক uint8_t *user_id,
    আকার_t user_id_len, ধ্রুবক অক্ষর *pin)
{
	fido_assert_t *প্রতিজ্ঞা = ফাঁকা;
	uint8_t message[32];
	পূর্ণসংখ্যা r = FIDO_ERR_INTERNAL;
	পূর্ণসংখ্যা sk_supports_uv, uv;
	আকার_t i;

	memset(message, '\0', আকার(message));
	যদি ((প্রতিজ্ঞা = fido_assert_new()) == ফাঁকা) {
		skdebug(__func__, "fido_assert_new failed");
		যাও out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	যদি ((r = fido_assert_set_clientdata(প্রতিজ্ঞা, message,
	    আকার(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		যাও out;
	}
	যদি ((r = fido_assert_set_rp(প্রতিজ্ঞা, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		যাও out;
	}
	যদি ((r = fido_assert_set_up(প্রতিজ্ঞা, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		যাও out;
	}
	uv = FIDO_OPT_OMIT;
	যদি (pin == ফাঁকা && check_sk_options(dev, "uv", &sk_supports_uv) == 0 &&
	    sk_supports_uv != -1)
		uv = FIDO_OPT_TRUE;
	যদি ((r = fido_assert_set_uv(প্রতিজ্ঞা, uv)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
		যাও out;
	}
	যদি ((r = fido_dev_get_assert(dev, প্রতিজ্ঞা, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		যাও out;
	}
	r = FIDO_ERR_NO_CREDENTIALS;
	skdebug(__func__, "%zu signatures returned", fido_assert_গুনতি(প্রতিজ্ঞা));
	জন্য (i = 0; i < fido_assert_গুনতি(প্রতিজ্ঞা); i++) {
		যদি (fido_assert_user_id_len(প্রতিজ্ঞা, i) == user_id_len &&
		    memcmp(fido_assert_user_id_ptr(প্রতিজ্ঞা, i), user_id,
		    user_id_len) == 0) {
			skdebug(__func__, "credential exists");
			r = FIDO_OK;
			যাও out;
		}
	}
 out:
	fido_assert_free(&প্রতিজ্ঞা);

	ফেরত r;
}

পূর্ণসংখ্যা
sk_enroll(uint32_t alg, ধ্রুবক uint8_t *challenge, আকার_t challenge_len,
    ধ্রুবক অক্ষর *application, uint8_t flags, ধ্রুবক অক্ষর *pin,
    কাঠামো sk_option **options, কাঠামো sk_enroll_response **enroll_response)
{
	fido_cred_t *cred = ফাঁকা;
	ধ্রুবক uint8_t *ptr;
	uint8_t user_id[32];
	কাঠামো sk_usbhid *sk = ফাঁকা;
	কাঠামো sk_enroll_response *response = ফাঁকা;
	আকার_t len;
	পূর্ণসংখ্যা credprot;
	পূর্ণসংখ্যা cose_alg;
	পূর্ণসংখ্যা ret = SSH_SK_ERR_GENERAL;
	পূর্ণসংখ্যা r;
	অক্ষর *device = ফাঁকা;

	fido_init(SSH_FIDO_INIT_ARG);

	যদি (enroll_response == ফাঁকা) {
		skdebug(__func__, "enroll_response == NULL");
		যাও out;
	}
	*enroll_response = ফাঁকা;
	memset(user_id, 0, আকার(user_id));
	যদি (check_enroll_options(options, &device, user_id,
	    আকার(user_id)) != 0)
		যাও out; /* error already logged */

	নির্বাচন(alg) {
#ifdef WITH_OPENSSL
	ক্ষেত্র SSH_SK_ECDSA:
		cose_alg = COSE_ES256;
		বিরতি;
#endif /* WITH_OPENSSL */
	ক্ষেত্র SSH_SK_ED25519:
		cose_alg = COSE_EDDSA;
		বিরতি;
	পূর্বনির্ধারিত:
		skdebug(__func__, "unsupported key type %d", alg);
		যাও out;
	}
	যদি (device != ফাঁকা)
		sk = sk_open(device);
	অন্যথা
		sk = sk_probe(ফাঁকা, ফাঁকা, 0, 0);
	যদি (sk == ফাঁকা) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		যাও out;
	}
	skdebug(__func__, "using device %s", sk->path);
	যদি ((flags & SSH_SK_RESIDENT_চাবি) != 0 &&
	    (flags & SSH_SK_FORCE_OPERATION) == 0 &&
	    (r = চাবি_lookup(sk->dev, application, user_id, আকার(user_id),
	    pin)) != FIDO_ERR_NO_CREDENTIALS) {
		যদি (r != FIDO_OK) {
			ret = fidoerr_to_skerr(r);
			skdebug(__func__, "key_lookup failed");
		} অন্যথা {
			ret = SSH_SK_ERR_CREDENTIAL_EXISTS;
			skdebug(__func__, "key exists");
		}
		যাও out;
	}
	যদি ((cred = fido_cred_new()) == ফাঁকা) {
		skdebug(__func__, "fido_cred_new failed");
		যাও out;
	}
	যদি ((r = fido_cred_set_type(cred, cose_alg)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_type: %s", fido_strerr(r));
		যাও out;
	}
	যদি ((r = fido_cred_set_clientdata(cred,
	    challenge, challenge_len)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata: %s",
		    fido_strerr(r));
		যাও out;
	}
	যদি ((r = fido_cred_set_rk(cred, (flags & SSH_SK_RESIDENT_চাবি) != 0 ?
	    FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rk: %s", fido_strerr(r));
		যাও out;
	}
	যদি ((r = fido_cred_set_user(cred, user_id, আকার(user_id),
	    "openssh", "openssh", ফাঁকা)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_user: %s", fido_strerr(r));
		যাও out;
	}
	যদি ((r = fido_cred_set_rp(cred, application, ফাঁকা)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rp: %s", fido_strerr(r));
		যাও out;
	}
	যদি ((flags & (SSH_SK_RESIDENT_চাবি|SSH_SK_USER_VERIFICATION_REQD)) != 0) {
#যদি !defined(HAVE_FIDO_DEV_SUPPORTS_CRED_PROT) || \
    !defined(HAVE_FIDO_CRED_SET_PROT)
		skdebug(__func__, "libfido2 version does not support a feature required for this operation. Please upgrade to >=1.5.0");
		ret = SSH_SK_ERR_UNSUPPORTED;
		যাও out;
		credprot = 0; (শূন্য)credprot; /* avoid warning */
#endif
		যদি (!fido_dev_supports_cred_prot(sk->dev)) {
			skdebug(__func__, "%s does not support credprot, "
			    "refusing to create unprotected "
			    "resident/verify-required key", sk->path);
			ret = SSH_SK_ERR_UNSUPPORTED;
			যাও out;
		}
		যদি ((flags & SSH_SK_USER_VERIFICATION_REQD))
			credprot = FIDO_CRED_PROT_UV_REQUIRED;
		অন্যথা
			credprot = FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID;

		যদি ((r = fido_cred_set_prot(cred, credprot)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_set_prot: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			যাও out;
		}
	}
	যদি ((r = fido_dev_make_cred(sk->dev, cred, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_make_cred: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		যাও out;
	}
	যদি (fido_cred_x5c_ptr(cred) != ফাঁকা) {
		যদি ((r = fido_cred_verify(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify: %s",
			    fido_strerr(r));
			যাও out;
		}
	} অন্যথা যদি (strcmp(fido_cred_fmt(cred), "none") != 0) {
		skdebug(__func__, "self-attested credential");
		যদি ((r = fido_cred_verify_self(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify_self: %s",
			    fido_strerr(r));
			যাও out;
		}
	} অন্যথা {
		skdebug(__func__, "no attestation data");
	}
	যদি ((response = calloc(1, আকার(*response))) == ফাঁকা) {
		skdebug(__func__, "calloc response failed");
		যাও out;
	}
	response->flags = flags;
	যদি (pack_public_চাবি(alg, cred, response) != 0) {
		skdebug(__func__, "pack_public_key failed");
		যাও out;
	}
	যদি ((ptr = fido_cred_id_ptr(cred)) != ফাঁকা) {
		len = fido_cred_id_len(cred);
		যদি ((response->চাবি_handle = calloc(1, len)) == ফাঁকা) {
			skdebug(__func__, "calloc key handle failed");
			যাও out;
		}
		memcpy(response->চাবি_handle, ptr, len);
		response->চাবি_handle_len = len;
	}
	যদি ((ptr = fido_cred_sig_ptr(cred)) != ফাঁকা) {
		len = fido_cred_sig_len(cred);
		যদি ((response->signature = calloc(1, len)) == ফাঁকা) {
			skdebug(__func__, "calloc signature failed");
			যাও out;
		}
		memcpy(response->signature, ptr, len);
		response->signature_len = len;
	}
	যদি ((ptr = fido_cred_x5c_ptr(cred)) != ফাঁকা) {
		len = fido_cred_x5c_len(cred);
		skdebug(__func__, "attestation cert len=%zu", len);
		যদি ((response->attestation_cert = calloc(1, len)) == ফাঁকা) {
			skdebug(__func__, "calloc attestation cert failed");
			যাও out;
		}
		memcpy(response->attestation_cert, ptr, len);
		response->attestation_cert_len = len;
	}
	যদি ((ptr = fido_cred_authdata_ptr(cred)) != ফাঁকা) {
		len = fido_cred_authdata_len(cred);
		skdebug(__func__, "authdata len=%zu", len);
		যদি ((response->authdata = calloc(1, len)) == ফাঁকা) {
			skdebug(__func__, "calloc authdata failed");
			যাও out;
		}
		memcpy(response->authdata, ptr, len);
		response->authdata_len = len;
	}
	*enroll_response = response;
	response = ফাঁকা;
	ret = 0;
 out:
	মুক্ত(device);
	যদি (response != ফাঁকা) {
		মুক্ত(response->public_চাবি);
		মুক্ত(response->চাবি_handle);
		মুক্ত(response->signature);
		মুক্ত(response->attestation_cert);
		মুক্ত(response->authdata);
		মুক্ত(response);
	}
	sk_close(sk);
	fido_cred_free(&cred);
	ফেরত ret;
}

#ifdef WITH_OPENSSL
স্থির পূর্ণসংখ্যা
pack_sig_ecdsa(fido_assert_t *প্রতিজ্ঞা, কাঠামো sk_sign_response *response)
{
	ECDSA_SIG *sig = ফাঁকা;
	ধ্রুবক BIGNUM *sig_r, *sig_s;
	ধ্রুবক unsigned অক্ষর *cp;
	আকার_t sig_len;
	পূর্ণসংখ্যা ret = -1;

	cp = fido_assert_sig_ptr(প্রতিজ্ঞা, 0);
	sig_len = fido_assert_sig_len(প্রতিজ্ঞা, 0);
	যদি ((sig = d2i_ECDSA_SIG(ফাঁকা, &cp, sig_len)) == ফাঁকা) {
		skdebug(__func__, "d2i_ECDSA_SIG failed");
		যাও out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_অঙ্ক_bytes(sig_r);
	response->sig_s_len = BN_অঙ্ক_bytes(sig_s);
	যদি ((response->sig_r = calloc(1, response->sig_r_len)) == ফাঁকা ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == ফাঁকা) {
		skdebug(__func__, "calloc signature failed");
		যাও out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	ECDSA_SIG_free(sig);
	যদি (ret != 0) {
		মুক্ত(response->sig_r);
		মুক্ত(response->sig_s);
		response->sig_r = ফাঁকা;
		response->sig_s = ফাঁকা;
	}
	ফেরত ret;
}
#endif /* WITH_OPENSSL */

স্থির পূর্ণসংখ্যা
pack_sig_ed25519(fido_assert_t *প্রতিজ্ঞা, কাঠামো sk_sign_response *response)
{
	ধ্রুবক unsigned অক্ষর *ptr;
	আকার_t len;
	পূর্ণসংখ্যা ret = -1;

	ptr = fido_assert_sig_ptr(প্রতিজ্ঞা, 0);
	len = fido_assert_sig_len(প্রতিজ্ঞা, 0);
	যদি (len != 64) {
		skdebug(__func__, "bad length %zu", len);
		যাও out;
	}
	response->sig_r_len = len;
	যদি ((response->sig_r = calloc(1, response->sig_r_len)) == ফাঁকা) {
		skdebug(__func__, "calloc signature failed");
		যাও out;
	}
	memcpy(response->sig_r, ptr, len);
	ret = 0;
 out:
	যদি (ret != 0) {
		মুক্ত(response->sig_r);
		response->sig_r = ফাঁকা;
	}
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
pack_sig(uint32_t  alg, fido_assert_t *প্রতিজ্ঞা,
    কাঠামো sk_sign_response *response)
{
	নির্বাচন(alg) {
#ifdef WITH_OPENSSL
	ক্ষেত্র SSH_SK_ECDSA:
		ফেরত pack_sig_ecdsa(প্রতিজ্ঞা, response);
#endif /* WITH_OPENSSL */
	ক্ষেত্র SSH_SK_ED25519:
		ফেরত pack_sig_ed25519(প্রতিজ্ঞা, response);
	পূর্বনির্ধারিত:
		ফেরত -1;
	}
}

/* Checks sk_options for sk_sign() and sk_load_resident_keys() */
স্থির পূর্ণসংখ্যা
check_sign_load_resident_options(কাঠামো sk_option **options, অক্ষর **devicep)
{
	আকার_t i;

	যদি (options == ফাঁকা)
		ফেরত 0;
	জন্য (i = 0; options[i] != ফাঁকা; i++) {
		যদি (strcmp(options[i]->name, "device") == 0) {
			যদি ((*devicep = strdup(options[i]->মান)) == ফাঁকা) {
				skdebug(__func__, "strdup device failed");
				ফেরত -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} অন্যথা {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			যদি (options[i]->required) {
				skdebug(__func__, "unknown required option");
				ফেরত -1;
			}
		}
	}
	ফেরত 0;
}

পূর্ণসংখ্যা
sk_sign(uint32_t alg, ধ্রুবক uint8_t *তথ্য, আকার_t datalen,
    ধ্রুবক অক্ষর *application,
    ধ্রুবক uint8_t *চাবি_handle, আকার_t চাবি_handle_len,
    uint8_t flags, ধ্রুবক অক্ষর *pin, কাঠামো sk_option **options,
    কাঠামো sk_sign_response **sign_response)
{
	fido_assert_t *প্রতিজ্ঞা = ফাঁকা;
	অক্ষর *device = ফাঁকা;
	কাঠামো sk_usbhid *sk = ফাঁকা;
	কাঠামো sk_sign_response *response = ফাঁকা;
	পূর্ণসংখ্যা ret = SSH_SK_ERR_GENERAL, internal_uv;
	পূর্ণসংখ্যা r;

	fido_init(SSH_FIDO_INIT_ARG);

	যদি (sign_response == ফাঁকা) {
		skdebug(__func__, "sign_response == NULL");
		যাও out;
	}
	*sign_response = ফাঁকা;
	যদি (check_sign_load_resident_options(options, &device) != 0)
		যাও out; /* error already logged */
	যদি (device != ফাঁকা)
		sk = sk_open(device);
	অন্যথা যদি (pin != ফাঁকা || (flags & SSH_SK_USER_VERIFICATION_REQD))
		sk = sk_probe(ফাঁকা, ফাঁকা, 0, 0);
	অন্যথা
		sk = sk_probe(application, চাবি_handle, চাবি_handle_len, 0);
	যদি (sk == ফাঁকা) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		যাও out;
	}
	যদি ((প্রতিজ্ঞা = fido_assert_new()) == ফাঁকা) {
		skdebug(__func__, "fido_assert_new failed");
		যাও out;
	}
	যদি ((r = fido_assert_set_clientdata(প্রতিজ্ঞা,
	    তথ্য, datalen)) != FIDO_OK)  {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		যাও out;
	}
	যদি ((r = fido_assert_set_rp(প্রতিজ্ঞা, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		যাও out;
	}
	যদি ((r = fido_assert_allow_cred(প্রতিজ্ঞা, চাবি_handle,
	    চাবি_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		যাও out;
	}
	যদি ((r = fido_assert_set_up(প্রতিজ্ঞা,
	    (flags & SSH_SK_USER_PRESENCE_REQD) ?
	    FIDO_OPT_TRUE : FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		যাও out;
	}
	/*
	 * WinHello requests the PIN by default.  Make "uv" request explicit
	 * to allow keys with and without -O verify-required to make sense.
	 */
	যদি (pin == ফাঁকা && fido_dev_is_winhello (sk->dev) &&
	    (r = fido_assert_set_uv(প্রতিজ্ঞা, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
	}
	যদি (pin == ফাঁকা && (flags & SSH_SK_USER_VERIFICATION_REQD)) {
		যদি (check_sk_options(sk->dev, "uv", &internal_uv) < 0 ||
		    internal_uv != 1) {
			skdebug(__func__, "check_sk_options uv");
			ret = SSH_SK_ERR_PIN_REQUIRED;
			যাও out;
		}
		যদি ((r = fido_assert_set_uv(প্রতিজ্ঞা,
		    FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_assert_set_uv: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			যাও out;
		}
	}
	যদি ((r = fido_dev_get_assert(sk->dev, প্রতিজ্ঞা, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		যাও out;
	}
	যদি ((response = calloc(1, আকার(*response))) == ফাঁকা) {
		skdebug(__func__, "calloc response failed");
		যাও out;
	}
	response->flags = fido_assert_flags(প্রতিজ্ঞা, 0);
	response->গণক = fido_assert_sigcount(প্রতিজ্ঞা, 0);
	যদি (pack_sig(alg, প্রতিজ্ঞা, response) != 0) {
		skdebug(__func__, "pack_sig failed");
		যাও out;
	}
	*sign_response = response;
	response = ফাঁকা;
	ret = 0;
 out:
	মুক্ত(device);
	যদি (response != ফাঁকা) {
		মুক্ত(response->sig_r);
		মুক্ত(response->sig_s);
		মুক্ত(response);
	}
	sk_close(sk);
	fido_assert_free(&প্রতিজ্ঞা);
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
read_rks(কাঠামো sk_usbhid *sk, ধ্রুবক অক্ষর *pin,
    কাঠামো sk_resident_চাবি ***rksp, আকার_t *nrksp)
{
	পূর্ণসংখ্যা ret = SSH_SK_ERR_GENERAL, r = -1;
	uint32_t alg;
	fido_credman_metadata_t *metadata = ফাঁকা;
	fido_credman_rp_t *rp = ফাঁকা;
	fido_credman_rk_t *rk = ফাঁকা;
	আকার_t i, j, nrp, nrk, user_id_len;
	ধ্রুবক fido_cred_t *cred;
	ধ্রুবক অক্ষর *rp_id, *rp_name, *user_name;
	কাঠামো sk_resident_চাবি *srk = ফাঁকা, **tmp;
	ধ্রুবক u_char *user_id;

	যদি (pin == ফাঁকা) {
		skdebug(__func__, "no PIN specified");
		ret = SSH_SK_ERR_PIN_REQUIRED;
		যাও out;
	}
	যদি ((metadata = fido_credman_metadata_new()) == ফাঁকা) {
		skdebug(__func__, "alloc failed");
		যাও out;
	}
	যদি ((r = fido_credman_get_dev_metadata(sk->dev, metadata, pin)) != 0) {
		যদি (r == FIDO_ERR_INVALID_COMMAND) {
			skdebug(__func__, "device %s does not support "
			    "resident keys", sk->path);
			ret = 0;
			যাও out;
		}
		skdebug(__func__, "get metadata for %s failed: %s",
		    sk->path, fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		যাও out;
	}
	skdebug(__func__, "existing %llu, remaining %llu",
	    (unsigned long long)fido_credman_rk_existing(metadata),
	    (unsigned long long)fido_credman_rk_remaining(metadata));
	যদি ((rp = fido_credman_rp_new()) == ফাঁকা) {
		skdebug(__func__, "alloc rp failed");
		যাও out;
	}
	যদি ((r = fido_credman_get_dev_rp(sk->dev, rp, pin)) != 0) {
		skdebug(__func__, "get RPs for %s failed: %s",
		    sk->path, fido_strerr(r));
		যাও out;
	}
	nrp = fido_credman_rp_গুনতি(rp);
	skdebug(__func__, "Device %s has resident keys for %zu RPs",
	    sk->path, nrp);

	/* Iterate over RP IDs that have resident keys */
	জন্য (i = 0; i < nrp; i++) {
		rp_id = fido_credman_rp_id(rp, i);
		rp_name = fido_credman_rp_name(rp, i);
		skdebug(__func__, "rp %zu: name=\"%s\" id=\"%s\" hashlen=%zu",
		    i, rp_name == ফাঁকা ? "(none)" : rp_name,
		    rp_id == ফাঁকা ? "(none)" : rp_id,
		    fido_credman_rp_id_hash_len(rp, i));

		/* Skip non-SSH RP IDs */
		যদি (rp_id == ফাঁকা ||
		    strncasecmp(fido_credman_rp_id(rp, i), "ssh:", 4) != 0)
			চালু;

		fido_credman_rk_free(&rk);
		যদি ((rk = fido_credman_rk_new()) == ফাঁকা) {
			skdebug(__func__, "alloc rk failed");
			যাও out;
		}
		যদি ((r = fido_credman_get_dev_rk(sk->dev,
		    fido_credman_rp_id(rp, i), rk, pin)) != 0) {
			skdebug(__func__, "get RKs for %s slot %zu failed: %s",
			    sk->path, i, fido_strerr(r));
			যাও out;
		}
		nrk = fido_credman_rk_গুনতি(rk);
		skdebug(__func__, "RP \"%s\" has %zu resident keys",
		    fido_credman_rp_id(rp, i), nrk);

		/* Iterate over resident keys for this RP ID */
		জন্য (j = 0; j < nrk; j++) {
			যদি ((cred = fido_credman_rk(rk, j)) == ফাঁকা) {
				skdebug(__func__, "no RK in slot %zu", j);
				চালু;
			}
			যদি ((user_name = fido_cred_user_name(cred)) == ফাঁকা)
				user_name = "";
			user_id = fido_cred_user_id_ptr(cred);
			user_id_len = fido_cred_user_id_len(cred);
			skdebug(__func__, "Device %s RP \"%s\" user \"%s\" "
			    "uidlen %zu slot %zu: type %d flags 0x%02x "
			    "prot 0x%02x", sk->path, rp_id, user_name,
			    user_id_len, j, fido_cred_type(cred),
			    fido_cred_flags(cred), fido_cred_prot(cred));

			/* Determine key algorithm */
			নির্বাচন (fido_cred_type(cred)) {
			ক্ষেত্র COSE_ES256:
				alg = SSH_SK_ECDSA;
				বিরতি;
			ক্ষেত্র COSE_EDDSA:
				alg = SSH_SK_ED25519;
				বিরতি;
			পূর্বনির্ধারিত:
				skdebug(__func__, "unsupported key type %d",
				    fido_cred_type(cred));
				চালু;
			}

			/* build response entry */
			যদি ((srk = calloc(1, আকার(*srk))) == ফাঁকা ||
			    (srk->চাবি.চাবি_handle = calloc(1,
			    fido_cred_id_len(cred))) == ফাঁকা ||
			    (srk->application = strdup(rp_id)) == ফাঁকা ||
			    (user_id_len > 0 &&
			     (srk->user_id = calloc(1, user_id_len)) == ফাঁকা)) {
				skdebug(__func__, "alloc sk_resident_key");
				যাও out;
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
				যাও out;
			}
			/* append */
			যদি ((tmp = recallocarray(*rksp, *nrksp, (*nrksp) + 1,
			    আকার(**rksp))) == ফাঁকা) {
				skdebug(__func__, "alloc rksp");
				যাও out;
			}
			*rksp = tmp;
			(*rksp)[(*nrksp)++] = srk;
			srk = ফাঁকা;
		}
	}
	/* Success */
	ret = 0;
 out:
	যদি (srk != ফাঁকা) {
		মুক্ত(srk->application);
		freezero(srk->চাবি.public_চাবি, srk->চাবি.public_চাবি_len);
		freezero(srk->চাবি.চাবি_handle, srk->চাবি.চাবি_handle_len);
		freezero(srk->user_id, srk->user_id_len);
		freezero(srk, আকার(*srk));
	}
	fido_credman_rp_free(&rp);
	fido_credman_rk_free(&rk);
	fido_credman_metadata_free(&metadata);
	ফেরত ret;
}

পূর্ণসংখ্যা
sk_load_resident_চাবিগুলি(ধ্রুবক অক্ষর *pin, কাঠামো sk_option **options,
    কাঠামো sk_resident_চাবি ***rksp, আকার_t *nrksp)
{
	পূর্ণসংখ্যা ret = SSH_SK_ERR_GENERAL, r = -1;
	আকার_t i, nrks = 0;
	কাঠামো sk_resident_চাবি **rks = ফাঁকা;
	কাঠামো sk_usbhid *sk = ফাঁকা;
	অক্ষর *device = ফাঁকা;

	*rksp = ফাঁকা;
	*nrksp = 0;

	fido_init(SSH_FIDO_INIT_ARG);

	যদি (check_sign_load_resident_options(options, &device) != 0)
		যাও out; /* error already logged */
	যদি (device != ফাঁকা)
		sk = sk_open(device);
	অন্যথা
		sk = sk_probe(ফাঁকা, ফাঁকা, 0, 1);
	যদি (sk == ফাঁকা) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		যাও out;
	}
	skdebug(__func__, "trying %s", sk->path);
	যদি ((r = read_rks(sk, pin, &rks, &nrks)) != 0) {
		skdebug(__func__, "read_rks failed for %s", sk->path);
		ret = r;
		যাও out;
	}
	/* success, unless we have no keys but a specific error */
	যদি (nrks > 0 || ret == SSH_SK_ERR_GENERAL)
		ret = 0;
	*rksp = rks;
	*nrksp = nrks;
	rks = ফাঁকা;
	nrks = 0;
 out:
	sk_close(sk);
	জন্য (i = 0; i < nrks; i++) {
		মুক্ত(rks[i]->application);
		freezero(rks[i]->চাবি.public_চাবি, rks[i]->চাবি.public_চাবি_len);
		freezero(rks[i]->চাবি.চাবি_handle, rks[i]->চাবি.চাবি_handle_len);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i], আকার(*rks[i]));
	}
	মুক্ত(device);
	মুক্ত(rks);
	ফেরত ret;
}

#endif /* ENABLE_SK_INTERNAL */
