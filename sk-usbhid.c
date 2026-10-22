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

#جے_تعریف_شدہ ENABLE_SK_اندرونی

#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <stdio.h>
#ضمن <stddef.h>
#ضمن <stdarg.h>
#ضمن <time.h>
#جے_تعریف_شدہ HAVE_SHA2_H
#ضمن <sha2.h>
#جے_انت

#جے_تعریف_شدہ WITH_OPENSSL
#ضمن <openssl/opensslv.h>
#ضمن <openssl/crypto.h>
#ضمن <openssl/bn.h>
#ضمن <openssl/ec.h>
#ضمن <openssl/ecdsa.h>
#ضمن <openssl/evp.h>
#ضمن "openbsd-compat/openssl-compat.h"
#جے_انت /* WITH_OPENSSL */

#ضمن <fido.h>
#ضمن <fido/credman.h>

/* backwards compat for libfido2 */
#جے_بنا_تعریف HAVE_FIDO_CRED_PROT
#تعریف_کرو fido_cred_prot(x) (0)
#جے_انت
#جے_بنا_تعریف HAVE_FIDO_CRED_سیٹ_PROT
#تعریف_کرو fido_cred_سیٹ_prot(x, y) (FIDO_ERR_UNSUPPORTED_OPTION)
#جے_انت
#جے_بنا_تعریف HAVE_FIDO_DEV_SUPPORTS_CRED_PROT
#تعریف_کرو fido_dev_supports_cred_prot(x) (0)
#جے_انت
#جے_بنا_تعریف HAVE_FIDO_DEV_GET_TOUCH_BEGIN
#تعریف_کرو fido_dev_get_touch_begin(x) (FIDO_ERR_UNSUPPORTED_OPTION)
#جے_انت
#جے_بنا_تعریف HAVE_FIDO_DEV_GET_TOUCH_حالت
#تعریف_کرو fido_dev_get_touch_حالت(x, y, z) (FIDO_ERR_UNSUPPORTED_OPTION)
#جے_انت
#جے_بنا_تعریف FIDO_CRED_PROT_UV_REQUIRED
#تعریف_کرو FIDO_CRED_PROT_UV_REQUIRED 0
#جے_انت
#جے_بنا_تعریف FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID
#تعریف_کرو FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID 0
#جے_انت

# include "misc.h"

#جے_بنا_تعریف SK_STANDALONE
# include "log.h"
# include "xmalloc.h"
/*
 * If building as part of OpenSSH, then rename exported functions.
 * This must be done before including sk-api.h.
 */
# define sk_api_نسخہ		ssh_sk_api_نسخہ
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_لدو_resident_کلیدیں	ssh_sk_لدو_resident_کلیدیں
#جے_انت /* !SK_STANDALONE */

#ضمن "sk-api.h"

/* #define SK_DEBUG 1 */

#جے_تعریف_شدہ SK_DEBUG
#تعریف_کرو SSH_FIDO_INIT_ARG	FIDO_DEBUG
#وإلا
#تعریف_کرو SSH_FIDO_INIT_ARG	0
#جے_انت

#تعریف_کرو MAX_FIDO_DEVICES	8
#تعریف_کرو FIDO_POLL_MS		50
#تعریف_کرو SELECT_MS		15000
#تعریف_کرو POLL_SLEEP_NS		200000000

#جے_بنا_تعریف FIDO_ERR_OPERATION_DENIED
#تعریف_کرو FIDO_ERR_OPERATION_DENIED 0x27
#جے_انت

بنية sk_usbhid {
	fido_dev_t *dev;
	حرف *رستہ;
};

/* Return the version of the middleware API */
uint32_t sk_api_نسخہ(فراغ);

/* Enroll a U2F key (private key generation) */
صحيح sk_enroll(uint32_t alg, ثابت uint8_t *challenge, ناپ_t challenge_len,
    ثابت حرف *application, uint8_t flags, ثابت حرف *pin,
    بنية sk_option **options, بنية sk_enroll_response **enroll_response);

/* Sign a challenge */
صحيح sk_sign(uint32_t alg, ثابت uint8_t *انکڑے, ناپ_t انکڑے_len,
    ثابت حرف *application, ثابت uint8_t *کلید_handle, ناپ_t کلید_handle_len,
    uint8_t flags, ثابت حرف *pin, بنية sk_option **options,
    بنية sk_sign_response **sign_response);

/* Load resident keys */
صحيح sk_لدو_resident_کلیدیں(ثابت حرف *pin, بنية sk_option **options,
    بنية sk_resident_کلید ***rks, ناپ_t *nrks);

ساكن فراغ skdebug(ثابت حرف *func, ثابت حرف *fmt, ...)
    __attribute__((__format__ (لکھو, 2, 3)));

ساكن فراغ
skdebug(ثابت حرف *func, ثابت حرف *fmt, ...)
{
#إذا !defined(SK_STANDALONE)
	حرف *پیغام;
	va_list ap;

	va_start(ap, fmt);
	xvasprintf(&پیغام, fmt, ap);
	va_end(ap);
	debug("%s: %s", func, پیغام);
	حرر(پیغام);
#وإلاإذا defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#وإلا
	(فراغ)func; /* XXX */
	(فراغ)fmt; /* XXX */
#جے_انت
}

uint32_t
sk_api_نسخہ(فراغ)
{
	أرجع SSH_SK_نسخہ_MAJOR;
}

ساكن بنية sk_usbhid *
sk_open(ثابت حرف *رستہ)
{
	بنية sk_usbhid *sk;
	صحيح r;

	إذا (رستہ == عدم) {
		skdebug(__func__, "path == NULL");
		أرجع عدم;
	}
	إذا ((sk = صفر_حافظہ_دیو(1, حجم(*sk))) == عدم) {
		skdebug(__func__, "calloc sk failed");
		أرجع عدم;
	}
	إذا ((sk->رستہ = strdup(رستہ)) == عدم) {
		skdebug(__func__, "strdup path failed");
		حرر(sk);
		أرجع عدم;
	}
	إذا ((sk->dev = fido_dev_new()) == عدم) {
		skdebug(__func__, "fido_dev_new failed");
		حرر(sk->رستہ);
		حرر(sk);
		أرجع عدم;
	}
	إذا ((r = fido_dev_open(sk->dev, sk->رستہ)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_open %s failed: %s", sk->رستہ,
		    fido_strerr(r));
		fido_dev_free(&sk->dev);
		حرر(sk->رستہ);
		حرر(sk);
		أرجع عدم;
	}
	أرجع sk;
}

ساكن فراغ
sk_close(بنية sk_usbhid *sk)
{
	إذا (sk == عدم)
		أرجع;
	fido_dev_cancel(sk->dev); /* cancel any pending operation */
	fido_dev_close(sk->dev);
	fido_dev_free(&sk->dev);
	حرر(sk->رستہ);
	حرر(sk);
}

ساكن بنية sk_usbhid **
sk_openv(ثابت fido_dev_info_t *devlist, ناپ_t ndevs, ناپ_t *nopen)
{
	ثابت fido_dev_info_t *di;
	بنية sk_usbhid **skv;
	ناپ_t i;

	*nopen = 0;
	إذا ((skv = صفر_حافظہ_دیو(ndevs, حجم(*skv))) == عدم) {
		skdebug(__func__, "calloc skv failed");
		أرجع عدم;
	}
	لكل (i = 0; i < ndevs; i++) {
		إذا ((di = fido_dev_info_ptr(devlist, i)) == عدم)
			skdebug(__func__, "fido_dev_info_ptr failed");
		وإلا إذا ((skv[*nopen] = sk_open(fido_dev_info_رستہ(di))) == عدم)
			skdebug(__func__, "sk_open failed");
		وإلا
			(*nopen)++;
	}
	إذا (*nopen == 0) {
		لكل (i = 0; i < ndevs; i++)
			sk_close(skv[i]);
		حرر(skv);
		skv = عدم;
	}

	أرجع skv;
}

ساكن فراغ
sk_closev(بنية sk_usbhid **skv, ناپ_t nsk)
{
	ناپ_t i;

	لكل (i = 0; i < nsk; i++)
		sk_close(skv[i]);
	حرر(skv);
}

ساكن صحيح
sk_touch_begin(بنية sk_usbhid **skv, ناپ_t nsk)
{
	ناپ_t i, ok = 0;
	صحيح r;

	لكل (i = 0; i < nsk; i++)
		إذا ((r = fido_dev_get_touch_begin(skv[i]->dev)) != FIDO_OK)
			skdebug(__func__, "fido_dev_get_touch_begin %s failed:"
			    " %s", skv[i]->رستہ, fido_strerr(r));
		وإلا
			ok++;

	أرجع ok ? 0 : -1;
}

ساكن صحيح
sk_touch_poll(بنية sk_usbhid **skv, ناپ_t nsk, صحيح *touch, ناپ_t *idx)
{
	بنية timespec ts_pause;
	ناپ_t npoll, i;
	صحيح r;

	ts_pause.tv_sec = 0;
	ts_pause.tv_nsec = POLL_SLEEP_NS;
	nanosleep(&ts_pause, عدم);
	npoll = nsk;
	لكل (i = 0; i < nsk; i++) {
		إذا (skv[i] == عدم)
			استمر; /* device discarded */
		skdebug(__func__, "polling %s", skv[i]->رستہ);
		إذا ((r = fido_dev_get_touch_حالت(skv[i]->dev, touch,
		    FIDO_POLL_MS)) != FIDO_OK) {
			skdebug(__func__, "fido_dev_get_touch_status %s: %s",
			    skv[i]->رستہ, fido_strerr(r));
			sk_close(skv[i]); /* discard device */
			skv[i] = عدم;
			إذا (--npoll == 0) {
				skdebug(__func__, "no device left to poll");
				أرجع -1;
			}
		} وإلا إذا (*touch) {
			*idx = i;
			أرجع 0;
		}
	}
	*touch = 0;
	أرجع 0;
}

#إذا !defined(HAVE_FIDO_ASSERT_سیٹ_CLIENTDATA) || \
    !defined(HAVE_FIDO_CRED_سیٹ_CLIENTDATA)
/* Calculate SHA256(m) */
ساكن صحيح
sha256_mem(ثابت فراغ *m, ناپ_t mlen, u_char *d, ناپ_t dlen)
{
#جے_تعریف_شدہ WITH_OPENSSL
	u_int mdlen;
#وإلا
	SHA2_CTX ctx;
#جے_انت

	إذا (dlen != 32)
		أرجع -1;
#جے_تعریف_شدہ WITH_OPENSSL
	mdlen = dlen;
	إذا (!EVP_Digest(m, mlen, d, &mdlen, EVP_sha256(), عدم))
		أرجع -1;
#وإلا
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ثابت uint8_t *)m, mlen);
	SHA256Final(d, &ctx);
#جے_انت
	أرجع 0;
}
#جے_انت /* !HAVE_FIDO_ASSERT_SET_CLIENTDATA || !HAVE_FIDO_CRED_SET_CLIENTDATA */

#جے_بنا_تعریف HAVE_FIDO_CRED_سیٹ_CLIENTDATA
ساكن صحيح
fido_cred_سیٹ_clientdata(fido_cred_t *cred, ثابت u_char *ptr, ناپ_t len)
{
	uint8_t d[32];
	صحيح r;

	إذا (sha256_mem(ptr, len, d, حجم(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		أرجع FIDO_ERR_اندرونی;
	}
	r = fido_cred_سیٹ_clientdata_hash(cred, d, حجم(d));
	explicit_bzero(d, حجم(d));
	إذا (r != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	أرجع r;
}
#جے_انت /* HAVE_FIDO_CRED_SET_CLIENTDATA */

#جے_بنا_تعریف HAVE_FIDO_ASSERT_سیٹ_CLIENTDATA
ساكن صحيح
fido_assert_سیٹ_clientdata(fido_assert_t *أكد, ثابت u_char *ptr, ناپ_t len)
{
	uint8_t d[32];
	صحيح r;

	إذا (sha256_mem(ptr, len, d, حجم(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		أرجع FIDO_ERR_اندرونی;
	}
	r = fido_assert_سیٹ_clientdata_hash(أكد, d, حجم(d));
	explicit_bzero(d, حجم(d));
	إذا (r != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	أرجع r;
}
#جے_انت /* HAVE_FIDO_ASSERT_SET_CLIENTDATA */

#جے_بنا_تعریف HAVE_FIDO_DEV_IS_WINHELLO
ساكن bool
fido_dev_is_winhello(ثابت fido_dev_t *fdev)
{
	أرجع 0;
}
#جے_انت /* HAVE_FIDO_DEV_IS_WINHELLO */

/* Check if the specified key handle exists on a given sk. */
ساكن صحيح
sk_try(ثابت بنية sk_usbhid *sk, ثابت حرف *application,
    ثابت uint8_t *کلید_handle, ناپ_t کلید_handle_len)
{
	fido_assert_t *أكد = عدم;
	صحيح r = FIDO_ERR_اندرونی;
	uint8_t سنیہا[32];

	memset(سنیہا, '\0', حجم(سنیہا));
	إذا ((أكد = fido_assert_new()) == عدم) {
		skdebug(__func__, "fido_assert_new failed");
		اذهب باہرلا;
	}
	/* generate an invalid signature on FIDO2 tokens */
	إذا ((r = fido_assert_سیٹ_clientdata(أكد, سنیہا,
	    حجم(سنیہا))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		اذهب باہرلا;
	}
	إذا ((r = fido_assert_سیٹ_rp(أكد, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		اذهب باہرلا;
	}
	إذا ((r = fido_assert_allow_cred(أكد, کلید_handle,
	    کلید_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		اذهب باہرلا;
	}
	إذا ((r = fido_assert_سیٹ_اتے(أكد, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_up: %s", fido_strerr(r));
		اذهب باہرلا;
	}
	r = fido_dev_get_assert(sk->dev, أكد, عدم);
	skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
	إذا (r == FIDO_ERR_USER_PRESENCE_REQUIRED) {
		/* U2F tokens may return this */
		r = FIDO_OK;
	}
 باہرلا:
	fido_assert_free(&أكد);

	أرجع r != FIDO_OK ? -1 : 0;
}

ساكن صحيح
check_sk_options(fido_dev_t *dev, ثابت حرف *opt, صحيح *ret)
{
	fido_cbor_info_t *info;
	حرف * ثابت *name;
	ثابت bool *قدر;
	ناپ_t len, i;
	صحيح r;

	*ret = -1;

	إذا (!fido_dev_is_fido2(dev)) {
		skdebug(__func__, "device is not fido2");
		أرجع 0;
	}
	إذا ((info = fido_cbor_info_new()) == عدم) {
		skdebug(__func__, "fido_cbor_info_new failed");
		أرجع -1;
	}
	إذا ((r = fido_dev_get_cbor_info(dev, info)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_cbor_info: %s", fido_strerr(r));
		fido_cbor_info_free(&info);
		أرجع -1;
	}
	name = fido_cbor_info_options_name_ptr(info);
	قدر = fido_cbor_info_options_قدر_ptr(info);
	len = fido_cbor_info_options_len(info);
	لكل (i = 0; i < len; i++) {
		إذا (!strcmp(name[i], opt)) {
			*ret = قدر[i];
			اكسر;
		}
	}
	fido_cbor_info_free(&info);
	إذا (*ret == -1)
		skdebug(__func__, "option %s is unknown", opt);
	وإلا
		skdebug(__func__, "option %s is %s", opt, *ret ? "on" : "off");

	أرجع 0;
}

ساكن بنية sk_usbhid *
sk_select_by_cred(ثابت fido_dev_info_t *devlist, ناپ_t ndevs,
    ثابت حرف *application, ثابت uint8_t *کلید_handle, ناپ_t کلید_handle_len)
{
	بنية sk_usbhid **skv, *sk;
	ناپ_t skvcnt, i;
	صحيح اندرونی_uv;

	إذا ((skv = sk_openv(devlist, ndevs, &skvcnt)) == عدم) {
		skdebug(__func__, "sk_openv failed");
		أرجع عدم;
	}
	إذا (skvcnt == 1 && check_sk_options(skv[0]->dev, "uv",
	    &اندرونی_uv) == 0 && اندرونی_uv != -1) {
		sk = skv[0];
		skv[0] = عدم;
		اذهب باہرلا;
	}
	sk = عدم;
	لكل (i = 0; i < skvcnt; i++) {
		إذا (sk_try(skv[i], application, کلید_handle,
		    کلید_handle_len) == 0) {
			sk = skv[i];
			skv[i] = عدم;
			skdebug(__func__, "found key in %s", sk->رستہ);
			اكسر;
		}
	}
 باہرلا:
	sk_closev(skv, skvcnt);
	أرجع sk;
}

ساكن بنية sk_usbhid *
sk_select_by_touch(ثابت fido_dev_info_t *devlist, ناپ_t ndevs)
{
	بنية sk_usbhid **skv, *sk;
	بنية timeval tv_شروع, tv_now, tv_delta;
	ناپ_t skvcnt, idx;
	صحيح touch, ms_remain;

	إذا ((skv = sk_openv(devlist, ndevs, &skvcnt)) == عدم) {
		skdebug(__func__, "sk_openv failed");
		أرجع عدم;
	}
	sk = عدم;
	إذا (skvcnt < 2) {
		إذا (skvcnt == 1) {
			/* single candidate */
			sk = skv[0];
			skv[0] = عدم;
		}
		اذهب باہرلا;
	}
#جے_بنا_تعریف HAVE_FIDO_DEV_GET_TOUCH_حالت
	skdebug(__func__, "libfido2 version does not support a feature needed for multiple tokens. Please upgrade to >=1.5.0");
	اذهب باہرلا;
#جے_انت

	إذا (sk_touch_begin(skv, skvcnt) == -1) {
		skdebug(__func__, "sk_touch_begin failed");
		اذهب باہرلا;
	}
	monotime_tv(&tv_شروع);
	افعل {
		إذا (sk_touch_poll(skv, skvcnt, &touch, &idx) == -1) {
			skdebug(__func__, "sk_touch_poll failed");
			اذهب باہرلا;
		}
		إذا (touch) {
			sk = skv[idx];
			skv[idx] = عدم;
			اذهب باہرلا;
		}
		monotime_tv(&tv_now);
		timersub(&tv_now, &tv_شروع, &tv_delta);
		ms_remain = SELECT_MS - tv_delta.tv_sec * 1000 -
		    tv_delta.tv_usec / 1000;
	} طالما (ms_remain >= FIDO_POLL_MS);
	skdebug(__func__, "timeout");
باہرلا:
	sk_closev(skv, skvcnt);
	أرجع sk;
}

ساكن بنية sk_usbhid *
sk_probe(ثابت حرف *application, ثابت uint8_t *کلید_handle,
    ناپ_t کلید_handle_len, صحيح probe_resident)
{
	بنية sk_usbhid *sk;
	fido_dev_info_t *devlist;
	ناپ_t ndevs;
	صحيح r;

#جے_تعریف_شدہ HAVE_CYGWIN
	إذا (!probe_resident && (sk = sk_open("windows://hello")) != عدم)
		أرجع sk;
#جے_انت /* HAVE_CYGWIN */
	إذا ((devlist = fido_dev_info_new(MAX_FIDO_DEVICES)) == عدم) {
		skdebug(__func__, "fido_dev_info_new failed");
		أرجع عدم;
	}
	إذا ((r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES,
	    &ndevs)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_info_manifest failed: %s",
		    fido_strerr(r));
		fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
		أرجع عدم;
	}
	skdebug(__func__, "%zu device(s) detected", ndevs);
	إذا (ndevs == 0) {
		sk = عدم;
	} وإلا إذا (application != عدم && کلید_handle != عدم) {
		skdebug(__func__, "selecting sk by cred");
		sk = sk_select_by_cred(devlist, ndevs, application, کلید_handle,
		    کلید_handle_len);
	} وإلا {
		skdebug(__func__, "selecting sk by touch");
		sk = sk_select_by_touch(devlist, ndevs);
	}
	fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
	أرجع sk;
}

#جے_تعریف_شدہ WITH_OPENSSL
/*
 * The key returned via fido_cred_pubkey_ptr() is in affine coordinates,
 * but the API expects a SEC1 octet string.
 */
ساكن صحيح
pack_عوامی_کلید_ecdsa(ثابت fido_cred_t *cred,
    بنية sk_enroll_response *response)
{
	ثابت uint8_t *ptr;
	BIGNUM *x = عدم, *y = عدم;
	EC_نقطہ *q = عدم;
	EC_گروہ *g = عدم;
	صحيح ret = -1;

	response->عوامی_کلید = عدم;
	response->عوامی_کلید_len = 0;

	إذا ((x = BN_new()) == عدم ||
	    (y = BN_new()) == عدم ||
	    (g = EC_گروہ_new_by_ونگ_name(NID_X9_62_prime256v1)) == عدم ||
	    (q = EC_نقطہ_new(g)) == عدم) {
		skdebug(__func__, "libcrypto setup failed");
		اذهب باہرلا;
	}
	إذا ((ptr = fido_cred_pubkey_ptr(cred)) == عدم) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		اذهب باہرلا;
	}
	إذا (fido_cred_pubkey_len(cred) != 64) {
		skdebug(__func__, "bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		اذهب باہرلا;
	}

	إذا (BN_bin2bn(ptr, 32, x) == عدم ||
	    BN_bin2bn(ptr + 32, 32, y) == عدم) {
		skdebug(__func__, "BN_bin2bn failed");
		اذهب باہرلا;
	}
	إذا (EC_نقطہ_سیٹ_affine_coordinates(g, q, x, y, عدم) != 1) {
		skdebug(__func__, "EC_POINT_set_affine_coordinates failed");
		اذهب باہرلا;
	}
	response->عوامی_کلید_len = EC_نقطہ_point2oct(g, q,
	    نقطہ_CONVERSION_UNCOMPRESSED, عدم, 0, عدم);
	إذا (response->عوامی_کلید_len == 0 || response->عوامی_کلید_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->عوامی_کلید_len);
		اذهب باہرلا;
	}
	إذا ((response->عوامی_کلید = حافظہ_دیو(response->عوامی_کلید_len)) == عدم) {
		skdebug(__func__, "malloc pubkey failed");
		اذهب باہرلا;
	}
	إذا (EC_نقطہ_point2oct(g, q, نقطہ_CONVERSION_UNCOMPRESSED,
	    response->عوامی_کلید, response->عوامی_کلید_len, عدم) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		اذهب باہرلا;
	}
	/* success */
	ret = 0;
 باہرلا:
	إذا (ret != 0 && response->عوامی_کلید != عدم) {
		memset(response->عوامی_کلید, 0, response->عوامی_کلید_len);
		حرر(response->عوامی_کلید);
		response->عوامی_کلید = عدم;
	}
	EC_نقطہ_free(q);
	EC_گروہ_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	أرجع ret;
}
#جے_انت /* WITH_OPENSSL */

ساكن صحيح
pack_عوامی_کلید_ed25519(ثابت fido_cred_t *cred,
    بنية sk_enroll_response *response)
{
	ثابت uint8_t *ptr;
	ناپ_t len;
	صحيح ret = -1;

	response->عوامی_کلید = عدم;
	response->عوامی_کلید_len = 0;

	إذا ((len = fido_cred_pubkey_len(cred)) != 32) {
		skdebug(__func__, "bad fido_cred_pubkey_len len %zu", len);
		اذهب باہرلا;
	}
	إذا ((ptr = fido_cred_pubkey_ptr(cred)) == عدم) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		اذهب باہرلا;
	}
	response->عوامی_کلید_len = len;
	إذا ((response->عوامی_کلید = حافظہ_دیو(response->عوامی_کلید_len)) == عدم) {
		skdebug(__func__, "malloc pubkey failed");
		اذهب باہرلا;
	}
	حافظہ_نقل(response->عوامی_کلید, ptr, len);
	ret = 0;
 باہرلا:
	إذا (ret != 0)
		حرر(response->عوامی_کلید);
	أرجع ret;
}

ساكن صحيح
pack_عوامی_کلید(uint32_t alg, ثابت fido_cred_t *cred,
    بنية sk_enroll_response *response)
{
	بدل(alg) {
#جے_تعریف_شدہ WITH_OPENSSL
	حالة SSH_SK_ECDSA:
		أرجع pack_عوامی_کلید_ecdsa(cred, response);
#جے_انت /* WITH_OPENSSL */
	حالة SSH_SK_ED25519:
		أرجع pack_عوامی_کلید_ed25519(cred, response);
	افتراضي:
		أرجع -1;
	}
}

ساكن صحيح
fidoerr_منزل_skerr(صحيح fidoerr)
{
	بدل (fidoerr) {
	حالة FIDO_ERR_UNSUPPORTED_OPTION:
	حالة FIDO_ERR_UNSUPPORTED_ALGORITHM:
		أرجع SSH_SK_ERR_UNSUPPORTED;
	حالة FIDO_ERR_PIN_REQUIRED:
	حالة FIDO_ERR_PIN_INVALID:
	حالة FIDO_ERR_OPERATION_DENIED:
		أرجع SSH_SK_ERR_PIN_REQUIRED;
	افتراضي:
		أرجع -1;
	}
}

ساكن صحيح
check_enroll_options(بنية sk_option **options, حرف **devicep,
    uint8_t *user_id, ناپ_t user_id_len)
{
	ناپ_t i;

	إذا (options == عدم)
		أرجع 0;
	لكل (i = 0; options[i] != عدم; i++) {
		إذا (strcmp(options[i]->name, "device") == 0) {
			إذا ((*devicep = strdup(options[i]->قدر)) == عدم) {
				skdebug(__func__, "strdup device failed");
				أرجع -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} وإلا إذا (strcmp(options[i]->name, "user") == 0) {
			إذا (strlcpy(user_id, options[i]->قدر, user_id_len) >=
			    user_id_len) {
				skdebug(__func__, "user too long");
				أرجع -1;
			}
			skdebug(__func__, "requested user %s",
			    (حرف *)user_id);
		} وإلا {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			إذا (options[i]->required) {
				skdebug(__func__, "unknown required option");
				أرجع -1;
			}
		}
	}
	أرجع 0;
}

ساكن صحيح
کلید_lookup(fido_dev_t *dev, ثابت حرف *application, ثابت uint8_t *user_id,
    ناپ_t user_id_len, ثابت حرف *pin)
{
	fido_assert_t *أكد = عدم;
	uint8_t سنیہا[32];
	صحيح r = FIDO_ERR_اندرونی;
	صحيح sk_supports_uv, uv;
	ناپ_t i;

	memset(سنیہا, '\0', حجم(سنیہا));
	إذا ((أكد = fido_assert_new()) == عدم) {
		skdebug(__func__, "fido_assert_new failed");
		اذهب باہرلا;
	}
	/* generate an invalid signature on FIDO2 tokens */
	إذا ((r = fido_assert_سیٹ_clientdata(أكد, سنیہا,
	    حجم(سنیہا))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		اذهب باہرلا;
	}
	إذا ((r = fido_assert_سیٹ_rp(أكد, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		اذهب باہرلا;
	}
	إذا ((r = fido_assert_سیٹ_اتے(أكد, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		اذهب باہرلا;
	}
	uv = FIDO_OPT_OMIT;
	إذا (pin == عدم && check_sk_options(dev, "uv", &sk_supports_uv) == 0 &&
	    sk_supports_uv != -1)
		uv = FIDO_OPT_TRUE;
	إذا ((r = fido_assert_سیٹ_uv(أكد, uv)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
		اذهب باہرلا;
	}
	إذا ((r = fido_dev_get_assert(dev, أكد, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		اذهب باہرلا;
	}
	r = FIDO_ERR_NO_CREDENTIALS;
	skdebug(__func__, "%zu signatures returned", fido_assert_گنتی(أكد));
	لكل (i = 0; i < fido_assert_گنتی(أكد); i++) {
		إذا (fido_assert_user_id_len(أكد, i) == user_id_len &&
		    memcmp(fido_assert_user_id_ptr(أكد, i), user_id,
		    user_id_len) == 0) {
			skdebug(__func__, "credential exists");
			r = FIDO_OK;
			اذهب باہرلا;
		}
	}
 باہرلا:
	fido_assert_free(&أكد);

	أرجع r;
}

صحيح
sk_enroll(uint32_t alg, ثابت uint8_t *challenge, ناپ_t challenge_len,
    ثابت حرف *application, uint8_t flags, ثابت حرف *pin,
    بنية sk_option **options, بنية sk_enroll_response **enroll_response)
{
	fido_cred_t *cred = عدم;
	ثابت uint8_t *ptr;
	uint8_t user_id[32];
	بنية sk_usbhid *sk = عدم;
	بنية sk_enroll_response *response = عدم;
	ناپ_t len;
	صحيح credprot;
	صحيح cose_alg;
	صحيح ret = SSH_SK_ERR_GENERAL;
	صحيح r;
	حرف *device = عدم;

	fido_init(SSH_FIDO_INIT_ARG);

	إذا (enroll_response == عدم) {
		skdebug(__func__, "enroll_response == NULL");
		اذهب باہرلا;
	}
	*enroll_response = عدم;
	memset(user_id, 0, حجم(user_id));
	إذا (check_enroll_options(options, &device, user_id,
	    حجم(user_id)) != 0)
		اذهب باہرلا; /* error already logged */

	بدل(alg) {
#جے_تعریف_شدہ WITH_OPENSSL
	حالة SSH_SK_ECDSA:
		cose_alg = COSE_ES256;
		اكسر;
#جے_انت /* WITH_OPENSSL */
	حالة SSH_SK_ED25519:
		cose_alg = COSE_EDDSA;
		اكسر;
	افتراضي:
		skdebug(__func__, "unsupported key type %d", alg);
		اذهب باہرلا;
	}
	إذا (device != عدم)
		sk = sk_open(device);
	وإلا
		sk = sk_probe(عدم, عدم, 0, 0);
	إذا (sk == عدم) {
		ret = SSH_SK_ERR_DEVICE_NOT_لبھیا;
		skdebug(__func__, "failed to find sk");
		اذهب باہرلا;
	}
	skdebug(__func__, "using device %s", sk->رستہ);
	إذا ((flags & SSH_SK_RESIDENT_کلید) != 0 &&
	    (flags & SSH_SK_FORCE_OPERATION) == 0 &&
	    (r = کلید_lookup(sk->dev, application, user_id, حجم(user_id),
	    pin)) != FIDO_ERR_NO_CREDENTIALS) {
		إذا (r != FIDO_OK) {
			ret = fidoerr_منزل_skerr(r);
			skdebug(__func__, "key_lookup failed");
		} وإلا {
			ret = SSH_SK_ERR_CREDENTIAL_EXISTS;
			skdebug(__func__, "key exists");
		}
		اذهب باہرلا;
	}
	إذا ((cred = fido_cred_new()) == عدم) {
		skdebug(__func__, "fido_cred_new failed");
		اذهب باہرلا;
	}
	إذا ((r = fido_cred_سیٹ_type(cred, cose_alg)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_type: %s", fido_strerr(r));
		اذهب باہرلا;
	}
	إذا ((r = fido_cred_سیٹ_clientdata(cred,
	    challenge, challenge_len)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata: %s",
		    fido_strerr(r));
		اذهب باہرلا;
	}
	إذا ((r = fido_cred_سیٹ_rk(cred, (flags & SSH_SK_RESIDENT_کلید) != 0 ?
	    FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rk: %s", fido_strerr(r));
		اذهب باہرلا;
	}
	إذا ((r = fido_cred_سیٹ_user(cred, user_id, حجم(user_id),
	    "openssh", "openssh", عدم)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_user: %s", fido_strerr(r));
		اذهب باہرلا;
	}
	إذا ((r = fido_cred_سیٹ_rp(cred, application, عدم)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rp: %s", fido_strerr(r));
		اذهب باہرلا;
	}
	إذا ((flags & (SSH_SK_RESIDENT_کلید|SSH_SK_USER_VERIFICATION_REQD)) != 0) {
#إذا !defined(HAVE_FIDO_DEV_SUPPORTS_CRED_PROT) || \
    !defined(HAVE_FIDO_CRED_سیٹ_PROT)
		skdebug(__func__, "libfido2 version does not support a feature required for this operation. Please upgrade to >=1.5.0");
		ret = SSH_SK_ERR_UNSUPPORTED;
		اذهب باہرلا;
		credprot = 0; (فراغ)credprot; /* avoid warning */
#جے_انت
		إذا (!fido_dev_supports_cred_prot(sk->dev)) {
			skdebug(__func__, "%s does not support credprot, "
			    "refusing to create unprotected "
			    "resident/verify-required key", sk->رستہ);
			ret = SSH_SK_ERR_UNSUPPORTED;
			اذهب باہرلا;
		}
		إذا ((flags & SSH_SK_USER_VERIFICATION_REQD))
			credprot = FIDO_CRED_PROT_UV_REQUIRED;
		وإلا
			credprot = FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID;

		إذا ((r = fido_cred_سیٹ_prot(cred, credprot)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_set_prot: %s",
			    fido_strerr(r));
			ret = fidoerr_منزل_skerr(r);
			اذهب باہرلا;
		}
	}
	إذا ((r = fido_dev_make_cred(sk->dev, cred, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_make_cred: %s", fido_strerr(r));
		ret = fidoerr_منزل_skerr(r);
		اذهب باہرلا;
	}
	إذا (fido_cred_x5c_ptr(cred) != عدم) {
		إذا ((r = fido_cred_verify(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify: %s",
			    fido_strerr(r));
			اذهب باہرلا;
		}
	} وإلا إذا (strcmp(fido_cred_fmt(cred), "none") != 0) {
		skdebug(__func__, "self-attested credential");
		إذا ((r = fido_cred_verify_self(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify_self: %s",
			    fido_strerr(r));
			اذهب باہرلا;
		}
	} وإلا {
		skdebug(__func__, "no attestation data");
	}
	إذا ((response = صفر_حافظہ_دیو(1, حجم(*response))) == عدم) {
		skdebug(__func__, "calloc response failed");
		اذهب باہرلا;
	}
	response->flags = flags;
	إذا (pack_عوامی_کلید(alg, cred, response) != 0) {
		skdebug(__func__, "pack_public_key failed");
		اذهب باہرلا;
	}
	إذا ((ptr = fido_cred_id_ptr(cred)) != عدم) {
		len = fido_cred_id_len(cred);
		إذا ((response->کلید_handle = صفر_حافظہ_دیو(1, len)) == عدم) {
			skdebug(__func__, "calloc key handle failed");
			اذهب باہرلا;
		}
		حافظہ_نقل(response->کلید_handle, ptr, len);
		response->کلید_handle_len = len;
	}
	إذا ((ptr = fido_cred_sig_ptr(cred)) != عدم) {
		len = fido_cred_sig_len(cred);
		إذا ((response->signature = صفر_حافظہ_دیو(1, len)) == عدم) {
			skdebug(__func__, "calloc signature failed");
			اذهب باہرلا;
		}
		حافظہ_نقل(response->signature, ptr, len);
		response->signature_len = len;
	}
	إذا ((ptr = fido_cred_x5c_ptr(cred)) != عدم) {
		len = fido_cred_x5c_len(cred);
		skdebug(__func__, "attestation cert len=%zu", len);
		إذا ((response->attestation_cert = صفر_حافظہ_دیو(1, len)) == عدم) {
			skdebug(__func__, "calloc attestation cert failed");
			اذهب باہرلا;
		}
		حافظہ_نقل(response->attestation_cert, ptr, len);
		response->attestation_cert_len = len;
	}
	إذا ((ptr = fido_cred_authdata_ptr(cred)) != عدم) {
		len = fido_cred_authdata_len(cred);
		skdebug(__func__, "authdata len=%zu", len);
		إذا ((response->authdata = صفر_حافظہ_دیو(1, len)) == عدم) {
			skdebug(__func__, "calloc authdata failed");
			اذهب باہرلا;
		}
		حافظہ_نقل(response->authdata, ptr, len);
		response->authdata_len = len;
	}
	*enroll_response = response;
	response = عدم;
	ret = 0;
 باہرلا:
	حرر(device);
	إذا (response != عدم) {
		حرر(response->عوامی_کلید);
		حرر(response->کلید_handle);
		حرر(response->signature);
		حرر(response->attestation_cert);
		حرر(response->authdata);
		حرر(response);
	}
	sk_close(sk);
	fido_cred_free(&cred);
	أرجع ret;
}

#جے_تعریف_شدہ WITH_OPENSSL
ساكن صحيح
pack_sig_ecdsa(fido_assert_t *أكد, بنية sk_sign_response *response)
{
	ECDSA_SIG *sig = عدم;
	ثابت BIGNUM *sig_r, *sig_s;
	ثابت بنانشانی حرف *cp;
	ناپ_t sig_len;
	صحيح ret = -1;

	cp = fido_assert_sig_ptr(أكد, 0);
	sig_len = fido_assert_sig_len(أكد, 0);
	إذا ((sig = d2i_ECDSA_SIG(عدم, &cp, sig_len)) == عدم) {
		skdebug(__func__, "d2i_ECDSA_SIG failed");
		اذهب باہرلا;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_عدد_بائٹاں(sig_r);
	response->sig_s_len = BN_عدد_بائٹاں(sig_s);
	إذا ((response->sig_r = صفر_حافظہ_دیو(1, response->sig_r_len)) == عدم ||
	    (response->sig_s = صفر_حافظہ_دیو(1, response->sig_s_len)) == عدم) {
		skdebug(__func__, "calloc signature failed");
		اذهب باہرلا;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 باہرلا:
	ECDSA_SIG_free(sig);
	إذا (ret != 0) {
		حرر(response->sig_r);
		حرر(response->sig_s);
		response->sig_r = عدم;
		response->sig_s = عدم;
	}
	أرجع ret;
}
#جے_انت /* WITH_OPENSSL */

ساكن صحيح
pack_sig_ed25519(fido_assert_t *أكد, بنية sk_sign_response *response)
{
	ثابت بنانشانی حرف *ptr;
	ناپ_t len;
	صحيح ret = -1;

	ptr = fido_assert_sig_ptr(أكد, 0);
	len = fido_assert_sig_len(أكد, 0);
	إذا (len != 64) {
		skdebug(__func__, "bad length %zu", len);
		اذهب باہرلا;
	}
	response->sig_r_len = len;
	إذا ((response->sig_r = صفر_حافظہ_دیو(1, response->sig_r_len)) == عدم) {
		skdebug(__func__, "calloc signature failed");
		اذهب باہرلا;
	}
	حافظہ_نقل(response->sig_r, ptr, len);
	ret = 0;
 باہرلا:
	إذا (ret != 0) {
		حرر(response->sig_r);
		response->sig_r = عدم;
	}
	أرجع ret;
}

ساكن صحيح
pack_sig(uint32_t  alg, fido_assert_t *أكد,
    بنية sk_sign_response *response)
{
	بدل(alg) {
#جے_تعریف_شدہ WITH_OPENSSL
	حالة SSH_SK_ECDSA:
		أرجع pack_sig_ecdsa(أكد, response);
#جے_انت /* WITH_OPENSSL */
	حالة SSH_SK_ED25519:
		أرجع pack_sig_ed25519(أكد, response);
	افتراضي:
		أرجع -1;
	}
}

/* Checks sk_options for sk_sign() and sk_load_resident_keys() */
ساكن صحيح
check_sign_لدو_resident_options(بنية sk_option **options, حرف **devicep)
{
	ناپ_t i;

	إذا (options == عدم)
		أرجع 0;
	لكل (i = 0; options[i] != عدم; i++) {
		إذا (strcmp(options[i]->name, "device") == 0) {
			إذا ((*devicep = strdup(options[i]->قدر)) == عدم) {
				skdebug(__func__, "strdup device failed");
				أرجع -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} وإلا {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			إذا (options[i]->required) {
				skdebug(__func__, "unknown required option");
				أرجع -1;
			}
		}
	}
	أرجع 0;
}

صحيح
sk_sign(uint32_t alg, ثابت uint8_t *انکڑے, ناپ_t datalen,
    ثابت حرف *application,
    ثابت uint8_t *کلید_handle, ناپ_t کلید_handle_len,
    uint8_t flags, ثابت حرف *pin, بنية sk_option **options,
    بنية sk_sign_response **sign_response)
{
	fido_assert_t *أكد = عدم;
	حرف *device = عدم;
	بنية sk_usbhid *sk = عدم;
	بنية sk_sign_response *response = عدم;
	صحيح ret = SSH_SK_ERR_GENERAL, اندرونی_uv;
	صحيح r;

	fido_init(SSH_FIDO_INIT_ARG);

	إذا (sign_response == عدم) {
		skdebug(__func__, "sign_response == NULL");
		اذهب باہرلا;
	}
	*sign_response = عدم;
	إذا (check_sign_لدو_resident_options(options, &device) != 0)
		اذهب باہرلا; /* error already logged */
	إذا (device != عدم)
		sk = sk_open(device);
	وإلا إذا (pin != عدم || (flags & SSH_SK_USER_VERIFICATION_REQD))
		sk = sk_probe(عدم, عدم, 0, 0);
	وإلا
		sk = sk_probe(application, کلید_handle, کلید_handle_len, 0);
	إذا (sk == عدم) {
		ret = SSH_SK_ERR_DEVICE_NOT_لبھیا;
		skdebug(__func__, "failed to find sk");
		اذهب باہرلا;
	}
	إذا ((أكد = fido_assert_new()) == عدم) {
		skdebug(__func__, "fido_assert_new failed");
		اذهب باہرلا;
	}
	إذا ((r = fido_assert_سیٹ_clientdata(أكد,
	    انکڑے, datalen)) != FIDO_OK)  {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		اذهب باہرلا;
	}
	إذا ((r = fido_assert_سیٹ_rp(أكد, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		اذهب باہرلا;
	}
	إذا ((r = fido_assert_allow_cred(أكد, کلید_handle,
	    کلید_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		اذهب باہرلا;
	}
	إذا ((r = fido_assert_سیٹ_اتے(أكد,
	    (flags & SSH_SK_USER_PRESENCE_REQD) ?
	    FIDO_OPT_TRUE : FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		اذهب باہرلا;
	}
	/*
	 * WinHello requests the PIN by default.  Make "uv" request explicit
	 * to allow keys with and without -O verify-required to make sense.
	 */
	إذا (pin == عدم && fido_dev_is_winhello (sk->dev) &&
	    (r = fido_assert_سیٹ_uv(أكد, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
	}
	إذا (pin == عدم && (flags & SSH_SK_USER_VERIFICATION_REQD)) {
		إذا (check_sk_options(sk->dev, "uv", &اندرونی_uv) < 0 ||
		    اندرونی_uv != 1) {
			skdebug(__func__, "check_sk_options uv");
			ret = SSH_SK_ERR_PIN_REQUIRED;
			اذهب باہرلا;
		}
		إذا ((r = fido_assert_سیٹ_uv(أكد,
		    FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_assert_set_uv: %s",
			    fido_strerr(r));
			ret = fidoerr_منزل_skerr(r);
			اذهب باہرلا;
		}
	}
	إذا ((r = fido_dev_get_assert(sk->dev, أكد, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ret = fidoerr_منزل_skerr(r);
		اذهب باہرلا;
	}
	إذا ((response = صفر_حافظہ_دیو(1, حجم(*response))) == عدم) {
		skdebug(__func__, "calloc response failed");
		اذهب باہرلا;
	}
	response->flags = fido_assert_flags(أكد, 0);
	response->counter = fido_assert_sigcount(أكد, 0);
	إذا (pack_sig(alg, أكد, response) != 0) {
		skdebug(__func__, "pack_sig failed");
		اذهب باہرلا;
	}
	*sign_response = response;
	response = عدم;
	ret = 0;
 باہرلا:
	حرر(device);
	إذا (response != عدم) {
		حرر(response->sig_r);
		حرر(response->sig_s);
		حرر(response);
	}
	sk_close(sk);
	fido_assert_free(&أكد);
	أرجع ret;
}

ساكن صحيح
read_rks(بنية sk_usbhid *sk, ثابت حرف *pin,
    بنية sk_resident_کلید ***rksp, ناپ_t *nrksp)
{
	صحيح ret = SSH_SK_ERR_GENERAL, r = -1;
	uint32_t alg;
	fido_credman_metadata_t *metadata = عدم;
	fido_credman_rp_t *rp = عدم;
	fido_credman_rk_t *rk = عدم;
	ناپ_t i, j, nrp, nrk, user_id_len;
	ثابت fido_cred_t *cred;
	ثابت حرف *rp_id, *rp_name, *user_name;
	بنية sk_resident_کلید *srk = عدم, **tmp;
	ثابت u_char *user_id;

	إذا (pin == عدم) {
		skdebug(__func__, "no PIN specified");
		ret = SSH_SK_ERR_PIN_REQUIRED;
		اذهب باہرلا;
	}
	إذا ((metadata = fido_credman_metadata_new()) == عدم) {
		skdebug(__func__, "alloc failed");
		اذهب باہرلا;
	}
	إذا ((r = fido_credman_get_dev_metadata(sk->dev, metadata, pin)) != 0) {
		إذا (r == FIDO_ERR_INVALID_COMMAND) {
			skdebug(__func__, "device %s does not support "
			    "resident keys", sk->رستہ);
			ret = 0;
			اذهب باہرلا;
		}
		skdebug(__func__, "get metadata for %s failed: %s",
		    sk->رستہ, fido_strerr(r));
		ret = fidoerr_منزل_skerr(r);
		اذهب باہرلا;
	}
	skdebug(__func__, "existing %llu, remaining %llu",
	    (بنانشانی لما لما)fido_credman_rk_existing(metadata),
	    (بنانشانی لما لما)fido_credman_rk_بچیا(metadata));
	إذا ((rp = fido_credman_rp_new()) == عدم) {
		skdebug(__func__, "alloc rp failed");
		اذهب باہرلا;
	}
	إذا ((r = fido_credman_get_dev_rp(sk->dev, rp, pin)) != 0) {
		skdebug(__func__, "get RPs for %s failed: %s",
		    sk->رستہ, fido_strerr(r));
		اذهب باہرلا;
	}
	nrp = fido_credman_rp_گنتی(rp);
	skdebug(__func__, "Device %s has resident keys for %zu RPs",
	    sk->رستہ, nrp);

	/* Iterate over RP IDs that have resident keys */
	لكل (i = 0; i < nrp; i++) {
		rp_id = fido_credman_rp_id(rp, i);
		rp_name = fido_credman_rp_name(rp, i);
		skdebug(__func__, "rp %zu: name=\"%s\" id=\"%s\" hashlen=%zu",
		    i, rp_name == عدم ? "(none)" : rp_name,
		    rp_id == عدم ? "(none)" : rp_id,
		    fido_credman_rp_id_hash_len(rp, i));

		/* Skip non-SSH RP IDs */
		إذا (rp_id == عدم ||
		    strncasecmp(fido_credman_rp_id(rp, i), "ssh:", 4) != 0)
			استمر;

		fido_credman_rk_free(&rk);
		إذا ((rk = fido_credman_rk_new()) == عدم) {
			skdebug(__func__, "alloc rk failed");
			اذهب باہرلا;
		}
		إذا ((r = fido_credman_get_dev_rk(sk->dev,
		    fido_credman_rp_id(rp, i), rk, pin)) != 0) {
			skdebug(__func__, "get RKs for %s slot %zu failed: %s",
			    sk->رستہ, i, fido_strerr(r));
			اذهب باہرلا;
		}
		nrk = fido_credman_rk_گنتی(rk);
		skdebug(__func__, "RP \"%s\" has %zu resident keys",
		    fido_credman_rp_id(rp, i), nrk);

		/* Iterate over resident keys for this RP ID */
		لكل (j = 0; j < nrk; j++) {
			إذا ((cred = fido_credman_rk(rk, j)) == عدم) {
				skdebug(__func__, "no RK in slot %zu", j);
				استمر;
			}
			إذا ((user_name = fido_cred_user_name(cred)) == عدم)
				user_name = "";
			user_id = fido_cred_user_id_ptr(cred);
			user_id_len = fido_cred_user_id_len(cred);
			skdebug(__func__, "Device %s RP \"%s\" user \"%s\" "
			    "uidlen %zu slot %zu: type %d flags 0x%02x "
			    "prot 0x%02x", sk->رستہ, rp_id, user_name,
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
			إذا ((srk = صفر_حافظہ_دیو(1, حجم(*srk))) == عدم ||
			    (srk->کلید.کلید_handle = صفر_حافظہ_دیو(1,
			    fido_cred_id_len(cred))) == عدم ||
			    (srk->application = strdup(rp_id)) == عدم ||
			    (user_id_len > 0 &&
			     (srk->user_id = صفر_حافظہ_دیو(1, user_id_len)) == عدم)) {
				skdebug(__func__, "alloc sk_resident_key");
				اذهب باہرلا;
			}

			srk->alg = alg;
			srk->کلید.کلید_handle_len = fido_cred_id_len(cred);
			حافظہ_نقل(srk->کلید.کلید_handle, fido_cred_id_ptr(cred),
			    srk->کلید.کلید_handle_len);
			srk->user_id_len = user_id_len;
			إذا (srk->user_id_len != 0)
				حافظہ_نقل(srk->user_id, user_id, srk->user_id_len);

#جے_تعریف_شدہ HAVE_FIDO_CRED_PROT
			إذا (fido_cred_prot(cred) ==
			    FIDO_CRED_PROT_UV_REQUIRED)
				srk->flags |=  SSH_SK_USER_VERIFICATION_REQD;
#جے_انت

			إذا ((r = pack_عوامی_کلید(srk->alg, cred,
			    &srk->کلید)) != 0) {
				skdebug(__func__, "pack public key failed");
				اذهب باہرلا;
			}
			/* append */
			إذا ((tmp = recallocarray(*rksp, *nrksp, (*nrksp) + 1,
			    حجم(**rksp))) == عدم) {
				skdebug(__func__, "alloc rksp");
				اذهب باہرلا;
			}
			*rksp = tmp;
			(*rksp)[(*nrksp)++] = srk;
			srk = عدم;
		}
	}
	/* Success */
	ret = 0;
 باہرلا:
	إذا (srk != عدم) {
		حرر(srk->application);
		freezero(srk->کلید.عوامی_کلید, srk->کلید.عوامی_کلید_len);
		freezero(srk->کلید.کلید_handle, srk->کلید.کلید_handle_len);
		freezero(srk->user_id, srk->user_id_len);
		freezero(srk, حجم(*srk));
	}
	fido_credman_rp_free(&rp);
	fido_credman_rk_free(&rk);
	fido_credman_metadata_free(&metadata);
	أرجع ret;
}

صحيح
sk_لدو_resident_کلیدیں(ثابت حرف *pin, بنية sk_option **options,
    بنية sk_resident_کلید ***rksp, ناپ_t *nrksp)
{
	صحيح ret = SSH_SK_ERR_GENERAL, r = -1;
	ناپ_t i, nrks = 0;
	بنية sk_resident_کلید **rks = عدم;
	بنية sk_usbhid *sk = عدم;
	حرف *device = عدم;

	*rksp = عدم;
	*nrksp = 0;

	fido_init(SSH_FIDO_INIT_ARG);

	إذا (check_sign_لدو_resident_options(options, &device) != 0)
		اذهب باہرلا; /* error already logged */
	إذا (device != عدم)
		sk = sk_open(device);
	وإلا
		sk = sk_probe(عدم, عدم, 0, 1);
	إذا (sk == عدم) {
		ret = SSH_SK_ERR_DEVICE_NOT_لبھیا;
		skdebug(__func__, "failed to find sk");
		اذهب باہرلا;
	}
	skdebug(__func__, "trying %s", sk->رستہ);
	إذا ((r = read_rks(sk, pin, &rks, &nrks)) != 0) {
		skdebug(__func__, "read_rks failed for %s", sk->رستہ);
		ret = r;
		اذهب باہرلا;
	}
	/* success, unless we have no keys but a specific error */
	إذا (nrks > 0 || ret == SSH_SK_ERR_GENERAL)
		ret = 0;
	*rksp = rks;
	*nrksp = nrks;
	rks = عدم;
	nrks = 0;
 باہرلا:
	sk_close(sk);
	لكل (i = 0; i < nrks; i++) {
		حرر(rks[i]->application);
		freezero(rks[i]->کلید.عوامی_کلید, rks[i]->کلید.عوامی_کلید_len);
		freezero(rks[i]->کلید.کلید_handle, rks[i]->کلید.کلید_handle_len);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i], حجم(*rks[i]));
	}
	حرر(device);
	حرر(rks);
	أرجع ret;
}

#جے_انت /* ENABLE_SK_INTERNAL */
