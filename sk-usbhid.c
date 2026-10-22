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

#اگر_تعریف_شدہ ENABLE_SK_اندرونی

#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <stdio.h>
#شامل <stddef.h>
#شامل <stdarg.h>
#شامل <time.h>
#اگر_تعریف_شدہ HAVE_SHA2_H
#شامل <sha2.h>
#اگر_ختم

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/opensslv.h>
#شامل <openssl/crypto.h>
#شامل <openssl/bn.h>
#شامل <openssl/ec.h>
#شامل <openssl/ecdsa.h>
#شامل <openssl/evp.h>
#شامل "openbsd-compat/openssl-compat.h"
#اگر_ختم /* WITH_OPENSSL */

#شامل <fido.h>
#شامل <fido/credman.h>

/* backwards compat for libfido2 */
#اگر_غیر_تعریف_شدہ HAVE_FIDO_CRED_PROT
#تعریف_کرو fido_cred_prot(x) (0)
#اگر_ختم
#اگر_غیر_تعریف_شدہ HAVE_FIDO_CRED_سیٹ_PROT
#تعریف_کرو fido_cred_سیٹ_prot(x, y) (FIDO_ERR_UNSUPPORTED_OPTION)
#اگر_ختم
#اگر_غیر_تعریف_شدہ HAVE_FIDO_DEV_SUPPORTS_CRED_PROT
#تعریف_کرو fido_dev_supports_cred_prot(x) (0)
#اگر_ختم
#اگر_غیر_تعریف_شدہ HAVE_FIDO_DEV_GET_TOUCH_BEGIN
#تعریف_کرو fido_dev_get_touch_begin(x) (FIDO_ERR_UNSUPPORTED_OPTION)
#اگر_ختم
#اگر_غیر_تعریف_شدہ HAVE_FIDO_DEV_GET_TOUCH_حالت
#تعریف_کرو fido_dev_get_touch_حالت(x, y, z) (FIDO_ERR_UNSUPPORTED_OPTION)
#اگر_ختم
#اگر_غیر_تعریف_شدہ FIDO_CRED_PROT_UV_REQUIRED
#تعریف_کرو FIDO_CRED_PROT_UV_REQUIRED 0
#اگر_ختم
#اگر_غیر_تعریف_شدہ FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID
#تعریف_کرو FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID 0
#اگر_ختم

# include "misc.h"

#اگر_غیر_تعریف_شدہ SK_STANDALONE
# include "log.h"
# include "xmalloc.h"
/*
 * If building as part of OpenSSH, then rename exported functions.
 * This must be done before including sk-api.h.
 */
# define sk_api_نسخہ		ssh_sk_api_نسخہ
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_بھرو_resident_کلیدیں	ssh_sk_بھرو_resident_کلیدیں
#اگر_ختم /* !SK_STANDALONE */

#شامل "sk-api.h"

/* #define SK_DEBUG 1 */

#اگر_تعریف_شدہ SK_DEBUG
#تعریف_کرو SSH_FIDO_INIT_ARG	FIDO_DEBUG
#ورنہ
#تعریف_کرو SSH_FIDO_INIT_ARG	0
#اگر_ختم

#تعریف_کرو MAX_FIDO_DEVICES	8
#تعریف_کرو FIDO_POLL_MS		50
#تعریف_کرو SELECT_MS		15000
#تعریف_کرو POLL_SLEEP_NS		200000000

#اگر_غیر_تعریف_شدہ FIDO_ERR_OPERATION_DENIED
#تعریف_کرو FIDO_ERR_OPERATION_DENIED 0x27
#اگر_ختم

ساخت sk_usbhid {
	fido_dev_t *dev;
	حرف *راستہ;
};

/* Return the version of the middleware API */
uint32_t sk_api_نسخہ(خالی);

/* Enroll a U2F key (private key generation) */
صحیح sk_enroll(uint32_t alg, ثابت uint8_t *challenge, سائز_t challenge_len,
    ثابت حرف *application, uint8_t flags, ثابت حرف *pin,
    ساخت sk_option **options, ساخت sk_enroll_response **enroll_response);

/* Sign a challenge */
صحیح sk_sign(uint32_t alg, ثابت uint8_t *ڈیٹا, سائز_t ڈیٹا_len,
    ثابت حرف *application, ثابت uint8_t *کلید_handle, سائز_t کلید_handle_len,
    uint8_t flags, ثابت حرف *pin, ساخت sk_option **options,
    ساخت sk_sign_response **sign_response);

/* Load resident keys */
صحیح sk_بھرو_resident_کلیدیں(ثابت حرف *pin, ساخت sk_option **options,
    ساخت sk_resident_کلید ***rks, سائز_t *nrks);

ساکن خالی skdebug(ثابت حرف *func, ثابت حرف *fmt, ...)
    __attribute__((__format__ (لکھو, 2, 3)));

ساکن خالی
skdebug(ثابت حرف *func, ثابت حرف *fmt, ...)
{
#اگر !defined(SK_STANDALONE)
	حرف *پیغام;
	va_list ap;

	va_start(ap, fmt);
	xvasprintf(&پیغام, fmt, ap);
	va_end(ap);
	debug("%s: %s", func, پیغام);
	آزاد(پیغام);
#وگرنہ_اگر defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#ورنہ
	(خالی)func; /* XXX */
	(خالی)fmt; /* XXX */
#اگر_ختم
}

uint32_t
sk_api_نسخہ(خالی)
{
	واپس SSH_SK_نسخہ_MAJOR;
}

ساکن ساخت sk_usbhid *
sk_open(ثابت حرف *راستہ)
{
	ساخت sk_usbhid *sk;
	صحیح r;

	اگر (راستہ == تہی) {
		skdebug(__func__, "path == NULL");
		واپس تہی;
	}
	اگر ((sk = صفر_حافظہ_دو(1, حجم(*sk))) == تہی) {
		skdebug(__func__, "calloc sk failed");
		واپس تہی;
	}
	اگر ((sk->راستہ = strdup(راستہ)) == تہی) {
		skdebug(__func__, "strdup path failed");
		آزاد(sk);
		واپس تہی;
	}
	اگر ((sk->dev = fido_dev_new()) == تہی) {
		skdebug(__func__, "fido_dev_new failed");
		آزاد(sk->راستہ);
		آزاد(sk);
		واپس تہی;
	}
	اگر ((r = fido_dev_open(sk->dev, sk->راستہ)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_open %s failed: %s", sk->راستہ,
		    fido_strerr(r));
		fido_dev_free(&sk->dev);
		آزاد(sk->راستہ);
		آزاد(sk);
		واپس تہی;
	}
	واپس sk;
}

ساکن خالی
sk_close(ساخت sk_usbhid *sk)
{
	اگر (sk == تہی)
		واپس;
	fido_dev_cancel(sk->dev); /* cancel any pending operation */
	fido_dev_close(sk->dev);
	fido_dev_free(&sk->dev);
	آزاد(sk->راستہ);
	آزاد(sk);
}

ساکن ساخت sk_usbhid **
sk_openv(ثابت fido_dev_info_t *devlist, سائز_t ndevs, سائز_t *nopen)
{
	ثابت fido_dev_info_t *di;
	ساخت sk_usbhid **skv;
	سائز_t i;

	*nopen = 0;
	اگر ((skv = صفر_حافظہ_دو(ndevs, حجم(*skv))) == تہی) {
		skdebug(__func__, "calloc skv failed");
		واپس تہی;
	}
	برائے (i = 0; i < ndevs; i++) {
		اگر ((di = fido_dev_info_ptr(devlist, i)) == تہی)
			skdebug(__func__, "fido_dev_info_ptr failed");
		ورنہ اگر ((skv[*nopen] = sk_open(fido_dev_info_راستہ(di))) == تہی)
			skdebug(__func__, "sk_open failed");
		ورنہ
			(*nopen)++;
	}
	اگر (*nopen == 0) {
		برائے (i = 0; i < ndevs; i++)
			sk_close(skv[i]);
		آزاد(skv);
		skv = تہی;
	}

	واپس skv;
}

ساکن خالی
sk_closev(ساخت sk_usbhid **skv, سائز_t nsk)
{
	سائز_t i;

	برائے (i = 0; i < nsk; i++)
		sk_close(skv[i]);
	آزاد(skv);
}

ساکن صحیح
sk_touch_begin(ساخت sk_usbhid **skv, سائز_t nsk)
{
	سائز_t i, ok = 0;
	صحیح r;

	برائے (i = 0; i < nsk; i++)
		اگر ((r = fido_dev_get_touch_begin(skv[i]->dev)) != FIDO_OK)
			skdebug(__func__, "fido_dev_get_touch_begin %s failed:"
			    " %s", skv[i]->راستہ, fido_strerr(r));
		ورنہ
			ok++;

	واپس ok ? 0 : -1;
}

ساکن صحیح
sk_touch_poll(ساخت sk_usbhid **skv, سائز_t nsk, صحیح *touch, سائز_t *idx)
{
	ساخت timespec ts_pause;
	سائز_t npoll, i;
	صحیح r;

	ts_pause.tv_sec = 0;
	ts_pause.tv_nsec = POLL_SLEEP_NS;
	nanosleep(&ts_pause, تہی);
	npoll = nsk;
	برائے (i = 0; i < nsk; i++) {
		اگر (skv[i] == تہی)
			جاری; /* device discarded */
		skdebug(__func__, "polling %s", skv[i]->راستہ);
		اگر ((r = fido_dev_get_touch_حالت(skv[i]->dev, touch,
		    FIDO_POLL_MS)) != FIDO_OK) {
			skdebug(__func__, "fido_dev_get_touch_status %s: %s",
			    skv[i]->راستہ, fido_strerr(r));
			sk_close(skv[i]); /* discard device */
			skv[i] = تہی;
			اگر (--npoll == 0) {
				skdebug(__func__, "no device left to poll");
				واپس -1;
			}
		} ورنہ اگر (*touch) {
			*idx = i;
			واپس 0;
		}
	}
	*touch = 0;
	واپس 0;
}

#اگر !defined(HAVE_FIDO_ASSERT_سیٹ_CLIENTDATA) || \
    !defined(HAVE_FIDO_CRED_سیٹ_CLIENTDATA)
/* Calculate SHA256(m) */
ساکن صحیح
sha256_mem(ثابت خالی *m, سائز_t mlen, u_char *d, سائز_t dlen)
{
#اگر_تعریف_شدہ WITH_OPENSSL
	u_int mdlen;
#ورنہ
	SHA2_CTX ctx;
#اگر_ختم

	اگر (dlen != 32)
		واپس -1;
#اگر_تعریف_شدہ WITH_OPENSSL
	mdlen = dlen;
	اگر (!EVP_Digest(m, mlen, d, &mdlen, EVP_sha256(), تہی))
		واپس -1;
#ورنہ
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ثابت uint8_t *)m, mlen);
	SHA256Final(d, &ctx);
#اگر_ختم
	واپس 0;
}
#اگر_ختم /* !HAVE_FIDO_ASSERT_SET_CLIENTDATA || !HAVE_FIDO_CRED_SET_CLIENTDATA */

#اگر_غیر_تعریف_شدہ HAVE_FIDO_CRED_سیٹ_CLIENTDATA
ساکن صحیح
fido_cred_سیٹ_clientdata(fido_cred_t *cred, ثابت u_char *ptr, سائز_t len)
{
	uint8_t d[32];
	صحیح r;

	اگر (sha256_mem(ptr, len, d, حجم(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		واپس FIDO_ERR_اندرونی;
	}
	r = fido_cred_سیٹ_clientdata_hash(cred, d, حجم(d));
	explicit_bzero(d, حجم(d));
	اگر (r != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	واپس r;
}
#اگر_ختم /* HAVE_FIDO_CRED_SET_CLIENTDATA */

#اگر_غیر_تعریف_شدہ HAVE_FIDO_ASSERT_سیٹ_CLIENTDATA
ساکن صحیح
fido_assert_سیٹ_clientdata(fido_assert_t *أكد, ثابت u_char *ptr, سائز_t len)
{
	uint8_t d[32];
	صحیح r;

	اگر (sha256_mem(ptr, len, d, حجم(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		واپس FIDO_ERR_اندرونی;
	}
	r = fido_assert_سیٹ_clientdata_hash(أكد, d, حجم(d));
	explicit_bzero(d, حجم(d));
	اگر (r != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	واپس r;
}
#اگر_ختم /* HAVE_FIDO_ASSERT_SET_CLIENTDATA */

#اگر_غیر_تعریف_شدہ HAVE_FIDO_DEV_IS_WINHELLO
ساکن bool
fido_dev_is_winhello(ثابت fido_dev_t *fdev)
{
	واپس 0;
}
#اگر_ختم /* HAVE_FIDO_DEV_IS_WINHELLO */

/* Check if the specified key handle exists on a given sk. */
ساکن صحیح
sk_try(ثابت ساخت sk_usbhid *sk, ثابت حرف *application,
    ثابت uint8_t *کلید_handle, سائز_t کلید_handle_len)
{
	fido_assert_t *أكد = تہی;
	صحیح r = FIDO_ERR_اندرونی;
	uint8_t پیغام_2[32];

	memset(پیغام_2, '\0', حجم(پیغام_2));
	اگر ((أكد = fido_assert_new()) == تہی) {
		skdebug(__func__, "fido_assert_new failed");
		جاؤ برآمد;
	}
	/* generate an invalid signature on FIDO2 tokens */
	اگر ((r = fido_assert_سیٹ_clientdata(أكد, پیغام_2,
	    حجم(پیغام_2))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		جاؤ برآمد;
	}
	اگر ((r = fido_assert_سیٹ_rp(أكد, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		جاؤ برآمد;
	}
	اگر ((r = fido_assert_allow_cred(أكد, کلید_handle,
	    کلید_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		جاؤ برآمد;
	}
	اگر ((r = fido_assert_سیٹ_اوپر(أكد, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_up: %s", fido_strerr(r));
		جاؤ برآمد;
	}
	r = fido_dev_get_assert(sk->dev, أكد, تہی);
	skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
	اگر (r == FIDO_ERR_USER_PRESENCE_REQUIRED) {
		/* U2F tokens may return this */
		r = FIDO_OK;
	}
 برآمد:
	fido_assert_free(&أكد);

	واپس r != FIDO_OK ? -1 : 0;
}

ساکن صحیح
check_sk_options(fido_dev_t *dev, ثابت حرف *opt, صحیح *ret)
{
	fido_cbor_info_t *info;
	حرف * ثابت *name;
	ثابت bool *قدر;
	سائز_t len, i;
	صحیح r;

	*ret = -1;

	اگر (!fido_dev_is_fido2(dev)) {
		skdebug(__func__, "device is not fido2");
		واپس 0;
	}
	اگر ((info = fido_cbor_info_new()) == تہی) {
		skdebug(__func__, "fido_cbor_info_new failed");
		واپس -1;
	}
	اگر ((r = fido_dev_get_cbor_info(dev, info)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_cbor_info: %s", fido_strerr(r));
		fido_cbor_info_free(&info);
		واپس -1;
	}
	name = fido_cbor_info_options_name_ptr(info);
	قدر = fido_cbor_info_options_قدر_ptr(info);
	len = fido_cbor_info_options_len(info);
	برائے (i = 0; i < len; i++) {
		اگر (!strcmp(name[i], opt)) {
			*ret = قدر[i];
			توڑو;
		}
	}
	fido_cbor_info_free(&info);
	اگر (*ret == -1)
		skdebug(__func__, "option %s is unknown", opt);
	ورنہ
		skdebug(__func__, "option %s is %s", opt, *ret ? "on" : "off");

	واپس 0;
}

ساکن ساخت sk_usbhid *
sk_select_by_cred(ثابت fido_dev_info_t *devlist, سائز_t ndevs,
    ثابت حرف *application, ثابت uint8_t *کلید_handle, سائز_t کلید_handle_len)
{
	ساخت sk_usbhid **skv, *sk;
	سائز_t skvcnt, i;
	صحیح اندرونی_uv;

	اگر ((skv = sk_openv(devlist, ndevs, &skvcnt)) == تہی) {
		skdebug(__func__, "sk_openv failed");
		واپس تہی;
	}
	اگر (skvcnt == 1 && check_sk_options(skv[0]->dev, "uv",
	    &اندرونی_uv) == 0 && اندرونی_uv != -1) {
		sk = skv[0];
		skv[0] = تہی;
		جاؤ برآمد;
	}
	sk = تہی;
	برائے (i = 0; i < skvcnt; i++) {
		اگر (sk_try(skv[i], application, کلید_handle,
		    کلید_handle_len) == 0) {
			sk = skv[i];
			skv[i] = تہی;
			skdebug(__func__, "found key in %s", sk->راستہ);
			توڑو;
		}
	}
 برآمد:
	sk_closev(skv, skvcnt);
	واپس sk;
}

ساکن ساخت sk_usbhid *
sk_select_by_touch(ثابت fido_dev_info_t *devlist, سائز_t ndevs)
{
	ساخت sk_usbhid **skv, *sk;
	ساخت timeval tv_آغاز, tv_now, tv_delta;
	سائز_t skvcnt, idx;
	صحیح touch, ms_remain;

	اگر ((skv = sk_openv(devlist, ndevs, &skvcnt)) == تہی) {
		skdebug(__func__, "sk_openv failed");
		واپس تہی;
	}
	sk = تہی;
	اگر (skvcnt < 2) {
		اگر (skvcnt == 1) {
			/* single candidate */
			sk = skv[0];
			skv[0] = تہی;
		}
		جاؤ برآمد;
	}
#اگر_غیر_تعریف_شدہ HAVE_FIDO_DEV_GET_TOUCH_حالت
	skdebug(__func__, "libfido2 version does not support a feature needed for multiple tokens. Please upgrade to >=1.5.0");
	جاؤ برآمد;
#اگر_ختم

	اگر (sk_touch_begin(skv, skvcnt) == -1) {
		skdebug(__func__, "sk_touch_begin failed");
		جاؤ برآمد;
	}
	monotime_tv(&tv_آغاز);
	کرو {
		اگر (sk_touch_poll(skv, skvcnt, &touch, &idx) == -1) {
			skdebug(__func__, "sk_touch_poll failed");
			جاؤ برآمد;
		}
		اگر (touch) {
			sk = skv[idx];
			skv[idx] = تہی;
			جاؤ برآمد;
		}
		monotime_tv(&tv_now);
		timersub(&tv_now, &tv_آغاز, &tv_delta);
		ms_remain = SELECT_MS - tv_delta.tv_sec * 1000 -
		    tv_delta.tv_usec / 1000;
	} جب (ms_remain >= FIDO_POLL_MS);
	skdebug(__func__, "timeout");
برآمد:
	sk_closev(skv, skvcnt);
	واپس sk;
}

ساکن ساخت sk_usbhid *
sk_probe(ثابت حرف *application, ثابت uint8_t *کلید_handle,
    سائز_t کلید_handle_len, صحیح probe_resident)
{
	ساخت sk_usbhid *sk;
	fido_dev_info_t *devlist;
	سائز_t ndevs;
	صحیح r;

#اگر_تعریف_شدہ HAVE_CYGWIN
	اگر (!probe_resident && (sk = sk_open("windows://hello")) != تہی)
		واپس sk;
#اگر_ختم /* HAVE_CYGWIN */
	اگر ((devlist = fido_dev_info_new(MAX_FIDO_DEVICES)) == تہی) {
		skdebug(__func__, "fido_dev_info_new failed");
		واپس تہی;
	}
	اگر ((r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES,
	    &ndevs)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_info_manifest failed: %s",
		    fido_strerr(r));
		fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
		واپس تہی;
	}
	skdebug(__func__, "%zu device(s) detected", ndevs);
	اگر (ndevs == 0) {
		sk = تہی;
	} ورنہ اگر (application != تہی && کلید_handle != تہی) {
		skdebug(__func__, "selecting sk by cred");
		sk = sk_select_by_cred(devlist, ndevs, application, کلید_handle,
		    کلید_handle_len);
	} ورنہ {
		skdebug(__func__, "selecting sk by touch");
		sk = sk_select_by_touch(devlist, ndevs);
	}
	fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
	واپس sk;
}

#اگر_تعریف_شدہ WITH_OPENSSL
/*
 * The key returned via fido_cred_pubkey_ptr() is in affine coordinates,
 * but the API expects a SEC1 octet string.
 */
ساکن صحیح
pack_عوامی_کلید_ecdsa(ثابت fido_cred_t *cred,
    ساخت sk_enroll_response *response)
{
	ثابت uint8_t *ptr;
	BIGNUM *x = تہی, *y = تہی;
	EC_نقطہ *q = تہی;
	EC_گروہ *g = تہی;
	صحیح ret = -1;

	response->عوامی_کلید = تہی;
	response->عوامی_کلید_len = 0;

	اگر ((x = BN_new()) == تہی ||
	    (y = BN_new()) == تہی ||
	    (g = EC_گروہ_new_by_خم_name(NID_X9_62_prime256v1)) == تہی ||
	    (q = EC_نقطہ_new(g)) == تہی) {
		skdebug(__func__, "libcrypto setup failed");
		جاؤ برآمد;
	}
	اگر ((ptr = fido_cred_pubkey_ptr(cred)) == تہی) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		جاؤ برآمد;
	}
	اگر (fido_cred_pubkey_len(cred) != 64) {
		skdebug(__func__, "bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		جاؤ برآمد;
	}

	اگر (BN_bin2bn(ptr, 32, x) == تہی ||
	    BN_bin2bn(ptr + 32, 32, y) == تہی) {
		skdebug(__func__, "BN_bin2bn failed");
		جاؤ برآمد;
	}
	اگر (EC_نقطہ_سیٹ_affine_coordinates(g, q, x, y, تہی) != 1) {
		skdebug(__func__, "EC_POINT_set_affine_coordinates failed");
		جاؤ برآمد;
	}
	response->عوامی_کلید_len = EC_نقطہ_point2oct(g, q,
	    نقطہ_CONVERSION_UNCOMPRESSED, تہی, 0, تہی);
	اگر (response->عوامی_کلید_len == 0 || response->عوامی_کلید_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->عوامی_کلید_len);
		جاؤ برآمد;
	}
	اگر ((response->عوامی_کلید = حافظہ_دو(response->عوامی_کلید_len)) == تہی) {
		skdebug(__func__, "malloc pubkey failed");
		جاؤ برآمد;
	}
	اگر (EC_نقطہ_point2oct(g, q, نقطہ_CONVERSION_UNCOMPRESSED,
	    response->عوامی_کلید, response->عوامی_کلید_len, تہی) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		جاؤ برآمد;
	}
	/* success */
	ret = 0;
 برآمد:
	اگر (ret != 0 && response->عوامی_کلید != تہی) {
		memset(response->عوامی_کلید, 0, response->عوامی_کلید_len);
		آزاد(response->عوامی_کلید);
		response->عوامی_کلید = تہی;
	}
	EC_نقطہ_free(q);
	EC_گروہ_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	واپس ret;
}
#اگر_ختم /* WITH_OPENSSL */

ساکن صحیح
pack_عوامی_کلید_ed25519(ثابت fido_cred_t *cred,
    ساخت sk_enroll_response *response)
{
	ثابت uint8_t *ptr;
	سائز_t len;
	صحیح ret = -1;

	response->عوامی_کلید = تہی;
	response->عوامی_کلید_len = 0;

	اگر ((len = fido_cred_pubkey_len(cred)) != 32) {
		skdebug(__func__, "bad fido_cred_pubkey_len len %zu", len);
		جاؤ برآمد;
	}
	اگر ((ptr = fido_cred_pubkey_ptr(cred)) == تہی) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		جاؤ برآمد;
	}
	response->عوامی_کلید_len = len;
	اگر ((response->عوامی_کلید = حافظہ_دو(response->عوامی_کلید_len)) == تہی) {
		skdebug(__func__, "malloc pubkey failed");
		جاؤ برآمد;
	}
	حافظہ_نقل(response->عوامی_کلید, ptr, len);
	ret = 0;
 برآمد:
	اگر (ret != 0)
		آزاد(response->عوامی_کلید);
	واپس ret;
}

ساکن صحیح
pack_عوامی_کلید(uint32_t alg, ثابت fido_cred_t *cred,
    ساخت sk_enroll_response *response)
{
	انتخاب(alg) {
#اگر_تعریف_شدہ WITH_OPENSSL
	حالت SSH_SK_ECDSA:
		واپس pack_عوامی_کلید_ecdsa(cred, response);
#اگر_ختم /* WITH_OPENSSL */
	حالت SSH_SK_ED25519:
		واپس pack_عوامی_کلید_ed25519(cred, response);
	طےشدہ:
		واپس -1;
	}
}

ساکن صحیح
fidoerr_مقصد_skerr(صحیح fidoerr)
{
	انتخاب (fidoerr) {
	حالت FIDO_ERR_UNSUPPORTED_OPTION:
	حالت FIDO_ERR_UNSUPPORTED_ALGORITHM:
		واپس SSH_SK_ERR_UNSUPPORTED;
	حالت FIDO_ERR_PIN_REQUIRED:
	حالت FIDO_ERR_PIN_INVALID:
	حالت FIDO_ERR_OPERATION_DENIED:
		واپس SSH_SK_ERR_PIN_REQUIRED;
	طےشدہ:
		واپس -1;
	}
}

ساکن صحیح
check_enroll_options(ساخت sk_option **options, حرف **devicep,
    uint8_t *user_id, سائز_t user_id_len)
{
	سائز_t i;

	اگر (options == تہی)
		واپس 0;
	برائے (i = 0; options[i] != تہی; i++) {
		اگر (strcmp(options[i]->name, "device") == 0) {
			اگر ((*devicep = strdup(options[i]->قدر)) == تہی) {
				skdebug(__func__, "strdup device failed");
				واپس -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} ورنہ اگر (strcmp(options[i]->name, "user") == 0) {
			اگر (strlcpy(user_id, options[i]->قدر, user_id_len) >=
			    user_id_len) {
				skdebug(__func__, "user too long");
				واپس -1;
			}
			skdebug(__func__, "requested user %s",
			    (حرف *)user_id);
		} ورنہ {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			اگر (options[i]->required) {
				skdebug(__func__, "unknown required option");
				واپس -1;
			}
		}
	}
	واپس 0;
}

ساکن صحیح
کلید_lookup(fido_dev_t *dev, ثابت حرف *application, ثابت uint8_t *user_id,
    سائز_t user_id_len, ثابت حرف *pin)
{
	fido_assert_t *أكد = تہی;
	uint8_t پیغام_2[32];
	صحیح r = FIDO_ERR_اندرونی;
	صحیح sk_supports_uv, uv;
	سائز_t i;

	memset(پیغام_2, '\0', حجم(پیغام_2));
	اگر ((أكد = fido_assert_new()) == تہی) {
		skdebug(__func__, "fido_assert_new failed");
		جاؤ برآمد;
	}
	/* generate an invalid signature on FIDO2 tokens */
	اگر ((r = fido_assert_سیٹ_clientdata(أكد, پیغام_2,
	    حجم(پیغام_2))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		جاؤ برآمد;
	}
	اگر ((r = fido_assert_سیٹ_rp(أكد, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		جاؤ برآمد;
	}
	اگر ((r = fido_assert_سیٹ_اوپر(أكد, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		جاؤ برآمد;
	}
	uv = FIDO_OPT_OMIT;
	اگر (pin == تہی && check_sk_options(dev, "uv", &sk_supports_uv) == 0 &&
	    sk_supports_uv != -1)
		uv = FIDO_OPT_TRUE;
	اگر ((r = fido_assert_سیٹ_uv(أكد, uv)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
		جاؤ برآمد;
	}
	اگر ((r = fido_dev_get_assert(dev, أكد, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		جاؤ برآمد;
	}
	r = FIDO_ERR_NO_CREDENTIALS;
	skdebug(__func__, "%zu signatures returned", fido_assert_گنتی(أكد));
	برائے (i = 0; i < fido_assert_گنتی(أكد); i++) {
		اگر (fido_assert_user_id_len(أكد, i) == user_id_len &&
		    memcmp(fido_assert_user_id_ptr(أكد, i), user_id,
		    user_id_len) == 0) {
			skdebug(__func__, "credential exists");
			r = FIDO_OK;
			جاؤ برآمد;
		}
	}
 برآمد:
	fido_assert_free(&أكد);

	واپس r;
}

صحیح
sk_enroll(uint32_t alg, ثابت uint8_t *challenge, سائز_t challenge_len,
    ثابت حرف *application, uint8_t flags, ثابت حرف *pin,
    ساخت sk_option **options, ساخت sk_enroll_response **enroll_response)
{
	fido_cred_t *cred = تہی;
	ثابت uint8_t *ptr;
	uint8_t user_id[32];
	ساخت sk_usbhid *sk = تہی;
	ساخت sk_enroll_response *response = تہی;
	سائز_t len;
	صحیح credprot;
	صحیح cose_alg;
	صحیح ret = SSH_SK_ERR_GENERAL;
	صحیح r;
	حرف *device = تہی;

	fido_init(SSH_FIDO_INIT_ARG);

	اگر (enroll_response == تہی) {
		skdebug(__func__, "enroll_response == NULL");
		جاؤ برآمد;
	}
	*enroll_response = تہی;
	memset(user_id, 0, حجم(user_id));
	اگر (check_enroll_options(options, &device, user_id,
	    حجم(user_id)) != 0)
		جاؤ برآمد; /* error already logged */

	انتخاب(alg) {
#اگر_تعریف_شدہ WITH_OPENSSL
	حالت SSH_SK_ECDSA:
		cose_alg = COSE_ES256;
		توڑو;
#اگر_ختم /* WITH_OPENSSL */
	حالت SSH_SK_ED25519:
		cose_alg = COSE_EDDSA;
		توڑو;
	طےشدہ:
		skdebug(__func__, "unsupported key type %d", alg);
		جاؤ برآمد;
	}
	اگر (device != تہی)
		sk = sk_open(device);
	ورنہ
		sk = sk_probe(تہی, تہی, 0, 0);
	اگر (sk == تہی) {
		ret = SSH_SK_ERR_DEVICE_NOT_ملا;
		skdebug(__func__, "failed to find sk");
		جاؤ برآمد;
	}
	skdebug(__func__, "using device %s", sk->راستہ);
	اگر ((flags & SSH_SK_RESIDENT_کلید) != 0 &&
	    (flags & SSH_SK_FORCE_OPERATION) == 0 &&
	    (r = کلید_lookup(sk->dev, application, user_id, حجم(user_id),
	    pin)) != FIDO_ERR_NO_CREDENTIALS) {
		اگر (r != FIDO_OK) {
			ret = fidoerr_مقصد_skerr(r);
			skdebug(__func__, "key_lookup failed");
		} ورنہ {
			ret = SSH_SK_ERR_CREDENTIAL_EXISTS;
			skdebug(__func__, "key exists");
		}
		جاؤ برآمد;
	}
	اگر ((cred = fido_cred_new()) == تہی) {
		skdebug(__func__, "fido_cred_new failed");
		جاؤ برآمد;
	}
	اگر ((r = fido_cred_سیٹ_type(cred, cose_alg)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_type: %s", fido_strerr(r));
		جاؤ برآمد;
	}
	اگر ((r = fido_cred_سیٹ_clientdata(cred,
	    challenge, challenge_len)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata: %s",
		    fido_strerr(r));
		جاؤ برآمد;
	}
	اگر ((r = fido_cred_سیٹ_rk(cred, (flags & SSH_SK_RESIDENT_کلید) != 0 ?
	    FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rk: %s", fido_strerr(r));
		جاؤ برآمد;
	}
	اگر ((r = fido_cred_سیٹ_user(cred, user_id, حجم(user_id),
	    "openssh", "openssh", تہی)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_user: %s", fido_strerr(r));
		جاؤ برآمد;
	}
	اگر ((r = fido_cred_سیٹ_rp(cred, application, تہی)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rp: %s", fido_strerr(r));
		جاؤ برآمد;
	}
	اگر ((flags & (SSH_SK_RESIDENT_کلید|SSH_SK_USER_VERIFICATION_REQD)) != 0) {
#اگر !defined(HAVE_FIDO_DEV_SUPPORTS_CRED_PROT) || \
    !defined(HAVE_FIDO_CRED_سیٹ_PROT)
		skdebug(__func__, "libfido2 version does not support a feature required for this operation. Please upgrade to >=1.5.0");
		ret = SSH_SK_ERR_UNSUPPORTED;
		جاؤ برآمد;
		credprot = 0; (خالی)credprot; /* avoid warning */
#اگر_ختم
		اگر (!fido_dev_supports_cred_prot(sk->dev)) {
			skdebug(__func__, "%s does not support credprot, "
			    "refusing to create unprotected "
			    "resident/verify-required key", sk->راستہ);
			ret = SSH_SK_ERR_UNSUPPORTED;
			جاؤ برآمد;
		}
		اگر ((flags & SSH_SK_USER_VERIFICATION_REQD))
			credprot = FIDO_CRED_PROT_UV_REQUIRED;
		ورنہ
			credprot = FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID;

		اگر ((r = fido_cred_سیٹ_prot(cred, credprot)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_set_prot: %s",
			    fido_strerr(r));
			ret = fidoerr_مقصد_skerr(r);
			جاؤ برآمد;
		}
	}
	اگر ((r = fido_dev_make_cred(sk->dev, cred, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_make_cred: %s", fido_strerr(r));
		ret = fidoerr_مقصد_skerr(r);
		جاؤ برآمد;
	}
	اگر (fido_cred_x5c_ptr(cred) != تہی) {
		اگر ((r = fido_cred_verify(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify: %s",
			    fido_strerr(r));
			جاؤ برآمد;
		}
	} ورنہ اگر (strcmp(fido_cred_fmt(cred), "none") != 0) {
		skdebug(__func__, "self-attested credential");
		اگر ((r = fido_cred_verify_self(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify_self: %s",
			    fido_strerr(r));
			جاؤ برآمد;
		}
	} ورنہ {
		skdebug(__func__, "no attestation data");
	}
	اگر ((response = صفر_حافظہ_دو(1, حجم(*response))) == تہی) {
		skdebug(__func__, "calloc response failed");
		جاؤ برآمد;
	}
	response->flags = flags;
	اگر (pack_عوامی_کلید(alg, cred, response) != 0) {
		skdebug(__func__, "pack_public_key failed");
		جاؤ برآمد;
	}
	اگر ((ptr = fido_cred_id_ptr(cred)) != تہی) {
		len = fido_cred_id_len(cred);
		اگر ((response->کلید_handle = صفر_حافظہ_دو(1, len)) == تہی) {
			skdebug(__func__, "calloc key handle failed");
			جاؤ برآمد;
		}
		حافظہ_نقل(response->کلید_handle, ptr, len);
		response->کلید_handle_len = len;
	}
	اگر ((ptr = fido_cred_sig_ptr(cred)) != تہی) {
		len = fido_cred_sig_len(cred);
		اگر ((response->signature = صفر_حافظہ_دو(1, len)) == تہی) {
			skdebug(__func__, "calloc signature failed");
			جاؤ برآمد;
		}
		حافظہ_نقل(response->signature, ptr, len);
		response->signature_len = len;
	}
	اگر ((ptr = fido_cred_x5c_ptr(cred)) != تہی) {
		len = fido_cred_x5c_len(cred);
		skdebug(__func__, "attestation cert len=%zu", len);
		اگر ((response->attestation_cert = صفر_حافظہ_دو(1, len)) == تہی) {
			skdebug(__func__, "calloc attestation cert failed");
			جاؤ برآمد;
		}
		حافظہ_نقل(response->attestation_cert, ptr, len);
		response->attestation_cert_len = len;
	}
	اگر ((ptr = fido_cred_authdata_ptr(cred)) != تہی) {
		len = fido_cred_authdata_len(cred);
		skdebug(__func__, "authdata len=%zu", len);
		اگر ((response->authdata = صفر_حافظہ_دو(1, len)) == تہی) {
			skdebug(__func__, "calloc authdata failed");
			جاؤ برآمد;
		}
		حافظہ_نقل(response->authdata, ptr, len);
		response->authdata_len = len;
	}
	*enroll_response = response;
	response = تہی;
	ret = 0;
 برآمد:
	آزاد(device);
	اگر (response != تہی) {
		آزاد(response->عوامی_کلید);
		آزاد(response->کلید_handle);
		آزاد(response->signature);
		آزاد(response->attestation_cert);
		آزاد(response->authdata);
		آزاد(response);
	}
	sk_close(sk);
	fido_cred_free(&cred);
	واپس ret;
}

#اگر_تعریف_شدہ WITH_OPENSSL
ساکن صحیح
pack_sig_ecdsa(fido_assert_t *أكد, ساخت sk_sign_response *response)
{
	ECDSA_SIG *sig = تہی;
	ثابت BIGNUM *sig_r, *sig_s;
	ثابت غیرعلامتی حرف *cp;
	سائز_t sig_len;
	صحیح ret = -1;

	cp = fido_assert_sig_ptr(أكد, 0);
	sig_len = fido_assert_sig_len(أكد, 0);
	اگر ((sig = d2i_ECDSA_SIG(تہی, &cp, sig_len)) == تہی) {
		skdebug(__func__, "d2i_ECDSA_SIG failed");
		جاؤ برآمد;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_عدد_بائٹیں(sig_r);
	response->sig_s_len = BN_عدد_بائٹیں(sig_s);
	اگر ((response->sig_r = صفر_حافظہ_دو(1, response->sig_r_len)) == تہی ||
	    (response->sig_s = صفر_حافظہ_دو(1, response->sig_s_len)) == تہی) {
		skdebug(__func__, "calloc signature failed");
		جاؤ برآمد;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 برآمد:
	ECDSA_SIG_free(sig);
	اگر (ret != 0) {
		آزاد(response->sig_r);
		آزاد(response->sig_s);
		response->sig_r = تہی;
		response->sig_s = تہی;
	}
	واپس ret;
}
#اگر_ختم /* WITH_OPENSSL */

ساکن صحیح
pack_sig_ed25519(fido_assert_t *أكد, ساخت sk_sign_response *response)
{
	ثابت غیرعلامتی حرف *ptr;
	سائز_t len;
	صحیح ret = -1;

	ptr = fido_assert_sig_ptr(أكد, 0);
	len = fido_assert_sig_len(أكد, 0);
	اگر (len != 64) {
		skdebug(__func__, "bad length %zu", len);
		جاؤ برآمد;
	}
	response->sig_r_len = len;
	اگر ((response->sig_r = صفر_حافظہ_دو(1, response->sig_r_len)) == تہی) {
		skdebug(__func__, "calloc signature failed");
		جاؤ برآمد;
	}
	حافظہ_نقل(response->sig_r, ptr, len);
	ret = 0;
 برآمد:
	اگر (ret != 0) {
		آزاد(response->sig_r);
		response->sig_r = تہی;
	}
	واپس ret;
}

ساکن صحیح
pack_sig(uint32_t  alg, fido_assert_t *أكد,
    ساخت sk_sign_response *response)
{
	انتخاب(alg) {
#اگر_تعریف_شدہ WITH_OPENSSL
	حالت SSH_SK_ECDSA:
		واپس pack_sig_ecdsa(أكد, response);
#اگر_ختم /* WITH_OPENSSL */
	حالت SSH_SK_ED25519:
		واپس pack_sig_ed25519(أكد, response);
	طےشدہ:
		واپس -1;
	}
}

/* Checks sk_options for sk_sign() and sk_load_resident_keys() */
ساکن صحیح
check_sign_بھرو_resident_options(ساخت sk_option **options, حرف **devicep)
{
	سائز_t i;

	اگر (options == تہی)
		واپس 0;
	برائے (i = 0; options[i] != تہی; i++) {
		اگر (strcmp(options[i]->name, "device") == 0) {
			اگر ((*devicep = strdup(options[i]->قدر)) == تہی) {
				skdebug(__func__, "strdup device failed");
				واپس -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} ورنہ {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			اگر (options[i]->required) {
				skdebug(__func__, "unknown required option");
				واپس -1;
			}
		}
	}
	واپس 0;
}

صحیح
sk_sign(uint32_t alg, ثابت uint8_t *ڈیٹا, سائز_t datalen,
    ثابت حرف *application,
    ثابت uint8_t *کلید_handle, سائز_t کلید_handle_len,
    uint8_t flags, ثابت حرف *pin, ساخت sk_option **options,
    ساخت sk_sign_response **sign_response)
{
	fido_assert_t *أكد = تہی;
	حرف *device = تہی;
	ساخت sk_usbhid *sk = تہی;
	ساخت sk_sign_response *response = تہی;
	صحیح ret = SSH_SK_ERR_GENERAL, اندرونی_uv;
	صحیح r;

	fido_init(SSH_FIDO_INIT_ARG);

	اگر (sign_response == تہی) {
		skdebug(__func__, "sign_response == NULL");
		جاؤ برآمد;
	}
	*sign_response = تہی;
	اگر (check_sign_بھرو_resident_options(options, &device) != 0)
		جاؤ برآمد; /* error already logged */
	اگر (device != تہی)
		sk = sk_open(device);
	ورنہ اگر (pin != تہی || (flags & SSH_SK_USER_VERIFICATION_REQD))
		sk = sk_probe(تہی, تہی, 0, 0);
	ورنہ
		sk = sk_probe(application, کلید_handle, کلید_handle_len, 0);
	اگر (sk == تہی) {
		ret = SSH_SK_ERR_DEVICE_NOT_ملا;
		skdebug(__func__, "failed to find sk");
		جاؤ برآمد;
	}
	اگر ((أكد = fido_assert_new()) == تہی) {
		skdebug(__func__, "fido_assert_new failed");
		جاؤ برآمد;
	}
	اگر ((r = fido_assert_سیٹ_clientdata(أكد,
	    ڈیٹا, datalen)) != FIDO_OK)  {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		جاؤ برآمد;
	}
	اگر ((r = fido_assert_سیٹ_rp(أكد, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		جاؤ برآمد;
	}
	اگر ((r = fido_assert_allow_cred(أكد, کلید_handle,
	    کلید_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		جاؤ برآمد;
	}
	اگر ((r = fido_assert_سیٹ_اوپر(أكد,
	    (flags & SSH_SK_USER_PRESENCE_REQD) ?
	    FIDO_OPT_TRUE : FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		جاؤ برآمد;
	}
	/*
	 * WinHello requests the PIN by default.  Make "uv" request explicit
	 * to allow keys with and without -O verify-required to make sense.
	 */
	اگر (pin == تہی && fido_dev_is_winhello (sk->dev) &&
	    (r = fido_assert_سیٹ_uv(أكد, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
	}
	اگر (pin == تہی && (flags & SSH_SK_USER_VERIFICATION_REQD)) {
		اگر (check_sk_options(sk->dev, "uv", &اندرونی_uv) < 0 ||
		    اندرونی_uv != 1) {
			skdebug(__func__, "check_sk_options uv");
			ret = SSH_SK_ERR_PIN_REQUIRED;
			جاؤ برآمد;
		}
		اگر ((r = fido_assert_سیٹ_uv(أكد,
		    FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_assert_set_uv: %s",
			    fido_strerr(r));
			ret = fidoerr_مقصد_skerr(r);
			جاؤ برآمد;
		}
	}
	اگر ((r = fido_dev_get_assert(sk->dev, أكد, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ret = fidoerr_مقصد_skerr(r);
		جاؤ برآمد;
	}
	اگر ((response = صفر_حافظہ_دو(1, حجم(*response))) == تہی) {
		skdebug(__func__, "calloc response failed");
		جاؤ برآمد;
	}
	response->flags = fido_assert_flags(أكد, 0);
	response->شمار_2 = fido_assert_sigcount(أكد, 0);
	اگر (pack_sig(alg, أكد, response) != 0) {
		skdebug(__func__, "pack_sig failed");
		جاؤ برآمد;
	}
	*sign_response = response;
	response = تہی;
	ret = 0;
 برآمد:
	آزاد(device);
	اگر (response != تہی) {
		آزاد(response->sig_r);
		آزاد(response->sig_s);
		آزاد(response);
	}
	sk_close(sk);
	fido_assert_free(&أكد);
	واپس ret;
}

ساکن صحیح
read_rks(ساخت sk_usbhid *sk, ثابت حرف *pin,
    ساخت sk_resident_کلید ***rksp, سائز_t *nrksp)
{
	صحیح ret = SSH_SK_ERR_GENERAL, r = -1;
	uint32_t alg;
	fido_credman_metadata_t *metadata = تہی;
	fido_credman_rp_t *rp = تہی;
	fido_credman_rk_t *rk = تہی;
	سائز_t i, j, nrp, nrk, user_id_len;
	ثابت fido_cred_t *cred;
	ثابت حرف *rp_id, *rp_name, *user_name;
	ساخت sk_resident_کلید *srk = تہی, **tmp;
	ثابت u_char *user_id;

	اگر (pin == تہی) {
		skdebug(__func__, "no PIN specified");
		ret = SSH_SK_ERR_PIN_REQUIRED;
		جاؤ برآمد;
	}
	اگر ((metadata = fido_credman_metadata_new()) == تہی) {
		skdebug(__func__, "alloc failed");
		جاؤ برآمد;
	}
	اگر ((r = fido_credman_get_dev_metadata(sk->dev, metadata, pin)) != 0) {
		اگر (r == FIDO_ERR_INVALID_COMMAND) {
			skdebug(__func__, "device %s does not support "
			    "resident keys", sk->راستہ);
			ret = 0;
			جاؤ برآمد;
		}
		skdebug(__func__, "get metadata for %s failed: %s",
		    sk->راستہ, fido_strerr(r));
		ret = fidoerr_مقصد_skerr(r);
		جاؤ برآمد;
	}
	skdebug(__func__, "existing %llu, remaining %llu",
	    (غیرعلامتی طویل طویل)fido_credman_rk_existing(metadata),
	    (غیرعلامتی طویل طویل)fido_credman_rk_بقایا(metadata));
	اگر ((rp = fido_credman_rp_new()) == تہی) {
		skdebug(__func__, "alloc rp failed");
		جاؤ برآمد;
	}
	اگر ((r = fido_credman_get_dev_rp(sk->dev, rp, pin)) != 0) {
		skdebug(__func__, "get RPs for %s failed: %s",
		    sk->راستہ, fido_strerr(r));
		جاؤ برآمد;
	}
	nrp = fido_credman_rp_گنتی(rp);
	skdebug(__func__, "Device %s has resident keys for %zu RPs",
	    sk->راستہ, nrp);

	/* Iterate over RP IDs that have resident keys */
	برائے (i = 0; i < nrp; i++) {
		rp_id = fido_credman_rp_id(rp, i);
		rp_name = fido_credman_rp_name(rp, i);
		skdebug(__func__, "rp %zu: name=\"%s\" id=\"%s\" hashlen=%zu",
		    i, rp_name == تہی ? "(none)" : rp_name,
		    rp_id == تہی ? "(none)" : rp_id,
		    fido_credman_rp_id_hash_len(rp, i));

		/* Skip non-SSH RP IDs */
		اگر (rp_id == تہی ||
		    strncasecmp(fido_credman_rp_id(rp, i), "ssh:", 4) != 0)
			جاری;

		fido_credman_rk_free(&rk);
		اگر ((rk = fido_credman_rk_new()) == تہی) {
			skdebug(__func__, "alloc rk failed");
			جاؤ برآمد;
		}
		اگر ((r = fido_credman_get_dev_rk(sk->dev,
		    fido_credman_rp_id(rp, i), rk, pin)) != 0) {
			skdebug(__func__, "get RKs for %s slot %zu failed: %s",
			    sk->راستہ, i, fido_strerr(r));
			جاؤ برآمد;
		}
		nrk = fido_credman_rk_گنتی(rk);
		skdebug(__func__, "RP \"%s\" has %zu resident keys",
		    fido_credman_rp_id(rp, i), nrk);

		/* Iterate over resident keys for this RP ID */
		برائے (j = 0; j < nrk; j++) {
			اگر ((cred = fido_credman_rk(rk, j)) == تہی) {
				skdebug(__func__, "no RK in slot %zu", j);
				جاری;
			}
			اگر ((user_name = fido_cred_user_name(cred)) == تہی)
				user_name = "";
			user_id = fido_cred_user_id_ptr(cred);
			user_id_len = fido_cred_user_id_len(cred);
			skdebug(__func__, "Device %s RP \"%s\" user \"%s\" "
			    "uidlen %zu slot %zu: type %d flags 0x%02x "
			    "prot 0x%02x", sk->راستہ, rp_id, user_name,
			    user_id_len, j, fido_cred_type(cred),
			    fido_cred_flags(cred), fido_cred_prot(cred));

			/* Determine key algorithm */
			انتخاب (fido_cred_type(cred)) {
			حالت COSE_ES256:
				alg = SSH_SK_ECDSA;
				توڑو;
			حالت COSE_EDDSA:
				alg = SSH_SK_ED25519;
				توڑو;
			طےشدہ:
				skdebug(__func__, "unsupported key type %d",
				    fido_cred_type(cred));
				جاری;
			}

			/* build response entry */
			اگر ((srk = صفر_حافظہ_دو(1, حجم(*srk))) == تہی ||
			    (srk->کلید.کلید_handle = صفر_حافظہ_دو(1,
			    fido_cred_id_len(cred))) == تہی ||
			    (srk->application = strdup(rp_id)) == تہی ||
			    (user_id_len > 0 &&
			     (srk->user_id = صفر_حافظہ_دو(1, user_id_len)) == تہی)) {
				skdebug(__func__, "alloc sk_resident_key");
				جاؤ برآمد;
			}

			srk->alg = alg;
			srk->کلید.کلید_handle_len = fido_cred_id_len(cred);
			حافظہ_نقل(srk->کلید.کلید_handle, fido_cred_id_ptr(cred),
			    srk->کلید.کلید_handle_len);
			srk->user_id_len = user_id_len;
			اگر (srk->user_id_len != 0)
				حافظہ_نقل(srk->user_id, user_id, srk->user_id_len);

#اگر_تعریف_شدہ HAVE_FIDO_CRED_PROT
			اگر (fido_cred_prot(cred) ==
			    FIDO_CRED_PROT_UV_REQUIRED)
				srk->flags |=  SSH_SK_USER_VERIFICATION_REQD;
#اگر_ختم

			اگر ((r = pack_عوامی_کلید(srk->alg, cred,
			    &srk->کلید)) != 0) {
				skdebug(__func__, "pack public key failed");
				جاؤ برآمد;
			}
			/* append */
			اگر ((tmp = recallocarray(*rksp, *nrksp, (*nrksp) + 1,
			    حجم(**rksp))) == تہی) {
				skdebug(__func__, "alloc rksp");
				جاؤ برآمد;
			}
			*rksp = tmp;
			(*rksp)[(*nrksp)++] = srk;
			srk = تہی;
		}
	}
	/* Success */
	ret = 0;
 برآمد:
	اگر (srk != تہی) {
		آزاد(srk->application);
		freezero(srk->کلید.عوامی_کلید, srk->کلید.عوامی_کلید_len);
		freezero(srk->کلید.کلید_handle, srk->کلید.کلید_handle_len);
		freezero(srk->user_id, srk->user_id_len);
		freezero(srk, حجم(*srk));
	}
	fido_credman_rp_free(&rp);
	fido_credman_rk_free(&rk);
	fido_credman_metadata_free(&metadata);
	واپس ret;
}

صحیح
sk_بھرو_resident_کلیدیں(ثابت حرف *pin, ساخت sk_option **options,
    ساخت sk_resident_کلید ***rksp, سائز_t *nrksp)
{
	صحیح ret = SSH_SK_ERR_GENERAL, r = -1;
	سائز_t i, nrks = 0;
	ساخت sk_resident_کلید **rks = تہی;
	ساخت sk_usbhid *sk = تہی;
	حرف *device = تہی;

	*rksp = تہی;
	*nrksp = 0;

	fido_init(SSH_FIDO_INIT_ARG);

	اگر (check_sign_بھرو_resident_options(options, &device) != 0)
		جاؤ برآمد; /* error already logged */
	اگر (device != تہی)
		sk = sk_open(device);
	ورنہ
		sk = sk_probe(تہی, تہی, 0, 1);
	اگر (sk == تہی) {
		ret = SSH_SK_ERR_DEVICE_NOT_ملا;
		skdebug(__func__, "failed to find sk");
		جاؤ برآمد;
	}
	skdebug(__func__, "trying %s", sk->راستہ);
	اگر ((r = read_rks(sk, pin, &rks, &nrks)) != 0) {
		skdebug(__func__, "read_rks failed for %s", sk->راستہ);
		ret = r;
		جاؤ برآمد;
	}
	/* success, unless we have no keys but a specific error */
	اگر (nrks > 0 || ret == SSH_SK_ERR_GENERAL)
		ret = 0;
	*rksp = rks;
	*nrksp = nrks;
	rks = تہی;
	nrks = 0;
 برآمد:
	sk_close(sk);
	برائے (i = 0; i < nrks; i++) {
		آزاد(rks[i]->application);
		freezero(rks[i]->کلید.عوامی_کلید, rks[i]->کلید.عوامی_کلید_len);
		freezero(rks[i]->کلید.کلید_handle, rks[i]->کلید.کلید_handle_len);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i], حجم(*rks[i]));
	}
	آزاد(device);
	آزاد(rks);
	واپس ret;
}

#اگر_ختم /* ENABLE_SK_INTERNAL */
