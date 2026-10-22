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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ifdef ENABLE_SK_INTERNAL

#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <time.h>
#ifdef HAVE_SHA2_H
#ಅನ್ತರ್ಭಾವ <sha2.h>
#endif

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/opensslv.h>
#ಅನ್ತರ್ಭಾವ <openssl/crypto.h>
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/ec.h>
#ಅನ್ತರ್ಭಾವ <openssl/ecdsa.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"
#endif /* WITH_OPENSSL */

#ಅನ್ತರ್ಭಾವ <fido.h>
#ಅನ್ತರ್ಭಾವ <fido/credman.h>

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
# define sk_load_resident_ಕೀಲಿಗಳು	ssh_sk_load_resident_ಕೀಲಿಗಳು
#endif /* !SK_STANDALONE */

#ಅನ್ತರ್ಭಾವ "sk-api.h"

/* #define SK_DEBUG 1 */

#ifdef SK_DEBUG
#define SSH_FIDO_INIT_ARG	FIDO_DEBUG
#ಅನ್ಯಥಾ
#define SSH_FIDO_INIT_ARG	0
#endif

#define MAX_FIDO_DEVICES	8
#define FIDO_POLL_MS		50
#define SELECT_MS		15000
#define POLL_SLEEP_NS		200000000

#ifndef FIDO_ERR_OPERATION_DENIED
#define FIDO_ERR_OPERATION_DENIED 0x27
#endif

ಸಂರಚನಾ sk_usbhid {
	fido_dev_t *dev;
	ವರ್ಣ *path;
};

/* Return the version of the middleware API */
uint32_t sk_api_version(ಶೂನ್ಯ);

/* Enroll a U2F key (private key generation) */
ಪೂರ್ಣಾಙ್ಕ sk_enroll(uint32_t alg, ಧ್ರುವ uint8_t *challenge, size_t challenge_len,
    ಧ್ರುವ ವರ್ಣ *application, uint8_t flags, ಧ್ರುವ ವರ್ಣ *pin,
    ಸಂರಚನಾ sk_option **options, ಸಂರಚನಾ sk_enroll_response **enroll_response);

/* Sign a challenge */
ಪೂರ್ಣಾಙ್ಕ sk_sign(uint32_t alg, ಧ್ರುವ uint8_t *data, size_t data_len,
    ಧ್ರುವ ವರ್ಣ *application, ಧ್ರುವ uint8_t *ಕೀಲಿ_handle, size_t ಕೀಲಿ_handle_len,
    uint8_t flags, ಧ್ರುವ ವರ್ಣ *pin, ಸಂರಚನಾ sk_option **options,
    ಸಂರಚನಾ sk_sign_response **sign_response);

/* Load resident keys */
ಪೂರ್ಣಾಙ್ಕ sk_load_resident_ಕೀಲಿಗಳು(ಧ್ರುವ ವರ್ಣ *pin, ಸಂರಚನಾ sk_option **options,
    ಸಂರಚನಾ sk_resident_ಕೀಲಿ ***rks, size_t *nrks);

ಸ್ಥಿರ ಶೂನ್ಯ skdebug(ಧ್ರುವ ವರ್ಣ *func, ಧ್ರುವ ವರ್ಣ *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

ಸ್ಥಿರ ಶೂನ್ಯ
skdebug(ಧ್ರುವ ವರ್ಣ *func, ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
#ಯದಿ !defined(SK_STANDALONE)
	ವರ್ಣ *ಸಂದೇಶ;
	va_list ap;

	va_start(ap, fmt);
	xvasprintf(&ಸಂದೇಶ, fmt, ap);
	va_end(ap);
	debug("%s: %s", func, ಸಂದೇಶ);
	ಮುಕ್ತ(ಸಂದೇಶ);
#ನೋಚೇದ್ಯದಿ defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#ಅನ್ಯಥಾ
	(ಶೂನ್ಯ)func; /* XXX */
	(ಶೂನ್ಯ)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(ಶೂನ್ಯ)
{
	ಪ್ರತ್ಯಾಗಮ SSH_SK_VERSION_MAJOR;
}

ಸ್ಥಿರ ಸಂರಚನಾ sk_usbhid *
sk_open(ಧ್ರುವ ವರ್ಣ *path)
{
	ಸಂರಚನಾ sk_usbhid *sk;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (path == ರಿಕ್ತ) {
		skdebug(__func__, "path == NULL");
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ ((sk = calloc(1, ಪರಿಮಾಣ(*sk))) == ರಿಕ್ತ) {
		skdebug(__func__, "calloc sk failed");
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ ((sk->path = strdup(path)) == ರಿಕ್ತ) {
		skdebug(__func__, "strdup path failed");
		ಮುಕ್ತ(sk);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ ((sk->dev = fido_dev_new()) == ರಿಕ್ತ) {
		skdebug(__func__, "fido_dev_new failed");
		ಮುಕ್ತ(sk->path);
		ಮುಕ್ತ(sk);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ ((r = fido_dev_open(sk->dev, sk->path)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_open %s failed: %s", sk->path,
		    fido_strerr(r));
		fido_dev_free(&sk->dev);
		ಮುಕ್ತ(sk->path);
		ಮುಕ್ತ(sk);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಪ್ರತ್ಯಾಗಮ sk;
}

ಸ್ಥಿರ ಶೂನ್ಯ
sk_close(ಸಂರಚನಾ sk_usbhid *sk)
{
	ಯದಿ (sk == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	fido_dev_cancel(sk->dev); /* cancel any pending operation */
	fido_dev_close(sk->dev);
	fido_dev_free(&sk->dev);
	ಮುಕ್ತ(sk->path);
	ಮುಕ್ತ(sk);
}

ಸ್ಥಿರ ಸಂರಚನಾ sk_usbhid **
sk_openv(ಧ್ರುವ fido_dev_info_t *devlist, size_t ndevs, size_t *nopen)
{
	ಧ್ರುವ fido_dev_info_t *di;
	ಸಂರಚನಾ sk_usbhid **skv;
	size_t i;

	*nopen = 0;
	ಯದಿ ((skv = calloc(ndevs, ಪರಿಮಾಣ(*skv))) == ರಿಕ್ತ) {
		skdebug(__func__, "calloc skv failed");
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಪ್ರತಿ (i = 0; i < ndevs; i++) {
		ಯದಿ ((di = fido_dev_info_ptr(devlist, i)) == ರಿಕ್ತ)
			skdebug(__func__, "fido_dev_info_ptr failed");
		ಅನ್ಯಥಾ ಯದಿ ((skv[*nopen] = sk_open(fido_dev_info_path(di))) == ರಿಕ್ತ)
			skdebug(__func__, "sk_open failed");
		ಅನ್ಯಥಾ
			(*nopen)++;
	}
	ಯದಿ (*nopen == 0) {
		ಪ್ರತಿ (i = 0; i < ndevs; i++)
			sk_close(skv[i]);
		ಮುಕ್ತ(skv);
		skv = ರಿಕ್ತ;
	}

	ಪ್ರತ್ಯಾಗಮ skv;
}

ಸ್ಥಿರ ಶೂನ್ಯ
sk_closev(ಸಂರಚನಾ sk_usbhid **skv, size_t nsk)
{
	size_t i;

	ಪ್ರತಿ (i = 0; i < nsk; i++)
		sk_close(skv[i]);
	ಮುಕ್ತ(skv);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sk_touch_begin(ಸಂರಚನಾ sk_usbhid **skv, size_t nsk)
{
	size_t i, ok = 0;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಪ್ರತಿ (i = 0; i < nsk; i++)
		ಯದಿ ((r = fido_dev_get_touch_begin(skv[i]->dev)) != FIDO_OK)
			skdebug(__func__, "fido_dev_get_touch_begin %s failed:"
			    " %s", skv[i]->path, fido_strerr(r));
		ಅನ್ಯಥಾ
			ok++;

	ಪ್ರತ್ಯಾಗಮ ok ? 0 : -1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sk_touch_poll(ಸಂರಚನಾ sk_usbhid **skv, size_t nsk, ಪೂರ್ಣಾಙ್ಕ *touch, size_t *idx)
{
	ಸಂರಚನಾ timespec ts_pause;
	size_t npoll, i;
	ಪೂರ್ಣಾಙ್ಕ r;

	ts_pause.tv_sec = 0;
	ts_pause.tv_nsec = POLL_SLEEP_NS;
	nanosleep(&ts_pause, ರಿಕ್ತ);
	npoll = nsk;
	ಪ್ರತಿ (i = 0; i < nsk; i++) {
		ಯದಿ (skv[i] == ರಿಕ್ತ)
			ಅನುವರ್ತ; /* device discarded */
		skdebug(__func__, "polling %s", skv[i]->path);
		ಯದಿ ((r = fido_dev_get_touch_status(skv[i]->dev, touch,
		    FIDO_POLL_MS)) != FIDO_OK) {
			skdebug(__func__, "fido_dev_get_touch_status %s: %s",
			    skv[i]->path, fido_strerr(r));
			sk_close(skv[i]); /* discard device */
			skv[i] = ರಿಕ್ತ;
			ಯದಿ (--npoll == 0) {
				skdebug(__func__, "no device left to poll");
				ಪ್ರತ್ಯಾಗಮ -1;
			}
		} ಅನ್ಯಥಾ ಯದಿ (*touch) {
			*idx = i;
			ಪ್ರತ್ಯಾಗಮ 0;
		}
	}
	*touch = 0;
	ಪ್ರತ್ಯಾಗಮ 0;
}

#ಯದಿ !defined(HAVE_FIDO_ASSERT_SET_CLIENTDATA) || \
    !defined(HAVE_FIDO_CRED_SET_CLIENTDATA)
/* Calculate SHA256(m) */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sha256_mem(ಧ್ರುವ ಶೂನ್ಯ *m, size_t mlen, u_char *d, size_t dlen)
{
#ifdef WITH_OPENSSL
	u_int mdlen;
#ಅನ್ಯಥಾ
	SHA2_CTX ctx;
#endif

	ಯದಿ (dlen != 32)
		ಪ್ರತ್ಯಾಗಮ -1;
#ifdef WITH_OPENSSL
	mdlen = dlen;
	ಯದಿ (!EVP_Digest(m, mlen, d, &mdlen, EVP_sha256(), ರಿಕ್ತ))
		ಪ್ರತ್ಯಾಗಮ -1;
#ಅನ್ಯಥಾ
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ಧ್ರುವ uint8_t *)m, mlen);
	SHA256Final(d, &ctx);
#endif
	ಪ್ರತ್ಯಾಗಮ 0;
}
#endif /* !HAVE_FIDO_ASSERT_SET_CLIENTDATA || !HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_CRED_SET_CLIENTDATA
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
fido_cred_set_clientdata(fido_cred_t *cred, ಧ್ರುವ u_char *ptr, size_t len)
{
	uint8_t d[32];
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (sha256_mem(ptr, len, d, ಪರಿಮಾಣ(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		ಪ್ರತ್ಯಾಗಮ FIDO_ERR_INTERNAL;
	}
	r = fido_cred_set_clientdata_hash(cred, d, ಪರಿಮಾಣ(d));
	explicit_bzero(d, ಪರಿಮಾಣ(d));
	ಯದಿ (r != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	ಪ್ರತ್ಯಾಗಮ r;
}
#endif /* HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_ASSERT_SET_CLIENTDATA
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
fido_assert_set_clientdata(fido_assert_t *ಪ್ರತಿಜ್ಞಾ, ಧ್ರುವ u_char *ptr, size_t len)
{
	uint8_t d[32];
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (sha256_mem(ptr, len, d, ಪರಿಮಾಣ(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		ಪ್ರತ್ಯಾಗಮ FIDO_ERR_INTERNAL;
	}
	r = fido_assert_set_clientdata_hash(ಪ್ರತಿಜ್ಞಾ, d, ಪರಿಮಾಣ(d));
	explicit_bzero(d, ಪರಿಮಾಣ(d));
	ಯದಿ (r != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	ಪ್ರತ್ಯಾಗಮ r;
}
#endif /* HAVE_FIDO_ASSERT_SET_CLIENTDATA */

#ifndef HAVE_FIDO_DEV_IS_WINHELLO
ಸ್ಥಿರ bool
fido_dev_is_winhello(ಧ್ರುವ fido_dev_t *fdev)
{
	ಪ್ರತ್ಯಾಗಮ 0;
}
#endif /* HAVE_FIDO_DEV_IS_WINHELLO */

/* Check if the specified key handle exists on a given sk. */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sk_try(ಧ್ರುವ ಸಂರಚನಾ sk_usbhid *sk, ಧ್ರುವ ವರ್ಣ *application,
    ಧ್ರುವ uint8_t *ಕೀಲಿ_handle, size_t ಕೀಲಿ_handle_len)
{
	fido_assert_t *ಪ್ರತಿಜ್ಞಾ = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = FIDO_ERR_INTERNAL;
	uint8_t message[32];

	memset(message, '\0', ಪರಿಮಾಣ(message));
	ಯದಿ ((ಪ್ರತಿಜ್ಞಾ = fido_assert_new()) == ರಿಕ್ತ) {
		skdebug(__func__, "fido_assert_new failed");
		ಗಚ್ಛ out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	ಯದಿ ((r = fido_assert_set_clientdata(ಪ್ರತಿಜ್ಞಾ, message,
	    ಪರಿಮಾಣ(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = fido_assert_set_rp(ಪ್ರತಿಜ್ಞಾ, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = fido_assert_allow_cred(ಪ್ರತಿಜ್ಞಾ, ಕೀಲಿ_handle,
	    ಕೀಲಿ_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = fido_assert_set_up(ಪ್ರತಿಜ್ಞಾ, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_up: %s", fido_strerr(r));
		ಗಚ್ಛ out;
	}
	r = fido_dev_get_assert(sk->dev, ಪ್ರತಿಜ್ಞಾ, ರಿಕ್ತ);
	skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
	ಯದಿ (r == FIDO_ERR_USER_PRESENCE_REQUIRED) {
		/* U2F tokens may return this */
		r = FIDO_OK;
	}
 out:
	fido_assert_free(&ಪ್ರತಿಜ್ಞಾ);

	ಪ್ರತ್ಯಾಗಮ r != FIDO_OK ? -1 : 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
check_sk_options(fido_dev_t *dev, ಧ್ರುವ ವರ್ಣ *opt, ಪೂರ್ಣಾಙ್ಕ *ret)
{
	fido_cbor_info_t *info;
	ವರ್ಣ * ಧ್ರುವ *name;
	ಧ್ರುವ bool *ಮೌಲ್ಯ;
	size_t len, i;
	ಪೂರ್ಣಾಙ್ಕ r;

	*ret = -1;

	ಯದಿ (!fido_dev_is_fido2(dev)) {
		skdebug(__func__, "device is not fido2");
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಯದಿ ((info = fido_cbor_info_new()) == ರಿಕ್ತ) {
		skdebug(__func__, "fido_cbor_info_new failed");
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ ((r = fido_dev_get_cbor_info(dev, info)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_cbor_info: %s", fido_strerr(r));
		fido_cbor_info_free(&info);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	name = fido_cbor_info_options_name_ptr(info);
	ಮೌಲ್ಯ = fido_cbor_info_options_ಮೌಲ್ಯ_ptr(info);
	len = fido_cbor_info_options_len(info);
	ಪ್ರತಿ (i = 0; i < len; i++) {
		ಯದಿ (!strcmp(name[i], opt)) {
			*ret = ಮೌಲ್ಯ[i];
			ಭಙ್ಗ;
		}
	}
	fido_cbor_info_free(&info);
	ಯದಿ (*ret == -1)
		skdebug(__func__, "option %s is unknown", opt);
	ಅನ್ಯಥಾ
		skdebug(__func__, "option %s is %s", opt, *ret ? "on" : "off");

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಸಂರಚನಾ sk_usbhid *
sk_select_by_cred(ಧ್ರುವ fido_dev_info_t *devlist, size_t ndevs,
    ಧ್ರುವ ವರ್ಣ *application, ಧ್ರುವ uint8_t *ಕೀಲಿ_handle, size_t ಕೀಲಿ_handle_len)
{
	ಸಂರಚನಾ sk_usbhid **skv, *sk;
	size_t skvcnt, i;
	ಪೂರ್ಣಾಙ್ಕ internal_uv;

	ಯದಿ ((skv = sk_openv(devlist, ndevs, &skvcnt)) == ರಿಕ್ತ) {
		skdebug(__func__, "sk_openv failed");
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ (skvcnt == 1 && check_sk_options(skv[0]->dev, "uv",
	    &internal_uv) == 0 && internal_uv != -1) {
		sk = skv[0];
		skv[0] = ರಿಕ್ತ;
		ಗಚ್ಛ out;
	}
	sk = ರಿಕ್ತ;
	ಪ್ರತಿ (i = 0; i < skvcnt; i++) {
		ಯದಿ (sk_try(skv[i], application, ಕೀಲಿ_handle,
		    ಕೀಲಿ_handle_len) == 0) {
			sk = skv[i];
			skv[i] = ರಿಕ್ತ;
			skdebug(__func__, "found key in %s", sk->path);
			ಭಙ್ಗ;
		}
	}
 out:
	sk_closev(skv, skvcnt);
	ಪ್ರತ್ಯಾಗಮ sk;
}

ಸ್ಥಿರ ಸಂರಚನಾ sk_usbhid *
sk_select_by_touch(ಧ್ರುವ fido_dev_info_t *devlist, size_t ndevs)
{
	ಸಂರಚನಾ sk_usbhid **skv, *sk;
	ಸಂರಚನಾ timeval tv_start, tv_now, tv_delta;
	size_t skvcnt, idx;
	ಪೂರ್ಣಾಙ್ಕ touch, ms_remain;

	ಯದಿ ((skv = sk_openv(devlist, ndevs, &skvcnt)) == ರಿಕ್ತ) {
		skdebug(__func__, "sk_openv failed");
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	sk = ರಿಕ್ತ;
	ಯದಿ (skvcnt < 2) {
		ಯದಿ (skvcnt == 1) {
			/* single candidate */
			sk = skv[0];
			skv[0] = ರಿಕ್ತ;
		}
		ಗಚ್ಛ out;
	}
#ifndef HAVE_FIDO_DEV_GET_TOUCH_STATUS
	skdebug(__func__, "libfido2 version does not support a feature needed for multiple tokens. Please upgrade to >=1.5.0");
	ಗಚ್ಛ out;
#endif

	ಯದಿ (sk_touch_begin(skv, skvcnt) == -1) {
		skdebug(__func__, "sk_touch_begin failed");
		ಗಚ್ಛ out;
	}
	monotime_tv(&tv_start);
	ಕುರು {
		ಯದಿ (sk_touch_poll(skv, skvcnt, &touch, &idx) == -1) {
			skdebug(__func__, "sk_touch_poll failed");
			ಗಚ್ಛ out;
		}
		ಯದಿ (touch) {
			sk = skv[idx];
			skv[idx] = ರಿಕ್ತ;
			ಗಚ್ಛ out;
		}
		monotime_tv(&tv_now);
		timersub(&tv_now, &tv_start, &tv_delta);
		ms_remain = SELECT_MS - tv_delta.tv_sec * 1000 -
		    tv_delta.tv_usec / 1000;
	} ಯಾವತ್ (ms_remain >= FIDO_POLL_MS);
	skdebug(__func__, "timeout");
out:
	sk_closev(skv, skvcnt);
	ಪ್ರತ್ಯಾಗಮ sk;
}

ಸ್ಥಿರ ಸಂರಚನಾ sk_usbhid *
sk_probe(ಧ್ರುವ ವರ್ಣ *application, ಧ್ರುವ uint8_t *ಕೀಲಿ_handle,
    size_t ಕೀಲಿ_handle_len, ಪೂರ್ಣಾಙ್ಕ probe_resident)
{
	ಸಂರಚನಾ sk_usbhid *sk;
	fido_dev_info_t *devlist;
	size_t ndevs;
	ಪೂರ್ಣಾಙ್ಕ r;

#ifdef HAVE_CYGWIN
	ಯದಿ (!probe_resident && (sk = sk_open("windows://hello")) != ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ sk;
#endif /* HAVE_CYGWIN */
	ಯದಿ ((devlist = fido_dev_info_new(MAX_FIDO_DEVICES)) == ರಿಕ್ತ) {
		skdebug(__func__, "fido_dev_info_new failed");
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ ((r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES,
	    &ndevs)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_info_manifest failed: %s",
		    fido_strerr(r));
		fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	skdebug(__func__, "%zu device(s) detected", ndevs);
	ಯದಿ (ndevs == 0) {
		sk = ರಿಕ್ತ;
	} ಅನ್ಯಥಾ ಯದಿ (application != ರಿಕ್ತ && ಕೀಲಿ_handle != ರಿಕ್ತ) {
		skdebug(__func__, "selecting sk by cred");
		sk = sk_select_by_cred(devlist, ndevs, application, ಕೀಲಿ_handle,
		    ಕೀಲಿ_handle_len);
	} ಅನ್ಯಥಾ {
		skdebug(__func__, "selecting sk by touch");
		sk = sk_select_by_touch(devlist, ndevs);
	}
	fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
	ಪ್ರತ್ಯಾಗಮ sk;
}

#ifdef WITH_OPENSSL
/*
 * The key returned via fido_cred_pubkey_ptr() is in affine coordinates,
 * but the API expects a SEC1 octet string.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pack_public_ಕೀಲಿ_ecdsa(ಧ್ರುವ fido_cred_t *cred,
    ಸಂರಚನಾ sk_enroll_response *response)
{
	ಧ್ರುವ uint8_t *ptr;
	BIGNUM *x = ರಿಕ್ತ, *y = ರಿಕ್ತ;
	EC_POINT *q = ರಿಕ್ತ;
	EC_GROUP *g = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ ret = -1;

	response->public_ಕೀಲಿ = ರಿಕ್ತ;
	response->public_ಕೀಲಿ_len = 0;

	ಯದಿ ((x = BN_new()) == ರಿಕ್ತ ||
	    (y = BN_new()) == ರಿಕ್ತ ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == ರಿಕ್ತ ||
	    (q = EC_POINT_new(g)) == ರಿಕ್ತ) {
		skdebug(__func__, "libcrypto setup failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((ptr = fido_cred_pubkey_ptr(cred)) == ರಿಕ್ತ) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ (fido_cred_pubkey_len(cred) != 64) {
		skdebug(__func__, "bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		ಗಚ್ಛ out;
	}

	ಯದಿ (BN_bin2bn(ptr, 32, x) == ರಿಕ್ತ ||
	    BN_bin2bn(ptr + 32, 32, y) == ರಿಕ್ತ) {
		skdebug(__func__, "BN_bin2bn failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ (EC_POINT_set_affine_coordinates(g, q, x, y, ರಿಕ್ತ) != 1) {
		skdebug(__func__, "EC_POINT_set_affine_coordinates failed");
		ಗಚ್ಛ out;
	}
	response->public_ಕೀಲಿ_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, ರಿಕ್ತ, 0, ರಿಕ್ತ);
	ಯದಿ (response->public_ಕೀಲಿ_len == 0 || response->public_ಕೀಲಿ_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_ಕೀಲಿ_len);
		ಗಚ್ಛ out;
	}
	ಯದಿ ((response->public_ಕೀಲಿ = malloc(response->public_ಕೀಲಿ_len)) == ರಿಕ್ತ) {
		skdebug(__func__, "malloc pubkey failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_ಕೀಲಿ, response->public_ಕೀಲಿ_len, ರಿಕ್ತ) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		ಗಚ್ಛ out;
	}
	/* success */
	ret = 0;
 out:
	ಯದಿ (ret != 0 && response->public_ಕೀಲಿ != ರಿಕ್ತ) {
		memset(response->public_ಕೀಲಿ, 0, response->public_ಕೀಲಿ_len);
		ಮುಕ್ತ(response->public_ಕೀಲಿ);
		response->public_ಕೀಲಿ = ರಿಕ್ತ;
	}
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	ಪ್ರತ್ಯಾಗಮ ret;
}
#endif /* WITH_OPENSSL */

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pack_public_ಕೀಲಿ_ed25519(ಧ್ರುವ fido_cred_t *cred,
    ಸಂರಚನಾ sk_enroll_response *response)
{
	ಧ್ರುವ uint8_t *ptr;
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ ret = -1;

	response->public_ಕೀಲಿ = ರಿಕ್ತ;
	response->public_ಕೀಲಿ_len = 0;

	ಯದಿ ((len = fido_cred_pubkey_len(cred)) != 32) {
		skdebug(__func__, "bad fido_cred_pubkey_len len %zu", len);
		ಗಚ್ಛ out;
	}
	ಯದಿ ((ptr = fido_cred_pubkey_ptr(cred)) == ರಿಕ್ತ) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		ಗಚ್ಛ out;
	}
	response->public_ಕೀಲಿ_len = len;
	ಯದಿ ((response->public_ಕೀಲಿ = malloc(response->public_ಕೀಲಿ_len)) == ರಿಕ್ತ) {
		skdebug(__func__, "malloc pubkey failed");
		ಗಚ್ಛ out;
	}
	memcpy(response->public_ಕೀಲಿ, ptr, len);
	ret = 0;
 out:
	ಯದಿ (ret != 0)
		ಮುಕ್ತ(response->public_ಕೀಲಿ);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pack_public_ಕೀಲಿ(uint32_t alg, ಧ್ರುವ fido_cred_t *cred,
    ಸಂರಚನಾ sk_enroll_response *response)
{
	ವಿಕಲ್ಪ(alg) {
#ifdef WITH_OPENSSL
	ಪಕ್ಷ SSH_SK_ECDSA:
		ಪ್ರತ್ಯಾಗಮ pack_public_ಕೀಲಿ_ecdsa(cred, response);
#endif /* WITH_OPENSSL */
	ಪಕ್ಷ SSH_SK_ED25519:
		ಪ್ರತ್ಯಾಗಮ pack_public_ಕೀಲಿ_ed25519(cred, response);
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ -1;
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
fidoerr_to_skerr(ಪೂರ್ಣಾಙ್ಕ fidoerr)
{
	ವಿಕಲ್ಪ (fidoerr) {
	ಪಕ್ಷ FIDO_ERR_UNSUPPORTED_OPTION:
	ಪಕ್ಷ FIDO_ERR_UNSUPPORTED_ALGORITHM:
		ಪ್ರತ್ಯಾಗಮ SSH_SK_ERR_UNSUPPORTED;
	ಪಕ್ಷ FIDO_ERR_PIN_REQUIRED:
	ಪಕ್ಷ FIDO_ERR_PIN_INVALID:
	ಪಕ್ಷ FIDO_ERR_OPERATION_DENIED:
		ಪ್ರತ್ಯಾಗಮ SSH_SK_ERR_PIN_REQUIRED;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ -1;
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
check_enroll_options(ಸಂರಚನಾ sk_option **options, ವರ್ಣ **devicep,
    uint8_t *user_id, size_t user_id_len)
{
	size_t i;

	ಯದಿ (options == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತಿ (i = 0; options[i] != ರಿಕ್ತ; i++) {
		ಯದಿ (strcmp(options[i]->name, "device") == 0) {
			ಯದಿ ((*devicep = strdup(options[i]->ಮೌಲ್ಯ)) == ರಿಕ್ತ) {
				skdebug(__func__, "strdup device failed");
				ಪ್ರತ್ಯಾಗಮ -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} ಅನ್ಯಥಾ ಯದಿ (strcmp(options[i]->name, "user") == 0) {
			ಯದಿ (strlcpy(user_id, options[i]->ಮೌಲ್ಯ, user_id_len) >=
			    user_id_len) {
				skdebug(__func__, "user too long");
				ಪ್ರತ್ಯಾಗಮ -1;
			}
			skdebug(__func__, "requested user %s",
			    (ವರ್ಣ *)user_id);
		} ಅನ್ಯಥಾ {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			ಯದಿ (options[i]->required) {
				skdebug(__func__, "unknown required option");
				ಪ್ರತ್ಯಾಗಮ -1;
			}
		}
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಕೀಲಿ_lookup(fido_dev_t *dev, ಧ್ರುವ ವರ್ಣ *application, ಧ್ರುವ uint8_t *user_id,
    size_t user_id_len, ಧ್ರುವ ವರ್ಣ *pin)
{
	fido_assert_t *ಪ್ರತಿಜ್ಞಾ = ರಿಕ್ತ;
	uint8_t message[32];
	ಪೂರ್ಣಾಙ್ಕ r = FIDO_ERR_INTERNAL;
	ಪೂರ್ಣಾಙ್ಕ sk_supports_uv, uv;
	size_t i;

	memset(message, '\0', ಪರಿಮಾಣ(message));
	ಯದಿ ((ಪ್ರತಿಜ್ಞಾ = fido_assert_new()) == ರಿಕ್ತ) {
		skdebug(__func__, "fido_assert_new failed");
		ಗಚ್ಛ out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	ಯದಿ ((r = fido_assert_set_clientdata(ಪ್ರತಿಜ್ಞಾ, message,
	    ಪರಿಮಾಣ(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = fido_assert_set_rp(ಪ್ರತಿಜ್ಞಾ, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = fido_assert_set_up(ಪ್ರತಿಜ್ಞಾ, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		ಗಚ್ಛ out;
	}
	uv = FIDO_OPT_OMIT;
	ಯದಿ (pin == ರಿಕ್ತ && check_sk_options(dev, "uv", &sk_supports_uv) == 0 &&
	    sk_supports_uv != -1)
		uv = FIDO_OPT_TRUE;
	ಯದಿ ((r = fido_assert_set_uv(ಪ್ರತಿಜ್ಞಾ, uv)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = fido_dev_get_assert(dev, ಪ್ರತಿಜ್ಞಾ, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ಗಚ್ಛ out;
	}
	r = FIDO_ERR_NO_CREDENTIALS;
	skdebug(__func__, "%zu signatures returned", fido_assert_ಎಣಿಕೆ(ಪ್ರತಿಜ್ಞಾ));
	ಪ್ರತಿ (i = 0; i < fido_assert_ಎಣಿಕೆ(ಪ್ರತಿಜ್ಞಾ); i++) {
		ಯದಿ (fido_assert_user_id_len(ಪ್ರತಿಜ್ಞಾ, i) == user_id_len &&
		    memcmp(fido_assert_user_id_ptr(ಪ್ರತಿಜ್ಞಾ, i), user_id,
		    user_id_len) == 0) {
			skdebug(__func__, "credential exists");
			r = FIDO_OK;
			ಗಚ್ಛ out;
		}
	}
 out:
	fido_assert_free(&ಪ್ರತಿಜ್ಞಾ);

	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sk_enroll(uint32_t alg, ಧ್ರುವ uint8_t *challenge, size_t challenge_len,
    ಧ್ರುವ ವರ್ಣ *application, uint8_t flags, ಧ್ರುವ ವರ್ಣ *pin,
    ಸಂರಚನಾ sk_option **options, ಸಂರಚನಾ sk_enroll_response **enroll_response)
{
	fido_cred_t *cred = ರಿಕ್ತ;
	ಧ್ರುವ uint8_t *ptr;
	uint8_t user_id[32];
	ಸಂರಚನಾ sk_usbhid *sk = ರಿಕ್ತ;
	ಸಂರಚನಾ sk_enroll_response *response = ರಿಕ್ತ;
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ credprot;
	ಪೂರ್ಣಾಙ್ಕ cose_alg;
	ಪೂರ್ಣಾಙ್ಕ ret = SSH_SK_ERR_GENERAL;
	ಪೂರ್ಣಾಙ್ಕ r;
	ವರ್ಣ *device = ರಿಕ್ತ;

	fido_init(SSH_FIDO_INIT_ARG);

	ಯದಿ (enroll_response == ರಿಕ್ತ) {
		skdebug(__func__, "enroll_response == NULL");
		ಗಚ್ಛ out;
	}
	*enroll_response = ರಿಕ್ತ;
	memset(user_id, 0, ಪರಿಮಾಣ(user_id));
	ಯದಿ (check_enroll_options(options, &device, user_id,
	    ಪರಿಮಾಣ(user_id)) != 0)
		ಗಚ್ಛ out; /* error already logged */

	ವಿಕಲ್ಪ(alg) {
#ifdef WITH_OPENSSL
	ಪಕ್ಷ SSH_SK_ECDSA:
		cose_alg = COSE_ES256;
		ಭಙ್ಗ;
#endif /* WITH_OPENSSL */
	ಪಕ್ಷ SSH_SK_ED25519:
		cose_alg = COSE_EDDSA;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		skdebug(__func__, "unsupported key type %d", alg);
		ಗಚ್ಛ out;
	}
	ಯದಿ (device != ರಿಕ್ತ)
		sk = sk_open(device);
	ಅನ್ಯಥಾ
		sk = sk_probe(ರಿಕ್ತ, ರಿಕ್ತ, 0, 0);
	ಯದಿ (sk == ರಿಕ್ತ) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		ಗಚ್ಛ out;
	}
	skdebug(__func__, "using device %s", sk->path);
	ಯದಿ ((flags & SSH_SK_RESIDENT_ಕೀಲಿ) != 0 &&
	    (flags & SSH_SK_FORCE_OPERATION) == 0 &&
	    (r = ಕೀಲಿ_lookup(sk->dev, application, user_id, ಪರಿಮಾಣ(user_id),
	    pin)) != FIDO_ERR_NO_CREDENTIALS) {
		ಯದಿ (r != FIDO_OK) {
			ret = fidoerr_to_skerr(r);
			skdebug(__func__, "key_lookup failed");
		} ಅನ್ಯಥಾ {
			ret = SSH_SK_ERR_CREDENTIAL_EXISTS;
			skdebug(__func__, "key exists");
		}
		ಗಚ್ಛ out;
	}
	ಯದಿ ((cred = fido_cred_new()) == ರಿಕ್ತ) {
		skdebug(__func__, "fido_cred_new failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = fido_cred_set_type(cred, cose_alg)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_type: %s", fido_strerr(r));
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = fido_cred_set_clientdata(cred,
	    challenge, challenge_len)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata: %s",
		    fido_strerr(r));
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = fido_cred_set_rk(cred, (flags & SSH_SK_RESIDENT_ಕೀಲಿ) != 0 ?
	    FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rk: %s", fido_strerr(r));
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = fido_cred_set_user(cred, user_id, ಪರಿಮಾಣ(user_id),
	    "openssh", "openssh", ರಿಕ್ತ)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_user: %s", fido_strerr(r));
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = fido_cred_set_rp(cred, application, ರಿಕ್ತ)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rp: %s", fido_strerr(r));
		ಗಚ್ಛ out;
	}
	ಯದಿ ((flags & (SSH_SK_RESIDENT_ಕೀಲಿ|SSH_SK_USER_VERIFICATION_REQD)) != 0) {
#ಯದಿ !defined(HAVE_FIDO_DEV_SUPPORTS_CRED_PROT) || \
    !defined(HAVE_FIDO_CRED_SET_PROT)
		skdebug(__func__, "libfido2 version does not support a feature required for this operation. Please upgrade to >=1.5.0");
		ret = SSH_SK_ERR_UNSUPPORTED;
		ಗಚ್ಛ out;
		credprot = 0; (ಶೂನ್ಯ)credprot; /* avoid warning */
#endif
		ಯದಿ (!fido_dev_supports_cred_prot(sk->dev)) {
			skdebug(__func__, "%s does not support credprot, "
			    "refusing to create unprotected "
			    "resident/verify-required key", sk->path);
			ret = SSH_SK_ERR_UNSUPPORTED;
			ಗಚ್ಛ out;
		}
		ಯದಿ ((flags & SSH_SK_USER_VERIFICATION_REQD))
			credprot = FIDO_CRED_PROT_UV_REQUIRED;
		ಅನ್ಯಥಾ
			credprot = FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID;

		ಯದಿ ((r = fido_cred_set_prot(cred, credprot)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_set_prot: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			ಗಚ್ಛ out;
		}
	}
	ಯದಿ ((r = fido_dev_make_cred(sk->dev, cred, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_make_cred: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		ಗಚ್ಛ out;
	}
	ಯದಿ (fido_cred_x5c_ptr(cred) != ರಿಕ್ತ) {
		ಯದಿ ((r = fido_cred_verify(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify: %s",
			    fido_strerr(r));
			ಗಚ್ಛ out;
		}
	} ಅನ್ಯಥಾ ಯದಿ (strcmp(fido_cred_fmt(cred), "none") != 0) {
		skdebug(__func__, "self-attested credential");
		ಯದಿ ((r = fido_cred_verify_self(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify_self: %s",
			    fido_strerr(r));
			ಗಚ್ಛ out;
		}
	} ಅನ್ಯಥಾ {
		skdebug(__func__, "no attestation data");
	}
	ಯದಿ ((response = calloc(1, ಪರಿಮಾಣ(*response))) == ರಿಕ್ತ) {
		skdebug(__func__, "calloc response failed");
		ಗಚ್ಛ out;
	}
	response->flags = flags;
	ಯದಿ (pack_public_ಕೀಲಿ(alg, cred, response) != 0) {
		skdebug(__func__, "pack_public_key failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((ptr = fido_cred_id_ptr(cred)) != ರಿಕ್ತ) {
		len = fido_cred_id_len(cred);
		ಯದಿ ((response->ಕೀಲಿ_handle = calloc(1, len)) == ರಿಕ್ತ) {
			skdebug(__func__, "calloc key handle failed");
			ಗಚ್ಛ out;
		}
		memcpy(response->ಕೀಲಿ_handle, ptr, len);
		response->ಕೀಲಿ_handle_len = len;
	}
	ಯದಿ ((ptr = fido_cred_sig_ptr(cred)) != ರಿಕ್ತ) {
		len = fido_cred_sig_len(cred);
		ಯದಿ ((response->signature = calloc(1, len)) == ರಿಕ್ತ) {
			skdebug(__func__, "calloc signature failed");
			ಗಚ್ಛ out;
		}
		memcpy(response->signature, ptr, len);
		response->signature_len = len;
	}
	ಯದಿ ((ptr = fido_cred_x5c_ptr(cred)) != ರಿಕ್ತ) {
		len = fido_cred_x5c_len(cred);
		skdebug(__func__, "attestation cert len=%zu", len);
		ಯದಿ ((response->attestation_cert = calloc(1, len)) == ರಿಕ್ತ) {
			skdebug(__func__, "calloc attestation cert failed");
			ಗಚ್ಛ out;
		}
		memcpy(response->attestation_cert, ptr, len);
		response->attestation_cert_len = len;
	}
	ಯದಿ ((ptr = fido_cred_authdata_ptr(cred)) != ರಿಕ್ತ) {
		len = fido_cred_authdata_len(cred);
		skdebug(__func__, "authdata len=%zu", len);
		ಯದಿ ((response->authdata = calloc(1, len)) == ರಿಕ್ತ) {
			skdebug(__func__, "calloc authdata failed");
			ಗಚ್ಛ out;
		}
		memcpy(response->authdata, ptr, len);
		response->authdata_len = len;
	}
	*enroll_response = response;
	response = ರಿಕ್ತ;
	ret = 0;
 out:
	ಮುಕ್ತ(device);
	ಯದಿ (response != ರಿಕ್ತ) {
		ಮುಕ್ತ(response->public_ಕೀಲಿ);
		ಮುಕ್ತ(response->ಕೀಲಿ_handle);
		ಮುಕ್ತ(response->signature);
		ಮುಕ್ತ(response->attestation_cert);
		ಮುಕ್ತ(response->authdata);
		ಮುಕ್ತ(response);
	}
	sk_close(sk);
	fido_cred_free(&cred);
	ಪ್ರತ್ಯಾಗಮ ret;
}

#ifdef WITH_OPENSSL
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pack_sig_ecdsa(fido_assert_t *ಪ್ರತಿಜ್ಞಾ, ಸಂರಚನಾ sk_sign_response *response)
{
	ECDSA_SIG *sig = ರಿಕ್ತ;
	ಧ್ರುವ BIGNUM *sig_r, *sig_s;
	ಧ್ರುವ unsigned ವರ್ಣ *cp;
	size_t sig_len;
	ಪೂರ್ಣಾಙ್ಕ ret = -1;

	cp = fido_assert_sig_ptr(ಪ್ರತಿಜ್ಞಾ, 0);
	sig_len = fido_assert_sig_len(ಪ್ರತಿಜ್ಞಾ, 0);
	ಯದಿ ((sig = d2i_ECDSA_SIG(ರಿಕ್ತ, &cp, sig_len)) == ರಿಕ್ತ) {
		skdebug(__func__, "d2i_ECDSA_SIG failed");
		ಗಚ್ಛ out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_ಅಂಕೆ_bytes(sig_r);
	response->sig_s_len = BN_ಅಂಕೆ_bytes(sig_s);
	ಯದಿ ((response->sig_r = calloc(1, response->sig_r_len)) == ರಿಕ್ತ ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == ರಿಕ್ತ) {
		skdebug(__func__, "calloc signature failed");
		ಗಚ್ಛ out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	ECDSA_SIG_free(sig);
	ಯದಿ (ret != 0) {
		ಮುಕ್ತ(response->sig_r);
		ಮುಕ್ತ(response->sig_s);
		response->sig_r = ರಿಕ್ತ;
		response->sig_s = ರಿಕ್ತ;
	}
	ಪ್ರತ್ಯಾಗಮ ret;
}
#endif /* WITH_OPENSSL */

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pack_sig_ed25519(fido_assert_t *ಪ್ರತಿಜ್ಞಾ, ಸಂರಚನಾ sk_sign_response *response)
{
	ಧ್ರುವ unsigned ವರ್ಣ *ptr;
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ ret = -1;

	ptr = fido_assert_sig_ptr(ಪ್ರತಿಜ್ಞಾ, 0);
	len = fido_assert_sig_len(ಪ್ರತಿಜ್ಞಾ, 0);
	ಯದಿ (len != 64) {
		skdebug(__func__, "bad length %zu", len);
		ಗಚ್ಛ out;
	}
	response->sig_r_len = len;
	ಯದಿ ((response->sig_r = calloc(1, response->sig_r_len)) == ರಿಕ್ತ) {
		skdebug(__func__, "calloc signature failed");
		ಗಚ್ಛ out;
	}
	memcpy(response->sig_r, ptr, len);
	ret = 0;
 out:
	ಯದಿ (ret != 0) {
		ಮುಕ್ತ(response->sig_r);
		response->sig_r = ರಿಕ್ತ;
	}
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pack_sig(uint32_t  alg, fido_assert_t *ಪ್ರತಿಜ್ಞಾ,
    ಸಂರಚನಾ sk_sign_response *response)
{
	ವಿಕಲ್ಪ(alg) {
#ifdef WITH_OPENSSL
	ಪಕ್ಷ SSH_SK_ECDSA:
		ಪ್ರತ್ಯಾಗಮ pack_sig_ecdsa(ಪ್ರತಿಜ್ಞಾ, response);
#endif /* WITH_OPENSSL */
	ಪಕ್ಷ SSH_SK_ED25519:
		ಪ್ರತ್ಯಾಗಮ pack_sig_ed25519(ಪ್ರತಿಜ್ಞಾ, response);
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ -1;
	}
}

/* Checks sk_options for sk_sign() and sk_load_resident_keys() */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
check_sign_load_resident_options(ಸಂರಚನಾ sk_option **options, ವರ್ಣ **devicep)
{
	size_t i;

	ಯದಿ (options == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತಿ (i = 0; options[i] != ರಿಕ್ತ; i++) {
		ಯದಿ (strcmp(options[i]->name, "device") == 0) {
			ಯದಿ ((*devicep = strdup(options[i]->ಮೌಲ್ಯ)) == ರಿಕ್ತ) {
				skdebug(__func__, "strdup device failed");
				ಪ್ರತ್ಯಾಗಮ -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} ಅನ್ಯಥಾ {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			ಯದಿ (options[i]->required) {
				skdebug(__func__, "unknown required option");
				ಪ್ರತ್ಯಾಗಮ -1;
			}
		}
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sk_sign(uint32_t alg, ಧ್ರುವ uint8_t *data, size_t datalen,
    ಧ್ರುವ ವರ್ಣ *application,
    ಧ್ರುವ uint8_t *ಕೀಲಿ_handle, size_t ಕೀಲಿ_handle_len,
    uint8_t flags, ಧ್ರುವ ವರ್ಣ *pin, ಸಂರಚನಾ sk_option **options,
    ಸಂರಚನಾ sk_sign_response **sign_response)
{
	fido_assert_t *ಪ್ರತಿಜ್ಞಾ = ರಿಕ್ತ;
	ವರ್ಣ *device = ರಿಕ್ತ;
	ಸಂರಚನಾ sk_usbhid *sk = ರಿಕ್ತ;
	ಸಂರಚನಾ sk_sign_response *response = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ ret = SSH_SK_ERR_GENERAL, internal_uv;
	ಪೂರ್ಣಾಙ್ಕ r;

	fido_init(SSH_FIDO_INIT_ARG);

	ಯದಿ (sign_response == ರಿಕ್ತ) {
		skdebug(__func__, "sign_response == NULL");
		ಗಚ್ಛ out;
	}
	*sign_response = ರಿಕ್ತ;
	ಯದಿ (check_sign_load_resident_options(options, &device) != 0)
		ಗಚ್ಛ out; /* error already logged */
	ಯದಿ (device != ರಿಕ್ತ)
		sk = sk_open(device);
	ಅನ್ಯಥಾ ಯದಿ (pin != ರಿಕ್ತ || (flags & SSH_SK_USER_VERIFICATION_REQD))
		sk = sk_probe(ರಿಕ್ತ, ರಿಕ್ತ, 0, 0);
	ಅನ್ಯಥಾ
		sk = sk_probe(application, ಕೀಲಿ_handle, ಕೀಲಿ_handle_len, 0);
	ಯದಿ (sk == ರಿಕ್ತ) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((ಪ್ರತಿಜ್ಞಾ = fido_assert_new()) == ರಿಕ್ತ) {
		skdebug(__func__, "fido_assert_new failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = fido_assert_set_clientdata(ಪ್ರತಿಜ್ಞಾ,
	    data, datalen)) != FIDO_OK)  {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = fido_assert_set_rp(ಪ್ರತಿಜ್ಞಾ, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = fido_assert_allow_cred(ಪ್ರತಿಜ್ಞಾ, ಕೀಲಿ_handle,
	    ಕೀಲಿ_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = fido_assert_set_up(ಪ್ರತಿಜ್ಞಾ,
	    (flags & SSH_SK_USER_PRESENCE_REQD) ?
	    FIDO_OPT_TRUE : FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		ಗಚ್ಛ out;
	}
	/*
	 * WinHello requests the PIN by default.  Make "uv" request explicit
	 * to allow keys with and without -O verify-required to make sense.
	 */
	ಯದಿ (pin == ರಿಕ್ತ && fido_dev_is_winhello (sk->dev) &&
	    (r = fido_assert_set_uv(ಪ್ರತಿಜ್ಞಾ, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
	}
	ಯದಿ (pin == ರಿಕ್ತ && (flags & SSH_SK_USER_VERIFICATION_REQD)) {
		ಯದಿ (check_sk_options(sk->dev, "uv", &internal_uv) < 0 ||
		    internal_uv != 1) {
			skdebug(__func__, "check_sk_options uv");
			ret = SSH_SK_ERR_PIN_REQUIRED;
			ಗಚ್ಛ out;
		}
		ಯದಿ ((r = fido_assert_set_uv(ಪ್ರತಿಜ್ಞಾ,
		    FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_assert_set_uv: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			ಗಚ್ಛ out;
		}
	}
	ಯದಿ ((r = fido_dev_get_assert(sk->dev, ಪ್ರತಿಜ್ಞಾ, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		ಗಚ್ಛ out;
	}
	ಯದಿ ((response = calloc(1, ಪರಿಮಾಣ(*response))) == ರಿಕ್ತ) {
		skdebug(__func__, "calloc response failed");
		ಗಚ್ಛ out;
	}
	response->flags = fido_assert_flags(ಪ್ರತಿಜ್ಞಾ, 0);
	response->counter = fido_assert_sigcount(ಪ್ರತಿಜ್ಞಾ, 0);
	ಯದಿ (pack_sig(alg, ಪ್ರತಿಜ್ಞಾ, response) != 0) {
		skdebug(__func__, "pack_sig failed");
		ಗಚ್ಛ out;
	}
	*sign_response = response;
	response = ರಿಕ್ತ;
	ret = 0;
 out:
	ಮುಕ್ತ(device);
	ಯದಿ (response != ರಿಕ್ತ) {
		ಮುಕ್ತ(response->sig_r);
		ಮುಕ್ತ(response->sig_s);
		ಮುಕ್ತ(response);
	}
	sk_close(sk);
	fido_assert_free(&ಪ್ರತಿಜ್ಞಾ);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
read_rks(ಸಂರಚನಾ sk_usbhid *sk, ಧ್ರುವ ವರ್ಣ *pin,
    ಸಂರಚನಾ sk_resident_ಕೀಲಿ ***rksp, size_t *nrksp)
{
	ಪೂರ್ಣಾಙ್ಕ ret = SSH_SK_ERR_GENERAL, r = -1;
	uint32_t alg;
	fido_credman_metadata_t *metadata = ರಿಕ್ತ;
	fido_credman_rp_t *rp = ರಿಕ್ತ;
	fido_credman_rk_t *rk = ರಿಕ್ತ;
	size_t i, j, nrp, nrk, user_id_len;
	ಧ್ರುವ fido_cred_t *cred;
	ಧ್ರುವ ವರ್ಣ *rp_id, *rp_name, *user_name;
	ಸಂರಚನಾ sk_resident_ಕೀಲಿ *srk = ರಿಕ್ತ, **tmp;
	ಧ್ರುವ u_char *user_id;

	ಯದಿ (pin == ರಿಕ್ತ) {
		skdebug(__func__, "no PIN specified");
		ret = SSH_SK_ERR_PIN_REQUIRED;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((metadata = fido_credman_metadata_new()) == ರಿಕ್ತ) {
		skdebug(__func__, "alloc failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = fido_credman_get_dev_metadata(sk->dev, metadata, pin)) != 0) {
		ಯದಿ (r == FIDO_ERR_INVALID_COMMAND) {
			skdebug(__func__, "device %s does not support "
			    "resident keys", sk->path);
			ret = 0;
			ಗಚ್ಛ out;
		}
		skdebug(__func__, "get metadata for %s failed: %s",
		    sk->path, fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		ಗಚ್ಛ out;
	}
	skdebug(__func__, "existing %llu, remaining %llu",
	    (unsigned long long)fido_credman_rk_existing(metadata),
	    (unsigned long long)fido_credman_rk_remaining(metadata));
	ಯದಿ ((rp = fido_credman_rp_new()) == ರಿಕ್ತ) {
		skdebug(__func__, "alloc rp failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = fido_credman_get_dev_rp(sk->dev, rp, pin)) != 0) {
		skdebug(__func__, "get RPs for %s failed: %s",
		    sk->path, fido_strerr(r));
		ಗಚ್ಛ out;
	}
	nrp = fido_credman_rp_ಎಣಿಕೆ(rp);
	skdebug(__func__, "Device %s has resident keys for %zu RPs",
	    sk->path, nrp);

	/* Iterate over RP IDs that have resident keys */
	ಪ್ರತಿ (i = 0; i < nrp; i++) {
		rp_id = fido_credman_rp_id(rp, i);
		rp_name = fido_credman_rp_name(rp, i);
		skdebug(__func__, "rp %zu: name=\"%s\" id=\"%s\" hashlen=%zu",
		    i, rp_name == ರಿಕ್ತ ? "(none)" : rp_name,
		    rp_id == ರಿಕ್ತ ? "(none)" : rp_id,
		    fido_credman_rp_id_hash_len(rp, i));

		/* Skip non-SSH RP IDs */
		ಯದಿ (rp_id == ರಿಕ್ತ ||
		    strncasecmp(fido_credman_rp_id(rp, i), "ssh:", 4) != 0)
			ಅನುವರ್ತ;

		fido_credman_rk_free(&rk);
		ಯದಿ ((rk = fido_credman_rk_new()) == ರಿಕ್ತ) {
			skdebug(__func__, "alloc rk failed");
			ಗಚ್ಛ out;
		}
		ಯದಿ ((r = fido_credman_get_dev_rk(sk->dev,
		    fido_credman_rp_id(rp, i), rk, pin)) != 0) {
			skdebug(__func__, "get RKs for %s slot %zu failed: %s",
			    sk->path, i, fido_strerr(r));
			ಗಚ್ಛ out;
		}
		nrk = fido_credman_rk_ಎಣಿಕೆ(rk);
		skdebug(__func__, "RP \"%s\" has %zu resident keys",
		    fido_credman_rp_id(rp, i), nrk);

		/* Iterate over resident keys for this RP ID */
		ಪ್ರತಿ (j = 0; j < nrk; j++) {
			ಯದಿ ((cred = fido_credman_rk(rk, j)) == ರಿಕ್ತ) {
				skdebug(__func__, "no RK in slot %zu", j);
				ಅನುವರ್ತ;
			}
			ಯದಿ ((user_name = fido_cred_user_name(cred)) == ರಿಕ್ತ)
				user_name = "";
			user_id = fido_cred_user_id_ptr(cred);
			user_id_len = fido_cred_user_id_len(cred);
			skdebug(__func__, "Device %s RP \"%s\" user \"%s\" "
			    "uidlen %zu slot %zu: type %d flags 0x%02x "
			    "prot 0x%02x", sk->path, rp_id, user_name,
			    user_id_len, j, fido_cred_type(cred),
			    fido_cred_flags(cred), fido_cred_prot(cred));

			/* Determine key algorithm */
			ವಿಕಲ್ಪ (fido_cred_type(cred)) {
			ಪಕ್ಷ COSE_ES256:
				alg = SSH_SK_ECDSA;
				ಭಙ್ಗ;
			ಪಕ್ಷ COSE_EDDSA:
				alg = SSH_SK_ED25519;
				ಭಙ್ಗ;
			ಸ್ವಭಾವ:
				skdebug(__func__, "unsupported key type %d",
				    fido_cred_type(cred));
				ಅನುವರ್ತ;
			}

			/* build response entry */
			ಯದಿ ((srk = calloc(1, ಪರಿಮಾಣ(*srk))) == ರಿಕ್ತ ||
			    (srk->ಕೀಲಿ.ಕೀಲಿ_handle = calloc(1,
			    fido_cred_id_len(cred))) == ರಿಕ್ತ ||
			    (srk->application = strdup(rp_id)) == ರಿಕ್ತ ||
			    (user_id_len > 0 &&
			     (srk->user_id = calloc(1, user_id_len)) == ರಿಕ್ತ)) {
				skdebug(__func__, "alloc sk_resident_key");
				ಗಚ್ಛ out;
			}

			srk->alg = alg;
			srk->ಕೀಲಿ.ಕೀಲಿ_handle_len = fido_cred_id_len(cred);
			memcpy(srk->ಕೀಲಿ.ಕೀಲಿ_handle, fido_cred_id_ptr(cred),
			    srk->ಕೀಲಿ.ಕೀಲಿ_handle_len);
			srk->user_id_len = user_id_len;
			ಯದಿ (srk->user_id_len != 0)
				memcpy(srk->user_id, user_id, srk->user_id_len);

#ifdef HAVE_FIDO_CRED_PROT
			ಯದಿ (fido_cred_prot(cred) ==
			    FIDO_CRED_PROT_UV_REQUIRED)
				srk->flags |=  SSH_SK_USER_VERIFICATION_REQD;
#endif

			ಯದಿ ((r = pack_public_ಕೀಲಿ(srk->alg, cred,
			    &srk->ಕೀಲಿ)) != 0) {
				skdebug(__func__, "pack public key failed");
				ಗಚ್ಛ out;
			}
			/* append */
			ಯದಿ ((tmp = recallocarray(*rksp, *nrksp, (*nrksp) + 1,
			    ಪರಿಮಾಣ(**rksp))) == ರಿಕ್ತ) {
				skdebug(__func__, "alloc rksp");
				ಗಚ್ಛ out;
			}
			*rksp = tmp;
			(*rksp)[(*nrksp)++] = srk;
			srk = ರಿಕ್ತ;
		}
	}
	/* Success */
	ret = 0;
 out:
	ಯದಿ (srk != ರಿಕ್ತ) {
		ಮುಕ್ತ(srk->application);
		freezero(srk->ಕೀಲಿ.public_ಕೀಲಿ, srk->ಕೀಲಿ.public_ಕೀಲಿ_len);
		freezero(srk->ಕೀಲಿ.ಕೀಲಿ_handle, srk->ಕೀಲಿ.ಕೀಲಿ_handle_len);
		freezero(srk->user_id, srk->user_id_len);
		freezero(srk, ಪರಿಮಾಣ(*srk));
	}
	fido_credman_rp_free(&rp);
	fido_credman_rk_free(&rk);
	fido_credman_metadata_free(&metadata);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
sk_load_resident_ಕೀಲಿಗಳು(ಧ್ರುವ ವರ್ಣ *pin, ಸಂರಚನಾ sk_option **options,
    ಸಂರಚನಾ sk_resident_ಕೀಲಿ ***rksp, size_t *nrksp)
{
	ಪೂರ್ಣಾಙ್ಕ ret = SSH_SK_ERR_GENERAL, r = -1;
	size_t i, nrks = 0;
	ಸಂರಚನಾ sk_resident_ಕೀಲಿ **rks = ರಿಕ್ತ;
	ಸಂರಚನಾ sk_usbhid *sk = ರಿಕ್ತ;
	ವರ್ಣ *device = ರಿಕ್ತ;

	*rksp = ರಿಕ್ತ;
	*nrksp = 0;

	fido_init(SSH_FIDO_INIT_ARG);

	ಯದಿ (check_sign_load_resident_options(options, &device) != 0)
		ಗಚ್ಛ out; /* error already logged */
	ಯದಿ (device != ರಿಕ್ತ)
		sk = sk_open(device);
	ಅನ್ಯಥಾ
		sk = sk_probe(ರಿಕ್ತ, ರಿಕ್ತ, 0, 1);
	ಯದಿ (sk == ರಿಕ್ತ) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		ಗಚ್ಛ out;
	}
	skdebug(__func__, "trying %s", sk->path);
	ಯದಿ ((r = read_rks(sk, pin, &rks, &nrks)) != 0) {
		skdebug(__func__, "read_rks failed for %s", sk->path);
		ret = r;
		ಗಚ್ಛ out;
	}
	/* success, unless we have no keys but a specific error */
	ಯದಿ (nrks > 0 || ret == SSH_SK_ERR_GENERAL)
		ret = 0;
	*rksp = rks;
	*nrksp = nrks;
	rks = ರಿಕ್ತ;
	nrks = 0;
 out:
	sk_close(sk);
	ಪ್ರತಿ (i = 0; i < nrks; i++) {
		ಮುಕ್ತ(rks[i]->application);
		freezero(rks[i]->ಕೀಲಿ.public_ಕೀಲಿ, rks[i]->ಕೀಲಿ.public_ಕೀಲಿ_len);
		freezero(rks[i]->ಕೀಲಿ.ಕೀಲಿ_handle, rks[i]->ಕೀಲಿ.ಕೀಲಿ_handle_len);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i], ಪರಿಮಾಣ(*rks[i]));
	}
	ಮುಕ್ತ(device);
	ಮುಕ್ತ(rks);
	ಪ್ರತ್ಯಾಗಮ ret;
}

#endif /* ENABLE_SK_INTERNAL */
