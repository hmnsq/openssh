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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifdef ENABLE_SK_INTERNAL

#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <time.h>
#ifdef HAVE_SHA2_H
#ଅନ୍ତର୍ଭାଵ <sha2.h>
#endif

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ <openssl/opensslv.h>
#ଅନ୍ତର୍ଭାଵ <openssl/crypto.h>
#ଅନ୍ତର୍ଭାଵ <openssl/bn.h>
#ଅନ୍ତର୍ଭାଵ <openssl/ec.h>
#ଅନ୍ତର୍ଭାଵ <openssl/ecdsa.h>
#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>
#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openssl-compat.h"
#endif /* WITH_OPENSSL */

#ଅନ୍ତର୍ଭାଵ <fido.h>
#ଅନ୍ତର୍ଭାଵ <fido/credman.h>

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
# define sk_load_resident_ଚାବିଗୁଡ଼ିକ	ssh_sk_load_resident_ଚାବିଗୁଡ଼ିକ
#endif /* !SK_STANDALONE */

#ଅନ୍ତର୍ଭାଵ "sk-api.h"

/* #define SK_DEBUG 1 */

#ifdef SK_DEBUG
#define SSH_FIDO_INIT_ARG	FIDO_DEBUG
#ଅନ୍ୟଥା
#define SSH_FIDO_INIT_ARG	0
#endif

#define MAX_FIDO_DEVICES	8
#define FIDO_POLL_MS		50
#define SELECT_MS		15000
#define POLL_SLEEP_NS		200000000

#ifndef FIDO_ERR_OPERATION_DENIED
#define FIDO_ERR_OPERATION_DENIED 0x27
#endif

ସଂରଚନା sk_usbhid {
	fido_dev_t *dev;
	ଅକ୍ଷର *path;
};

/* Return the version of the middleware API */
uint32_t sk_api_version(ଶୂନ୍ୟ);

/* Enroll a U2F key (private key generation) */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sk_enroll(uint32_t alg, ଅଚଳ uint8_t *challenge, size_t challenge_len,
    ଅଚଳ ଅକ୍ଷର *application, uint8_t flags, ଅଚଳ ଅକ୍ଷର *pin,
    ସଂରଚନା sk_option **options, ସଂରଚନା sk_enroll_response **enroll_response);

/* Sign a challenge */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sk_sign(uint32_t alg, ଅଚଳ uint8_t *data, size_t data_len,
    ଅଚଳ ଅକ୍ଷର *application, ଅଚଳ uint8_t *ଚାବି_handle, size_t ଚାବି_handle_len,
    uint8_t flags, ଅଚଳ ଅକ୍ଷର *pin, ସଂରଚନା sk_option **options,
    ସଂରଚନା sk_sign_response **sign_response);

/* Load resident keys */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sk_load_resident_ଚାବିଗୁଡ଼ିକ(ଅଚଳ ଅକ୍ଷର *pin, ସଂରଚନା sk_option **options,
    ସଂରଚନା sk_resident_ଚାବି ***rks, size_t *nrks);

ସ୍ଥିର ଶୂନ୍ୟ skdebug(ଅଚଳ ଅକ୍ଷର *func, ଅଚଳ ଅକ୍ଷର *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

ସ୍ଥିର ଶୂନ୍ୟ
skdebug(ଅଚଳ ଅକ୍ଷର *func, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
#ଯଦି !defined(SK_STANDALONE)
	ଅକ୍ଷର *ସନ୍ଦେଶ;
	va_list ap;

	va_start(ap, fmt);
	xvasprintf(&ସନ୍ଦେଶ, fmt, ap);
	va_end(ap);
	debug("%s: %s", func, ସନ୍ଦେଶ);
	ମୁକ୍ତ(ସନ୍ଦେଶ);
#ନଚେତଯଦି defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#ଅନ୍ୟଥା
	(ଶୂନ୍ୟ)func; /* XXX */
	(ଶୂନ୍ୟ)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(ଶୂନ୍ୟ)
{
	ଫେରନ୍ତୁ SSH_SK_VERSION_MAJOR;
}

ସ୍ଥିର ସଂରଚନା sk_usbhid *
sk_open(ଅଚଳ ଅକ୍ଷର *path)
{
	ସଂରଚନା sk_usbhid *sk;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (path == ଖାଲି) {
		skdebug(__func__, "path == NULL");
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି ((sk = calloc(1, ଆକାର(*sk))) == ଖାଲି) {
		skdebug(__func__, "calloc sk failed");
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି ((sk->path = strdup(path)) == ଖାଲି) {
		skdebug(__func__, "strdup path failed");
		ମୁକ୍ତ(sk);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି ((sk->dev = fido_dev_new()) == ଖାଲି) {
		skdebug(__func__, "fido_dev_new failed");
		ମୁକ୍ତ(sk->path);
		ମୁକ୍ତ(sk);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି ((r = fido_dev_open(sk->dev, sk->path)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_open %s failed: %s", sk->path,
		    fido_strerr(r));
		fido_dev_free(&sk->dev);
		ମୁକ୍ତ(sk->path);
		ମୁକ୍ତ(sk);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଫେରନ୍ତୁ sk;
}

ସ୍ଥିର ଶୂନ୍ୟ
sk_close(ସଂରଚନା sk_usbhid *sk)
{
	ଯଦି (sk == ଖାଲି)
		ଫେରନ୍ତୁ;
	fido_dev_cancel(sk->dev); /* cancel any pending operation */
	fido_dev_close(sk->dev);
	fido_dev_free(&sk->dev);
	ମୁକ୍ତ(sk->path);
	ମୁକ୍ତ(sk);
}

ସ୍ଥିର ସଂରଚନା sk_usbhid **
sk_openv(ଅଚଳ fido_dev_info_t *devlist, size_t ndevs, size_t *nopen)
{
	ଅଚଳ fido_dev_info_t *di;
	ସଂରଚନା sk_usbhid **skv;
	size_t i;

	*nopen = 0;
	ଯଦି ((skv = calloc(ndevs, ଆକାର(*skv))) == ଖାଲି) {
		skdebug(__func__, "calloc skv failed");
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ପାଇଁ (i = 0; i < ndevs; i++) {
		ଯଦି ((di = fido_dev_info_ptr(devlist, i)) == ଖାଲି)
			skdebug(__func__, "fido_dev_info_ptr failed");
		ଅନ୍ୟଥା ଯଦି ((skv[*nopen] = sk_open(fido_dev_info_path(di))) == ଖାଲି)
			skdebug(__func__, "sk_open failed");
		ଅନ୍ୟଥା
			(*nopen)++;
	}
	ଯଦି (*nopen == 0) {
		ପାଇଁ (i = 0; i < ndevs; i++)
			sk_close(skv[i]);
		ମୁକ୍ତ(skv);
		skv = ଖାଲି;
	}

	ଫେରନ୍ତୁ skv;
}

ସ୍ଥିର ଶୂନ୍ୟ
sk_closev(ସଂରଚନା sk_usbhid **skv, size_t nsk)
{
	size_t i;

	ପାଇଁ (i = 0; i < nsk; i++)
		sk_close(skv[i]);
	ମୁକ୍ତ(skv);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sk_touch_begin(ସଂରଚନା sk_usbhid **skv, size_t nsk)
{
	size_t i, ok = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ପାଇଁ (i = 0; i < nsk; i++)
		ଯଦି ((r = fido_dev_get_touch_begin(skv[i]->dev)) != FIDO_OK)
			skdebug(__func__, "fido_dev_get_touch_begin %s failed:"
			    " %s", skv[i]->path, fido_strerr(r));
		ଅନ୍ୟଥା
			ok++;

	ଫେରନ୍ତୁ ok ? 0 : -1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sk_touch_poll(ସଂରଚନା sk_usbhid **skv, size_t nsk, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *touch, size_t *idx)
{
	ସଂରଚନା timespec ts_pause;
	size_t npoll, i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ts_pause.tv_sec = 0;
	ts_pause.tv_nsec = POLL_SLEEP_NS;
	nanosleep(&ts_pause, ଖାଲି);
	npoll = nsk;
	ପାଇଁ (i = 0; i < nsk; i++) {
		ଯଦି (skv[i] == ଖାଲି)
			ଜାରି; /* device discarded */
		skdebug(__func__, "polling %s", skv[i]->path);
		ଯଦି ((r = fido_dev_get_touch_status(skv[i]->dev, touch,
		    FIDO_POLL_MS)) != FIDO_OK) {
			skdebug(__func__, "fido_dev_get_touch_status %s: %s",
			    skv[i]->path, fido_strerr(r));
			sk_close(skv[i]); /* discard device */
			skv[i] = ଖାଲି;
			ଯଦି (--npoll == 0) {
				skdebug(__func__, "no device left to poll");
				ଫେରନ୍ତୁ -1;
			}
		} ଅନ୍ୟଥା ଯଦି (*touch) {
			*idx = i;
			ଫେରନ୍ତୁ 0;
		}
	}
	*touch = 0;
	ଫେରନ୍ତୁ 0;
}

#ଯଦି !defined(HAVE_FIDO_ASSERT_SET_CLIENTDATA) || \
    !defined(HAVE_FIDO_CRED_SET_CLIENTDATA)
/* Calculate SHA256(m) */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sha256_mem(ଅଚଳ ଶୂନ୍ୟ *m, size_t mlen, u_char *d, size_t dlen)
{
#ifdef WITH_OPENSSL
	u_int mdlen;
#ଅନ୍ୟଥା
	SHA2_CTX ctx;
#endif

	ଯଦି (dlen != 32)
		ଫେରନ୍ତୁ -1;
#ifdef WITH_OPENSSL
	mdlen = dlen;
	ଯଦି (!EVP_Digest(m, mlen, d, &mdlen, EVP_sha256(), ଖାଲି))
		ଫେରନ୍ତୁ -1;
#ଅନ୍ୟଥା
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ଅଚଳ uint8_t *)m, mlen);
	SHA256Final(d, &ctx);
#endif
	ଫେରନ୍ତୁ 0;
}
#endif /* !HAVE_FIDO_ASSERT_SET_CLIENTDATA || !HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_CRED_SET_CLIENTDATA
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
fido_cred_set_clientdata(fido_cred_t *cred, ଅଚଳ u_char *ptr, size_t len)
{
	uint8_t d[32];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (sha256_mem(ptr, len, d, ଆକାର(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		ଫେରନ୍ତୁ FIDO_ERR_INTERNAL;
	}
	r = fido_cred_set_clientdata_hash(cred, d, ଆକାର(d));
	explicit_bzero(d, ଆକାର(d));
	ଯଦି (r != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	ଫେରନ୍ତୁ r;
}
#endif /* HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_ASSERT_SET_CLIENTDATA
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
fido_assert_set_clientdata(fido_assert_t *ପ୍ରତିଜ୍ଞା, ଅଚଳ u_char *ptr, size_t len)
{
	uint8_t d[32];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (sha256_mem(ptr, len, d, ଆକାର(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		ଫେରନ୍ତୁ FIDO_ERR_INTERNAL;
	}
	r = fido_assert_set_clientdata_hash(ପ୍ରତିଜ୍ଞା, d, ଆକାର(d));
	explicit_bzero(d, ଆକାର(d));
	ଯଦି (r != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	ଫେରନ୍ତୁ r;
}
#endif /* HAVE_FIDO_ASSERT_SET_CLIENTDATA */

#ifndef HAVE_FIDO_DEV_IS_WINHELLO
ସ୍ଥିର bool
fido_dev_is_winhello(ଅଚଳ fido_dev_t *fdev)
{
	ଫେରନ୍ତୁ 0;
}
#endif /* HAVE_FIDO_DEV_IS_WINHELLO */

/* Check if the specified key handle exists on a given sk. */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sk_try(ଅଚଳ ସଂରଚନା sk_usbhid *sk, ଅଚଳ ଅକ୍ଷର *application,
    ଅଚଳ uint8_t *ଚାବି_handle, size_t ଚାବି_handle_len)
{
	fido_assert_t *ପ୍ରତିଜ୍ଞା = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = FIDO_ERR_INTERNAL;
	uint8_t message[32];

	memset(message, '\0', ଆକାର(message));
	ଯଦି ((ପ୍ରତିଜ୍ଞା = fido_assert_new()) == ଖାଲି) {
		skdebug(__func__, "fido_assert_new failed");
		ଯାଅ out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	ଯଦି ((r = fido_assert_set_clientdata(ପ୍ରତିଜ୍ଞା, message,
	    ଆକାର(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		ଯାଅ out;
	}
	ଯଦି ((r = fido_assert_set_rp(ପ୍ରତିଜ୍ଞା, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		ଯାଅ out;
	}
	ଯଦି ((r = fido_assert_allow_cred(ପ୍ରତିଜ୍ଞା, ଚାବି_handle,
	    ଚାବି_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		ଯାଅ out;
	}
	ଯଦି ((r = fido_assert_set_up(ପ୍ରତିଜ୍ଞା, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_up: %s", fido_strerr(r));
		ଯାଅ out;
	}
	r = fido_dev_get_assert(sk->dev, ପ୍ରତିଜ୍ଞା, ଖାଲି);
	skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
	ଯଦି (r == FIDO_ERR_USER_PRESENCE_REQUIRED) {
		/* U2F tokens may return this */
		r = FIDO_OK;
	}
 out:
	fido_assert_free(&ପ୍ରତିଜ୍ଞା);

	ଫେରନ୍ତୁ r != FIDO_OK ? -1 : 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
check_sk_options(fido_dev_t *dev, ଅଚଳ ଅକ୍ଷର *opt, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *ret)
{
	fido_cbor_info_t *info;
	ଅକ୍ଷର * ଅଚଳ *name;
	ଅଚଳ bool *ମୂଲ୍ୟ;
	size_t len, i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	*ret = -1;

	ଯଦି (!fido_dev_is_fido2(dev)) {
		skdebug(__func__, "device is not fido2");
		ଫେରନ୍ତୁ 0;
	}
	ଯଦି ((info = fido_cbor_info_new()) == ଖାଲି) {
		skdebug(__func__, "fido_cbor_info_new failed");
		ଫେରନ୍ତୁ -1;
	}
	ଯଦି ((r = fido_dev_get_cbor_info(dev, info)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_cbor_info: %s", fido_strerr(r));
		fido_cbor_info_free(&info);
		ଫେରନ୍ତୁ -1;
	}
	name = fido_cbor_info_options_name_ptr(info);
	ମୂଲ୍ୟ = fido_cbor_info_options_ମୂଲ୍ୟ_ptr(info);
	len = fido_cbor_info_options_len(info);
	ପାଇଁ (i = 0; i < len; i++) {
		ଯଦି (!strcmp(name[i], opt)) {
			*ret = ମୂଲ୍ୟ[i];
			ଭାଙ୍ଗ;
		}
	}
	fido_cbor_info_free(&info);
	ଯଦି (*ret == -1)
		skdebug(__func__, "option %s is unknown", opt);
	ଅନ୍ୟଥା
		skdebug(__func__, "option %s is %s", opt, *ret ? "on" : "off");

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ସଂରଚନା sk_usbhid *
sk_select_by_cred(ଅଚଳ fido_dev_info_t *devlist, size_t ndevs,
    ଅଚଳ ଅକ୍ଷର *application, ଅଚଳ uint8_t *ଚାବି_handle, size_t ଚାବି_handle_len)
{
	ସଂରଚନା sk_usbhid **skv, *sk;
	size_t skvcnt, i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା internal_uv;

	ଯଦି ((skv = sk_openv(devlist, ndevs, &skvcnt)) == ଖାଲି) {
		skdebug(__func__, "sk_openv failed");
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି (skvcnt == 1 && check_sk_options(skv[0]->dev, "uv",
	    &internal_uv) == 0 && internal_uv != -1) {
		sk = skv[0];
		skv[0] = ଖାଲି;
		ଯାଅ out;
	}
	sk = ଖାଲି;
	ପାଇଁ (i = 0; i < skvcnt; i++) {
		ଯଦି (sk_try(skv[i], application, ଚାବି_handle,
		    ଚାବି_handle_len) == 0) {
			sk = skv[i];
			skv[i] = ଖାଲି;
			skdebug(__func__, "found key in %s", sk->path);
			ଭାଙ୍ଗ;
		}
	}
 out:
	sk_closev(skv, skvcnt);
	ଫେରନ୍ତୁ sk;
}

ସ୍ଥିର ସଂରଚନା sk_usbhid *
sk_select_by_touch(ଅଚଳ fido_dev_info_t *devlist, size_t ndevs)
{
	ସଂରଚନା sk_usbhid **skv, *sk;
	ସଂରଚନା timeval tv_start, tv_now, tv_delta;
	size_t skvcnt, idx;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା touch, ms_remain;

	ଯଦି ((skv = sk_openv(devlist, ndevs, &skvcnt)) == ଖାଲି) {
		skdebug(__func__, "sk_openv failed");
		ଫେରନ୍ତୁ ଖାଲି;
	}
	sk = ଖାଲି;
	ଯଦି (skvcnt < 2) {
		ଯଦି (skvcnt == 1) {
			/* single candidate */
			sk = skv[0];
			skv[0] = ଖାଲି;
		}
		ଯାଅ out;
	}
#ifndef HAVE_FIDO_DEV_GET_TOUCH_STATUS
	skdebug(__func__, "libfido2 version does not support a feature needed for multiple tokens. Please upgrade to >=1.5.0");
	ଯାଅ out;
#endif

	ଯଦି (sk_touch_begin(skv, skvcnt) == -1) {
		skdebug(__func__, "sk_touch_begin failed");
		ଯାଅ out;
	}
	monotime_tv(&tv_start);
	କର {
		ଯଦି (sk_touch_poll(skv, skvcnt, &touch, &idx) == -1) {
			skdebug(__func__, "sk_touch_poll failed");
			ଯାଅ out;
		}
		ଯଦି (touch) {
			sk = skv[idx];
			skv[idx] = ଖାଲି;
			ଯାଅ out;
		}
		monotime_tv(&tv_now);
		timersub(&tv_now, &tv_start, &tv_delta);
		ms_remain = SELECT_MS - tv_delta.tv_sec * 1000 -
		    tv_delta.tv_usec / 1000;
	} ଯେତେବେଳେ (ms_remain >= FIDO_POLL_MS);
	skdebug(__func__, "timeout");
out:
	sk_closev(skv, skvcnt);
	ଫେରନ୍ତୁ sk;
}

ସ୍ଥିର ସଂରଚନା sk_usbhid *
sk_probe(ଅଚଳ ଅକ୍ଷର *application, ଅଚଳ uint8_t *ଚାବି_handle,
    size_t ଚାବି_handle_len, ପୂର୍ଣ୍ଣସଂଖ୍ୟା probe_resident)
{
	ସଂରଚନା sk_usbhid *sk;
	fido_dev_info_t *devlist;
	size_t ndevs;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

#ifdef HAVE_CYGWIN
	ଯଦି (!probe_resident && (sk = sk_open("windows://hello")) != ଖାଲି)
		ଫେରନ୍ତୁ sk;
#endif /* HAVE_CYGWIN */
	ଯଦି ((devlist = fido_dev_info_new(MAX_FIDO_DEVICES)) == ଖାଲି) {
		skdebug(__func__, "fido_dev_info_new failed");
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି ((r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES,
	    &ndevs)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_info_manifest failed: %s",
		    fido_strerr(r));
		fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	skdebug(__func__, "%zu device(s) detected", ndevs);
	ଯଦି (ndevs == 0) {
		sk = ଖାଲି;
	} ଅନ୍ୟଥା ଯଦି (application != ଖାଲି && ଚାବି_handle != ଖାଲି) {
		skdebug(__func__, "selecting sk by cred");
		sk = sk_select_by_cred(devlist, ndevs, application, ଚାବି_handle,
		    ଚାବି_handle_len);
	} ଅନ୍ୟଥା {
		skdebug(__func__, "selecting sk by touch");
		sk = sk_select_by_touch(devlist, ndevs);
	}
	fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
	ଫେରନ୍ତୁ sk;
}

#ifdef WITH_OPENSSL
/*
 * The key returned via fido_cred_pubkey_ptr() is in affine coordinates,
 * but the API expects a SEC1 octet string.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pack_public_ଚାବି_ecdsa(ଅଚଳ fido_cred_t *cred,
    ସଂରଚନା sk_enroll_response *response)
{
	ଅଚଳ uint8_t *ptr;
	BIGNUM *x = ଖାଲି, *y = ଖାଲି;
	EC_POINT *q = ଖାଲି;
	EC_GROUP *g = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;

	response->public_ଚାବି = ଖାଲି;
	response->public_ଚାବି_len = 0;

	ଯଦି ((x = BN_new()) == ଖାଲି ||
	    (y = BN_new()) == ଖାଲି ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == ଖାଲି ||
	    (q = EC_POINT_new(g)) == ଖାଲି) {
		skdebug(__func__, "libcrypto setup failed");
		ଯାଅ out;
	}
	ଯଦି ((ptr = fido_cred_pubkey_ptr(cred)) == ଖାଲି) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		ଯାଅ out;
	}
	ଯଦି (fido_cred_pubkey_len(cred) != 64) {
		skdebug(__func__, "bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		ଯାଅ out;
	}

	ଯଦି (BN_bin2bn(ptr, 32, x) == ଖାଲି ||
	    BN_bin2bn(ptr + 32, 32, y) == ଖାଲି) {
		skdebug(__func__, "BN_bin2bn failed");
		ଯାଅ out;
	}
	ଯଦି (EC_POINT_set_affine_coordinates(g, q, x, y, ଖାଲି) != 1) {
		skdebug(__func__, "EC_POINT_set_affine_coordinates failed");
		ଯାଅ out;
	}
	response->public_ଚାବି_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, ଖାଲି, 0, ଖାଲି);
	ଯଦି (response->public_ଚାବି_len == 0 || response->public_ଚାବି_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_ଚାବି_len);
		ଯାଅ out;
	}
	ଯଦି ((response->public_ଚାବି = malloc(response->public_ଚାବି_len)) == ଖାଲି) {
		skdebug(__func__, "malloc pubkey failed");
		ଯାଅ out;
	}
	ଯଦି (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_ଚାବି, response->public_ଚାବି_len, ଖାଲି) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		ଯାଅ out;
	}
	/* success */
	ret = 0;
 out:
	ଯଦି (ret != 0 && response->public_ଚାବି != ଖାଲି) {
		memset(response->public_ଚାବି, 0, response->public_ଚାବି_len);
		ମୁକ୍ତ(response->public_ଚାବି);
		response->public_ଚାବି = ଖାଲି;
	}
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	ଫେରନ୍ତୁ ret;
}
#endif /* WITH_OPENSSL */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pack_public_ଚାବି_ed25519(ଅଚଳ fido_cred_t *cred,
    ସଂରଚନା sk_enroll_response *response)
{
	ଅଚଳ uint8_t *ptr;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;

	response->public_ଚାବି = ଖାଲି;
	response->public_ଚାବି_len = 0;

	ଯଦି ((len = fido_cred_pubkey_len(cred)) != 32) {
		skdebug(__func__, "bad fido_cred_pubkey_len len %zu", len);
		ଯାଅ out;
	}
	ଯଦି ((ptr = fido_cred_pubkey_ptr(cred)) == ଖାଲି) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		ଯାଅ out;
	}
	response->public_ଚାବି_len = len;
	ଯଦି ((response->public_ଚାବି = malloc(response->public_ଚାବି_len)) == ଖାଲି) {
		skdebug(__func__, "malloc pubkey failed");
		ଯାଅ out;
	}
	memcpy(response->public_ଚାବି, ptr, len);
	ret = 0;
 out:
	ଯଦି (ret != 0)
		ମୁକ୍ତ(response->public_ଚାବି);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pack_public_ଚାବି(uint32_t alg, ଅଚଳ fido_cred_t *cred,
    ସଂରଚନା sk_enroll_response *response)
{
	ବାଛ(alg) {
#ifdef WITH_OPENSSL
	ସ୍ଥିତି SSH_SK_ECDSA:
		ଫେରନ୍ତୁ pack_public_ଚାବି_ecdsa(cred, response);
#endif /* WITH_OPENSSL */
	ସ୍ଥିତି SSH_SK_ED25519:
		ଫେରନ୍ତୁ pack_public_ଚାବି_ed25519(cred, response);
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ -1;
	}
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
fidoerr_to_skerr(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fidoerr)
{
	ବାଛ (fidoerr) {
	ସ୍ଥିତି FIDO_ERR_UNSUPPORTED_OPTION:
	ସ୍ଥିତି FIDO_ERR_UNSUPPORTED_ALGORITHM:
		ଫେରନ୍ତୁ SSH_SK_ERR_UNSUPPORTED;
	ସ୍ଥିତି FIDO_ERR_PIN_REQUIRED:
	ସ୍ଥିତି FIDO_ERR_PIN_INVALID:
	ସ୍ଥିତି FIDO_ERR_OPERATION_DENIED:
		ଫେରନ୍ତୁ SSH_SK_ERR_PIN_REQUIRED;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ -1;
	}
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
check_enroll_options(ସଂରଚନା sk_option **options, ଅକ୍ଷର **devicep,
    uint8_t *user_id, size_t user_id_len)
{
	size_t i;

	ଯଦି (options == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ପାଇଁ (i = 0; options[i] != ଖାଲି; i++) {
		ଯଦି (strcmp(options[i]->name, "device") == 0) {
			ଯଦି ((*devicep = strdup(options[i]->ମୂଲ୍ୟ)) == ଖାଲି) {
				skdebug(__func__, "strdup device failed");
				ଫେରନ୍ତୁ -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} ଅନ୍ୟଥା ଯଦି (strcmp(options[i]->name, "user") == 0) {
			ଯଦି (strlcpy(user_id, options[i]->ମୂଲ୍ୟ, user_id_len) >=
			    user_id_len) {
				skdebug(__func__, "user too long");
				ଫେରନ୍ତୁ -1;
			}
			skdebug(__func__, "requested user %s",
			    (ଅକ୍ଷର *)user_id);
		} ଅନ୍ୟଥା {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			ଯଦି (options[i]->required) {
				skdebug(__func__, "unknown required option");
				ଫେରନ୍ତୁ -1;
			}
		}
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ଚାବି_lookup(fido_dev_t *dev, ଅଚଳ ଅକ୍ଷର *application, ଅଚଳ uint8_t *user_id,
    size_t user_id_len, ଅଚଳ ଅକ୍ଷର *pin)
{
	fido_assert_t *ପ୍ରତିଜ୍ଞା = ଖାଲି;
	uint8_t message[32];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = FIDO_ERR_INTERNAL;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା sk_supports_uv, uv;
	size_t i;

	memset(message, '\0', ଆକାର(message));
	ଯଦି ((ପ୍ରତିଜ୍ଞା = fido_assert_new()) == ଖାଲି) {
		skdebug(__func__, "fido_assert_new failed");
		ଯାଅ out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	ଯଦି ((r = fido_assert_set_clientdata(ପ୍ରତିଜ୍ଞା, message,
	    ଆକାର(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		ଯାଅ out;
	}
	ଯଦି ((r = fido_assert_set_rp(ପ୍ରତିଜ୍ଞା, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		ଯାଅ out;
	}
	ଯଦି ((r = fido_assert_set_up(ପ୍ରତିଜ୍ଞା, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		ଯାଅ out;
	}
	uv = FIDO_OPT_OMIT;
	ଯଦି (pin == ଖାଲି && check_sk_options(dev, "uv", &sk_supports_uv) == 0 &&
	    sk_supports_uv != -1)
		uv = FIDO_OPT_TRUE;
	ଯଦି ((r = fido_assert_set_uv(ପ୍ରତିଜ୍ଞା, uv)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
		ଯାଅ out;
	}
	ଯଦି ((r = fido_dev_get_assert(dev, ପ୍ରତିଜ୍ଞା, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ଯାଅ out;
	}
	r = FIDO_ERR_NO_CREDENTIALS;
	skdebug(__func__, "%zu signatures returned", fido_assert_ଗଣନା(ପ୍ରତିଜ୍ଞା));
	ପାଇଁ (i = 0; i < fido_assert_ଗଣନା(ପ୍ରତିଜ୍ଞା); i++) {
		ଯଦି (fido_assert_user_id_len(ପ୍ରତିଜ୍ଞା, i) == user_id_len &&
		    memcmp(fido_assert_user_id_ptr(ପ୍ରତିଜ୍ଞା, i), user_id,
		    user_id_len) == 0) {
			skdebug(__func__, "credential exists");
			r = FIDO_OK;
			ଯାଅ out;
		}
	}
 out:
	fido_assert_free(&ପ୍ରତିଜ୍ଞା);

	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sk_enroll(uint32_t alg, ଅଚଳ uint8_t *challenge, size_t challenge_len,
    ଅଚଳ ଅକ୍ଷର *application, uint8_t flags, ଅଚଳ ଅକ୍ଷର *pin,
    ସଂରଚନା sk_option **options, ସଂରଚନା sk_enroll_response **enroll_response)
{
	fido_cred_t *cred = ଖାଲି;
	ଅଚଳ uint8_t *ptr;
	uint8_t user_id[32];
	ସଂରଚନା sk_usbhid *sk = ଖାଲି;
	ସଂରଚନା sk_enroll_response *response = ଖାଲି;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା credprot;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା cose_alg;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = SSH_SK_ERR_GENERAL;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଅକ୍ଷର *device = ଖାଲି;

	fido_init(SSH_FIDO_INIT_ARG);

	ଯଦି (enroll_response == ଖାଲି) {
		skdebug(__func__, "enroll_response == NULL");
		ଯାଅ out;
	}
	*enroll_response = ଖାଲି;
	memset(user_id, 0, ଆକାର(user_id));
	ଯଦି (check_enroll_options(options, &device, user_id,
	    ଆକାର(user_id)) != 0)
		ଯାଅ out; /* error already logged */

	ବାଛ(alg) {
#ifdef WITH_OPENSSL
	ସ୍ଥିତି SSH_SK_ECDSA:
		cose_alg = COSE_ES256;
		ଭାଙ୍ଗ;
#endif /* WITH_OPENSSL */
	ସ୍ଥିତି SSH_SK_ED25519:
		cose_alg = COSE_EDDSA;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		skdebug(__func__, "unsupported key type %d", alg);
		ଯାଅ out;
	}
	ଯଦି (device != ଖାଲି)
		sk = sk_open(device);
	ଅନ୍ୟଥା
		sk = sk_probe(ଖାଲି, ଖାଲି, 0, 0);
	ଯଦି (sk == ଖାଲି) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		ଯାଅ out;
	}
	skdebug(__func__, "using device %s", sk->path);
	ଯଦି ((flags & SSH_SK_RESIDENT_ଚାବି) != 0 &&
	    (flags & SSH_SK_FORCE_OPERATION) == 0 &&
	    (r = ଚାବି_lookup(sk->dev, application, user_id, ଆକାର(user_id),
	    pin)) != FIDO_ERR_NO_CREDENTIALS) {
		ଯଦି (r != FIDO_OK) {
			ret = fidoerr_to_skerr(r);
			skdebug(__func__, "key_lookup failed");
		} ଅନ୍ୟଥା {
			ret = SSH_SK_ERR_CREDENTIAL_EXISTS;
			skdebug(__func__, "key exists");
		}
		ଯାଅ out;
	}
	ଯଦି ((cred = fido_cred_new()) == ଖାଲି) {
		skdebug(__func__, "fido_cred_new failed");
		ଯାଅ out;
	}
	ଯଦି ((r = fido_cred_set_type(cred, cose_alg)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_type: %s", fido_strerr(r));
		ଯାଅ out;
	}
	ଯଦି ((r = fido_cred_set_clientdata(cred,
	    challenge, challenge_len)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata: %s",
		    fido_strerr(r));
		ଯାଅ out;
	}
	ଯଦି ((r = fido_cred_set_rk(cred, (flags & SSH_SK_RESIDENT_ଚାବି) != 0 ?
	    FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rk: %s", fido_strerr(r));
		ଯାଅ out;
	}
	ଯଦି ((r = fido_cred_set_user(cred, user_id, ଆକାର(user_id),
	    "openssh", "openssh", ଖାଲି)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_user: %s", fido_strerr(r));
		ଯାଅ out;
	}
	ଯଦି ((r = fido_cred_set_rp(cred, application, ଖାଲି)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rp: %s", fido_strerr(r));
		ଯାଅ out;
	}
	ଯଦି ((flags & (SSH_SK_RESIDENT_ଚାବି|SSH_SK_USER_VERIFICATION_REQD)) != 0) {
#ଯଦି !defined(HAVE_FIDO_DEV_SUPPORTS_CRED_PROT) || \
    !defined(HAVE_FIDO_CRED_SET_PROT)
		skdebug(__func__, "libfido2 version does not support a feature required for this operation. Please upgrade to >=1.5.0");
		ret = SSH_SK_ERR_UNSUPPORTED;
		ଯାଅ out;
		credprot = 0; (ଶୂନ୍ୟ)credprot; /* avoid warning */
#endif
		ଯଦି (!fido_dev_supports_cred_prot(sk->dev)) {
			skdebug(__func__, "%s does not support credprot, "
			    "refusing to create unprotected "
			    "resident/verify-required key", sk->path);
			ret = SSH_SK_ERR_UNSUPPORTED;
			ଯାଅ out;
		}
		ଯଦି ((flags & SSH_SK_USER_VERIFICATION_REQD))
			credprot = FIDO_CRED_PROT_UV_REQUIRED;
		ଅନ୍ୟଥା
			credprot = FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID;

		ଯଦି ((r = fido_cred_set_prot(cred, credprot)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_set_prot: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			ଯାଅ out;
		}
	}
	ଯଦି ((r = fido_dev_make_cred(sk->dev, cred, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_make_cred: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		ଯାଅ out;
	}
	ଯଦି (fido_cred_x5c_ptr(cred) != ଖାଲି) {
		ଯଦି ((r = fido_cred_verify(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify: %s",
			    fido_strerr(r));
			ଯାଅ out;
		}
	} ଅନ୍ୟଥା ଯଦି (strcmp(fido_cred_fmt(cred), "none") != 0) {
		skdebug(__func__, "self-attested credential");
		ଯଦି ((r = fido_cred_verify_self(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify_self: %s",
			    fido_strerr(r));
			ଯାଅ out;
		}
	} ଅନ୍ୟଥା {
		skdebug(__func__, "no attestation data");
	}
	ଯଦି ((response = calloc(1, ଆକାର(*response))) == ଖାଲି) {
		skdebug(__func__, "calloc response failed");
		ଯାଅ out;
	}
	response->flags = flags;
	ଯଦି (pack_public_ଚାବି(alg, cred, response) != 0) {
		skdebug(__func__, "pack_public_key failed");
		ଯାଅ out;
	}
	ଯଦି ((ptr = fido_cred_id_ptr(cred)) != ଖାଲି) {
		len = fido_cred_id_len(cred);
		ଯଦି ((response->ଚାବି_handle = calloc(1, len)) == ଖାଲି) {
			skdebug(__func__, "calloc key handle failed");
			ଯାଅ out;
		}
		memcpy(response->ଚାବି_handle, ptr, len);
		response->ଚାବି_handle_len = len;
	}
	ଯଦି ((ptr = fido_cred_sig_ptr(cred)) != ଖାଲି) {
		len = fido_cred_sig_len(cred);
		ଯଦି ((response->signature = calloc(1, len)) == ଖାଲି) {
			skdebug(__func__, "calloc signature failed");
			ଯାଅ out;
		}
		memcpy(response->signature, ptr, len);
		response->signature_len = len;
	}
	ଯଦି ((ptr = fido_cred_x5c_ptr(cred)) != ଖାଲି) {
		len = fido_cred_x5c_len(cred);
		skdebug(__func__, "attestation cert len=%zu", len);
		ଯଦି ((response->attestation_cert = calloc(1, len)) == ଖାଲି) {
			skdebug(__func__, "calloc attestation cert failed");
			ଯାଅ out;
		}
		memcpy(response->attestation_cert, ptr, len);
		response->attestation_cert_len = len;
	}
	ଯଦି ((ptr = fido_cred_authdata_ptr(cred)) != ଖାଲି) {
		len = fido_cred_authdata_len(cred);
		skdebug(__func__, "authdata len=%zu", len);
		ଯଦି ((response->authdata = calloc(1, len)) == ଖାଲି) {
			skdebug(__func__, "calloc authdata failed");
			ଯାଅ out;
		}
		memcpy(response->authdata, ptr, len);
		response->authdata_len = len;
	}
	*enroll_response = response;
	response = ଖାଲି;
	ret = 0;
 out:
	ମୁକ୍ତ(device);
	ଯଦି (response != ଖାଲି) {
		ମୁକ୍ତ(response->public_ଚାବି);
		ମୁକ୍ତ(response->ଚାବି_handle);
		ମୁକ୍ତ(response->signature);
		ମୁକ୍ତ(response->attestation_cert);
		ମୁକ୍ତ(response->authdata);
		ମୁକ୍ତ(response);
	}
	sk_close(sk);
	fido_cred_free(&cred);
	ଫେରନ୍ତୁ ret;
}

#ifdef WITH_OPENSSL
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pack_sig_ecdsa(fido_assert_t *ପ୍ରତିଜ୍ଞା, ସଂରଚନା sk_sign_response *response)
{
	ECDSA_SIG *sig = ଖାଲି;
	ଅଚଳ BIGNUM *sig_r, *sig_s;
	ଅଚଳ unsigned ଅକ୍ଷର *cp;
	size_t sig_len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;

	cp = fido_assert_sig_ptr(ପ୍ରତିଜ୍ଞା, 0);
	sig_len = fido_assert_sig_len(ପ୍ରତିଜ୍ଞା, 0);
	ଯଦି ((sig = d2i_ECDSA_SIG(ଖାଲି, &cp, sig_len)) == ଖାଲି) {
		skdebug(__func__, "d2i_ECDSA_SIG failed");
		ଯାଅ out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_ଅଙ୍କ_bytes(sig_r);
	response->sig_s_len = BN_ଅଙ୍କ_bytes(sig_s);
	ଯଦି ((response->sig_r = calloc(1, response->sig_r_len)) == ଖାଲି ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == ଖାଲି) {
		skdebug(__func__, "calloc signature failed");
		ଯାଅ out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	ECDSA_SIG_free(sig);
	ଯଦି (ret != 0) {
		ମୁକ୍ତ(response->sig_r);
		ମୁକ୍ତ(response->sig_s);
		response->sig_r = ଖାଲି;
		response->sig_s = ଖାଲି;
	}
	ଫେରନ୍ତୁ ret;
}
#endif /* WITH_OPENSSL */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pack_sig_ed25519(fido_assert_t *ପ୍ରତିଜ୍ଞା, ସଂରଚନା sk_sign_response *response)
{
	ଅଚଳ unsigned ଅକ୍ଷର *ptr;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;

	ptr = fido_assert_sig_ptr(ପ୍ରତିଜ୍ଞା, 0);
	len = fido_assert_sig_len(ପ୍ରତିଜ୍ଞା, 0);
	ଯଦି (len != 64) {
		skdebug(__func__, "bad length %zu", len);
		ଯାଅ out;
	}
	response->sig_r_len = len;
	ଯଦି ((response->sig_r = calloc(1, response->sig_r_len)) == ଖାଲି) {
		skdebug(__func__, "calloc signature failed");
		ଯାଅ out;
	}
	memcpy(response->sig_r, ptr, len);
	ret = 0;
 out:
	ଯଦି (ret != 0) {
		ମୁକ୍ତ(response->sig_r);
		response->sig_r = ଖାଲି;
	}
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pack_sig(uint32_t  alg, fido_assert_t *ପ୍ରତିଜ୍ଞା,
    ସଂରଚନା sk_sign_response *response)
{
	ବାଛ(alg) {
#ifdef WITH_OPENSSL
	ସ୍ଥିତି SSH_SK_ECDSA:
		ଫେରନ୍ତୁ pack_sig_ecdsa(ପ୍ରତିଜ୍ଞା, response);
#endif /* WITH_OPENSSL */
	ସ୍ଥିତି SSH_SK_ED25519:
		ଫେରନ୍ତୁ pack_sig_ed25519(ପ୍ରତିଜ୍ଞା, response);
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ -1;
	}
}

/* Checks sk_options for sk_sign() and sk_load_resident_keys() */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
check_sign_load_resident_options(ସଂରଚନା sk_option **options, ଅକ୍ଷର **devicep)
{
	size_t i;

	ଯଦି (options == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ପାଇଁ (i = 0; options[i] != ଖାଲି; i++) {
		ଯଦି (strcmp(options[i]->name, "device") == 0) {
			ଯଦି ((*devicep = strdup(options[i]->ମୂଲ୍ୟ)) == ଖାଲି) {
				skdebug(__func__, "strdup device failed");
				ଫେରନ୍ତୁ -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} ଅନ୍ୟଥା {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			ଯଦି (options[i]->required) {
				skdebug(__func__, "unknown required option");
				ଫେରନ୍ତୁ -1;
			}
		}
	}
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sk_sign(uint32_t alg, ଅଚଳ uint8_t *data, size_t datalen,
    ଅଚଳ ଅକ୍ଷର *application,
    ଅଚଳ uint8_t *ଚାବି_handle, size_t ଚାବି_handle_len,
    uint8_t flags, ଅଚଳ ଅକ୍ଷର *pin, ସଂରଚନା sk_option **options,
    ସଂରଚନା sk_sign_response **sign_response)
{
	fido_assert_t *ପ୍ରତିଜ୍ଞା = ଖାଲି;
	ଅକ୍ଷର *device = ଖାଲି;
	ସଂରଚନା sk_usbhid *sk = ଖାଲି;
	ସଂରଚନା sk_sign_response *response = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = SSH_SK_ERR_GENERAL, internal_uv;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	fido_init(SSH_FIDO_INIT_ARG);

	ଯଦି (sign_response == ଖାଲି) {
		skdebug(__func__, "sign_response == NULL");
		ଯାଅ out;
	}
	*sign_response = ଖାଲି;
	ଯଦି (check_sign_load_resident_options(options, &device) != 0)
		ଯାଅ out; /* error already logged */
	ଯଦି (device != ଖାଲି)
		sk = sk_open(device);
	ଅନ୍ୟଥା ଯଦି (pin != ଖାଲି || (flags & SSH_SK_USER_VERIFICATION_REQD))
		sk = sk_probe(ଖାଲି, ଖାଲି, 0, 0);
	ଅନ୍ୟଥା
		sk = sk_probe(application, ଚାବି_handle, ଚାବି_handle_len, 0);
	ଯଦି (sk == ଖାଲି) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		ଯାଅ out;
	}
	ଯଦି ((ପ୍ରତିଜ୍ଞା = fido_assert_new()) == ଖାଲି) {
		skdebug(__func__, "fido_assert_new failed");
		ଯାଅ out;
	}
	ଯଦି ((r = fido_assert_set_clientdata(ପ୍ରତିଜ୍ଞା,
	    data, datalen)) != FIDO_OK)  {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		ଯାଅ out;
	}
	ଯଦି ((r = fido_assert_set_rp(ପ୍ରତିଜ୍ଞା, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		ଯାଅ out;
	}
	ଯଦି ((r = fido_assert_allow_cred(ପ୍ରତିଜ୍ଞା, ଚାବି_handle,
	    ଚାବି_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		ଯାଅ out;
	}
	ଯଦି ((r = fido_assert_set_up(ପ୍ରତିଜ୍ଞା,
	    (flags & SSH_SK_USER_PRESENCE_REQD) ?
	    FIDO_OPT_TRUE : FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		ଯାଅ out;
	}
	/*
	 * WinHello requests the PIN by default.  Make "uv" request explicit
	 * to allow keys with and without -O verify-required to make sense.
	 */
	ଯଦି (pin == ଖାଲି && fido_dev_is_winhello (sk->dev) &&
	    (r = fido_assert_set_uv(ପ୍ରତିଜ୍ଞା, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
	}
	ଯଦି (pin == ଖାଲି && (flags & SSH_SK_USER_VERIFICATION_REQD)) {
		ଯଦି (check_sk_options(sk->dev, "uv", &internal_uv) < 0 ||
		    internal_uv != 1) {
			skdebug(__func__, "check_sk_options uv");
			ret = SSH_SK_ERR_PIN_REQUIRED;
			ଯାଅ out;
		}
		ଯଦି ((r = fido_assert_set_uv(ପ୍ରତିଜ୍ଞା,
		    FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_assert_set_uv: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			ଯାଅ out;
		}
	}
	ଯଦି ((r = fido_dev_get_assert(sk->dev, ପ୍ରତିଜ୍ଞା, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		ଯାଅ out;
	}
	ଯଦି ((response = calloc(1, ଆକାର(*response))) == ଖାଲି) {
		skdebug(__func__, "calloc response failed");
		ଯାଅ out;
	}
	response->flags = fido_assert_flags(ପ୍ରତିଜ୍ଞା, 0);
	response->counter = fido_assert_sigcount(ପ୍ରତିଜ୍ଞା, 0);
	ଯଦି (pack_sig(alg, ପ୍ରତିଜ୍ଞା, response) != 0) {
		skdebug(__func__, "pack_sig failed");
		ଯାଅ out;
	}
	*sign_response = response;
	response = ଖାଲି;
	ret = 0;
 out:
	ମୁକ୍ତ(device);
	ଯଦି (response != ଖାଲି) {
		ମୁକ୍ତ(response->sig_r);
		ମୁକ୍ତ(response->sig_s);
		ମୁକ୍ତ(response);
	}
	sk_close(sk);
	fido_assert_free(&ପ୍ରତିଜ୍ଞା);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
read_rks(ସଂରଚନା sk_usbhid *sk, ଅଚଳ ଅକ୍ଷର *pin,
    ସଂରଚନା sk_resident_ଚାବି ***rksp, size_t *nrksp)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = SSH_SK_ERR_GENERAL, r = -1;
	uint32_t alg;
	fido_credman_metadata_t *metadata = ଖାଲି;
	fido_credman_rp_t *rp = ଖାଲି;
	fido_credman_rk_t *rk = ଖାଲି;
	size_t i, j, nrp, nrk, user_id_len;
	ଅଚଳ fido_cred_t *cred;
	ଅଚଳ ଅକ୍ଷର *rp_id, *rp_name, *user_name;
	ସଂରଚନା sk_resident_ଚାବି *srk = ଖାଲି, **tmp;
	ଅଚଳ u_char *user_id;

	ଯଦି (pin == ଖାଲି) {
		skdebug(__func__, "no PIN specified");
		ret = SSH_SK_ERR_PIN_REQUIRED;
		ଯାଅ out;
	}
	ଯଦି ((metadata = fido_credman_metadata_new()) == ଖାଲି) {
		skdebug(__func__, "alloc failed");
		ଯାଅ out;
	}
	ଯଦି ((r = fido_credman_get_dev_metadata(sk->dev, metadata, pin)) != 0) {
		ଯଦି (r == FIDO_ERR_INVALID_COMMAND) {
			skdebug(__func__, "device %s does not support "
			    "resident keys", sk->path);
			ret = 0;
			ଯାଅ out;
		}
		skdebug(__func__, "get metadata for %s failed: %s",
		    sk->path, fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		ଯାଅ out;
	}
	skdebug(__func__, "existing %llu, remaining %llu",
	    (unsigned long long)fido_credman_rk_existing(metadata),
	    (unsigned long long)fido_credman_rk_remaining(metadata));
	ଯଦି ((rp = fido_credman_rp_new()) == ଖାଲି) {
		skdebug(__func__, "alloc rp failed");
		ଯାଅ out;
	}
	ଯଦି ((r = fido_credman_get_dev_rp(sk->dev, rp, pin)) != 0) {
		skdebug(__func__, "get RPs for %s failed: %s",
		    sk->path, fido_strerr(r));
		ଯାଅ out;
	}
	nrp = fido_credman_rp_ଗଣନା(rp);
	skdebug(__func__, "Device %s has resident keys for %zu RPs",
	    sk->path, nrp);

	/* Iterate over RP IDs that have resident keys */
	ପାଇଁ (i = 0; i < nrp; i++) {
		rp_id = fido_credman_rp_id(rp, i);
		rp_name = fido_credman_rp_name(rp, i);
		skdebug(__func__, "rp %zu: name=\"%s\" id=\"%s\" hashlen=%zu",
		    i, rp_name == ଖାଲି ? "(none)" : rp_name,
		    rp_id == ଖାଲି ? "(none)" : rp_id,
		    fido_credman_rp_id_hash_len(rp, i));

		/* Skip non-SSH RP IDs */
		ଯଦି (rp_id == ଖାଲି ||
		    strncasecmp(fido_credman_rp_id(rp, i), "ssh:", 4) != 0)
			ଜାରି;

		fido_credman_rk_free(&rk);
		ଯଦି ((rk = fido_credman_rk_new()) == ଖାଲି) {
			skdebug(__func__, "alloc rk failed");
			ଯାଅ out;
		}
		ଯଦି ((r = fido_credman_get_dev_rk(sk->dev,
		    fido_credman_rp_id(rp, i), rk, pin)) != 0) {
			skdebug(__func__, "get RKs for %s slot %zu failed: %s",
			    sk->path, i, fido_strerr(r));
			ଯାଅ out;
		}
		nrk = fido_credman_rk_ଗଣନା(rk);
		skdebug(__func__, "RP \"%s\" has %zu resident keys",
		    fido_credman_rp_id(rp, i), nrk);

		/* Iterate over resident keys for this RP ID */
		ପାଇଁ (j = 0; j < nrk; j++) {
			ଯଦି ((cred = fido_credman_rk(rk, j)) == ଖାଲି) {
				skdebug(__func__, "no RK in slot %zu", j);
				ଜାରି;
			}
			ଯଦି ((user_name = fido_cred_user_name(cred)) == ଖାଲି)
				user_name = "";
			user_id = fido_cred_user_id_ptr(cred);
			user_id_len = fido_cred_user_id_len(cred);
			skdebug(__func__, "Device %s RP \"%s\" user \"%s\" "
			    "uidlen %zu slot %zu: type %d flags 0x%02x "
			    "prot 0x%02x", sk->path, rp_id, user_name,
			    user_id_len, j, fido_cred_type(cred),
			    fido_cred_flags(cred), fido_cred_prot(cred));

			/* Determine key algorithm */
			ବାଛ (fido_cred_type(cred)) {
			ସ୍ଥିତି COSE_ES256:
				alg = SSH_SK_ECDSA;
				ଭାଙ୍ଗ;
			ସ୍ଥିତି COSE_EDDSA:
				alg = SSH_SK_ED25519;
				ଭାଙ୍ଗ;
			ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
				skdebug(__func__, "unsupported key type %d",
				    fido_cred_type(cred));
				ଜାରି;
			}

			/* build response entry */
			ଯଦି ((srk = calloc(1, ଆକାର(*srk))) == ଖାଲି ||
			    (srk->ଚାବି.ଚାବି_handle = calloc(1,
			    fido_cred_id_len(cred))) == ଖାଲି ||
			    (srk->application = strdup(rp_id)) == ଖାଲି ||
			    (user_id_len > 0 &&
			     (srk->user_id = calloc(1, user_id_len)) == ଖାଲି)) {
				skdebug(__func__, "alloc sk_resident_key");
				ଯାଅ out;
			}

			srk->alg = alg;
			srk->ଚାବି.ଚାବି_handle_len = fido_cred_id_len(cred);
			memcpy(srk->ଚାବି.ଚାବି_handle, fido_cred_id_ptr(cred),
			    srk->ଚାବି.ଚାବି_handle_len);
			srk->user_id_len = user_id_len;
			ଯଦି (srk->user_id_len != 0)
				memcpy(srk->user_id, user_id, srk->user_id_len);

#ifdef HAVE_FIDO_CRED_PROT
			ଯଦି (fido_cred_prot(cred) ==
			    FIDO_CRED_PROT_UV_REQUIRED)
				srk->flags |=  SSH_SK_USER_VERIFICATION_REQD;
#endif

			ଯଦି ((r = pack_public_ଚାବି(srk->alg, cred,
			    &srk->ଚାବି)) != 0) {
				skdebug(__func__, "pack public key failed");
				ଯାଅ out;
			}
			/* append */
			ଯଦି ((tmp = recallocarray(*rksp, *nrksp, (*nrksp) + 1,
			    ଆକାର(**rksp))) == ଖାଲି) {
				skdebug(__func__, "alloc rksp");
				ଯାଅ out;
			}
			*rksp = tmp;
			(*rksp)[(*nrksp)++] = srk;
			srk = ଖାଲି;
		}
	}
	/* Success */
	ret = 0;
 out:
	ଯଦି (srk != ଖାଲି) {
		ମୁକ୍ତ(srk->application);
		freezero(srk->ଚାବି.public_ଚାବି, srk->ଚାବି.public_ଚାବି_len);
		freezero(srk->ଚାବି.ଚାବି_handle, srk->ଚାବି.ଚାବି_handle_len);
		freezero(srk->user_id, srk->user_id_len);
		freezero(srk, ଆକାର(*srk));
	}
	fido_credman_rp_free(&rp);
	fido_credman_rk_free(&rk);
	fido_credman_metadata_free(&metadata);
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sk_load_resident_ଚାବିଗୁଡ଼ିକ(ଅଚଳ ଅକ୍ଷର *pin, ସଂରଚନା sk_option **options,
    ସଂରଚନା sk_resident_ଚାବି ***rksp, size_t *nrksp)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = SSH_SK_ERR_GENERAL, r = -1;
	size_t i, nrks = 0;
	ସଂରଚନା sk_resident_ଚାବି **rks = ଖାଲି;
	ସଂରଚନା sk_usbhid *sk = ଖାଲି;
	ଅକ୍ଷର *device = ଖାଲି;

	*rksp = ଖାଲି;
	*nrksp = 0;

	fido_init(SSH_FIDO_INIT_ARG);

	ଯଦି (check_sign_load_resident_options(options, &device) != 0)
		ଯାଅ out; /* error already logged */
	ଯଦି (device != ଖାଲି)
		sk = sk_open(device);
	ଅନ୍ୟଥା
		sk = sk_probe(ଖାଲି, ଖାଲି, 0, 1);
	ଯଦି (sk == ଖାଲି) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		ଯାଅ out;
	}
	skdebug(__func__, "trying %s", sk->path);
	ଯଦି ((r = read_rks(sk, pin, &rks, &nrks)) != 0) {
		skdebug(__func__, "read_rks failed for %s", sk->path);
		ret = r;
		ଯାଅ out;
	}
	/* success, unless we have no keys but a specific error */
	ଯଦି (nrks > 0 || ret == SSH_SK_ERR_GENERAL)
		ret = 0;
	*rksp = rks;
	*nrksp = nrks;
	rks = ଖାଲି;
	nrks = 0;
 out:
	sk_close(sk);
	ପାଇଁ (i = 0; i < nrks; i++) {
		ମୁକ୍ତ(rks[i]->application);
		freezero(rks[i]->ଚାବି.public_ଚାବି, rks[i]->ଚାବି.public_ଚାବି_len);
		freezero(rks[i]->ଚାବି.ଚାବି_handle, rks[i]->ଚାବି.ଚାବି_handle_len);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i], ଆକାର(*rks[i]));
	}
	ମୁକ୍ତ(device);
	ମୁକ୍ତ(rks);
	ଫେରନ୍ତୁ ret;
}

#endif /* ENABLE_SK_INTERNAL */
