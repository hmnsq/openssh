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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_SK_ਅੰਦਰੂਨੀ

#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SHA2_H
#ਅਨ੍ਤਰ੍ਭਾਵ <sha2.h>
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/opensslv.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/crypto.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ec.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ecdsa.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

#ਅਨ੍ਤਰ੍ਭਾਵ <fido.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fido/credman.h>

/* backwards compat for libfido2 */
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FIDO_CRED_PROT
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ fido_cred_prot(x) (0)
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FIDO_CRED_ਸੈੱਟ_PROT
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ fido_cred_ਸੈੱਟ_prot(x, y) (FIDO_ERR_UNSUPPORTED_OPTION)
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FIDO_DEV_SUPPORTS_CRED_PROT
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ fido_dev_supports_cred_prot(x) (0)
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FIDO_DEV_GET_TOUCH_BEGIN
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ fido_dev_get_touch_begin(x) (FIDO_ERR_UNSUPPORTED_OPTION)
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FIDO_DEV_GET_TOUCH_ਸਥਿਤੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ fido_dev_get_touch_ਸਥਿਤੀ(x, y, z) (FIDO_ERR_UNSUPPORTED_OPTION)
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ FIDO_CRED_PROT_UV_REQUIRED
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FIDO_CRED_PROT_UV_REQUIRED 0
#ਜੇ_ਅੰਤ
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID 0
#ਜੇ_ਅੰਤ

# include "misc.h"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ SK_STANDALONE
# include "log.h"
# include "xmalloc.h"
/*
 * If building as part of OpenSSH, then rename exported functions.
 * This must be done before including sk-api.h.
 */
# define sk_api_ਸੰਸਕਰਣ		ssh_sk_api_ਸੰਸਕਰਣ
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_ਲੱਦੋ_resident_ਕੁੰਜੀਆਂ	ssh_sk_ਲੱਦੋ_resident_ਕੁੰਜੀਆਂ
#ਜੇ_ਅੰਤ /* !SK_STANDALONE */

#ਅਨ੍ਤਰ੍ਭਾਵ "sk-api.h"

/* #define SK_DEBUG 1 */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SK_DEBUG
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_FIDO_INIT_ARG	FIDO_DEBUG
#ਨਹੀਂਤਾਂ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_FIDO_INIT_ARG	0
#ਜੇ_ਅੰਤ

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAX_FIDO_DEVICES	8
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FIDO_POLL_MS		50
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SELECT_MS		15000
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ POLL_SLEEP_NS		200000000

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ FIDO_ERR_OPERATION_DENIED
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FIDO_ERR_OPERATION_DENIED 0x27
#ਜੇ_ਅੰਤ

ਬਣਤਰ sk_usbhid {
	fido_dev_t *dev;
	ਅੱਖਰ *ਰਸਤਾ;
};

/* Return the version of the middleware API */
uint32_t sk_api_ਸੰਸਕਰਣ(ਖਾਲੀ);

/* Enroll a U2F key (private key generation) */
ਪੂਰਨ sk_enroll(uint32_t alg, ਅਚਲ uint8_t *challenge, ਮਾਪ_t challenge_len,
    ਅਚਲ ਅੱਖਰ *application, uint8_t flags, ਅਚਲ ਅੱਖਰ *pin,
    ਬਣਤਰ sk_option **options, ਬਣਤਰ sk_enroll_response **enroll_response);

/* Sign a challenge */
ਪੂਰਨ sk_sign(uint32_t alg, ਅਚਲ uint8_t *ਅੰਕੜੇ, ਮਾਪ_t ਅੰਕੜੇ_len,
    ਅਚਲ ਅੱਖਰ *application, ਅਚਲ uint8_t *ਕੁੰਜੀ_handle, ਮਾਪ_t ਕੁੰਜੀ_handle_len,
    uint8_t flags, ਅਚਲ ਅੱਖਰ *pin, ਬਣਤਰ sk_option **options,
    ਬਣਤਰ sk_sign_response **sign_response);

/* Load resident keys */
ਪੂਰਨ sk_ਲੱਦੋ_resident_ਕੁੰਜੀਆਂ(ਅਚਲ ਅੱਖਰ *pin, ਬਣਤਰ sk_option **options,
    ਬਣਤਰ sk_resident_ਕੁੰਜੀ ***rks, ਮਾਪ_t *nrks);

ਸਥਿਰ ਖਾਲੀ skdebug(ਅਚਲ ਅੱਖਰ *func, ਅਚਲ ਅੱਖਰ *fmt, ...)
    __attribute__((__format__ (ਲਿਖੋ, 2, 3)));

ਸਥਿਰ ਖਾਲੀ
skdebug(ਅਚਲ ਅੱਖਰ *func, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
#ਜੇ !defined(SK_STANDALONE)
	ਅੱਖਰ *ਸੁਨੇਹਾ;
	va_list ap;

	va_start(ap, fmt);
	xvasprintf(&ਸੁਨੇਹਾ, fmt, ap);
	va_end(ap);
	debug("%s: %s", func, ਸੁਨੇਹਾ);
	ਮੁਕਤ(ਸੁਨੇਹਾ);
#ਜਾਂਜੇ defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#ਨਹੀਂਤਾਂ
	(ਖਾਲੀ)func; /* XXX */
	(ਖਾਲੀ)fmt; /* XXX */
#ਜੇ_ਅੰਤ
}

uint32_t
sk_api_ਸੰਸਕਰਣ(ਖਾਲੀ)
{
	ਵਾਪਸ SSH_SK_ਸੰਸਕਰਣ_MAJOR;
}

ਸਥਿਰ ਬਣਤਰ sk_usbhid *
sk_open(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	ਬਣਤਰ sk_usbhid *sk;
	ਪੂਰਨ r;

	ਜੇ (ਰਸਤਾ == ਨਿਰਾ) {
		skdebug(__func__, "path == NULL");
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ ((sk = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*sk))) == ਨਿਰਾ) {
		skdebug(__func__, "calloc sk failed");
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ ((sk->ਰਸਤਾ = strdup(ਰਸਤਾ)) == ਨਿਰਾ) {
		skdebug(__func__, "strdup path failed");
		ਮੁਕਤ(sk);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ ((sk->dev = fido_dev_new()) == ਨਿਰਾ) {
		skdebug(__func__, "fido_dev_new failed");
		ਮੁਕਤ(sk->ਰਸਤਾ);
		ਮੁਕਤ(sk);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ ((r = fido_dev_open(sk->dev, sk->ਰਸਤਾ)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_open %s failed: %s", sk->ਰਸਤਾ,
		    fido_strerr(r));
		fido_dev_free(&sk->dev);
		ਮੁਕਤ(sk->ਰਸਤਾ);
		ਮੁਕਤ(sk);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਵਾਪਸ sk;
}

ਸਥਿਰ ਖਾਲੀ
sk_close(ਬਣਤਰ sk_usbhid *sk)
{
	ਜੇ (sk == ਨਿਰਾ)
		ਵਾਪਸ;
	fido_dev_cancel(sk->dev); /* cancel any pending operation */
	fido_dev_close(sk->dev);
	fido_dev_free(&sk->dev);
	ਮੁਕਤ(sk->ਰਸਤਾ);
	ਮੁਕਤ(sk);
}

ਸਥਿਰ ਬਣਤਰ sk_usbhid **
sk_openv(ਅਚਲ fido_dev_info_t *devlist, ਮਾਪ_t ndevs, ਮਾਪ_t *nopen)
{
	ਅਚਲ fido_dev_info_t *di;
	ਬਣਤਰ sk_usbhid **skv;
	ਮਾਪ_t i;

	*nopen = 0;
	ਜੇ ((skv = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(ndevs, ਆਕਾਰ(*skv))) == ਨਿਰਾ) {
		skdebug(__func__, "calloc skv failed");
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਲਈ (i = 0; i < ndevs; i++) {
		ਜੇ ((di = fido_dev_info_ptr(devlist, i)) == ਨਿਰਾ)
			skdebug(__func__, "fido_dev_info_ptr failed");
		ਨਹੀਂਤਾਂ ਜੇ ((skv[*nopen] = sk_open(fido_dev_info_ਰਸਤਾ(di))) == ਨਿਰਾ)
			skdebug(__func__, "sk_open failed");
		ਨਹੀਂਤਾਂ
			(*nopen)++;
	}
	ਜੇ (*nopen == 0) {
		ਲਈ (i = 0; i < ndevs; i++)
			sk_close(skv[i]);
		ਮੁਕਤ(skv);
		skv = ਨਿਰਾ;
	}

	ਵਾਪਸ skv;
}

ਸਥਿਰ ਖਾਲੀ
sk_closev(ਬਣਤਰ sk_usbhid **skv, ਮਾਪ_t nsk)
{
	ਮਾਪ_t i;

	ਲਈ (i = 0; i < nsk; i++)
		sk_close(skv[i]);
	ਮੁਕਤ(skv);
}

ਸਥਿਰ ਪੂਰਨ
sk_touch_begin(ਬਣਤਰ sk_usbhid **skv, ਮਾਪ_t nsk)
{
	ਮਾਪ_t i, ok = 0;
	ਪੂਰਨ r;

	ਲਈ (i = 0; i < nsk; i++)
		ਜੇ ((r = fido_dev_get_touch_begin(skv[i]->dev)) != FIDO_OK)
			skdebug(__func__, "fido_dev_get_touch_begin %s failed:"
			    " %s", skv[i]->ਰਸਤਾ, fido_strerr(r));
		ਨਹੀਂਤਾਂ
			ok++;

	ਵਾਪਸ ok ? 0 : -1;
}

ਸਥਿਰ ਪੂਰਨ
sk_touch_poll(ਬਣਤਰ sk_usbhid **skv, ਮਾਪ_t nsk, ਪੂਰਨ *touch, ਮਾਪ_t *idx)
{
	ਬਣਤਰ timespec ts_pause;
	ਮਾਪ_t npoll, i;
	ਪੂਰਨ r;

	ts_pause.tv_sec = 0;
	ts_pause.tv_nsec = POLL_SLEEP_NS;
	nanosleep(&ts_pause, ਨਿਰਾ);
	npoll = nsk;
	ਲਈ (i = 0; i < nsk; i++) {
		ਜੇ (skv[i] == ਨਿਰਾ)
			ਜਾਰੀ; /* device discarded */
		skdebug(__func__, "polling %s", skv[i]->ਰਸਤਾ);
		ਜੇ ((r = fido_dev_get_touch_ਸਥਿਤੀ(skv[i]->dev, touch,
		    FIDO_POLL_MS)) != FIDO_OK) {
			skdebug(__func__, "fido_dev_get_touch_status %s: %s",
			    skv[i]->ਰਸਤਾ, fido_strerr(r));
			sk_close(skv[i]); /* discard device */
			skv[i] = ਨਿਰਾ;
			ਜੇ (--npoll == 0) {
				skdebug(__func__, "no device left to poll");
				ਵਾਪਸ -1;
			}
		} ਨਹੀਂਤਾਂ ਜੇ (*touch) {
			*idx = i;
			ਵਾਪਸ 0;
		}
	}
	*touch = 0;
	ਵਾਪਸ 0;
}

#ਜੇ !defined(HAVE_FIDO_ASSERT_ਸੈੱਟ_CLIENTDATA) || \
    !defined(HAVE_FIDO_CRED_ਸੈੱਟ_CLIENTDATA)
/* Calculate SHA256(m) */
ਸਥਿਰ ਪੂਰਨ
sha256_mem(ਅਚਲ ਖਾਲੀ *m, ਮਾਪ_t mlen, u_char *d, ਮਾਪ_t dlen)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	u_int mdlen;
#ਨਹੀਂਤਾਂ
	SHA2_CTX ctx;
#ਜੇ_ਅੰਤ

	ਜੇ (dlen != 32)
		ਵਾਪਸ -1;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	mdlen = dlen;
	ਜੇ (!EVP_Digest(m, mlen, d, &mdlen, EVP_sha256(), ਨਿਰਾ))
		ਵਾਪਸ -1;
#ਨਹੀਂਤਾਂ
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ਅਚਲ uint8_t *)m, mlen);
	SHA256Final(d, &ctx);
#ਜੇ_ਅੰਤ
	ਵਾਪਸ 0;
}
#ਜੇ_ਅੰਤ /* !HAVE_FIDO_ASSERT_SET_CLIENTDATA || !HAVE_FIDO_CRED_SET_CLIENTDATA */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FIDO_CRED_ਸੈੱਟ_CLIENTDATA
ਸਥਿਰ ਪੂਰਨ
fido_cred_ਸੈੱਟ_clientdata(fido_cred_t *cred, ਅਚਲ u_char *ptr, ਮਾਪ_t len)
{
	uint8_t d[32];
	ਪੂਰਨ r;

	ਜੇ (sha256_mem(ptr, len, d, ਆਕਾਰ(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		ਵਾਪਸ FIDO_ERR_ਅੰਦਰੂਨੀ;
	}
	r = fido_cred_ਸੈੱਟ_clientdata_hash(cred, d, ਆਕਾਰ(d));
	explicit_bzero(d, ਆਕਾਰ(d));
	ਜੇ (r != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	ਵਾਪਸ r;
}
#ਜੇ_ਅੰਤ /* HAVE_FIDO_CRED_SET_CLIENTDATA */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FIDO_ASSERT_ਸੈੱਟ_CLIENTDATA
ਸਥਿਰ ਪੂਰਨ
fido_assert_ਸੈੱਟ_clientdata(fido_assert_t *ਪ੍ਰਤਿਜ੍ਞਾ, ਅਚਲ u_char *ptr, ਮਾਪ_t len)
{
	uint8_t d[32];
	ਪੂਰਨ r;

	ਜੇ (sha256_mem(ptr, len, d, ਆਕਾਰ(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		ਵਾਪਸ FIDO_ERR_ਅੰਦਰੂਨੀ;
	}
	r = fido_assert_ਸੈੱਟ_clientdata_hash(ਪ੍ਰਤਿਜ੍ਞਾ, d, ਆਕਾਰ(d));
	explicit_bzero(d, ਆਕਾਰ(d));
	ਜੇ (r != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	ਵਾਪਸ r;
}
#ਜੇ_ਅੰਤ /* HAVE_FIDO_ASSERT_SET_CLIENTDATA */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FIDO_DEV_IS_WINHELLO
ਸਥਿਰ bool
fido_dev_is_winhello(ਅਚਲ fido_dev_t *fdev)
{
	ਵਾਪਸ 0;
}
#ਜੇ_ਅੰਤ /* HAVE_FIDO_DEV_IS_WINHELLO */

/* Check if the specified key handle exists on a given sk. */
ਸਥਿਰ ਪੂਰਨ
sk_try(ਅਚਲ ਬਣਤਰ sk_usbhid *sk, ਅਚਲ ਅੱਖਰ *application,
    ਅਚਲ uint8_t *ਕੁੰਜੀ_handle, ਮਾਪ_t ਕੁੰਜੀ_handle_len)
{
	fido_assert_t *ਪ੍ਰਤਿਜ੍ਞਾ = ਨਿਰਾ;
	ਪੂਰਨ r = FIDO_ERR_ਅੰਦਰੂਨੀ;
	uint8_t ਸੁਨੇਹਾ_2[32];

	memset(ਸੁਨੇਹਾ_2, '\0', ਆਕਾਰ(ਸੁਨੇਹਾ_2));
	ਜੇ ((ਪ੍ਰਤਿਜ੍ਞਾ = fido_assert_new()) == ਨਿਰਾ) {
		skdebug(__func__, "fido_assert_new failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* generate an invalid signature on FIDO2 tokens */
	ਜੇ ((r = fido_assert_ਸੈੱਟ_clientdata(ਪ੍ਰਤਿਜ੍ਞਾ, ਸੁਨੇਹਾ_2,
	    ਆਕਾਰ(ਸੁਨੇਹਾ_2))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = fido_assert_ਸੈੱਟ_rp(ਪ੍ਰਤਿਜ੍ਞਾ, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = fido_assert_allow_cred(ਪ੍ਰਤਿਜ੍ਞਾ, ਕੁੰਜੀ_handle,
	    ਕੁੰਜੀ_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = fido_assert_ਸੈੱਟ_ਉੱਪਰ(ਪ੍ਰਤਿਜ੍ਞਾ, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_up: %s", fido_strerr(r));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	r = fido_dev_get_assert(sk->dev, ਪ੍ਰਤਿਜ੍ਞਾ, ਨਿਰਾ);
	skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
	ਜੇ (r == FIDO_ERR_USER_PRESENCE_REQUIRED) {
		/* U2F tokens may return this */
		r = FIDO_OK;
	}
 ਬਾਹਰਲਾ:
	fido_assert_free(&ਪ੍ਰਤਿਜ੍ਞਾ);

	ਵਾਪਸ r != FIDO_OK ? -1 : 0;
}

ਸਥਿਰ ਪੂਰਨ
check_sk_options(fido_dev_t *dev, ਅਚਲ ਅੱਖਰ *opt, ਪੂਰਨ *ret)
{
	fido_cbor_info_t *info;
	ਅੱਖਰ * ਅਚਲ *name;
	ਅਚਲ bool *ਮੁੱਲ;
	ਮਾਪ_t len, i;
	ਪੂਰਨ r;

	*ret = -1;

	ਜੇ (!fido_dev_is_fido2(dev)) {
		skdebug(__func__, "device is not fido2");
		ਵਾਪਸ 0;
	}
	ਜੇ ((info = fido_cbor_info_new()) == ਨਿਰਾ) {
		skdebug(__func__, "fido_cbor_info_new failed");
		ਵਾਪਸ -1;
	}
	ਜੇ ((r = fido_dev_get_cbor_info(dev, info)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_cbor_info: %s", fido_strerr(r));
		fido_cbor_info_free(&info);
		ਵਾਪਸ -1;
	}
	name = fido_cbor_info_options_name_ptr(info);
	ਮੁੱਲ = fido_cbor_info_options_ਮੁੱਲ_ptr(info);
	len = fido_cbor_info_options_len(info);
	ਲਈ (i = 0; i < len; i++) {
		ਜੇ (!strcmp(name[i], opt)) {
			*ret = ਮੁੱਲ[i];
			ਰੋਕੋ;
		}
	}
	fido_cbor_info_free(&info);
	ਜੇ (*ret == -1)
		skdebug(__func__, "option %s is unknown", opt);
	ਨਹੀਂਤਾਂ
		skdebug(__func__, "option %s is %s", opt, *ret ? "on" : "off");

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਬਣਤਰ sk_usbhid *
sk_select_by_cred(ਅਚਲ fido_dev_info_t *devlist, ਮਾਪ_t ndevs,
    ਅਚਲ ਅੱਖਰ *application, ਅਚਲ uint8_t *ਕੁੰਜੀ_handle, ਮਾਪ_t ਕੁੰਜੀ_handle_len)
{
	ਬਣਤਰ sk_usbhid **skv, *sk;
	ਮਾਪ_t skvcnt, i;
	ਪੂਰਨ ਅੰਦਰੂਨੀ_uv;

	ਜੇ ((skv = sk_openv(devlist, ndevs, &skvcnt)) == ਨਿਰਾ) {
		skdebug(__func__, "sk_openv failed");
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ (skvcnt == 1 && check_sk_options(skv[0]->dev, "uv",
	    &ਅੰਦਰੂਨੀ_uv) == 0 && ਅੰਦਰੂਨੀ_uv != -1) {
		sk = skv[0];
		skv[0] = ਨਿਰਾ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	sk = ਨਿਰਾ;
	ਲਈ (i = 0; i < skvcnt; i++) {
		ਜੇ (sk_try(skv[i], application, ਕੁੰਜੀ_handle,
		    ਕੁੰਜੀ_handle_len) == 0) {
			sk = skv[i];
			skv[i] = ਨਿਰਾ;
			skdebug(__func__, "found key in %s", sk->ਰਸਤਾ);
			ਰੋਕੋ;
		}
	}
 ਬਾਹਰਲਾ:
	sk_closev(skv, skvcnt);
	ਵਾਪਸ sk;
}

ਸਥਿਰ ਬਣਤਰ sk_usbhid *
sk_select_by_touch(ਅਚਲ fido_dev_info_t *devlist, ਮਾਪ_t ndevs)
{
	ਬਣਤਰ sk_usbhid **skv, *sk;
	ਬਣਤਰ timeval tv_ਸ਼ੁਰੂ, tv_now, tv_delta;
	ਮਾਪ_t skvcnt, idx;
	ਪੂਰਨ touch, ms_remain;

	ਜੇ ((skv = sk_openv(devlist, ndevs, &skvcnt)) == ਨਿਰਾ) {
		skdebug(__func__, "sk_openv failed");
		ਵਾਪਸ ਨਿਰਾ;
	}
	sk = ਨਿਰਾ;
	ਜੇ (skvcnt < 2) {
		ਜੇ (skvcnt == 1) {
			/* single candidate */
			sk = skv[0];
			skv[0] = ਨਿਰਾ;
		}
		ਜਾਓ ਬਾਹਰਲਾ;
	}
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_FIDO_DEV_GET_TOUCH_ਸਥਿਤੀ
	skdebug(__func__, "libfido2 version does not support a feature needed for multiple tokens. Please upgrade to >=1.5.0");
	ਜਾਓ ਬਾਹਰਲਾ;
#ਜੇ_ਅੰਤ

	ਜੇ (sk_touch_begin(skv, skvcnt) == -1) {
		skdebug(__func__, "sk_touch_begin failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	monotime_tv(&tv_ਸ਼ੁਰੂ);
	ਕਰੋ {
		ਜੇ (sk_touch_poll(skv, skvcnt, &touch, &idx) == -1) {
			skdebug(__func__, "sk_touch_poll failed");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (touch) {
			sk = skv[idx];
			skv[idx] = ਨਿਰਾ;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		monotime_tv(&tv_now);
		timersub(&tv_now, &tv_ਸ਼ੁਰੂ, &tv_delta);
		ms_remain = SELECT_MS - tv_delta.tv_sec * 1000 -
		    tv_delta.tv_usec / 1000;
	} ਜਦੋਂ (ms_remain >= FIDO_POLL_MS);
	skdebug(__func__, "timeout");
ਬਾਹਰਲਾ:
	sk_closev(skv, skvcnt);
	ਵਾਪਸ sk;
}

ਸਥਿਰ ਬਣਤਰ sk_usbhid *
sk_probe(ਅਚਲ ਅੱਖਰ *application, ਅਚਲ uint8_t *ਕੁੰਜੀ_handle,
    ਮਾਪ_t ਕੁੰਜੀ_handle_len, ਪੂਰਨ probe_resident)
{
	ਬਣਤਰ sk_usbhid *sk;
	fido_dev_info_t *devlist;
	ਮਾਪ_t ndevs;
	ਪੂਰਨ r;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_CYGWIN
	ਜੇ (!probe_resident && (sk = sk_open("windows://hello")) != ਨਿਰਾ)
		ਵਾਪਸ sk;
#ਜੇ_ਅੰਤ /* HAVE_CYGWIN */
	ਜੇ ((devlist = fido_dev_info_new(MAX_FIDO_DEVICES)) == ਨਿਰਾ) {
		skdebug(__func__, "fido_dev_info_new failed");
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ ((r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES,
	    &ndevs)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_info_manifest failed: %s",
		    fido_strerr(r));
		fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
		ਵਾਪਸ ਨਿਰਾ;
	}
	skdebug(__func__, "%zu device(s) detected", ndevs);
	ਜੇ (ndevs == 0) {
		sk = ਨਿਰਾ;
	} ਨਹੀਂਤਾਂ ਜੇ (application != ਨਿਰਾ && ਕੁੰਜੀ_handle != ਨਿਰਾ) {
		skdebug(__func__, "selecting sk by cred");
		sk = sk_select_by_cred(devlist, ndevs, application, ਕੁੰਜੀ_handle,
		    ਕੁੰਜੀ_handle_len);
	} ਨਹੀਂਤਾਂ {
		skdebug(__func__, "selecting sk by touch");
		sk = sk_select_by_touch(devlist, ndevs);
	}
	fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
	ਵਾਪਸ sk;
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
/*
 * The key returned via fido_cred_pubkey_ptr() is in affine coordinates,
 * but the API expects a SEC1 octet string.
 */
ਸਥਿਰ ਪੂਰਨ
pack_ਜਨਤਕ_ਕੁੰਜੀ_ecdsa(ਅਚਲ fido_cred_t *cred,
    ਬਣਤਰ sk_enroll_response *response)
{
	ਅਚਲ uint8_t *ptr;
	BIGNUM *x = ਨਿਰਾ, *y = ਨਿਰਾ;
	EC_ਬਿੰਦੂ *q = ਨਿਰਾ;
	EC_ਸਮੂਹ *g = ਨਿਰਾ;
	ਪੂਰਨ ret = -1;

	response->ਜਨਤਕ_ਕੁੰਜੀ = ਨਿਰਾ;
	response->ਜਨਤਕ_ਕੁੰਜੀ_len = 0;

	ਜੇ ((x = BN_new()) == ਨਿਰਾ ||
	    (y = BN_new()) == ਨਿਰਾ ||
	    (g = EC_ਸਮੂਹ_new_by_ਵਕਰ_name(NID_X9_62_prime256v1)) == ਨਿਰਾ ||
	    (q = EC_ਬਿੰਦੂ_new(g)) == ਨਿਰਾ) {
		skdebug(__func__, "libcrypto setup failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((ptr = fido_cred_pubkey_ptr(cred)) == ਨਿਰਾ) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (fido_cred_pubkey_len(cred) != 64) {
		skdebug(__func__, "bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ (BN_bin2bn(ptr, 32, x) == ਨਿਰਾ ||
	    BN_bin2bn(ptr + 32, 32, y) == ਨਿਰਾ) {
		skdebug(__func__, "BN_bin2bn failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EC_ਬਿੰਦੂ_ਸੈੱਟ_affine_coordinates(g, q, x, y, ਨਿਰਾ) != 1) {
		skdebug(__func__, "EC_POINT_set_affine_coordinates failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	response->ਜਨਤਕ_ਕੁੰਜੀ_len = EC_ਬਿੰਦੂ_point2oct(g, q,
	    ਬਿੰਦੂ_CONVERSION_UNCOMPRESSED, ਨਿਰਾ, 0, ਨਿਰਾ);
	ਜੇ (response->ਜਨਤਕ_ਕੁੰਜੀ_len == 0 || response->ਜਨਤਕ_ਕੁੰਜੀ_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->ਜਨਤਕ_ਕੁੰਜੀ_len);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((response->ਜਨਤਕ_ਕੁੰਜੀ = ਸਮ੍ਰਿਤੀ_ਦਿਓ(response->ਜਨਤਕ_ਕੁੰਜੀ_len)) == ਨਿਰਾ) {
		skdebug(__func__, "malloc pubkey failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EC_ਬਿੰਦੂ_point2oct(g, q, ਬਿੰਦੂ_CONVERSION_UNCOMPRESSED,
	    response->ਜਨਤਕ_ਕੁੰਜੀ, response->ਜਨਤਕ_ਕੁੰਜੀ_len, ਨਿਰਾ) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	ret = 0;
 ਬਾਹਰਲਾ:
	ਜੇ (ret != 0 && response->ਜਨਤਕ_ਕੁੰਜੀ != ਨਿਰਾ) {
		memset(response->ਜਨਤਕ_ਕੁੰਜੀ, 0, response->ਜਨਤਕ_ਕੁੰਜੀ_len);
		ਮੁਕਤ(response->ਜਨਤਕ_ਕੁੰਜੀ);
		response->ਜਨਤਕ_ਕੁੰਜੀ = ਨਿਰਾ;
	}
	EC_ਬਿੰਦੂ_free(q);
	EC_ਸਮੂਹ_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	ਵਾਪਸ ret;
}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

ਸਥਿਰ ਪੂਰਨ
pack_ਜਨਤਕ_ਕੁੰਜੀ_ed25519(ਅਚਲ fido_cred_t *cred,
    ਬਣਤਰ sk_enroll_response *response)
{
	ਅਚਲ uint8_t *ptr;
	ਮਾਪ_t len;
	ਪੂਰਨ ret = -1;

	response->ਜਨਤਕ_ਕੁੰਜੀ = ਨਿਰਾ;
	response->ਜਨਤਕ_ਕੁੰਜੀ_len = 0;

	ਜੇ ((len = fido_cred_pubkey_len(cred)) != 32) {
		skdebug(__func__, "bad fido_cred_pubkey_len len %zu", len);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((ptr = fido_cred_pubkey_ptr(cred)) == ਨਿਰਾ) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	response->ਜਨਤਕ_ਕੁੰਜੀ_len = len;
	ਜੇ ((response->ਜਨਤਕ_ਕੁੰਜੀ = ਸਮ੍ਰਿਤੀ_ਦਿਓ(response->ਜਨਤਕ_ਕੁੰਜੀ_len)) == ਨਿਰਾ) {
		skdebug(__func__, "malloc pubkey failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(response->ਜਨਤਕ_ਕੁੰਜੀ, ptr, len);
	ret = 0;
 ਬਾਹਰਲਾ:
	ਜੇ (ret != 0)
		ਮੁਕਤ(response->ਜਨਤਕ_ਕੁੰਜੀ);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
pack_ਜਨਤਕ_ਕੁੰਜੀ(uint32_t alg, ਅਚਲ fido_cred_t *cred,
    ਬਣਤਰ sk_enroll_response *response)
{
	ਚੋਣ(alg) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਹਾਲਤ SSH_SK_ECDSA:
		ਵਾਪਸ pack_ਜਨਤਕ_ਕੁੰਜੀ_ecdsa(cred, response);
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
	ਹਾਲਤ SSH_SK_ED25519:
		ਵਾਪਸ pack_ਜਨਤਕ_ਕੁੰਜੀ_ed25519(cred, response);
	ਮੂਲ:
		ਵਾਪਸ -1;
	}
}

ਸਥਿਰ ਪੂਰਨ
fidoerr_ਮੰਜ਼ਿਲ_skerr(ਪੂਰਨ fidoerr)
{
	ਚੋਣ (fidoerr) {
	ਹਾਲਤ FIDO_ERR_UNSUPPORTED_OPTION:
	ਹਾਲਤ FIDO_ERR_UNSUPPORTED_ALGORITHM:
		ਵਾਪਸ SSH_SK_ERR_UNSUPPORTED;
	ਹਾਲਤ FIDO_ERR_PIN_REQUIRED:
	ਹਾਲਤ FIDO_ERR_PIN_INVALID:
	ਹਾਲਤ FIDO_ERR_OPERATION_DENIED:
		ਵਾਪਸ SSH_SK_ERR_PIN_REQUIRED;
	ਮੂਲ:
		ਵਾਪਸ -1;
	}
}

ਸਥਿਰ ਪੂਰਨ
check_enroll_options(ਬਣਤਰ sk_option **options, ਅੱਖਰ **devicep,
    uint8_t *user_id, ਮਾਪ_t user_id_len)
{
	ਮਾਪ_t i;

	ਜੇ (options == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਲਈ (i = 0; options[i] != ਨਿਰਾ; i++) {
		ਜੇ (strcmp(options[i]->name, "device") == 0) {
			ਜੇ ((*devicep = strdup(options[i]->ਮੁੱਲ)) == ਨਿਰਾ) {
				skdebug(__func__, "strdup device failed");
				ਵਾਪਸ -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} ਨਹੀਂਤਾਂ ਜੇ (strcmp(options[i]->name, "user") == 0) {
			ਜੇ (strlcpy(user_id, options[i]->ਮੁੱਲ, user_id_len) >=
			    user_id_len) {
				skdebug(__func__, "user too long");
				ਵਾਪਸ -1;
			}
			skdebug(__func__, "requested user %s",
			    (ਅੱਖਰ *)user_id);
		} ਨਹੀਂਤਾਂ {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			ਜੇ (options[i]->required) {
				skdebug(__func__, "unknown required option");
				ਵਾਪਸ -1;
			}
		}
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ਕੁੰਜੀ_lookup(fido_dev_t *dev, ਅਚਲ ਅੱਖਰ *application, ਅਚਲ uint8_t *user_id,
    ਮਾਪ_t user_id_len, ਅਚਲ ਅੱਖਰ *pin)
{
	fido_assert_t *ਪ੍ਰਤਿਜ੍ਞਾ = ਨਿਰਾ;
	uint8_t ਸੁਨੇਹਾ_2[32];
	ਪੂਰਨ r = FIDO_ERR_ਅੰਦਰੂਨੀ;
	ਪੂਰਨ sk_supports_uv, uv;
	ਮਾਪ_t i;

	memset(ਸੁਨੇਹਾ_2, '\0', ਆਕਾਰ(ਸੁਨੇਹਾ_2));
	ਜੇ ((ਪ੍ਰਤਿਜ੍ਞਾ = fido_assert_new()) == ਨਿਰਾ) {
		skdebug(__func__, "fido_assert_new failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* generate an invalid signature on FIDO2 tokens */
	ਜੇ ((r = fido_assert_ਸੈੱਟ_clientdata(ਪ੍ਰਤਿਜ੍ਞਾ, ਸੁਨੇਹਾ_2,
	    ਆਕਾਰ(ਸੁਨੇਹਾ_2))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = fido_assert_ਸੈੱਟ_rp(ਪ੍ਰਤਿਜ੍ਞਾ, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = fido_assert_ਸੈੱਟ_ਉੱਪਰ(ਪ੍ਰਤਿਜ੍ਞਾ, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	uv = FIDO_OPT_OMIT;
	ਜੇ (pin == ਨਿਰਾ && check_sk_options(dev, "uv", &sk_supports_uv) == 0 &&
	    sk_supports_uv != -1)
		uv = FIDO_OPT_TRUE;
	ਜੇ ((r = fido_assert_ਸੈੱਟ_uv(ਪ੍ਰਤਿਜ੍ਞਾ, uv)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = fido_dev_get_assert(dev, ਪ੍ਰਤਿਜ੍ਞਾ, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	r = FIDO_ERR_NO_CREDENTIALS;
	skdebug(__func__, "%zu signatures returned", fido_assert_ਗਿਣਤੀ(ਪ੍ਰਤਿਜ੍ਞਾ));
	ਲਈ (i = 0; i < fido_assert_ਗਿਣਤੀ(ਪ੍ਰਤਿਜ੍ਞਾ); i++) {
		ਜੇ (fido_assert_user_id_len(ਪ੍ਰਤਿਜ੍ਞਾ, i) == user_id_len &&
		    memcmp(fido_assert_user_id_ptr(ਪ੍ਰਤਿਜ੍ਞਾ, i), user_id,
		    user_id_len) == 0) {
			skdebug(__func__, "credential exists");
			r = FIDO_OK;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}
 ਬਾਹਰਲਾ:
	fido_assert_free(&ਪ੍ਰਤਿਜ੍ਞਾ);

	ਵਾਪਸ r;
}

ਪੂਰਨ
sk_enroll(uint32_t alg, ਅਚਲ uint8_t *challenge, ਮਾਪ_t challenge_len,
    ਅਚਲ ਅੱਖਰ *application, uint8_t flags, ਅਚਲ ਅੱਖਰ *pin,
    ਬਣਤਰ sk_option **options, ਬਣਤਰ sk_enroll_response **enroll_response)
{
	fido_cred_t *cred = ਨਿਰਾ;
	ਅਚਲ uint8_t *ptr;
	uint8_t user_id[32];
	ਬਣਤਰ sk_usbhid *sk = ਨਿਰਾ;
	ਬਣਤਰ sk_enroll_response *response = ਨਿਰਾ;
	ਮਾਪ_t len;
	ਪੂਰਨ credprot;
	ਪੂਰਨ cose_alg;
	ਪੂਰਨ ret = SSH_SK_ERR_GENERAL;
	ਪੂਰਨ r;
	ਅੱਖਰ *device = ਨਿਰਾ;

	fido_init(SSH_FIDO_INIT_ARG);

	ਜੇ (enroll_response == ਨਿਰਾ) {
		skdebug(__func__, "enroll_response == NULL");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	*enroll_response = ਨਿਰਾ;
	memset(user_id, 0, ਆਕਾਰ(user_id));
	ਜੇ (check_enroll_options(options, &device, user_id,
	    ਆਕਾਰ(user_id)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ; /* error already logged */

	ਚੋਣ(alg) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਹਾਲਤ SSH_SK_ECDSA:
		cose_alg = COSE_ES256;
		ਰੋਕੋ;
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
	ਹਾਲਤ SSH_SK_ED25519:
		cose_alg = COSE_EDDSA;
		ਰੋਕੋ;
	ਮੂਲ:
		skdebug(__func__, "unsupported key type %d", alg);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (device != ਨਿਰਾ)
		sk = sk_open(device);
	ਨਹੀਂਤਾਂ
		sk = sk_probe(ਨਿਰਾ, ਨਿਰਾ, 0, 0);
	ਜੇ (sk == ਨਿਰਾ) {
		ret = SSH_SK_ERR_DEVICE_NOT_ਮਿਲਿਆ;
		skdebug(__func__, "failed to find sk");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	skdebug(__func__, "using device %s", sk->ਰਸਤਾ);
	ਜੇ ((flags & SSH_SK_RESIDENT_ਕੁੰਜੀ) != 0 &&
	    (flags & SSH_SK_FORCE_OPERATION) == 0 &&
	    (r = ਕੁੰਜੀ_lookup(sk->dev, application, user_id, ਆਕਾਰ(user_id),
	    pin)) != FIDO_ERR_NO_CREDENTIALS) {
		ਜੇ (r != FIDO_OK) {
			ret = fidoerr_ਮੰਜ਼ਿਲ_skerr(r);
			skdebug(__func__, "key_lookup failed");
		} ਨਹੀਂਤਾਂ {
			ret = SSH_SK_ERR_CREDENTIAL_EXISTS;
			skdebug(__func__, "key exists");
		}
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((cred = fido_cred_new()) == ਨਿਰਾ) {
		skdebug(__func__, "fido_cred_new failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = fido_cred_ਸੈੱਟ_type(cred, cose_alg)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_type: %s", fido_strerr(r));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = fido_cred_ਸੈੱਟ_clientdata(cred,
	    challenge, challenge_len)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata: %s",
		    fido_strerr(r));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = fido_cred_ਸੈੱਟ_rk(cred, (flags & SSH_SK_RESIDENT_ਕੁੰਜੀ) != 0 ?
	    FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rk: %s", fido_strerr(r));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = fido_cred_ਸੈੱਟ_user(cred, user_id, ਆਕਾਰ(user_id),
	    "openssh", "openssh", ਨਿਰਾ)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_user: %s", fido_strerr(r));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = fido_cred_ਸੈੱਟ_rp(cred, application, ਨਿਰਾ)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rp: %s", fido_strerr(r));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((flags & (SSH_SK_RESIDENT_ਕੁੰਜੀ|SSH_SK_USER_VERIFICATION_REQD)) != 0) {
#ਜੇ !defined(HAVE_FIDO_DEV_SUPPORTS_CRED_PROT) || \
    !defined(HAVE_FIDO_CRED_ਸੈੱਟ_PROT)
		skdebug(__func__, "libfido2 version does not support a feature required for this operation. Please upgrade to >=1.5.0");
		ret = SSH_SK_ERR_UNSUPPORTED;
		ਜਾਓ ਬਾਹਰਲਾ;
		credprot = 0; (ਖਾਲੀ)credprot; /* avoid warning */
#ਜੇ_ਅੰਤ
		ਜੇ (!fido_dev_supports_cred_prot(sk->dev)) {
			skdebug(__func__, "%s does not support credprot, "
			    "refusing to create unprotected "
			    "resident/verify-required key", sk->ਰਸਤਾ);
			ret = SSH_SK_ERR_UNSUPPORTED;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((flags & SSH_SK_USER_VERIFICATION_REQD))
			credprot = FIDO_CRED_PROT_UV_REQUIRED;
		ਨਹੀਂਤਾਂ
			credprot = FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID;

		ਜੇ ((r = fido_cred_ਸੈੱਟ_prot(cred, credprot)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_set_prot: %s",
			    fido_strerr(r));
			ret = fidoerr_ਮੰਜ਼ਿਲ_skerr(r);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}
	ਜੇ ((r = fido_dev_make_cred(sk->dev, cred, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_make_cred: %s", fido_strerr(r));
		ret = fidoerr_ਮੰਜ਼ਿਲ_skerr(r);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (fido_cred_x5c_ptr(cred) != ਨਿਰਾ) {
		ਜੇ ((r = fido_cred_verify(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify: %s",
			    fido_strerr(r));
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	} ਨਹੀਂਤਾਂ ਜੇ (strcmp(fido_cred_fmt(cred), "none") != 0) {
		skdebug(__func__, "self-attested credential");
		ਜੇ ((r = fido_cred_verify_self(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify_self: %s",
			    fido_strerr(r));
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	} ਨਹੀਂਤਾਂ {
		skdebug(__func__, "no attestation data");
	}
	ਜੇ ((response = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*response))) == ਨਿਰਾ) {
		skdebug(__func__, "calloc response failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	response->flags = flags;
	ਜੇ (pack_ਜਨਤਕ_ਕੁੰਜੀ(alg, cred, response) != 0) {
		skdebug(__func__, "pack_public_key failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((ptr = fido_cred_id_ptr(cred)) != ਨਿਰਾ) {
		len = fido_cred_id_len(cred);
		ਜੇ ((response->ਕੁੰਜੀ_handle = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, len)) == ਨਿਰਾ) {
			skdebug(__func__, "calloc key handle failed");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(response->ਕੁੰਜੀ_handle, ptr, len);
		response->ਕੁੰਜੀ_handle_len = len;
	}
	ਜੇ ((ptr = fido_cred_sig_ptr(cred)) != ਨਿਰਾ) {
		len = fido_cred_sig_len(cred);
		ਜੇ ((response->signature = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, len)) == ਨਿਰਾ) {
			skdebug(__func__, "calloc signature failed");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(response->signature, ptr, len);
		response->signature_len = len;
	}
	ਜੇ ((ptr = fido_cred_x5c_ptr(cred)) != ਨਿਰਾ) {
		len = fido_cred_x5c_len(cred);
		skdebug(__func__, "attestation cert len=%zu", len);
		ਜੇ ((response->attestation_cert = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, len)) == ਨਿਰਾ) {
			skdebug(__func__, "calloc attestation cert failed");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(response->attestation_cert, ptr, len);
		response->attestation_cert_len = len;
	}
	ਜੇ ((ptr = fido_cred_authdata_ptr(cred)) != ਨਿਰਾ) {
		len = fido_cred_authdata_len(cred);
		skdebug(__func__, "authdata len=%zu", len);
		ਜੇ ((response->authdata = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, len)) == ਨਿਰਾ) {
			skdebug(__func__, "calloc authdata failed");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(response->authdata, ptr, len);
		response->authdata_len = len;
	}
	*enroll_response = response;
	response = ਨਿਰਾ;
	ret = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(device);
	ਜੇ (response != ਨਿਰਾ) {
		ਮੁਕਤ(response->ਜਨਤਕ_ਕੁੰਜੀ);
		ਮੁਕਤ(response->ਕੁੰਜੀ_handle);
		ਮੁਕਤ(response->signature);
		ਮੁਕਤ(response->attestation_cert);
		ਮੁਕਤ(response->authdata);
		ਮੁਕਤ(response);
	}
	sk_close(sk);
	fido_cred_free(&cred);
	ਵਾਪਸ ret;
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
ਸਥਿਰ ਪੂਰਨ
pack_sig_ecdsa(fido_assert_t *ਪ੍ਰਤਿਜ੍ਞਾ, ਬਣਤਰ sk_sign_response *response)
{
	ECDSA_SIG *sig = ਨਿਰਾ;
	ਅਚਲ BIGNUM *sig_r, *sig_s;
	ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *cp;
	ਮਾਪ_t sig_len;
	ਪੂਰਨ ret = -1;

	cp = fido_assert_sig_ptr(ਪ੍ਰਤਿਜ੍ਞਾ, 0);
	sig_len = fido_assert_sig_len(ਪ੍ਰਤਿਜ੍ਞਾ, 0);
	ਜੇ ((sig = d2i_ECDSA_SIG(ਨਿਰਾ, &cp, sig_len)) == ਨਿਰਾ) {
		skdebug(__func__, "d2i_ECDSA_SIG failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_ਅੰਕ_ਬਾਈਟਾਂ(sig_r);
	response->sig_s_len = BN_ਅੰਕ_ਬਾਈਟਾਂ(sig_s);
	ਜੇ ((response->sig_r = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, response->sig_r_len)) == ਨਿਰਾ ||
	    (response->sig_s = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, response->sig_s_len)) == ਨਿਰਾ) {
		skdebug(__func__, "calloc signature failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 ਬਾਹਰਲਾ:
	ECDSA_SIG_free(sig);
	ਜੇ (ret != 0) {
		ਮੁਕਤ(response->sig_r);
		ਮੁਕਤ(response->sig_s);
		response->sig_r = ਨਿਰਾ;
		response->sig_s = ਨਿਰਾ;
	}
	ਵਾਪਸ ret;
}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

ਸਥਿਰ ਪੂਰਨ
pack_sig_ed25519(fido_assert_t *ਪ੍ਰਤਿਜ੍ਞਾ, ਬਣਤਰ sk_sign_response *response)
{
	ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ptr;
	ਮਾਪ_t len;
	ਪੂਰਨ ret = -1;

	ptr = fido_assert_sig_ptr(ਪ੍ਰਤਿਜ੍ਞਾ, 0);
	len = fido_assert_sig_len(ਪ੍ਰਤਿਜ੍ਞਾ, 0);
	ਜੇ (len != 64) {
		skdebug(__func__, "bad length %zu", len);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	response->sig_r_len = len;
	ਜੇ ((response->sig_r = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, response->sig_r_len)) == ਨਿਰਾ) {
		skdebug(__func__, "calloc signature failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(response->sig_r, ptr, len);
	ret = 0;
 ਬਾਹਰਲਾ:
	ਜੇ (ret != 0) {
		ਮੁਕਤ(response->sig_r);
		response->sig_r = ਨਿਰਾ;
	}
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
pack_sig(uint32_t  alg, fido_assert_t *ਪ੍ਰਤਿਜ੍ਞਾ,
    ਬਣਤਰ sk_sign_response *response)
{
	ਚੋਣ(alg) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਹਾਲਤ SSH_SK_ECDSA:
		ਵਾਪਸ pack_sig_ecdsa(ਪ੍ਰਤਿਜ੍ਞਾ, response);
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
	ਹਾਲਤ SSH_SK_ED25519:
		ਵਾਪਸ pack_sig_ed25519(ਪ੍ਰਤਿਜ੍ਞਾ, response);
	ਮੂਲ:
		ਵਾਪਸ -1;
	}
}

/* Checks sk_options for sk_sign() and sk_load_resident_keys() */
ਸਥਿਰ ਪੂਰਨ
check_sign_ਲੱਦੋ_resident_options(ਬਣਤਰ sk_option **options, ਅੱਖਰ **devicep)
{
	ਮਾਪ_t i;

	ਜੇ (options == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਲਈ (i = 0; options[i] != ਨਿਰਾ; i++) {
		ਜੇ (strcmp(options[i]->name, "device") == 0) {
			ਜੇ ((*devicep = strdup(options[i]->ਮੁੱਲ)) == ਨਿਰਾ) {
				skdebug(__func__, "strdup device failed");
				ਵਾਪਸ -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} ਨਹੀਂਤਾਂ {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			ਜੇ (options[i]->required) {
				skdebug(__func__, "unknown required option");
				ਵਾਪਸ -1;
			}
		}
	}
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sk_sign(uint32_t alg, ਅਚਲ uint8_t *ਅੰਕੜੇ, ਮਾਪ_t datalen,
    ਅਚਲ ਅੱਖਰ *application,
    ਅਚਲ uint8_t *ਕੁੰਜੀ_handle, ਮਾਪ_t ਕੁੰਜੀ_handle_len,
    uint8_t flags, ਅਚਲ ਅੱਖਰ *pin, ਬਣਤਰ sk_option **options,
    ਬਣਤਰ sk_sign_response **sign_response)
{
	fido_assert_t *ਪ੍ਰਤਿਜ੍ਞਾ = ਨਿਰਾ;
	ਅੱਖਰ *device = ਨਿਰਾ;
	ਬਣਤਰ sk_usbhid *sk = ਨਿਰਾ;
	ਬਣਤਰ sk_sign_response *response = ਨਿਰਾ;
	ਪੂਰਨ ret = SSH_SK_ERR_GENERAL, ਅੰਦਰੂਨੀ_uv;
	ਪੂਰਨ r;

	fido_init(SSH_FIDO_INIT_ARG);

	ਜੇ (sign_response == ਨਿਰਾ) {
		skdebug(__func__, "sign_response == NULL");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	*sign_response = ਨਿਰਾ;
	ਜੇ (check_sign_ਲੱਦੋ_resident_options(options, &device) != 0)
		ਜਾਓ ਬਾਹਰਲਾ; /* error already logged */
	ਜੇ (device != ਨਿਰਾ)
		sk = sk_open(device);
	ਨਹੀਂਤਾਂ ਜੇ (pin != ਨਿਰਾ || (flags & SSH_SK_USER_VERIFICATION_REQD))
		sk = sk_probe(ਨਿਰਾ, ਨਿਰਾ, 0, 0);
	ਨਹੀਂਤਾਂ
		sk = sk_probe(application, ਕੁੰਜੀ_handle, ਕੁੰਜੀ_handle_len, 0);
	ਜੇ (sk == ਨਿਰਾ) {
		ret = SSH_SK_ERR_DEVICE_NOT_ਮਿਲਿਆ;
		skdebug(__func__, "failed to find sk");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((ਪ੍ਰਤਿਜ੍ਞਾ = fido_assert_new()) == ਨਿਰਾ) {
		skdebug(__func__, "fido_assert_new failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = fido_assert_ਸੈੱਟ_clientdata(ਪ੍ਰਤਿਜ੍ਞਾ,
	    ਅੰਕੜੇ, datalen)) != FIDO_OK)  {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = fido_assert_ਸੈੱਟ_rp(ਪ੍ਰਤਿਜ੍ਞਾ, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = fido_assert_allow_cred(ਪ੍ਰਤਿਜ੍ਞਾ, ਕੁੰਜੀ_handle,
	    ਕੁੰਜੀ_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = fido_assert_ਸੈੱਟ_ਉੱਪਰ(ਪ੍ਰਤਿਜ੍ਞਾ,
	    (flags & SSH_SK_USER_PRESENCE_REQD) ?
	    FIDO_OPT_TRUE : FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/*
	 * WinHello requests the PIN by default.  Make "uv" request explicit
	 * to allow keys with and without -O verify-required to make sense.
	 */
	ਜੇ (pin == ਨਿਰਾ && fido_dev_is_winhello (sk->dev) &&
	    (r = fido_assert_ਸੈੱਟ_uv(ਪ੍ਰਤਿਜ੍ਞਾ, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
	}
	ਜੇ (pin == ਨਿਰਾ && (flags & SSH_SK_USER_VERIFICATION_REQD)) {
		ਜੇ (check_sk_options(sk->dev, "uv", &ਅੰਦਰੂਨੀ_uv) < 0 ||
		    ਅੰਦਰੂਨੀ_uv != 1) {
			skdebug(__func__, "check_sk_options uv");
			ret = SSH_SK_ERR_PIN_REQUIRED;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((r = fido_assert_ਸੈੱਟ_uv(ਪ੍ਰਤਿਜ੍ਞਾ,
		    FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_assert_set_uv: %s",
			    fido_strerr(r));
			ret = fidoerr_ਮੰਜ਼ਿਲ_skerr(r);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}
	ਜੇ ((r = fido_dev_get_assert(sk->dev, ਪ੍ਰਤਿਜ੍ਞਾ, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ret = fidoerr_ਮੰਜ਼ਿਲ_skerr(r);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((response = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*response))) == ਨਿਰਾ) {
		skdebug(__func__, "calloc response failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	response->flags = fido_assert_flags(ਪ੍ਰਤਿਜ੍ਞਾ, 0);
	response->counter = fido_assert_sigcount(ਪ੍ਰਤਿਜ੍ਞਾ, 0);
	ਜੇ (pack_sig(alg, ਪ੍ਰਤਿਜ੍ਞਾ, response) != 0) {
		skdebug(__func__, "pack_sig failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	*sign_response = response;
	response = ਨਿਰਾ;
	ret = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(device);
	ਜੇ (response != ਨਿਰਾ) {
		ਮੁਕਤ(response->sig_r);
		ਮੁਕਤ(response->sig_s);
		ਮੁਕਤ(response);
	}
	sk_close(sk);
	fido_assert_free(&ਪ੍ਰਤਿਜ੍ਞਾ);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
read_rks(ਬਣਤਰ sk_usbhid *sk, ਅਚਲ ਅੱਖਰ *pin,
    ਬਣਤਰ sk_resident_ਕੁੰਜੀ ***rksp, ਮਾਪ_t *nrksp)
{
	ਪੂਰਨ ret = SSH_SK_ERR_GENERAL, r = -1;
	uint32_t alg;
	fido_credman_metadata_t *metadata = ਨਿਰਾ;
	fido_credman_rp_t *rp = ਨਿਰਾ;
	fido_credman_rk_t *rk = ਨਿਰਾ;
	ਮਾਪ_t i, j, nrp, nrk, user_id_len;
	ਅਚਲ fido_cred_t *cred;
	ਅਚਲ ਅੱਖਰ *rp_id, *rp_name, *user_name;
	ਬਣਤਰ sk_resident_ਕੁੰਜੀ *srk = ਨਿਰਾ, **tmp;
	ਅਚਲ u_char *user_id;

	ਜੇ (pin == ਨਿਰਾ) {
		skdebug(__func__, "no PIN specified");
		ret = SSH_SK_ERR_PIN_REQUIRED;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((metadata = fido_credman_metadata_new()) == ਨਿਰਾ) {
		skdebug(__func__, "alloc failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = fido_credman_get_dev_metadata(sk->dev, metadata, pin)) != 0) {
		ਜੇ (r == FIDO_ERR_INVALID_COMMAND) {
			skdebug(__func__, "device %s does not support "
			    "resident keys", sk->ਰਸਤਾ);
			ret = 0;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		skdebug(__func__, "get metadata for %s failed: %s",
		    sk->ਰਸਤਾ, fido_strerr(r));
		ret = fidoerr_ਮੰਜ਼ਿਲ_skerr(r);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	skdebug(__func__, "existing %llu, remaining %llu",
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)fido_credman_rk_existing(metadata),
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)fido_credman_rk_ਬਚਿਆ(metadata));
	ਜੇ ((rp = fido_credman_rp_new()) == ਨਿਰਾ) {
		skdebug(__func__, "alloc rp failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = fido_credman_get_dev_rp(sk->dev, rp, pin)) != 0) {
		skdebug(__func__, "get RPs for %s failed: %s",
		    sk->ਰਸਤਾ, fido_strerr(r));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	nrp = fido_credman_rp_ਗਿਣਤੀ(rp);
	skdebug(__func__, "Device %s has resident keys for %zu RPs",
	    sk->ਰਸਤਾ, nrp);

	/* Iterate over RP IDs that have resident keys */
	ਲਈ (i = 0; i < nrp; i++) {
		rp_id = fido_credman_rp_id(rp, i);
		rp_name = fido_credman_rp_name(rp, i);
		skdebug(__func__, "rp %zu: name=\"%s\" id=\"%s\" hashlen=%zu",
		    i, rp_name == ਨਿਰਾ ? "(none)" : rp_name,
		    rp_id == ਨਿਰਾ ? "(none)" : rp_id,
		    fido_credman_rp_id_hash_len(rp, i));

		/* Skip non-SSH RP IDs */
		ਜੇ (rp_id == ਨਿਰਾ ||
		    strncasecmp(fido_credman_rp_id(rp, i), "ssh:", 4) != 0)
			ਜਾਰੀ;

		fido_credman_rk_free(&rk);
		ਜੇ ((rk = fido_credman_rk_new()) == ਨਿਰਾ) {
			skdebug(__func__, "alloc rk failed");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((r = fido_credman_get_dev_rk(sk->dev,
		    fido_credman_rp_id(rp, i), rk, pin)) != 0) {
			skdebug(__func__, "get RKs for %s slot %zu failed: %s",
			    sk->ਰਸਤਾ, i, fido_strerr(r));
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		nrk = fido_credman_rk_ਗਿਣਤੀ(rk);
		skdebug(__func__, "RP \"%s\" has %zu resident keys",
		    fido_credman_rp_id(rp, i), nrk);

		/* Iterate over resident keys for this RP ID */
		ਲਈ (j = 0; j < nrk; j++) {
			ਜੇ ((cred = fido_credman_rk(rk, j)) == ਨਿਰਾ) {
				skdebug(__func__, "no RK in slot %zu", j);
				ਜਾਰੀ;
			}
			ਜੇ ((user_name = fido_cred_user_name(cred)) == ਨਿਰਾ)
				user_name = "";
			user_id = fido_cred_user_id_ptr(cred);
			user_id_len = fido_cred_user_id_len(cred);
			skdebug(__func__, "Device %s RP \"%s\" user \"%s\" "
			    "uidlen %zu slot %zu: type %d flags 0x%02x "
			    "prot 0x%02x", sk->ਰਸਤਾ, rp_id, user_name,
			    user_id_len, j, fido_cred_type(cred),
			    fido_cred_flags(cred), fido_cred_prot(cred));

			/* Determine key algorithm */
			ਚੋਣ (fido_cred_type(cred)) {
			ਹਾਲਤ COSE_ES256:
				alg = SSH_SK_ECDSA;
				ਰੋਕੋ;
			ਹਾਲਤ COSE_EDDSA:
				alg = SSH_SK_ED25519;
				ਰੋਕੋ;
			ਮੂਲ:
				skdebug(__func__, "unsupported key type %d",
				    fido_cred_type(cred));
				ਜਾਰੀ;
			}

			/* build response entry */
			ਜੇ ((srk = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*srk))) == ਨਿਰਾ ||
			    (srk->ਕੁੰਜੀ.ਕੁੰਜੀ_handle = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1,
			    fido_cred_id_len(cred))) == ਨਿਰਾ ||
			    (srk->application = strdup(rp_id)) == ਨਿਰਾ ||
			    (user_id_len > 0 &&
			     (srk->user_id = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, user_id_len)) == ਨਿਰਾ)) {
				skdebug(__func__, "alloc sk_resident_key");
				ਜਾਓ ਬਾਹਰਲਾ;
			}

			srk->alg = alg;
			srk->ਕੁੰਜੀ.ਕੁੰਜੀ_handle_len = fido_cred_id_len(cred);
			ਸਮ੍ਰਿਤੀ_ਨਕਲ(srk->ਕੁੰਜੀ.ਕੁੰਜੀ_handle, fido_cred_id_ptr(cred),
			    srk->ਕੁੰਜੀ.ਕੁੰਜੀ_handle_len);
			srk->user_id_len = user_id_len;
			ਜੇ (srk->user_id_len != 0)
				ਸਮ੍ਰਿਤੀ_ਨਕਲ(srk->user_id, user_id, srk->user_id_len);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_FIDO_CRED_PROT
			ਜੇ (fido_cred_prot(cred) ==
			    FIDO_CRED_PROT_UV_REQUIRED)
				srk->flags |=  SSH_SK_USER_VERIFICATION_REQD;
#ਜੇ_ਅੰਤ

			ਜੇ ((r = pack_ਜਨਤਕ_ਕੁੰਜੀ(srk->alg, cred,
			    &srk->ਕੁੰਜੀ)) != 0) {
				skdebug(__func__, "pack public key failed");
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			/* append */
			ਜੇ ((tmp = recallocarray(*rksp, *nrksp, (*nrksp) + 1,
			    ਆਕਾਰ(**rksp))) == ਨਿਰਾ) {
				skdebug(__func__, "alloc rksp");
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			*rksp = tmp;
			(*rksp)[(*nrksp)++] = srk;
			srk = ਨਿਰਾ;
		}
	}
	/* Success */
	ret = 0;
 ਬਾਹਰਲਾ:
	ਜੇ (srk != ਨਿਰਾ) {
		ਮੁਕਤ(srk->application);
		freezero(srk->ਕੁੰਜੀ.ਜਨਤਕ_ਕੁੰਜੀ, srk->ਕੁੰਜੀ.ਜਨਤਕ_ਕੁੰਜੀ_len);
		freezero(srk->ਕੁੰਜੀ.ਕੁੰਜੀ_handle, srk->ਕੁੰਜੀ.ਕੁੰਜੀ_handle_len);
		freezero(srk->user_id, srk->user_id_len);
		freezero(srk, ਆਕਾਰ(*srk));
	}
	fido_credman_rp_free(&rp);
	fido_credman_rk_free(&rk);
	fido_credman_metadata_free(&metadata);
	ਵਾਪਸ ret;
}

ਪੂਰਨ
sk_ਲੱਦੋ_resident_ਕੁੰਜੀਆਂ(ਅਚਲ ਅੱਖਰ *pin, ਬਣਤਰ sk_option **options,
    ਬਣਤਰ sk_resident_ਕੁੰਜੀ ***rksp, ਮਾਪ_t *nrksp)
{
	ਪੂਰਨ ret = SSH_SK_ERR_GENERAL, r = -1;
	ਮਾਪ_t i, nrks = 0;
	ਬਣਤਰ sk_resident_ਕੁੰਜੀ **rks = ਨਿਰਾ;
	ਬਣਤਰ sk_usbhid *sk = ਨਿਰਾ;
	ਅੱਖਰ *device = ਨਿਰਾ;

	*rksp = ਨਿਰਾ;
	*nrksp = 0;

	fido_init(SSH_FIDO_INIT_ARG);

	ਜੇ (check_sign_ਲੱਦੋ_resident_options(options, &device) != 0)
		ਜਾਓ ਬਾਹਰਲਾ; /* error already logged */
	ਜੇ (device != ਨਿਰਾ)
		sk = sk_open(device);
	ਨਹੀਂਤਾਂ
		sk = sk_probe(ਨਿਰਾ, ਨਿਰਾ, 0, 1);
	ਜੇ (sk == ਨਿਰਾ) {
		ret = SSH_SK_ERR_DEVICE_NOT_ਮਿਲਿਆ;
		skdebug(__func__, "failed to find sk");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	skdebug(__func__, "trying %s", sk->ਰਸਤਾ);
	ਜੇ ((r = read_rks(sk, pin, &rks, &nrks)) != 0) {
		skdebug(__func__, "read_rks failed for %s", sk->ਰਸਤਾ);
		ret = r;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success, unless we have no keys but a specific error */
	ਜੇ (nrks > 0 || ret == SSH_SK_ERR_GENERAL)
		ret = 0;
	*rksp = rks;
	*nrksp = nrks;
	rks = ਨਿਰਾ;
	nrks = 0;
 ਬਾਹਰਲਾ:
	sk_close(sk);
	ਲਈ (i = 0; i < nrks; i++) {
		ਮੁਕਤ(rks[i]->application);
		freezero(rks[i]->ਕੁੰਜੀ.ਜਨਤਕ_ਕੁੰਜੀ, rks[i]->ਕੁੰਜੀ.ਜਨਤਕ_ਕੁੰਜੀ_len);
		freezero(rks[i]->ਕੁੰਜੀ.ਕੁੰਜੀ_handle, rks[i]->ਕੁੰਜੀ.ਕੁੰਜੀ_handle_len);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i], ਆਕਾਰ(*rks[i]));
	}
	ਮੁਕਤ(device);
	ਮੁਕਤ(rks);
	ਵਾਪਸ ret;
}

#ਜੇ_ਅੰਤ /* ENABLE_SK_INTERNAL */
