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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_SK_ಆಂತರಿಕ

#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <time.h>
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SHA2_H
#ಅನ್ತರ್ಭಾವ <sha2.h>
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/opensslv.h>
#ಅನ್ತರ್ಭಾವ <openssl/crypto.h>
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/ec.h>
#ಅನ್ತರ್ಭಾವ <openssl/ecdsa.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

#ಅನ್ತರ್ಭಾವ <fido.h>
#ಅನ್ತರ್ಭಾವ <fido/credman.h>

/* backwards compat for libfido2 */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FIDO_CRED_PROT
#ವ್ಯಾಖ್ಯಾನಿಸು fido_cred_prot(x) (0)
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FIDO_CRED_ಗಣ_PROT
#ವ್ಯಾಖ್ಯಾನಿಸು fido_cred_ಗಣ_prot(x, y) (FIDO_ERR_UNSUPPORTED_OPTION)
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FIDO_DEV_SUPPORTS_CRED_PROT
#ವ್ಯಾಖ್ಯಾನಿಸು fido_dev_supports_cred_prot(x) (0)
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FIDO_DEV_GET_TOUCH_BEGIN
#ವ್ಯಾಖ್ಯಾನಿಸು fido_dev_get_touch_begin(x) (FIDO_ERR_UNSUPPORTED_OPTION)
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FIDO_DEV_GET_TOUCH_ಸ್ಥಿತಿ
#ವ್ಯಾಖ್ಯಾನಿಸು fido_dev_get_touch_ಸ್ಥಿತಿ(x, y, z) (FIDO_ERR_UNSUPPORTED_OPTION)
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ FIDO_CRED_PROT_UV_REQUIRED
#ವ್ಯಾಖ್ಯಾನಿಸು FIDO_CRED_PROT_UV_REQUIRED 0
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID
#ವ್ಯಾಖ್ಯಾನಿಸು FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID 0
#ಆದರೆ_ಅಂತ್ಯ

# include "misc.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ SK_STANDALONE
# include "log.h"
# include "xmalloc.h"
/*
 * If building as part of OpenSSH, then rename exported functions.
 * This must be done before including sk-api.h.
 */
# define sk_api_ಆವೃತ್ತಿ		ssh_sk_api_ಆವೃತ್ತಿ
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_ತುಂಬು_resident_ಕೀಲಿಗಳು	ssh_sk_ತುಂಬು_resident_ಕೀಲಿಗಳು
#ಆದರೆ_ಅಂತ್ಯ /* !SK_STANDALONE */

#ಅನ್ತರ್ಭಾವ "sk-api.h"

/* #define SK_DEBUG 1 */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SK_DEBUG
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_FIDO_INIT_ARG	FIDO_DEBUG
#ಇಲ್ಲದಿದ್ದರೆ
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_FIDO_INIT_ARG	0
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು MAX_FIDO_DEVICES	8
#ವ್ಯಾಖ್ಯಾನಿಸು FIDO_POLL_MS		50
#ವ್ಯಾಖ್ಯಾನಿಸು SELECT_MS		15000
#ವ್ಯಾಖ್ಯಾನಿಸು POLL_SLEEP_NS		200000000

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ FIDO_ERR_OPERATION_DENIED
#ವ್ಯಾಖ್ಯಾನಿಸು FIDO_ERR_OPERATION_DENIED 0x27
#ಆದರೆ_ಅಂತ್ಯ

ರಚನೆ sk_usbhid {
	fido_dev_t *dev;
	ಅಕ್ಷರ *ಮಾರ್ಗ;
};

/* Return the version of the middleware API */
uint32_t sk_api_ಆವೃತ್ತಿ(ಶೂನ್ಯ);

/* Enroll a U2F key (private key generation) */
ಪೂರ್ಣಾಂಕ sk_enroll(uint32_t alg, ಸ್ಥಿರಾಂಕ uint8_t *challenge, ಗಾತ್ರ_t challenge_len,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application, uint8_t flags, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin,
    ರಚನೆ sk_option **options, ರಚನೆ sk_enroll_response **enroll_response);

/* Sign a challenge */
ಪೂರ್ಣಾಂಕ sk_sign(uint32_t alg, ಸ್ಥಿರಾಂಕ uint8_t *ದತ್ತಾಂಶ, ಗಾತ್ರ_t ದತ್ತಾಂಶ_len,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application, ಸ್ಥಿರಾಂಕ uint8_t *ಕೀಲಿ_handle, ಗಾತ್ರ_t ಕೀಲಿ_handle_len,
    uint8_t flags, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin, ರಚನೆ sk_option **options,
    ರಚನೆ sk_sign_response **sign_response);

/* Load resident keys */
ಪೂರ್ಣಾಂಕ sk_ತುಂಬು_resident_ಕೀಲಿಗಳು(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin, ರಚನೆ sk_option **options,
    ರಚನೆ sk_resident_ಕೀಲಿ ***rks, ಗಾತ್ರ_t *nrks);

ಸ್ಥಿರ ಶೂನ್ಯ skdebug(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *func, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
    __attribute__((__format__ (ಬರೆ, 2, 3)));

ಸ್ಥಿರ ಶೂನ್ಯ
skdebug(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *func, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
#ಆದರೆ !defined(SK_STANDALONE)
	ಅಕ್ಷರ *ಸಂದೇಶ;
	va_list ap;

	va_start(ap, fmt);
	xvasprintf(&ಸಂದೇಶ, fmt, ap);
	va_end(ap);
	debug("%s: %s", func, ಸಂದೇಶ);
	ಬಿಡುಗಡೆ(ಸಂದೇಶ);
#ಅಥವಾಆದರೆ defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#ಇಲ್ಲದಿದ್ದರೆ
	(ಶೂನ್ಯ)func; /* XXX */
	(ಶೂನ್ಯ)fmt; /* XXX */
#ಆದರೆ_ಅಂತ್ಯ
}

uint32_t
sk_api_ಆವೃತ್ತಿ(ಶೂನ್ಯ)
{
	ಹಿಂತಿರುಗಿ SSH_SK_ಆವೃತ್ತಿ_MAJOR;
}

ಸ್ಥಿರ ರಚನೆ sk_usbhid *
sk_open(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ರಚನೆ sk_usbhid *sk;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (ಮಾರ್ಗ == ಖಾಲಿ) {
		skdebug(__func__, "path == NULL");
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ ((sk = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*sk))) == ಖಾಲಿ) {
		skdebug(__func__, "calloc sk failed");
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ ((sk->ಮಾರ್ಗ = strdup(ಮಾರ್ಗ)) == ಖಾಲಿ) {
		skdebug(__func__, "strdup path failed");
		ಬಿಡುಗಡೆ(sk);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ ((sk->dev = fido_dev_new()) == ಖಾಲಿ) {
		skdebug(__func__, "fido_dev_new failed");
		ಬಿಡುಗಡೆ(sk->ಮಾರ್ಗ);
		ಬಿಡುಗಡೆ(sk);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ ((r = fido_dev_open(sk->dev, sk->ಮಾರ್ಗ)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_open %s failed: %s", sk->ಮಾರ್ಗ,
		    fido_strerr(r));
		fido_dev_free(&sk->dev);
		ಬಿಡುಗಡೆ(sk->ಮಾರ್ಗ);
		ಬಿಡುಗಡೆ(sk);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಹಿಂತಿರುಗಿ sk;
}

ಸ್ಥಿರ ಶೂನ್ಯ
sk_close(ರಚನೆ sk_usbhid *sk)
{
	ಆದರೆ (sk == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	fido_dev_cancel(sk->dev); /* cancel any pending operation */
	fido_dev_close(sk->dev);
	fido_dev_free(&sk->dev);
	ಬಿಡುಗಡೆ(sk->ಮಾರ್ಗ);
	ಬಿಡುಗಡೆ(sk);
}

ಸ್ಥಿರ ರಚನೆ sk_usbhid **
sk_openv(ಸ್ಥಿರಾಂಕ fido_dev_info_t *devlist, ಗಾತ್ರ_t ndevs, ಗಾತ್ರ_t *nopen)
{
	ಸ್ಥಿರಾಂಕ fido_dev_info_t *di;
	ರಚನೆ sk_usbhid **skv;
	ಗಾತ್ರ_t i;

	*nopen = 0;
	ಆದರೆ ((skv = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(ndevs, ಗಾತ್ರ(*skv))) == ಖಾಲಿ) {
		skdebug(__func__, "calloc skv failed");
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಗಾಗಿ (i = 0; i < ndevs; i++) {
		ಆದರೆ ((di = fido_dev_info_ptr(devlist, i)) == ಖಾಲಿ)
			skdebug(__func__, "fido_dev_info_ptr failed");
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((skv[*nopen] = sk_open(fido_dev_info_ಮಾರ್ಗ(di))) == ಖಾಲಿ)
			skdebug(__func__, "sk_open failed");
		ಇಲ್ಲದಿದ್ದರೆ
			(*nopen)++;
	}
	ಆದರೆ (*nopen == 0) {
		ಗಾಗಿ (i = 0; i < ndevs; i++)
			sk_close(skv[i]);
		ಬಿಡುಗಡೆ(skv);
		skv = ಖಾಲಿ;
	}

	ಹಿಂತಿರುಗಿ skv;
}

ಸ್ಥಿರ ಶೂನ್ಯ
sk_closev(ರಚನೆ sk_usbhid **skv, ಗಾತ್ರ_t nsk)
{
	ಗಾತ್ರ_t i;

	ಗಾಗಿ (i = 0; i < nsk; i++)
		sk_close(skv[i]);
	ಬಿಡುಗಡೆ(skv);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sk_touch_begin(ರಚನೆ sk_usbhid **skv, ಗಾತ್ರ_t nsk)
{
	ಗಾತ್ರ_t i, ok = 0;
	ಪೂರ್ಣಾಂಕ r;

	ಗಾಗಿ (i = 0; i < nsk; i++)
		ಆದರೆ ((r = fido_dev_get_touch_begin(skv[i]->dev)) != FIDO_OK)
			skdebug(__func__, "fido_dev_get_touch_begin %s failed:"
			    " %s", skv[i]->ಮಾರ್ಗ, fido_strerr(r));
		ಇಲ್ಲದಿದ್ದರೆ
			ok++;

	ಹಿಂತಿರುಗಿ ok ? 0 : -1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sk_touch_poll(ರಚನೆ sk_usbhid **skv, ಗಾತ್ರ_t nsk, ಪೂರ್ಣಾಂಕ *touch, ಗಾತ್ರ_t *idx)
{
	ರಚನೆ timespec ts_pause;
	ಗಾತ್ರ_t npoll, i;
	ಪೂರ್ಣಾಂಕ r;

	ts_pause.tv_sec = 0;
	ts_pause.tv_nsec = POLL_SLEEP_NS;
	nanosleep(&ts_pause, ಖಾಲಿ);
	npoll = nsk;
	ಗಾಗಿ (i = 0; i < nsk; i++) {
		ಆದರೆ (skv[i] == ಖಾಲಿ)
			ಮುಂದುವರಿ; /* device discarded */
		skdebug(__func__, "polling %s", skv[i]->ಮಾರ್ಗ);
		ಆದರೆ ((r = fido_dev_get_touch_ಸ್ಥಿತಿ(skv[i]->dev, touch,
		    FIDO_POLL_MS)) != FIDO_OK) {
			skdebug(__func__, "fido_dev_get_touch_status %s: %s",
			    skv[i]->ಮಾರ್ಗ, fido_strerr(r));
			sk_close(skv[i]); /* discard device */
			skv[i] = ಖಾಲಿ;
			ಆದರೆ (--npoll == 0) {
				skdebug(__func__, "no device left to poll");
				ಹಿಂತಿರುಗಿ -1;
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (*touch) {
			*idx = i;
			ಹಿಂತಿರುಗಿ 0;
		}
	}
	*touch = 0;
	ಹಿಂತಿರುಗಿ 0;
}

#ಆದರೆ !defined(HAVE_FIDO_ASSERT_ಗಣ_CLIENTDATA) || \
    !defined(HAVE_FIDO_CRED_ಗಣ_CLIENTDATA)
/* Calculate SHA256(m) */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sha256_mem(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *m, ಗಾತ್ರ_t mlen, u_char *d, ಗಾತ್ರ_t dlen)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	u_int mdlen;
#ಇಲ್ಲದಿದ್ದರೆ
	SHA2_CTX ctx;
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (dlen != 32)
		ಹಿಂತಿರುಗಿ -1;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	mdlen = dlen;
	ಆದರೆ (!EVP_Digest(m, mlen, d, &mdlen, EVP_sha256(), ಖಾಲಿ))
		ಹಿಂತಿರುಗಿ -1;
#ಇಲ್ಲದಿದ್ದರೆ
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ಸ್ಥಿರಾಂಕ uint8_t *)m, mlen);
	SHA256Final(d, &ctx);
#ಆದರೆ_ಅಂತ್ಯ
	ಹಿಂತಿರುಗಿ 0;
}
#ಆದರೆ_ಅಂತ್ಯ /* !HAVE_FIDO_ASSERT_SET_CLIENTDATA || !HAVE_FIDO_CRED_SET_CLIENTDATA */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FIDO_CRED_ಗಣ_CLIENTDATA
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
fido_cred_ಗಣ_clientdata(fido_cred_t *cred, ಸ್ಥಿರಾಂಕ u_char *ptr, ಗಾತ್ರ_t len)
{
	uint8_t d[32];
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (sha256_mem(ptr, len, d, ಗಾತ್ರ(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		ಹಿಂತಿರುಗಿ FIDO_ERR_ಆಂತರಿಕ;
	}
	r = fido_cred_ಗಣ_clientdata_hash(cred, d, ಗಾತ್ರ(d));
	explicit_bzero(d, ಗಾತ್ರ(d));
	ಆದರೆ (r != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	ಹಿಂತಿರುಗಿ r;
}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_FIDO_CRED_SET_CLIENTDATA */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FIDO_ASSERT_ಗಣ_CLIENTDATA
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
fido_assert_ಗಣ_clientdata(fido_assert_t *ಪ್ರತಿಜ್ಞಾ, ಸ್ಥಿರಾಂಕ u_char *ptr, ಗಾತ್ರ_t len)
{
	uint8_t d[32];
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (sha256_mem(ptr, len, d, ಗಾತ್ರ(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		ಹಿಂತಿರುಗಿ FIDO_ERR_ಆಂತರಿಕ;
	}
	r = fido_assert_ಗಣ_clientdata_hash(ಪ್ರತಿಜ್ಞಾ, d, ಗಾತ್ರ(d));
	explicit_bzero(d, ಗಾತ್ರ(d));
	ಆದರೆ (r != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	ಹಿಂತಿರುಗಿ r;
}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_FIDO_ASSERT_SET_CLIENTDATA */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FIDO_DEV_IS_WINHELLO
ಸ್ಥಿರ bool
fido_dev_is_winhello(ಸ್ಥಿರಾಂಕ fido_dev_t *fdev)
{
	ಹಿಂತಿರುಗಿ 0;
}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_FIDO_DEV_IS_WINHELLO */

/* Check if the specified key handle exists on a given sk. */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sk_try(ಸ್ಥಿರಾಂಕ ರಚನೆ sk_usbhid *sk, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application,
    ಸ್ಥಿರಾಂಕ uint8_t *ಕೀಲಿ_handle, ಗಾತ್ರ_t ಕೀಲಿ_handle_len)
{
	fido_assert_t *ಪ್ರತಿಜ್ಞಾ = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = FIDO_ERR_ಆಂತರಿಕ;
	uint8_t ಸಂದೇಶ_2[32];

	memset(ಸಂದೇಶ_2, '\0', ಗಾತ್ರ(ಸಂದೇಶ_2));
	ಆದರೆ ((ಪ್ರತಿಜ್ಞಾ = fido_assert_new()) == ಖಾಲಿ) {
		skdebug(__func__, "fido_assert_new failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* generate an invalid signature on FIDO2 tokens */
	ಆದರೆ ((r = fido_assert_ಗಣ_clientdata(ಪ್ರತಿಜ್ಞಾ, ಸಂದೇಶ_2,
	    ಗಾತ್ರ(ಸಂದೇಶ_2))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = fido_assert_ಗಣ_rp(ಪ್ರತಿಜ್ಞಾ, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = fido_assert_allow_cred(ಪ್ರತಿಜ್ಞಾ, ಕೀಲಿ_handle,
	    ಕೀಲಿ_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = fido_assert_ಗಣ_ಮೇಲೆ(ಪ್ರತಿಜ್ಞಾ, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_up: %s", fido_strerr(r));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	r = fido_dev_get_assert(sk->dev, ಪ್ರತಿಜ್ಞಾ, ಖಾಲಿ);
	skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
	ಆದರೆ (r == FIDO_ERR_USER_PRESENCE_REQUIRED) {
		/* U2F tokens may return this */
		r = FIDO_OK;
	}
 ಹೊರಹೋಗು:
	fido_assert_free(&ಪ್ರತಿಜ್ಞಾ);

	ಹಿಂತಿರುಗಿ r != FIDO_OK ? -1 : 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
check_sk_options(fido_dev_t *dev, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *opt, ಪೂರ್ಣಾಂಕ *ret)
{
	fido_cbor_info_t *info;
	ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ *name;
	ಸ್ಥಿರಾಂಕ bool *ಮೌಲ್ಯ;
	ಗಾತ್ರ_t len, i;
	ಪೂರ್ಣಾಂಕ r;

	*ret = -1;

	ಆದರೆ (!fido_dev_is_fido2(dev)) {
		skdebug(__func__, "device is not fido2");
		ಹಿಂತಿರುಗಿ 0;
	}
	ಆದರೆ ((info = fido_cbor_info_new()) == ಖಾಲಿ) {
		skdebug(__func__, "fido_cbor_info_new failed");
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ ((r = fido_dev_get_cbor_info(dev, info)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_cbor_info: %s", fido_strerr(r));
		fido_cbor_info_free(&info);
		ಹಿಂತಿರುಗಿ -1;
	}
	name = fido_cbor_info_options_name_ptr(info);
	ಮೌಲ್ಯ = fido_cbor_info_options_ಮೌಲ್ಯ_ptr(info);
	len = fido_cbor_info_options_len(info);
	ಗಾಗಿ (i = 0; i < len; i++) {
		ಆದರೆ (!strcmp(name[i], opt)) {
			*ret = ಮೌಲ್ಯ[i];
			ನಿಲ್ಲಿಸು;
		}
	}
	fido_cbor_info_free(&info);
	ಆದರೆ (*ret == -1)
		skdebug(__func__, "option %s is unknown", opt);
	ಇಲ್ಲದಿದ್ದರೆ
		skdebug(__func__, "option %s is %s", opt, *ret ? "on" : "off");

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ರಚನೆ sk_usbhid *
sk_select_by_cred(ಸ್ಥಿರಾಂಕ fido_dev_info_t *devlist, ಗಾತ್ರ_t ndevs,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application, ಸ್ಥಿರಾಂಕ uint8_t *ಕೀಲಿ_handle, ಗಾತ್ರ_t ಕೀಲಿ_handle_len)
{
	ರಚನೆ sk_usbhid **skv, *sk;
	ಗಾತ್ರ_t skvcnt, i;
	ಪೂರ್ಣಾಂಕ ಆಂತರಿಕ_uv;

	ಆದರೆ ((skv = sk_openv(devlist, ndevs, &skvcnt)) == ಖಾಲಿ) {
		skdebug(__func__, "sk_openv failed");
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ (skvcnt == 1 && check_sk_options(skv[0]->dev, "uv",
	    &ಆಂತರಿಕ_uv) == 0 && ಆಂತರಿಕ_uv != -1) {
		sk = skv[0];
		skv[0] = ಖಾಲಿ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	sk = ಖಾಲಿ;
	ಗಾಗಿ (i = 0; i < skvcnt; i++) {
		ಆದರೆ (sk_try(skv[i], application, ಕೀಲಿ_handle,
		    ಕೀಲಿ_handle_len) == 0) {
			sk = skv[i];
			skv[i] = ಖಾಲಿ;
			skdebug(__func__, "found key in %s", sk->ಮಾರ್ಗ);
			ನಿಲ್ಲಿಸು;
		}
	}
 ಹೊರಹೋಗು:
	sk_closev(skv, skvcnt);
	ಹಿಂತಿರುಗಿ sk;
}

ಸ್ಥಿರ ರಚನೆ sk_usbhid *
sk_select_by_touch(ಸ್ಥಿರಾಂಕ fido_dev_info_t *devlist, ಗಾತ್ರ_t ndevs)
{
	ರಚನೆ sk_usbhid **skv, *sk;
	ರಚನೆ timeval tv_ಆರಂಭ, tv_now, tv_delta;
	ಗಾತ್ರ_t skvcnt, idx;
	ಪೂರ್ಣಾಂಕ touch, ms_remain;

	ಆದರೆ ((skv = sk_openv(devlist, ndevs, &skvcnt)) == ಖಾಲಿ) {
		skdebug(__func__, "sk_openv failed");
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	sk = ಖಾಲಿ;
	ಆದರೆ (skvcnt < 2) {
		ಆದರೆ (skvcnt == 1) {
			/* single candidate */
			sk = skv[0];
			skv[0] = ಖಾಲಿ;
		}
		ಹೋಗು ಹೊರಹೋಗು;
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_FIDO_DEV_GET_TOUCH_ಸ್ಥಿತಿ
	skdebug(__func__, "libfido2 version does not support a feature needed for multiple tokens. Please upgrade to >=1.5.0");
	ಹೋಗು ಹೊರಹೋಗು;
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (sk_touch_begin(skv, skvcnt) == -1) {
		skdebug(__func__, "sk_touch_begin failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	monotime_tv(&tv_ಆರಂಭ);
	ಮಾಡು {
		ಆದರೆ (sk_touch_poll(skv, skvcnt, &touch, &idx) == -1) {
			skdebug(__func__, "sk_touch_poll failed");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (touch) {
			sk = skv[idx];
			skv[idx] = ಖಾಲಿ;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		monotime_tv(&tv_now);
		timersub(&tv_now, &tv_ಆರಂಭ, &tv_delta);
		ms_remain = SELECT_MS - tv_delta.tv_sec * 1000 -
		    tv_delta.tv_usec / 1000;
	} ಆಗ (ms_remain >= FIDO_POLL_MS);
	skdebug(__func__, "timeout");
ಹೊರಹೋಗು:
	sk_closev(skv, skvcnt);
	ಹಿಂತಿರುಗಿ sk;
}

ಸ್ಥಿರ ರಚನೆ sk_usbhid *
sk_probe(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application, ಸ್ಥಿರಾಂಕ uint8_t *ಕೀಲಿ_handle,
    ಗಾತ್ರ_t ಕೀಲಿ_handle_len, ಪೂರ್ಣಾಂಕ probe_resident)
{
	ರಚನೆ sk_usbhid *sk;
	fido_dev_info_t *devlist;
	ಗಾತ್ರ_t ndevs;
	ಪೂರ್ಣಾಂಕ r;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_CYGWIN
	ಆದರೆ (!probe_resident && (sk = sk_open("windows://hello")) != ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ sk;
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_CYGWIN */
	ಆದರೆ ((devlist = fido_dev_info_new(MAX_FIDO_DEVICES)) == ಖಾಲಿ) {
		skdebug(__func__, "fido_dev_info_new failed");
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ ((r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES,
	    &ndevs)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_info_manifest failed: %s",
		    fido_strerr(r));
		fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	skdebug(__func__, "%zu device(s) detected", ndevs);
	ಆದರೆ (ndevs == 0) {
		sk = ಖಾಲಿ;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (application != ಖಾಲಿ && ಕೀಲಿ_handle != ಖಾಲಿ) {
		skdebug(__func__, "selecting sk by cred");
		sk = sk_select_by_cred(devlist, ndevs, application, ಕೀಲಿ_handle,
		    ಕೀಲಿ_handle_len);
	} ಇಲ್ಲದಿದ್ದರೆ {
		skdebug(__func__, "selecting sk by touch");
		sk = sk_select_by_touch(devlist, ndevs);
	}
	fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
	ಹಿಂತಿರುಗಿ sk;
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
/*
 * The key returned via fido_cred_pubkey_ptr() is in affine coordinates,
 * but the API expects a SEC1 octet string.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pack_ಬಹಿರಂಗ_ಕೀಲಿ_ecdsa(ಸ್ಥಿರಾಂಕ fido_cred_t *cred,
    ರಚನೆ sk_enroll_response *response)
{
	ಸ್ಥಿರಾಂಕ uint8_t *ptr;
	BIGNUM *x = ಖಾಲಿ, *y = ಖಾಲಿ;
	EC_ಬಿಂದು *q = ಖಾಲಿ;
	EC_ಗುಂಪು *g = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ret = -1;

	response->ಬಹಿರಂಗ_ಕೀಲಿ = ಖಾಲಿ;
	response->ಬಹಿರಂಗ_ಕೀಲಿ_len = 0;

	ಆದರೆ ((x = BN_new()) == ಖಾಲಿ ||
	    (y = BN_new()) == ಖಾಲಿ ||
	    (g = EC_ಗುಂಪು_new_by_ವಕ್ರ_name(NID_X9_62_prime256v1)) == ಖಾಲಿ ||
	    (q = EC_ಬಿಂದು_new(g)) == ಖಾಲಿ) {
		skdebug(__func__, "libcrypto setup failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((ptr = fido_cred_pubkey_ptr(cred)) == ಖಾಲಿ) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (fido_cred_pubkey_len(cred) != 64) {
		skdebug(__func__, "bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ (BN_bin2bn(ptr, 32, x) == ಖಾಲಿ ||
	    BN_bin2bn(ptr + 32, 32, y) == ಖಾಲಿ) {
		skdebug(__func__, "BN_bin2bn failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EC_ಬಿಂದು_ಗಣ_affine_coordinates(g, q, x, y, ಖಾಲಿ) != 1) {
		skdebug(__func__, "EC_POINT_set_affine_coordinates failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	response->ಬಹಿರಂಗ_ಕೀಲಿ_len = EC_ಬಿಂದು_point2oct(g, q,
	    ಬಿಂದು_CONVERSION_UNCOMPRESSED, ಖಾಲಿ, 0, ಖಾಲಿ);
	ಆದರೆ (response->ಬಹಿರಂಗ_ಕೀಲಿ_len == 0 || response->ಬಹಿರಂಗ_ಕೀಲಿ_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->ಬಹಿರಂಗ_ಕೀಲಿ_len);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((response->ಬಹಿರಂಗ_ಕೀಲಿ = ಸ್ಮರಣೆ_ಕೊಡು(response->ಬಹಿರಂಗ_ಕೀಲಿ_len)) == ಖಾಲಿ) {
		skdebug(__func__, "malloc pubkey failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EC_ಬಿಂದು_point2oct(g, q, ಬಿಂದು_CONVERSION_UNCOMPRESSED,
	    response->ಬಹಿರಂಗ_ಕೀಲಿ, response->ಬಹಿರಂಗ_ಕೀಲಿ_len, ಖಾಲಿ) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	ret = 0;
 ಹೊರಹೋಗು:
	ಆದರೆ (ret != 0 && response->ಬಹಿರಂಗ_ಕೀಲಿ != ಖಾಲಿ) {
		memset(response->ಬಹಿರಂಗ_ಕೀಲಿ, 0, response->ಬಹಿರಂಗ_ಕೀಲಿ_len);
		ಬಿಡುಗಡೆ(response->ಬಹಿರಂಗ_ಕೀಲಿ);
		response->ಬಹಿರಂಗ_ಕೀಲಿ = ಖಾಲಿ;
	}
	EC_ಬಿಂದು_free(q);
	EC_ಗುಂಪು_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	ಹಿಂತಿರುಗಿ ret;
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pack_ಬಹಿರಂಗ_ಕೀಲಿ_ed25519(ಸ್ಥಿರಾಂಕ fido_cred_t *cred,
    ರಚನೆ sk_enroll_response *response)
{
	ಸ್ಥಿರಾಂಕ uint8_t *ptr;
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ ret = -1;

	response->ಬಹಿರಂಗ_ಕೀಲಿ = ಖಾಲಿ;
	response->ಬಹಿರಂಗ_ಕೀಲಿ_len = 0;

	ಆದರೆ ((len = fido_cred_pubkey_len(cred)) != 32) {
		skdebug(__func__, "bad fido_cred_pubkey_len len %zu", len);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((ptr = fido_cred_pubkey_ptr(cred)) == ಖಾಲಿ) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	response->ಬಹಿರಂಗ_ಕೀಲಿ_len = len;
	ಆದರೆ ((response->ಬಹಿರಂಗ_ಕೀಲಿ = ಸ್ಮರಣೆ_ಕೊಡು(response->ಬಹಿರಂಗ_ಕೀಲಿ_len)) == ಖಾಲಿ) {
		skdebug(__func__, "malloc pubkey failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಸ್ಮರಣೆ_ನಕಲು(response->ಬಹಿರಂಗ_ಕೀಲಿ, ptr, len);
	ret = 0;
 ಹೊರಹೋಗು:
	ಆದರೆ (ret != 0)
		ಬಿಡುಗಡೆ(response->ಬಹಿರಂಗ_ಕೀಲಿ);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pack_ಬಹಿರಂಗ_ಕೀಲಿ(uint32_t alg, ಸ್ಥಿರಾಂಕ fido_cred_t *cred,
    ರಚನೆ sk_enroll_response *response)
{
	ಆಯ್ಕೆ(alg) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಸ್ಥಿತಿ SSH_SK_ECDSA:
		ಹಿಂತಿರುಗಿ pack_ಬಹಿರಂಗ_ಕೀಲಿ_ecdsa(cred, response);
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	ಸ್ಥಿತಿ SSH_SK_ED25519:
		ಹಿಂತಿರುಗಿ pack_ಬಹಿರಂಗ_ಕೀಲಿ_ed25519(cred, response);
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ -1;
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
fidoerr_ಗಮ್ಯ_skerr(ಪೂರ್ಣಾಂಕ fidoerr)
{
	ಆಯ್ಕೆ (fidoerr) {
	ಸ್ಥಿತಿ FIDO_ERR_UNSUPPORTED_OPTION:
	ಸ್ಥಿತಿ FIDO_ERR_UNSUPPORTED_ALGORITHM:
		ಹಿಂತಿರುಗಿ SSH_SK_ERR_UNSUPPORTED;
	ಸ್ಥಿತಿ FIDO_ERR_PIN_REQUIRED:
	ಸ್ಥಿತಿ FIDO_ERR_PIN_INVALID:
	ಸ್ಥಿತಿ FIDO_ERR_OPERATION_DENIED:
		ಹಿಂತಿರುಗಿ SSH_SK_ERR_PIN_REQUIRED;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ -1;
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
check_enroll_options(ರಚನೆ sk_option **options, ಅಕ್ಷರ **devicep,
    uint8_t *user_id, ಗಾತ್ರ_t user_id_len)
{
	ಗಾತ್ರ_t i;

	ಆದರೆ (options == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಗಾಗಿ (i = 0; options[i] != ಖಾಲಿ; i++) {
		ಆದರೆ (strcmp(options[i]->name, "device") == 0) {
			ಆದರೆ ((*devicep = strdup(options[i]->ಮೌಲ್ಯ)) == ಖಾಲಿ) {
				skdebug(__func__, "strdup device failed");
				ಹಿಂತಿರುಗಿ -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(options[i]->name, "user") == 0) {
			ಆದರೆ (strlcpy(user_id, options[i]->ಮೌಲ್ಯ, user_id_len) >=
			    user_id_len) {
				skdebug(__func__, "user too long");
				ಹಿಂತಿರುಗಿ -1;
			}
			skdebug(__func__, "requested user %s",
			    (ಅಕ್ಷರ *)user_id);
		} ಇಲ್ಲದಿದ್ದರೆ {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			ಆದರೆ (options[i]->required) {
				skdebug(__func__, "unknown required option");
				ಹಿಂತಿರುಗಿ -1;
			}
		}
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಕೀಲಿ_lookup(fido_dev_t *dev, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application, ಸ್ಥಿರಾಂಕ uint8_t *user_id,
    ಗಾತ್ರ_t user_id_len, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin)
{
	fido_assert_t *ಪ್ರತಿಜ್ಞಾ = ಖಾಲಿ;
	uint8_t ಸಂದೇಶ_2[32];
	ಪೂರ್ಣಾಂಕ r = FIDO_ERR_ಆಂತರಿಕ;
	ಪೂರ್ಣಾಂಕ sk_supports_uv, uv;
	ಗಾತ್ರ_t i;

	memset(ಸಂದೇಶ_2, '\0', ಗಾತ್ರ(ಸಂದೇಶ_2));
	ಆದರೆ ((ಪ್ರತಿಜ್ಞಾ = fido_assert_new()) == ಖಾಲಿ) {
		skdebug(__func__, "fido_assert_new failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* generate an invalid signature on FIDO2 tokens */
	ಆದರೆ ((r = fido_assert_ಗಣ_clientdata(ಪ್ರತಿಜ್ಞಾ, ಸಂದೇಶ_2,
	    ಗಾತ್ರ(ಸಂದೇಶ_2))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = fido_assert_ಗಣ_rp(ಪ್ರತಿಜ್ಞಾ, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = fido_assert_ಗಣ_ಮೇಲೆ(ಪ್ರತಿಜ್ಞಾ, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	uv = FIDO_OPT_OMIT;
	ಆದರೆ (pin == ಖಾಲಿ && check_sk_options(dev, "uv", &sk_supports_uv) == 0 &&
	    sk_supports_uv != -1)
		uv = FIDO_OPT_TRUE;
	ಆದರೆ ((r = fido_assert_ಗಣ_uv(ಪ್ರತಿಜ್ಞಾ, uv)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = fido_dev_get_assert(dev, ಪ್ರತಿಜ್ಞಾ, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	r = FIDO_ERR_NO_CREDENTIALS;
	skdebug(__func__, "%zu signatures returned", fido_assert_ಎಣಿಕೆ(ಪ್ರತಿಜ್ಞಾ));
	ಗಾಗಿ (i = 0; i < fido_assert_ಎಣಿಕೆ(ಪ್ರತಿಜ್ಞಾ); i++) {
		ಆದರೆ (fido_assert_user_id_len(ಪ್ರತಿಜ್ಞಾ, i) == user_id_len &&
		    memcmp(fido_assert_user_id_ptr(ಪ್ರತಿಜ್ಞಾ, i), user_id,
		    user_id_len) == 0) {
			skdebug(__func__, "credential exists");
			r = FIDO_OK;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}
 ಹೊರಹೋಗು:
	fido_assert_free(&ಪ್ರತಿಜ್ಞಾ);

	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sk_enroll(uint32_t alg, ಸ್ಥಿರಾಂಕ uint8_t *challenge, ಗಾತ್ರ_t challenge_len,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application, uint8_t flags, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin,
    ರಚನೆ sk_option **options, ರಚನೆ sk_enroll_response **enroll_response)
{
	fido_cred_t *cred = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ uint8_t *ptr;
	uint8_t user_id[32];
	ರಚನೆ sk_usbhid *sk = ಖಾಲಿ;
	ರಚನೆ sk_enroll_response *response = ಖಾಲಿ;
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ credprot;
	ಪೂರ್ಣಾಂಕ cose_alg;
	ಪೂರ್ಣಾಂಕ ret = SSH_SK_ERR_GENERAL;
	ಪೂರ್ಣಾಂಕ r;
	ಅಕ್ಷರ *device = ಖಾಲಿ;

	fido_init(SSH_FIDO_INIT_ARG);

	ಆದರೆ (enroll_response == ಖಾಲಿ) {
		skdebug(__func__, "enroll_response == NULL");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	*enroll_response = ಖಾಲಿ;
	memset(user_id, 0, ಗಾತ್ರ(user_id));
	ಆದರೆ (check_enroll_options(options, &device, user_id,
	    ಗಾತ್ರ(user_id)) != 0)
		ಹೋಗು ಹೊರಹೋಗು; /* error already logged */

	ಆಯ್ಕೆ(alg) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಸ್ಥಿತಿ SSH_SK_ECDSA:
		cose_alg = COSE_ES256;
		ನಿಲ್ಲಿಸು;
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	ಸ್ಥಿತಿ SSH_SK_ED25519:
		cose_alg = COSE_EDDSA;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		skdebug(__func__, "unsupported key type %d", alg);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (device != ಖಾಲಿ)
		sk = sk_open(device);
	ಇಲ್ಲದಿದ್ದರೆ
		sk = sk_probe(ಖಾಲಿ, ಖಾಲಿ, 0, 0);
	ಆದರೆ (sk == ಖಾಲಿ) {
		ret = SSH_SK_ERR_DEVICE_NOT_ಸಿಕ್ಕಿತು;
		skdebug(__func__, "failed to find sk");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	skdebug(__func__, "using device %s", sk->ಮಾರ್ಗ);
	ಆದರೆ ((flags & SSH_SK_RESIDENT_ಕೀಲಿ) != 0 &&
	    (flags & SSH_SK_FORCE_OPERATION) == 0 &&
	    (r = ಕೀಲಿ_lookup(sk->dev, application, user_id, ಗಾತ್ರ(user_id),
	    pin)) != FIDO_ERR_NO_CREDENTIALS) {
		ಆದರೆ (r != FIDO_OK) {
			ret = fidoerr_ಗಮ್ಯ_skerr(r);
			skdebug(__func__, "key_lookup failed");
		} ಇಲ್ಲದಿದ್ದರೆ {
			ret = SSH_SK_ERR_CREDENTIAL_EXISTS;
			skdebug(__func__, "key exists");
		}
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((cred = fido_cred_new()) == ಖಾಲಿ) {
		skdebug(__func__, "fido_cred_new failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = fido_cred_ಗಣ_type(cred, cose_alg)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_type: %s", fido_strerr(r));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = fido_cred_ಗಣ_clientdata(cred,
	    challenge, challenge_len)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata: %s",
		    fido_strerr(r));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = fido_cred_ಗಣ_rk(cred, (flags & SSH_SK_RESIDENT_ಕೀಲಿ) != 0 ?
	    FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rk: %s", fido_strerr(r));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = fido_cred_ಗಣ_user(cred, user_id, ಗಾತ್ರ(user_id),
	    "openssh", "openssh", ಖಾಲಿ)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_user: %s", fido_strerr(r));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = fido_cred_ಗಣ_rp(cred, application, ಖಾಲಿ)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rp: %s", fido_strerr(r));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((flags & (SSH_SK_RESIDENT_ಕೀಲಿ|SSH_SK_USER_VERIFICATION_REQD)) != 0) {
#ಆದರೆ !defined(HAVE_FIDO_DEV_SUPPORTS_CRED_PROT) || \
    !defined(HAVE_FIDO_CRED_ಗಣ_PROT)
		skdebug(__func__, "libfido2 version does not support a feature required for this operation. Please upgrade to >=1.5.0");
		ret = SSH_SK_ERR_UNSUPPORTED;
		ಹೋಗು ಹೊರಹೋಗು;
		credprot = 0; (ಶೂನ್ಯ)credprot; /* avoid warning */
#ಆದರೆ_ಅಂತ್ಯ
		ಆದರೆ (!fido_dev_supports_cred_prot(sk->dev)) {
			skdebug(__func__, "%s does not support credprot, "
			    "refusing to create unprotected "
			    "resident/verify-required key", sk->ಮಾರ್ಗ);
			ret = SSH_SK_ERR_UNSUPPORTED;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((flags & SSH_SK_USER_VERIFICATION_REQD))
			credprot = FIDO_CRED_PROT_UV_REQUIRED;
		ಇಲ್ಲದಿದ್ದರೆ
			credprot = FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID;

		ಆದರೆ ((r = fido_cred_ಗಣ_prot(cred, credprot)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_set_prot: %s",
			    fido_strerr(r));
			ret = fidoerr_ಗಮ್ಯ_skerr(r);
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}
	ಆದರೆ ((r = fido_dev_make_cred(sk->dev, cred, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_make_cred: %s", fido_strerr(r));
		ret = fidoerr_ಗಮ್ಯ_skerr(r);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (fido_cred_x5c_ptr(cred) != ಖಾಲಿ) {
		ಆದರೆ ((r = fido_cred_verify(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify: %s",
			    fido_strerr(r));
			ಹೋಗು ಹೊರಹೋಗು;
		}
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(fido_cred_fmt(cred), "none") != 0) {
		skdebug(__func__, "self-attested credential");
		ಆದರೆ ((r = fido_cred_verify_self(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify_self: %s",
			    fido_strerr(r));
			ಹೋಗು ಹೊರಹೋಗು;
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		skdebug(__func__, "no attestation data");
	}
	ಆದರೆ ((response = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*response))) == ಖಾಲಿ) {
		skdebug(__func__, "calloc response failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	response->flags = flags;
	ಆದರೆ (pack_ಬಹಿರಂಗ_ಕೀಲಿ(alg, cred, response) != 0) {
		skdebug(__func__, "pack_public_key failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((ptr = fido_cred_id_ptr(cred)) != ಖಾಲಿ) {
		len = fido_cred_id_len(cred);
		ಆದರೆ ((response->ಕೀಲಿ_handle = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, len)) == ಖಾಲಿ) {
			skdebug(__func__, "calloc key handle failed");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಸ್ಮರಣೆ_ನಕಲು(response->ಕೀಲಿ_handle, ptr, len);
		response->ಕೀಲಿ_handle_len = len;
	}
	ಆದರೆ ((ptr = fido_cred_sig_ptr(cred)) != ಖಾಲಿ) {
		len = fido_cred_sig_len(cred);
		ಆದರೆ ((response->signature = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, len)) == ಖಾಲಿ) {
			skdebug(__func__, "calloc signature failed");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಸ್ಮರಣೆ_ನಕಲು(response->signature, ptr, len);
		response->signature_len = len;
	}
	ಆದರೆ ((ptr = fido_cred_x5c_ptr(cred)) != ಖಾಲಿ) {
		len = fido_cred_x5c_len(cred);
		skdebug(__func__, "attestation cert len=%zu", len);
		ಆದರೆ ((response->attestation_cert = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, len)) == ಖಾಲಿ) {
			skdebug(__func__, "calloc attestation cert failed");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಸ್ಮರಣೆ_ನಕಲು(response->attestation_cert, ptr, len);
		response->attestation_cert_len = len;
	}
	ಆದರೆ ((ptr = fido_cred_authdata_ptr(cred)) != ಖಾಲಿ) {
		len = fido_cred_authdata_len(cred);
		skdebug(__func__, "authdata len=%zu", len);
		ಆದರೆ ((response->authdata = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, len)) == ಖಾಲಿ) {
			skdebug(__func__, "calloc authdata failed");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಸ್ಮರಣೆ_ನಕಲು(response->authdata, ptr, len);
		response->authdata_len = len;
	}
	*enroll_response = response;
	response = ಖಾಲಿ;
	ret = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(device);
	ಆದರೆ (response != ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(response->ಬಹಿರಂಗ_ಕೀಲಿ);
		ಬಿಡುಗಡೆ(response->ಕೀಲಿ_handle);
		ಬಿಡುಗಡೆ(response->signature);
		ಬಿಡುಗಡೆ(response->attestation_cert);
		ಬಿಡುಗಡೆ(response->authdata);
		ಬಿಡುಗಡೆ(response);
	}
	sk_close(sk);
	fido_cred_free(&cred);
	ಹಿಂತಿರುಗಿ ret;
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pack_sig_ecdsa(fido_assert_t *ಪ್ರತಿಜ್ಞಾ, ರಚನೆ sk_sign_response *response)
{
	ECDSA_SIG *sig = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ BIGNUM *sig_r, *sig_s;
	ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *cp;
	ಗಾತ್ರ_t sig_len;
	ಪೂರ್ಣಾಂಕ ret = -1;

	cp = fido_assert_sig_ptr(ಪ್ರತಿಜ್ಞಾ, 0);
	sig_len = fido_assert_sig_len(ಪ್ರತಿಜ್ಞಾ, 0);
	ಆದರೆ ((sig = d2i_ECDSA_SIG(ಖಾಲಿ, &cp, sig_len)) == ಖಾಲಿ) {
		skdebug(__func__, "d2i_ECDSA_SIG failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_ಅಂಕೆ_ಬೈಟುಗಳು(sig_r);
	response->sig_s_len = BN_ಅಂಕೆ_ಬೈಟುಗಳು(sig_s);
	ಆದರೆ ((response->sig_r = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, response->sig_r_len)) == ಖಾಲಿ ||
	    (response->sig_s = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, response->sig_s_len)) == ಖಾಲಿ) {
		skdebug(__func__, "calloc signature failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 ಹೊರಹೋಗು:
	ECDSA_SIG_free(sig);
	ಆದರೆ (ret != 0) {
		ಬಿಡುಗಡೆ(response->sig_r);
		ಬಿಡುಗಡೆ(response->sig_s);
		response->sig_r = ಖಾಲಿ;
		response->sig_s = ಖಾಲಿ;
	}
	ಹಿಂತಿರುಗಿ ret;
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pack_sig_ed25519(fido_assert_t *ಪ್ರತಿಜ್ಞಾ, ರಚನೆ sk_sign_response *response)
{
	ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ptr;
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ ret = -1;

	ptr = fido_assert_sig_ptr(ಪ್ರತಿಜ್ಞಾ, 0);
	len = fido_assert_sig_len(ಪ್ರತಿಜ್ಞಾ, 0);
	ಆದರೆ (len != 64) {
		skdebug(__func__, "bad length %zu", len);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	response->sig_r_len = len;
	ಆದರೆ ((response->sig_r = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, response->sig_r_len)) == ಖಾಲಿ) {
		skdebug(__func__, "calloc signature failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಸ್ಮರಣೆ_ನಕಲು(response->sig_r, ptr, len);
	ret = 0;
 ಹೊರಹೋಗು:
	ಆದರೆ (ret != 0) {
		ಬಿಡುಗಡೆ(response->sig_r);
		response->sig_r = ಖಾಲಿ;
	}
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pack_sig(uint32_t  alg, fido_assert_t *ಪ್ರತಿಜ್ಞಾ,
    ರಚನೆ sk_sign_response *response)
{
	ಆಯ್ಕೆ(alg) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಸ್ಥಿತಿ SSH_SK_ECDSA:
		ಹಿಂತಿರುಗಿ pack_sig_ecdsa(ಪ್ರತಿಜ್ಞಾ, response);
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	ಸ್ಥಿತಿ SSH_SK_ED25519:
		ಹಿಂತಿರುಗಿ pack_sig_ed25519(ಪ್ರತಿಜ್ಞಾ, response);
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ -1;
	}
}

/* Checks sk_options for sk_sign() and sk_load_resident_keys() */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
check_sign_ತುಂಬು_resident_options(ರಚನೆ sk_option **options, ಅಕ್ಷರ **devicep)
{
	ಗಾತ್ರ_t i;

	ಆದರೆ (options == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಗಾಗಿ (i = 0; options[i] != ಖಾಲಿ; i++) {
		ಆದರೆ (strcmp(options[i]->name, "device") == 0) {
			ಆದರೆ ((*devicep = strdup(options[i]->ಮೌಲ್ಯ)) == ಖಾಲಿ) {
				skdebug(__func__, "strdup device failed");
				ಹಿಂತಿರುಗಿ -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} ಇಲ್ಲದಿದ್ದರೆ {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			ಆದರೆ (options[i]->required) {
				skdebug(__func__, "unknown required option");
				ಹಿಂತಿರುಗಿ -1;
			}
		}
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sk_sign(uint32_t alg, ಸ್ಥಿರಾಂಕ uint8_t *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application,
    ಸ್ಥಿರಾಂಕ uint8_t *ಕೀಲಿ_handle, ಗಾತ್ರ_t ಕೀಲಿ_handle_len,
    uint8_t flags, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin, ರಚನೆ sk_option **options,
    ರಚನೆ sk_sign_response **sign_response)
{
	fido_assert_t *ಪ್ರತಿಜ್ಞಾ = ಖಾಲಿ;
	ಅಕ್ಷರ *device = ಖಾಲಿ;
	ರಚನೆ sk_usbhid *sk = ಖಾಲಿ;
	ರಚನೆ sk_sign_response *response = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ret = SSH_SK_ERR_GENERAL, ಆಂತರಿಕ_uv;
	ಪೂರ್ಣಾಂಕ r;

	fido_init(SSH_FIDO_INIT_ARG);

	ಆದರೆ (sign_response == ಖಾಲಿ) {
		skdebug(__func__, "sign_response == NULL");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	*sign_response = ಖಾಲಿ;
	ಆದರೆ (check_sign_ತುಂಬು_resident_options(options, &device) != 0)
		ಹೋಗು ಹೊರಹೋಗು; /* error already logged */
	ಆದರೆ (device != ಖಾಲಿ)
		sk = sk_open(device);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (pin != ಖಾಲಿ || (flags & SSH_SK_USER_VERIFICATION_REQD))
		sk = sk_probe(ಖಾಲಿ, ಖಾಲಿ, 0, 0);
	ಇಲ್ಲದಿದ್ದರೆ
		sk = sk_probe(application, ಕೀಲಿ_handle, ಕೀಲಿ_handle_len, 0);
	ಆದರೆ (sk == ಖಾಲಿ) {
		ret = SSH_SK_ERR_DEVICE_NOT_ಸಿಕ್ಕಿತು;
		skdebug(__func__, "failed to find sk");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((ಪ್ರತಿಜ್ಞಾ = fido_assert_new()) == ಖಾಲಿ) {
		skdebug(__func__, "fido_assert_new failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = fido_assert_ಗಣ_clientdata(ಪ್ರತಿಜ್ಞಾ,
	    ದತ್ತಾಂಶ, datalen)) != FIDO_OK)  {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = fido_assert_ಗಣ_rp(ಪ್ರತಿಜ್ಞಾ, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = fido_assert_allow_cred(ಪ್ರತಿಜ್ಞಾ, ಕೀಲಿ_handle,
	    ಕೀಲಿ_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = fido_assert_ಗಣ_ಮೇಲೆ(ಪ್ರತಿಜ್ಞಾ,
	    (flags & SSH_SK_USER_PRESENCE_REQD) ?
	    FIDO_OPT_TRUE : FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/*
	 * WinHello requests the PIN by default.  Make "uv" request explicit
	 * to allow keys with and without -O verify-required to make sense.
	 */
	ಆದರೆ (pin == ಖಾಲಿ && fido_dev_is_winhello (sk->dev) &&
	    (r = fido_assert_ಗಣ_uv(ಪ್ರತಿಜ್ಞಾ, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
	}
	ಆದರೆ (pin == ಖಾಲಿ && (flags & SSH_SK_USER_VERIFICATION_REQD)) {
		ಆದರೆ (check_sk_options(sk->dev, "uv", &ಆಂತರಿಕ_uv) < 0 ||
		    ಆಂತರಿಕ_uv != 1) {
			skdebug(__func__, "check_sk_options uv");
			ret = SSH_SK_ERR_PIN_REQUIRED;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((r = fido_assert_ಗಣ_uv(ಪ್ರತಿಜ್ಞಾ,
		    FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_assert_set_uv: %s",
			    fido_strerr(r));
			ret = fidoerr_ಗಮ್ಯ_skerr(r);
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}
	ಆದರೆ ((r = fido_dev_get_assert(sk->dev, ಪ್ರತಿಜ್ಞಾ, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ret = fidoerr_ಗಮ್ಯ_skerr(r);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((response = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*response))) == ಖಾಲಿ) {
		skdebug(__func__, "calloc response failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	response->flags = fido_assert_flags(ಪ್ರತಿಜ್ಞಾ, 0);
	response->counter = fido_assert_sigcount(ಪ್ರತಿಜ್ಞಾ, 0);
	ಆದರೆ (pack_sig(alg, ಪ್ರತಿಜ್ಞಾ, response) != 0) {
		skdebug(__func__, "pack_sig failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	*sign_response = response;
	response = ಖಾಲಿ;
	ret = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(device);
	ಆದರೆ (response != ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(response->sig_r);
		ಬಿಡುಗಡೆ(response->sig_s);
		ಬಿಡುಗಡೆ(response);
	}
	sk_close(sk);
	fido_assert_free(&ಪ್ರತಿಜ್ಞಾ);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
read_rks(ರಚನೆ sk_usbhid *sk, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin,
    ರಚನೆ sk_resident_ಕೀಲಿ ***rksp, ಗಾತ್ರ_t *nrksp)
{
	ಪೂರ್ಣಾಂಕ ret = SSH_SK_ERR_GENERAL, r = -1;
	uint32_t alg;
	fido_credman_metadata_t *metadata = ಖಾಲಿ;
	fido_credman_rp_t *rp = ಖಾಲಿ;
	fido_credman_rk_t *rk = ಖಾಲಿ;
	ಗಾತ್ರ_t i, j, nrp, nrk, user_id_len;
	ಸ್ಥಿರಾಂಕ fido_cred_t *cred;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *rp_id, *rp_name, *user_name;
	ರಚನೆ sk_resident_ಕೀಲಿ *srk = ಖಾಲಿ, **tmp;
	ಸ್ಥಿರಾಂಕ u_char *user_id;

	ಆದರೆ (pin == ಖಾಲಿ) {
		skdebug(__func__, "no PIN specified");
		ret = SSH_SK_ERR_PIN_REQUIRED;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((metadata = fido_credman_metadata_new()) == ಖಾಲಿ) {
		skdebug(__func__, "alloc failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = fido_credman_get_dev_metadata(sk->dev, metadata, pin)) != 0) {
		ಆದರೆ (r == FIDO_ERR_INVALID_COMMAND) {
			skdebug(__func__, "device %s does not support "
			    "resident keys", sk->ಮಾರ್ಗ);
			ret = 0;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		skdebug(__func__, "get metadata for %s failed: %s",
		    sk->ಮಾರ್ಗ, fido_strerr(r));
		ret = fidoerr_ಗಮ್ಯ_skerr(r);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	skdebug(__func__, "existing %llu, remaining %llu",
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)fido_credman_rk_existing(metadata),
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)fido_credman_rk_ಉಳಿದ(metadata));
	ಆದರೆ ((rp = fido_credman_rp_new()) == ಖಾಲಿ) {
		skdebug(__func__, "alloc rp failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = fido_credman_get_dev_rp(sk->dev, rp, pin)) != 0) {
		skdebug(__func__, "get RPs for %s failed: %s",
		    sk->ಮಾರ್ಗ, fido_strerr(r));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	nrp = fido_credman_rp_ಎಣಿಕೆ(rp);
	skdebug(__func__, "Device %s has resident keys for %zu RPs",
	    sk->ಮಾರ್ಗ, nrp);

	/* Iterate over RP IDs that have resident keys */
	ಗಾಗಿ (i = 0; i < nrp; i++) {
		rp_id = fido_credman_rp_id(rp, i);
		rp_name = fido_credman_rp_name(rp, i);
		skdebug(__func__, "rp %zu: name=\"%s\" id=\"%s\" hashlen=%zu",
		    i, rp_name == ಖಾಲಿ ? "(none)" : rp_name,
		    rp_id == ಖಾಲಿ ? "(none)" : rp_id,
		    fido_credman_rp_id_hash_len(rp, i));

		/* Skip non-SSH RP IDs */
		ಆದರೆ (rp_id == ಖಾಲಿ ||
		    strncasecmp(fido_credman_rp_id(rp, i), "ssh:", 4) != 0)
			ಮುಂದುವರಿ;

		fido_credman_rk_free(&rk);
		ಆದರೆ ((rk = fido_credman_rk_new()) == ಖಾಲಿ) {
			skdebug(__func__, "alloc rk failed");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((r = fido_credman_get_dev_rk(sk->dev,
		    fido_credman_rp_id(rp, i), rk, pin)) != 0) {
			skdebug(__func__, "get RKs for %s slot %zu failed: %s",
			    sk->ಮಾರ್ಗ, i, fido_strerr(r));
			ಹೋಗು ಹೊರಹೋಗು;
		}
		nrk = fido_credman_rk_ಎಣಿಕೆ(rk);
		skdebug(__func__, "RP \"%s\" has %zu resident keys",
		    fido_credman_rp_id(rp, i), nrk);

		/* Iterate over resident keys for this RP ID */
		ಗಾಗಿ (j = 0; j < nrk; j++) {
			ಆದರೆ ((cred = fido_credman_rk(rk, j)) == ಖಾಲಿ) {
				skdebug(__func__, "no RK in slot %zu", j);
				ಮುಂದುವರಿ;
			}
			ಆದರೆ ((user_name = fido_cred_user_name(cred)) == ಖಾಲಿ)
				user_name = "";
			user_id = fido_cred_user_id_ptr(cred);
			user_id_len = fido_cred_user_id_len(cred);
			skdebug(__func__, "Device %s RP \"%s\" user \"%s\" "
			    "uidlen %zu slot %zu: type %d flags 0x%02x "
			    "prot 0x%02x", sk->ಮಾರ್ಗ, rp_id, user_name,
			    user_id_len, j, fido_cred_type(cred),
			    fido_cred_flags(cred), fido_cred_prot(cred));

			/* Determine key algorithm */
			ಆಯ್ಕೆ (fido_cred_type(cred)) {
			ಸ್ಥಿತಿ COSE_ES256:
				alg = SSH_SK_ECDSA;
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ COSE_EDDSA:
				alg = SSH_SK_ED25519;
				ನಿಲ್ಲಿಸು;
			ಪೂರ್ವನಿಯೋಜಿತ:
				skdebug(__func__, "unsupported key type %d",
				    fido_cred_type(cred));
				ಮುಂದುವರಿ;
			}

			/* build response entry */
			ಆದರೆ ((srk = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*srk))) == ಖಾಲಿ ||
			    (srk->ಕೀಲಿ.ಕೀಲಿ_handle = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1,
			    fido_cred_id_len(cred))) == ಖಾಲಿ ||
			    (srk->application = strdup(rp_id)) == ಖಾಲಿ ||
			    (user_id_len > 0 &&
			     (srk->user_id = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, user_id_len)) == ಖಾಲಿ)) {
				skdebug(__func__, "alloc sk_resident_key");
				ಹೋಗು ಹೊರಹೋಗು;
			}

			srk->alg = alg;
			srk->ಕೀಲಿ.ಕೀಲಿ_handle_len = fido_cred_id_len(cred);
			ಸ್ಮರಣೆ_ನಕಲು(srk->ಕೀಲಿ.ಕೀಲಿ_handle, fido_cred_id_ptr(cred),
			    srk->ಕೀಲಿ.ಕೀಲಿ_handle_len);
			srk->user_id_len = user_id_len;
			ಆದರೆ (srk->user_id_len != 0)
				ಸ್ಮರಣೆ_ನಕಲು(srk->user_id, user_id, srk->user_id_len);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_FIDO_CRED_PROT
			ಆದರೆ (fido_cred_prot(cred) ==
			    FIDO_CRED_PROT_UV_REQUIRED)
				srk->flags |=  SSH_SK_USER_VERIFICATION_REQD;
#ಆದರೆ_ಅಂತ್ಯ

			ಆದರೆ ((r = pack_ಬಹಿರಂಗ_ಕೀಲಿ(srk->alg, cred,
			    &srk->ಕೀಲಿ)) != 0) {
				skdebug(__func__, "pack public key failed");
				ಹೋಗು ಹೊರಹೋಗು;
			}
			/* append */
			ಆದರೆ ((tmp = recallocarray(*rksp, *nrksp, (*nrksp) + 1,
			    ಗಾತ್ರ(**rksp))) == ಖಾಲಿ) {
				skdebug(__func__, "alloc rksp");
				ಹೋಗು ಹೊರಹೋಗು;
			}
			*rksp = tmp;
			(*rksp)[(*nrksp)++] = srk;
			srk = ಖಾಲಿ;
		}
	}
	/* Success */
	ret = 0;
 ಹೊರಹೋಗು:
	ಆದರೆ (srk != ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(srk->application);
		freezero(srk->ಕೀಲಿ.ಬಹಿರಂಗ_ಕೀಲಿ, srk->ಕೀಲಿ.ಬಹಿರಂಗ_ಕೀಲಿ_len);
		freezero(srk->ಕೀಲಿ.ಕೀಲಿ_handle, srk->ಕೀಲಿ.ಕೀಲಿ_handle_len);
		freezero(srk->user_id, srk->user_id_len);
		freezero(srk, ಗಾತ್ರ(*srk));
	}
	fido_credman_rp_free(&rp);
	fido_credman_rk_free(&rk);
	fido_credman_metadata_free(&metadata);
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
sk_ತುಂಬು_resident_ಕೀಲಿಗಳು(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin, ರಚನೆ sk_option **options,
    ರಚನೆ sk_resident_ಕೀಲಿ ***rksp, ಗಾತ್ರ_t *nrksp)
{
	ಪೂರ್ಣಾಂಕ ret = SSH_SK_ERR_GENERAL, r = -1;
	ಗಾತ್ರ_t i, nrks = 0;
	ರಚನೆ sk_resident_ಕೀಲಿ **rks = ಖಾಲಿ;
	ರಚನೆ sk_usbhid *sk = ಖಾಲಿ;
	ಅಕ್ಷರ *device = ಖಾಲಿ;

	*rksp = ಖಾಲಿ;
	*nrksp = 0;

	fido_init(SSH_FIDO_INIT_ARG);

	ಆದರೆ (check_sign_ತುಂಬು_resident_options(options, &device) != 0)
		ಹೋಗು ಹೊರಹೋಗು; /* error already logged */
	ಆದರೆ (device != ಖಾಲಿ)
		sk = sk_open(device);
	ಇಲ್ಲದಿದ್ದರೆ
		sk = sk_probe(ಖಾಲಿ, ಖಾಲಿ, 0, 1);
	ಆದರೆ (sk == ಖಾಲಿ) {
		ret = SSH_SK_ERR_DEVICE_NOT_ಸಿಕ್ಕಿತು;
		skdebug(__func__, "failed to find sk");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	skdebug(__func__, "trying %s", sk->ಮಾರ್ಗ);
	ಆದರೆ ((r = read_rks(sk, pin, &rks, &nrks)) != 0) {
		skdebug(__func__, "read_rks failed for %s", sk->ಮಾರ್ಗ);
		ret = r;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success, unless we have no keys but a specific error */
	ಆದರೆ (nrks > 0 || ret == SSH_SK_ERR_GENERAL)
		ret = 0;
	*rksp = rks;
	*nrksp = nrks;
	rks = ಖಾಲಿ;
	nrks = 0;
 ಹೊರಹೋಗು:
	sk_close(sk);
	ಗಾಗಿ (i = 0; i < nrks; i++) {
		ಬಿಡುಗಡೆ(rks[i]->application);
		freezero(rks[i]->ಕೀಲಿ.ಬಹಿರಂಗ_ಕೀಲಿ, rks[i]->ಕೀಲಿ.ಬಹಿರಂಗ_ಕೀಲಿ_len);
		freezero(rks[i]->ಕೀಲಿ.ಕೀಲಿ_handle, rks[i]->ಕೀಲಿ.ಕೀಲಿ_handle_len);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i], ಗಾತ್ರ(*rks[i]));
	}
	ಬಿಡುಗಡೆ(device);
	ಬಿಡುಗಡೆ(rks);
	ಹಿಂತಿರುಗಿ ret;
}

#ಆದರೆ_ಅಂತ್ಯ /* ENABLE_SK_INTERNAL */
