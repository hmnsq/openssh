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

#अन्तर्भाव "includes.h"

#ifdef ENABLE_SK_INTERNAL

#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <time.h>
#ifdef HAVE_SHA2_H
#अन्तर्भाव <sha2.h>
#endif

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/opensslv.h>
#अन्तर्भाव <openssl/crypto.h>
#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/ec.h>
#अन्तर्भाव <openssl/ecdsa.h>
#अन्तर्भाव <openssl/evp.h>
#अन्तर्भाव "openbsd-compat/openssl-compat.h"
#endif /* WITH_OPENSSL */

#अन्तर्भाव <fido.h>
#अन्तर्भाव <fido/credman.h>

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
# define sk_load_resident_कुञ्चिकाः	ssh_sk_load_resident_कुञ्चिकाः
#endif /* !SK_STANDALONE */

#अन्तर्भाव "sk-api.h"

/* #define SK_DEBUG 1 */

#ifdef SK_DEBUG
#define SSH_FIDO_INIT_ARG	FIDO_DEBUG
#अण्णहा
#define SSH_FIDO_INIT_ARG	0
#endif

#define MAX_FIDO_DEVICES	8
#define FIDO_POLL_MS		50
#define SELECT_MS		15000
#define POLL_SLEEP_NS		200000000

#ifndef FIDO_ERR_OPERATION_DENIED
#define FIDO_ERR_OPERATION_DENIED 0x27
#endif

संरचना sk_usbhid {
	fido_dev_t *dev;
	वर्ण *path;
};

/* Return the version of the middleware API */
uint32_t sk_api_version(शून्य);

/* Enroll a U2F key (private key generation) */
पूर्णाङ्क sk_enroll(uint32_t alg, ध्रुव uint8_t *challenge, size_t challenge_len,
    ध्रुव वर्ण *application, uint8_t flags, ध्रुव वर्ण *pin,
    संरचना sk_option **options, संरचना sk_enroll_response **enroll_response);

/* Sign a challenge */
पूर्णाङ्क sk_sign(uint32_t alg, ध्रुव uint8_t *data, size_t data_len,
    ध्रुव वर्ण *application, ध्रुव uint8_t *कुञ्चिका_handle, size_t कुञ्चिका_handle_len,
    uint8_t flags, ध्रुव वर्ण *pin, संरचना sk_option **options,
    संरचना sk_sign_response **sign_response);

/* Load resident keys */
पूर्णाङ्क sk_load_resident_कुञ्चिकाः(ध्रुव वर्ण *pin, संरचना sk_option **options,
    संरचना sk_resident_कुञ्चिका ***rks, size_t *nrks);

स्थिर शून्य skdebug(ध्रुव वर्ण *func, ध्रुव वर्ण *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

स्थिर शून्य
skdebug(ध्रुव वर्ण *func, ध्रुव वर्ण *fmt, ...)
{
#जइ !defined(SK_STANDALONE)
	वर्ण *सन्देशः;
	va_list ap;

	va_start(ap, fmt);
	xvasprintf(&सन्देशः, fmt, ap);
	va_end(ap);
	debug("%s: %s", func, सन्देशः);
	मुक्त(सन्देशः);
#नोचेद्यदि defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#अण्णहा
	(शून्य)func; /* XXX */
	(शून्य)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(शून्य)
{
	प्रत्यागम SSH_SK_VERSION_MAJOR;
}

स्थिर संरचना sk_usbhid *
sk_open(ध्रुव वर्ण *path)
{
	संरचना sk_usbhid *sk;
	पूर्णाङ्क r;

	जइ (path == रिक्त) {
		skdebug(__func__, "path == NULL");
		प्रत्यागम रिक्त;
	}
	जइ ((sk = calloc(1, परिमाण(*sk))) == रिक्त) {
		skdebug(__func__, "calloc sk failed");
		प्रत्यागम रिक्त;
	}
	जइ ((sk->path = strdup(path)) == रिक्त) {
		skdebug(__func__, "strdup path failed");
		मुक्त(sk);
		प्रत्यागम रिक्त;
	}
	जइ ((sk->dev = fido_dev_new()) == रिक्त) {
		skdebug(__func__, "fido_dev_new failed");
		मुक्त(sk->path);
		मुक्त(sk);
		प्रत्यागम रिक्त;
	}
	जइ ((r = fido_dev_open(sk->dev, sk->path)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_open %s failed: %s", sk->path,
		    fido_strerr(r));
		fido_dev_free(&sk->dev);
		मुक्त(sk->path);
		मुक्त(sk);
		प्रत्यागम रिक्त;
	}
	प्रत्यागम sk;
}

स्थिर शून्य
sk_close(संरचना sk_usbhid *sk)
{
	जइ (sk == रिक्त)
		प्रत्यागम;
	fido_dev_cancel(sk->dev); /* cancel any pending operation */
	fido_dev_close(sk->dev);
	fido_dev_free(&sk->dev);
	मुक्त(sk->path);
	मुक्त(sk);
}

स्थिर संरचना sk_usbhid **
sk_openv(ध्रुव fido_dev_info_t *devlist, size_t ndevs, size_t *nopen)
{
	ध्रुव fido_dev_info_t *di;
	संरचना sk_usbhid **skv;
	size_t i;

	*nopen = 0;
	जइ ((skv = calloc(ndevs, परिमाण(*skv))) == रिक्त) {
		skdebug(__func__, "calloc skv failed");
		प्रत्यागम रिक्त;
	}
	प्रति (i = 0; i < ndevs; i++) {
		जइ ((di = fido_dev_info_ptr(devlist, i)) == रिक्त)
			skdebug(__func__, "fido_dev_info_ptr failed");
		अण्णहा जइ ((skv[*nopen] = sk_open(fido_dev_info_path(di))) == रिक्त)
			skdebug(__func__, "sk_open failed");
		अण्णहा
			(*nopen)++;
	}
	जइ (*nopen == 0) {
		प्रति (i = 0; i < ndevs; i++)
			sk_close(skv[i]);
		मुक्त(skv);
		skv = रिक्त;
	}

	प्रत्यागम skv;
}

स्थिर शून्य
sk_closev(संरचना sk_usbhid **skv, size_t nsk)
{
	size_t i;

	प्रति (i = 0; i < nsk; i++)
		sk_close(skv[i]);
	मुक्त(skv);
}

स्थिर पूर्णाङ्क
sk_touch_begin(संरचना sk_usbhid **skv, size_t nsk)
{
	size_t i, ok = 0;
	पूर्णाङ्क r;

	प्रति (i = 0; i < nsk; i++)
		जइ ((r = fido_dev_get_touch_begin(skv[i]->dev)) != FIDO_OK)
			skdebug(__func__, "fido_dev_get_touch_begin %s failed:"
			    " %s", skv[i]->path, fido_strerr(r));
		अण्णहा
			ok++;

	प्रत्यागम ok ? 0 : -1;
}

स्थिर पूर्णाङ्क
sk_touch_poll(संरचना sk_usbhid **skv, size_t nsk, पूर्णाङ्क *touch, size_t *idx)
{
	संरचना timespec ts_pause;
	size_t npoll, i;
	पूर्णाङ्क r;

	ts_pause.tv_sec = 0;
	ts_pause.tv_nsec = POLL_SLEEP_NS;
	nanosleep(&ts_pause, रिक्त);
	npoll = nsk;
	प्रति (i = 0; i < nsk; i++) {
		जइ (skv[i] == रिक्त)
			अनुवर्त; /* device discarded */
		skdebug(__func__, "polling %s", skv[i]->path);
		जइ ((r = fido_dev_get_touch_status(skv[i]->dev, touch,
		    FIDO_POLL_MS)) != FIDO_OK) {
			skdebug(__func__, "fido_dev_get_touch_status %s: %s",
			    skv[i]->path, fido_strerr(r));
			sk_close(skv[i]); /* discard device */
			skv[i] = रिक्त;
			जइ (--npoll == 0) {
				skdebug(__func__, "no device left to poll");
				प्रत्यागम -1;
			}
		} अण्णहा जइ (*touch) {
			*idx = i;
			प्रत्यागम 0;
		}
	}
	*touch = 0;
	प्रत्यागम 0;
}

#जइ !defined(HAVE_FIDO_ASSERT_SET_CLIENTDATA) || \
    !defined(HAVE_FIDO_CRED_SET_CLIENTDATA)
/* Calculate SHA256(m) */
स्थिर पूर्णाङ्क
sha256_mem(ध्रुव शून्य *m, size_t mlen, u_char *d, size_t dlen)
{
#ifdef WITH_OPENSSL
	u_int mdlen;
#अण्णहा
	SHA2_CTX ctx;
#endif

	जइ (dlen != 32)
		प्रत्यागम -1;
#ifdef WITH_OPENSSL
	mdlen = dlen;
	जइ (!EVP_Digest(m, mlen, d, &mdlen, EVP_sha256(), रिक्त))
		प्रत्यागम -1;
#अण्णहा
	SHA256Init(&ctx);
	SHA256Update(&ctx, (ध्रुव uint8_t *)m, mlen);
	SHA256Final(d, &ctx);
#endif
	प्रत्यागम 0;
}
#endif /* !HAVE_FIDO_ASSERT_SET_CLIENTDATA || !HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_CRED_SET_CLIENTDATA
स्थिर पूर्णाङ्क
fido_cred_set_clientdata(fido_cred_t *cred, ध्रुव u_char *ptr, size_t len)
{
	uint8_t d[32];
	पूर्णाङ्क r;

	जइ (sha256_mem(ptr, len, d, परिमाण(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		प्रत्यागम FIDO_ERR_INTERNAL;
	}
	r = fido_cred_set_clientdata_hash(cred, d, परिमाण(d));
	explicit_bzero(d, परिमाण(d));
	जइ (r != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	प्रत्यागम r;
}
#endif /* HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_ASSERT_SET_CLIENTDATA
स्थिर पूर्णाङ्क
fido_assert_set_clientdata(fido_assert_t *प्रतिज्ञा, ध्रुव u_char *ptr, size_t len)
{
	uint8_t d[32];
	पूर्णाङ्क r;

	जइ (sha256_mem(ptr, len, d, परिमाण(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		प्रत्यागम FIDO_ERR_INTERNAL;
	}
	r = fido_assert_set_clientdata_hash(प्रतिज्ञा, d, परिमाण(d));
	explicit_bzero(d, परिमाण(d));
	जइ (r != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	प्रत्यागम r;
}
#endif /* HAVE_FIDO_ASSERT_SET_CLIENTDATA */

#ifndef HAVE_FIDO_DEV_IS_WINHELLO
स्थिर bool
fido_dev_is_winhello(ध्रुव fido_dev_t *fdev)
{
	प्रत्यागम 0;
}
#endif /* HAVE_FIDO_DEV_IS_WINHELLO */

/* Check if the specified key handle exists on a given sk. */
स्थिर पूर्णाङ्क
sk_try(ध्रुव संरचना sk_usbhid *sk, ध्रुव वर्ण *application,
    ध्रुव uint8_t *कुञ्चिका_handle, size_t कुञ्चिका_handle_len)
{
	fido_assert_t *प्रतिज्ञा = रिक्त;
	पूर्णाङ्क r = FIDO_ERR_INTERNAL;
	uint8_t message[32];

	memset(message, '\0', परिमाण(message));
	जइ ((प्रतिज्ञा = fido_assert_new()) == रिक्त) {
		skdebug(__func__, "fido_assert_new failed");
		गच्छ out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	जइ ((r = fido_assert_set_clientdata(प्रतिज्ञा, message,
	    परिमाण(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		गच्छ out;
	}
	जइ ((r = fido_assert_set_rp(प्रतिज्ञा, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		गच्छ out;
	}
	जइ ((r = fido_assert_allow_cred(प्रतिज्ञा, कुञ्चिका_handle,
	    कुञ्चिका_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		गच्छ out;
	}
	जइ ((r = fido_assert_set_up(प्रतिज्ञा, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_up: %s", fido_strerr(r));
		गच्छ out;
	}
	r = fido_dev_get_assert(sk->dev, प्रतिज्ञा, रिक्त);
	skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
	जइ (r == FIDO_ERR_USER_PRESENCE_REQUIRED) {
		/* U2F tokens may return this */
		r = FIDO_OK;
	}
 out:
	fido_assert_free(&प्रतिज्ञा);

	प्रत्यागम r != FIDO_OK ? -1 : 0;
}

स्थिर पूर्णाङ्क
check_sk_options(fido_dev_t *dev, ध्रुव वर्ण *opt, पूर्णाङ्क *ret)
{
	fido_cbor_info_t *info;
	वर्ण * ध्रुव *name;
	ध्रुव bool *मानम्;
	size_t len, i;
	पूर्णाङ्क r;

	*ret = -1;

	जइ (!fido_dev_is_fido2(dev)) {
		skdebug(__func__, "device is not fido2");
		प्रत्यागम 0;
	}
	जइ ((info = fido_cbor_info_new()) == रिक्त) {
		skdebug(__func__, "fido_cbor_info_new failed");
		प्रत्यागम -1;
	}
	जइ ((r = fido_dev_get_cbor_info(dev, info)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_cbor_info: %s", fido_strerr(r));
		fido_cbor_info_free(&info);
		प्रत्यागम -1;
	}
	name = fido_cbor_info_options_name_ptr(info);
	मानम् = fido_cbor_info_options_मानम्_ptr(info);
	len = fido_cbor_info_options_len(info);
	प्रति (i = 0; i < len; i++) {
		जइ (!strcmp(name[i], opt)) {
			*ret = मानम्[i];
			भङ्ग;
		}
	}
	fido_cbor_info_free(&info);
	जइ (*ret == -1)
		skdebug(__func__, "option %s is unknown", opt);
	अण्णहा
		skdebug(__func__, "option %s is %s", opt, *ret ? "on" : "off");

	प्रत्यागम 0;
}

स्थिर संरचना sk_usbhid *
sk_select_by_cred(ध्रुव fido_dev_info_t *devlist, size_t ndevs,
    ध्रुव वर्ण *application, ध्रुव uint8_t *कुञ्चिका_handle, size_t कुञ्चिका_handle_len)
{
	संरचना sk_usbhid **skv, *sk;
	size_t skvcnt, i;
	पूर्णाङ्क internal_uv;

	जइ ((skv = sk_openv(devlist, ndevs, &skvcnt)) == रिक्त) {
		skdebug(__func__, "sk_openv failed");
		प्रत्यागम रिक्त;
	}
	जइ (skvcnt == 1 && check_sk_options(skv[0]->dev, "uv",
	    &internal_uv) == 0 && internal_uv != -1) {
		sk = skv[0];
		skv[0] = रिक्त;
		गच्छ out;
	}
	sk = रिक्त;
	प्रति (i = 0; i < skvcnt; i++) {
		जइ (sk_try(skv[i], application, कुञ्चिका_handle,
		    कुञ्चिका_handle_len) == 0) {
			sk = skv[i];
			skv[i] = रिक्त;
			skdebug(__func__, "found key in %s", sk->path);
			भङ्ग;
		}
	}
 out:
	sk_closev(skv, skvcnt);
	प्रत्यागम sk;
}

स्थिर संरचना sk_usbhid *
sk_select_by_touch(ध्रुव fido_dev_info_t *devlist, size_t ndevs)
{
	संरचना sk_usbhid **skv, *sk;
	संरचना timeval tv_start, tv_now, tv_delta;
	size_t skvcnt, idx;
	पूर्णाङ्क touch, ms_remain;

	जइ ((skv = sk_openv(devlist, ndevs, &skvcnt)) == रिक्त) {
		skdebug(__func__, "sk_openv failed");
		प्रत्यागम रिक्त;
	}
	sk = रिक्त;
	जइ (skvcnt < 2) {
		जइ (skvcnt == 1) {
			/* single candidate */
			sk = skv[0];
			skv[0] = रिक्त;
		}
		गच्छ out;
	}
#ifndef HAVE_FIDO_DEV_GET_TOUCH_STATUS
	skdebug(__func__, "libfido2 version does not support a feature needed for multiple tokens. Please upgrade to >=1.5.0");
	गच्छ out;
#endif

	जइ (sk_touch_begin(skv, skvcnt) == -1) {
		skdebug(__func__, "sk_touch_begin failed");
		गच्छ out;
	}
	monotime_tv(&tv_start);
	करेहि {
		जइ (sk_touch_poll(skv, skvcnt, &touch, &idx) == -1) {
			skdebug(__func__, "sk_touch_poll failed");
			गच्छ out;
		}
		जइ (touch) {
			sk = skv[idx];
			skv[idx] = रिक्त;
			गच्छ out;
		}
		monotime_tv(&tv_now);
		timersub(&tv_now, &tv_start, &tv_delta);
		ms_remain = SELECT_MS - tv_delta.tv_sec * 1000 -
		    tv_delta.tv_usec / 1000;
	} जाव (ms_remain >= FIDO_POLL_MS);
	skdebug(__func__, "timeout");
out:
	sk_closev(skv, skvcnt);
	प्रत्यागम sk;
}

स्थिर संरचना sk_usbhid *
sk_probe(ध्रुव वर्ण *application, ध्रुव uint8_t *कुञ्चिका_handle,
    size_t कुञ्चिका_handle_len, पूर्णाङ्क probe_resident)
{
	संरचना sk_usbhid *sk;
	fido_dev_info_t *devlist;
	size_t ndevs;
	पूर्णाङ्क r;

#ifdef HAVE_CYGWIN
	जइ (!probe_resident && (sk = sk_open("windows://hello")) != रिक्त)
		प्रत्यागम sk;
#endif /* HAVE_CYGWIN */
	जइ ((devlist = fido_dev_info_new(MAX_FIDO_DEVICES)) == रिक्त) {
		skdebug(__func__, "fido_dev_info_new failed");
		प्रत्यागम रिक्त;
	}
	जइ ((r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES,
	    &ndevs)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_info_manifest failed: %s",
		    fido_strerr(r));
		fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
		प्रत्यागम रिक्त;
	}
	skdebug(__func__, "%zu device(s) detected", ndevs);
	जइ (ndevs == 0) {
		sk = रिक्त;
	} अण्णहा जइ (application != रिक्त && कुञ्चिका_handle != रिक्त) {
		skdebug(__func__, "selecting sk by cred");
		sk = sk_select_by_cred(devlist, ndevs, application, कुञ्चिका_handle,
		    कुञ्चिका_handle_len);
	} अण्णहा {
		skdebug(__func__, "selecting sk by touch");
		sk = sk_select_by_touch(devlist, ndevs);
	}
	fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
	प्रत्यागम sk;
}

#ifdef WITH_OPENSSL
/*
 * The key returned via fido_cred_pubkey_ptr() is in affine coordinates,
 * but the API expects a SEC1 octet string.
 */
स्थिर पूर्णाङ्क
pack_public_कुञ्चिका_ecdsa(ध्रुव fido_cred_t *cred,
    संरचना sk_enroll_response *response)
{
	ध्रुव uint8_t *ptr;
	BIGNUM *x = रिक्त, *y = रिक्त;
	EC_POINT *q = रिक्त;
	EC_GROUP *g = रिक्त;
	पूर्णाङ्क ret = -1;

	response->public_कुञ्चिका = रिक्त;
	response->public_कुञ्चिका_len = 0;

	जइ ((x = BN_new()) == रिक्त ||
	    (y = BN_new()) == रिक्त ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == रिक्त ||
	    (q = EC_POINT_new(g)) == रिक्त) {
		skdebug(__func__, "libcrypto setup failed");
		गच्छ out;
	}
	जइ ((ptr = fido_cred_pubkey_ptr(cred)) == रिक्त) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		गच्छ out;
	}
	जइ (fido_cred_pubkey_len(cred) != 64) {
		skdebug(__func__, "bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		गच्छ out;
	}

	जइ (BN_bin2bn(ptr, 32, x) == रिक्त ||
	    BN_bin2bn(ptr + 32, 32, y) == रिक्त) {
		skdebug(__func__, "BN_bin2bn failed");
		गच्छ out;
	}
	जइ (EC_POINT_set_affine_coordinates(g, q, x, y, रिक्त) != 1) {
		skdebug(__func__, "EC_POINT_set_affine_coordinates failed");
		गच्छ out;
	}
	response->public_कुञ्चिका_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, रिक्त, 0, रिक्त);
	जइ (response->public_कुञ्चिका_len == 0 || response->public_कुञ्चिका_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_कुञ्चिका_len);
		गच्छ out;
	}
	जइ ((response->public_कुञ्चिका = malloc(response->public_कुञ्चिका_len)) == रिक्त) {
		skdebug(__func__, "malloc pubkey failed");
		गच्छ out;
	}
	जइ (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_कुञ्चिका, response->public_कुञ्चिका_len, रिक्त) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		गच्छ out;
	}
	/* success */
	ret = 0;
 out:
	जइ (ret != 0 && response->public_कुञ्चिका != रिक्त) {
		memset(response->public_कुञ्चिका, 0, response->public_कुञ्चिका_len);
		मुक्त(response->public_कुञ्चिका);
		response->public_कुञ्चिका = रिक्त;
	}
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	प्रत्यागम ret;
}
#endif /* WITH_OPENSSL */

स्थिर पूर्णाङ्क
pack_public_कुञ्चिका_ed25519(ध्रुव fido_cred_t *cred,
    संरचना sk_enroll_response *response)
{
	ध्रुव uint8_t *ptr;
	size_t len;
	पूर्णाङ्क ret = -1;

	response->public_कुञ्चिका = रिक्त;
	response->public_कुञ्चिका_len = 0;

	जइ ((len = fido_cred_pubkey_len(cred)) != 32) {
		skdebug(__func__, "bad fido_cred_pubkey_len len %zu", len);
		गच्छ out;
	}
	जइ ((ptr = fido_cred_pubkey_ptr(cred)) == रिक्त) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		गच्छ out;
	}
	response->public_कुञ्चिका_len = len;
	जइ ((response->public_कुञ्चिका = malloc(response->public_कुञ्चिका_len)) == रिक्त) {
		skdebug(__func__, "malloc pubkey failed");
		गच्छ out;
	}
	memcpy(response->public_कुञ्चिका, ptr, len);
	ret = 0;
 out:
	जइ (ret != 0)
		मुक्त(response->public_कुञ्चिका);
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
pack_public_कुञ्चिका(uint32_t alg, ध्रुव fido_cred_t *cred,
    संरचना sk_enroll_response *response)
{
	विकल्प(alg) {
#ifdef WITH_OPENSSL
	पक्ष SSH_SK_ECDSA:
		प्रत्यागम pack_public_कुञ्चिका_ecdsa(cred, response);
#endif /* WITH_OPENSSL */
	पक्ष SSH_SK_ED25519:
		प्रत्यागम pack_public_कुञ्चिका_ed25519(cred, response);
	स्वभाव:
		प्रत्यागम -1;
	}
}

स्थिर पूर्णाङ्क
fidoerr_to_skerr(पूर्णाङ्क fidoerr)
{
	विकल्प (fidoerr) {
	पक्ष FIDO_ERR_UNSUPPORTED_OPTION:
	पक्ष FIDO_ERR_UNSUPPORTED_ALGORITHM:
		प्रत्यागम SSH_SK_ERR_UNSUPPORTED;
	पक्ष FIDO_ERR_PIN_REQUIRED:
	पक्ष FIDO_ERR_PIN_INVALID:
	पक्ष FIDO_ERR_OPERATION_DENIED:
		प्रत्यागम SSH_SK_ERR_PIN_REQUIRED;
	स्वभाव:
		प्रत्यागम -1;
	}
}

स्थिर पूर्णाङ्क
check_enroll_options(संरचना sk_option **options, वर्ण **devicep,
    uint8_t *user_id, size_t user_id_len)
{
	size_t i;

	जइ (options == रिक्त)
		प्रत्यागम 0;
	प्रति (i = 0; options[i] != रिक्त; i++) {
		जइ (strcmp(options[i]->name, "device") == 0) {
			जइ ((*devicep = strdup(options[i]->मानम्)) == रिक्त) {
				skdebug(__func__, "strdup device failed");
				प्रत्यागम -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} अण्णहा जइ (strcmp(options[i]->name, "user") == 0) {
			जइ (strlcpy(user_id, options[i]->मानम्, user_id_len) >=
			    user_id_len) {
				skdebug(__func__, "user too long");
				प्रत्यागम -1;
			}
			skdebug(__func__, "requested user %s",
			    (वर्ण *)user_id);
		} अण्णहा {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			जइ (options[i]->required) {
				skdebug(__func__, "unknown required option");
				प्रत्यागम -1;
			}
		}
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
कुञ्चिका_lookup(fido_dev_t *dev, ध्रुव वर्ण *application, ध्रुव uint8_t *user_id,
    size_t user_id_len, ध्रुव वर्ण *pin)
{
	fido_assert_t *प्रतिज्ञा = रिक्त;
	uint8_t message[32];
	पूर्णाङ्क r = FIDO_ERR_INTERNAL;
	पूर्णाङ्क sk_supports_uv, uv;
	size_t i;

	memset(message, '\0', परिमाण(message));
	जइ ((प्रतिज्ञा = fido_assert_new()) == रिक्त) {
		skdebug(__func__, "fido_assert_new failed");
		गच्छ out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	जइ ((r = fido_assert_set_clientdata(प्रतिज्ञा, message,
	    परिमाण(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		गच्छ out;
	}
	जइ ((r = fido_assert_set_rp(प्रतिज्ञा, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		गच्छ out;
	}
	जइ ((r = fido_assert_set_up(प्रतिज्ञा, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		गच्छ out;
	}
	uv = FIDO_OPT_OMIT;
	जइ (pin == रिक्त && check_sk_options(dev, "uv", &sk_supports_uv) == 0 &&
	    sk_supports_uv != -1)
		uv = FIDO_OPT_TRUE;
	जइ ((r = fido_assert_set_uv(प्रतिज्ञा, uv)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
		गच्छ out;
	}
	जइ ((r = fido_dev_get_assert(dev, प्रतिज्ञा, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		गच्छ out;
	}
	r = FIDO_ERR_NO_CREDENTIALS;
	skdebug(__func__, "%zu signatures returned", fido_assert_गणनम्(प्रतिज्ञा));
	प्रति (i = 0; i < fido_assert_गणनम्(प्रतिज्ञा); i++) {
		जइ (fido_assert_user_id_len(प्रतिज्ञा, i) == user_id_len &&
		    memcmp(fido_assert_user_id_ptr(प्रतिज्ञा, i), user_id,
		    user_id_len) == 0) {
			skdebug(__func__, "credential exists");
			r = FIDO_OK;
			गच्छ out;
		}
	}
 out:
	fido_assert_free(&प्रतिज्ञा);

	प्रत्यागम r;
}

पूर्णाङ्क
sk_enroll(uint32_t alg, ध्रुव uint8_t *challenge, size_t challenge_len,
    ध्रुव वर्ण *application, uint8_t flags, ध्रुव वर्ण *pin,
    संरचना sk_option **options, संरचना sk_enroll_response **enroll_response)
{
	fido_cred_t *cred = रिक्त;
	ध्रुव uint8_t *ptr;
	uint8_t user_id[32];
	संरचना sk_usbhid *sk = रिक्त;
	संरचना sk_enroll_response *response = रिक्त;
	size_t len;
	पूर्णाङ्क credprot;
	पूर्णाङ्क cose_alg;
	पूर्णाङ्क ret = SSH_SK_ERR_GENERAL;
	पूर्णाङ्क r;
	वर्ण *device = रिक्त;

	fido_init(SSH_FIDO_INIT_ARG);

	जइ (enroll_response == रिक्त) {
		skdebug(__func__, "enroll_response == NULL");
		गच्छ out;
	}
	*enroll_response = रिक्त;
	memset(user_id, 0, परिमाण(user_id));
	जइ (check_enroll_options(options, &device, user_id,
	    परिमाण(user_id)) != 0)
		गच्छ out; /* error already logged */

	विकल्प(alg) {
#ifdef WITH_OPENSSL
	पक्ष SSH_SK_ECDSA:
		cose_alg = COSE_ES256;
		भङ्ग;
#endif /* WITH_OPENSSL */
	पक्ष SSH_SK_ED25519:
		cose_alg = COSE_EDDSA;
		भङ्ग;
	स्वभाव:
		skdebug(__func__, "unsupported key type %d", alg);
		गच्छ out;
	}
	जइ (device != रिक्त)
		sk = sk_open(device);
	अण्णहा
		sk = sk_probe(रिक्त, रिक्त, 0, 0);
	जइ (sk == रिक्त) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		गच्छ out;
	}
	skdebug(__func__, "using device %s", sk->path);
	जइ ((flags & SSH_SK_RESIDENT_कुञ्चिका) != 0 &&
	    (flags & SSH_SK_FORCE_OPERATION) == 0 &&
	    (r = कुञ्चिका_lookup(sk->dev, application, user_id, परिमाण(user_id),
	    pin)) != FIDO_ERR_NO_CREDENTIALS) {
		जइ (r != FIDO_OK) {
			ret = fidoerr_to_skerr(r);
			skdebug(__func__, "key_lookup failed");
		} अण्णहा {
			ret = SSH_SK_ERR_CREDENTIAL_EXISTS;
			skdebug(__func__, "key exists");
		}
		गच्छ out;
	}
	जइ ((cred = fido_cred_new()) == रिक्त) {
		skdebug(__func__, "fido_cred_new failed");
		गच्छ out;
	}
	जइ ((r = fido_cred_set_type(cred, cose_alg)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_type: %s", fido_strerr(r));
		गच्छ out;
	}
	जइ ((r = fido_cred_set_clientdata(cred,
	    challenge, challenge_len)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata: %s",
		    fido_strerr(r));
		गच्छ out;
	}
	जइ ((r = fido_cred_set_rk(cred, (flags & SSH_SK_RESIDENT_कुञ्चिका) != 0 ?
	    FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rk: %s", fido_strerr(r));
		गच्छ out;
	}
	जइ ((r = fido_cred_set_user(cred, user_id, परिमाण(user_id),
	    "openssh", "openssh", रिक्त)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_user: %s", fido_strerr(r));
		गच्छ out;
	}
	जइ ((r = fido_cred_set_rp(cred, application, रिक्त)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rp: %s", fido_strerr(r));
		गच्छ out;
	}
	जइ ((flags & (SSH_SK_RESIDENT_कुञ्चिका|SSH_SK_USER_VERIFICATION_REQD)) != 0) {
#जइ !defined(HAVE_FIDO_DEV_SUPPORTS_CRED_PROT) || \
    !defined(HAVE_FIDO_CRED_SET_PROT)
		skdebug(__func__, "libfido2 version does not support a feature required for this operation. Please upgrade to >=1.5.0");
		ret = SSH_SK_ERR_UNSUPPORTED;
		गच्छ out;
		credprot = 0; (शून्य)credprot; /* avoid warning */
#endif
		जइ (!fido_dev_supports_cred_prot(sk->dev)) {
			skdebug(__func__, "%s does not support credprot, "
			    "refusing to create unprotected "
			    "resident/verify-required key", sk->path);
			ret = SSH_SK_ERR_UNSUPPORTED;
			गच्छ out;
		}
		जइ ((flags & SSH_SK_USER_VERIFICATION_REQD))
			credprot = FIDO_CRED_PROT_UV_REQUIRED;
		अण्णहा
			credprot = FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID;

		जइ ((r = fido_cred_set_prot(cred, credprot)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_set_prot: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			गच्छ out;
		}
	}
	जइ ((r = fido_dev_make_cred(sk->dev, cred, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_make_cred: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		गच्छ out;
	}
	जइ (fido_cred_x5c_ptr(cred) != रिक्त) {
		जइ ((r = fido_cred_verify(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify: %s",
			    fido_strerr(r));
			गच्छ out;
		}
	} अण्णहा जइ (strcmp(fido_cred_fmt(cred), "none") != 0) {
		skdebug(__func__, "self-attested credential");
		जइ ((r = fido_cred_verify_self(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify_self: %s",
			    fido_strerr(r));
			गच्छ out;
		}
	} अण्णहा {
		skdebug(__func__, "no attestation data");
	}
	जइ ((response = calloc(1, परिमाण(*response))) == रिक्त) {
		skdebug(__func__, "calloc response failed");
		गच्छ out;
	}
	response->flags = flags;
	जइ (pack_public_कुञ्चिका(alg, cred, response) != 0) {
		skdebug(__func__, "pack_public_key failed");
		गच्छ out;
	}
	जइ ((ptr = fido_cred_id_ptr(cred)) != रिक्त) {
		len = fido_cred_id_len(cred);
		जइ ((response->कुञ्चिका_handle = calloc(1, len)) == रिक्त) {
			skdebug(__func__, "calloc key handle failed");
			गच्छ out;
		}
		memcpy(response->कुञ्चिका_handle, ptr, len);
		response->कुञ्चिका_handle_len = len;
	}
	जइ ((ptr = fido_cred_sig_ptr(cred)) != रिक्त) {
		len = fido_cred_sig_len(cred);
		जइ ((response->signature = calloc(1, len)) == रिक्त) {
			skdebug(__func__, "calloc signature failed");
			गच्छ out;
		}
		memcpy(response->signature, ptr, len);
		response->signature_len = len;
	}
	जइ ((ptr = fido_cred_x5c_ptr(cred)) != रिक्त) {
		len = fido_cred_x5c_len(cred);
		skdebug(__func__, "attestation cert len=%zu", len);
		जइ ((response->attestation_cert = calloc(1, len)) == रिक्त) {
			skdebug(__func__, "calloc attestation cert failed");
			गच्छ out;
		}
		memcpy(response->attestation_cert, ptr, len);
		response->attestation_cert_len = len;
	}
	जइ ((ptr = fido_cred_authdata_ptr(cred)) != रिक्त) {
		len = fido_cred_authdata_len(cred);
		skdebug(__func__, "authdata len=%zu", len);
		जइ ((response->authdata = calloc(1, len)) == रिक्त) {
			skdebug(__func__, "calloc authdata failed");
			गच्छ out;
		}
		memcpy(response->authdata, ptr, len);
		response->authdata_len = len;
	}
	*enroll_response = response;
	response = रिक्त;
	ret = 0;
 out:
	मुक्त(device);
	जइ (response != रिक्त) {
		मुक्त(response->public_कुञ्चिका);
		मुक्त(response->कुञ्चिका_handle);
		मुक्त(response->signature);
		मुक्त(response->attestation_cert);
		मुक्त(response->authdata);
		मुक्त(response);
	}
	sk_close(sk);
	fido_cred_free(&cred);
	प्रत्यागम ret;
}

#ifdef WITH_OPENSSL
स्थिर पूर्णाङ्क
pack_sig_ecdsa(fido_assert_t *प्रतिज्ञा, संरचना sk_sign_response *response)
{
	ECDSA_SIG *sig = रिक्त;
	ध्रुव BIGNUM *sig_r, *sig_s;
	ध्रुव unsigned वर्ण *cp;
	size_t sig_len;
	पूर्णाङ्क ret = -1;

	cp = fido_assert_sig_ptr(प्रतिज्ञा, 0);
	sig_len = fido_assert_sig_len(प्रतिज्ञा, 0);
	जइ ((sig = d2i_ECDSA_SIG(रिक्त, &cp, sig_len)) == रिक्त) {
		skdebug(__func__, "d2i_ECDSA_SIG failed");
		गच्छ out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_अङ्कः_bytes(sig_r);
	response->sig_s_len = BN_अङ्कः_bytes(sig_s);
	जइ ((response->sig_r = calloc(1, response->sig_r_len)) == रिक्त ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == रिक्त) {
		skdebug(__func__, "calloc signature failed");
		गच्छ out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	ECDSA_SIG_free(sig);
	जइ (ret != 0) {
		मुक्त(response->sig_r);
		मुक्त(response->sig_s);
		response->sig_r = रिक्त;
		response->sig_s = रिक्त;
	}
	प्रत्यागम ret;
}
#endif /* WITH_OPENSSL */

स्थिर पूर्णाङ्क
pack_sig_ed25519(fido_assert_t *प्रतिज्ञा, संरचना sk_sign_response *response)
{
	ध्रुव unsigned वर्ण *ptr;
	size_t len;
	पूर्णाङ्क ret = -1;

	ptr = fido_assert_sig_ptr(प्रतिज्ञा, 0);
	len = fido_assert_sig_len(प्रतिज्ञा, 0);
	जइ (len != 64) {
		skdebug(__func__, "bad length %zu", len);
		गच्छ out;
	}
	response->sig_r_len = len;
	जइ ((response->sig_r = calloc(1, response->sig_r_len)) == रिक्त) {
		skdebug(__func__, "calloc signature failed");
		गच्छ out;
	}
	memcpy(response->sig_r, ptr, len);
	ret = 0;
 out:
	जइ (ret != 0) {
		मुक्त(response->sig_r);
		response->sig_r = रिक्त;
	}
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
pack_sig(uint32_t  alg, fido_assert_t *प्रतिज्ञा,
    संरचना sk_sign_response *response)
{
	विकल्प(alg) {
#ifdef WITH_OPENSSL
	पक्ष SSH_SK_ECDSA:
		प्रत्यागम pack_sig_ecdsa(प्रतिज्ञा, response);
#endif /* WITH_OPENSSL */
	पक्ष SSH_SK_ED25519:
		प्रत्यागम pack_sig_ed25519(प्रतिज्ञा, response);
	स्वभाव:
		प्रत्यागम -1;
	}
}

/* Checks sk_options for sk_sign() and sk_load_resident_keys() */
स्थिर पूर्णाङ्क
check_sign_load_resident_options(संरचना sk_option **options, वर्ण **devicep)
{
	size_t i;

	जइ (options == रिक्त)
		प्रत्यागम 0;
	प्रति (i = 0; options[i] != रिक्त; i++) {
		जइ (strcmp(options[i]->name, "device") == 0) {
			जइ ((*devicep = strdup(options[i]->मानम्)) == रिक्त) {
				skdebug(__func__, "strdup device failed");
				प्रत्यागम -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} अण्णहा {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			जइ (options[i]->required) {
				skdebug(__func__, "unknown required option");
				प्रत्यागम -1;
			}
		}
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
sk_sign(uint32_t alg, ध्रुव uint8_t *data, size_t datalen,
    ध्रुव वर्ण *application,
    ध्रुव uint8_t *कुञ्चिका_handle, size_t कुञ्चिका_handle_len,
    uint8_t flags, ध्रुव वर्ण *pin, संरचना sk_option **options,
    संरचना sk_sign_response **sign_response)
{
	fido_assert_t *प्रतिज्ञा = रिक्त;
	वर्ण *device = रिक्त;
	संरचना sk_usbhid *sk = रिक्त;
	संरचना sk_sign_response *response = रिक्त;
	पूर्णाङ्क ret = SSH_SK_ERR_GENERAL, internal_uv;
	पूर्णाङ्क r;

	fido_init(SSH_FIDO_INIT_ARG);

	जइ (sign_response == रिक्त) {
		skdebug(__func__, "sign_response == NULL");
		गच्छ out;
	}
	*sign_response = रिक्त;
	जइ (check_sign_load_resident_options(options, &device) != 0)
		गच्छ out; /* error already logged */
	जइ (device != रिक्त)
		sk = sk_open(device);
	अण्णहा जइ (pin != रिक्त || (flags & SSH_SK_USER_VERIFICATION_REQD))
		sk = sk_probe(रिक्त, रिक्त, 0, 0);
	अण्णहा
		sk = sk_probe(application, कुञ्चिका_handle, कुञ्चिका_handle_len, 0);
	जइ (sk == रिक्त) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		गच्छ out;
	}
	जइ ((प्रतिज्ञा = fido_assert_new()) == रिक्त) {
		skdebug(__func__, "fido_assert_new failed");
		गच्छ out;
	}
	जइ ((r = fido_assert_set_clientdata(प्रतिज्ञा,
	    data, datalen)) != FIDO_OK)  {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		गच्छ out;
	}
	जइ ((r = fido_assert_set_rp(प्रतिज्ञा, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		गच्छ out;
	}
	जइ ((r = fido_assert_allow_cred(प्रतिज्ञा, कुञ्चिका_handle,
	    कुञ्चिका_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		गच्छ out;
	}
	जइ ((r = fido_assert_set_up(प्रतिज्ञा,
	    (flags & SSH_SK_USER_PRESENCE_REQD) ?
	    FIDO_OPT_TRUE : FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		गच्छ out;
	}
	/*
	 * WinHello requests the PIN by default.  Make "uv" request explicit
	 * to allow keys with and without -O verify-required to make sense.
	 */
	जइ (pin == रिक्त && fido_dev_is_winhello (sk->dev) &&
	    (r = fido_assert_set_uv(प्रतिज्ञा, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
	}
	जइ (pin == रिक्त && (flags & SSH_SK_USER_VERIFICATION_REQD)) {
		जइ (check_sk_options(sk->dev, "uv", &internal_uv) < 0 ||
		    internal_uv != 1) {
			skdebug(__func__, "check_sk_options uv");
			ret = SSH_SK_ERR_PIN_REQUIRED;
			गच्छ out;
		}
		जइ ((r = fido_assert_set_uv(प्रतिज्ञा,
		    FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_assert_set_uv: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			गच्छ out;
		}
	}
	जइ ((r = fido_dev_get_assert(sk->dev, प्रतिज्ञा, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		गच्छ out;
	}
	जइ ((response = calloc(1, परिमाण(*response))) == रिक्त) {
		skdebug(__func__, "calloc response failed");
		गच्छ out;
	}
	response->flags = fido_assert_flags(प्रतिज्ञा, 0);
	response->counter = fido_assert_sigcount(प्रतिज्ञा, 0);
	जइ (pack_sig(alg, प्रतिज्ञा, response) != 0) {
		skdebug(__func__, "pack_sig failed");
		गच्छ out;
	}
	*sign_response = response;
	response = रिक्त;
	ret = 0;
 out:
	मुक्त(device);
	जइ (response != रिक्त) {
		मुक्त(response->sig_r);
		मुक्त(response->sig_s);
		मुक्त(response);
	}
	sk_close(sk);
	fido_assert_free(&प्रतिज्ञा);
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
read_rks(संरचना sk_usbhid *sk, ध्रुव वर्ण *pin,
    संरचना sk_resident_कुञ्चिका ***rksp, size_t *nrksp)
{
	पूर्णाङ्क ret = SSH_SK_ERR_GENERAL, r = -1;
	uint32_t alg;
	fido_credman_metadata_t *metadata = रिक्त;
	fido_credman_rp_t *rp = रिक्त;
	fido_credman_rk_t *rk = रिक्त;
	size_t i, j, nrp, nrk, user_id_len;
	ध्रुव fido_cred_t *cred;
	ध्रुव वर्ण *rp_id, *rp_name, *user_name;
	संरचना sk_resident_कुञ्चिका *srk = रिक्त, **tmp;
	ध्रुव u_char *user_id;

	जइ (pin == रिक्त) {
		skdebug(__func__, "no PIN specified");
		ret = SSH_SK_ERR_PIN_REQUIRED;
		गच्छ out;
	}
	जइ ((metadata = fido_credman_metadata_new()) == रिक्त) {
		skdebug(__func__, "alloc failed");
		गच्छ out;
	}
	जइ ((r = fido_credman_get_dev_metadata(sk->dev, metadata, pin)) != 0) {
		जइ (r == FIDO_ERR_INVALID_COMMAND) {
			skdebug(__func__, "device %s does not support "
			    "resident keys", sk->path);
			ret = 0;
			गच्छ out;
		}
		skdebug(__func__, "get metadata for %s failed: %s",
		    sk->path, fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		गच्छ out;
	}
	skdebug(__func__, "existing %llu, remaining %llu",
	    (unsigned long long)fido_credman_rk_existing(metadata),
	    (unsigned long long)fido_credman_rk_remaining(metadata));
	जइ ((rp = fido_credman_rp_new()) == रिक्त) {
		skdebug(__func__, "alloc rp failed");
		गच्छ out;
	}
	जइ ((r = fido_credman_get_dev_rp(sk->dev, rp, pin)) != 0) {
		skdebug(__func__, "get RPs for %s failed: %s",
		    sk->path, fido_strerr(r));
		गच्छ out;
	}
	nrp = fido_credman_rp_गणनम्(rp);
	skdebug(__func__, "Device %s has resident keys for %zu RPs",
	    sk->path, nrp);

	/* Iterate over RP IDs that have resident keys */
	प्रति (i = 0; i < nrp; i++) {
		rp_id = fido_credman_rp_id(rp, i);
		rp_name = fido_credman_rp_name(rp, i);
		skdebug(__func__, "rp %zu: name=\"%s\" id=\"%s\" hashlen=%zu",
		    i, rp_name == रिक्त ? "(none)" : rp_name,
		    rp_id == रिक्त ? "(none)" : rp_id,
		    fido_credman_rp_id_hash_len(rp, i));

		/* Skip non-SSH RP IDs */
		जइ (rp_id == रिक्त ||
		    strncasecmp(fido_credman_rp_id(rp, i), "ssh:", 4) != 0)
			अनुवर्त;

		fido_credman_rk_free(&rk);
		जइ ((rk = fido_credman_rk_new()) == रिक्त) {
			skdebug(__func__, "alloc rk failed");
			गच्छ out;
		}
		जइ ((r = fido_credman_get_dev_rk(sk->dev,
		    fido_credman_rp_id(rp, i), rk, pin)) != 0) {
			skdebug(__func__, "get RKs for %s slot %zu failed: %s",
			    sk->path, i, fido_strerr(r));
			गच्छ out;
		}
		nrk = fido_credman_rk_गणनम्(rk);
		skdebug(__func__, "RP \"%s\" has %zu resident keys",
		    fido_credman_rp_id(rp, i), nrk);

		/* Iterate over resident keys for this RP ID */
		प्रति (j = 0; j < nrk; j++) {
			जइ ((cred = fido_credman_rk(rk, j)) == रिक्त) {
				skdebug(__func__, "no RK in slot %zu", j);
				अनुवर्त;
			}
			जइ ((user_name = fido_cred_user_name(cred)) == रिक्त)
				user_name = "";
			user_id = fido_cred_user_id_ptr(cred);
			user_id_len = fido_cred_user_id_len(cred);
			skdebug(__func__, "Device %s RP \"%s\" user \"%s\" "
			    "uidlen %zu slot %zu: type %d flags 0x%02x "
			    "prot 0x%02x", sk->path, rp_id, user_name,
			    user_id_len, j, fido_cred_type(cred),
			    fido_cred_flags(cred), fido_cred_prot(cred));

			/* Determine key algorithm */
			विकल्प (fido_cred_type(cred)) {
			पक्ष COSE_ES256:
				alg = SSH_SK_ECDSA;
				भङ्ग;
			पक्ष COSE_EDDSA:
				alg = SSH_SK_ED25519;
				भङ्ग;
			स्वभाव:
				skdebug(__func__, "unsupported key type %d",
				    fido_cred_type(cred));
				अनुवर्त;
			}

			/* build response entry */
			जइ ((srk = calloc(1, परिमाण(*srk))) == रिक्त ||
			    (srk->कुञ्चिका.कुञ्चिका_handle = calloc(1,
			    fido_cred_id_len(cred))) == रिक्त ||
			    (srk->application = strdup(rp_id)) == रिक्त ||
			    (user_id_len > 0 &&
			     (srk->user_id = calloc(1, user_id_len)) == रिक्त)) {
				skdebug(__func__, "alloc sk_resident_key");
				गच्छ out;
			}

			srk->alg = alg;
			srk->कुञ्चिका.कुञ्चिका_handle_len = fido_cred_id_len(cred);
			memcpy(srk->कुञ्चिका.कुञ्चिका_handle, fido_cred_id_ptr(cred),
			    srk->कुञ्चिका.कुञ्चिका_handle_len);
			srk->user_id_len = user_id_len;
			जइ (srk->user_id_len != 0)
				memcpy(srk->user_id, user_id, srk->user_id_len);

#ifdef HAVE_FIDO_CRED_PROT
			जइ (fido_cred_prot(cred) ==
			    FIDO_CRED_PROT_UV_REQUIRED)
				srk->flags |=  SSH_SK_USER_VERIFICATION_REQD;
#endif

			जइ ((r = pack_public_कुञ्चिका(srk->alg, cred,
			    &srk->कुञ्चिका)) != 0) {
				skdebug(__func__, "pack public key failed");
				गच्छ out;
			}
			/* append */
			जइ ((tmp = recallocarray(*rksp, *nrksp, (*nrksp) + 1,
			    परिमाण(**rksp))) == रिक्त) {
				skdebug(__func__, "alloc rksp");
				गच्छ out;
			}
			*rksp = tmp;
			(*rksp)[(*nrksp)++] = srk;
			srk = रिक्त;
		}
	}
	/* Success */
	ret = 0;
 out:
	जइ (srk != रिक्त) {
		मुक्त(srk->application);
		freezero(srk->कुञ्चिका.public_कुञ्चिका, srk->कुञ्चिका.public_कुञ्चिका_len);
		freezero(srk->कुञ्चिका.कुञ्चिका_handle, srk->कुञ्चिका.कुञ्चिका_handle_len);
		freezero(srk->user_id, srk->user_id_len);
		freezero(srk, परिमाण(*srk));
	}
	fido_credman_rp_free(&rp);
	fido_credman_rk_free(&rk);
	fido_credman_metadata_free(&metadata);
	प्रत्यागम ret;
}

पूर्णाङ्क
sk_load_resident_कुञ्चिकाः(ध्रुव वर्ण *pin, संरचना sk_option **options,
    संरचना sk_resident_कुञ्चिका ***rksp, size_t *nrksp)
{
	पूर्णाङ्क ret = SSH_SK_ERR_GENERAL, r = -1;
	size_t i, nrks = 0;
	संरचना sk_resident_कुञ्चिका **rks = रिक्त;
	संरचना sk_usbhid *sk = रिक्त;
	वर्ण *device = रिक्त;

	*rksp = रिक्त;
	*nrksp = 0;

	fido_init(SSH_FIDO_INIT_ARG);

	जइ (check_sign_load_resident_options(options, &device) != 0)
		गच्छ out; /* error already logged */
	जइ (device != रिक्त)
		sk = sk_open(device);
	अण्णहा
		sk = sk_probe(रिक्त, रिक्त, 0, 1);
	जइ (sk == रिक्त) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		गच्छ out;
	}
	skdebug(__func__, "trying %s", sk->path);
	जइ ((r = read_rks(sk, pin, &rks, &nrks)) != 0) {
		skdebug(__func__, "read_rks failed for %s", sk->path);
		ret = r;
		गच्छ out;
	}
	/* success, unless we have no keys but a specific error */
	जइ (nrks > 0 || ret == SSH_SK_ERR_GENERAL)
		ret = 0;
	*rksp = rks;
	*nrksp = nrks;
	rks = रिक्त;
	nrks = 0;
 out:
	sk_close(sk);
	प्रति (i = 0; i < nrks; i++) {
		मुक्त(rks[i]->application);
		freezero(rks[i]->कुञ्चिका.public_कुञ्चिका, rks[i]->कुञ्चिका.public_कुञ्चिका_len);
		freezero(rks[i]->कुञ्चिका.कुञ्चिका_handle, rks[i]->कुञ्चिका.कुञ्चिका_handle_len);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i], परिमाण(*rks[i]));
	}
	मुक्त(device);
	मुक्त(rks);
	प्रत्यागम ret;
}

#endif /* ENABLE_SK_INTERNAL */
