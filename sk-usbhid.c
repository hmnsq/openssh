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
# define sk_load_resident_साँचोहरू	ssh_sk_load_resident_साँचोहरू
#endif /* !SK_STANDALONE */

#अन्तर्भाव "sk-api.h"

/* #define SK_DEBUG 1 */

#ifdef SK_DEBUG
#define SSH_FIDO_INIT_ARG	FIDO_DEBUG
#अन्यथा
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
पूर्णाङ्क sk_enroll(uint32_t alg, अचर uint8_t *challenge, माप_प्रकार challenge_len,
    अचर वर्ण *application, uint8_t flags, अचर वर्ण *pin,
    संरचना sk_option **options, संरचना sk_enroll_response **enroll_response);

/* Sign a challenge */
पूर्णाङ्क sk_sign(uint32_t alg, अचर uint8_t *data, माप_प्रकार data_len,
    अचर वर्ण *application, अचर uint8_t *साँचो_handle, माप_प्रकार साँचो_handle_len,
    uint8_t flags, अचर वर्ण *pin, संरचना sk_option **options,
    संरचना sk_sign_response **sign_response);

/* Load resident keys */
पूर्णाङ्क sk_load_resident_साँचोहरू(अचर वर्ण *pin, संरचना sk_option **options,
    संरचना sk_resident_साँचो ***rks, माप_प्रकार *nrks);

स्थिर शून्य skdebug(अचर वर्ण *func, अचर वर्ण *fmt, ...)
    __attribute__((__format__ (म_लिखो, 2, 3)));

स्थिर शून्य
skdebug(अचर वर्ण *func, अचर वर्ण *fmt, ...)
{
#यदि !defined(SK_STANDALONE)
	वर्ण *सन्देश;
	बहु_सूची ap;

	बहु_शुरू(ap, fmt);
	xvasprintf(&सन्देश, fmt, ap);
	बहु_पूर्ण(ap);
	debug("%s: %s", func, सन्देश);
	मुक्त(सन्देश);
#अथवायदि defined(SK_DEBUG)
	बहु_सूची ap;

	बहु_शुरू(ap, fmt);
	ख_लिखो(मानक_त्रुटि, "%s: ", func);
	भख_लिखो(मानक_त्रुटि, fmt, ap);
	ख_अक्षर_दो('\n', मानक_त्रुटि);
	बहु_पूर्ण(ap);
#अन्यथा
	(शून्य)func; /* XXX */
	(शून्य)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(शून्य)
{
	फर्काऊ SSH_SK_VERSION_MAJOR;
}

स्थिर संरचना sk_usbhid *
sk_open(अचर वर्ण *path)
{
	संरचना sk_usbhid *sk;
	पूर्णाङ्क r;

	यदि (path == रिक्त) {
		skdebug(__func__, "path == NULL");
		फर्काऊ रिक्त;
	}
	यदि ((sk = सुस्मृति(1, परिमाण(*sk))) == रिक्त) {
		skdebug(__func__, "calloc sk failed");
		फर्काऊ रिक्त;
	}
	यदि ((sk->path = strdup(path)) == रिक्त) {
		skdebug(__func__, "strdup path failed");
		मुक्त(sk);
		फर्काऊ रिक्त;
	}
	यदि ((sk->dev = fido_dev_new()) == रिक्त) {
		skdebug(__func__, "fido_dev_new failed");
		मुक्त(sk->path);
		मुक्त(sk);
		फर्काऊ रिक्त;
	}
	यदि ((r = fido_dev_open(sk->dev, sk->path)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_open %s failed: %s", sk->path,
		    fido_strerr(r));
		fido_dev_free(&sk->dev);
		मुक्त(sk->path);
		मुक्त(sk);
		फर्काऊ रिक्त;
	}
	फर्काऊ sk;
}

स्थिर शून्य
sk_close(संरचना sk_usbhid *sk)
{
	यदि (sk == रिक्त)
		फर्काऊ;
	fido_dev_cancel(sk->dev); /* cancel any pending operation */
	fido_dev_close(sk->dev);
	fido_dev_free(&sk->dev);
	मुक्त(sk->path);
	मुक्त(sk);
}

स्थिर संरचना sk_usbhid **
sk_openv(अचर fido_dev_info_t *devlist, माप_प्रकार ndevs, माप_प्रकार *nopen)
{
	अचर fido_dev_info_t *di;
	संरचना sk_usbhid **skv;
	माप_प्रकार i;

	*nopen = 0;
	यदि ((skv = सुस्मृति(ndevs, परिमाण(*skv))) == रिक्त) {
		skdebug(__func__, "calloc skv failed");
		फर्काऊ रिक्त;
	}
	लागि (i = 0; i < ndevs; i++) {
		यदि ((di = fido_dev_info_ptr(devlist, i)) == रिक्त)
			skdebug(__func__, "fido_dev_info_ptr failed");
		अन्यथा यदि ((skv[*nopen] = sk_open(fido_dev_info_path(di))) == रिक्त)
			skdebug(__func__, "sk_open failed");
		अन्यथा
			(*nopen)++;
	}
	यदि (*nopen == 0) {
		लागि (i = 0; i < ndevs; i++)
			sk_close(skv[i]);
		मुक्त(skv);
		skv = रिक्त;
	}

	फर्काऊ skv;
}

स्थिर शून्य
sk_closev(संरचना sk_usbhid **skv, माप_प्रकार nsk)
{
	माप_प्रकार i;

	लागि (i = 0; i < nsk; i++)
		sk_close(skv[i]);
	मुक्त(skv);
}

स्थिर पूर्णाङ्क
sk_touch_begin(संरचना sk_usbhid **skv, माप_प्रकार nsk)
{
	माप_प्रकार i, ok = 0;
	पूर्णाङ्क r;

	लागि (i = 0; i < nsk; i++)
		यदि ((r = fido_dev_get_touch_begin(skv[i]->dev)) != FIDO_OK)
			skdebug(__func__, "fido_dev_get_touch_begin %s failed:"
			    " %s", skv[i]->path, fido_strerr(r));
		अन्यथा
			ok++;

	फर्काऊ ok ? 0 : -1;
}

स्थिर पूर्णाङ्क
sk_touch_poll(संरचना sk_usbhid **skv, माप_प्रकार nsk, पूर्णाङ्क *touch, माप_प्रकार *idx)
{
	संरचना timespec ts_pause;
	माप_प्रकार npoll, i;
	पूर्णाङ्क r;

	ts_pause.tv_sec = 0;
	ts_pause.tv_nsec = POLL_SLEEP_NS;
	nanosleep(&ts_pause, रिक्त);
	npoll = nsk;
	लागि (i = 0; i < nsk; i++) {
		यदि (skv[i] == रिक्त)
			जारी; /* device discarded */
		skdebug(__func__, "polling %s", skv[i]->path);
		यदि ((r = fido_dev_get_touch_status(skv[i]->dev, touch,
		    FIDO_POLL_MS)) != FIDO_OK) {
			skdebug(__func__, "fido_dev_get_touch_status %s: %s",
			    skv[i]->path, fido_strerr(r));
			sk_close(skv[i]); /* discard device */
			skv[i] = रिक्त;
			यदि (--npoll == 0) {
				skdebug(__func__, "no device left to poll");
				फर्काऊ -1;
			}
		} अन्यथा यदि (*touch) {
			*idx = i;
			फर्काऊ 0;
		}
	}
	*touch = 0;
	फर्काऊ 0;
}

#यदि !defined(HAVE_FIDO_ASSERT_SET_CLIENTDATA) || \
    !defined(HAVE_FIDO_CRED_SET_CLIENTDATA)
/* Calculate SHA256(m) */
स्थिर पूर्णाङ्क
sha256_mem(अचर शून्य *m, माप_प्रकार mlen, u_char *d, माप_प्रकार dlen)
{
#ifdef WITH_OPENSSL
	u_int mdlen;
#अन्यथा
	SHA2_CTX ctx;
#endif

	यदि (dlen != 32)
		फर्काऊ -1;
#ifdef WITH_OPENSSL
	mdlen = dlen;
	यदि (!EVP_Digest(m, mlen, d, &mdlen, EVP_sha256(), रिक्त))
		फर्काऊ -1;
#अन्यथा
	SHA256Init(&ctx);
	SHA256Update(&ctx, (अचर uint8_t *)m, mlen);
	SHA256Final(d, &ctx);
#endif
	फर्काऊ 0;
}
#endif /* !HAVE_FIDO_ASSERT_SET_CLIENTDATA || !HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_CRED_SET_CLIENTDATA
स्थिर पूर्णाङ्क
fido_cred_set_clientdata(fido_cred_t *cred, अचर u_char *ptr, माप_प्रकार len)
{
	uint8_t d[32];
	पूर्णाङ्क r;

	यदि (sha256_mem(ptr, len, d, परिमाण(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		फर्काऊ FIDO_ERR_INTERNAL;
	}
	r = fido_cred_set_clientdata_hash(cred, d, परिमाण(d));
	explicit_bzero(d, परिमाण(d));
	यदि (r != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	फर्काऊ r;
}
#endif /* HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_ASSERT_SET_CLIENTDATA
स्थिर पूर्णाङ्क
fido_assert_set_clientdata(fido_assert_t *प्रतिज्ञा, अचर u_char *ptr, माप_प्रकार len)
{
	uint8_t d[32];
	पूर्णाङ्क r;

	यदि (sha256_mem(ptr, len, d, परिमाण(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		फर्काऊ FIDO_ERR_INTERNAL;
	}
	r = fido_assert_set_clientdata_hash(प्रतिज्ञा, d, परिमाण(d));
	explicit_bzero(d, परिमाण(d));
	यदि (r != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	फर्काऊ r;
}
#endif /* HAVE_FIDO_ASSERT_SET_CLIENTDATA */

#ifndef HAVE_FIDO_DEV_IS_WINHELLO
स्थिर bool
fido_dev_is_winhello(अचर fido_dev_t *fdev)
{
	फर्काऊ 0;
}
#endif /* HAVE_FIDO_DEV_IS_WINHELLO */

/* Check if the specified key handle exists on a given sk. */
स्थिर पूर्णाङ्क
sk_try(अचर संरचना sk_usbhid *sk, अचर वर्ण *application,
    अचर uint8_t *साँचो_handle, माप_प्रकार साँचो_handle_len)
{
	fido_assert_t *प्रतिज्ञा = रिक्त;
	पूर्णाङ्क r = FIDO_ERR_INTERNAL;
	uint8_t message[32];

	स_रखो(message, '\0', परिमाण(message));
	यदि ((प्रतिज्ञा = fido_assert_new()) == रिक्त) {
		skdebug(__func__, "fido_assert_new failed");
		गच्छ out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	यदि ((r = fido_assert_set_clientdata(प्रतिज्ञा, message,
	    परिमाण(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		गच्छ out;
	}
	यदि ((r = fido_assert_set_rp(प्रतिज्ञा, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		गच्छ out;
	}
	यदि ((r = fido_assert_allow_cred(प्रतिज्ञा, साँचो_handle,
	    साँचो_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		गच्छ out;
	}
	यदि ((r = fido_assert_set_up(प्रतिज्ञा, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_up: %s", fido_strerr(r));
		गच्छ out;
	}
	r = fido_dev_get_assert(sk->dev, प्रतिज्ञा, रिक्त);
	skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
	यदि (r == FIDO_ERR_USER_PRESENCE_REQUIRED) {
		/* U2F tokens may return this */
		r = FIDO_OK;
	}
 out:
	fido_assert_free(&प्रतिज्ञा);

	फर्काऊ r != FIDO_OK ? -1 : 0;
}

स्थिर पूर्णाङ्क
check_sk_options(fido_dev_t *dev, अचर वर्ण *opt, पूर्णाङ्क *ret)
{
	fido_cbor_info_t *info;
	वर्ण * अचर *name;
	अचर bool *मान;
	माप_प्रकार len, i;
	पूर्णाङ्क r;

	*ret = -1;

	यदि (!fido_dev_is_fido2(dev)) {
		skdebug(__func__, "device is not fido2");
		फर्काऊ 0;
	}
	यदि ((info = fido_cbor_info_new()) == रिक्त) {
		skdebug(__func__, "fido_cbor_info_new failed");
		फर्काऊ -1;
	}
	यदि ((r = fido_dev_get_cbor_info(dev, info)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_cbor_info: %s", fido_strerr(r));
		fido_cbor_info_free(&info);
		फर्काऊ -1;
	}
	name = fido_cbor_info_options_name_ptr(info);
	मान = fido_cbor_info_options_मान_ptr(info);
	len = fido_cbor_info_options_len(info);
	लागि (i = 0; i < len; i++) {
		यदि (!म_भेद(name[i], opt)) {
			*ret = मान[i];
			रोक;
		}
	}
	fido_cbor_info_free(&info);
	यदि (*ret == -1)
		skdebug(__func__, "option %s is unknown", opt);
	अन्यथा
		skdebug(__func__, "option %s is %s", opt, *ret ? "on" : "off");

	फर्काऊ 0;
}

स्थिर संरचना sk_usbhid *
sk_select_by_cred(अचर fido_dev_info_t *devlist, माप_प्रकार ndevs,
    अचर वर्ण *application, अचर uint8_t *साँचो_handle, माप_प्रकार साँचो_handle_len)
{
	संरचना sk_usbhid **skv, *sk;
	माप_प्रकार skvcnt, i;
	पूर्णाङ्क internal_uv;

	यदि ((skv = sk_openv(devlist, ndevs, &skvcnt)) == रिक्त) {
		skdebug(__func__, "sk_openv failed");
		फर्काऊ रिक्त;
	}
	यदि (skvcnt == 1 && check_sk_options(skv[0]->dev, "uv",
	    &internal_uv) == 0 && internal_uv != -1) {
		sk = skv[0];
		skv[0] = रिक्त;
		गच्छ out;
	}
	sk = रिक्त;
	लागि (i = 0; i < skvcnt; i++) {
		यदि (sk_try(skv[i], application, साँचो_handle,
		    साँचो_handle_len) == 0) {
			sk = skv[i];
			skv[i] = रिक्त;
			skdebug(__func__, "found key in %s", sk->path);
			रोक;
		}
	}
 out:
	sk_closev(skv, skvcnt);
	फर्काऊ sk;
}

स्थिर संरचना sk_usbhid *
sk_select_by_touch(अचर fido_dev_info_t *devlist, माप_प्रकार ndevs)
{
	संरचना sk_usbhid **skv, *sk;
	संरचना timeval tv_start, tv_now, tv_delta;
	माप_प्रकार skvcnt, idx;
	पूर्णाङ्क touch, ms_remain;

	यदि ((skv = sk_openv(devlist, ndevs, &skvcnt)) == रिक्त) {
		skdebug(__func__, "sk_openv failed");
		फर्काऊ रिक्त;
	}
	sk = रिक्त;
	यदि (skvcnt < 2) {
		यदि (skvcnt == 1) {
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

	यदि (sk_touch_begin(skv, skvcnt) == -1) {
		skdebug(__func__, "sk_touch_begin failed");
		गच्छ out;
	}
	monotime_tv(&tv_start);
	गर {
		यदि (sk_touch_poll(skv, skvcnt, &touch, &idx) == -1) {
			skdebug(__func__, "sk_touch_poll failed");
			गच्छ out;
		}
		यदि (touch) {
			sk = skv[idx];
			skv[idx] = रिक्त;
			गच्छ out;
		}
		monotime_tv(&tv_now);
		timersub(&tv_now, &tv_start, &tv_delta);
		ms_remain = SELECT_MS - tv_delta.tv_sec * 1000 -
		    tv_delta.tv_usec / 1000;
	} जबसम्म (ms_remain >= FIDO_POLL_MS);
	skdebug(__func__, "timeout");
out:
	sk_closev(skv, skvcnt);
	फर्काऊ sk;
}

स्थिर संरचना sk_usbhid *
sk_probe(अचर वर्ण *application, अचर uint8_t *साँचो_handle,
    माप_प्रकार साँचो_handle_len, पूर्णाङ्क probe_resident)
{
	संरचना sk_usbhid *sk;
	fido_dev_info_t *devlist;
	माप_प्रकार ndevs;
	पूर्णाङ्क r;

#ifdef HAVE_CYGWIN
	यदि (!probe_resident && (sk = sk_open("windows://hello")) != रिक्त)
		फर्काऊ sk;
#endif /* HAVE_CYGWIN */
	यदि ((devlist = fido_dev_info_new(MAX_FIDO_DEVICES)) == रिक्त) {
		skdebug(__func__, "fido_dev_info_new failed");
		फर्काऊ रिक्त;
	}
	यदि ((r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES,
	    &ndevs)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_info_manifest failed: %s",
		    fido_strerr(r));
		fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
		फर्काऊ रिक्त;
	}
	skdebug(__func__, "%zu device(s) detected", ndevs);
	यदि (ndevs == 0) {
		sk = रिक्त;
	} अन्यथा यदि (application != रिक्त && साँचो_handle != रिक्त) {
		skdebug(__func__, "selecting sk by cred");
		sk = sk_select_by_cred(devlist, ndevs, application, साँचो_handle,
		    साँचो_handle_len);
	} अन्यथा {
		skdebug(__func__, "selecting sk by touch");
		sk = sk_select_by_touch(devlist, ndevs);
	}
	fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
	फर्काऊ sk;
}

#ifdef WITH_OPENSSL
/*
 * The key returned via fido_cred_pubkey_ptr() is in affine coordinates,
 * but the API expects a SEC1 octet string.
 */
स्थिर पूर्णाङ्क
pack_public_साँचो_ecdsa(अचर fido_cred_t *cred,
    संरचना sk_enroll_response *response)
{
	अचर uint8_t *ptr;
	BIGNUM *x = रिक्त, *y = रिक्त;
	EC_POINT *q = रिक्त;
	EC_GROUP *g = रिक्त;
	पूर्णाङ्क ret = -1;

	response->public_साँचो = रिक्त;
	response->public_साँचो_len = 0;

	यदि ((x = BN_new()) == रिक्त ||
	    (y = BN_new()) == रिक्त ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == रिक्त ||
	    (q = EC_POINT_new(g)) == रिक्त) {
		skdebug(__func__, "libcrypto setup failed");
		गच्छ out;
	}
	यदि ((ptr = fido_cred_pubkey_ptr(cred)) == रिक्त) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		गच्छ out;
	}
	यदि (fido_cred_pubkey_len(cred) != 64) {
		skdebug(__func__, "bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		गच्छ out;
	}

	यदि (BN_bin2bn(ptr, 32, x) == रिक्त ||
	    BN_bin2bn(ptr + 32, 32, y) == रिक्त) {
		skdebug(__func__, "BN_bin2bn failed");
		गच्छ out;
	}
	यदि (EC_POINT_set_affine_coordinates(g, q, x, y, रिक्त) != 1) {
		skdebug(__func__, "EC_POINT_set_affine_coordinates failed");
		गच्छ out;
	}
	response->public_साँचो_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, रिक्त, 0, रिक्त);
	यदि (response->public_साँचो_len == 0 || response->public_साँचो_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_साँचो_len);
		गच्छ out;
	}
	यदि ((response->public_साँचो = दो_स्मृति(response->public_साँचो_len)) == रिक्त) {
		skdebug(__func__, "malloc pubkey failed");
		गच्छ out;
	}
	यदि (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_साँचो, response->public_साँचो_len, रिक्त) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		गच्छ out;
	}
	/* success */
	ret = 0;
 out:
	यदि (ret != 0 && response->public_साँचो != रिक्त) {
		स_रखो(response->public_साँचो, 0, response->public_साँचो_len);
		मुक्त(response->public_साँचो);
		response->public_साँचो = रिक्त;
	}
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	फर्काऊ ret;
}
#endif /* WITH_OPENSSL */

स्थिर पूर्णाङ्क
pack_public_साँचो_ed25519(अचर fido_cred_t *cred,
    संरचना sk_enroll_response *response)
{
	अचर uint8_t *ptr;
	माप_प्रकार len;
	पूर्णाङ्क ret = -1;

	response->public_साँचो = रिक्त;
	response->public_साँचो_len = 0;

	यदि ((len = fido_cred_pubkey_len(cred)) != 32) {
		skdebug(__func__, "bad fido_cred_pubkey_len len %zu", len);
		गच्छ out;
	}
	यदि ((ptr = fido_cred_pubkey_ptr(cred)) == रिक्त) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		गच्छ out;
	}
	response->public_साँचो_len = len;
	यदि ((response->public_साँचो = दो_स्मृति(response->public_साँचो_len)) == रिक्त) {
		skdebug(__func__, "malloc pubkey failed");
		गच्छ out;
	}
	स_नकल(response->public_साँचो, ptr, len);
	ret = 0;
 out:
	यदि (ret != 0)
		मुक्त(response->public_साँचो);
	फर्काऊ ret;
}

स्थिर पूर्णाङ्क
pack_public_साँचो(uint32_t alg, अचर fido_cred_t *cred,
    संरचना sk_enroll_response *response)
{
	विकल्प(alg) {
#ifdef WITH_OPENSSL
	पक्ष SSH_SK_ECDSA:
		फर्काऊ pack_public_साँचो_ecdsa(cred, response);
#endif /* WITH_OPENSSL */
	पक्ष SSH_SK_ED25519:
		फर्काऊ pack_public_साँचो_ed25519(cred, response);
	स्वभाव:
		फर्काऊ -1;
	}
}

स्थिर पूर्णाङ्क
fidoerr_to_skerr(पूर्णाङ्क fidoerr)
{
	विकल्प (fidoerr) {
	पक्ष FIDO_ERR_UNSUPPORTED_OPTION:
	पक्ष FIDO_ERR_UNSUPPORTED_ALGORITHM:
		फर्काऊ SSH_SK_ERR_UNSUPPORTED;
	पक्ष FIDO_ERR_PIN_REQUIRED:
	पक्ष FIDO_ERR_PIN_INVALID:
	पक्ष FIDO_ERR_OPERATION_DENIED:
		फर्काऊ SSH_SK_ERR_PIN_REQUIRED;
	स्वभाव:
		फर्काऊ -1;
	}
}

स्थिर पूर्णाङ्क
check_enroll_options(संरचना sk_option **options, वर्ण **devicep,
    uint8_t *user_id, माप_प्रकार user_id_len)
{
	माप_प्रकार i;

	यदि (options == रिक्त)
		फर्काऊ 0;
	लागि (i = 0; options[i] != रिक्त; i++) {
		यदि (म_भेद(options[i]->name, "device") == 0) {
			यदि ((*devicep = strdup(options[i]->मान)) == रिक्त) {
				skdebug(__func__, "strdup device failed");
				फर्काऊ -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} अन्यथा यदि (म_भेद(options[i]->name, "user") == 0) {
			यदि (strlcpy(user_id, options[i]->मान, user_id_len) >=
			    user_id_len) {
				skdebug(__func__, "user too long");
				फर्काऊ -1;
			}
			skdebug(__func__, "requested user %s",
			    (वर्ण *)user_id);
		} अन्यथा {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			यदि (options[i]->required) {
				skdebug(__func__, "unknown required option");
				फर्काऊ -1;
			}
		}
	}
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
साँचो_lookup(fido_dev_t *dev, अचर वर्ण *application, अचर uint8_t *user_id,
    माप_प्रकार user_id_len, अचर वर्ण *pin)
{
	fido_assert_t *प्रतिज्ञा = रिक्त;
	uint8_t message[32];
	पूर्णाङ्क r = FIDO_ERR_INTERNAL;
	पूर्णाङ्क sk_supports_uv, uv;
	माप_प्रकार i;

	स_रखो(message, '\0', परिमाण(message));
	यदि ((प्रतिज्ञा = fido_assert_new()) == रिक्त) {
		skdebug(__func__, "fido_assert_new failed");
		गच्छ out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	यदि ((r = fido_assert_set_clientdata(प्रतिज्ञा, message,
	    परिमाण(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		गच्छ out;
	}
	यदि ((r = fido_assert_set_rp(प्रतिज्ञा, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		गच्छ out;
	}
	यदि ((r = fido_assert_set_up(प्रतिज्ञा, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		गच्छ out;
	}
	uv = FIDO_OPT_OMIT;
	यदि (pin == रिक्त && check_sk_options(dev, "uv", &sk_supports_uv) == 0 &&
	    sk_supports_uv != -1)
		uv = FIDO_OPT_TRUE;
	यदि ((r = fido_assert_set_uv(प्रतिज्ञा, uv)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
		गच्छ out;
	}
	यदि ((r = fido_dev_get_assert(dev, प्रतिज्ञा, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		गच्छ out;
	}
	r = FIDO_ERR_NO_CREDENTIALS;
	skdebug(__func__, "%zu signatures returned", fido_assert_गन्ती(प्रतिज्ञा));
	लागि (i = 0; i < fido_assert_गन्ती(प्रतिज्ञा); i++) {
		यदि (fido_assert_user_id_len(प्रतिज्ञा, i) == user_id_len &&
		    स_भेद(fido_assert_user_id_ptr(प्रतिज्ञा, i), user_id,
		    user_id_len) == 0) {
			skdebug(__func__, "credential exists");
			r = FIDO_OK;
			गच्छ out;
		}
	}
 out:
	fido_assert_free(&प्रतिज्ञा);

	फर्काऊ r;
}

पूर्णाङ्क
sk_enroll(uint32_t alg, अचर uint8_t *challenge, माप_प्रकार challenge_len,
    अचर वर्ण *application, uint8_t flags, अचर वर्ण *pin,
    संरचना sk_option **options, संरचना sk_enroll_response **enroll_response)
{
	fido_cred_t *cred = रिक्त;
	अचर uint8_t *ptr;
	uint8_t user_id[32];
	संरचना sk_usbhid *sk = रिक्त;
	संरचना sk_enroll_response *response = रिक्त;
	माप_प्रकार len;
	पूर्णाङ्क credprot;
	पूर्णाङ्क cose_alg;
	पूर्णाङ्क ret = SSH_SK_ERR_GENERAL;
	पूर्णाङ्क r;
	वर्ण *device = रिक्त;

	fido_init(SSH_FIDO_INIT_ARG);

	यदि (enroll_response == रिक्त) {
		skdebug(__func__, "enroll_response == NULL");
		गच्छ out;
	}
	*enroll_response = रिक्त;
	स_रखो(user_id, 0, परिमाण(user_id));
	यदि (check_enroll_options(options, &device, user_id,
	    परिमाण(user_id)) != 0)
		गच्छ out; /* error already logged */

	विकल्प(alg) {
#ifdef WITH_OPENSSL
	पक्ष SSH_SK_ECDSA:
		cose_alg = COSE_ES256;
		रोक;
#endif /* WITH_OPENSSL */
	पक्ष SSH_SK_ED25519:
		cose_alg = COSE_EDDSA;
		रोक;
	स्वभाव:
		skdebug(__func__, "unsupported key type %d", alg);
		गच्छ out;
	}
	यदि (device != रिक्त)
		sk = sk_open(device);
	अन्यथा
		sk = sk_probe(रिक्त, रिक्त, 0, 0);
	यदि (sk == रिक्त) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		गच्छ out;
	}
	skdebug(__func__, "using device %s", sk->path);
	यदि ((flags & SSH_SK_RESIDENT_साँचो) != 0 &&
	    (flags & SSH_SK_FORCE_OPERATION) == 0 &&
	    (r = साँचो_lookup(sk->dev, application, user_id, परिमाण(user_id),
	    pin)) != FIDO_ERR_NO_CREDENTIALS) {
		यदि (r != FIDO_OK) {
			ret = fidoerr_to_skerr(r);
			skdebug(__func__, "key_lookup failed");
		} अन्यथा {
			ret = SSH_SK_ERR_CREDENTIAL_EXISTS;
			skdebug(__func__, "key exists");
		}
		गच्छ out;
	}
	यदि ((cred = fido_cred_new()) == रिक्त) {
		skdebug(__func__, "fido_cred_new failed");
		गच्छ out;
	}
	यदि ((r = fido_cred_set_type(cred, cose_alg)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_type: %s", fido_strerr(r));
		गच्छ out;
	}
	यदि ((r = fido_cred_set_clientdata(cred,
	    challenge, challenge_len)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata: %s",
		    fido_strerr(r));
		गच्छ out;
	}
	यदि ((r = fido_cred_set_rk(cred, (flags & SSH_SK_RESIDENT_साँचो) != 0 ?
	    FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rk: %s", fido_strerr(r));
		गच्छ out;
	}
	यदि ((r = fido_cred_set_user(cred, user_id, परिमाण(user_id),
	    "openssh", "openssh", रिक्त)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_user: %s", fido_strerr(r));
		गच्छ out;
	}
	यदि ((r = fido_cred_set_rp(cred, application, रिक्त)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rp: %s", fido_strerr(r));
		गच्छ out;
	}
	यदि ((flags & (SSH_SK_RESIDENT_साँचो|SSH_SK_USER_VERIFICATION_REQD)) != 0) {
#यदि !defined(HAVE_FIDO_DEV_SUPPORTS_CRED_PROT) || \
    !defined(HAVE_FIDO_CRED_SET_PROT)
		skdebug(__func__, "libfido2 version does not support a feature required for this operation. Please upgrade to >=1.5.0");
		ret = SSH_SK_ERR_UNSUPPORTED;
		गच्छ out;
		credprot = 0; (शून्य)credprot; /* avoid warning */
#endif
		यदि (!fido_dev_supports_cred_prot(sk->dev)) {
			skdebug(__func__, "%s does not support credprot, "
			    "refusing to create unprotected "
			    "resident/verify-required key", sk->path);
			ret = SSH_SK_ERR_UNSUPPORTED;
			गच्छ out;
		}
		यदि ((flags & SSH_SK_USER_VERIFICATION_REQD))
			credprot = FIDO_CRED_PROT_UV_REQUIRED;
		अन्यथा
			credprot = FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID;

		यदि ((r = fido_cred_set_prot(cred, credprot)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_set_prot: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			गच्छ out;
		}
	}
	यदि ((r = fido_dev_make_cred(sk->dev, cred, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_make_cred: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		गच्छ out;
	}
	यदि (fido_cred_x5c_ptr(cred) != रिक्त) {
		यदि ((r = fido_cred_verify(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify: %s",
			    fido_strerr(r));
			गच्छ out;
		}
	} अन्यथा यदि (म_भेद(fido_cred_fmt(cred), "none") != 0) {
		skdebug(__func__, "self-attested credential");
		यदि ((r = fido_cred_verify_self(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify_self: %s",
			    fido_strerr(r));
			गच्छ out;
		}
	} अन्यथा {
		skdebug(__func__, "no attestation data");
	}
	यदि ((response = सुस्मृति(1, परिमाण(*response))) == रिक्त) {
		skdebug(__func__, "calloc response failed");
		गच्छ out;
	}
	response->flags = flags;
	यदि (pack_public_साँचो(alg, cred, response) != 0) {
		skdebug(__func__, "pack_public_key failed");
		गच्छ out;
	}
	यदि ((ptr = fido_cred_id_ptr(cred)) != रिक्त) {
		len = fido_cred_id_len(cred);
		यदि ((response->साँचो_handle = सुस्मृति(1, len)) == रिक्त) {
			skdebug(__func__, "calloc key handle failed");
			गच्छ out;
		}
		स_नकल(response->साँचो_handle, ptr, len);
		response->साँचो_handle_len = len;
	}
	यदि ((ptr = fido_cred_sig_ptr(cred)) != रिक्त) {
		len = fido_cred_sig_len(cred);
		यदि ((response->signature = सुस्मृति(1, len)) == रिक्त) {
			skdebug(__func__, "calloc signature failed");
			गच्छ out;
		}
		स_नकल(response->signature, ptr, len);
		response->signature_len = len;
	}
	यदि ((ptr = fido_cred_x5c_ptr(cred)) != रिक्त) {
		len = fido_cred_x5c_len(cred);
		skdebug(__func__, "attestation cert len=%zu", len);
		यदि ((response->attestation_cert = सुस्मृति(1, len)) == रिक्त) {
			skdebug(__func__, "calloc attestation cert failed");
			गच्छ out;
		}
		स_नकल(response->attestation_cert, ptr, len);
		response->attestation_cert_len = len;
	}
	यदि ((ptr = fido_cred_authdata_ptr(cred)) != रिक्त) {
		len = fido_cred_authdata_len(cred);
		skdebug(__func__, "authdata len=%zu", len);
		यदि ((response->authdata = सुस्मृति(1, len)) == रिक्त) {
			skdebug(__func__, "calloc authdata failed");
			गच्छ out;
		}
		स_नकल(response->authdata, ptr, len);
		response->authdata_len = len;
	}
	*enroll_response = response;
	response = रिक्त;
	ret = 0;
 out:
	मुक्त(device);
	यदि (response != रिक्त) {
		मुक्त(response->public_साँचो);
		मुक्त(response->साँचो_handle);
		मुक्त(response->signature);
		मुक्त(response->attestation_cert);
		मुक्त(response->authdata);
		मुक्त(response);
	}
	sk_close(sk);
	fido_cred_free(&cred);
	फर्काऊ ret;
}

#ifdef WITH_OPENSSL
स्थिर पूर्णाङ्क
pack_sig_ecdsa(fido_assert_t *प्रतिज्ञा, संरचना sk_sign_response *response)
{
	ECDSA_SIG *sig = रिक्त;
	अचर BIGNUM *sig_r, *sig_s;
	अचर अचिन्हित वर्ण *cp;
	माप_प्रकार sig_len;
	पूर्णाङ्क ret = -1;

	cp = fido_assert_sig_ptr(प्रतिज्ञा, 0);
	sig_len = fido_assert_sig_len(प्रतिज्ञा, 0);
	यदि ((sig = d2i_ECDSA_SIG(रिक्त, &cp, sig_len)) == रिक्त) {
		skdebug(__func__, "d2i_ECDSA_SIG failed");
		गच्छ out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_अङ्क_bytes(sig_r);
	response->sig_s_len = BN_अङ्क_bytes(sig_s);
	यदि ((response->sig_r = सुस्मृति(1, response->sig_r_len)) == रिक्त ||
	    (response->sig_s = सुस्मृति(1, response->sig_s_len)) == रिक्त) {
		skdebug(__func__, "calloc signature failed");
		गच्छ out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	ECDSA_SIG_free(sig);
	यदि (ret != 0) {
		मुक्त(response->sig_r);
		मुक्त(response->sig_s);
		response->sig_r = रिक्त;
		response->sig_s = रिक्त;
	}
	फर्काऊ ret;
}
#endif /* WITH_OPENSSL */

स्थिर पूर्णाङ्क
pack_sig_ed25519(fido_assert_t *प्रतिज्ञा, संरचना sk_sign_response *response)
{
	अचर अचिन्हित वर्ण *ptr;
	माप_प्रकार len;
	पूर्णाङ्क ret = -1;

	ptr = fido_assert_sig_ptr(प्रतिज्ञा, 0);
	len = fido_assert_sig_len(प्रतिज्ञा, 0);
	यदि (len != 64) {
		skdebug(__func__, "bad length %zu", len);
		गच्छ out;
	}
	response->sig_r_len = len;
	यदि ((response->sig_r = सुस्मृति(1, response->sig_r_len)) == रिक्त) {
		skdebug(__func__, "calloc signature failed");
		गच्छ out;
	}
	स_नकल(response->sig_r, ptr, len);
	ret = 0;
 out:
	यदि (ret != 0) {
		मुक्त(response->sig_r);
		response->sig_r = रिक्त;
	}
	फर्काऊ ret;
}

स्थिर पूर्णाङ्क
pack_sig(uint32_t  alg, fido_assert_t *प्रतिज्ञा,
    संरचना sk_sign_response *response)
{
	विकल्प(alg) {
#ifdef WITH_OPENSSL
	पक्ष SSH_SK_ECDSA:
		फर्काऊ pack_sig_ecdsa(प्रतिज्ञा, response);
#endif /* WITH_OPENSSL */
	पक्ष SSH_SK_ED25519:
		फर्काऊ pack_sig_ed25519(प्रतिज्ञा, response);
	स्वभाव:
		फर्काऊ -1;
	}
}

/* Checks sk_options for sk_sign() and sk_load_resident_keys() */
स्थिर पूर्णाङ्क
check_sign_load_resident_options(संरचना sk_option **options, वर्ण **devicep)
{
	माप_प्रकार i;

	यदि (options == रिक्त)
		फर्काऊ 0;
	लागि (i = 0; options[i] != रिक्त; i++) {
		यदि (म_भेद(options[i]->name, "device") == 0) {
			यदि ((*devicep = strdup(options[i]->मान)) == रिक्त) {
				skdebug(__func__, "strdup device failed");
				फर्काऊ -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} अन्यथा {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			यदि (options[i]->required) {
				skdebug(__func__, "unknown required option");
				फर्काऊ -1;
			}
		}
	}
	फर्काऊ 0;
}

पूर्णाङ्क
sk_sign(uint32_t alg, अचर uint8_t *data, माप_प्रकार datalen,
    अचर वर्ण *application,
    अचर uint8_t *साँचो_handle, माप_प्रकार साँचो_handle_len,
    uint8_t flags, अचर वर्ण *pin, संरचना sk_option **options,
    संरचना sk_sign_response **sign_response)
{
	fido_assert_t *प्रतिज्ञा = रिक्त;
	वर्ण *device = रिक्त;
	संरचना sk_usbhid *sk = रिक्त;
	संरचना sk_sign_response *response = रिक्त;
	पूर्णाङ्क ret = SSH_SK_ERR_GENERAL, internal_uv;
	पूर्णाङ्क r;

	fido_init(SSH_FIDO_INIT_ARG);

	यदि (sign_response == रिक्त) {
		skdebug(__func__, "sign_response == NULL");
		गच्छ out;
	}
	*sign_response = रिक्त;
	यदि (check_sign_load_resident_options(options, &device) != 0)
		गच्छ out; /* error already logged */
	यदि (device != रिक्त)
		sk = sk_open(device);
	अन्यथा यदि (pin != रिक्त || (flags & SSH_SK_USER_VERIFICATION_REQD))
		sk = sk_probe(रिक्त, रिक्त, 0, 0);
	अन्यथा
		sk = sk_probe(application, साँचो_handle, साँचो_handle_len, 0);
	यदि (sk == रिक्त) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		गच्छ out;
	}
	यदि ((प्रतिज्ञा = fido_assert_new()) == रिक्त) {
		skdebug(__func__, "fido_assert_new failed");
		गच्छ out;
	}
	यदि ((r = fido_assert_set_clientdata(प्रतिज्ञा,
	    data, datalen)) != FIDO_OK)  {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		गच्छ out;
	}
	यदि ((r = fido_assert_set_rp(प्रतिज्ञा, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		गच्छ out;
	}
	यदि ((r = fido_assert_allow_cred(प्रतिज्ञा, साँचो_handle,
	    साँचो_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		गच्छ out;
	}
	यदि ((r = fido_assert_set_up(प्रतिज्ञा,
	    (flags & SSH_SK_USER_PRESENCE_REQD) ?
	    FIDO_OPT_TRUE : FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		गच्छ out;
	}
	/*
	 * WinHello requests the PIN by default.  Make "uv" request explicit
	 * to allow keys with and without -O verify-required to make sense.
	 */
	यदि (pin == रिक्त && fido_dev_is_winhello (sk->dev) &&
	    (r = fido_assert_set_uv(प्रतिज्ञा, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
	}
	यदि (pin == रिक्त && (flags & SSH_SK_USER_VERIFICATION_REQD)) {
		यदि (check_sk_options(sk->dev, "uv", &internal_uv) < 0 ||
		    internal_uv != 1) {
			skdebug(__func__, "check_sk_options uv");
			ret = SSH_SK_ERR_PIN_REQUIRED;
			गच्छ out;
		}
		यदि ((r = fido_assert_set_uv(प्रतिज्ञा,
		    FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_assert_set_uv: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			गच्छ out;
		}
	}
	यदि ((r = fido_dev_get_assert(sk->dev, प्रतिज्ञा, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		गच्छ out;
	}
	यदि ((response = सुस्मृति(1, परिमाण(*response))) == रिक्त) {
		skdebug(__func__, "calloc response failed");
		गच्छ out;
	}
	response->flags = fido_assert_flags(प्रतिज्ञा, 0);
	response->counter = fido_assert_sigcount(प्रतिज्ञा, 0);
	यदि (pack_sig(alg, प्रतिज्ञा, response) != 0) {
		skdebug(__func__, "pack_sig failed");
		गच्छ out;
	}
	*sign_response = response;
	response = रिक्त;
	ret = 0;
 out:
	मुक्त(device);
	यदि (response != रिक्त) {
		मुक्त(response->sig_r);
		मुक्त(response->sig_s);
		मुक्त(response);
	}
	sk_close(sk);
	fido_assert_free(&प्रतिज्ञा);
	फर्काऊ ret;
}

स्थिर पूर्णाङ्क
read_rks(संरचना sk_usbhid *sk, अचर वर्ण *pin,
    संरचना sk_resident_साँचो ***rksp, माप_प्रकार *nrksp)
{
	पूर्णाङ्क ret = SSH_SK_ERR_GENERAL, r = -1;
	uint32_t alg;
	fido_credman_metadata_t *metadata = रिक्त;
	fido_credman_rp_t *rp = रिक्त;
	fido_credman_rk_t *rk = रिक्त;
	माप_प्रकार i, j, nrp, nrk, user_id_len;
	अचर fido_cred_t *cred;
	अचर वर्ण *rp_id, *rp_name, *user_name;
	संरचना sk_resident_साँचो *srk = रिक्त, **tmp;
	अचर u_char *user_id;

	यदि (pin == रिक्त) {
		skdebug(__func__, "no PIN specified");
		ret = SSH_SK_ERR_PIN_REQUIRED;
		गच्छ out;
	}
	यदि ((metadata = fido_credman_metadata_new()) == रिक्त) {
		skdebug(__func__, "alloc failed");
		गच्छ out;
	}
	यदि ((r = fido_credman_get_dev_metadata(sk->dev, metadata, pin)) != 0) {
		यदि (r == FIDO_ERR_INVALID_COMMAND) {
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
	    (अचिन्हित दीर्घ दीर्घ)fido_credman_rk_existing(metadata),
	    (अचिन्हित दीर्घ दीर्घ)fido_credman_rk_remaining(metadata));
	यदि ((rp = fido_credman_rp_new()) == रिक्त) {
		skdebug(__func__, "alloc rp failed");
		गच्छ out;
	}
	यदि ((r = fido_credman_get_dev_rp(sk->dev, rp, pin)) != 0) {
		skdebug(__func__, "get RPs for %s failed: %s",
		    sk->path, fido_strerr(r));
		गच्छ out;
	}
	nrp = fido_credman_rp_गन्ती(rp);
	skdebug(__func__, "Device %s has resident keys for %zu RPs",
	    sk->path, nrp);

	/* Iterate over RP IDs that have resident keys */
	लागि (i = 0; i < nrp; i++) {
		rp_id = fido_credman_rp_id(rp, i);
		rp_name = fido_credman_rp_name(rp, i);
		skdebug(__func__, "rp %zu: name=\"%s\" id=\"%s\" hashlen=%zu",
		    i, rp_name == रिक्त ? "(none)" : rp_name,
		    rp_id == रिक्त ? "(none)" : rp_id,
		    fido_credman_rp_id_hash_len(rp, i));

		/* Skip non-SSH RP IDs */
		यदि (rp_id == रिक्त ||
		    strncasecmp(fido_credman_rp_id(rp, i), "ssh:", 4) != 0)
			जारी;

		fido_credman_rk_free(&rk);
		यदि ((rk = fido_credman_rk_new()) == रिक्त) {
			skdebug(__func__, "alloc rk failed");
			गच्छ out;
		}
		यदि ((r = fido_credman_get_dev_rk(sk->dev,
		    fido_credman_rp_id(rp, i), rk, pin)) != 0) {
			skdebug(__func__, "get RKs for %s slot %zu failed: %s",
			    sk->path, i, fido_strerr(r));
			गच्छ out;
		}
		nrk = fido_credman_rk_गन्ती(rk);
		skdebug(__func__, "RP \"%s\" has %zu resident keys",
		    fido_credman_rp_id(rp, i), nrk);

		/* Iterate over resident keys for this RP ID */
		लागि (j = 0; j < nrk; j++) {
			यदि ((cred = fido_credman_rk(rk, j)) == रिक्त) {
				skdebug(__func__, "no RK in slot %zu", j);
				जारी;
			}
			यदि ((user_name = fido_cred_user_name(cred)) == रिक्त)
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
				रोक;
			पक्ष COSE_EDDSA:
				alg = SSH_SK_ED25519;
				रोक;
			स्वभाव:
				skdebug(__func__, "unsupported key type %d",
				    fido_cred_type(cred));
				जारी;
			}

			/* build response entry */
			यदि ((srk = सुस्मृति(1, परिमाण(*srk))) == रिक्त ||
			    (srk->साँचो.साँचो_handle = सुस्मृति(1,
			    fido_cred_id_len(cred))) == रिक्त ||
			    (srk->application = strdup(rp_id)) == रिक्त ||
			    (user_id_len > 0 &&
			     (srk->user_id = सुस्मृति(1, user_id_len)) == रिक्त)) {
				skdebug(__func__, "alloc sk_resident_key");
				गच्छ out;
			}

			srk->alg = alg;
			srk->साँचो.साँचो_handle_len = fido_cred_id_len(cred);
			स_नकल(srk->साँचो.साँचो_handle, fido_cred_id_ptr(cred),
			    srk->साँचो.साँचो_handle_len);
			srk->user_id_len = user_id_len;
			यदि (srk->user_id_len != 0)
				स_नकल(srk->user_id, user_id, srk->user_id_len);

#ifdef HAVE_FIDO_CRED_PROT
			यदि (fido_cred_prot(cred) ==
			    FIDO_CRED_PROT_UV_REQUIRED)
				srk->flags |=  SSH_SK_USER_VERIFICATION_REQD;
#endif

			यदि ((r = pack_public_साँचो(srk->alg, cred,
			    &srk->साँचो)) != 0) {
				skdebug(__func__, "pack public key failed");
				गच्छ out;
			}
			/* append */
			यदि ((tmp = recallocarray(*rksp, *nrksp, (*nrksp) + 1,
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
	यदि (srk != रिक्त) {
		मुक्त(srk->application);
		freezero(srk->साँचो.public_साँचो, srk->साँचो.public_साँचो_len);
		freezero(srk->साँचो.साँचो_handle, srk->साँचो.साँचो_handle_len);
		freezero(srk->user_id, srk->user_id_len);
		freezero(srk, परिमाण(*srk));
	}
	fido_credman_rp_free(&rp);
	fido_credman_rk_free(&rk);
	fido_credman_metadata_free(&metadata);
	फर्काऊ ret;
}

पूर्णाङ्क
sk_load_resident_साँचोहरू(अचर वर्ण *pin, संरचना sk_option **options,
    संरचना sk_resident_साँचो ***rksp, माप_प्रकार *nrksp)
{
	पूर्णाङ्क ret = SSH_SK_ERR_GENERAL, r = -1;
	माप_प्रकार i, nrks = 0;
	संरचना sk_resident_साँचो **rks = रिक्त;
	संरचना sk_usbhid *sk = रिक्त;
	वर्ण *device = रिक्त;

	*rksp = रिक्त;
	*nrksp = 0;

	fido_init(SSH_FIDO_INIT_ARG);

	यदि (check_sign_load_resident_options(options, &device) != 0)
		गच्छ out; /* error already logged */
	यदि (device != रिक्त)
		sk = sk_open(device);
	अन्यथा
		sk = sk_probe(रिक्त, रिक्त, 0, 1);
	यदि (sk == रिक्त) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		गच्छ out;
	}
	skdebug(__func__, "trying %s", sk->path);
	यदि ((r = read_rks(sk, pin, &rks, &nrks)) != 0) {
		skdebug(__func__, "read_rks failed for %s", sk->path);
		ret = r;
		गच्छ out;
	}
	/* success, unless we have no keys but a specific error */
	यदि (nrks > 0 || ret == SSH_SK_ERR_GENERAL)
		ret = 0;
	*rksp = rks;
	*nrksp = nrks;
	rks = रिक्त;
	nrks = 0;
 out:
	sk_close(sk);
	लागि (i = 0; i < nrks; i++) {
		मुक्त(rks[i]->application);
		freezero(rks[i]->साँचो.public_साँचो, rks[i]->साँचो.public_साँचो_len);
		freezero(rks[i]->साँचो.साँचो_handle, rks[i]->साँचो.साँचो_handle_len);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i], परिमाण(*rks[i]));
	}
	मुक्त(device);
	मुक्त(rks);
	फर्काऊ ret;
}

#endif /* ENABLE_SK_INTERNAL */
