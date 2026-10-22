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

#समावेश "includes.h"

#अगर_घोषित ENABLE_SK_INTERNAL

#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <stdio.h>
#समावेश <stddef.h>
#समावेश <stdarg.h>
#समावेश <time.h>
#अगर_घोषित HAVE_SHA2_H
#समावेश <sha2.h>
#पूर्ण_अगर

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/opensslv.h>
#समावेश <openssl/crypto.h>
#समावेश <openssl/bn.h>
#समावेश <openssl/ec.h>
#समावेश <openssl/ecdsa.h>
#समावेश <openssl/evp.h>
#समावेश "openbsd-compat/openssl-compat.h"
#पूर्ण_अगर /* WITH_OPENSSL */

#समावेश <fido.h>
#समावेश <fido/credman.h>

/* backwards compat for libfido2 */
#अगर_अघोषित HAVE_FIDO_CRED_PROT
#घोषणा fido_cred_prot(x) (0)
#पूर्ण_अगर
#अगर_अघोषित HAVE_FIDO_CRED_SET_PROT
#घोषणा fido_cred_set_prot(x, y) (FIDO_ERR_UNSUPPORTED_OPTION)
#पूर्ण_अगर
#अगर_अघोषित HAVE_FIDO_DEV_SUPPORTS_CRED_PROT
#घोषणा fido_dev_supports_cred_prot(x) (0)
#पूर्ण_अगर
#अगर_अघोषित HAVE_FIDO_DEV_GET_TOUCH_BEGIN
#घोषणा fido_dev_get_touch_begin(x) (FIDO_ERR_UNSUPPORTED_OPTION)
#पूर्ण_अगर
#अगर_अघोषित HAVE_FIDO_DEV_GET_TOUCH_STATUS
#घोषणा fido_dev_get_touch_status(x, y, z) (FIDO_ERR_UNSUPPORTED_OPTION)
#पूर्ण_अगर
#अगर_अघोषित FIDO_CRED_PROT_UV_REQUIRED
#घोषणा FIDO_CRED_PROT_UV_REQUIRED 0
#पूर्ण_अगर
#अगर_अघोषित FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID
#घोषणा FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID 0
#पूर्ण_अगर

# include "misc.h"

#अगर_अघोषित SK_STANDALONE
# include "log.h"
# include "xmalloc.h"
/*
 * If building as part of OpenSSH, then rename exported functions.
 * This must be done before including sk-api.h.
 */
# define sk_api_version		ssh_sk_api_version
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_load_resident_कुंजियाँ	ssh_sk_load_resident_कुंजियाँ
#पूर्ण_अगर /* !SK_STANDALONE */

#समावेश "sk-api.h"

/* #define SK_DEBUG 1 */

#अगर_घोषित SK_DEBUG
#घोषणा SSH_FIDO_INIT_ARG	FIDO_DEBUG
#अन्यथा
#घोषणा SSH_FIDO_INIT_ARG	0
#पूर्ण_अगर

#घोषणा MAX_FIDO_DEVICES	8
#घोषणा FIDO_POLL_MS		50
#घोषणा SELECT_MS		15000
#घोषणा POLL_SLEEP_NS		200000000

#अगर_अघोषित FIDO_ERR_OPERATION_DENIED
#घोषणा FIDO_ERR_OPERATION_DENIED 0x27
#पूर्ण_अगर

काष्ठा sk_usbhid {
	fido_dev_t *dev;
	अक्षर *path;
};

/* Return the version of the middleware API */
uint32_t sk_api_version(व्योम);

/* Enroll a U2F key (private key generation) */
पूर्णांक sk_enroll(uint32_t alg, स्थिर uint8_t *challenge, माप_प्रकार challenge_len,
    स्थिर अक्षर *application, uint8_t flags, स्थिर अक्षर *pin,
    काष्ठा sk_option **options, काष्ठा sk_enroll_response **enroll_response);

/* Sign a challenge */
पूर्णांक sk_sign(uint32_t alg, स्थिर uint8_t *तथ्य, माप_प्रकार तथ्य_len,
    स्थिर अक्षर *application, स्थिर uint8_t *कुंजी_handle, माप_प्रकार कुंजी_handle_len,
    uint8_t flags, स्थिर अक्षर *pin, काष्ठा sk_option **options,
    काष्ठा sk_sign_response **sign_response);

/* Load resident keys */
पूर्णांक sk_load_resident_कुंजियाँ(स्थिर अक्षर *pin, काष्ठा sk_option **options,
    काष्ठा sk_resident_कुंजी ***rks, माप_प्रकार *nrks);

अटल व्योम skdebug(स्थिर अक्षर *func, स्थिर अक्षर *fmt, ...)
    __attribute__((__format__ (म_लिखो, 2, 3)));

अटल व्योम
skdebug(स्थिर अक्षर *func, स्थिर अक्षर *fmt, ...)
{
#अगर !defined(SK_STANDALONE)
	अक्षर *संदेश;
	बहु_सूची ap;

	बहु_शुरू(ap, fmt);
	xvasprintf(&संदेश, fmt, ap);
	बहु_पूर्ण(ap);
	debug("%s: %s", func, संदेश);
	मुक्त(संदेश);
#या_अगर defined(SK_DEBUG)
	बहु_सूची ap;

	बहु_शुरू(ap, fmt);
	ख_लिखो(मानक_त्रुटि, "%s: ", func);
	भख_लिखो(मानक_त्रुटि, fmt, ap);
	ख_अक्षर_दो('\n', मानक_त्रुटि);
	बहु_पूर्ण(ap);
#अन्यथा
	(व्योम)func; /* XXX */
	(व्योम)fmt; /* XXX */
#पूर्ण_अगर
}

uint32_t
sk_api_version(व्योम)
{
	वापस SSH_SK_VERSION_MAJOR;
}

अटल काष्ठा sk_usbhid *
sk_open(स्थिर अक्षर *path)
{
	काष्ठा sk_usbhid *sk;
	पूर्णांक r;

	अगर (path == शून्य) {
		skdebug(__func__, "path == NULL");
		वापस शून्य;
	}
	अगर ((sk = सुस्मृति(1, माप(*sk))) == शून्य) {
		skdebug(__func__, "calloc sk failed");
		वापस शून्य;
	}
	अगर ((sk->path = strdup(path)) == शून्य) {
		skdebug(__func__, "strdup path failed");
		मुक्त(sk);
		वापस शून्य;
	}
	अगर ((sk->dev = fido_dev_new()) == शून्य) {
		skdebug(__func__, "fido_dev_new failed");
		मुक्त(sk->path);
		मुक्त(sk);
		वापस शून्य;
	}
	अगर ((r = fido_dev_open(sk->dev, sk->path)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_open %s failed: %s", sk->path,
		    fido_strerr(r));
		fido_dev_free(&sk->dev);
		मुक्त(sk->path);
		मुक्त(sk);
		वापस शून्य;
	}
	वापस sk;
}

अटल व्योम
sk_close(काष्ठा sk_usbhid *sk)
{
	अगर (sk == शून्य)
		वापस;
	fido_dev_cancel(sk->dev); /* cancel any pending operation */
	fido_dev_close(sk->dev);
	fido_dev_free(&sk->dev);
	मुक्त(sk->path);
	मुक्त(sk);
}

अटल काष्ठा sk_usbhid **
sk_openv(स्थिर fido_dev_info_t *devlist, माप_प्रकार ndevs, माप_प्रकार *nopen)
{
	स्थिर fido_dev_info_t *di;
	काष्ठा sk_usbhid **skv;
	माप_प्रकार i;

	*nopen = 0;
	अगर ((skv = सुस्मृति(ndevs, माप(*skv))) == शून्य) {
		skdebug(__func__, "calloc skv failed");
		वापस शून्य;
	}
	क्रम (i = 0; i < ndevs; i++) {
		अगर ((di = fido_dev_info_ptr(devlist, i)) == शून्य)
			skdebug(__func__, "fido_dev_info_ptr failed");
		अन्यथा अगर ((skv[*nopen] = sk_open(fido_dev_info_path(di))) == शून्य)
			skdebug(__func__, "sk_open failed");
		अन्यथा
			(*nopen)++;
	}
	अगर (*nopen == 0) {
		क्रम (i = 0; i < ndevs; i++)
			sk_close(skv[i]);
		मुक्त(skv);
		skv = शून्य;
	}

	वापस skv;
}

अटल व्योम
sk_closev(काष्ठा sk_usbhid **skv, माप_प्रकार nsk)
{
	माप_प्रकार i;

	क्रम (i = 0; i < nsk; i++)
		sk_close(skv[i]);
	मुक्त(skv);
}

अटल पूर्णांक
sk_touch_begin(काष्ठा sk_usbhid **skv, माप_प्रकार nsk)
{
	माप_प्रकार i, ok = 0;
	पूर्णांक r;

	क्रम (i = 0; i < nsk; i++)
		अगर ((r = fido_dev_get_touch_begin(skv[i]->dev)) != FIDO_OK)
			skdebug(__func__, "fido_dev_get_touch_begin %s failed:"
			    " %s", skv[i]->path, fido_strerr(r));
		अन्यथा
			ok++;

	वापस ok ? 0 : -1;
}

अटल पूर्णांक
sk_touch_poll(काष्ठा sk_usbhid **skv, माप_प्रकार nsk, पूर्णांक *touch, माप_प्रकार *idx)
{
	काष्ठा timespec ts_pause;
	माप_प्रकार npoll, i;
	पूर्णांक r;

	ts_pause.tv_sec = 0;
	ts_pause.tv_nsec = POLL_SLEEP_NS;
	nanosleep(&ts_pause, शून्य);
	npoll = nsk;
	क्रम (i = 0; i < nsk; i++) {
		अगर (skv[i] == शून्य)
			जारी; /* device discarded */
		skdebug(__func__, "polling %s", skv[i]->path);
		अगर ((r = fido_dev_get_touch_status(skv[i]->dev, touch,
		    FIDO_POLL_MS)) != FIDO_OK) {
			skdebug(__func__, "fido_dev_get_touch_status %s: %s",
			    skv[i]->path, fido_strerr(r));
			sk_close(skv[i]); /* discard device */
			skv[i] = शून्य;
			अगर (--npoll == 0) {
				skdebug(__func__, "no device left to poll");
				वापस -1;
			}
		} अन्यथा अगर (*touch) {
			*idx = i;
			वापस 0;
		}
	}
	*touch = 0;
	वापस 0;
}

#अगर !defined(HAVE_FIDO_ASSERT_SET_CLIENTDATA) || \
    !defined(HAVE_FIDO_CRED_SET_CLIENTDATA)
/* Calculate SHA256(m) */
अटल पूर्णांक
sha256_mem(स्थिर व्योम *m, माप_प्रकार mlen, u_char *d, माप_प्रकार dlen)
{
#अगर_घोषित WITH_OPENSSL
	u_int mdlen;
#अन्यथा
	SHA2_CTX ctx;
#पूर्ण_अगर

	अगर (dlen != 32)
		वापस -1;
#अगर_घोषित WITH_OPENSSL
	mdlen = dlen;
	अगर (!EVP_Digest(m, mlen, d, &mdlen, EVP_sha256(), शून्य))
		वापस -1;
#अन्यथा
	SHA256Init(&ctx);
	SHA256Update(&ctx, (स्थिर uint8_t *)m, mlen);
	SHA256Final(d, &ctx);
#पूर्ण_अगर
	वापस 0;
}
#पूर्ण_अगर /* !HAVE_FIDO_ASSERT_SET_CLIENTDATA || !HAVE_FIDO_CRED_SET_CLIENTDATA */

#अगर_अघोषित HAVE_FIDO_CRED_SET_CLIENTDATA
अटल पूर्णांक
fido_cred_set_clientdata(fido_cred_t *cred, स्थिर u_char *ptr, माप_प्रकार len)
{
	uint8_t d[32];
	पूर्णांक r;

	अगर (sha256_mem(ptr, len, d, माप(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		वापस FIDO_ERR_INTERNAL;
	}
	r = fido_cred_set_clientdata_hash(cred, d, माप(d));
	explicit_bzero(d, माप(d));
	अगर (r != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	वापस r;
}
#पूर्ण_अगर /* HAVE_FIDO_CRED_SET_CLIENTDATA */

#अगर_अघोषित HAVE_FIDO_ASSERT_SET_CLIENTDATA
अटल पूर्णांक
fido_assert_set_clientdata(fido_assert_t *निश्चित, स्थिर u_char *ptr, माप_प्रकार len)
{
	uint8_t d[32];
	पूर्णांक r;

	अगर (sha256_mem(ptr, len, d, माप(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		वापस FIDO_ERR_INTERNAL;
	}
	r = fido_assert_set_clientdata_hash(निश्चित, d, माप(d));
	explicit_bzero(d, माप(d));
	अगर (r != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	वापस r;
}
#पूर्ण_अगर /* HAVE_FIDO_ASSERT_SET_CLIENTDATA */

#अगर_अघोषित HAVE_FIDO_DEV_IS_WINHELLO
अटल bool
fido_dev_is_winhello(स्थिर fido_dev_t *fdev)
{
	वापस 0;
}
#पूर्ण_अगर /* HAVE_FIDO_DEV_IS_WINHELLO */

/* Check if the specified key handle exists on a given sk. */
अटल पूर्णांक
sk_try(स्थिर काष्ठा sk_usbhid *sk, स्थिर अक्षर *application,
    स्थिर uint8_t *कुंजी_handle, माप_प्रकार कुंजी_handle_len)
{
	fido_assert_t *निश्चित = शून्य;
	पूर्णांक r = FIDO_ERR_INTERNAL;
	uint8_t message[32];

	स_रखो(message, '\0', माप(message));
	अगर ((निश्चित = fido_assert_new()) == शून्य) {
		skdebug(__func__, "fido_assert_new failed");
		जाओ out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	अगर ((r = fido_assert_set_clientdata(निश्चित, message,
	    माप(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		जाओ out;
	}
	अगर ((r = fido_assert_set_rp(निश्चित, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		जाओ out;
	}
	अगर ((r = fido_assert_allow_cred(निश्चित, कुंजी_handle,
	    कुंजी_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		जाओ out;
	}
	अगर ((r = fido_assert_set_up(निश्चित, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_up: %s", fido_strerr(r));
		जाओ out;
	}
	r = fido_dev_get_assert(sk->dev, निश्चित, शून्य);
	skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
	अगर (r == FIDO_ERR_USER_PRESENCE_REQUIRED) {
		/* U2F tokens may return this */
		r = FIDO_OK;
	}
 out:
	fido_assert_free(&निश्चित);

	वापस r != FIDO_OK ? -1 : 0;
}

अटल पूर्णांक
check_sk_options(fido_dev_t *dev, स्थिर अक्षर *opt, पूर्णांक *ret)
{
	fido_cbor_info_t *info;
	अक्षर * स्थिर *name;
	स्थिर bool *मूल्य;
	माप_प्रकार len, i;
	पूर्णांक r;

	*ret = -1;

	अगर (!fido_dev_is_fido2(dev)) {
		skdebug(__func__, "device is not fido2");
		वापस 0;
	}
	अगर ((info = fido_cbor_info_new()) == शून्य) {
		skdebug(__func__, "fido_cbor_info_new failed");
		वापस -1;
	}
	अगर ((r = fido_dev_get_cbor_info(dev, info)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_cbor_info: %s", fido_strerr(r));
		fido_cbor_info_free(&info);
		वापस -1;
	}
	name = fido_cbor_info_options_name_ptr(info);
	मूल्य = fido_cbor_info_options_मूल्य_ptr(info);
	len = fido_cbor_info_options_len(info);
	क्रम (i = 0; i < len; i++) {
		अगर (!म_भेद(name[i], opt)) {
			*ret = मूल्य[i];
			अवरोध;
		}
	}
	fido_cbor_info_free(&info);
	अगर (*ret == -1)
		skdebug(__func__, "option %s is unknown", opt);
	अन्यथा
		skdebug(__func__, "option %s is %s", opt, *ret ? "on" : "off");

	वापस 0;
}

अटल काष्ठा sk_usbhid *
sk_select_by_cred(स्थिर fido_dev_info_t *devlist, माप_प्रकार ndevs,
    स्थिर अक्षर *application, स्थिर uint8_t *कुंजी_handle, माप_प्रकार कुंजी_handle_len)
{
	काष्ठा sk_usbhid **skv, *sk;
	माप_प्रकार skvcnt, i;
	पूर्णांक internal_uv;

	अगर ((skv = sk_openv(devlist, ndevs, &skvcnt)) == शून्य) {
		skdebug(__func__, "sk_openv failed");
		वापस शून्य;
	}
	अगर (skvcnt == 1 && check_sk_options(skv[0]->dev, "uv",
	    &internal_uv) == 0 && internal_uv != -1) {
		sk = skv[0];
		skv[0] = शून्य;
		जाओ out;
	}
	sk = शून्य;
	क्रम (i = 0; i < skvcnt; i++) {
		अगर (sk_try(skv[i], application, कुंजी_handle,
		    कुंजी_handle_len) == 0) {
			sk = skv[i];
			skv[i] = शून्य;
			skdebug(__func__, "found key in %s", sk->path);
			अवरोध;
		}
	}
 out:
	sk_closev(skv, skvcnt);
	वापस sk;
}

अटल काष्ठा sk_usbhid *
sk_select_by_touch(स्थिर fido_dev_info_t *devlist, माप_प्रकार ndevs)
{
	काष्ठा sk_usbhid **skv, *sk;
	काष्ठा timeval tv_start, tv_now, tv_delta;
	माप_प्रकार skvcnt, idx;
	पूर्णांक touch, ms_remain;

	अगर ((skv = sk_openv(devlist, ndevs, &skvcnt)) == शून्य) {
		skdebug(__func__, "sk_openv failed");
		वापस शून्य;
	}
	sk = शून्य;
	अगर (skvcnt < 2) {
		अगर (skvcnt == 1) {
			/* single candidate */
			sk = skv[0];
			skv[0] = शून्य;
		}
		जाओ out;
	}
#अगर_अघोषित HAVE_FIDO_DEV_GET_TOUCH_STATUS
	skdebug(__func__, "libfido2 version does not support a feature needed for multiple tokens. Please upgrade to >=1.5.0");
	जाओ out;
#पूर्ण_अगर

	अगर (sk_touch_begin(skv, skvcnt) == -1) {
		skdebug(__func__, "sk_touch_begin failed");
		जाओ out;
	}
	monotime_tv(&tv_start);
	करो {
		अगर (sk_touch_poll(skv, skvcnt, &touch, &idx) == -1) {
			skdebug(__func__, "sk_touch_poll failed");
			जाओ out;
		}
		अगर (touch) {
			sk = skv[idx];
			skv[idx] = शून्य;
			जाओ out;
		}
		monotime_tv(&tv_now);
		timersub(&tv_now, &tv_start, &tv_delta);
		ms_remain = SELECT_MS - tv_delta.tv_sec * 1000 -
		    tv_delta.tv_usec / 1000;
	} जबतक (ms_remain >= FIDO_POLL_MS);
	skdebug(__func__, "timeout");
out:
	sk_closev(skv, skvcnt);
	वापस sk;
}

अटल काष्ठा sk_usbhid *
sk_probe(स्थिर अक्षर *application, स्थिर uint8_t *कुंजी_handle,
    माप_प्रकार कुंजी_handle_len, पूर्णांक probe_resident)
{
	काष्ठा sk_usbhid *sk;
	fido_dev_info_t *devlist;
	माप_प्रकार ndevs;
	पूर्णांक r;

#अगर_घोषित HAVE_CYGWIN
	अगर (!probe_resident && (sk = sk_open("windows://hello")) != शून्य)
		वापस sk;
#पूर्ण_अगर /* HAVE_CYGWIN */
	अगर ((devlist = fido_dev_info_new(MAX_FIDO_DEVICES)) == शून्य) {
		skdebug(__func__, "fido_dev_info_new failed");
		वापस शून्य;
	}
	अगर ((r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES,
	    &ndevs)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_info_manifest failed: %s",
		    fido_strerr(r));
		fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
		वापस शून्य;
	}
	skdebug(__func__, "%zu device(s) detected", ndevs);
	अगर (ndevs == 0) {
		sk = शून्य;
	} अन्यथा अगर (application != शून्य && कुंजी_handle != शून्य) {
		skdebug(__func__, "selecting sk by cred");
		sk = sk_select_by_cred(devlist, ndevs, application, कुंजी_handle,
		    कुंजी_handle_len);
	} अन्यथा {
		skdebug(__func__, "selecting sk by touch");
		sk = sk_select_by_touch(devlist, ndevs);
	}
	fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
	वापस sk;
}

#अगर_घोषित WITH_OPENSSL
/*
 * The key returned via fido_cred_pubkey_ptr() is in affine coordinates,
 * but the API expects a SEC1 octet string.
 */
अटल पूर्णांक
pack_public_कुंजी_ecdsa(स्थिर fido_cred_t *cred,
    काष्ठा sk_enroll_response *response)
{
	स्थिर uint8_t *ptr;
	BIGNUM *x = शून्य, *y = शून्य;
	EC_POINT *q = शून्य;
	EC_GROUP *g = शून्य;
	पूर्णांक ret = -1;

	response->public_कुंजी = शून्य;
	response->public_कुंजी_len = 0;

	अगर ((x = BN_new()) == शून्य ||
	    (y = BN_new()) == शून्य ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == शून्य ||
	    (q = EC_POINT_new(g)) == शून्य) {
		skdebug(__func__, "libcrypto setup failed");
		जाओ out;
	}
	अगर ((ptr = fido_cred_pubkey_ptr(cred)) == शून्य) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		जाओ out;
	}
	अगर (fido_cred_pubkey_len(cred) != 64) {
		skdebug(__func__, "bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		जाओ out;
	}

	अगर (BN_bin2bn(ptr, 32, x) == शून्य ||
	    BN_bin2bn(ptr + 32, 32, y) == शून्य) {
		skdebug(__func__, "BN_bin2bn failed");
		जाओ out;
	}
	अगर (EC_POINT_set_affine_coordinates(g, q, x, y, शून्य) != 1) {
		skdebug(__func__, "EC_POINT_set_affine_coordinates failed");
		जाओ out;
	}
	response->public_कुंजी_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, शून्य, 0, शून्य);
	अगर (response->public_कुंजी_len == 0 || response->public_कुंजी_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_कुंजी_len);
		जाओ out;
	}
	अगर ((response->public_कुंजी = दो_स्मृति(response->public_कुंजी_len)) == शून्य) {
		skdebug(__func__, "malloc pubkey failed");
		जाओ out;
	}
	अगर (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_कुंजी, response->public_कुंजी_len, शून्य) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		जाओ out;
	}
	/* success */
	ret = 0;
 out:
	अगर (ret != 0 && response->public_कुंजी != शून्य) {
		स_रखो(response->public_कुंजी, 0, response->public_कुंजी_len);
		मुक्त(response->public_कुंजी);
		response->public_कुंजी = शून्य;
	}
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	वापस ret;
}
#पूर्ण_अगर /* WITH_OPENSSL */

अटल पूर्णांक
pack_public_कुंजी_ed25519(स्थिर fido_cred_t *cred,
    काष्ठा sk_enroll_response *response)
{
	स्थिर uint8_t *ptr;
	माप_प्रकार len;
	पूर्णांक ret = -1;

	response->public_कुंजी = शून्य;
	response->public_कुंजी_len = 0;

	अगर ((len = fido_cred_pubkey_len(cred)) != 32) {
		skdebug(__func__, "bad fido_cred_pubkey_len len %zu", len);
		जाओ out;
	}
	अगर ((ptr = fido_cred_pubkey_ptr(cred)) == शून्य) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		जाओ out;
	}
	response->public_कुंजी_len = len;
	अगर ((response->public_कुंजी = दो_स्मृति(response->public_कुंजी_len)) == शून्य) {
		skdebug(__func__, "malloc pubkey failed");
		जाओ out;
	}
	स_नकल(response->public_कुंजी, ptr, len);
	ret = 0;
 out:
	अगर (ret != 0)
		मुक्त(response->public_कुंजी);
	वापस ret;
}

अटल पूर्णांक
pack_public_कुंजी(uint32_t alg, स्थिर fido_cred_t *cred,
    काष्ठा sk_enroll_response *response)
{
	चयन(alg) {
#अगर_घोषित WITH_OPENSSL
	हाल SSH_SK_ECDSA:
		वापस pack_public_कुंजी_ecdsa(cred, response);
#पूर्ण_अगर /* WITH_OPENSSL */
	हाल SSH_SK_ED25519:
		वापस pack_public_कुंजी_ed25519(cred, response);
	शेष:
		वापस -1;
	}
}

अटल पूर्णांक
fidoerr_to_skerr(पूर्णांक fidoerr)
{
	चयन (fidoerr) {
	हाल FIDO_ERR_UNSUPPORTED_OPTION:
	हाल FIDO_ERR_UNSUPPORTED_ALGORITHM:
		वापस SSH_SK_ERR_UNSUPPORTED;
	हाल FIDO_ERR_PIN_REQUIRED:
	हाल FIDO_ERR_PIN_INVALID:
	हाल FIDO_ERR_OPERATION_DENIED:
		वापस SSH_SK_ERR_PIN_REQUIRED;
	शेष:
		वापस -1;
	}
}

अटल पूर्णांक
check_enroll_options(काष्ठा sk_option **options, अक्षर **devicep,
    uint8_t *user_id, माप_प्रकार user_id_len)
{
	माप_प्रकार i;

	अगर (options == शून्य)
		वापस 0;
	क्रम (i = 0; options[i] != शून्य; i++) {
		अगर (म_भेद(options[i]->name, "device") == 0) {
			अगर ((*devicep = strdup(options[i]->मूल्य)) == शून्य) {
				skdebug(__func__, "strdup device failed");
				वापस -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} अन्यथा अगर (म_भेद(options[i]->name, "user") == 0) {
			अगर (strlcpy(user_id, options[i]->मूल्य, user_id_len) >=
			    user_id_len) {
				skdebug(__func__, "user too long");
				वापस -1;
			}
			skdebug(__func__, "requested user %s",
			    (अक्षर *)user_id);
		} अन्यथा {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			अगर (options[i]->required) {
				skdebug(__func__, "unknown required option");
				वापस -1;
			}
		}
	}
	वापस 0;
}

अटल पूर्णांक
कुंजी_lookup(fido_dev_t *dev, स्थिर अक्षर *application, स्थिर uint8_t *user_id,
    माप_प्रकार user_id_len, स्थिर अक्षर *pin)
{
	fido_assert_t *निश्चित = शून्य;
	uint8_t message[32];
	पूर्णांक r = FIDO_ERR_INTERNAL;
	पूर्णांक sk_supports_uv, uv;
	माप_प्रकार i;

	स_रखो(message, '\0', माप(message));
	अगर ((निश्चित = fido_assert_new()) == शून्य) {
		skdebug(__func__, "fido_assert_new failed");
		जाओ out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	अगर ((r = fido_assert_set_clientdata(निश्चित, message,
	    माप(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		जाओ out;
	}
	अगर ((r = fido_assert_set_rp(निश्चित, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		जाओ out;
	}
	अगर ((r = fido_assert_set_up(निश्चित, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		जाओ out;
	}
	uv = FIDO_OPT_OMIT;
	अगर (pin == शून्य && check_sk_options(dev, "uv", &sk_supports_uv) == 0 &&
	    sk_supports_uv != -1)
		uv = FIDO_OPT_TRUE;
	अगर ((r = fido_assert_set_uv(निश्चित, uv)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
		जाओ out;
	}
	अगर ((r = fido_dev_get_assert(dev, निश्चित, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		जाओ out;
	}
	r = FIDO_ERR_NO_CREDENTIALS;
	skdebug(__func__, "%zu signatures returned", fido_assert_गिनती(निश्चित));
	क्रम (i = 0; i < fido_assert_गिनती(निश्चित); i++) {
		अगर (fido_assert_user_id_len(निश्चित, i) == user_id_len &&
		    स_भेद(fido_assert_user_id_ptr(निश्चित, i), user_id,
		    user_id_len) == 0) {
			skdebug(__func__, "credential exists");
			r = FIDO_OK;
			जाओ out;
		}
	}
 out:
	fido_assert_free(&निश्चित);

	वापस r;
}

पूर्णांक
sk_enroll(uint32_t alg, स्थिर uint8_t *challenge, माप_प्रकार challenge_len,
    स्थिर अक्षर *application, uint8_t flags, स्थिर अक्षर *pin,
    काष्ठा sk_option **options, काष्ठा sk_enroll_response **enroll_response)
{
	fido_cred_t *cred = शून्य;
	स्थिर uint8_t *ptr;
	uint8_t user_id[32];
	काष्ठा sk_usbhid *sk = शून्य;
	काष्ठा sk_enroll_response *response = शून्य;
	माप_प्रकार len;
	पूर्णांक credprot;
	पूर्णांक cose_alg;
	पूर्णांक ret = SSH_SK_ERR_GENERAL;
	पूर्णांक r;
	अक्षर *device = शून्य;

	fido_init(SSH_FIDO_INIT_ARG);

	अगर (enroll_response == शून्य) {
		skdebug(__func__, "enroll_response == NULL");
		जाओ out;
	}
	*enroll_response = शून्य;
	स_रखो(user_id, 0, माप(user_id));
	अगर (check_enroll_options(options, &device, user_id,
	    माप(user_id)) != 0)
		जाओ out; /* error already logged */

	चयन(alg) {
#अगर_घोषित WITH_OPENSSL
	हाल SSH_SK_ECDSA:
		cose_alg = COSE_ES256;
		अवरोध;
#पूर्ण_अगर /* WITH_OPENSSL */
	हाल SSH_SK_ED25519:
		cose_alg = COSE_EDDSA;
		अवरोध;
	शेष:
		skdebug(__func__, "unsupported key type %d", alg);
		जाओ out;
	}
	अगर (device != शून्य)
		sk = sk_open(device);
	अन्यथा
		sk = sk_probe(शून्य, शून्य, 0, 0);
	अगर (sk == शून्य) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		जाओ out;
	}
	skdebug(__func__, "using device %s", sk->path);
	अगर ((flags & SSH_SK_RESIDENT_कुंजी) != 0 &&
	    (flags & SSH_SK_FORCE_OPERATION) == 0 &&
	    (r = कुंजी_lookup(sk->dev, application, user_id, माप(user_id),
	    pin)) != FIDO_ERR_NO_CREDENTIALS) {
		अगर (r != FIDO_OK) {
			ret = fidoerr_to_skerr(r);
			skdebug(__func__, "key_lookup failed");
		} अन्यथा {
			ret = SSH_SK_ERR_CREDENTIAL_EXISTS;
			skdebug(__func__, "key exists");
		}
		जाओ out;
	}
	अगर ((cred = fido_cred_new()) == शून्य) {
		skdebug(__func__, "fido_cred_new failed");
		जाओ out;
	}
	अगर ((r = fido_cred_set_type(cred, cose_alg)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_type: %s", fido_strerr(r));
		जाओ out;
	}
	अगर ((r = fido_cred_set_clientdata(cred,
	    challenge, challenge_len)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata: %s",
		    fido_strerr(r));
		जाओ out;
	}
	अगर ((r = fido_cred_set_rk(cred, (flags & SSH_SK_RESIDENT_कुंजी) != 0 ?
	    FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rk: %s", fido_strerr(r));
		जाओ out;
	}
	अगर ((r = fido_cred_set_user(cred, user_id, माप(user_id),
	    "openssh", "openssh", शून्य)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_user: %s", fido_strerr(r));
		जाओ out;
	}
	अगर ((r = fido_cred_set_rp(cred, application, शून्य)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rp: %s", fido_strerr(r));
		जाओ out;
	}
	अगर ((flags & (SSH_SK_RESIDENT_कुंजी|SSH_SK_USER_VERIFICATION_REQD)) != 0) {
#अगर !defined(HAVE_FIDO_DEV_SUPPORTS_CRED_PROT) || \
    !defined(HAVE_FIDO_CRED_SET_PROT)
		skdebug(__func__, "libfido2 version does not support a feature required for this operation. Please upgrade to >=1.5.0");
		ret = SSH_SK_ERR_UNSUPPORTED;
		जाओ out;
		credprot = 0; (व्योम)credprot; /* avoid warning */
#पूर्ण_अगर
		अगर (!fido_dev_supports_cred_prot(sk->dev)) {
			skdebug(__func__, "%s does not support credprot, "
			    "refusing to create unprotected "
			    "resident/verify-required key", sk->path);
			ret = SSH_SK_ERR_UNSUPPORTED;
			जाओ out;
		}
		अगर ((flags & SSH_SK_USER_VERIFICATION_REQD))
			credprot = FIDO_CRED_PROT_UV_REQUIRED;
		अन्यथा
			credprot = FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID;

		अगर ((r = fido_cred_set_prot(cred, credprot)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_set_prot: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			जाओ out;
		}
	}
	अगर ((r = fido_dev_make_cred(sk->dev, cred, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_make_cred: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		जाओ out;
	}
	अगर (fido_cred_x5c_ptr(cred) != शून्य) {
		अगर ((r = fido_cred_verify(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify: %s",
			    fido_strerr(r));
			जाओ out;
		}
	} अन्यथा अगर (म_भेद(fido_cred_fmt(cred), "none") != 0) {
		skdebug(__func__, "self-attested credential");
		अगर ((r = fido_cred_verify_self(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify_self: %s",
			    fido_strerr(r));
			जाओ out;
		}
	} अन्यथा {
		skdebug(__func__, "no attestation data");
	}
	अगर ((response = सुस्मृति(1, माप(*response))) == शून्य) {
		skdebug(__func__, "calloc response failed");
		जाओ out;
	}
	response->flags = flags;
	अगर (pack_public_कुंजी(alg, cred, response) != 0) {
		skdebug(__func__, "pack_public_key failed");
		जाओ out;
	}
	अगर ((ptr = fido_cred_id_ptr(cred)) != शून्य) {
		len = fido_cred_id_len(cred);
		अगर ((response->कुंजी_handle = सुस्मृति(1, len)) == शून्य) {
			skdebug(__func__, "calloc key handle failed");
			जाओ out;
		}
		स_नकल(response->कुंजी_handle, ptr, len);
		response->कुंजी_handle_len = len;
	}
	अगर ((ptr = fido_cred_sig_ptr(cred)) != शून्य) {
		len = fido_cred_sig_len(cred);
		अगर ((response->signature = सुस्मृति(1, len)) == शून्य) {
			skdebug(__func__, "calloc signature failed");
			जाओ out;
		}
		स_नकल(response->signature, ptr, len);
		response->signature_len = len;
	}
	अगर ((ptr = fido_cred_x5c_ptr(cred)) != शून्य) {
		len = fido_cred_x5c_len(cred);
		skdebug(__func__, "attestation cert len=%zu", len);
		अगर ((response->attestation_cert = सुस्मृति(1, len)) == शून्य) {
			skdebug(__func__, "calloc attestation cert failed");
			जाओ out;
		}
		स_नकल(response->attestation_cert, ptr, len);
		response->attestation_cert_len = len;
	}
	अगर ((ptr = fido_cred_authdata_ptr(cred)) != शून्य) {
		len = fido_cred_authdata_len(cred);
		skdebug(__func__, "authdata len=%zu", len);
		अगर ((response->authdata = सुस्मृति(1, len)) == शून्य) {
			skdebug(__func__, "calloc authdata failed");
			जाओ out;
		}
		स_नकल(response->authdata, ptr, len);
		response->authdata_len = len;
	}
	*enroll_response = response;
	response = शून्य;
	ret = 0;
 out:
	मुक्त(device);
	अगर (response != शून्य) {
		मुक्त(response->public_कुंजी);
		मुक्त(response->कुंजी_handle);
		मुक्त(response->signature);
		मुक्त(response->attestation_cert);
		मुक्त(response->authdata);
		मुक्त(response);
	}
	sk_close(sk);
	fido_cred_free(&cred);
	वापस ret;
}

#अगर_घोषित WITH_OPENSSL
अटल पूर्णांक
pack_sig_ecdsa(fido_assert_t *निश्चित, काष्ठा sk_sign_response *response)
{
	ECDSA_SIG *sig = शून्य;
	स्थिर BIGNUM *sig_r, *sig_s;
	स्थिर अचिन्हित अक्षर *cp;
	माप_प्रकार sig_len;
	पूर्णांक ret = -1;

	cp = fido_assert_sig_ptr(निश्चित, 0);
	sig_len = fido_assert_sig_len(निश्चित, 0);
	अगर ((sig = d2i_ECDSA_SIG(शून्य, &cp, sig_len)) == शून्य) {
		skdebug(__func__, "d2i_ECDSA_SIG failed");
		जाओ out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_अंक_bytes(sig_r);
	response->sig_s_len = BN_अंक_bytes(sig_s);
	अगर ((response->sig_r = सुस्मृति(1, response->sig_r_len)) == शून्य ||
	    (response->sig_s = सुस्मृति(1, response->sig_s_len)) == शून्य) {
		skdebug(__func__, "calloc signature failed");
		जाओ out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	ECDSA_SIG_free(sig);
	अगर (ret != 0) {
		मुक्त(response->sig_r);
		मुक्त(response->sig_s);
		response->sig_r = शून्य;
		response->sig_s = शून्य;
	}
	वापस ret;
}
#पूर्ण_अगर /* WITH_OPENSSL */

अटल पूर्णांक
pack_sig_ed25519(fido_assert_t *निश्चित, काष्ठा sk_sign_response *response)
{
	स्थिर अचिन्हित अक्षर *ptr;
	माप_प्रकार len;
	पूर्णांक ret = -1;

	ptr = fido_assert_sig_ptr(निश्चित, 0);
	len = fido_assert_sig_len(निश्चित, 0);
	अगर (len != 64) {
		skdebug(__func__, "bad length %zu", len);
		जाओ out;
	}
	response->sig_r_len = len;
	अगर ((response->sig_r = सुस्मृति(1, response->sig_r_len)) == शून्य) {
		skdebug(__func__, "calloc signature failed");
		जाओ out;
	}
	स_नकल(response->sig_r, ptr, len);
	ret = 0;
 out:
	अगर (ret != 0) {
		मुक्त(response->sig_r);
		response->sig_r = शून्य;
	}
	वापस ret;
}

अटल पूर्णांक
pack_sig(uint32_t  alg, fido_assert_t *निश्चित,
    काष्ठा sk_sign_response *response)
{
	चयन(alg) {
#अगर_घोषित WITH_OPENSSL
	हाल SSH_SK_ECDSA:
		वापस pack_sig_ecdsa(निश्चित, response);
#पूर्ण_अगर /* WITH_OPENSSL */
	हाल SSH_SK_ED25519:
		वापस pack_sig_ed25519(निश्चित, response);
	शेष:
		वापस -1;
	}
}

/* Checks sk_options for sk_sign() and sk_load_resident_keys() */
अटल पूर्णांक
check_sign_load_resident_options(काष्ठा sk_option **options, अक्षर **devicep)
{
	माप_प्रकार i;

	अगर (options == शून्य)
		वापस 0;
	क्रम (i = 0; options[i] != शून्य; i++) {
		अगर (म_भेद(options[i]->name, "device") == 0) {
			अगर ((*devicep = strdup(options[i]->मूल्य)) == शून्य) {
				skdebug(__func__, "strdup device failed");
				वापस -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} अन्यथा {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			अगर (options[i]->required) {
				skdebug(__func__, "unknown required option");
				वापस -1;
			}
		}
	}
	वापस 0;
}

पूर्णांक
sk_sign(uint32_t alg, स्थिर uint8_t *तथ्य, माप_प्रकार datalen,
    स्थिर अक्षर *application,
    स्थिर uint8_t *कुंजी_handle, माप_प्रकार कुंजी_handle_len,
    uint8_t flags, स्थिर अक्षर *pin, काष्ठा sk_option **options,
    काष्ठा sk_sign_response **sign_response)
{
	fido_assert_t *निश्चित = शून्य;
	अक्षर *device = शून्य;
	काष्ठा sk_usbhid *sk = शून्य;
	काष्ठा sk_sign_response *response = शून्य;
	पूर्णांक ret = SSH_SK_ERR_GENERAL, internal_uv;
	पूर्णांक r;

	fido_init(SSH_FIDO_INIT_ARG);

	अगर (sign_response == शून्य) {
		skdebug(__func__, "sign_response == NULL");
		जाओ out;
	}
	*sign_response = शून्य;
	अगर (check_sign_load_resident_options(options, &device) != 0)
		जाओ out; /* error already logged */
	अगर (device != शून्य)
		sk = sk_open(device);
	अन्यथा अगर (pin != शून्य || (flags & SSH_SK_USER_VERIFICATION_REQD))
		sk = sk_probe(शून्य, शून्य, 0, 0);
	अन्यथा
		sk = sk_probe(application, कुंजी_handle, कुंजी_handle_len, 0);
	अगर (sk == शून्य) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		जाओ out;
	}
	अगर ((निश्चित = fido_assert_new()) == शून्य) {
		skdebug(__func__, "fido_assert_new failed");
		जाओ out;
	}
	अगर ((r = fido_assert_set_clientdata(निश्चित,
	    तथ्य, datalen)) != FIDO_OK)  {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		जाओ out;
	}
	अगर ((r = fido_assert_set_rp(निश्चित, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		जाओ out;
	}
	अगर ((r = fido_assert_allow_cred(निश्चित, कुंजी_handle,
	    कुंजी_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		जाओ out;
	}
	अगर ((r = fido_assert_set_up(निश्चित,
	    (flags & SSH_SK_USER_PRESENCE_REQD) ?
	    FIDO_OPT_TRUE : FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		जाओ out;
	}
	/*
	 * WinHello requests the PIN by default.  Make "uv" request explicit
	 * to allow keys with and without -O verify-required to make sense.
	 */
	अगर (pin == शून्य && fido_dev_is_winhello (sk->dev) &&
	    (r = fido_assert_set_uv(निश्चित, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
	}
	अगर (pin == शून्य && (flags & SSH_SK_USER_VERIFICATION_REQD)) {
		अगर (check_sk_options(sk->dev, "uv", &internal_uv) < 0 ||
		    internal_uv != 1) {
			skdebug(__func__, "check_sk_options uv");
			ret = SSH_SK_ERR_PIN_REQUIRED;
			जाओ out;
		}
		अगर ((r = fido_assert_set_uv(निश्चित,
		    FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_assert_set_uv: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			जाओ out;
		}
	}
	अगर ((r = fido_dev_get_assert(sk->dev, निश्चित, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		जाओ out;
	}
	अगर ((response = सुस्मृति(1, माप(*response))) == शून्य) {
		skdebug(__func__, "calloc response failed");
		जाओ out;
	}
	response->flags = fido_assert_flags(निश्चित, 0);
	response->गणक = fido_assert_sigcount(निश्चित, 0);
	अगर (pack_sig(alg, निश्चित, response) != 0) {
		skdebug(__func__, "pack_sig failed");
		जाओ out;
	}
	*sign_response = response;
	response = शून्य;
	ret = 0;
 out:
	मुक्त(device);
	अगर (response != शून्य) {
		मुक्त(response->sig_r);
		मुक्त(response->sig_s);
		मुक्त(response);
	}
	sk_close(sk);
	fido_assert_free(&निश्चित);
	वापस ret;
}

अटल पूर्णांक
read_rks(काष्ठा sk_usbhid *sk, स्थिर अक्षर *pin,
    काष्ठा sk_resident_कुंजी ***rksp, माप_प्रकार *nrksp)
{
	पूर्णांक ret = SSH_SK_ERR_GENERAL, r = -1;
	uint32_t alg;
	fido_credman_metadata_t *metadata = शून्य;
	fido_credman_rp_t *rp = शून्य;
	fido_credman_rk_t *rk = शून्य;
	माप_प्रकार i, j, nrp, nrk, user_id_len;
	स्थिर fido_cred_t *cred;
	स्थिर अक्षर *rp_id, *rp_name, *user_name;
	काष्ठा sk_resident_कुंजी *srk = शून्य, **tmp;
	स्थिर u_char *user_id;

	अगर (pin == शून्य) {
		skdebug(__func__, "no PIN specified");
		ret = SSH_SK_ERR_PIN_REQUIRED;
		जाओ out;
	}
	अगर ((metadata = fido_credman_metadata_new()) == शून्य) {
		skdebug(__func__, "alloc failed");
		जाओ out;
	}
	अगर ((r = fido_credman_get_dev_metadata(sk->dev, metadata, pin)) != 0) {
		अगर (r == FIDO_ERR_INVALID_COMMAND) {
			skdebug(__func__, "device %s does not support "
			    "resident keys", sk->path);
			ret = 0;
			जाओ out;
		}
		skdebug(__func__, "get metadata for %s failed: %s",
		    sk->path, fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		जाओ out;
	}
	skdebug(__func__, "existing %llu, remaining %llu",
	    (अचिन्हित दीर्घ दीर्घ)fido_credman_rk_existing(metadata),
	    (अचिन्हित दीर्घ दीर्घ)fido_credman_rk_remaining(metadata));
	अगर ((rp = fido_credman_rp_new()) == शून्य) {
		skdebug(__func__, "alloc rp failed");
		जाओ out;
	}
	अगर ((r = fido_credman_get_dev_rp(sk->dev, rp, pin)) != 0) {
		skdebug(__func__, "get RPs for %s failed: %s",
		    sk->path, fido_strerr(r));
		जाओ out;
	}
	nrp = fido_credman_rp_गिनती(rp);
	skdebug(__func__, "Device %s has resident keys for %zu RPs",
	    sk->path, nrp);

	/* Iterate over RP IDs that have resident keys */
	क्रम (i = 0; i < nrp; i++) {
		rp_id = fido_credman_rp_id(rp, i);
		rp_name = fido_credman_rp_name(rp, i);
		skdebug(__func__, "rp %zu: name=\"%s\" id=\"%s\" hashlen=%zu",
		    i, rp_name == शून्य ? "(none)" : rp_name,
		    rp_id == शून्य ? "(none)" : rp_id,
		    fido_credman_rp_id_hash_len(rp, i));

		/* Skip non-SSH RP IDs */
		अगर (rp_id == शून्य ||
		    strncasecmp(fido_credman_rp_id(rp, i), "ssh:", 4) != 0)
			जारी;

		fido_credman_rk_free(&rk);
		अगर ((rk = fido_credman_rk_new()) == शून्य) {
			skdebug(__func__, "alloc rk failed");
			जाओ out;
		}
		अगर ((r = fido_credman_get_dev_rk(sk->dev,
		    fido_credman_rp_id(rp, i), rk, pin)) != 0) {
			skdebug(__func__, "get RKs for %s slot %zu failed: %s",
			    sk->path, i, fido_strerr(r));
			जाओ out;
		}
		nrk = fido_credman_rk_गिनती(rk);
		skdebug(__func__, "RP \"%s\" has %zu resident keys",
		    fido_credman_rp_id(rp, i), nrk);

		/* Iterate over resident keys for this RP ID */
		क्रम (j = 0; j < nrk; j++) {
			अगर ((cred = fido_credman_rk(rk, j)) == शून्य) {
				skdebug(__func__, "no RK in slot %zu", j);
				जारी;
			}
			अगर ((user_name = fido_cred_user_name(cred)) == शून्य)
				user_name = "";
			user_id = fido_cred_user_id_ptr(cred);
			user_id_len = fido_cred_user_id_len(cred);
			skdebug(__func__, "Device %s RP \"%s\" user \"%s\" "
			    "uidlen %zu slot %zu: type %d flags 0x%02x "
			    "prot 0x%02x", sk->path, rp_id, user_name,
			    user_id_len, j, fido_cred_type(cred),
			    fido_cred_flags(cred), fido_cred_prot(cred));

			/* Determine key algorithm */
			चयन (fido_cred_type(cred)) {
			हाल COSE_ES256:
				alg = SSH_SK_ECDSA;
				अवरोध;
			हाल COSE_EDDSA:
				alg = SSH_SK_ED25519;
				अवरोध;
			शेष:
				skdebug(__func__, "unsupported key type %d",
				    fido_cred_type(cred));
				जारी;
			}

			/* build response entry */
			अगर ((srk = सुस्मृति(1, माप(*srk))) == शून्य ||
			    (srk->कुंजी.कुंजी_handle = सुस्मृति(1,
			    fido_cred_id_len(cred))) == शून्य ||
			    (srk->application = strdup(rp_id)) == शून्य ||
			    (user_id_len > 0 &&
			     (srk->user_id = सुस्मृति(1, user_id_len)) == शून्य)) {
				skdebug(__func__, "alloc sk_resident_key");
				जाओ out;
			}

			srk->alg = alg;
			srk->कुंजी.कुंजी_handle_len = fido_cred_id_len(cred);
			स_नकल(srk->कुंजी.कुंजी_handle, fido_cred_id_ptr(cred),
			    srk->कुंजी.कुंजी_handle_len);
			srk->user_id_len = user_id_len;
			अगर (srk->user_id_len != 0)
				स_नकल(srk->user_id, user_id, srk->user_id_len);

#अगर_घोषित HAVE_FIDO_CRED_PROT
			अगर (fido_cred_prot(cred) ==
			    FIDO_CRED_PROT_UV_REQUIRED)
				srk->flags |=  SSH_SK_USER_VERIFICATION_REQD;
#पूर्ण_अगर

			अगर ((r = pack_public_कुंजी(srk->alg, cred,
			    &srk->कुंजी)) != 0) {
				skdebug(__func__, "pack public key failed");
				जाओ out;
			}
			/* append */
			अगर ((tmp = recallocarray(*rksp, *nrksp, (*nrksp) + 1,
			    माप(**rksp))) == शून्य) {
				skdebug(__func__, "alloc rksp");
				जाओ out;
			}
			*rksp = tmp;
			(*rksp)[(*nrksp)++] = srk;
			srk = शून्य;
		}
	}
	/* Success */
	ret = 0;
 out:
	अगर (srk != शून्य) {
		मुक्त(srk->application);
		freezero(srk->कुंजी.public_कुंजी, srk->कुंजी.public_कुंजी_len);
		freezero(srk->कुंजी.कुंजी_handle, srk->कुंजी.कुंजी_handle_len);
		freezero(srk->user_id, srk->user_id_len);
		freezero(srk, माप(*srk));
	}
	fido_credman_rp_free(&rp);
	fido_credman_rk_free(&rk);
	fido_credman_metadata_free(&metadata);
	वापस ret;
}

पूर्णांक
sk_load_resident_कुंजियाँ(स्थिर अक्षर *pin, काष्ठा sk_option **options,
    काष्ठा sk_resident_कुंजी ***rksp, माप_प्रकार *nrksp)
{
	पूर्णांक ret = SSH_SK_ERR_GENERAL, r = -1;
	माप_प्रकार i, nrks = 0;
	काष्ठा sk_resident_कुंजी **rks = शून्य;
	काष्ठा sk_usbhid *sk = शून्य;
	अक्षर *device = शून्य;

	*rksp = शून्य;
	*nrksp = 0;

	fido_init(SSH_FIDO_INIT_ARG);

	अगर (check_sign_load_resident_options(options, &device) != 0)
		जाओ out; /* error already logged */
	अगर (device != शून्य)
		sk = sk_open(device);
	अन्यथा
		sk = sk_probe(शून्य, शून्य, 0, 1);
	अगर (sk == शून्य) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		जाओ out;
	}
	skdebug(__func__, "trying %s", sk->path);
	अगर ((r = read_rks(sk, pin, &rks, &nrks)) != 0) {
		skdebug(__func__, "read_rks failed for %s", sk->path);
		ret = r;
		जाओ out;
	}
	/* success, unless we have no keys but a specific error */
	अगर (nrks > 0 || ret == SSH_SK_ERR_GENERAL)
		ret = 0;
	*rksp = rks;
	*nrksp = nrks;
	rks = शून्य;
	nrks = 0;
 out:
	sk_close(sk);
	क्रम (i = 0; i < nrks; i++) {
		मुक्त(rks[i]->application);
		freezero(rks[i]->कुंजी.public_कुंजी, rks[i]->कुंजी.public_कुंजी_len);
		freezero(rks[i]->कुंजी.कुंजी_handle, rks[i]->कुंजी.कुंजी_handle_len);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i], माप(*rks[i]));
	}
	मुक्त(device);
	मुक्त(rks);
	वापस ret;
}

#पूर्ण_अगर /* ENABLE_SK_INTERNAL */
