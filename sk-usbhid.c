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

#અન્તર્ભાવ "includes.h"

#ifdef ENABLE_SK_INTERNAL

#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <time.h>
#ifdef HAVE_SHA2_H
#અન્તર્ભાવ <sha2.h>
#endif

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/opensslv.h>
#અન્તર્ભાવ <openssl/crypto.h>
#અન્તર્ભાવ <openssl/bn.h>
#અન્તર્ભાવ <openssl/ec.h>
#અન્તર્ભાવ <openssl/ecdsa.h>
#અન્તર્ભાવ <openssl/evp.h>
#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"
#endif /* WITH_OPENSSL */

#અન્તર્ભાવ <fido.h>
#અન્તર્ભાવ <fido/credman.h>

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
# define sk_load_resident_ચાવીઓ	ssh_sk_load_resident_ચાવીઓ
#endif /* !SK_STANDALONE */

#અન્તર્ભાવ "sk-api.h"

/* #define SK_DEBUG 1 */

#ifdef SK_DEBUG
#define SSH_FIDO_INIT_ARG	FIDO_DEBUG
#નહીંતર
#define SSH_FIDO_INIT_ARG	0
#endif

#define MAX_FIDO_DEVICES	8
#define FIDO_POLL_MS		50
#define SELECT_MS		15000
#define POLL_SLEEP_NS		200000000

#ifndef FIDO_ERR_OPERATION_DENIED
#define FIDO_ERR_OPERATION_DENIED 0x27
#endif

સંરચના sk_usbhid {
	fido_dev_t *dev;
	અક્ષર *path;
};

/* Return the version of the middleware API */
uint32_t sk_api_version(શૂન્ય);

/* Enroll a U2F key (private key generation) */
પૂર્ણાંક sk_enroll(uint32_t alg, અચલ uint8_t *challenge, size_t challenge_len,
    અચલ અક્ષર *application, uint8_t flags, અચલ અક્ષર *pin,
    સંરચના sk_option **options, સંરચના sk_enroll_response **enroll_response);

/* Sign a challenge */
પૂર્ણાંક sk_sign(uint32_t alg, અચલ uint8_t *data, size_t data_len,
    અચલ અક્ષર *application, અચલ uint8_t *ચાવી_handle, size_t ચાવી_handle_len,
    uint8_t flags, અચલ અક્ષર *pin, સંરચના sk_option **options,
    સંરચના sk_sign_response **sign_response);

/* Load resident keys */
પૂર્ણાંક sk_load_resident_ચાવીઓ(અચલ અક્ષર *pin, સંરચના sk_option **options,
    સંરચના sk_resident_ચાવી ***rks, size_t *nrks);

સ્થિર શૂન્ય skdebug(અચલ અક્ષર *func, અચલ અક્ષર *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

સ્થિર શૂન્ય
skdebug(અચલ અક્ષર *func, અચલ અક્ષર *fmt, ...)
{
#જો !defined(SK_STANDALONE)
	અક્ષર *સંદેશ;
	va_list ap;

	va_start(ap, fmt);
	xvasprintf(&સંદેશ, fmt, ap);
	va_end(ap);
	debug("%s: %s", func, સંદેશ);
	મુક્ત(સંદેશ);
#અથવાજો defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#નહીંતર
	(શૂન્ય)func; /* XXX */
	(શૂન્ય)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(શૂન્ય)
{
	પાછા SSH_SK_VERSION_MAJOR;
}

સ્થિર સંરચના sk_usbhid *
sk_open(અચલ અક્ષર *path)
{
	સંરચના sk_usbhid *sk;
	પૂર્ણાંક r;

	જો (path == ખાલી) {
		skdebug(__func__, "path == NULL");
		પાછા ખાલી;
	}
	જો ((sk = calloc(1, કદ(*sk))) == ખાલી) {
		skdebug(__func__, "calloc sk failed");
		પાછા ખાલી;
	}
	જો ((sk->path = strdup(path)) == ખાલી) {
		skdebug(__func__, "strdup path failed");
		મુક્ત(sk);
		પાછા ખાલી;
	}
	જો ((sk->dev = fido_dev_new()) == ખાલી) {
		skdebug(__func__, "fido_dev_new failed");
		મુક્ત(sk->path);
		મુક્ત(sk);
		પાછા ખાલી;
	}
	જો ((r = fido_dev_open(sk->dev, sk->path)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_open %s failed: %s", sk->path,
		    fido_strerr(r));
		fido_dev_free(&sk->dev);
		મુક્ત(sk->path);
		મુક્ત(sk);
		પાછા ખાલી;
	}
	પાછા sk;
}

સ્થિર શૂન્ય
sk_close(સંરચના sk_usbhid *sk)
{
	જો (sk == ખાલી)
		પાછા;
	fido_dev_cancel(sk->dev); /* cancel any pending operation */
	fido_dev_close(sk->dev);
	fido_dev_free(&sk->dev);
	મુક્ત(sk->path);
	મુક્ત(sk);
}

સ્થિર સંરચના sk_usbhid **
sk_openv(અચલ fido_dev_info_t *devlist, size_t ndevs, size_t *nopen)
{
	અચલ fido_dev_info_t *di;
	સંરચના sk_usbhid **skv;
	size_t i;

	*nopen = 0;
	જો ((skv = calloc(ndevs, કદ(*skv))) == ખાલી) {
		skdebug(__func__, "calloc skv failed");
		પાછા ખાલી;
	}
	માટે (i = 0; i < ndevs; i++) {
		જો ((di = fido_dev_info_ptr(devlist, i)) == ખાલી)
			skdebug(__func__, "fido_dev_info_ptr failed");
		નહીંતર જો ((skv[*nopen] = sk_open(fido_dev_info_path(di))) == ખાલી)
			skdebug(__func__, "sk_open failed");
		નહીંતર
			(*nopen)++;
	}
	જો (*nopen == 0) {
		માટે (i = 0; i < ndevs; i++)
			sk_close(skv[i]);
		મુક્ત(skv);
		skv = ખાલી;
	}

	પાછા skv;
}

સ્થિર શૂન્ય
sk_closev(સંરચના sk_usbhid **skv, size_t nsk)
{
	size_t i;

	માટે (i = 0; i < nsk; i++)
		sk_close(skv[i]);
	મુક્ત(skv);
}

સ્થિર પૂર્ણાંક
sk_touch_begin(સંરચના sk_usbhid **skv, size_t nsk)
{
	size_t i, ok = 0;
	પૂર્ણાંક r;

	માટે (i = 0; i < nsk; i++)
		જો ((r = fido_dev_get_touch_begin(skv[i]->dev)) != FIDO_OK)
			skdebug(__func__, "fido_dev_get_touch_begin %s failed:"
			    " %s", skv[i]->path, fido_strerr(r));
		નહીંતર
			ok++;

	પાછા ok ? 0 : -1;
}

સ્થિર પૂર્ણાંક
sk_touch_poll(સંરચના sk_usbhid **skv, size_t nsk, પૂર્ણાંક *touch, size_t *idx)
{
	સંરચના timespec ts_pause;
	size_t npoll, i;
	પૂર્ણાંક r;

	ts_pause.tv_sec = 0;
	ts_pause.tv_nsec = POLL_SLEEP_NS;
	nanosleep(&ts_pause, ખાલી);
	npoll = nsk;
	માટે (i = 0; i < nsk; i++) {
		જો (skv[i] == ખાલી)
			ચાલુ; /* device discarded */
		skdebug(__func__, "polling %s", skv[i]->path);
		જો ((r = fido_dev_get_touch_status(skv[i]->dev, touch,
		    FIDO_POLL_MS)) != FIDO_OK) {
			skdebug(__func__, "fido_dev_get_touch_status %s: %s",
			    skv[i]->path, fido_strerr(r));
			sk_close(skv[i]); /* discard device */
			skv[i] = ખાલી;
			જો (--npoll == 0) {
				skdebug(__func__, "no device left to poll");
				પાછા -1;
			}
		} નહીંતર જો (*touch) {
			*idx = i;
			પાછા 0;
		}
	}
	*touch = 0;
	પાછા 0;
}

#જો !defined(HAVE_FIDO_ASSERT_SET_CLIENTDATA) || \
    !defined(HAVE_FIDO_CRED_SET_CLIENTDATA)
/* Calculate SHA256(m) */
સ્થિર પૂર્ણાંક
sha256_mem(અચલ શૂન્ય *m, size_t mlen, u_char *d, size_t dlen)
{
#ifdef WITH_OPENSSL
	u_int mdlen;
#નહીંતર
	SHA2_CTX ctx;
#endif

	જો (dlen != 32)
		પાછા -1;
#ifdef WITH_OPENSSL
	mdlen = dlen;
	જો (!EVP_Digest(m, mlen, d, &mdlen, EVP_sha256(), ખાલી))
		પાછા -1;
#નહીંતર
	SHA256Init(&ctx);
	SHA256Update(&ctx, (અચલ uint8_t *)m, mlen);
	SHA256Final(d, &ctx);
#endif
	પાછા 0;
}
#endif /* !HAVE_FIDO_ASSERT_SET_CLIENTDATA || !HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_CRED_SET_CLIENTDATA
સ્થિર પૂર્ણાંક
fido_cred_set_clientdata(fido_cred_t *cred, અચલ u_char *ptr, size_t len)
{
	uint8_t d[32];
	પૂર્ણાંક r;

	જો (sha256_mem(ptr, len, d, કદ(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		પાછા FIDO_ERR_INTERNAL;
	}
	r = fido_cred_set_clientdata_hash(cred, d, કદ(d));
	explicit_bzero(d, કદ(d));
	જો (r != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	પાછા r;
}
#endif /* HAVE_FIDO_CRED_SET_CLIENTDATA */

#ifndef HAVE_FIDO_ASSERT_SET_CLIENTDATA
સ્થિર પૂર્ણાંક
fido_assert_set_clientdata(fido_assert_t *પ્રતિજ્ઞા, અચલ u_char *ptr, size_t len)
{
	uint8_t d[32];
	પૂર્ણાંક r;

	જો (sha256_mem(ptr, len, d, કદ(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		પાછા FIDO_ERR_INTERNAL;
	}
	r = fido_assert_set_clientdata_hash(પ્રતિજ્ઞા, d, કદ(d));
	explicit_bzero(d, કદ(d));
	જો (r != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	પાછા r;
}
#endif /* HAVE_FIDO_ASSERT_SET_CLIENTDATA */

#ifndef HAVE_FIDO_DEV_IS_WINHELLO
સ્થિર bool
fido_dev_is_winhello(અચલ fido_dev_t *fdev)
{
	પાછા 0;
}
#endif /* HAVE_FIDO_DEV_IS_WINHELLO */

/* Check if the specified key handle exists on a given sk. */
સ્થિર પૂર્ણાંક
sk_try(અચલ સંરચના sk_usbhid *sk, અચલ અક્ષર *application,
    અચલ uint8_t *ચાવી_handle, size_t ચાવી_handle_len)
{
	fido_assert_t *પ્રતિજ્ઞા = ખાલી;
	પૂર્ણાંક r = FIDO_ERR_INTERNAL;
	uint8_t message[32];

	memset(message, '\0', કદ(message));
	જો ((પ્રતિજ્ઞા = fido_assert_new()) == ખાલી) {
		skdebug(__func__, "fido_assert_new failed");
		જાઓ out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	જો ((r = fido_assert_set_clientdata(પ્રતિજ્ઞા, message,
	    કદ(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		જાઓ out;
	}
	જો ((r = fido_assert_set_rp(પ્રતિજ્ઞા, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		જાઓ out;
	}
	જો ((r = fido_assert_allow_cred(પ્રતિજ્ઞા, ચાવી_handle,
	    ચાવી_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		જાઓ out;
	}
	જો ((r = fido_assert_set_up(પ્રતિજ્ઞા, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_up: %s", fido_strerr(r));
		જાઓ out;
	}
	r = fido_dev_get_assert(sk->dev, પ્રતિજ્ઞા, ખાલી);
	skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
	જો (r == FIDO_ERR_USER_PRESENCE_REQUIRED) {
		/* U2F tokens may return this */
		r = FIDO_OK;
	}
 out:
	fido_assert_free(&પ્રતિજ્ઞા);

	પાછા r != FIDO_OK ? -1 : 0;
}

સ્થિર પૂર્ણાંક
check_sk_options(fido_dev_t *dev, અચલ અક્ષર *opt, પૂર્ણાંક *ret)
{
	fido_cbor_info_t *info;
	અક્ષર * અચલ *name;
	અચલ bool *કિંમત;
	size_t len, i;
	પૂર્ણાંક r;

	*ret = -1;

	જો (!fido_dev_is_fido2(dev)) {
		skdebug(__func__, "device is not fido2");
		પાછા 0;
	}
	જો ((info = fido_cbor_info_new()) == ખાલી) {
		skdebug(__func__, "fido_cbor_info_new failed");
		પાછા -1;
	}
	જો ((r = fido_dev_get_cbor_info(dev, info)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_cbor_info: %s", fido_strerr(r));
		fido_cbor_info_free(&info);
		પાછા -1;
	}
	name = fido_cbor_info_options_name_ptr(info);
	કિંમત = fido_cbor_info_options_કિંમત_ptr(info);
	len = fido_cbor_info_options_len(info);
	માટે (i = 0; i < len; i++) {
		જો (!strcmp(name[i], opt)) {
			*ret = કિંમત[i];
			તોડો;
		}
	}
	fido_cbor_info_free(&info);
	જો (*ret == -1)
		skdebug(__func__, "option %s is unknown", opt);
	નહીંતર
		skdebug(__func__, "option %s is %s", opt, *ret ? "on" : "off");

	પાછા 0;
}

સ્થિર સંરચના sk_usbhid *
sk_select_by_cred(અચલ fido_dev_info_t *devlist, size_t ndevs,
    અચલ અક્ષર *application, અચલ uint8_t *ચાવી_handle, size_t ચાવી_handle_len)
{
	સંરચના sk_usbhid **skv, *sk;
	size_t skvcnt, i;
	પૂર્ણાંક internal_uv;

	જો ((skv = sk_openv(devlist, ndevs, &skvcnt)) == ખાલી) {
		skdebug(__func__, "sk_openv failed");
		પાછા ખાલી;
	}
	જો (skvcnt == 1 && check_sk_options(skv[0]->dev, "uv",
	    &internal_uv) == 0 && internal_uv != -1) {
		sk = skv[0];
		skv[0] = ખાલી;
		જાઓ out;
	}
	sk = ખાલી;
	માટે (i = 0; i < skvcnt; i++) {
		જો (sk_try(skv[i], application, ચાવી_handle,
		    ચાવી_handle_len) == 0) {
			sk = skv[i];
			skv[i] = ખાલી;
			skdebug(__func__, "found key in %s", sk->path);
			તોડો;
		}
	}
 out:
	sk_closev(skv, skvcnt);
	પાછા sk;
}

સ્થિર સંરચના sk_usbhid *
sk_select_by_touch(અચલ fido_dev_info_t *devlist, size_t ndevs)
{
	સંરચના sk_usbhid **skv, *sk;
	સંરચના timeval tv_start, tv_now, tv_delta;
	size_t skvcnt, idx;
	પૂર્ણાંક touch, ms_remain;

	જો ((skv = sk_openv(devlist, ndevs, &skvcnt)) == ખાલી) {
		skdebug(__func__, "sk_openv failed");
		પાછા ખાલી;
	}
	sk = ખાલી;
	જો (skvcnt < 2) {
		જો (skvcnt == 1) {
			/* single candidate */
			sk = skv[0];
			skv[0] = ખાલી;
		}
		જાઓ out;
	}
#ifndef HAVE_FIDO_DEV_GET_TOUCH_STATUS
	skdebug(__func__, "libfido2 version does not support a feature needed for multiple tokens. Please upgrade to >=1.5.0");
	જાઓ out;
#endif

	જો (sk_touch_begin(skv, skvcnt) == -1) {
		skdebug(__func__, "sk_touch_begin failed");
		જાઓ out;
	}
	monotime_tv(&tv_start);
	કરો {
		જો (sk_touch_poll(skv, skvcnt, &touch, &idx) == -1) {
			skdebug(__func__, "sk_touch_poll failed");
			જાઓ out;
		}
		જો (touch) {
			sk = skv[idx];
			skv[idx] = ખાલી;
			જાઓ out;
		}
		monotime_tv(&tv_now);
		timersub(&tv_now, &tv_start, &tv_delta);
		ms_remain = SELECT_MS - tv_delta.tv_sec * 1000 -
		    tv_delta.tv_usec / 1000;
	} જ્યારે (ms_remain >= FIDO_POLL_MS);
	skdebug(__func__, "timeout");
out:
	sk_closev(skv, skvcnt);
	પાછા sk;
}

સ્થિર સંરચના sk_usbhid *
sk_probe(અચલ અક્ષર *application, અચલ uint8_t *ચાવી_handle,
    size_t ચાવી_handle_len, પૂર્ણાંક probe_resident)
{
	સંરચના sk_usbhid *sk;
	fido_dev_info_t *devlist;
	size_t ndevs;
	પૂર્ણાંક r;

#ifdef HAVE_CYGWIN
	જો (!probe_resident && (sk = sk_open("windows://hello")) != ખાલી)
		પાછા sk;
#endif /* HAVE_CYGWIN */
	જો ((devlist = fido_dev_info_new(MAX_FIDO_DEVICES)) == ખાલી) {
		skdebug(__func__, "fido_dev_info_new failed");
		પાછા ખાલી;
	}
	જો ((r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES,
	    &ndevs)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_info_manifest failed: %s",
		    fido_strerr(r));
		fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
		પાછા ખાલી;
	}
	skdebug(__func__, "%zu device(s) detected", ndevs);
	જો (ndevs == 0) {
		sk = ખાલી;
	} નહીંતર જો (application != ખાલી && ચાવી_handle != ખાલી) {
		skdebug(__func__, "selecting sk by cred");
		sk = sk_select_by_cred(devlist, ndevs, application, ચાવી_handle,
		    ચાવી_handle_len);
	} નહીંતર {
		skdebug(__func__, "selecting sk by touch");
		sk = sk_select_by_touch(devlist, ndevs);
	}
	fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
	પાછા sk;
}

#ifdef WITH_OPENSSL
/*
 * The key returned via fido_cred_pubkey_ptr() is in affine coordinates,
 * but the API expects a SEC1 octet string.
 */
સ્થિર પૂર્ણાંક
pack_public_ચાવી_ecdsa(અચલ fido_cred_t *cred,
    સંરચના sk_enroll_response *response)
{
	અચલ uint8_t *ptr;
	BIGNUM *x = ખાલી, *y = ખાલી;
	EC_POINT *q = ખાલી;
	EC_GROUP *g = ખાલી;
	પૂર્ણાંક ret = -1;

	response->public_ચાવી = ખાલી;
	response->public_ચાવી_len = 0;

	જો ((x = BN_new()) == ખાલી ||
	    (y = BN_new()) == ખાલી ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == ખાલી ||
	    (q = EC_POINT_new(g)) == ખાલી) {
		skdebug(__func__, "libcrypto setup failed");
		જાઓ out;
	}
	જો ((ptr = fido_cred_pubkey_ptr(cred)) == ખાલી) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		જાઓ out;
	}
	જો (fido_cred_pubkey_len(cred) != 64) {
		skdebug(__func__, "bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		જાઓ out;
	}

	જો (BN_bin2bn(ptr, 32, x) == ખાલી ||
	    BN_bin2bn(ptr + 32, 32, y) == ખાલી) {
		skdebug(__func__, "BN_bin2bn failed");
		જાઓ out;
	}
	જો (EC_POINT_set_affine_coordinates(g, q, x, y, ખાલી) != 1) {
		skdebug(__func__, "EC_POINT_set_affine_coordinates failed");
		જાઓ out;
	}
	response->public_ચાવી_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, ખાલી, 0, ખાલી);
	જો (response->public_ચાવી_len == 0 || response->public_ચાવી_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_ચાવી_len);
		જાઓ out;
	}
	જો ((response->public_ચાવી = malloc(response->public_ચાવી_len)) == ખાલી) {
		skdebug(__func__, "malloc pubkey failed");
		જાઓ out;
	}
	જો (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_ચાવી, response->public_ચાવી_len, ખાલી) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		જાઓ out;
	}
	/* success */
	ret = 0;
 out:
	જો (ret != 0 && response->public_ચાવી != ખાલી) {
		memset(response->public_ચાવી, 0, response->public_ચાવી_len);
		મુક્ત(response->public_ચાવી);
		response->public_ચાવી = ખાલી;
	}
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	પાછા ret;
}
#endif /* WITH_OPENSSL */

સ્થિર પૂર્ણાંક
pack_public_ચાવી_ed25519(અચલ fido_cred_t *cred,
    સંરચના sk_enroll_response *response)
{
	અચલ uint8_t *ptr;
	size_t len;
	પૂર્ણાંક ret = -1;

	response->public_ચાવી = ખાલી;
	response->public_ચાવી_len = 0;

	જો ((len = fido_cred_pubkey_len(cred)) != 32) {
		skdebug(__func__, "bad fido_cred_pubkey_len len %zu", len);
		જાઓ out;
	}
	જો ((ptr = fido_cred_pubkey_ptr(cred)) == ખાલી) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		જાઓ out;
	}
	response->public_ચાવી_len = len;
	જો ((response->public_ચાવી = malloc(response->public_ચાવી_len)) == ખાલી) {
		skdebug(__func__, "malloc pubkey failed");
		જાઓ out;
	}
	memcpy(response->public_ચાવી, ptr, len);
	ret = 0;
 out:
	જો (ret != 0)
		મુક્ત(response->public_ચાવી);
	પાછા ret;
}

સ્થિર પૂર્ણાંક
pack_public_ચાવી(uint32_t alg, અચલ fido_cred_t *cred,
    સંરચના sk_enroll_response *response)
{
	પસંદગી(alg) {
#ifdef WITH_OPENSSL
	સ્થિતિ SSH_SK_ECDSA:
		પાછા pack_public_ચાવી_ecdsa(cred, response);
#endif /* WITH_OPENSSL */
	સ્થિતિ SSH_SK_ED25519:
		પાછા pack_public_ચાવી_ed25519(cred, response);
	મૂળભૂત:
		પાછા -1;
	}
}

સ્થિર પૂર્ણાંક
fidoerr_to_skerr(પૂર્ણાંક fidoerr)
{
	પસંદગી (fidoerr) {
	સ્થિતિ FIDO_ERR_UNSUPPORTED_OPTION:
	સ્થિતિ FIDO_ERR_UNSUPPORTED_ALGORITHM:
		પાછા SSH_SK_ERR_UNSUPPORTED;
	સ્થિતિ FIDO_ERR_PIN_REQUIRED:
	સ્થિતિ FIDO_ERR_PIN_INVALID:
	સ્થિતિ FIDO_ERR_OPERATION_DENIED:
		પાછા SSH_SK_ERR_PIN_REQUIRED;
	મૂળભૂત:
		પાછા -1;
	}
}

સ્થિર પૂર્ણાંક
check_enroll_options(સંરચના sk_option **options, અક્ષર **devicep,
    uint8_t *user_id, size_t user_id_len)
{
	size_t i;

	જો (options == ખાલી)
		પાછા 0;
	માટે (i = 0; options[i] != ખાલી; i++) {
		જો (strcmp(options[i]->name, "device") == 0) {
			જો ((*devicep = strdup(options[i]->કિંમત)) == ખાલી) {
				skdebug(__func__, "strdup device failed");
				પાછા -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} નહીંતર જો (strcmp(options[i]->name, "user") == 0) {
			જો (strlcpy(user_id, options[i]->કિંમત, user_id_len) >=
			    user_id_len) {
				skdebug(__func__, "user too long");
				પાછા -1;
			}
			skdebug(__func__, "requested user %s",
			    (અક્ષર *)user_id);
		} નહીંતર {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			જો (options[i]->required) {
				skdebug(__func__, "unknown required option");
				પાછા -1;
			}
		}
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
ચાવી_lookup(fido_dev_t *dev, અચલ અક્ષર *application, અચલ uint8_t *user_id,
    size_t user_id_len, અચલ અક્ષર *pin)
{
	fido_assert_t *પ્રતિજ્ઞા = ખાલી;
	uint8_t message[32];
	પૂર્ણાંક r = FIDO_ERR_INTERNAL;
	પૂર્ણાંક sk_supports_uv, uv;
	size_t i;

	memset(message, '\0', કદ(message));
	જો ((પ્રતિજ્ઞા = fido_assert_new()) == ખાલી) {
		skdebug(__func__, "fido_assert_new failed");
		જાઓ out;
	}
	/* generate an invalid signature on FIDO2 tokens */
	જો ((r = fido_assert_set_clientdata(પ્રતિજ્ઞા, message,
	    કદ(message))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		જાઓ out;
	}
	જો ((r = fido_assert_set_rp(પ્રતિજ્ઞા, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		જાઓ out;
	}
	જો ((r = fido_assert_set_up(પ્રતિજ્ઞા, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		જાઓ out;
	}
	uv = FIDO_OPT_OMIT;
	જો (pin == ખાલી && check_sk_options(dev, "uv", &sk_supports_uv) == 0 &&
	    sk_supports_uv != -1)
		uv = FIDO_OPT_TRUE;
	જો ((r = fido_assert_set_uv(પ્રતિજ્ઞા, uv)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
		જાઓ out;
	}
	જો ((r = fido_dev_get_assert(dev, પ્રતિજ્ઞા, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		જાઓ out;
	}
	r = FIDO_ERR_NO_CREDENTIALS;
	skdebug(__func__, "%zu signatures returned", fido_assert_ગણતરી(પ્રતિજ્ઞા));
	માટે (i = 0; i < fido_assert_ગણતરી(પ્રતિજ્ઞા); i++) {
		જો (fido_assert_user_id_len(પ્રતિજ્ઞા, i) == user_id_len &&
		    memcmp(fido_assert_user_id_ptr(પ્રતિજ્ઞા, i), user_id,
		    user_id_len) == 0) {
			skdebug(__func__, "credential exists");
			r = FIDO_OK;
			જાઓ out;
		}
	}
 out:
	fido_assert_free(&પ્રતિજ્ઞા);

	પાછા r;
}

પૂર્ણાંક
sk_enroll(uint32_t alg, અચલ uint8_t *challenge, size_t challenge_len,
    અચલ અક્ષર *application, uint8_t flags, અચલ અક્ષર *pin,
    સંરચના sk_option **options, સંરચના sk_enroll_response **enroll_response)
{
	fido_cred_t *cred = ખાલી;
	અચલ uint8_t *ptr;
	uint8_t user_id[32];
	સંરચના sk_usbhid *sk = ખાલી;
	સંરચના sk_enroll_response *response = ખાલી;
	size_t len;
	પૂર્ણાંક credprot;
	પૂર્ણાંક cose_alg;
	પૂર્ણાંક ret = SSH_SK_ERR_GENERAL;
	પૂર્ણાંક r;
	અક્ષર *device = ખાલી;

	fido_init(SSH_FIDO_INIT_ARG);

	જો (enroll_response == ખાલી) {
		skdebug(__func__, "enroll_response == NULL");
		જાઓ out;
	}
	*enroll_response = ખાલી;
	memset(user_id, 0, કદ(user_id));
	જો (check_enroll_options(options, &device, user_id,
	    કદ(user_id)) != 0)
		જાઓ out; /* error already logged */

	પસંદગી(alg) {
#ifdef WITH_OPENSSL
	સ્થિતિ SSH_SK_ECDSA:
		cose_alg = COSE_ES256;
		તોડો;
#endif /* WITH_OPENSSL */
	સ્થિતિ SSH_SK_ED25519:
		cose_alg = COSE_EDDSA;
		તોડો;
	મૂળભૂત:
		skdebug(__func__, "unsupported key type %d", alg);
		જાઓ out;
	}
	જો (device != ખાલી)
		sk = sk_open(device);
	નહીંતર
		sk = sk_probe(ખાલી, ખાલી, 0, 0);
	જો (sk == ખાલી) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		જાઓ out;
	}
	skdebug(__func__, "using device %s", sk->path);
	જો ((flags & SSH_SK_RESIDENT_ચાવી) != 0 &&
	    (flags & SSH_SK_FORCE_OPERATION) == 0 &&
	    (r = ચાવી_lookup(sk->dev, application, user_id, કદ(user_id),
	    pin)) != FIDO_ERR_NO_CREDENTIALS) {
		જો (r != FIDO_OK) {
			ret = fidoerr_to_skerr(r);
			skdebug(__func__, "key_lookup failed");
		} નહીંતર {
			ret = SSH_SK_ERR_CREDENTIAL_EXISTS;
			skdebug(__func__, "key exists");
		}
		જાઓ out;
	}
	જો ((cred = fido_cred_new()) == ખાલી) {
		skdebug(__func__, "fido_cred_new failed");
		જાઓ out;
	}
	જો ((r = fido_cred_set_type(cred, cose_alg)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_type: %s", fido_strerr(r));
		જાઓ out;
	}
	જો ((r = fido_cred_set_clientdata(cred,
	    challenge, challenge_len)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata: %s",
		    fido_strerr(r));
		જાઓ out;
	}
	જો ((r = fido_cred_set_rk(cred, (flags & SSH_SK_RESIDENT_ચાવી) != 0 ?
	    FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rk: %s", fido_strerr(r));
		જાઓ out;
	}
	જો ((r = fido_cred_set_user(cred, user_id, કદ(user_id),
	    "openssh", "openssh", ખાલી)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_user: %s", fido_strerr(r));
		જાઓ out;
	}
	જો ((r = fido_cred_set_rp(cred, application, ખાલી)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rp: %s", fido_strerr(r));
		જાઓ out;
	}
	જો ((flags & (SSH_SK_RESIDENT_ચાવી|SSH_SK_USER_VERIFICATION_REQD)) != 0) {
#જો !defined(HAVE_FIDO_DEV_SUPPORTS_CRED_PROT) || \
    !defined(HAVE_FIDO_CRED_SET_PROT)
		skdebug(__func__, "libfido2 version does not support a feature required for this operation. Please upgrade to >=1.5.0");
		ret = SSH_SK_ERR_UNSUPPORTED;
		જાઓ out;
		credprot = 0; (શૂન્ય)credprot; /* avoid warning */
#endif
		જો (!fido_dev_supports_cred_prot(sk->dev)) {
			skdebug(__func__, "%s does not support credprot, "
			    "refusing to create unprotected "
			    "resident/verify-required key", sk->path);
			ret = SSH_SK_ERR_UNSUPPORTED;
			જાઓ out;
		}
		જો ((flags & SSH_SK_USER_VERIFICATION_REQD))
			credprot = FIDO_CRED_PROT_UV_REQUIRED;
		નહીંતર
			credprot = FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID;

		જો ((r = fido_cred_set_prot(cred, credprot)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_set_prot: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			જાઓ out;
		}
	}
	જો ((r = fido_dev_make_cred(sk->dev, cred, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_make_cred: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		જાઓ out;
	}
	જો (fido_cred_x5c_ptr(cred) != ખાલી) {
		જો ((r = fido_cred_verify(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify: %s",
			    fido_strerr(r));
			જાઓ out;
		}
	} નહીંતર જો (strcmp(fido_cred_fmt(cred), "none") != 0) {
		skdebug(__func__, "self-attested credential");
		જો ((r = fido_cred_verify_self(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify_self: %s",
			    fido_strerr(r));
			જાઓ out;
		}
	} નહીંતર {
		skdebug(__func__, "no attestation data");
	}
	જો ((response = calloc(1, કદ(*response))) == ખાલી) {
		skdebug(__func__, "calloc response failed");
		જાઓ out;
	}
	response->flags = flags;
	જો (pack_public_ચાવી(alg, cred, response) != 0) {
		skdebug(__func__, "pack_public_key failed");
		જાઓ out;
	}
	જો ((ptr = fido_cred_id_ptr(cred)) != ખાલી) {
		len = fido_cred_id_len(cred);
		જો ((response->ચાવી_handle = calloc(1, len)) == ખાલી) {
			skdebug(__func__, "calloc key handle failed");
			જાઓ out;
		}
		memcpy(response->ચાવી_handle, ptr, len);
		response->ચાવી_handle_len = len;
	}
	જો ((ptr = fido_cred_sig_ptr(cred)) != ખાલી) {
		len = fido_cred_sig_len(cred);
		જો ((response->signature = calloc(1, len)) == ખાલી) {
			skdebug(__func__, "calloc signature failed");
			જાઓ out;
		}
		memcpy(response->signature, ptr, len);
		response->signature_len = len;
	}
	જો ((ptr = fido_cred_x5c_ptr(cred)) != ખાલી) {
		len = fido_cred_x5c_len(cred);
		skdebug(__func__, "attestation cert len=%zu", len);
		જો ((response->attestation_cert = calloc(1, len)) == ખાલી) {
			skdebug(__func__, "calloc attestation cert failed");
			જાઓ out;
		}
		memcpy(response->attestation_cert, ptr, len);
		response->attestation_cert_len = len;
	}
	જો ((ptr = fido_cred_authdata_ptr(cred)) != ખાલી) {
		len = fido_cred_authdata_len(cred);
		skdebug(__func__, "authdata len=%zu", len);
		જો ((response->authdata = calloc(1, len)) == ખાલી) {
			skdebug(__func__, "calloc authdata failed");
			જાઓ out;
		}
		memcpy(response->authdata, ptr, len);
		response->authdata_len = len;
	}
	*enroll_response = response;
	response = ખાલી;
	ret = 0;
 out:
	મુક્ત(device);
	જો (response != ખાલી) {
		મુક્ત(response->public_ચાવી);
		મુક્ત(response->ચાવી_handle);
		મુક્ત(response->signature);
		મુક્ત(response->attestation_cert);
		મુક્ત(response->authdata);
		મુક્ત(response);
	}
	sk_close(sk);
	fido_cred_free(&cred);
	પાછા ret;
}

#ifdef WITH_OPENSSL
સ્થિર પૂર્ણાંક
pack_sig_ecdsa(fido_assert_t *પ્રતિજ્ઞા, સંરચના sk_sign_response *response)
{
	ECDSA_SIG *sig = ખાલી;
	અચલ BIGNUM *sig_r, *sig_s;
	અચલ unsigned અક્ષર *cp;
	size_t sig_len;
	પૂર્ણાંક ret = -1;

	cp = fido_assert_sig_ptr(પ્રતિજ્ઞા, 0);
	sig_len = fido_assert_sig_len(પ્રતિજ્ઞા, 0);
	જો ((sig = d2i_ECDSA_SIG(ખાલી, &cp, sig_len)) == ખાલી) {
		skdebug(__func__, "d2i_ECDSA_SIG failed");
		જાઓ out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_અંક_bytes(sig_r);
	response->sig_s_len = BN_અંક_bytes(sig_s);
	જો ((response->sig_r = calloc(1, response->sig_r_len)) == ખાલી ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == ખાલી) {
		skdebug(__func__, "calloc signature failed");
		જાઓ out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	ECDSA_SIG_free(sig);
	જો (ret != 0) {
		મુક્ત(response->sig_r);
		મુક્ત(response->sig_s);
		response->sig_r = ખાલી;
		response->sig_s = ખાલી;
	}
	પાછા ret;
}
#endif /* WITH_OPENSSL */

સ્થિર પૂર્ણાંક
pack_sig_ed25519(fido_assert_t *પ્રતિજ્ઞા, સંરચના sk_sign_response *response)
{
	અચલ unsigned અક્ષર *ptr;
	size_t len;
	પૂર્ણાંક ret = -1;

	ptr = fido_assert_sig_ptr(પ્રતિજ્ઞા, 0);
	len = fido_assert_sig_len(પ્રતિજ્ઞા, 0);
	જો (len != 64) {
		skdebug(__func__, "bad length %zu", len);
		જાઓ out;
	}
	response->sig_r_len = len;
	જો ((response->sig_r = calloc(1, response->sig_r_len)) == ખાલી) {
		skdebug(__func__, "calloc signature failed");
		જાઓ out;
	}
	memcpy(response->sig_r, ptr, len);
	ret = 0;
 out:
	જો (ret != 0) {
		મુક્ત(response->sig_r);
		response->sig_r = ખાલી;
	}
	પાછા ret;
}

સ્થિર પૂર્ણાંક
pack_sig(uint32_t  alg, fido_assert_t *પ્રતિજ્ઞા,
    સંરચના sk_sign_response *response)
{
	પસંદગી(alg) {
#ifdef WITH_OPENSSL
	સ્થિતિ SSH_SK_ECDSA:
		પાછા pack_sig_ecdsa(પ્રતિજ્ઞા, response);
#endif /* WITH_OPENSSL */
	સ્થિતિ SSH_SK_ED25519:
		પાછા pack_sig_ed25519(પ્રતિજ્ઞા, response);
	મૂળભૂત:
		પાછા -1;
	}
}

/* Checks sk_options for sk_sign() and sk_load_resident_keys() */
સ્થિર પૂર્ણાંક
check_sign_load_resident_options(સંરચના sk_option **options, અક્ષર **devicep)
{
	size_t i;

	જો (options == ખાલી)
		પાછા 0;
	માટે (i = 0; options[i] != ખાલી; i++) {
		જો (strcmp(options[i]->name, "device") == 0) {
			જો ((*devicep = strdup(options[i]->કિંમત)) == ખાલી) {
				skdebug(__func__, "strdup device failed");
				પાછા -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} નહીંતર {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			જો (options[i]->required) {
				skdebug(__func__, "unknown required option");
				પાછા -1;
			}
		}
	}
	પાછા 0;
}

પૂર્ણાંક
sk_sign(uint32_t alg, અચલ uint8_t *data, size_t datalen,
    અચલ અક્ષર *application,
    અચલ uint8_t *ચાવી_handle, size_t ચાવી_handle_len,
    uint8_t flags, અચલ અક્ષર *pin, સંરચના sk_option **options,
    સંરચના sk_sign_response **sign_response)
{
	fido_assert_t *પ્રતિજ્ઞા = ખાલી;
	અક્ષર *device = ખાલી;
	સંરચના sk_usbhid *sk = ખાલી;
	સંરચના sk_sign_response *response = ખાલી;
	પૂર્ણાંક ret = SSH_SK_ERR_GENERAL, internal_uv;
	પૂર્ણાંક r;

	fido_init(SSH_FIDO_INIT_ARG);

	જો (sign_response == ખાલી) {
		skdebug(__func__, "sign_response == NULL");
		જાઓ out;
	}
	*sign_response = ખાલી;
	જો (check_sign_load_resident_options(options, &device) != 0)
		જાઓ out; /* error already logged */
	જો (device != ખાલી)
		sk = sk_open(device);
	નહીંતર જો (pin != ખાલી || (flags & SSH_SK_USER_VERIFICATION_REQD))
		sk = sk_probe(ખાલી, ખાલી, 0, 0);
	નહીંતર
		sk = sk_probe(application, ચાવી_handle, ચાવી_handle_len, 0);
	જો (sk == ખાલી) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		જાઓ out;
	}
	જો ((પ્રતિજ્ઞા = fido_assert_new()) == ખાલી) {
		skdebug(__func__, "fido_assert_new failed");
		જાઓ out;
	}
	જો ((r = fido_assert_set_clientdata(પ્રતિજ્ઞા,
	    data, datalen)) != FIDO_OK)  {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		જાઓ out;
	}
	જો ((r = fido_assert_set_rp(પ્રતિજ્ઞા, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		જાઓ out;
	}
	જો ((r = fido_assert_allow_cred(પ્રતિજ્ઞા, ચાવી_handle,
	    ચાવી_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		જાઓ out;
	}
	જો ((r = fido_assert_set_up(પ્રતિજ્ઞા,
	    (flags & SSH_SK_USER_PRESENCE_REQD) ?
	    FIDO_OPT_TRUE : FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		જાઓ out;
	}
	/*
	 * WinHello requests the PIN by default.  Make "uv" request explicit
	 * to allow keys with and without -O verify-required to make sense.
	 */
	જો (pin == ખાલી && fido_dev_is_winhello (sk->dev) &&
	    (r = fido_assert_set_uv(પ્રતિજ્ઞા, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
	}
	જો (pin == ખાલી && (flags & SSH_SK_USER_VERIFICATION_REQD)) {
		જો (check_sk_options(sk->dev, "uv", &internal_uv) < 0 ||
		    internal_uv != 1) {
			skdebug(__func__, "check_sk_options uv");
			ret = SSH_SK_ERR_PIN_REQUIRED;
			જાઓ out;
		}
		જો ((r = fido_assert_set_uv(પ્રતિજ્ઞા,
		    FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_assert_set_uv: %s",
			    fido_strerr(r));
			ret = fidoerr_to_skerr(r);
			જાઓ out;
		}
	}
	જો ((r = fido_dev_get_assert(sk->dev, પ્રતિજ્ઞા, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		જાઓ out;
	}
	જો ((response = calloc(1, કદ(*response))) == ખાલી) {
		skdebug(__func__, "calloc response failed");
		જાઓ out;
	}
	response->flags = fido_assert_flags(પ્રતિજ્ઞા, 0);
	response->counter = fido_assert_sigcount(પ્રતિજ્ઞા, 0);
	જો (pack_sig(alg, પ્રતિજ્ઞા, response) != 0) {
		skdebug(__func__, "pack_sig failed");
		જાઓ out;
	}
	*sign_response = response;
	response = ખાલી;
	ret = 0;
 out:
	મુક્ત(device);
	જો (response != ખાલી) {
		મુક્ત(response->sig_r);
		મુક્ત(response->sig_s);
		મુક્ત(response);
	}
	sk_close(sk);
	fido_assert_free(&પ્રતિજ્ઞા);
	પાછા ret;
}

સ્થિર પૂર્ણાંક
read_rks(સંરચના sk_usbhid *sk, અચલ અક્ષર *pin,
    સંરચના sk_resident_ચાવી ***rksp, size_t *nrksp)
{
	પૂર્ણાંક ret = SSH_SK_ERR_GENERAL, r = -1;
	uint32_t alg;
	fido_credman_metadata_t *metadata = ખાલી;
	fido_credman_rp_t *rp = ખાલી;
	fido_credman_rk_t *rk = ખાલી;
	size_t i, j, nrp, nrk, user_id_len;
	અચલ fido_cred_t *cred;
	અચલ અક્ષર *rp_id, *rp_name, *user_name;
	સંરચના sk_resident_ચાવી *srk = ખાલી, **tmp;
	અચલ u_char *user_id;

	જો (pin == ખાલી) {
		skdebug(__func__, "no PIN specified");
		ret = SSH_SK_ERR_PIN_REQUIRED;
		જાઓ out;
	}
	જો ((metadata = fido_credman_metadata_new()) == ખાલી) {
		skdebug(__func__, "alloc failed");
		જાઓ out;
	}
	જો ((r = fido_credman_get_dev_metadata(sk->dev, metadata, pin)) != 0) {
		જો (r == FIDO_ERR_INVALID_COMMAND) {
			skdebug(__func__, "device %s does not support "
			    "resident keys", sk->path);
			ret = 0;
			જાઓ out;
		}
		skdebug(__func__, "get metadata for %s failed: %s",
		    sk->path, fido_strerr(r));
		ret = fidoerr_to_skerr(r);
		જાઓ out;
	}
	skdebug(__func__, "existing %llu, remaining %llu",
	    (unsigned long long)fido_credman_rk_existing(metadata),
	    (unsigned long long)fido_credman_rk_remaining(metadata));
	જો ((rp = fido_credman_rp_new()) == ખાલી) {
		skdebug(__func__, "alloc rp failed");
		જાઓ out;
	}
	જો ((r = fido_credman_get_dev_rp(sk->dev, rp, pin)) != 0) {
		skdebug(__func__, "get RPs for %s failed: %s",
		    sk->path, fido_strerr(r));
		જાઓ out;
	}
	nrp = fido_credman_rp_ગણતરી(rp);
	skdebug(__func__, "Device %s has resident keys for %zu RPs",
	    sk->path, nrp);

	/* Iterate over RP IDs that have resident keys */
	માટે (i = 0; i < nrp; i++) {
		rp_id = fido_credman_rp_id(rp, i);
		rp_name = fido_credman_rp_name(rp, i);
		skdebug(__func__, "rp %zu: name=\"%s\" id=\"%s\" hashlen=%zu",
		    i, rp_name == ખાલી ? "(none)" : rp_name,
		    rp_id == ખાલી ? "(none)" : rp_id,
		    fido_credman_rp_id_hash_len(rp, i));

		/* Skip non-SSH RP IDs */
		જો (rp_id == ખાલી ||
		    strncasecmp(fido_credman_rp_id(rp, i), "ssh:", 4) != 0)
			ચાલુ;

		fido_credman_rk_free(&rk);
		જો ((rk = fido_credman_rk_new()) == ખાલી) {
			skdebug(__func__, "alloc rk failed");
			જાઓ out;
		}
		જો ((r = fido_credman_get_dev_rk(sk->dev,
		    fido_credman_rp_id(rp, i), rk, pin)) != 0) {
			skdebug(__func__, "get RKs for %s slot %zu failed: %s",
			    sk->path, i, fido_strerr(r));
			જાઓ out;
		}
		nrk = fido_credman_rk_ગણતરી(rk);
		skdebug(__func__, "RP \"%s\" has %zu resident keys",
		    fido_credman_rp_id(rp, i), nrk);

		/* Iterate over resident keys for this RP ID */
		માટે (j = 0; j < nrk; j++) {
			જો ((cred = fido_credman_rk(rk, j)) == ખાલી) {
				skdebug(__func__, "no RK in slot %zu", j);
				ચાલુ;
			}
			જો ((user_name = fido_cred_user_name(cred)) == ખાલી)
				user_name = "";
			user_id = fido_cred_user_id_ptr(cred);
			user_id_len = fido_cred_user_id_len(cred);
			skdebug(__func__, "Device %s RP \"%s\" user \"%s\" "
			    "uidlen %zu slot %zu: type %d flags 0x%02x "
			    "prot 0x%02x", sk->path, rp_id, user_name,
			    user_id_len, j, fido_cred_type(cred),
			    fido_cred_flags(cred), fido_cred_prot(cred));

			/* Determine key algorithm */
			પસંદગી (fido_cred_type(cred)) {
			સ્થિતિ COSE_ES256:
				alg = SSH_SK_ECDSA;
				તોડો;
			સ્થિતિ COSE_EDDSA:
				alg = SSH_SK_ED25519;
				તોડો;
			મૂળભૂત:
				skdebug(__func__, "unsupported key type %d",
				    fido_cred_type(cred));
				ચાલુ;
			}

			/* build response entry */
			જો ((srk = calloc(1, કદ(*srk))) == ખાલી ||
			    (srk->ચાવી.ચાવી_handle = calloc(1,
			    fido_cred_id_len(cred))) == ખાલી ||
			    (srk->application = strdup(rp_id)) == ખાલી ||
			    (user_id_len > 0 &&
			     (srk->user_id = calloc(1, user_id_len)) == ખાલી)) {
				skdebug(__func__, "alloc sk_resident_key");
				જાઓ out;
			}

			srk->alg = alg;
			srk->ચાવી.ચાવી_handle_len = fido_cred_id_len(cred);
			memcpy(srk->ચાવી.ચાવી_handle, fido_cred_id_ptr(cred),
			    srk->ચાવી.ચાવી_handle_len);
			srk->user_id_len = user_id_len;
			જો (srk->user_id_len != 0)
				memcpy(srk->user_id, user_id, srk->user_id_len);

#ifdef HAVE_FIDO_CRED_PROT
			જો (fido_cred_prot(cred) ==
			    FIDO_CRED_PROT_UV_REQUIRED)
				srk->flags |=  SSH_SK_USER_VERIFICATION_REQD;
#endif

			જો ((r = pack_public_ચાવી(srk->alg, cred,
			    &srk->ચાવી)) != 0) {
				skdebug(__func__, "pack public key failed");
				જાઓ out;
			}
			/* append */
			જો ((tmp = recallocarray(*rksp, *nrksp, (*nrksp) + 1,
			    કદ(**rksp))) == ખાલી) {
				skdebug(__func__, "alloc rksp");
				જાઓ out;
			}
			*rksp = tmp;
			(*rksp)[(*nrksp)++] = srk;
			srk = ખાલી;
		}
	}
	/* Success */
	ret = 0;
 out:
	જો (srk != ખાલી) {
		મુક્ત(srk->application);
		freezero(srk->ચાવી.public_ચાવી, srk->ચાવી.public_ચાવી_len);
		freezero(srk->ચાવી.ચાવી_handle, srk->ચાવી.ચાવી_handle_len);
		freezero(srk->user_id, srk->user_id_len);
		freezero(srk, કદ(*srk));
	}
	fido_credman_rp_free(&rp);
	fido_credman_rk_free(&rk);
	fido_credman_metadata_free(&metadata);
	પાછા ret;
}

પૂર્ણાંક
sk_load_resident_ચાવીઓ(અચલ અક્ષર *pin, સંરચના sk_option **options,
    સંરચના sk_resident_ચાવી ***rksp, size_t *nrksp)
{
	પૂર્ણાંક ret = SSH_SK_ERR_GENERAL, r = -1;
	size_t i, nrks = 0;
	સંરચના sk_resident_ચાવી **rks = ખાલી;
	સંરચના sk_usbhid *sk = ખાલી;
	અક્ષર *device = ખાલી;

	*rksp = ખાલી;
	*nrksp = 0;

	fido_init(SSH_FIDO_INIT_ARG);

	જો (check_sign_load_resident_options(options, &device) != 0)
		જાઓ out; /* error already logged */
	જો (device != ખાલી)
		sk = sk_open(device);
	નહીંતર
		sk = sk_probe(ખાલી, ખાલી, 0, 1);
	જો (sk == ખાલી) {
		ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
		skdebug(__func__, "failed to find sk");
		જાઓ out;
	}
	skdebug(__func__, "trying %s", sk->path);
	જો ((r = read_rks(sk, pin, &rks, &nrks)) != 0) {
		skdebug(__func__, "read_rks failed for %s", sk->path);
		ret = r;
		જાઓ out;
	}
	/* success, unless we have no keys but a specific error */
	જો (nrks > 0 || ret == SSH_SK_ERR_GENERAL)
		ret = 0;
	*rksp = rks;
	*nrksp = nrks;
	rks = ખાલી;
	nrks = 0;
 out:
	sk_close(sk);
	માટે (i = 0; i < nrks; i++) {
		મુક્ત(rks[i]->application);
		freezero(rks[i]->ચાવી.public_ચાવી, rks[i]->ચાવી.public_ચાવી_len);
		freezero(rks[i]->ચાવી.ચાવી_handle, rks[i]->ચાવી.ચાવી_handle_len);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i], કદ(*rks[i]));
	}
	મુક્ત(device);
	મુક્ત(rks);
	પાછા ret;
}

#endif /* ENABLE_SK_INTERNAL */
