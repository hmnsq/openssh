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

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే ENABLE_SK_అంతర్గత

#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stddef.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <time.h>
#నిర్వచితమైతే HAVE_SHA2_H
#అన్తర్భావ <sha2.h>
#అయితే_ముగింపు

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/opensslv.h>
#అన్తర్భావ <openssl/crypto.h>
#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/ec.h>
#అన్తర్భావ <openssl/ecdsa.h>
#అన్తర్భావ <openssl/evp.h>
#అన్తర్భావ "openbsd-compat/openssl-compat.h"
#అయితే_ముగింపు /* WITH_OPENSSL */

#అన్తర్భావ <fido.h>
#అన్తర్భావ <fido/credman.h>

/* backwards compat for libfido2 */
#నిర్వచితం_కాకపోతే HAVE_FIDO_CRED_PROT
#నిర్వచించు fido_cred_prot(x) (0)
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే HAVE_FIDO_CRED_సమితి_PROT
#నిర్వచించు fido_cred_సమితి_prot(x, y) (FIDO_ERR_UNSUPPORTED_OPTION)
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే HAVE_FIDO_DEV_SUPPORTS_CRED_PROT
#నిర్వచించు fido_dev_supports_cred_prot(x) (0)
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే HAVE_FIDO_DEV_GET_TOUCH_BEGIN
#నిర్వచించు fido_dev_get_touch_begin(x) (FIDO_ERR_UNSUPPORTED_OPTION)
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే HAVE_FIDO_DEV_GET_TOUCH_స్థితి
#నిర్వచించు fido_dev_get_touch_స్థితి(x, y, z) (FIDO_ERR_UNSUPPORTED_OPTION)
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే FIDO_CRED_PROT_UV_REQUIRED
#నిర్వచించు FIDO_CRED_PROT_UV_REQUIRED 0
#అయితే_ముగింపు
#నిర్వచితం_కాకపోతే FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID
#నిర్వచించు FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID 0
#అయితే_ముగింపు

# include "misc.h"

#నిర్వచితం_కాకపోతే SK_STANDALONE
# include "log.h"
# include "xmalloc.h"
/*
 * If building as part of OpenSSH, then rename exported functions.
 * This must be done before including sk-api.h.
 */
# define sk_api_సంస్కరణ		ssh_sk_api_సంస్కరణ
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_ఎక్కించు_resident_కీలకాలు	ssh_sk_ఎక్కించు_resident_కీలకాలు
#అయితే_ముగింపు /* !SK_STANDALONE */

#అన్తర్భావ "sk-api.h"

/* #define SK_DEBUG 1 */

#నిర్వచితమైతే SK_DEBUG
#నిర్వచించు SSH_FIDO_INIT_ARG	FIDO_DEBUG
#లేకపోతే
#నిర్వచించు SSH_FIDO_INIT_ARG	0
#అయితే_ముగింపు

#నిర్వచించు MAX_FIDO_DEVICES	8
#నిర్వచించు FIDO_POLL_MS		50
#నిర్వచించు SELECT_MS		15000
#నిర్వచించు POLL_SLEEP_NS		200000000

#నిర్వచితం_కాకపోతే FIDO_ERR_OPERATION_DENIED
#నిర్వచించు FIDO_ERR_OPERATION_DENIED 0x27
#అయితే_ముగింపు

నిర్మాణం sk_usbhid {
	fido_dev_t *dev;
	అక్షరం *మార్గం;
};

/* Return the version of the middleware API */
uint32_t sk_api_సంస్కరణ(శూన్య);

/* Enroll a U2F key (private key generation) */
పూర్ణాంకం sk_enroll(uint32_t alg, స్థిరరాశి uint8_t *challenge, కొలత_t challenge_len,
    స్థిరరాశి అక్షరం *application, uint8_t flags, స్థిరరాశి అక్షరం *pin,
    నిర్మాణం sk_option **options, నిర్మాణం sk_enroll_response **enroll_response);

/* Sign a challenge */
పూర్ణాంకం sk_sign(uint32_t alg, స్థిరరాశి uint8_t *దత్తాంశం, కొలత_t దత్తాంశం_len,
    స్థిరరాశి అక్షరం *application, స్థిరరాశి uint8_t *కీలకం_handle, కొలత_t కీలకం_handle_len,
    uint8_t flags, స్థిరరాశి అక్షరం *pin, నిర్మాణం sk_option **options,
    నిర్మాణం sk_sign_response **sign_response);

/* Load resident keys */
పూర్ణాంకం sk_ఎక్కించు_resident_కీలకాలు(స్థిరరాశి అక్షరం *pin, నిర్మాణం sk_option **options,
    నిర్మాణం sk_resident_కీలకం ***rks, కొలత_t *nrks);

స్థిర శూన్య skdebug(స్థిరరాశి అక్షరం *func, స్థిరరాశి అక్షరం *fmt, ...)
    __attribute__((__format__ (రాయి, 2, 3)));

స్థిర శూన్య
skdebug(స్థిరరాశి అక్షరం *func, స్థిరరాశి అక్షరం *fmt, ...)
{
#ఒకవేళ !defined(SK_STANDALONE)
	అక్షరం *సందేశం;
	va_list ap;

	va_start(ap, fmt);
	xvasprintf(&సందేశం, fmt, ap);
	va_end(ap);
	debug("%s: %s", func, సందేశం);
	విడుదల(సందేశం);
#లేదావేళ defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#లేకపోతే
	(శూన్య)func; /* XXX */
	(శూన్య)fmt; /* XXX */
#అయితే_ముగింపు
}

uint32_t
sk_api_సంస్కరణ(శూన్య)
{
	తిరిగి SSH_SK_సంస్కరణ_MAJOR;
}

స్థిర నిర్మాణం sk_usbhid *
sk_open(స్థిరరాశి అక్షరం *మార్గం)
{
	నిర్మాణం sk_usbhid *sk;
	పూర్ణాంకం r;

	ఒకవేళ (మార్గం == ఖాళీ) {
		skdebug(__func__, "path == NULL");
		తిరిగి ఖాళీ;
	}
	ఒకవేళ ((sk = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*sk))) == ఖాళీ) {
		skdebug(__func__, "calloc sk failed");
		తిరిగి ఖాళీ;
	}
	ఒకవేళ ((sk->మార్గం = strdup(మార్గం)) == ఖాళీ) {
		skdebug(__func__, "strdup path failed");
		విడుదల(sk);
		తిరిగి ఖాళీ;
	}
	ఒకవేళ ((sk->dev = fido_dev_new()) == ఖాళీ) {
		skdebug(__func__, "fido_dev_new failed");
		విడుదల(sk->మార్గం);
		విడుదల(sk);
		తిరిగి ఖాళీ;
	}
	ఒకవేళ ((r = fido_dev_open(sk->dev, sk->మార్గం)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_open %s failed: %s", sk->మార్గం,
		    fido_strerr(r));
		fido_dev_free(&sk->dev);
		విడుదల(sk->మార్గం);
		విడుదల(sk);
		తిరిగి ఖాళీ;
	}
	తిరిగి sk;
}

స్థిర శూన్య
sk_close(నిర్మాణం sk_usbhid *sk)
{
	ఒకవేళ (sk == ఖాళీ)
		తిరిగి;
	fido_dev_cancel(sk->dev); /* cancel any pending operation */
	fido_dev_close(sk->dev);
	fido_dev_free(&sk->dev);
	విడుదల(sk->మార్గం);
	విడుదల(sk);
}

స్థిర నిర్మాణం sk_usbhid **
sk_openv(స్థిరరాశి fido_dev_info_t *devlist, కొలత_t ndevs, కొలత_t *nopen)
{
	స్థిరరాశి fido_dev_info_t *di;
	నిర్మాణం sk_usbhid **skv;
	కొలత_t i;

	*nopen = 0;
	ఒకవేళ ((skv = సున్నా_జ్ఞాపకం_ఇవ్వు(ndevs, పరిమాణం(*skv))) == ఖాళీ) {
		skdebug(__func__, "calloc skv failed");
		తిరిగి ఖాళీ;
	}
	కొరకు (i = 0; i < ndevs; i++) {
		ఒకవేళ ((di = fido_dev_info_ptr(devlist, i)) == ఖాళీ)
			skdebug(__func__, "fido_dev_info_ptr failed");
		లేకపోతే ఒకవేళ ((skv[*nopen] = sk_open(fido_dev_info_మార్గం(di))) == ఖాళీ)
			skdebug(__func__, "sk_open failed");
		లేకపోతే
			(*nopen)++;
	}
	ఒకవేళ (*nopen == 0) {
		కొరకు (i = 0; i < ndevs; i++)
			sk_close(skv[i]);
		విడుదల(skv);
		skv = ఖాళీ;
	}

	తిరిగి skv;
}

స్థిర శూన్య
sk_closev(నిర్మాణం sk_usbhid **skv, కొలత_t nsk)
{
	కొలత_t i;

	కొరకు (i = 0; i < nsk; i++)
		sk_close(skv[i]);
	విడుదల(skv);
}

స్థిర పూర్ణాంకం
sk_touch_begin(నిర్మాణం sk_usbhid **skv, కొలత_t nsk)
{
	కొలత_t i, ok = 0;
	పూర్ణాంకం r;

	కొరకు (i = 0; i < nsk; i++)
		ఒకవేళ ((r = fido_dev_get_touch_begin(skv[i]->dev)) != FIDO_OK)
			skdebug(__func__, "fido_dev_get_touch_begin %s failed:"
			    " %s", skv[i]->మార్గం, fido_strerr(r));
		లేకపోతే
			ok++;

	తిరిగి ok ? 0 : -1;
}

స్థిర పూర్ణాంకం
sk_touch_poll(నిర్మాణం sk_usbhid **skv, కొలత_t nsk, పూర్ణాంకం *touch, కొలత_t *idx)
{
	నిర్మాణం timespec ts_pause;
	కొలత_t npoll, i;
	పూర్ణాంకం r;

	ts_pause.tv_sec = 0;
	ts_pause.tv_nsec = POLL_SLEEP_NS;
	nanosleep(&ts_pause, ఖాళీ);
	npoll = nsk;
	కొరకు (i = 0; i < nsk; i++) {
		ఒకవేళ (skv[i] == ఖాళీ)
			కొనసాగు; /* device discarded */
		skdebug(__func__, "polling %s", skv[i]->మార్గం);
		ఒకవేళ ((r = fido_dev_get_touch_స్థితి(skv[i]->dev, touch,
		    FIDO_POLL_MS)) != FIDO_OK) {
			skdebug(__func__, "fido_dev_get_touch_status %s: %s",
			    skv[i]->మార్గం, fido_strerr(r));
			sk_close(skv[i]); /* discard device */
			skv[i] = ఖాళీ;
			ఒకవేళ (--npoll == 0) {
				skdebug(__func__, "no device left to poll");
				తిరిగి -1;
			}
		} లేకపోతే ఒకవేళ (*touch) {
			*idx = i;
			తిరిగి 0;
		}
	}
	*touch = 0;
	తిరిగి 0;
}

#ఒకవేళ !defined(HAVE_FIDO_ASSERT_సమితి_CLIENTDATA) || \
    !defined(HAVE_FIDO_CRED_సమితి_CLIENTDATA)
/* Calculate SHA256(m) */
స్థిర పూర్ణాంకం
sha256_mem(స్థిరరాశి శూన్య *m, కొలత_t mlen, u_char *d, కొలత_t dlen)
{
#నిర్వచితమైతే WITH_OPENSSL
	u_int mdlen;
#లేకపోతే
	SHA2_CTX ctx;
#అయితే_ముగింపు

	ఒకవేళ (dlen != 32)
		తిరిగి -1;
#నిర్వచితమైతే WITH_OPENSSL
	mdlen = dlen;
	ఒకవేళ (!EVP_Digest(m, mlen, d, &mdlen, EVP_sha256(), ఖాళీ))
		తిరిగి -1;
#లేకపోతే
	SHA256Init(&ctx);
	SHA256Update(&ctx, (స్థిరరాశి uint8_t *)m, mlen);
	SHA256Final(d, &ctx);
#అయితే_ముగింపు
	తిరిగి 0;
}
#అయితే_ముగింపు /* !HAVE_FIDO_ASSERT_SET_CLIENTDATA || !HAVE_FIDO_CRED_SET_CLIENTDATA */

#నిర్వచితం_కాకపోతే HAVE_FIDO_CRED_సమితి_CLIENTDATA
స్థిర పూర్ణాంకం
fido_cred_సమితి_clientdata(fido_cred_t *cred, స్థిరరాశి u_char *ptr, కొలత_t len)
{
	uint8_t d[32];
	పూర్ణాంకం r;

	ఒకవేళ (sha256_mem(ptr, len, d, పరిమాణం(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		తిరిగి FIDO_ERR_అంతర్గత;
	}
	r = fido_cred_సమితి_clientdata_hash(cred, d, పరిమాణం(d));
	explicit_bzero(d, పరిమాణం(d));
	ఒకవేళ (r != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	తిరిగి r;
}
#అయితే_ముగింపు /* HAVE_FIDO_CRED_SET_CLIENTDATA */

#నిర్వచితం_కాకపోతే HAVE_FIDO_ASSERT_సమితి_CLIENTDATA
స్థిర పూర్ణాంకం
fido_assert_సమితి_clientdata(fido_assert_t *ప్రతిజ్ఞా, స్థిరరాశి u_char *ptr, కొలత_t len)
{
	uint8_t d[32];
	పూర్ణాంకం r;

	ఒకవేళ (sha256_mem(ptr, len, d, పరిమాణం(d)) != 0) {
		skdebug(__func__, "hash challenge failed");
		తిరిగి FIDO_ERR_అంతర్గత;
	}
	r = fido_assert_సమితి_clientdata_hash(ప్రతిజ్ఞా, d, పరిమాణం(d));
	explicit_bzero(d, పరిమాణం(d));
	ఒకవేళ (r != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata_hash failed: %s",
		    fido_strerr(r));
	}
	తిరిగి r;
}
#అయితే_ముగింపు /* HAVE_FIDO_ASSERT_SET_CLIENTDATA */

#నిర్వచితం_కాకపోతే HAVE_FIDO_DEV_IS_WINHELLO
స్థిర bool
fido_dev_is_winhello(స్థిరరాశి fido_dev_t *fdev)
{
	తిరిగి 0;
}
#అయితే_ముగింపు /* HAVE_FIDO_DEV_IS_WINHELLO */

/* Check if the specified key handle exists on a given sk. */
స్థిర పూర్ణాంకం
sk_try(స్థిరరాశి నిర్మాణం sk_usbhid *sk, స్థిరరాశి అక్షరం *application,
    స్థిరరాశి uint8_t *కీలకం_handle, కొలత_t కీలకం_handle_len)
{
	fido_assert_t *ప్రతిజ్ఞా = ఖాళీ;
	పూర్ణాంకం r = FIDO_ERR_అంతర్గత;
	uint8_t సందేశం_2[32];

	memset(సందేశం_2, '\0', పరిమాణం(సందేశం_2));
	ఒకవేళ ((ప్రతిజ్ఞా = fido_assert_new()) == ఖాళీ) {
		skdebug(__func__, "fido_assert_new failed");
		వెళ్ళు బహిర్గతం;
	}
	/* generate an invalid signature on FIDO2 tokens */
	ఒకవేళ ((r = fido_assert_సమితి_clientdata(ప్రతిజ్ఞా, సందేశం_2,
	    పరిమాణం(సందేశం_2))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = fido_assert_సమితి_rp(ప్రతిజ్ఞా, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = fido_assert_allow_cred(ప్రతిజ్ఞా, కీలకం_handle,
	    కీలకం_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = fido_assert_సమితి_పైకి(ప్రతిజ్ఞా, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_up: %s", fido_strerr(r));
		వెళ్ళు బహిర్గతం;
	}
	r = fido_dev_get_assert(sk->dev, ప్రతిజ్ఞా, ఖాళీ);
	skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
	ఒకవేళ (r == FIDO_ERR_USER_PRESENCE_REQUIRED) {
		/* U2F tokens may return this */
		r = FIDO_OK;
	}
 బహిర్గతం:
	fido_assert_free(&ప్రతిజ్ఞా);

	తిరిగి r != FIDO_OK ? -1 : 0;
}

స్థిర పూర్ణాంకం
check_sk_options(fido_dev_t *dev, స్థిరరాశి అక్షరం *opt, పూర్ణాంకం *ret)
{
	fido_cbor_info_t *info;
	అక్షరం * స్థిరరాశి *name;
	స్థిరరాశి bool *విలువ;
	కొలత_t len, i;
	పూర్ణాంకం r;

	*ret = -1;

	ఒకవేళ (!fido_dev_is_fido2(dev)) {
		skdebug(__func__, "device is not fido2");
		తిరిగి 0;
	}
	ఒకవేళ ((info = fido_cbor_info_new()) == ఖాళీ) {
		skdebug(__func__, "fido_cbor_info_new failed");
		తిరిగి -1;
	}
	ఒకవేళ ((r = fido_dev_get_cbor_info(dev, info)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_cbor_info: %s", fido_strerr(r));
		fido_cbor_info_free(&info);
		తిరిగి -1;
	}
	name = fido_cbor_info_options_name_ptr(info);
	విలువ = fido_cbor_info_options_విలువ_ptr(info);
	len = fido_cbor_info_options_len(info);
	కొరకు (i = 0; i < len; i++) {
		ఒకవేళ (!strcmp(name[i], opt)) {
			*ret = విలువ[i];
			ఆపు;
		}
	}
	fido_cbor_info_free(&info);
	ఒకవేళ (*ret == -1)
		skdebug(__func__, "option %s is unknown", opt);
	లేకపోతే
		skdebug(__func__, "option %s is %s", opt, *ret ? "on" : "off");

	తిరిగి 0;
}

స్థిర నిర్మాణం sk_usbhid *
sk_select_by_cred(స్థిరరాశి fido_dev_info_t *devlist, కొలత_t ndevs,
    స్థిరరాశి అక్షరం *application, స్థిరరాశి uint8_t *కీలకం_handle, కొలత_t కీలకం_handle_len)
{
	నిర్మాణం sk_usbhid **skv, *sk;
	కొలత_t skvcnt, i;
	పూర్ణాంకం అంతర్గత_uv;

	ఒకవేళ ((skv = sk_openv(devlist, ndevs, &skvcnt)) == ఖాళీ) {
		skdebug(__func__, "sk_openv failed");
		తిరిగి ఖాళీ;
	}
	ఒకవేళ (skvcnt == 1 && check_sk_options(skv[0]->dev, "uv",
	    &అంతర్గత_uv) == 0 && అంతర్గత_uv != -1) {
		sk = skv[0];
		skv[0] = ఖాళీ;
		వెళ్ళు బహిర్గతం;
	}
	sk = ఖాళీ;
	కొరకు (i = 0; i < skvcnt; i++) {
		ఒకవేళ (sk_try(skv[i], application, కీలకం_handle,
		    కీలకం_handle_len) == 0) {
			sk = skv[i];
			skv[i] = ఖాళీ;
			skdebug(__func__, "found key in %s", sk->మార్గం);
			ఆపు;
		}
	}
 బహిర్గతం:
	sk_closev(skv, skvcnt);
	తిరిగి sk;
}

స్థిర నిర్మాణం sk_usbhid *
sk_select_by_touch(స్థిరరాశి fido_dev_info_t *devlist, కొలత_t ndevs)
{
	నిర్మాణం sk_usbhid **skv, *sk;
	నిర్మాణం timeval tv_ప్రారంభం, tv_now, tv_delta;
	కొలత_t skvcnt, idx;
	పూర్ణాంకం touch, ms_remain;

	ఒకవేళ ((skv = sk_openv(devlist, ndevs, &skvcnt)) == ఖాళీ) {
		skdebug(__func__, "sk_openv failed");
		తిరిగి ఖాళీ;
	}
	sk = ఖాళీ;
	ఒకవేళ (skvcnt < 2) {
		ఒకవేళ (skvcnt == 1) {
			/* single candidate */
			sk = skv[0];
			skv[0] = ఖాళీ;
		}
		వెళ్ళు బహిర్గతం;
	}
#నిర్వచితం_కాకపోతే HAVE_FIDO_DEV_GET_TOUCH_స్థితి
	skdebug(__func__, "libfido2 version does not support a feature needed for multiple tokens. Please upgrade to >=1.5.0");
	వెళ్ళు బహిర్గతం;
#అయితే_ముగింపు

	ఒకవేళ (sk_touch_begin(skv, skvcnt) == -1) {
		skdebug(__func__, "sk_touch_begin failed");
		వెళ్ళు బహిర్గతం;
	}
	monotime_tv(&tv_ప్రారంభం);
	చేయి {
		ఒకవేళ (sk_touch_poll(skv, skvcnt, &touch, &idx) == -1) {
			skdebug(__func__, "sk_touch_poll failed");
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (touch) {
			sk = skv[idx];
			skv[idx] = ఖాళీ;
			వెళ్ళు బహిర్గతం;
		}
		monotime_tv(&tv_now);
		timersub(&tv_now, &tv_ప్రారంభం, &tv_delta);
		ms_remain = SELECT_MS - tv_delta.tv_sec * 1000 -
		    tv_delta.tv_usec / 1000;
	} అయితే (ms_remain >= FIDO_POLL_MS);
	skdebug(__func__, "timeout");
బహిర్గతం:
	sk_closev(skv, skvcnt);
	తిరిగి sk;
}

స్థిర నిర్మాణం sk_usbhid *
sk_probe(స్థిరరాశి అక్షరం *application, స్థిరరాశి uint8_t *కీలకం_handle,
    కొలత_t కీలకం_handle_len, పూర్ణాంకం probe_resident)
{
	నిర్మాణం sk_usbhid *sk;
	fido_dev_info_t *devlist;
	కొలత_t ndevs;
	పూర్ణాంకం r;

#నిర్వచితమైతే HAVE_CYGWIN
	ఒకవేళ (!probe_resident && (sk = sk_open("windows://hello")) != ఖాళీ)
		తిరిగి sk;
#అయితే_ముగింపు /* HAVE_CYGWIN */
	ఒకవేళ ((devlist = fido_dev_info_new(MAX_FIDO_DEVICES)) == ఖాళీ) {
		skdebug(__func__, "fido_dev_info_new failed");
		తిరిగి ఖాళీ;
	}
	ఒకవేళ ((r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES,
	    &ndevs)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_info_manifest failed: %s",
		    fido_strerr(r));
		fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
		తిరిగి ఖాళీ;
	}
	skdebug(__func__, "%zu device(s) detected", ndevs);
	ఒకవేళ (ndevs == 0) {
		sk = ఖాళీ;
	} లేకపోతే ఒకవేళ (application != ఖాళీ && కీలకం_handle != ఖాళీ) {
		skdebug(__func__, "selecting sk by cred");
		sk = sk_select_by_cred(devlist, ndevs, application, కీలకం_handle,
		    కీలకం_handle_len);
	} లేకపోతే {
		skdebug(__func__, "selecting sk by touch");
		sk = sk_select_by_touch(devlist, ndevs);
	}
	fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
	తిరిగి sk;
}

#నిర్వచితమైతే WITH_OPENSSL
/*
 * The key returned via fido_cred_pubkey_ptr() is in affine coordinates,
 * but the API expects a SEC1 octet string.
 */
స్థిర పూర్ణాంకం
pack_ప్రజా_కీలకం_ecdsa(స్థిరరాశి fido_cred_t *cred,
    నిర్మాణం sk_enroll_response *response)
{
	స్థిరరాశి uint8_t *ptr;
	BIGNUM *x = ఖాళీ, *y = ఖాళీ;
	EC_బిందువు *q = ఖాళీ;
	EC_సమూహం *g = ఖాళీ;
	పూర్ణాంకం ret = -1;

	response->ప్రజా_కీలకం = ఖాళీ;
	response->ప్రజా_కీలకం_len = 0;

	ఒకవేళ ((x = BN_new()) == ఖాళీ ||
	    (y = BN_new()) == ఖాళీ ||
	    (g = EC_సమూహం_new_by_వక్రం_name(NID_X9_62_prime256v1)) == ఖాళీ ||
	    (q = EC_బిందువు_new(g)) == ఖాళీ) {
		skdebug(__func__, "libcrypto setup failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((ptr = fido_cred_pubkey_ptr(cred)) == ఖాళీ) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (fido_cred_pubkey_len(cred) != 64) {
		skdebug(__func__, "bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ (BN_bin2bn(ptr, 32, x) == ఖాళీ ||
	    BN_bin2bn(ptr + 32, 32, y) == ఖాళీ) {
		skdebug(__func__, "BN_bin2bn failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EC_బిందువు_సమితి_affine_coordinates(g, q, x, y, ఖాళీ) != 1) {
		skdebug(__func__, "EC_POINT_set_affine_coordinates failed");
		వెళ్ళు బహిర్గతం;
	}
	response->ప్రజా_కీలకం_len = EC_బిందువు_point2oct(g, q,
	    బిందువు_CONVERSION_UNCOMPRESSED, ఖాళీ, 0, ఖాళీ);
	ఒకవేళ (response->ప్రజా_కీలకం_len == 0 || response->ప్రజా_కీలకం_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->ప్రజా_కీలకం_len);
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((response->ప్రజా_కీలకం = జ్ఞాపకం_ఇవ్వు(response->ప్రజా_కీలకం_len)) == ఖాళీ) {
		skdebug(__func__, "malloc pubkey failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EC_బిందువు_point2oct(g, q, బిందువు_CONVERSION_UNCOMPRESSED,
	    response->ప్రజా_కీలకం, response->ప్రజా_కీలకం_len, ఖాళీ) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	ret = 0;
 బహిర్గతం:
	ఒకవేళ (ret != 0 && response->ప్రజా_కీలకం != ఖాళీ) {
		memset(response->ప్రజా_కీలకం, 0, response->ప్రజా_కీలకం_len);
		విడుదల(response->ప్రజా_కీలకం);
		response->ప్రజా_కీలకం = ఖాళీ;
	}
	EC_బిందువు_free(q);
	EC_సమూహం_free(g);
	BN_clear_free(x);
	BN_clear_free(y);
	తిరిగి ret;
}
#అయితే_ముగింపు /* WITH_OPENSSL */

స్థిర పూర్ణాంకం
pack_ప్రజా_కీలకం_ed25519(స్థిరరాశి fido_cred_t *cred,
    నిర్మాణం sk_enroll_response *response)
{
	స్థిరరాశి uint8_t *ptr;
	కొలత_t len;
	పూర్ణాంకం ret = -1;

	response->ప్రజా_కీలకం = ఖాళీ;
	response->ప్రజా_కీలకం_len = 0;

	ఒకవేళ ((len = fido_cred_pubkey_len(cred)) != 32) {
		skdebug(__func__, "bad fido_cred_pubkey_len len %zu", len);
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((ptr = fido_cred_pubkey_ptr(cred)) == ఖాళీ) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		వెళ్ళు బహిర్గతం;
	}
	response->ప్రజా_కీలకం_len = len;
	ఒకవేళ ((response->ప్రజా_కీలకం = జ్ఞాపకం_ఇవ్వు(response->ప్రజా_కీలకం_len)) == ఖాళీ) {
		skdebug(__func__, "malloc pubkey failed");
		వెళ్ళు బహిర్గతం;
	}
	జ్ఞాపకం_నకలు(response->ప్రజా_కీలకం, ptr, len);
	ret = 0;
 బహిర్గతం:
	ఒకవేళ (ret != 0)
		విడుదల(response->ప్రజా_కీలకం);
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
pack_ప్రజా_కీలకం(uint32_t alg, స్థిరరాశి fido_cred_t *cred,
    నిర్మాణం sk_enroll_response *response)
{
	ఎంపిక(alg) {
#నిర్వచితమైతే WITH_OPENSSL
	స్థితి SSH_SK_ECDSA:
		తిరిగి pack_ప్రజా_కీలకం_ecdsa(cred, response);
#అయితే_ముగింపు /* WITH_OPENSSL */
	స్థితి SSH_SK_ED25519:
		తిరిగి pack_ప్రజా_కీలకం_ed25519(cred, response);
	అప్రమేయ:
		తిరిగి -1;
	}
}

స్థిర పూర్ణాంకం
fidoerr_గమ్యం_skerr(పూర్ణాంకం fidoerr)
{
	ఎంపిక (fidoerr) {
	స్థితి FIDO_ERR_UNSUPPORTED_OPTION:
	స్థితి FIDO_ERR_UNSUPPORTED_ALGORITHM:
		తిరిగి SSH_SK_ERR_UNSUPPORTED;
	స్థితి FIDO_ERR_PIN_REQUIRED:
	స్థితి FIDO_ERR_PIN_INVALID:
	స్థితి FIDO_ERR_OPERATION_DENIED:
		తిరిగి SSH_SK_ERR_PIN_REQUIRED;
	అప్రమేయ:
		తిరిగి -1;
	}
}

స్థిర పూర్ణాంకం
check_enroll_options(నిర్మాణం sk_option **options, అక్షరం **devicep,
    uint8_t *user_id, కొలత_t user_id_len)
{
	కొలత_t i;

	ఒకవేళ (options == ఖాళీ)
		తిరిగి 0;
	కొరకు (i = 0; options[i] != ఖాళీ; i++) {
		ఒకవేళ (strcmp(options[i]->name, "device") == 0) {
			ఒకవేళ ((*devicep = strdup(options[i]->విలువ)) == ఖాళీ) {
				skdebug(__func__, "strdup device failed");
				తిరిగి -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} లేకపోతే ఒకవేళ (strcmp(options[i]->name, "user") == 0) {
			ఒకవేళ (strlcpy(user_id, options[i]->విలువ, user_id_len) >=
			    user_id_len) {
				skdebug(__func__, "user too long");
				తిరిగి -1;
			}
			skdebug(__func__, "requested user %s",
			    (అక్షరం *)user_id);
		} లేకపోతే {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			ఒకవేళ (options[i]->required) {
				skdebug(__func__, "unknown required option");
				తిరిగి -1;
			}
		}
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
కీలకం_lookup(fido_dev_t *dev, స్థిరరాశి అక్షరం *application, స్థిరరాశి uint8_t *user_id,
    కొలత_t user_id_len, స్థిరరాశి అక్షరం *pin)
{
	fido_assert_t *ప్రతిజ్ఞా = ఖాళీ;
	uint8_t సందేశం_2[32];
	పూర్ణాంకం r = FIDO_ERR_అంతర్గత;
	పూర్ణాంకం sk_supports_uv, uv;
	కొలత_t i;

	memset(సందేశం_2, '\0', పరిమాణం(సందేశం_2));
	ఒకవేళ ((ప్రతిజ్ఞా = fido_assert_new()) == ఖాళీ) {
		skdebug(__func__, "fido_assert_new failed");
		వెళ్ళు బహిర్గతం;
	}
	/* generate an invalid signature on FIDO2 tokens */
	ఒకవేళ ((r = fido_assert_సమితి_clientdata(ప్రతిజ్ఞా, సందేశం_2,
	    పరిమాణం(సందేశం_2))) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = fido_assert_సమితి_rp(ప్రతిజ్ఞా, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = fido_assert_సమితి_పైకి(ప్రతిజ్ఞా, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		వెళ్ళు బహిర్గతం;
	}
	uv = FIDO_OPT_OMIT;
	ఒకవేళ (pin == ఖాళీ && check_sk_options(dev, "uv", &sk_supports_uv) == 0 &&
	    sk_supports_uv != -1)
		uv = FIDO_OPT_TRUE;
	ఒకవేళ ((r = fido_assert_సమితి_uv(ప్రతిజ్ఞా, uv)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = fido_dev_get_assert(dev, ప్రతిజ్ఞా, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		వెళ్ళు బహిర్గతం;
	}
	r = FIDO_ERR_NO_CREDENTIALS;
	skdebug(__func__, "%zu signatures returned", fido_assert_లెక్క(ప్రతిజ్ఞా));
	కొరకు (i = 0; i < fido_assert_లెక్క(ప్రతిజ్ఞా); i++) {
		ఒకవేళ (fido_assert_user_id_len(ప్రతిజ్ఞా, i) == user_id_len &&
		    memcmp(fido_assert_user_id_ptr(ప్రతిజ్ఞా, i), user_id,
		    user_id_len) == 0) {
			skdebug(__func__, "credential exists");
			r = FIDO_OK;
			వెళ్ళు బహిర్గతం;
		}
	}
 బహిర్గతం:
	fido_assert_free(&ప్రతిజ్ఞా);

	తిరిగి r;
}

పూర్ణాంకం
sk_enroll(uint32_t alg, స్థిరరాశి uint8_t *challenge, కొలత_t challenge_len,
    స్థిరరాశి అక్షరం *application, uint8_t flags, స్థిరరాశి అక్షరం *pin,
    నిర్మాణం sk_option **options, నిర్మాణం sk_enroll_response **enroll_response)
{
	fido_cred_t *cred = ఖాళీ;
	స్థిరరాశి uint8_t *ptr;
	uint8_t user_id[32];
	నిర్మాణం sk_usbhid *sk = ఖాళీ;
	నిర్మాణం sk_enroll_response *response = ఖాళీ;
	కొలత_t len;
	పూర్ణాంకం credprot;
	పూర్ణాంకం cose_alg;
	పూర్ణాంకం ret = SSH_SK_ERR_GENERAL;
	పూర్ణాంకం r;
	అక్షరం *device = ఖాళీ;

	fido_init(SSH_FIDO_INIT_ARG);

	ఒకవేళ (enroll_response == ఖాళీ) {
		skdebug(__func__, "enroll_response == NULL");
		వెళ్ళు బహిర్గతం;
	}
	*enroll_response = ఖాళీ;
	memset(user_id, 0, పరిమాణం(user_id));
	ఒకవేళ (check_enroll_options(options, &device, user_id,
	    పరిమాణం(user_id)) != 0)
		వెళ్ళు బహిర్గతం; /* error already logged */

	ఎంపిక(alg) {
#నిర్వచితమైతే WITH_OPENSSL
	స్థితి SSH_SK_ECDSA:
		cose_alg = COSE_ES256;
		ఆపు;
#అయితే_ముగింపు /* WITH_OPENSSL */
	స్థితి SSH_SK_ED25519:
		cose_alg = COSE_EDDSA;
		ఆపు;
	అప్రమేయ:
		skdebug(__func__, "unsupported key type %d", alg);
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (device != ఖాళీ)
		sk = sk_open(device);
	లేకపోతే
		sk = sk_probe(ఖాళీ, ఖాళీ, 0, 0);
	ఒకవేళ (sk == ఖాళీ) {
		ret = SSH_SK_ERR_DEVICE_NOT_దొరికింది;
		skdebug(__func__, "failed to find sk");
		వెళ్ళు బహిర్గతం;
	}
	skdebug(__func__, "using device %s", sk->మార్గం);
	ఒకవేళ ((flags & SSH_SK_RESIDENT_కీలకం) != 0 &&
	    (flags & SSH_SK_FORCE_OPERATION) == 0 &&
	    (r = కీలకం_lookup(sk->dev, application, user_id, పరిమాణం(user_id),
	    pin)) != FIDO_ERR_NO_CREDENTIALS) {
		ఒకవేళ (r != FIDO_OK) {
			ret = fidoerr_గమ్యం_skerr(r);
			skdebug(__func__, "key_lookup failed");
		} లేకపోతే {
			ret = SSH_SK_ERR_CREDENTIAL_EXISTS;
			skdebug(__func__, "key exists");
		}
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((cred = fido_cred_new()) == ఖాళీ) {
		skdebug(__func__, "fido_cred_new failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = fido_cred_సమితి_type(cred, cose_alg)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_type: %s", fido_strerr(r));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = fido_cred_సమితి_clientdata(cred,
	    challenge, challenge_len)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata: %s",
		    fido_strerr(r));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = fido_cred_సమితి_rk(cred, (flags & SSH_SK_RESIDENT_కీలకం) != 0 ?
	    FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rk: %s", fido_strerr(r));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = fido_cred_సమితి_user(cred, user_id, పరిమాణం(user_id),
	    "openssh", "openssh", ఖాళీ)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_user: %s", fido_strerr(r));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = fido_cred_సమితి_rp(cred, application, ఖాళీ)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rp: %s", fido_strerr(r));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((flags & (SSH_SK_RESIDENT_కీలకం|SSH_SK_USER_VERIFICATION_REQD)) != 0) {
#ఒకవేళ !defined(HAVE_FIDO_DEV_SUPPORTS_CRED_PROT) || \
    !defined(HAVE_FIDO_CRED_సమితి_PROT)
		skdebug(__func__, "libfido2 version does not support a feature required for this operation. Please upgrade to >=1.5.0");
		ret = SSH_SK_ERR_UNSUPPORTED;
		వెళ్ళు బహిర్గతం;
		credprot = 0; (శూన్య)credprot; /* avoid warning */
#అయితే_ముగింపు
		ఒకవేళ (!fido_dev_supports_cred_prot(sk->dev)) {
			skdebug(__func__, "%s does not support credprot, "
			    "refusing to create unprotected "
			    "resident/verify-required key", sk->మార్గం);
			ret = SSH_SK_ERR_UNSUPPORTED;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((flags & SSH_SK_USER_VERIFICATION_REQD))
			credprot = FIDO_CRED_PROT_UV_REQUIRED;
		లేకపోతే
			credprot = FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID;

		ఒకవేళ ((r = fido_cred_సమితి_prot(cred, credprot)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_set_prot: %s",
			    fido_strerr(r));
			ret = fidoerr_గమ్యం_skerr(r);
			వెళ్ళు బహిర్గతం;
		}
	}
	ఒకవేళ ((r = fido_dev_make_cred(sk->dev, cred, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_make_cred: %s", fido_strerr(r));
		ret = fidoerr_గమ్యం_skerr(r);
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (fido_cred_x5c_ptr(cred) != ఖాళీ) {
		ఒకవేళ ((r = fido_cred_verify(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify: %s",
			    fido_strerr(r));
			వెళ్ళు బహిర్గతం;
		}
	} లేకపోతే ఒకవేళ (strcmp(fido_cred_fmt(cred), "none") != 0) {
		skdebug(__func__, "self-attested credential");
		ఒకవేళ ((r = fido_cred_verify_self(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify_self: %s",
			    fido_strerr(r));
			వెళ్ళు బహిర్గతం;
		}
	} లేకపోతే {
		skdebug(__func__, "no attestation data");
	}
	ఒకవేళ ((response = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*response))) == ఖాళీ) {
		skdebug(__func__, "calloc response failed");
		వెళ్ళు బహిర్గతం;
	}
	response->flags = flags;
	ఒకవేళ (pack_ప్రజా_కీలకం(alg, cred, response) != 0) {
		skdebug(__func__, "pack_public_key failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((ptr = fido_cred_id_ptr(cred)) != ఖాళీ) {
		len = fido_cred_id_len(cred);
		ఒకవేళ ((response->కీలకం_handle = సున్నా_జ్ఞాపకం_ఇవ్వు(1, len)) == ఖాళీ) {
			skdebug(__func__, "calloc key handle failed");
			వెళ్ళు బహిర్గతం;
		}
		జ్ఞాపకం_నకలు(response->కీలకం_handle, ptr, len);
		response->కీలకం_handle_len = len;
	}
	ఒకవేళ ((ptr = fido_cred_sig_ptr(cred)) != ఖాళీ) {
		len = fido_cred_sig_len(cred);
		ఒకవేళ ((response->signature = సున్నా_జ్ఞాపకం_ఇవ్వు(1, len)) == ఖాళీ) {
			skdebug(__func__, "calloc signature failed");
			వెళ్ళు బహిర్గతం;
		}
		జ్ఞాపకం_నకలు(response->signature, ptr, len);
		response->signature_len = len;
	}
	ఒకవేళ ((ptr = fido_cred_x5c_ptr(cred)) != ఖాళీ) {
		len = fido_cred_x5c_len(cred);
		skdebug(__func__, "attestation cert len=%zu", len);
		ఒకవేళ ((response->attestation_cert = సున్నా_జ్ఞాపకం_ఇవ్వు(1, len)) == ఖాళీ) {
			skdebug(__func__, "calloc attestation cert failed");
			వెళ్ళు బహిర్గతం;
		}
		జ్ఞాపకం_నకలు(response->attestation_cert, ptr, len);
		response->attestation_cert_len = len;
	}
	ఒకవేళ ((ptr = fido_cred_authdata_ptr(cred)) != ఖాళీ) {
		len = fido_cred_authdata_len(cred);
		skdebug(__func__, "authdata len=%zu", len);
		ఒకవేళ ((response->authdata = సున్నా_జ్ఞాపకం_ఇవ్వు(1, len)) == ఖాళీ) {
			skdebug(__func__, "calloc authdata failed");
			వెళ్ళు బహిర్గతం;
		}
		జ్ఞాపకం_నకలు(response->authdata, ptr, len);
		response->authdata_len = len;
	}
	*enroll_response = response;
	response = ఖాళీ;
	ret = 0;
 బహిర్గతం:
	విడుదల(device);
	ఒకవేళ (response != ఖాళీ) {
		విడుదల(response->ప్రజా_కీలకం);
		విడుదల(response->కీలకం_handle);
		విడుదల(response->signature);
		విడుదల(response->attestation_cert);
		విడుదల(response->authdata);
		విడుదల(response);
	}
	sk_close(sk);
	fido_cred_free(&cred);
	తిరిగి ret;
}

#నిర్వచితమైతే WITH_OPENSSL
స్థిర పూర్ణాంకం
pack_sig_ecdsa(fido_assert_t *ప్రతిజ్ఞా, నిర్మాణం sk_sign_response *response)
{
	ECDSA_SIG *sig = ఖాళీ;
	స్థిరరాశి BIGNUM *sig_r, *sig_s;
	స్థిరరాశి గుర్తులేని అక్షరం *cp;
	కొలత_t sig_len;
	పూర్ణాంకం ret = -1;

	cp = fido_assert_sig_ptr(ప్రతిజ్ఞా, 0);
	sig_len = fido_assert_sig_len(ప్రతిజ్ఞా, 0);
	ఒకవేళ ((sig = d2i_ECDSA_SIG(ఖాళీ, &cp, sig_len)) == ఖాళీ) {
		skdebug(__func__, "d2i_ECDSA_SIG failed");
		వెళ్ళు బహిర్గతం;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_అంకె_బైట్లు(sig_r);
	response->sig_s_len = BN_అంకె_బైట్లు(sig_s);
	ఒకవేళ ((response->sig_r = సున్నా_జ్ఞాపకం_ఇవ్వు(1, response->sig_r_len)) == ఖాళీ ||
	    (response->sig_s = సున్నా_జ్ఞాపకం_ఇవ్వు(1, response->sig_s_len)) == ఖాళీ) {
		skdebug(__func__, "calloc signature failed");
		వెళ్ళు బహిర్గతం;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 బహిర్గతం:
	ECDSA_SIG_free(sig);
	ఒకవేళ (ret != 0) {
		విడుదల(response->sig_r);
		విడుదల(response->sig_s);
		response->sig_r = ఖాళీ;
		response->sig_s = ఖాళీ;
	}
	తిరిగి ret;
}
#అయితే_ముగింపు /* WITH_OPENSSL */

స్థిర పూర్ణాంకం
pack_sig_ed25519(fido_assert_t *ప్రతిజ్ఞా, నిర్మాణం sk_sign_response *response)
{
	స్థిరరాశి గుర్తులేని అక్షరం *ptr;
	కొలత_t len;
	పూర్ణాంకం ret = -1;

	ptr = fido_assert_sig_ptr(ప్రతిజ్ఞా, 0);
	len = fido_assert_sig_len(ప్రతిజ్ఞా, 0);
	ఒకవేళ (len != 64) {
		skdebug(__func__, "bad length %zu", len);
		వెళ్ళు బహిర్గతం;
	}
	response->sig_r_len = len;
	ఒకవేళ ((response->sig_r = సున్నా_జ్ఞాపకం_ఇవ్వు(1, response->sig_r_len)) == ఖాళీ) {
		skdebug(__func__, "calloc signature failed");
		వెళ్ళు బహిర్గతం;
	}
	జ్ఞాపకం_నకలు(response->sig_r, ptr, len);
	ret = 0;
 బహిర్గతం:
	ఒకవేళ (ret != 0) {
		విడుదల(response->sig_r);
		response->sig_r = ఖాళీ;
	}
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
pack_sig(uint32_t  alg, fido_assert_t *ప్రతిజ్ఞా,
    నిర్మాణం sk_sign_response *response)
{
	ఎంపిక(alg) {
#నిర్వచితమైతే WITH_OPENSSL
	స్థితి SSH_SK_ECDSA:
		తిరిగి pack_sig_ecdsa(ప్రతిజ్ఞా, response);
#అయితే_ముగింపు /* WITH_OPENSSL */
	స్థితి SSH_SK_ED25519:
		తిరిగి pack_sig_ed25519(ప్రతిజ్ఞా, response);
	అప్రమేయ:
		తిరిగి -1;
	}
}

/* Checks sk_options for sk_sign() and sk_load_resident_keys() */
స్థిర పూర్ణాంకం
check_sign_ఎక్కించు_resident_options(నిర్మాణం sk_option **options, అక్షరం **devicep)
{
	కొలత_t i;

	ఒకవేళ (options == ఖాళీ)
		తిరిగి 0;
	కొరకు (i = 0; options[i] != ఖాళీ; i++) {
		ఒకవేళ (strcmp(options[i]->name, "device") == 0) {
			ఒకవేళ ((*devicep = strdup(options[i]->విలువ)) == ఖాళీ) {
				skdebug(__func__, "strdup device failed");
				తిరిగి -1;
			}
			skdebug(__func__, "requested device %s", *devicep);
		} లేకపోతే {
			skdebug(__func__, "requested unsupported option %s",
			    options[i]->name);
			ఒకవేళ (options[i]->required) {
				skdebug(__func__, "unknown required option");
				తిరిగి -1;
			}
		}
	}
	తిరిగి 0;
}

పూర్ణాంకం
sk_sign(uint32_t alg, స్థిరరాశి uint8_t *దత్తాంశం, కొలత_t datalen,
    స్థిరరాశి అక్షరం *application,
    స్థిరరాశి uint8_t *కీలకం_handle, కొలత_t కీలకం_handle_len,
    uint8_t flags, స్థిరరాశి అక్షరం *pin, నిర్మాణం sk_option **options,
    నిర్మాణం sk_sign_response **sign_response)
{
	fido_assert_t *ప్రతిజ్ఞా = ఖాళీ;
	అక్షరం *device = ఖాళీ;
	నిర్మాణం sk_usbhid *sk = ఖాళీ;
	నిర్మాణం sk_sign_response *response = ఖాళీ;
	పూర్ణాంకం ret = SSH_SK_ERR_GENERAL, అంతర్గత_uv;
	పూర్ణాంకం r;

	fido_init(SSH_FIDO_INIT_ARG);

	ఒకవేళ (sign_response == ఖాళీ) {
		skdebug(__func__, "sign_response == NULL");
		వెళ్ళు బహిర్గతం;
	}
	*sign_response = ఖాళీ;
	ఒకవేళ (check_sign_ఎక్కించు_resident_options(options, &device) != 0)
		వెళ్ళు బహిర్గతం; /* error already logged */
	ఒకవేళ (device != ఖాళీ)
		sk = sk_open(device);
	లేకపోతే ఒకవేళ (pin != ఖాళీ || (flags & SSH_SK_USER_VERIFICATION_REQD))
		sk = sk_probe(ఖాళీ, ఖాళీ, 0, 0);
	లేకపోతే
		sk = sk_probe(application, కీలకం_handle, కీలకం_handle_len, 0);
	ఒకవేళ (sk == ఖాళీ) {
		ret = SSH_SK_ERR_DEVICE_NOT_దొరికింది;
		skdebug(__func__, "failed to find sk");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((ప్రతిజ్ఞా = fido_assert_new()) == ఖాళీ) {
		skdebug(__func__, "fido_assert_new failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = fido_assert_సమితి_clientdata(ప్రతిజ్ఞా,
	    దత్తాంశం, datalen)) != FIDO_OK)  {
		skdebug(__func__, "fido_assert_set_clientdata: %s",
		    fido_strerr(r));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = fido_assert_సమితి_rp(ప్రతిజ్ఞా, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = fido_assert_allow_cred(ప్రతిజ్ఞా, కీలకం_handle,
	    కీలకం_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = fido_assert_సమితి_పైకి(ప్రతిజ్ఞా,
	    (flags & SSH_SK_USER_PRESENCE_REQD) ?
	    FIDO_OPT_TRUE : FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		వెళ్ళు బహిర్గతం;
	}
	/*
	 * WinHello requests the PIN by default.  Make "uv" request explicit
	 * to allow keys with and without -O verify-required to make sense.
	 */
	ఒకవేళ (pin == ఖాళీ && fido_dev_is_winhello (sk->dev) &&
	    (r = fido_assert_సమితి_uv(ప్రతిజ్ఞా, FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_uv: %s", fido_strerr(r));
	}
	ఒకవేళ (pin == ఖాళీ && (flags & SSH_SK_USER_VERIFICATION_REQD)) {
		ఒకవేళ (check_sk_options(sk->dev, "uv", &అంతర్గత_uv) < 0 ||
		    అంతర్గత_uv != 1) {
			skdebug(__func__, "check_sk_options uv");
			ret = SSH_SK_ERR_PIN_REQUIRED;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((r = fido_assert_సమితి_uv(ప్రతిజ్ఞా,
		    FIDO_OPT_TRUE)) != FIDO_OK) {
			skdebug(__func__, "fido_assert_set_uv: %s",
			    fido_strerr(r));
			ret = fidoerr_గమ్యం_skerr(r);
			వెళ్ళు బహిర్గతం;
		}
	}
	ఒకవేళ ((r = fido_dev_get_assert(sk->dev, ప్రతిజ్ఞా, pin)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_get_assert: %s", fido_strerr(r));
		ret = fidoerr_గమ్యం_skerr(r);
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((response = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*response))) == ఖాళీ) {
		skdebug(__func__, "calloc response failed");
		వెళ్ళు బహిర్గతం;
	}
	response->flags = fido_assert_flags(ప్రతిజ్ఞా, 0);
	response->counter = fido_assert_sigcount(ప్రతిజ్ఞా, 0);
	ఒకవేళ (pack_sig(alg, ప్రతిజ్ఞా, response) != 0) {
		skdebug(__func__, "pack_sig failed");
		వెళ్ళు బహిర్గతం;
	}
	*sign_response = response;
	response = ఖాళీ;
	ret = 0;
 బహిర్గతం:
	విడుదల(device);
	ఒకవేళ (response != ఖాళీ) {
		విడుదల(response->sig_r);
		విడుదల(response->sig_s);
		విడుదల(response);
	}
	sk_close(sk);
	fido_assert_free(&ప్రతిజ్ఞా);
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
read_rks(నిర్మాణం sk_usbhid *sk, స్థిరరాశి అక్షరం *pin,
    నిర్మాణం sk_resident_కీలకం ***rksp, కొలత_t *nrksp)
{
	పూర్ణాంకం ret = SSH_SK_ERR_GENERAL, r = -1;
	uint32_t alg;
	fido_credman_metadata_t *metadata = ఖాళీ;
	fido_credman_rp_t *rp = ఖాళీ;
	fido_credman_rk_t *rk = ఖాళీ;
	కొలత_t i, j, nrp, nrk, user_id_len;
	స్థిరరాశి fido_cred_t *cred;
	స్థిరరాశి అక్షరం *rp_id, *rp_name, *user_name;
	నిర్మాణం sk_resident_కీలకం *srk = ఖాళీ, **tmp;
	స్థిరరాశి u_char *user_id;

	ఒకవేళ (pin == ఖాళీ) {
		skdebug(__func__, "no PIN specified");
		ret = SSH_SK_ERR_PIN_REQUIRED;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((metadata = fido_credman_metadata_new()) == ఖాళీ) {
		skdebug(__func__, "alloc failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = fido_credman_get_dev_metadata(sk->dev, metadata, pin)) != 0) {
		ఒకవేళ (r == FIDO_ERR_INVALID_COMMAND) {
			skdebug(__func__, "device %s does not support "
			    "resident keys", sk->మార్గం);
			ret = 0;
			వెళ్ళు బహిర్గతం;
		}
		skdebug(__func__, "get metadata for %s failed: %s",
		    sk->మార్గం, fido_strerr(r));
		ret = fidoerr_గమ్యం_skerr(r);
		వెళ్ళు బహిర్గతం;
	}
	skdebug(__func__, "existing %llu, remaining %llu",
	    (గుర్తులేని దీర్ఘ దీర్ఘ)fido_credman_rk_existing(metadata),
	    (గుర్తులేని దీర్ఘ దీర్ఘ)fido_credman_rk_మిగిలిన(metadata));
	ఒకవేళ ((rp = fido_credman_rp_new()) == ఖాళీ) {
		skdebug(__func__, "alloc rp failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = fido_credman_get_dev_rp(sk->dev, rp, pin)) != 0) {
		skdebug(__func__, "get RPs for %s failed: %s",
		    sk->మార్గం, fido_strerr(r));
		వెళ్ళు బహిర్గతం;
	}
	nrp = fido_credman_rp_లెక్క(rp);
	skdebug(__func__, "Device %s has resident keys for %zu RPs",
	    sk->మార్గం, nrp);

	/* Iterate over RP IDs that have resident keys */
	కొరకు (i = 0; i < nrp; i++) {
		rp_id = fido_credman_rp_id(rp, i);
		rp_name = fido_credman_rp_name(rp, i);
		skdebug(__func__, "rp %zu: name=\"%s\" id=\"%s\" hashlen=%zu",
		    i, rp_name == ఖాళీ ? "(none)" : rp_name,
		    rp_id == ఖాళీ ? "(none)" : rp_id,
		    fido_credman_rp_id_hash_len(rp, i));

		/* Skip non-SSH RP IDs */
		ఒకవేళ (rp_id == ఖాళీ ||
		    strncasecmp(fido_credman_rp_id(rp, i), "ssh:", 4) != 0)
			కొనసాగు;

		fido_credman_rk_free(&rk);
		ఒకవేళ ((rk = fido_credman_rk_new()) == ఖాళీ) {
			skdebug(__func__, "alloc rk failed");
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((r = fido_credman_get_dev_rk(sk->dev,
		    fido_credman_rp_id(rp, i), rk, pin)) != 0) {
			skdebug(__func__, "get RKs for %s slot %zu failed: %s",
			    sk->మార్గం, i, fido_strerr(r));
			వెళ్ళు బహిర్గతం;
		}
		nrk = fido_credman_rk_లెక్క(rk);
		skdebug(__func__, "RP \"%s\" has %zu resident keys",
		    fido_credman_rp_id(rp, i), nrk);

		/* Iterate over resident keys for this RP ID */
		కొరకు (j = 0; j < nrk; j++) {
			ఒకవేళ ((cred = fido_credman_rk(rk, j)) == ఖాళీ) {
				skdebug(__func__, "no RK in slot %zu", j);
				కొనసాగు;
			}
			ఒకవేళ ((user_name = fido_cred_user_name(cred)) == ఖాళీ)
				user_name = "";
			user_id = fido_cred_user_id_ptr(cred);
			user_id_len = fido_cred_user_id_len(cred);
			skdebug(__func__, "Device %s RP \"%s\" user \"%s\" "
			    "uidlen %zu slot %zu: type %d flags 0x%02x "
			    "prot 0x%02x", sk->మార్గం, rp_id, user_name,
			    user_id_len, j, fido_cred_type(cred),
			    fido_cred_flags(cred), fido_cred_prot(cred));

			/* Determine key algorithm */
			ఎంపిక (fido_cred_type(cred)) {
			స్థితి COSE_ES256:
				alg = SSH_SK_ECDSA;
				ఆపు;
			స్థితి COSE_EDDSA:
				alg = SSH_SK_ED25519;
				ఆపు;
			అప్రమేయ:
				skdebug(__func__, "unsupported key type %d",
				    fido_cred_type(cred));
				కొనసాగు;
			}

			/* build response entry */
			ఒకవేళ ((srk = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*srk))) == ఖాళీ ||
			    (srk->కీలకం.కీలకం_handle = సున్నా_జ్ఞాపకం_ఇవ్వు(1,
			    fido_cred_id_len(cred))) == ఖాళీ ||
			    (srk->application = strdup(rp_id)) == ఖాళీ ||
			    (user_id_len > 0 &&
			     (srk->user_id = సున్నా_జ్ఞాపకం_ఇవ్వు(1, user_id_len)) == ఖాళీ)) {
				skdebug(__func__, "alloc sk_resident_key");
				వెళ్ళు బహిర్గతం;
			}

			srk->alg = alg;
			srk->కీలకం.కీలకం_handle_len = fido_cred_id_len(cred);
			జ్ఞాపకం_నకలు(srk->కీలకం.కీలకం_handle, fido_cred_id_ptr(cred),
			    srk->కీలకం.కీలకం_handle_len);
			srk->user_id_len = user_id_len;
			ఒకవేళ (srk->user_id_len != 0)
				జ్ఞాపకం_నకలు(srk->user_id, user_id, srk->user_id_len);

#నిర్వచితమైతే HAVE_FIDO_CRED_PROT
			ఒకవేళ (fido_cred_prot(cred) ==
			    FIDO_CRED_PROT_UV_REQUIRED)
				srk->flags |=  SSH_SK_USER_VERIFICATION_REQD;
#అయితే_ముగింపు

			ఒకవేళ ((r = pack_ప్రజా_కీలకం(srk->alg, cred,
			    &srk->కీలకం)) != 0) {
				skdebug(__func__, "pack public key failed");
				వెళ్ళు బహిర్గతం;
			}
			/* append */
			ఒకవేళ ((tmp = recallocarray(*rksp, *nrksp, (*nrksp) + 1,
			    పరిమాణం(**rksp))) == ఖాళీ) {
				skdebug(__func__, "alloc rksp");
				వెళ్ళు బహిర్గతం;
			}
			*rksp = tmp;
			(*rksp)[(*nrksp)++] = srk;
			srk = ఖాళీ;
		}
	}
	/* Success */
	ret = 0;
 బహిర్గతం:
	ఒకవేళ (srk != ఖాళీ) {
		విడుదల(srk->application);
		freezero(srk->కీలకం.ప్రజా_కీలకం, srk->కీలకం.ప్రజా_కీలకం_len);
		freezero(srk->కీలకం.కీలకం_handle, srk->కీలకం.కీలకం_handle_len);
		freezero(srk->user_id, srk->user_id_len);
		freezero(srk, పరిమాణం(*srk));
	}
	fido_credman_rp_free(&rp);
	fido_credman_rk_free(&rk);
	fido_credman_metadata_free(&metadata);
	తిరిగి ret;
}

పూర్ణాంకం
sk_ఎక్కించు_resident_కీలకాలు(స్థిరరాశి అక్షరం *pin, నిర్మాణం sk_option **options,
    నిర్మాణం sk_resident_కీలకం ***rksp, కొలత_t *nrksp)
{
	పూర్ణాంకం ret = SSH_SK_ERR_GENERAL, r = -1;
	కొలత_t i, nrks = 0;
	నిర్మాణం sk_resident_కీలకం **rks = ఖాళీ;
	నిర్మాణం sk_usbhid *sk = ఖాళీ;
	అక్షరం *device = ఖాళీ;

	*rksp = ఖాళీ;
	*nrksp = 0;

	fido_init(SSH_FIDO_INIT_ARG);

	ఒకవేళ (check_sign_ఎక్కించు_resident_options(options, &device) != 0)
		వెళ్ళు బహిర్గతం; /* error already logged */
	ఒకవేళ (device != ఖాళీ)
		sk = sk_open(device);
	లేకపోతే
		sk = sk_probe(ఖాళీ, ఖాళీ, 0, 1);
	ఒకవేళ (sk == ఖాళీ) {
		ret = SSH_SK_ERR_DEVICE_NOT_దొరికింది;
		skdebug(__func__, "failed to find sk");
		వెళ్ళు బహిర్గతం;
	}
	skdebug(__func__, "trying %s", sk->మార్గం);
	ఒకవేళ ((r = read_rks(sk, pin, &rks, &nrks)) != 0) {
		skdebug(__func__, "read_rks failed for %s", sk->మార్గం);
		ret = r;
		వెళ్ళు బహిర్గతం;
	}
	/* success, unless we have no keys but a specific error */
	ఒకవేళ (nrks > 0 || ret == SSH_SK_ERR_GENERAL)
		ret = 0;
	*rksp = rks;
	*nrksp = nrks;
	rks = ఖాళీ;
	nrks = 0;
 బహిర్గతం:
	sk_close(sk);
	కొరకు (i = 0; i < nrks; i++) {
		విడుదల(rks[i]->application);
		freezero(rks[i]->కీలకం.ప్రజా_కీలకం, rks[i]->కీలకం.ప్రజా_కీలకం_len);
		freezero(rks[i]->కీలకం.కీలకం_handle, rks[i]->కీలకం.కీలకం_handle_len);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i], పరిమాణం(*rks[i]));
	}
	విడుదల(device);
	విడుదల(rks);
	తిరిగి ret;
}

#అయితే_ముగింపు /* ENABLE_SK_INTERNAL */
