/* $OpenBSD: ssherr-libcrypto.c,v 1.2 2026/06/30 03:42:53 tb Exp $ */
/*
 * Copyright (c) 2026 Darren Tucker
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

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ "log.h"

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ <openssl/err.h>

ଅଚଳ ଅକ୍ଷର *
ssherr_libcrypto(ଶୂନ୍ୟ)
{
	unsigned long e;
	ସ୍ଥିର ଅକ୍ଷର buf[512];
	ଅକ୍ଷର ସନ୍ଦେଶ[4096];
	ଅଚଳ ଅକ୍ଷର *reason = ଖାଲି, *file, *data;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ln, fl;

	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, ଖାଲି);
	ଯେତେବେଳେ ((e = ERR_get_error_ଧାଡ଼ି_data(&file, &ln, &data, &fl)) != 0) {
		ERR_error_string_n(e, buf, ଆକାର(buf));
		snprintf(ସନ୍ଦେଶ, ଆକାର(ସନ୍ଦେଶ), "%s:%s:%d:%s", buf, file, ln,
		    (fl & ERR_TXT_STRING) ? data : "");
		debug("libcrypto: '%s'", ସନ୍ଦେଶ);
		ଯଦି ((reason = ERR_reason_error_string(e)) != ଖାଲି)
			snprintf(buf, ଆକାର(buf), "error in libcrypto: %s",
			    reason);
	}
	ଯଦି (reason == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	ଫେରନ୍ତୁ buf;
}
#ଅନ୍ୟଥା
ଅଚଳ ଅକ୍ଷର *
ssherr_libcrypto(ଶୂନ୍ୟ)
{
	ଫେରନ୍ତୁ ଖାଲି;
}
#endif
