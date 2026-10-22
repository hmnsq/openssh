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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "log.h"

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/err.h>

స్థిరరాశి అక్షరం *
ssherr_libcrypto(శూన్య)
{
	గుర్తులేని దీర్ఘ e;
	స్థిర అక్షరం buf[512];
	అక్షరం సందేశం[4096];
	స్థిరరాశి అక్షరం *reason = ఖాళీ, *file, *దత్తాంశం;
	పూర్ణాంకం ln, fl;

	OPENSSL_init_crypto(OPENSSL_INIT_ఎక్కించు_CRYPTO_అక్షరశ్రేణులు, ఖాళీ);
	అయితే ((e = ERR_get_error_పంక్తి_దత్తాంశం(&file, &ln, &దత్తాంశం, &fl)) != 0) {
		ERR_error_string_n(e, buf, పరిమాణం(buf));
		snprintf(సందేశం, పరిమాణం(సందేశం), "%s:%s:%d:%s", buf, file, ln,
		    (fl & ERR_TXT_STRING) ? దత్తాంశం : "");
		debug("libcrypto: '%s'", సందేశం);
		ఒకవేళ ((reason = ERR_reason_error_string(e)) != ఖాళీ)
			snprintf(buf, పరిమాణం(buf), "error in libcrypto: %s",
			    reason);
	}
	ఒకవేళ (reason == ఖాళీ)
		తిరిగి ఖాళీ;
	తిరిగి buf;
}
#లేకపోతే
స్థిరరాశి అక్షరం *
ssherr_libcrypto(శూన్య)
{
	తిరిగి ఖాళీ;
}
#అయితే_ముగింపు
