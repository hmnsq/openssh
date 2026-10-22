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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "log.h"

#यदि_परिभाषितम् WITH_OPENSSL
#अन्तर्भाव <openssl/err.h>

ध्रुव वर्ण *
ssherr_libcrypto(शून्य)
{
	अचिह्नित दीर्घ e;
	स्थिर वर्ण buf[512];
	वर्ण सन्देशः[4096];
	ध्रुव वर्ण *reason = रिक्त, *file, *दत्त;
	पूर्णाङ्क ln, fl;

	OPENSSL_init_crypto(OPENSSL_INIT_आरोपय_CRYPTO_वाक्यानि, रिक्त);
	यावत् ((e = ERR_get_error_पङ्क्तिः_दत्त(&file, &ln, &दत्त, &fl)) != 0) {
		ERR_error_string_n(e, buf, परिमाण(buf));
		snprintf(सन्देशः, परिमाण(सन्देशः), "%s:%s:%d:%s", buf, file, ln,
		    (fl & ERR_TXT_STRING) ? दत्त : "");
		debug("libcrypto: '%s'", सन्देशः);
		यदि ((reason = ERR_reason_error_string(e)) != रिक्त)
			snprintf(buf, परिमाण(buf), "error in libcrypto: %s",
			    reason);
	}
	यदि (reason == रिक्त)
		प्रत्यागम रिक्त;
	प्रत्यागम buf;
}
#अन्यथा
ध्रुव वर्ण *
ssherr_libcrypto(शून्य)
{
	प्रत्यागम रिक्त;
}
#यदि_अन्तः
