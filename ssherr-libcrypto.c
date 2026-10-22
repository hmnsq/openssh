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

#ضمن "includes.h"

#ضمن <sys/types.h>

#ضمن <errno.h>
#ضمن <string.h>

#ضمن "log.h"

#ifdef WITH_OPENSSL
#ضمن <openssl/err.h>

ثابت حرف *
ssherr_libcrypto(فراغ)
{
	unsigned long e;
	ساكن حرف buf[512];
	حرف پەیام[4096];
	ثابت حرف *reason = عدم, *file, *data;
	صحيح ln, fl;

	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, عدم);
	طالما ((e = ERR_get_error_هێڵ_data(&file, &ln, &data, &fl)) != 0) {
		ERR_error_string_n(e, buf, حجم(buf));
		snprintf(پەیام, حجم(پەیام), "%s:%s:%d:%s", buf, file, ln,
		    (fl & ERR_TXT_STRING) ? data : "");
		debug("libcrypto: '%s'", پەیام);
		إذا ((reason = ERR_reason_error_string(e)) != عدم)
			snprintf(buf, حجم(buf), "error in libcrypto: %s",
			    reason);
	}
	إذا (reason == عدم)
		أرجع عدم;
	أرجع buf;
}
#وإلا
ثابت حرف *
ssherr_libcrypto(فراغ)
{
	أرجع عدم;
}
#endif
