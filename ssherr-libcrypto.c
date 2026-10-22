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

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <errno.h>
#شامل <string.h>

#شامل "log.h"

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/err.h>

ثابت حرف *
ssherr_libcrypto(خالی)
{
	غیرعلامتی طویل e;
	ساکن حرف buf[512];
	حرف پیغام[4096];
	ثابت حرف *reason = تہی, *file, *ڈیٹا;
	صحیح ln, fl;

	OPENSSL_init_crypto(OPENSSL_INIT_بھرو_CRYPTO_لڑیاں, تہی);
	جب ((e = ERR_get_error_سطر_ڈیٹا(&file, &ln, &ڈیٹا, &fl)) != 0) {
		ERR_error_string_n(e, buf, حجم(buf));
		snprintf(پیغام, حجم(پیغام), "%s:%s:%d:%s", buf, file, ln,
		    (fl & ERR_TXT_STRING) ? ڈیٹا : "");
		debug("libcrypto: '%s'", پیغام);
		اگر ((reason = ERR_reason_error_string(e)) != تہی)
			snprintf(buf, حجم(buf), "error in libcrypto: %s",
			    reason);
	}
	اگر (reason == تہی)
		واپس تہی;
	واپس buf;
}
#ورنہ
ثابت حرف *
ssherr_libcrypto(خالی)
{
	واپس تہی;
}
#اگر_ختم
