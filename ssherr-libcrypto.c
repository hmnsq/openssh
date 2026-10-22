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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <string.h>

#অন্তর্ভাব "log.h"

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/err.h>

ধ্রুব বর্ণ *
ssherr_libcrypto(শূন্য)
{
	unsigned long e;
	স্থির বর্ণ buf[512];
	বর্ণ বার্তা[4096];
	ধ্রুব বর্ণ *reason = রিক্ত, *file, *data;
	পূর্ণাঙ্ক ln, fl;

	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, রিক্ত);
	যাবত্ ((e = ERR_get_error_সারি_data(&file, &ln, &data, &fl)) != 0) {
		ERR_error_string_n(e, buf, পরিমাণ(buf));
		snprintf(বার্তা, পরিমাণ(বার্তা), "%s:%s:%d:%s", buf, file, ln,
		    (fl & ERR_TXT_STRING) ? data : "");
		debug("libcrypto: '%s'", বার্তা);
		যদি ((reason = ERR_reason_error_string(e)) != রিক্ত)
			snprintf(buf, পরিমাণ(buf), "error in libcrypto: %s",
			    reason);
	}
	যদি (reason == রিক্ত)
		প্রত্যাগম রিক্ত;
	প্রত্যাগম buf;
}
#অন্যথা
ধ্রুব বর্ণ *
ssherr_libcrypto(শূন্য)
{
	প্রত্যাগম রিক্ত;
}
#endif
