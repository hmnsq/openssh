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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>

#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <string.h>

#অন্তর্ভাৱ "log.h"

#ifdef WITH_OPENSSL
#অন্তর্ভাৱ <openssl/err.h>

ধ্রুৱ ৱর্ণ *
ssherr_libcrypto(শূন্য)
{
	unsigned long e;
	স্থির ৱর্ণ buf[512];
	ৱর্ণ বাৰ্তা[4096];
	ধ্রুৱ ৱর্ণ *reason = রিক্ত, *file, *data;
	পূর্ণাঙ্ক ln, fl;

	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, রিক্ত);
	যেতিয়ালৈ ((e = ERR_get_error_সাৰি_data(&file, &ln, &data, &fl)) != 0) {
		ERR_error_string_n(e, buf, পরিমাণ(buf));
		snprintf(বাৰ্তা, পরিমাণ(বাৰ্তা), "%s:%s:%d:%s", buf, file, ln,
		    (fl & ERR_TXT_STRING) ? data : "");
		debug("libcrypto: '%s'", বাৰ্তা);
		যদি ((reason = ERR_reason_error_string(e)) != রিক্ত)
			snprintf(buf, পরিমাণ(buf), "error in libcrypto: %s",
			    reason);
	}
	যদি (reason == রিক্ত)
		ঘূৰাই রিক্ত;
	ঘূৰাই buf;
}
#অন্যথা
ধ্রুৱ ৱর্ণ *
ssherr_libcrypto(শূন্য)
{
	ঘূৰাই রিক্ত;
}
#endif
