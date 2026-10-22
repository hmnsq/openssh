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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "log.h"

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/err.h>

மாறிலி எழுத்து *
ssherr_libcrypto(வெறுமை)
{
	unsigned long e;
	நிலையான எழுத்து buf[512];
	எழுத்து செய்தி[4096];
	மாறிலி எழுத்து *reason = வெற்று, *file, *data;
	முழு ln, fl;

	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, வெற்று);
	போது ((e = ERR_get_error_வரி_data(&file, &ln, &data, &fl)) != 0) {
		ERR_error_string_n(e, buf, அளவு(buf));
		snprintf(செய்தி, அளவு(செய்தி), "%s:%s:%d:%s", buf, file, ln,
		    (fl & ERR_TXT_STRING) ? data : "");
		debug("libcrypto: '%s'", செய்தி);
		எனில் ((reason = ERR_reason_error_string(e)) != வெற்று)
			snprintf(buf, அளவு(buf), "error in libcrypto: %s",
			    reason);
	}
	எனில் (reason == வெற்று)
		திரும்பு வெற்று;
	திரும்பு buf;
}
#இல்லையெனில்
மாறிலி எழுத்து *
ssherr_libcrypto(வெறுமை)
{
	திரும்பு வெற்று;
}
#endif
