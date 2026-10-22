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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "log.h"

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/err.h>

സ്ഥിരം അക്ഷരം *
ssherr_libcrypto(ശൂന്യം)
{
	unsigned long e;
	സ്ഥിതം അക്ഷരം buf[512];
	അക്ഷരം സന്ദേശം[4096];
	സ്ഥിരം അക്ഷരം *reason = ശൂന്യ, *file, *data;
	പൂർണ്ണസംഖ്യ ln, fl;

	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, ശൂന്യ);
	ആകുമ്പോൾ ((e = ERR_get_error_വരി_data(&file, &ln, &data, &fl)) != 0) {
		ERR_error_string_n(e, buf, വലുപ്പം(buf));
		snprintf(സന്ദേശം, വലുപ്പം(സന്ദേശം), "%s:%s:%d:%s", buf, file, ln,
		    (fl & ERR_TXT_STRING) ? data : "");
		debug("libcrypto: '%s'", സന്ദേശം);
		എങ്കിൽ ((reason = ERR_reason_error_string(e)) != ശൂന്യ)
			snprintf(buf, വലുപ്പം(buf), "error in libcrypto: %s",
			    reason);
	}
	എങ്കിൽ (reason == ശൂന്യ)
		തിരികെ ശൂന്യ;
	തിരികെ buf;
}
#അല്ലെങ്കിൽ
സ്ഥിരം അക്ഷരം *
ssherr_libcrypto(ശൂന്യം)
{
	തിരികെ ശൂന്യ;
}
#endif
