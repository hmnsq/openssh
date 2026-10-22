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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ "log.h"

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/err.h>

અચલ અક્ષર *
ssherr_libcrypto(શૂન્ય)
{
	unsigned long e;
	સ્થિર અક્ષર buf[512];
	અક્ષર સંદેશ[4096];
	અચલ અક્ષર *reason = ખાલી, *file, *data;
	પૂર્ણાંક ln, fl;

	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, ખાલી);
	જ્યારે ((e = ERR_get_error_લીટી_data(&file, &ln, &data, &fl)) != 0) {
		ERR_error_string_n(e, buf, કદ(buf));
		snprintf(સંદેશ, કદ(સંદેશ), "%s:%s:%d:%s", buf, file, ln,
		    (fl & ERR_TXT_STRING) ? data : "");
		debug("libcrypto: '%s'", સંદેશ);
		જો ((reason = ERR_reason_error_string(e)) != ખાલી)
			snprintf(buf, કદ(buf), "error in libcrypto: %s",
			    reason);
	}
	જો (reason == ખાલી)
		પાછા ખાલી;
	પાછા buf;
}
#નહીંતર
અચલ અક્ષર *
ssherr_libcrypto(શૂન્ય)
{
	પાછા ખાલી;
}
#endif
