/*
 * Copyright (c) 2005 Darren Tucker
 * Copyright (c) 2005 Damien Miller
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

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ BUFSZ 2048

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

ਸਥਿਰ ਪੂਰਨ failed = 0;

ਸਥਿਰ ਖਾਲੀ
fail(ਅਚਲ ਅੱਖਰ *m)
{
	fprintf(stderr, "snprintftest: %s\n", m);
	failed = 1;
}

ਪੂਰਨ x_snprintf(ਅੱਖਰ *str, ਮਾਪ_t ਗਿਣਤੀ_2, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	ਮਾਪ_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, ਗਿਣਤੀ_2, fmt, ap);
	va_end(ap);
	ਵਾਪਸ ret;
}

ਪੂਰਨ
ਮੁੱਖ(ਖਾਲੀ)
{
	ਅੱਖਰ b[5];
	ਅੱਖਰ *src = ਨਿਰਾ;
	ਪੂਰਨ ret;

	memset(b, 'X', ਆਕਾਰ(b));
	ret = snprintf(b, 5, "123456789");
	ਜੇ (ret != 9 || b[4] != '\0')
		fail("snprintf does not correctly terminate long strings");

	/* check for read overrun on unterminated string */
	ਜੇ ((src = ਸਮ੍ਰਿਤੀ_ਦਿਓ(BUFSZ)) == ਨਿਰਾ) {
		fail("malloc failed");
	} ਨਹੀਂਤਾਂ {
		memset(src, 'a', BUFSZ);
		snprintf(b, ਆਕਾਰ(b), "%.*s", 1, src);
		ਜੇ (strcmp(b, "a") != 0)
			fail("failed with length limit '%%.s'");
	}

	/* check that snprintf and vsnprintf return sane values */
	ਜੇ (snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("snprintf does not return required length");
	ਜੇ (x_snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("vsnprintf does not return required length");

	ਮੁਕਤ(src);
	ਵਾਪਸ failed;
}
