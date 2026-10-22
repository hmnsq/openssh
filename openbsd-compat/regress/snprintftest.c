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

#define BUFSZ 2048

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <string.h>

സ്ഥിതം പൂർണ്ണസംഖ്യ failed = 0;

സ്ഥിതം ശൂന്യം
fail(സ്ഥിരം അക്ഷരം *m)
{
	fprintf(stderr, "snprintftest: %s\n", m);
	failed = 1;
}

പൂർണ്ണസംഖ്യ x_snprintf(അക്ഷരം *str, size_t എണ്ണം, സ്ഥിരം അക്ഷരം *fmt, ...)
{
	size_t ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(str, എണ്ണം, fmt, ap);
	va_end(ap);
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
പ്രധാന(ശൂന്യം)
{
	അക്ഷരം b[5];
	അക്ഷരം *src = ശൂന്യ;
	പൂർണ്ണസംഖ്യ ret;

	memset(b, 'X', വലുപ്പം(b));
	ret = snprintf(b, 5, "123456789");
	എങ്കിൽ (ret != 9 || b[4] != '\0')
		fail("snprintf does not correctly terminate long strings");

	/* check for read overrun on unterminated string */
	എങ്കിൽ ((src = malloc(BUFSZ)) == ശൂന്യ) {
		fail("malloc failed");
	} അല്ലെങ്കിൽ {
		memset(src, 'a', BUFSZ);
		snprintf(b, വലുപ്പം(b), "%.*s", 1, src);
		എങ്കിൽ (strcmp(b, "a") != 0)
			fail("failed with length limit '%%.s'");
	}

	/* check that snprintf and vsnprintf return sane values */
	എങ്കിൽ (snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("snprintf does not return required length");
	എങ്കിൽ (x_snprintf(b, 1, "%s %d", "hello", 12345) != 11)
		fail("vsnprintf does not return required length");

	സ്വതന്ത്രം(src);
	തിരികെ failed;
}
